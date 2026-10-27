//! A KEM whose private-key operation is not Diffie-Hellman, brought by an
//! outside crate through [`RecipientKem`] alone:
//!
//! - The KEM names its own recipient key type, and its own decapsulation
//!   trait, [`StubDecapsulator`], as its `PrivateKey`.
//! - Its certificate profile asserts `keyEncipherment`, as an ML-KEM
//!   certificate does (RFC 9935 §5).
//! - A backend outside the crate implements that trait.
//! - A [`KeyAgreementIdentity`] pairs the backend with a key-agreement certificate.
//! - A [`StubProvider`] seals and opens an `AuthEnvelopedData` under the KEM,
//!   with the house algorithms for the rest.
//!
//! The arithmetic is a stub that masks the shared secret with a digest of the
//! recipient key, so the tests prove the seam and not the KEM.

use std::sync::Arc;

use tightbeam::crypto::aead::Aes256Gcm;
use tightbeam::crypto::cms::{
	AuthEnvelopedData, Encapsulation, EnvelopeError, KeyAgreementIdentity, Opener, Recipient, RecipientKem,
};
use tightbeam::crypto::hash::{Digest, Sha3_256};
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::key::{KeyBackend, KeyError};
use tightbeam::crypto::profiles::{
	AeadProvider, Aes256Wrap, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, KeyWrapProvider,
	SigningProvider, TightbeamProfile,
};
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Encode;
use tightbeam::oids::DATA;
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use tightbeam::testing::{EnvelopeRecipient, TestCertificate};
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::ext::pkix::{KeyUsage, KeyUsages};
use tightbeam::x509::Certificate;
use tightbeam::zeroize::Zeroizing;
use tightbeam::ZeroizingBytes;

use super::{CONTENT, UKM_LABEL};

#[cfg(feature = "transport-cms")]
mod flow {
	pub use tightbeam::crypto::x509::KeyPurposes;
	pub use tightbeam::der::asn1::BitString;
	pub use tightbeam::oids::KEM_ML_KEM_1024;
	pub use tightbeam::spki::SubjectPublicKeyInfoOwned;
	pub use tightbeam::testing::{TestCmsServer, TestIdentity};
	pub use tightbeam::transport::handshake::negotiation::RunnableProfile;
	pub use tightbeam::transport::handshake::{
		Client, ClientConfig, Cms, CmsClientSettings, CmsIdentityPair, CmsServerChain, CmsServerIdentity,
		CmsServerSettings, Handshake, HandshakeError, ProvisionedTrust, Server, ServerConfig, SupportedProfiles,
	};
}

#[cfg(feature = "transport-cms")]
use super::trust::PinningTrust;
#[cfg(feature = "transport-cms")]
use flow::*;

/// The identifier of the stub KEM, under the outside arc.
const STUB_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.3");

/// The recipient key of the stub KEM: the bits of a certificate's
/// `subjectPublicKey`, whatever their algorithm.
#[derive(Clone, Debug, PartialEq)]
struct StubKey(Vec<u8>);

impl StubKey {
	/// The mask of the shared secret: the SHA3-256 digest of the key bits.
	fn mask(&self) -> [u8; 32] {
		Sha3_256::digest(&self.0).into()
	}
}

/// `secret` under `mask`, octet by octet.
fn masked(secret: &[u8], mask: &[u8]) -> Vec<u8> {
	secret.iter().zip(mask).map(|(octet, mask)| octet ^ mask).collect()
}

/// The private-key operation of the stub KEM, which the holder of a stub
/// recipient key implements in place of a Diffie-Hellman agreement.
trait StubDecapsulator: KeyBackend {
	/// Whether this backend holds the private half of `recipient`.
	fn answers_for(&self, recipient: &StubKey) -> bool;

	/// The shared secret that `kemct` carries to the holder of this key.
	fn decapsulate<'a>(&'a self, kemct: &'a [u8]) -> MaybeSendFuture<'a, Result<ZeroizingBytes, KeyError>>;
}

/// The stub KEM, whose `PrivateKey` is [`StubDecapsulator`].
struct StubKem;

impl RecipientKem for StubKem {
	const OID: ObjectIdentifier = STUB_KEM;
	const USAGE: KeyUsages = KeyUsages::KeyEncipherment;
	type PublicKey = StubKey;
	type PrivateKey = dyn StubDecapsulator;

	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<StubKey, CertificateValidationError> {
		Ok(StubKey(spki.subject_public_key.raw_bytes().to_vec()))
	}

	fn encapsulate(recipient: &StubKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		let mut shared_secret = Zeroizing::new(vec![0u8; 32]);
		rng.try_fill_bytes(&mut shared_secret).map_err(|_| EnvelopeError::Random)?;
		let kemct = masked(&shared_secret, &recipient.mask());
		Ok(Encapsulation { shared_secret, kemct })
	}

	/// The crate hands the opener's recipient beside its backend, and the
	/// stub refuses a pair whose backend holds another key.
	fn decapsulate<'a>(
		key: &'a dyn StubDecapsulator,
		recipient: &'a StubKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		Box::pin(async move {
			if !key.answers_for(recipient) {
				return Err(EnvelopeError::KeyMismatch);
			}

			Ok(key.decapsulate(kemct).await?)
		})
	}
}

/// The backend of a stub recipient key, which unmasks a `kemct` itself.
#[derive(Debug)]
struct StubBackend {
	/// The DER SubjectPublicKeyInfo of the certificate the backend answers for.
	public_key_der: Vec<u8>,
	/// The recipient key, whose mask the backend holds.
	key: StubKey,
}

impl KeyBackend for StubBackend {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: STUB_KEM, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key_der.to_owned())
	}
}

impl StubDecapsulator for StubBackend {
	fn answers_for(&self, recipient: &StubKey) -> bool {
		self.key == *recipient
	}

	fn decapsulate<'a>(&'a self, kemct: &'a [u8]) -> MaybeSendFuture<'a, Result<ZeroizingBytes, KeyError>> {
		let shared_secret = Zeroizing::new(masked(kemct, &self.key.mask()));
		Box::pin(async move { Ok(shared_secret) })
	}
}

/// The profile of [`StubProvider`]: the house profile.
type StubProfile = TightbeamProfile;

/// A provider an outside crate defines around the stub KEM, with the house
/// algorithms for everything else.
#[derive(Debug, Default, Clone, Copy)]
struct StubProvider {
	profile: StubProfile,
}

impl DigestProvider for StubProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for StubProvider {
	type AeadCipher = Aes256Gcm;
}

impl KeyWrapProvider for StubProvider {
	type KeyWrap = Aes256Wrap;
}

impl SigningProvider for StubProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for StubProvider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for StubProvider {
	type Curve = Secp256k1;
}

impl CryptoProvider for StubProvider {
	type Profile = StubProfile;
	type Kem = StubKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// A certificate of a fresh key whose `keyUsage` is `usage` alone.
fn certificate_of(usage: KeyUsages) -> Certificate {
	let certificate = TestCertificate::self_signed(&SigningKey::random(&mut OsRng));
	TestCertificate::with_key_usage(certificate, KeyUsage(usage.into()))
}

/// A stub backend of the key of `certificate`.
fn backend_of(certificate: &Certificate) -> Arc<dyn StubDecapsulator> {
	let spki = &certificate.tbs_certificate.subject_public_key_info;
	let public_key_der = spki.to_der().expect("the certificate's SPKI encodes");
	let key = StubKey(spki.subject_public_key.raw_bytes().to_vec());
	Arc::new(StubBackend { public_key_der, key })
}

/// A key-agreement identity under the stub KEM: a certificate that asserts
/// `keyEncipherment` alone, beside a stub backend of its key.
fn stub_identity() -> KeyAgreementIdentity<StubKem> {
	let certificate = certificate_of(KeyUsages::KeyEncipherment);
	let backend = backend_of(&certificate);
	let identity = KeyAgreementIdentity::new(certificate, backend);
	identity.expect("the stub backend answers for the certificate's key")
}

/// [`CONTENT`] sealed under [`StubProvider`] to the recipient of `identity`.
fn stub_sealed(identity: &KeyAgreementIdentity<StubKem>) -> AuthEnvelopedData {
	let recipient = Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL };
	let sealed = AuthEnvelopedData::seal::<StubProvider>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals under the stub KEM")
}

/// A seal to a key-agreement identity of the stub KEM opens through its
/// backend, whose private-key operation is the KEM's own trait.
#[tokio::test]
async fn a_kem_with_its_own_private_key_operation_opens_its_seal() -> Result<(), Box<dyn std::error::Error>> {
	let identity = stub_identity();
	let sealed = stub_sealed(&identity);
	let opener = Opener::Kem { identity: &identity, ukm_label: UKM_LABEL };
	let arrived = sealed.to_der()?;

	let opened = sealed.open::<StubProvider>(arrived, &opener, DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The stub KEM's certificate profile asserts `keyEncipherment`, so a
/// certificate of `keyAgreement` alone is refused for its recipient.
#[test]
fn a_stub_recipient_certificate_of_key_agreement_is_refused() {
	let certificate = certificate_of(KeyUsages::KeyAgreement);
	let backend = backend_of(&certificate);

	let refused = KeyAgreementIdentity::<StubKem>::new(certificate, backend);
	assert!(matches!(
		refused,
		Err(EnvelopeError::Certificate(CertificateValidationError::MissingKeyUsage(
			KeyUsages::KeyEncipherment
		)))
	));
}

/// The `KEMRecipientInfo` of a stub seal names the stub KEM by its own
/// identifier.
#[test]
fn a_stub_seal_names_the_stub_kem() {
	let sealed = stub_sealed(&stub_identity());
	let kem = sealed.kem_recipient();
	assert_eq!(kem.kem.oid, STUB_KEM);
}

/// The certificate of `certificate`'s subject with a stub recipient key: an
/// ML-KEM-1024 SubjectPublicKeyInfo over stub bits, which no handshake curve
/// reads as a point, asserting `keyEncipherment` alone.
#[cfg(feature = "transport-cms")]
fn with_stub_key(certificate: Certificate) -> Certificate {
	let algorithm = AlgorithmIdentifierOwned { oid: KEM_ML_KEM_1024, parameters: None };
	let subject_public_key = BitString::from_bytes(&[0x5a; 64]).expect("stub bits are a BIT STRING");

	let mut certificate = certificate;
	certificate.tbs_certificate.subject_public_key_info = SubjectPublicKeyInfoOwned { algorithm, subject_public_key };
	TestCertificate::with_key_usage(certificate, KeyUsage(KeyUsages::KeyEncipherment.into()))
}

/// The stub CMS server, whose key-agreement certificate holds a key of the
/// stub KEM, a client of it that pins that certificate against the outside
/// store `store` makes of the server and that certificate, and the server's
/// handshake, both under [`StubProvider`].
#[cfg(feature = "transport-cms")]
fn stub_parties(store: impl FnOnce(&TestCmsServer, Certificate) -> PinningTrust) -> StubParties {
	let server = TestCmsServer::generate("stub server");
	let key_agreement = with_stub_key(server.key_agreement.to_owned());
	let identity = KeyAgreementIdentity::<StubKem>::new(key_agreement.to_owned(), backend_of(&key_agreement));
	let pair = CmsIdentityPair::new(server.signing_identity(), identity.expect("the stub backend holds its key"));

	let pinned = CmsServerIdentity::Certificate(Arc::new(key_agreement.to_owned()));
	let store = store(&server, key_agreement);
	let trust = ProvisionedTrust::new(pinned, Arc::new(store)).expect("the store admits the pinned certificate");

	let client_identity = TestIdentity::of(&SigningKey::random(&mut OsRng));
	let settings = CmsClientSettings { trust, identity: client_identity };
	let client = ClientConfig::<Cms, StubProvider>::new(settings, KeyPurposes::HOUSE);
	let profiles = SupportedProfiles::from(RunnableProfile::<StubProvider>::native().descriptor());
	let pair = pair.expect("the stub server's certificates name one subject with two keys");
	let server_config = ServerConfig::<Cms, StubProvider>::new(CmsServerSettings, pair, profiles, KeyPurposes::HOUSE);

	let client = Handshake::client(client.expect("the client configuration holds"));
	let handshake = Handshake::server(server_config.expect("the server configuration holds"));
	StubParties { client, handshake, server }
}

/// What [`stub_parties`] returns.
#[cfg(feature = "transport-cms")]
struct StubParties {
	/// The client, before its opening.
	client: Handshake<Client, Cms, StubProvider>,
	/// The server's handshake.
	handshake: Handshake<Server, Cms, StubProvider>,
	/// The server's certificates and keys.
	server: TestCmsServer,
}

/// A CMS server whose key-agreement certificate holds a key of the stub KEM
/// runs the whole flow under [`StubProvider`]:
///
/// - The client pins the key-agreement certificate, and the opening seals to its key.
/// - The stub backend opens the opening.
/// - A store an outside crate defines admits both certificates under one trust anchor.
/// - The client compares the server ephemeral with the signing key alone.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_kem_of_its_own_key_type_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let under_authority = |server: &TestCmsServer, key_agreement: Certificate| {
		PinningTrust::under(server.authority.to_owned(), vec![server.signing.to_owned(), key_agreement])
	};

	let StubParties { mut client, mut handshake, server } = stub_parties(under_authority);
	let opening = client.start()?;
	let reply = handshake.reply(opening).await?;
	let closing = client.respond(reply).await?;

	handshake.finish(closing).await?;

	assert_eq!(client.peer_certificate(), Some(&server.signing));
	Ok(())
}

/// An outside store that names each pin its own trust anchor gives the two
/// certificates of the stub server two anchors, so the client refuses the
/// reply.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn an_outside_store_of_two_anchors_refuses_the_pair() -> Result<(), Box<dyn std::error::Error>> {
	let each_its_own_anchor = |server: &TestCmsServer, key_agreement: Certificate| {
		PinningTrust::of(vec![server.signing.to_owned(), key_agreement])
	};

	let StubParties { mut client, mut handshake, .. } = stub_parties(each_its_own_anchor);
	let opening = client.start()?;
	let reply = handshake.reply(opening).await?;

	let refused = client.respond(reply).await;
	assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
	Ok(())
}

/// An outside store anchors a pinned chain at the authority it names for the
/// chain's leaf, so a client pins the chain through it.
#[cfg(feature = "transport-cms")]
#[test]
fn an_outside_store_anchors_a_pinned_chain() -> Result<(), HandshakeError> {
	let server = TestCmsServer::generate("stub server");
	let store = PinningTrust::under(server.authority.to_owned(), vec![server.key_agreement.to_owned()]);

	let chain = CmsServerChain::new([server.authority.to_owned(), server.key_agreement.to_owned()])?;
	ProvisionedTrust::new(CmsServerIdentity::Chain(chain), Arc::new(store))?;
	Ok(())
}

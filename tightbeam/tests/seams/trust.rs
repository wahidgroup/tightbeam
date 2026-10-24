//! A trust store an outside crate defines through [`CertificateTrust`]
//! alone, and a server policy it defines through [`CertificateValidation`].
//!
//! [`PinningTrust`] trusts the certificates its operator pins, names the
//! trust anchor of each, and resolves a frame signer among them admitted for
//! the signer purpose. The crate's default `verify_frame` runs over it and
//! returns the admitted certificate in [`TrustVerification::Verified`].
//!
//! It reads a key by its [`CanonicalKey`], the rule that the contract of
//! [`CertificateTrust`] names.

use std::sync::Arc;

use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::{Secp256k1Policy, VerificationPolicy};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::crypto::x509::store::{CertificateTrust, TrustVerification};
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{CanonicalKey, ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::{TestCertificate, TestIdentity, TestKey, TestMessage};
use tightbeam::x509::Certificate;
use tightbeam::{Frame, Version};

#[cfg(feature = "transport-cms")]
use tightbeam::crypto::hpke::DhKemSecp256k1;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::crypto::profiles::DefaultCryptoProvider;
#[cfg(feature = "transport-hpke")]
use tightbeam::crypto::x509::policy::DirectTrustValidator;
#[cfg(feature = "transport-cms")]
use tightbeam::testing::TestCmsServer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::negotiation::RunnableProfile;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::SupportedProfiles;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::{Client, ClientConfig, Handshake, HandshakeError, Server, ServerConfig};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings};
#[cfg(feature = "transport-hpke")]
use tightbeam::transport::handshake::{Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust};

/// A store that trusts the certificates its operator pins, each by its
/// whole encoding, and admits the signers among them under the house
/// signer purpose.
#[derive(Debug)]
pub(crate) struct PinningTrust {
	/// The certificates the operator pinned.
	pinned: Vec<Arc<Certificate>>,
	/// The pinned certificates the signer purpose admits.
	signers: Vec<PeerCertificate<ErasedSigning>>,
	/// The anchor the operator names for every pin, or `None` when each pin
	/// is its own anchor.
	anchor: Option<Arc<Certificate>>,
}

impl PinningTrust {
	/// A store that pins `pinned`, each its own trust anchor. A certificate
	/// the signer purpose refuses stays pinned and resolves no signer, so its
	/// refusal drops here.
	pub(crate) fn of(pinned: Vec<Certificate>) -> Self {
		let purpose = KeyPurposes::HOUSE.signer;
		let admit = |certificate: &Certificate| PeerCertificate::parse(certificate.to_owned(), purpose);
		let signers = pinned.iter().filter_map(|certificate| admit(certificate).ok()).collect();
		let pinned = pinned.into_iter().map(Arc::new).collect();
		Self { pinned, signers, anchor: None }
	}

	/// A store that pins `pinned` under `anchor`, the authority that issued
	/// them, as the trust anchor of each.
	pub(crate) fn under(anchor: Certificate, pinned: Vec<Certificate>) -> Self {
		let anchor = Some(Arc::new(anchor));
		Self { anchor, ..Self::of(pinned) }
	}

	/// The pin that is `cert`.
	fn pin(&self, cert: &Certificate) -> Result<&Arc<Certificate>, CertificateValidationError> {
		let pin = self.pinned.iter().find(|pin| pin.as_ref() == cert);
		pin.ok_or(CertificateValidationError::CertificateNotTrusted)
	}
}

impl CertificateValidation for PinningTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The evaluation admits the certificate alone, so its pin drops here.
		self.pin(cert).map(drop)
	}
}

impl CertificateTrust for PinningTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.pin(cert).is_ok()
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		// The store trusts pins, so a chain's anchor is the one its leaf names.
		let leaf = chain.last().ok_or(CertificateValidationError::EmptyChain)?;
		self.trust_anchor(leaf)
	}

	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		let pin = self.pin(cert)?;
		let anchor = self.anchor.as_ref().unwrap_or(pin);
		Ok(Arc::clone(anchor))
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		let mut signers = self.signers.iter();
		signers.find(|signer| signer.certificate().is_named_by(sid).unwrap_or(false))
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		// A key whose canonical form the encoder refuses names no pin.
		let key = CanonicalKey::of(spki).ok()?;
		let holds_key = |pin: &&Arc<Certificate>| {
			let pinned = CanonicalKey::of(&pin.tbs_certificate.subject_public_key_info);
			pinned.is_ok_and(|pinned| pinned == key)
		};
		self.pinned.iter().find(holds_key).map(Arc::as_ref)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&const { Secp256k1Policy::new() }
	}
}

/// A frame that `identity` signed.
async fn signed_by(identity: &SigningIdentity) -> Frame {
	let builder = FrameBuilder::from(Version::V1).with_id(b"pinned-frame").with_order(1696521600);
	let builder = builder.with_message(TestMessage::sample(None));
	let mut frame = builder.build().expect("the frame builds");
	frame.sign_with_provider(identity).await.expect("the identity signs the frame");
	frame
}

/// The certificate of the signer `verification` verified, if it verified.
fn verified_signer(verification: TrustVerification<'_>) -> Option<&Certificate> {
	match verification {
		TrustVerification::Verified(signer, _) => Some(signer.certificate().as_ref()),
		_ => None,
	}
}

/// The crate's default frame verification resolves the signer through the
/// outside store and returns the certificate the store admitted.
#[tokio::test]
async fn an_outside_trust_verifies_a_frame_its_signer_signed() {
	let identity = TestIdentity::of(&TestKey::insecure_fixed_signing());
	let trust = PinningTrust::of(vec![identity.certificate().to_owned()]);
	let frame = signed_by(&identity).await;

	let verification = trust.verify_frame(&frame);
	assert_eq!(verified_signer(verification), Some(identity.certificate()));
}

/// The outside store reads one secp256k1 point in either SEC 1 form as one
/// key, so a certificate of the compressed form resolves to the pinned
/// certificate of its key.
#[test]
fn an_outside_trust_finds_a_pinned_key_in_its_compressed_form() {
	let pinned = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let compressed = TestCertificate::with_compressed_key(pinned.to_owned());
	let trust = PinningTrust::of(vec![pinned.to_owned()]);

	let enrolled = trust.enrolled_certificate(&compressed);
	assert_eq!(enrolled, Some(&pinned));
}

/// The key whose point is the generator of secp256k1, whose y-coordinate is
/// even (SEC 2 v2.0 §2.4.1). The compact form names the point of even y
/// (BIP 340), so a compact copy of this key decodes to the same point.
fn generator_key() -> SigningKey {
	let mut scalar = [0u8; 32];
	scalar[31] = 1;
	SigningKey::from_slice(&scalar).expect("one is a secp256k1 scalar")
}

/// The outside store reads a key in the compact form by its bits, as the
/// contract states, so a compact copy of a pinned key resolves to no enrolled
/// certificate, though the copy decodes to the pinned point.
#[test]
fn an_outside_trust_finds_no_pinned_key_in_its_compact_form() {
	let pinned = TestCertificate::self_signed(&generator_key());
	let compact = TestCertificate::with_compact_key(pinned.to_owned());
	let trust = PinningTrust::of(vec![pinned]);

	let enrolled = trust.enrolled_certificate(&compact);
	assert_eq!(enrolled, None);
}

/// A pinned certificate whose `extendedKeyUsage` names the server's purpose
/// alone is no frame signer, so its frame resolves no signer.
#[tokio::test]
async fn an_outside_trust_resolves_no_signer_of_another_purpose() {
	let key = TestKey::insecure_fixed_signing();
	let certificate = TestCertificate::self_signed(&key);
	let certificate = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.server]);
	let identity = TestIdentity::presenting(certificate.to_owned(), &key);
	let trust = PinningTrust::of(vec![certificate]);
	let frame = signed_by(&identity).await;

	let verification = trust.verify_frame(&frame);
	assert!(matches!(verification, TrustVerification::UnknownSigner));
}

/// A server policy an outside crate defines: it admits the one certificate
/// whose SubjectPublicKeyInfo it pins. A client runs it under each flow on
/// the server's identity certificate, through `with_server_policy`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct OutsidePin(SubjectPublicKeyInfoOwned);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl OutsidePin {
	/// The policy that pins the key of `certificate`, as a client takes it.
	fn of(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
		Arc::new(Self(certificate.tbs_certificate.subject_public_key_info.to_owned()))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl CertificateValidation for OutsidePin {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let pinned = cert.tbs_certificate.subject_public_key_info == self.0;
		pinned.then_some(()).ok_or(CertificateValidationError::PublicKeyNotPinned)
	}
}

/// The native profile of the house provider, which both endpoints run.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn house_profiles() -> SupportedProfiles {
	SupportedProfiles::from(RunnableProfile::<DefaultCryptoProvider>::native().descriptor())
}

/// A client of flow `F` under the house provider.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
type HouseClient<F> = Handshake<Client, F, DefaultCryptoProvider>;

/// A server of flow `F` under the house provider.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
type HouseServer<F> = Handshake<Server, F, DefaultCryptoProvider>;

/// An HPKE client that trusts the certificate of `server` and runs `policy`
/// as its server policy, beside the server of `server`.
#[cfg(feature = "transport-hpke")]
fn hpke_endpoints(
	server: SigningIdentity,
	policy: Arc<dyn CertificateValidation>,
) -> (HouseClient<Hpke>, HouseServer<Hpke>) {
	let trust = DirectTrustValidator::default().with_trust_chain([server.certificate().to_owned()]);
	let settings = HpkeClientSettings::new(LearnedTrust::new(trust));
	let client = ClientConfig::<Hpke, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("an anonymous client serves the client role");

	let settings = HpkeServerSettings::new();
	let purposes = KeyPurposes::HOUSE;
	let config = ServerConfig::<Hpke, DefaultCryptoProvider>::new(settings, server, house_profiles(), purposes);
	let config = config.expect("a test server identity serves the server role");
	let client = Handshake::client(client.with_server_policy([policy]));
	(client, Handshake::server(config))
}

/// A CMS client that pins the key-agreement certificate of `server` and runs
/// `policy` as its server policy, beside a server that holds `pair`.
#[cfg(feature = "transport-cms")]
fn cms_endpoints(
	server: &TestCmsServer,
	pair: CmsIdentityPair<DhKemSecp256k1>,
	policy: Arc<dyn CertificateValidation>,
) -> (HouseClient<Cms>, HouseServer<Cms>) {
	let identity = TestIdentity::of(&TestKey::insecure_fixed_signing());
	let settings = CmsClientSettings { trust: server.trust(), identity };
	let client = ClientConfig::<Cms, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("a test client identity serves the client role");

	let purposes = KeyPurposes::HOUSE;
	let config = ServerConfig::<Cms, DefaultCryptoProvider>::new(CmsServerSettings, pair, house_profiles(), purposes);
	let config = config.expect("a test server pair serves the server role");
	let client = Handshake::client(client.with_server_policy([policy]));
	(client, Handshake::server(config))
}

/// The outside policy reads the certificate an HPKE reply names, so it admits
/// the server whose key it pins.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_outside_policy_admits_the_hpke_server_it_pins() -> Result<(), HandshakeError> {
	let server = TestIdentity::of(&TestKey::insecure_fixed_signing());
	let expected = server.certificate().to_owned();
	let (mut client, mut server) = hpke_endpoints(server, OutsidePin::of(&expected));

	let reply = server.reply(client.start()?).await?;
	client.respond(reply).await?;
	assert_eq!(client.peer_certificate(), Some(&expected));
	Ok(())
}

/// The outside policy refuses an HPKE server whose key it does not pin,
/// though the client's trust admits that server.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_outside_policy_refuses_an_hpke_server_it_does_not_pin() -> Result<(), HandshakeError> {
	let server = TestIdentity::of(&TestKey::insecure_fixed_signing());
	let other = TestCertificate::self_signed(&TestKey::negation_of(&TestKey::insecure_fixed_signing()));
	let (mut client, mut server) = hpke_endpoints(server, OutsidePin::of(&other));

	let reply = server.reply(client.start()?).await?;
	let refused = client.respond(reply).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(
			CertificateValidationError::PublicKeyNotPinned
		))
	));
	Ok(())
}

/// The outside policy reads the pinned key-agreement certificate of a CMS
/// server, so a pin of its key admits the server after the server rotates
/// its signing certificate.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn an_outside_policy_admits_a_cms_server_after_its_signing_certificate_rotates() -> Result<(), HandshakeError> {
	let server = TestCmsServer::generate("outside policy server");
	let (pair, rotated) = server.rotated_pair();
	let (mut client, mut server) = cms_endpoints(&server, pair, OutsidePin::of(&server.key_agreement));

	let reply = server.reply(client.start()?).await?;
	client.respond(reply).await?;
	assert_eq!(client.peer_certificate(), Some(&rotated));
	Ok(())
}

/// The outside policy reads the pinned key-agreement certificate before the
/// opening, so a pin of the signing certificate refuses the CMS server
/// before the client seals anything to it.
#[cfg(feature = "transport-cms")]
#[test]
fn an_outside_policy_refuses_a_cms_server_before_the_opening() {
	let server = TestCmsServer::generate("outside policy server");
	let (mut client, _server) = cms_endpoints(&server, server.pair(), OutsidePin::of(&server.signing));

	let refused = client.start();
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(
			CertificateValidationError::PublicKeyNotPinned
		))
	));
}

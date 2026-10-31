//! A trust store an outside crate defines through [`CertificateTrust`] alone,
//! and a server policy it defines through [`CertificateValidation`].
//!
//! [`PinningTrust`] trusts the certificates its operator pins, and names the
//! trust anchor of each. The crate's defaults run over it:
//!
//! - `verify_frame` returns a pin the signer purpose admits, in [`TrustVerification::Verified`].
//! - `verify_presented`, over its `verify_chain`, anchors an HPKE client through `LearnedTrust::anchored`.
//! - `evaluate_presented`, over its `evaluate`, admits the client of a mutual server.
//! - `find_by_canonical_key` finds the pin of a session's canonical key.
//!
//! It reads a key by its [`CanonicalKey`], as the contract of
//! [`CertificateTrust`] names. [`IndexedTrust`] keeps the same pins in a
//! [`KeyIndex`] of its own, so it finds a canonical key with no decode, as the
//! built-in store does.

use std::sync::Arc;

use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::{Secp256k1Policy, VerificationPolicy};
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::{CertificateValidation, ChainValidator};
use tightbeam::crypto::x509::store::{CertificateTrust, TrustVerification};
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{CanonicalKey, ErasedSigning, KeyIndex, KeyPurposes, PeerCertificate};
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::{TestCertificate, TestIdentity, TestKey};
use tightbeam::x509::Certificate;
use tightbeam::Version;

#[cfg(feature = "transport-cms")]
use tightbeam::crypto::hpke::DhKemSecp256k1;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::crypto::profiles::DefaultCryptoProvider;
#[cfg(feature = "transport-cms")]
use tightbeam::testing::TestCmsServer;
#[cfg(feature = "transport-hpke")]
use tightbeam::transport::handshake::PeerAuthentication;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::{Client, Handshake, HandshakeError, HandshakeMessage, Server};
#[cfg(feature = "transport-hpke")]
use tightbeam::transport::handshake::{ClientConfig, Hpke, HpkeClientSettings, LearnedTrust, ServerConfig};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{Cms, CmsIdentityPair, CmsServerSettings};

use super::signed_by;
use crate::common::result::TestResult;

#[cfg(feature = "transport-cms")]
use super::{cms_client, native_server};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use super::{native_profile, replied};
#[cfg(feature = "transport-hpke")]
use crate::common::security::{hpke_client_config, hpke_client_config_presenting, pinning_validator, ServerMaterials};

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
	let identity = TestIdentity::insecure_fixed();
	let trust = PinningTrust::of(vec![identity.certificate().to_owned()]);
	let frame = signed_by(&identity, Version::V1).await;

	let verification = trust.verify_frame(&frame);
	assert_eq!(verified_signer(verification), Some(identity.certificate()));
}

/// A store that keeps the pin of a [`PinningTrust`] in a [`KeyIndex`] of its
/// own, and finds a key there as the built-in store finds it.
#[derive(Debug)]
struct IndexedTrust {
	/// The store that answers each lookup by certificate.
	pins: PinningTrust,
	/// The pin under the canonical form of its key.
	keys: KeyIndex<Certificate>,
}

impl IndexedTrust {
	/// A store that pins `pinned` and indexes its key.
	fn of(pinned: Certificate) -> Self {
		let mut keys = KeyIndex::default();
		let indexed = keys.insert(&pinned.tbs_certificate.subject_public_key_info, pinned.to_owned());
		indexed.expect("the canonical form of a fixture key encodes");
		let pins = PinningTrust::of(vec![pinned]);
		Self { pins, keys }
	}
}

impl CertificateValidation for IndexedTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		self.pins.evaluate(cert)
	}
}

impl CertificateTrust for IndexedTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.pins.is_trusted(cert)
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.pins.verify_chain(chain)
	}

	fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
		self.pins.trust_anchor(cert)
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		self.pins.find_by_signer_identifier(sid)
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		self.keys.find(spki)
	}

	/// The index finds `key` by its DER as it stands, with no decode.
	fn find_by_canonical_key(&self, key: &CanonicalKey) -> Option<&Certificate> {
		self.keys.get(key)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		self.pins.to_policy_ref()
	}
}

// An outside store finds the pin of a session's canonical key, which the
// compressed form of the pinned key gives.
tightbeam::tb_cases! {
	fn an_outside_trust_finds_a_pinned_key_by_its_canonical_form(
		store: fn(Certificate) -> Box<dyn CertificateTrust>
	) -> TestResult {
		let pinned = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let compressed = TestCertificate::with_compressed_key(pinned.to_owned());
		let trust = store(pinned.to_owned());
		let key = CanonicalKey::of(&compressed.tbs_certificate.subject_public_key_info)?;

		let found = trust.find_by_canonical_key(&key);
		assert_eq!(found, Some(&pinned));
		Ok(())
	}
	cases {
		/// The crate's default lookup by canonical key decodes the key and
		/// asks the outside store.
		through_the_default => |pinned| Box::new(PinningTrust::of(vec![pinned])),
		/// An outside store built on the crate's key index finds the key in
		/// that index, as the built-in store does.
		in_its_key_index => |pinned| Box::new(IndexedTrust::of(pinned)),
	}
}

/// The key whose point is the generator of secp256k1, whose y-coordinate is
/// even (SEC 2 v2.0 §2.4.1). The compact form names the point of even y
/// (BIP 340), so a compact copy of this key decodes to the same point.
fn generator_key() -> SigningKey {
	let mut scalar = [0u8; 32];
	scalar[31] = 1;
	SigningKey::from_slice(&scalar).expect("one is a secp256k1 scalar")
}

// An outside store enrols a certificate that presents a pinned key in
// another SEC 1 form by the key that form reads as.
tightbeam::tb_cases! {
	fn an_outside_trust_reads_a_pinned_key((form, enrolled): (fn(Certificate) -> Certificate, bool)) {
		let pinned = TestCertificate::self_signed(&generator_key());
		let presented = form(pinned.to_owned());
		let trust = PinningTrust::of(vec![pinned.to_owned()]);

		let found = trust.enrolled_certificate(&presented);
		assert_eq!(found, enrolled.then_some(&pinned));
	}
	cases {
		/// The outside store reads one secp256k1 point in either SEC 1 form
		/// as one key, so the compressed form resolves to the pin of its key.
		in_its_compressed_form_as_its_point => (TestCertificate::with_compressed_key, true),
		/// The outside store reads a key in the compact form by its bits, as
		/// the contract states, so a compact copy resolves to no pin, though
		/// the copy decodes to the pinned point.
		in_its_compact_form_as_its_bits => (TestCertificate::with_compact_key, false),
	}
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
	let frame = signed_by(&identity, Version::V1).await;

	let verification = trust.verify_frame(&frame);
	assert!(matches!(verification, TrustVerification::UnknownSigner));
}

/// A server policy an outside crate defines: it admits a client only beside
/// the issuer its operator names.
struct IssuedBy {
	/// The issuer that a client presents beside its certificate.
	issuer: Certificate,
}

impl CertificateValidation for IssuedBy {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		// The policy admits a client by the issuers it presents, so it
		// refuses a certificate read alone, whose contents drop here.
		let _ = cert;
		Err(CertificateValidationError::CertificateNotTrusted)
	}

	fn evaluate_presented(
		&self,
		issuers: &[Certificate],
		leaf: &Certificate,
	) -> Result<(), CertificateValidationError> {
		// The policy reads the issuers alone, so the leaf drops here.
		let _ = leaf;
		let presented = issuers.contains(&self.issuer);
		presented.then_some(()).ok_or(CertificateValidationError::CertificateNotTrusted)
	}
}

/// A chain that holds the outside policy hands it the issuers a client
/// presents, so the chain admits the client beside them.
#[test]
fn an_outside_policy_in_a_chain_admits_a_client_beside_its_issuers() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let policy = ChainValidator::default().add(IssuedBy { issuer: chain.intermediate.to_owned() });

	policy.evaluate_presented(&[chain.intermediate], &chain.leaf)?;
	Ok(())
}

/// A server policy an outside crate defines: it admits the one certificate
/// whose SubjectPublicKeyInfo it pins. A client runs it under each flow on
/// the server's identity certificate, through `with_server_policy`. It is
/// also the trust of an HPKE client, through `LearnedTrust::new`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct OutsidePin(SubjectPublicKeyInfoOwned);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl OutsidePin {
	/// The policy that pins the key of `certificate`.
	fn pinning(certificate: &Certificate) -> Self {
		Self(certificate.tbs_certificate.subject_public_key_info.to_owned())
	}

	/// The policy that pins the key of `certificate`, as a client takes its
	/// server policy.
	fn of(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
		Arc::new(Self::pinning(certificate))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl CertificateValidation for OutsidePin {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		let pinned = cert.tbs_certificate.subject_public_key_info == self.0;
		pinned.then_some(()).ok_or(CertificateValidationError::PublicKeyNotPinned)
	}
}

/// A client of flow `F` under the house provider.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
type HouseClient<F> = Handshake<Client, F, DefaultCryptoProvider>;

/// A server of flow `F` under the house provider.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
type HouseServer<F> = Handshake<Server, F, DefaultCryptoProvider>;

/// The certificate of the negation of the key of
/// [`TestKey::insecure_fixed_signing`], whose point shares the x-coordinate of
/// the house server key and differs in y.
#[cfg(feature = "transport-hpke")]
fn negated_certificate() -> Certificate {
	TestCertificate::self_signed(&TestKey::negation_of(&TestKey::insecure_fixed_signing()))
}

/// An HPKE client whose trust pins `trusted` and whose server policy is the
/// outside pin of the key of `pinned`.
#[cfg(feature = "transport-hpke")]
fn client_under_an_outside_policy(trusted: &Certificate, pinned: &Certificate) -> HouseClient<Hpke> {
	let config = hpke_client_config::<DefaultCryptoProvider>(pinning_validator(trusted));
	Handshake::client(config.with_server_policy([OutsidePin::of(pinned)]))
}

/// An anonymous HPKE client under the house provider that learns its server
/// through `trust`.
#[cfg(feature = "transport-hpke")]
fn client_learning_through(trust: LearnedTrust) -> HouseClient<Hpke> {
	let settings = HpkeClientSettings::new(trust);
	let config = ClientConfig::<Hpke, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE);
	Handshake::client(config.expect("an anonymous client serves the client role"))
}

/// An HPKE client anchored on an outside store that pins `pinned`, which
/// admits a server through the path validation the store defines.
#[cfg(feature = "transport-hpke")]
fn client_on_an_outside_store(pinned: &Certificate) -> HouseClient<Hpke> {
	let store = Arc::new(PinningTrust::of(vec![pinned.to_owned()]));
	client_learning_through(LearnedTrust::anchored(store))
}

/// An HPKE client whose learned trust runs the outside pin of the key of
/// `pinned` on the certificate each reply names, through `LearnedTrust::new`.
#[cfg(feature = "transport-hpke")]
fn client_through_an_outside_pin(pinned: &Certificate) -> HouseClient<Hpke> {
	let trust = LearnedTrust::new(OutsidePin::pinning(pinned));
	client_learning_through(trust)
}

/// The configuration of the HPKE server of `materials`, which runs the
/// native profile of the house provider.
#[cfg(feature = "transport-hpke")]
fn house_hpke_server(materials: &ServerMaterials) -> ServerConfig<Hpke, DefaultCryptoProvider> {
	let profile = native_profile::<DefaultCryptoProvider>();
	materials.hpke_server_config([profile])
}

/// The answer of `client` to the reply of the HPKE server of `materials`.
#[cfg(feature = "transport-hpke")]
async fn answer_of(
	client: &mut HouseClient<Hpke>,
	materials: &ServerMaterials,
) -> Result<HandshakeMessage, HandshakeError> {
	let mut server = Handshake::server(house_hpke_server(materials));
	let reply = replied(client, &mut server).await;
	client.respond(reply).await
}

/// A CMS client that pins the key-agreement certificate of `server` and runs
/// `policy` as its server policy, beside a server that holds `pair`.
#[cfg(feature = "transport-cms")]
fn cms_endpoints(
	server: &TestCmsServer,
	pair: CmsIdentityPair<DhKemSecp256k1>,
	policy: Arc<dyn CertificateValidation>,
) -> (HouseClient<Cms>, HouseServer<Cms>) {
	let client = cms_client::<DefaultCryptoProvider>(server.trust(), TestIdentity::insecure_fixed());
	let config = native_server::<Cms, DefaultCryptoProvider>(CmsServerSettings, pair);
	let client = Handshake::client(client.with_server_policy([policy]));
	(client, Handshake::server(config))
}

// An HPKE client admits the server whose key the outside part of its trust
// pins.
#[cfg(feature = "transport-hpke")]
tightbeam::tb_cases! {
	async fn an_hpke_client_admits_the_server_it_pins(client_of: fn(&Certificate) -> HouseClient<Hpke>) -> TestResult {
		let materials = ServerMaterials::fixed();
		let mut client = client_of(&materials.certificate);

		answer_of(&mut client, &materials).await?;
		assert_eq!(client.peer_certificate(), Some(materials.certificate.as_ref()));
		Ok(())
	}
	cases {
		/// The outside policy reads the certificate an HPKE reply names.
		under_an_outside_policy => |server| client_under_an_outside_policy(server, server),
		/// An HPKE client anchored on the outside store admits the server
		/// that the store pins.
		on_an_outside_store => client_on_an_outside_store,
		/// The outside pin, the validator of the learned trust, reads the
		/// certificate an HPKE reply names.
		through_an_outside_validator => client_through_an_outside_pin,
	}
}

// The outside pin refuses an HPKE server whose key shares its x-coordinate
// with the pinned key and differs in y, and the refusal is the error of the
// pin.
#[cfg(feature = "transport-hpke")]
tightbeam::tb_cases! {
	async fn an_outside_pin_refuses_an_hpke_server_of_another_key(client_of: fn(&Certificate) -> HouseClient<Hpke>) {
		let materials = ServerMaterials::fixed();
		let mut client = client_of(&materials.certificate);

		let refused = answer_of(&mut client, &materials).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::PublicKeyNotPinned
			))
		));
	}
	cases {
		/// The outside pin refuses the server as the server policy, though
		/// the client's trust admits that server.
		as_the_server_policy => |server| client_under_an_outside_policy(server, &negated_certificate()),
		/// The outside pin refuses the server as the validator of the
		/// learned trust.
		as_the_learned_trust => |_| client_through_an_outside_pin(&negated_certificate()),
	}
}

/// An HPKE client anchored on the outside store refuses a server whose
/// certificate the store does not pin.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_outside_store_refuses_an_hpke_server_it_does_not_pin() {
	let materials = ServerMaterials::fixed();
	let mut client = client_on_an_outside_store(&negated_certificate());

	let refused = answer_of(&mut client, &materials).await;
	assert!(matches!(
		refused,
		Err(HandshakeError::CertificateValidationError(
			CertificateValidationError::CertificateNotTrusted
		))
	));
}

/// The outside policy reads the pinned key-agreement certificate of a CMS
/// server, so a pin of its key admits the server after the server rotates
/// its signing certificate.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn an_outside_policy_admits_a_cms_server_after_its_signing_certificate_rotates() -> TestResult {
	let server = TestCmsServer::generate("outside policy server");
	let (pair, rotated) = server.rotated_pair();
	let (mut client, mut server) = cms_endpoints(&server, pair, OutsidePin::of(&server.key_agreement));

	let reply = replied(&mut client, &mut server).await;
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

/// A mutual HPKE server whose one client validator is the outside store
/// admits the client it pins. The default `evaluate_presented` reads the
/// client's certificate and drops the issuers its Finished presents.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_outside_store_admits_the_client_it_pins_beside_its_presented_issuers() -> TestResult {
	let chain = TestCertificate::insecure_fixed_chain()?;
	let identity = TestIdentity::presenting(chain.leaf.to_owned(), &chain.leaf_key).with_chain([chain.intermediate])?;
	let materials = ServerMaterials::fixed();
	let trust = pinning_validator(&materials.certificate);

	let client = hpke_client_config_presenting::<DefaultCryptoProvider>(trust, identity);
	let mut server = house_hpke_server(&materials);
	let validator: Arc<dyn CertificateValidation> = Arc::new(PinningTrust::of(vec![chain.leaf.to_owned()]));

	server.peer_authentication = PeerAuthentication::Anonymous.and(validator);

	let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));
	let reply = replied(&mut client, &mut server).await;
	let closing = client.respond(reply).await?;

	server.finish(closing).await?;

	let session = server.complete()?;
	assert_eq!(session.peer(), Some(&chain.leaf));
	Ok(())
}

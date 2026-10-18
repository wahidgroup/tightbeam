//! Shared fixtures for security threat integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use tightbeam::{
	asn1::OctetString,
	crypto::{
		cms::AuthEnvelopedData,
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		policy::Secp256k1Policy,
		profiles::{SecurityProfileDesc, TightbeamProfile},
		sign::{ecdsa::Secp256k1SigningKey, SigningIdentity},
		x509::policy::{CertificateValidation, DirectTrustValidator},
		x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
	},
	der::asn1::ObjectIdentifier,
	oids::{AES_128_GCM, AES_128_WRAP},
	random::OsRng,
	testing::{
		error::{FdrConfigError, TestingError},
		fixtures::{TestCertificate, TestKey},
	},
	x509::Certificate,
	TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::testing::TestCmsServer;

/// Build the standard testing error that threat scenarios use to signal an
/// observed insecure outcome, which becomes a spec `ModeMismatch`.
pub fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "security_threat",
		reason,
	}))
}

/// The sealed closing with the middle byte of its encrypted content flipped.
/// A flipped content byte is the one wire handle a MITM has on what the
/// closing seals: the client Finished or the anonymous attributes, and the
/// acknowledgement inside either.
pub fn flip_sealed_content(sealed_closing: &AuthEnvelopedData) -> Result<AuthEnvelopedData, TightBeamError> {
	let mut tampered = sealed_closing.to_owned();
	let content = tampered.auth_encrypted_content_info.encrypted_content.as_ref();
	let content = content.ok_or_else(|| expectation_failure("a sealed closing carries content"))?;
	let mut forged = content.as_bytes().to_vec();
	let middle = forged.len() / 2;

	forged[middle] ^= 0xFF;
	tampered.auth_encrypted_content_info.encrypted_content = Some(OctetString::new(forged)?);
	Ok(tampered)
}

/// The server credentials of a handshake fixture, over the fixed test key.
#[derive(Clone)]
pub struct ServerMaterials {
	/// The certificate the server presents.
	pub certificate: Arc<Certificate>,
	/// The provider of the server's static signing key.
	pub key_provider: Arc<dyn SigningKeyProvider>,
	/// The server's static secret key, which an observer test holds to show
	/// what it fails to open. It sits in an `Arc`, so the bundle is `Clone`
	/// without copying secret material.
	secret_key: Arc<k256::SecretKey>,
	/// The two identities a CMS server holds under one test authority: a
	/// signing certificate and a key-agreement certificate of one subject.
	#[cfg(feature = "transport-cms")]
	pub cms: Arc<TestCmsServer>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = TestKey::insecure_fixed_signing();
		let certificate = Arc::new(TestCertificate::self_signed(&signing_key));

		let secret_key_bytes = signing_key.to_bytes();
		let secret_key = k256::SecretKey::from_bytes(&secret_key_bytes).expect("valid secret key");

		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(server_key));
		Self {
			certificate,
			key_provider: provider,
			secret_key: Arc::new(secret_key),
			#[cfg(feature = "transport-cms")]
			cms: Arc::new(TestCmsServer::generate("tightbeam test server")),
		}
	}

	/// The server's static secret key, which an observer test holds.
	pub fn secret_key(&self) -> &k256::SecretKey {
		&self.secret_key
	}

	/// The certificate and its key as the one value a server signs under.
	pub fn identity(&self) -> SigningIdentity {
		let certificate = Arc::clone(&self.certificate);
		let key_provider = Arc::clone(&self.key_provider);
		SigningIdentity::new(certificate, key_provider).expect("the server key matches its certificate")
	}

	/// These materials with a certificate whose `extendedKeyUsage` names
	/// `purpose` alone.
	pub fn with_key_purpose(mut self, purpose: ObjectIdentifier) -> Self {
		let certificate = self.certificate.as_ref().to_owned();
		self.certificate = Arc::new(TestCertificate::with_key_purposes(certificate, [purpose]));
		self
	}
}

/// The client credentials of a mutual-authentication handshake fixture.
#[derive(Clone)]
pub struct ClientMaterials {
	/// The certificate the client presents.
	pub certificate: Arc<Certificate>,
	/// The provider of the client's signing key.
	pub key_provider: Arc<dyn SigningKeyProvider>,
}

impl ClientMaterials {
	/// A fresh random identity, distinct from any server materials.
	pub fn generate() -> Self {
		let signing_key = random_signing_key();
		Self::from_signing_key(signing_key)
	}

	/// A fixed-seed identity, for a scenario whose outcome names the client.
	pub fn deterministic() -> Self {
		let signing_key = deterministic_signing_key();
		Self::from_signing_key(signing_key)
	}

	/// A self-signed certificate over `signing_key`, beside the provider that
	/// proves it.
	fn from_signing_key(signing_key: Secp256k1SigningKey) -> Self {
		let certificate = Arc::new(test_certificate(&signing_key));
		let key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { certificate, key_provider }
	}

	/// The certificate and its key as the one value a handshake client takes.
	pub fn identity(&self) -> SigningIdentity {
		let certificate = Arc::clone(&self.certificate);
		let key_provider = Arc::clone(&self.key_provider);
		SigningIdentity::new(certificate, key_provider).expect("the client key matches its certificate")
	}

	/// These materials with a certificate whose `extendedKeyUsage` names
	/// `purpose` alone.
	pub fn with_key_purpose(mut self, purpose: ObjectIdentifier) -> Self {
		let certificate = self.certificate.as_ref().to_owned();
		self.certificate = Arc::new(TestCertificate::with_key_purposes(certificate, [purpose]));
		self
	}
}

/// A direct-trust validator that pins the given server certificate.
///
/// A handshake client fails closed without a validator (CWE-295), so every
/// session pins the identity of the server it dials.
pub fn pinning_validator(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
	let trust_chain = vec![certificate.to_owned()];
	let data = DirectTrustValidator::default().with_trust_chain(trust_chain);
	Arc::new(data)
}

/// A trust store that pins the given server certificate, for a CMS client.
pub fn pinning_trust_store(certificate: &Certificate) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let store = CertificateTrustBuilder::from(Secp256k1Policy::default())
		.with_certificate(certificate.to_owned())?
		.build();
	Ok(Arc::new(store))
}

/// The fixed-seed signing key, for a fixture that needs one stable identity.
pub fn deterministic_signing_key() -> Secp256k1SigningKey {
	TestKey::insecure_fixed_signing()
}

/// A fresh random signing key, for an identity unrelated to every other one.
pub fn random_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// A self-signed test certificate over `signing_key`.
pub fn test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
	TestCertificate::self_signed(signing_key)
}

/// The default profile descriptor, which every threat scenario shares.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

/// The strong profile (AES-256-GCM) of a downgrade test, which is the profile
/// the default provider runs.
pub fn strong_security_profile() -> SecurityProfileDesc {
	default_security_profile()
}

/// The weak profile (AES-128-GCM) of a downgrade test, which is the profile
/// the AES-128 test provider runs.
pub fn weak_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		aead: Some(AES_128_GCM),
		key_wrap: Some(AES_128_WRAP),
		..default_security_profile()
	}
}

/// The hooks and test doubles that the receipt and settlement threat scenarios
/// share.
#[cfg(all(
	any(feature = "transport-cms", feature = "transport-hpke"),
	feature = "transport-multiplex"
))]
mod receipt_fixtures {
	use std::sync::atomic::{AtomicUsize, Ordering};
	use std::sync::{Arc, Mutex};

	use tightbeam::asn1::OctetString;
	use tightbeam::transport::handshake::negotiation::{
		AuthorizationGrant, AuthorizationRefusal, TransportAuthorizer, TransportOffer,
	};
	use tightbeam::transport::handshake::receipt::{
		ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
	};
	use tightbeam::utils::marker::MaybeSendFuture;
	use tightbeam::TightBeamError;

	/// Whether `needle` appears as a contiguous window inside `haystack`.
	pub fn contains_window(haystack: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
		let haystack = haystack.as_ref();
		let needle = needle.as_ref();
		haystack.windows(needle.len()).any(|window| window == needle)
	}

	/// An authorizer that grants the requested budgets, with an optional
	/// settlement challenge, and keeps the default settlement.
	///
	/// The default settles a challenge-free receipt and refuses a challenged
	/// one, so an authorizer from `challenging` refuses every settlement.
	pub struct GrantingAuthorizer {
		challenge: Option<OctetString>,
	}

	impl GrantingAuthorizer {
		/// Grant without demanding a settlement answer.
		pub fn challenge_free() -> Self {
			Self { challenge: None }
		}

		/// Grant with the given settlement challenge attached.
		pub fn challenging(challenge: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
			let challenge = challenge.as_ref();
			Ok(Self { challenge: Some(OctetString::new(challenge)?) })
		}
	}

	impl TransportAuthorizer for GrantingAuthorizer {
		fn authorize<'a>(
			&'a self,
			offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move {
				Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: self.challenge.to_owned() })
			})
		}
	}

	/// An authorizer that grants budgets with a settlement challenge and counts
	/// every call to `settle`, so a scenario can prove whether the hook fired.
	pub struct SettleSpyAuthorizer {
		challenge: OctetString,
		settle_calls: Arc<AtomicUsize>,
	}

	impl SettleSpyAuthorizer {
		/// A spy that grants budgets with the given settlement challenge.
		pub fn challenging(challenge: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
			let challenge = challenge.as_ref();
			Ok(Self {
				challenge: OctetString::new(challenge)?,
				settle_calls: Arc::new(AtomicUsize::new(0)),
			})
		}

		/// Return the number of calls the `settle` hook has received so far.
		pub fn settle_calls(&self) -> usize {
			self.settle_calls.load(Ordering::SeqCst)
		}
	}

	impl TransportAuthorizer for SettleSpyAuthorizer {
		fn authorize<'a>(
			&'a self,
			offer: &'a TransportOffer,
		) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
			Box::pin(async move {
				Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(self.challenge.to_owned()) })
			})
		}

		fn settle<'a>(
			&'a self,
			_receipt: &'a SessionReceipt,
			_response: Option<&'a [u8]>,
		) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
			self.settle_calls.fetch_add(1, Ordering::SeqCst);
			Box::pin(async move { Ok(()) })
		}
	}

	/// An approver that approves every receipt and answers its challenge with
	/// one fixed settlement answer.
	pub struct PayingApprover {
		response: OctetString,
	}

	impl PayingApprover {
		/// An approver that answers every challenge with `response`.
		pub fn answering(response: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
			let response = response.as_ref();
			Ok(Self { response: OctetString::new(response)? })
		}
	}

	impl ReceiptApprover for PayingApprover {
		fn approve<'a>(
			&'a self,
			_receipt: &'a SessionReceipt,
		) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>> {
			Box::pin(async move { Ok(Some(self.response.to_owned())) })
		}
	}

	/// An observer that records every [`SessionOutcome`] the server hands it.
	#[derive(Default)]
	pub struct RecordingObserver {
		outcomes: Mutex<Vec<SessionOutcome>>,
	}

	impl RecordingObserver {
		/// A snapshot of the outcomes recorded so far.
		pub fn recorded(&self) -> Vec<SessionOutcome> {
			self.outcomes.lock().map(|outcomes| outcomes.to_owned()).unwrap_or_default()
		}
	}

	impl SessionObserver for RecordingObserver {
		fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()> {
			Box::pin(async move {
				if let Ok(mut outcomes) = self.outcomes.lock() {
					outcomes.push(outcome.to_owned());
				}
			})
		}
	}
}

#[cfg(all(
	any(feature = "transport-cms", feature = "transport-hpke"),
	feature = "transport-multiplex"
))]
pub use receipt_fixtures::*;

/// Endpoint configurations and message conversions for a hand-driven HPKE
/// handshake. Every step takes and returns the container that carries an HPKE
/// message, so a scenario converts where it inspects or tampers with one.
#[cfg(feature = "transport-hpke")]
mod hpke_handshake {
	use std::sync::Arc;

	use tightbeam::cms::content_info::ContentInfo;
	use tightbeam::crypto::profiles::SecurityProfileDesc;
	use tightbeam::crypto::sign::SigningIdentity;
	use tightbeam::crypto::x509::policy::CertificateValidation;
	use tightbeam::crypto::x509::KeyPurposes;
	use tightbeam::der::asn1::OctetStringRef;
	use tightbeam::der::{Any, Decode, Encode, Tag};
	use tightbeam::oids::DATA;
	use tightbeam::transport::handshake::{
		ClientConfig, ClientHello, HandshakeMessage, HandshakeProvider, Hpke, HpkeClientSettings, HpkeServerSettings,
		LearnedTrust, ServerConfig, ServerHandshake, SupportedProfiles,
	};

	use super::ServerMaterials;

	/// The configuration of an anonymous HPKE client that admits its server
	/// through `validator`.
	pub fn hpke_client_config<P: HandshakeProvider>(
		validator: Arc<dyn CertificateValidation>,
	) -> ClientConfig<Hpke, P> {
		let trust = LearnedTrust::from(validator);
		let config = ClientConfig::new(HpkeClientSettings::new(trust), KeyPurposes::HOUSE);
		config.expect("an anonymous client holds no identity to refuse")
	}

	/// The configuration of an HPKE client that admits its server through
	/// `validator` and presents `identity`.
	pub fn hpke_client_config_presenting<P: HandshakeProvider>(
		validator: Arc<dyn CertificateValidation>,
		identity: SigningIdentity,
	) -> ClientConfig<Hpke, P> {
		let mut settings = HpkeClientSettings::new(LearnedTrust::from(validator));
		settings.identity = Some(identity);
		let config = ClientConfig::new(settings, KeyPurposes::HOUSE);
		config.expect("a test client identity serves the client role")
	}

	/// The configuration of an HPKE server that presents the certificate of
	/// `materials`, runs `profiles` in preference order, and demands no client
	/// certificate.
	pub fn hpke_server_config<P: HandshakeProvider>(
		materials: &ServerMaterials,
		profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> ServerConfig<Hpke, P> {
		let settings = HpkeServerSettings::new();
		let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");
		let config = ServerConfig::new(settings, materials.identity(), profiles, KeyPurposes::HOUSE);
		config.expect("a test server identity serves the server role")
	}

	/// The DER of the `ClientHello` that `opening` carries as the OCTET
	/// STRING of its `ContentInfo`.
	pub fn carried_hello(opening: HandshakeMessage) -> Vec<u8> {
		let data = opening.data().expect("an HPKE opening is a ContentInfo");
		let octets = data.value().content.decode_as::<OctetStringRef<'_>>();
		let octets = octets.expect("the opening carries its hello as an OCTET STRING");
		octets.as_bytes().to_vec()
	}

	/// `hello` as the opening an HPKE server reads: a `ContentInfo` of type
	/// `id-data` whose OCTET STRING is its DER.
	pub fn hello_opening(hello: &ClientHello) -> HandshakeMessage {
		let der = hello.to_der().expect("a ClientHello encodes");
		let content = Any::new(Tag::OctetString, der).expect("the hello fits an OCTET STRING");
		let opening = HandshakeMessage::try_from(ContentInfo { content_type: DATA, content });
		opening.expect("the opening encodes")
	}

	/// The `ServerHandshake` that `reply` signs as its content.
	pub fn signed_handshake(reply: HandshakeMessage) -> ServerHandshake {
		let signed = reply.signed().expect("an HPKE reply is a SignedData").into_value();
		let econtent = signed.encap_content_info.econtent.expect("the reply carries its content");
		ServerHandshake::from_der(econtent.value()).expect("the reply signs a ServerHandshake")
	}

	/// `reply` with `handshake` in place of the content it signs, as a MITM
	/// rewrites it. The signature and every attribute stay as they were.
	pub fn rewritten_reply(reply: HandshakeMessage, handshake: &ServerHandshake) -> HandshakeMessage {
		let mut signed = reply.signed().expect("an HPKE reply is a SignedData").into_value();
		let der = handshake.to_der().expect("a ServerHandshake encodes");
		let content = Any::new(Tag::OctetString, der).expect("the content fits an OCTET STRING");
		signed.encap_content_info.econtent = Some(content);
		HandshakeMessage::try_from(signed).expect("the rewritten reply encodes")
	}
}

// Consumers sit behind wider feature gates, so a narrow feature combination
// compiles the helpers unused.
#[allow(unused_imports)]
#[cfg(feature = "transport-hpke")]
pub use hpke_handshake::*;

/// The baseline CMS pair that the loopback, receipt, and security threat
/// suites share. Each suite sets its own offers, hooks, or policies on the pair
/// and reuses the identities.
#[cfg(feature = "transport-cms")]
mod cms_pair {
	use std::sync::Arc;

	use tightbeam::crypto::hpke::DhKemSecp256k1;
	use tightbeam::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use tightbeam::crypto::sign::SigningIdentity;
	use tightbeam::crypto::x509::KeyPurposes;
	use tightbeam::transport::handshake::negotiation::SecurityOffer;
	use tightbeam::transport::handshake::{
		ClientConfig, Cms, CmsClientSettings, CmsServerSettings, HandshakeProvider, PeerAuthentication, ServerConfig,
		SupportedProfiles,
	};
	use tightbeam::x509::Certificate;
	use tightbeam::TightBeamError;

	use super::{ClientMaterials, ServerMaterials};

	/// The configuration of a CMS client that presents `identity` and seals
	/// to the CMS server of `materials`, whose two certificates the store of
	/// their authority admits.
	pub fn cms_client_config<P: HandshakeProvider<Kem = DhKemSecp256k1>>(
		materials: &ServerMaterials,
		identity: SigningIdentity,
	) -> ClientConfig<Cms, P> {
		let trust = materials.cms.trust();
		let config = ClientConfig::new(CmsClientSettings { trust, identity }, KeyPurposes::HOUSE);
		config.expect("a test client identity serves the client role")
	}

	/// The configuration of a CMS server that holds the two identities of
	/// `materials`, runs `profiles` in preference order, and records no client
	/// as its peer.
	pub fn cms_server_config<P: HandshakeProvider<Kem = DhKemSecp256k1>>(
		materials: &ServerMaterials,
		profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> ServerConfig<Cms, P> {
		let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");
		let config = ServerConfig::new(CmsServerSettings, materials.cms.pair(), profiles, KeyPurposes::HOUSE);
		config.expect("a test server pair serves the server role")
	}

	/// A CMS client and server over the fixture server identity, beside the
	/// certificate of the fresh identity that the client presents.
	///
	/// Each endpoint is held as its configuration, so a suite sets its offers
	/// and hooks on it and then creates the handshake.
	pub struct CmsHandshakePair {
		/// The client configuration, which presents the fresh identity.
		pub client: ClientConfig<Cms, DefaultCryptoProvider>,
		/// The server configuration.
		pub server: ServerConfig<Cms, DefaultCryptoProvider>,
		/// The certificate of the identity the client presents.
		pub client_certificate: Arc<Certificate>,
	}

	/// Build the pair.
	///
	/// - The client offers `client_profiles`, pins the server certificate, and presents a fresh identity.
	/// - The server runs `server_profiles` and authenticates its client under `peer_authentication`.
	pub fn cms_handshake_pair(
		materials: &ServerMaterials,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		peer_authentication: PeerAuthentication,
	) -> Result<CmsHandshakePair, TightBeamError> {
		let client_profiles: Vec<SecurityProfileDesc> = client_profiles.into_iter().collect();
		let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();
		let client_materials = ClientMaterials::generate();
		let client_certificate = Arc::clone(&client_materials.certificate);

		let mut client = cms_client_config(materials, client_materials.identity());
		client.security_offer = Some(SecurityOffer::new(client_profiles));

		// The server learns the client certificate from the closing it opens,
		// as it does in production. Seeding it here would test a
		// server that already knows what the handshake is meant to establish.
		let mut server = cms_server_config(materials, server_profiles);
		server.peer_authentication = peer_authentication;

		Ok(CmsHandshakePair { client, server, client_certificate })
	}
}

// Consumers (loopback, receipt fixtures, security threats) sit behind
// wider feature gates, so a narrow feature combination compiles the
// fixture unused.
#[allow(unused_imports)]
#[cfg(feature = "transport-cms")]
pub use cms_pair::*;

/// A CMS client and server pair that a receipt scenario drives by hand.
#[cfg(all(feature = "transport-cms", feature = "transport-multiplex"))]
mod cms_fixtures {
	use std::sync::Arc;

	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportAuthorizer, TransportOffer};
	use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
	use tightbeam::transport::handshake::{Client, Cms, Handshake, PeerAuthentication, Server};
	use tightbeam::TightBeamError;

	use super::{cms_handshake_pair, default_security_profile, ServerMaterials};

	/// The hooks installed on a [`cms_mutual_budget_pair`] fixture.
	#[derive(Default)]
	pub struct CmsSessionHooks {
		/// The budget-grant policy the server consults.
		pub authorizer: Option<Arc<dyn TransportAuthorizer>>,
		/// The approver the client consults before it countersigns.
		pub approver: Option<Arc<dyn ReceiptApprover>>,
		/// The observer the server reports each receipt outcome to.
		pub observer: Option<Arc<dyn SessionObserver>>,
	}

	/// A mutually authenticated CMS client and server with a budget-bearing
	/// transport offer, ready to drive by hand.
	pub struct CmsSessionPair {
		/// The client, before its opening.
		pub client: Handshake<Client, Cms, DefaultCryptoProvider>,
		/// The server, before the opening arrives.
		pub server: Handshake<Server, Cms, DefaultCryptoProvider>,
	}

	/// Build the pair. The client presents a fresh identity, pins the server of
	/// `materials`, and requests the `request` budgets.
	pub fn cms_mutual_budget_pair(
		materials: &ServerMaterials,
		request: MuxBudgets,
		hooks: CmsSessionHooks,
	) -> Result<CmsSessionPair, TightBeamError> {
		let profile = default_security_profile();
		let offer = TransportOffer::mux(4).with_budgets(request);
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
		let pair =
			cms_handshake_pair(materials, vec![profile], vec![profile], PeerAuthentication::mutual([validator]))?;

		let mut config = pair.client;
		config.transport_offer = Some(offer.to_owned());
		config.receipt_approver = hooks.approver;

		let mut server = pair.server;
		server.transport = Some(offer);
		server.transport_authorizer = hooks.authorizer;
		server.session_observer = hooks.observer;

		Ok(CmsSessionPair { client: Handshake::client(config), server: Handshake::server(server) })
	}
}

#[cfg(all(feature = "transport-cms", feature = "transport-multiplex"))]
pub use cms_fixtures::*;

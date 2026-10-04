//! Shared fixtures for security threat integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use tightbeam::{
	crypto::profiles::DefaultCryptoProvider,
	crypto::{
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		policy::Secp256k1Policy,
		profiles::{SecurityProfileDesc, TightbeamProfile},
		sign::ecdsa::Secp256k1SigningKey,
		x509::policy::{CertificateValidation, DirectTrustValidator},
		x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
	},
	oids::{AES_128_GCM, AES_128_WRAP},
	random::OsRng,
	testing::{
		error::{FdrConfigError, TestingError},
		fixtures::{TestCertificate, TestKey},
	},
	transport::handshake::HandshakeKeyManager,
	transport::state::ClientIdentity,
	x509::Certificate,
	TightBeamError,
};

/// Build the standard testing error that threat scenarios use to signal an
/// observed insecure outcome, which becomes a spec `ModeMismatch`.
pub fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "security_threat",
		reason,
	}))
}

/// The server credentials of a handshake fixture, over the fixed test key.
#[derive(Clone)]
pub struct ServerMaterials {
	/// The certificate the server presents.
	pub certificate: Arc<Certificate>,
	/// The provider of the server's static signing key.
	pub key_provider: Arc<dyn SigningKeyProvider>,
	/// The secret key a test decrypts an ECIES payload with. It sits in an
	/// `Arc`, so the bundle is `Clone` without copying secret material.
	secret_key: Arc<k256::SecretKey>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = TestKey::insecure_fixed_signing();
		let certificate = Arc::new(TestCertificate::self_signed(&signing_key));

		let secret_key_bytes = signing_key.to_bytes();
		let secret_key = k256::SecretKey::from_bytes(&secret_key_bytes).expect("valid secret key");

		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(server_key));
		Self { certificate, key_provider: provider, secret_key: Arc::new(secret_key) }
	}

	/// The secret key, which a test uses to decrypt an ECIES payload.
	pub fn secret_key(&self) -> &k256::SecretKey {
		&self.secret_key
	}
}

/// The client credentials of a mutual-authentication handshake fixture.
#[derive(Clone)]
pub struct ClientMaterials {
	/// The certificate the client presents.
	pub certificate: Arc<Certificate>,
	/// The key manager that holds the client's signing key.
	pub key_manager: Arc<HandshakeKeyManager<DefaultCryptoProvider>>,
	/// The same provider the key manager holds, for a key manager under
	/// another crypto provider.
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

	/// A self-signed certificate over `signing_key`, bound to the key manager
	/// that proves it.
	fn from_signing_key(signing_key: Secp256k1SigningKey) -> Self {
		let certificate = Arc::new(test_certificate(&signing_key));
		let key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		let key_manager = Arc::new(HandshakeKeyManager::new(Arc::clone(&key_provider)));
		Self { certificate, key_manager, key_provider }
	}

	/// The certificate and its key as the one value a handshake client takes.
	pub fn identity(&self) -> ClientIdentity<DefaultCryptoProvider> {
		ClientIdentity::new(Arc::clone(&self.certificate), Arc::clone(&self.key_manager))
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
	let store = CertificateTrustBuilder::from(Secp256k1Policy)
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
	any(feature = "transport-cms", feature = "transport-ecies"),
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
	any(feature = "transport-cms", feature = "transport-ecies"),
	feature = "transport-multiplex"
))]
pub use receipt_fixtures::*;

/// Endpoint configurations and message conversions for a hand-driven ECIES
/// handshake. Every step takes and returns the container that tunnels an ECIES
/// message, so a scenario converts where it inspects or tampers with one.
#[cfg(feature = "transport-ecies")]
mod ecies_handshake {
	use std::sync::Arc;

	use tightbeam::cms::enveloped_data::EnvelopedData;
	use tightbeam::cms::signed_data::SignedData;
	use tightbeam::crypto::profiles::SecurityProfileDesc;
	use tightbeam::crypto::x509::policy::CertificateValidation;
	use tightbeam::der::Encode;
	use tightbeam::transport::handshake::{
		ClientConfig, ClientHello, ClientKeyExchange, Ecies, EciesClientSettings, EciesServerSettings,
		HandshakeMessage, HandshakeProvider, LearnedTrust, ServerConfig, ServerHandshake, SupportedProfiles,
	};

	use super::ServerMaterials;

	/// The configuration of an anonymous ECIES client that admits its server
	/// through `validator`.
	pub fn ecies_client_config<P: HandshakeProvider>(
		validator: Arc<dyn CertificateValidation>,
	) -> ClientConfig<Ecies, P> {
		let trust = LearnedTrust::from(validator);
		ClientConfig::new(EciesClientSettings::new(trust))
	}

	/// The configuration of an ECIES server that presents the certificate of
	/// `materials`, runs `profiles` in preference order, and demands no client
	/// certificate.
	pub fn ecies_server_config<P: HandshakeProvider>(
		materials: &ServerMaterials,
		profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> ServerConfig<Ecies, P> {
		let settings = EciesServerSettings::new(Arc::clone(&materials.certificate));
		let key = Arc::clone(&materials.key_provider);
		let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");
		ServerConfig::new(settings, key, profiles)
	}

	/// The DER of the `ClientHello` that `opening` tunnels.
	pub fn tunneled_hello(opening: HandshakeMessage) -> Vec<u8> {
		let tunnel = opening.signed().expect("an ECIES opening travels in a SignedData");
		let hello = ClientHello::try_from(tunnel.value()).expect("the opening tunnels a ClientHello");
		hello.to_der().expect("a decoded ClientHello encodes")
	}

	/// `hello` as the opening an ECIES server reads.
	pub fn tunneled_opening(hello: &ClientHello) -> HandshakeMessage {
		let tunnel = SignedData::try_from(hello).expect("a ClientHello tunnels in a SignedData");
		HandshakeMessage::try_from(tunnel).expect("the tunnel encodes")
	}

	/// The `ServerHandshake` that `reply` tunnels.
	pub fn tunneled_handshake(reply: HandshakeMessage) -> ServerHandshake {
		let tunnel = reply.signed().expect("an ECIES reply travels in a SignedData");
		ServerHandshake::try_from(tunnel.value()).expect("the reply tunnels a ServerHandshake")
	}

	/// `handshake` as the reply an ECIES client reads.
	pub fn tunneled_reply(handshake: &ServerHandshake) -> HandshakeMessage {
		let tunnel = SignedData::try_from(handshake).expect("a ServerHandshake tunnels in a SignedData");
		HandshakeMessage::try_from(tunnel).expect("the tunnel encodes")
	}

	/// The `ClientKeyExchange` that `closing` carries.
	pub fn carried_key_exchange(closing: HandshakeMessage) -> ClientKeyExchange {
		let carrier = closing.enveloped().expect("an ECIES closing travels in an EnvelopedData");
		ClientKeyExchange::try_from(carrier.value()).expect("the closing carries a ClientKeyExchange")
	}

	/// `key_exchange` as the closing an ECIES server reads.
	pub fn carried_closing(key_exchange: &ClientKeyExchange) -> HandshakeMessage {
		let carrier = EnvelopedData::try_from(key_exchange).expect("a ClientKeyExchange travels in an EnvelopedData");
		HandshakeMessage::try_from(carrier).expect("the carrier encodes")
	}
}

// Consumers sit behind wider feature gates, so a narrow feature combination
// compiles the helpers unused.
#[allow(unused_imports)]
#[cfg(feature = "transport-ecies")]
pub use ecies_handshake::*;

/// The baseline CMS pair that the loopback, receipt, and security threat
/// suites share. Each suite sets its own offers, hooks, or policies on the pair
/// and reuses the identities.
#[cfg(feature = "transport-cms")]
mod cms_pair {
	use std::sync::Arc;

	use tightbeam::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use tightbeam::crypto::x509::store::CertificateTrust;
	use tightbeam::transport::handshake::negotiation::SecurityOffer;
	use tightbeam::transport::handshake::{
		ClientConfig, Cms, CmsClientSettings, CmsServerIdentity, CmsServerSettings, HandshakeProvider,
		PeerAuthentication, ProvisionedTrust, ServerConfig, SupportedProfiles,
	};
	use tightbeam::transport::state::ClientIdentity;
	use tightbeam::x509::Certificate;
	use tightbeam::TightBeamError;

	use super::{pinning_trust_store, ClientMaterials, ServerMaterials};

	/// The configuration of a CMS client that presents `identity` and
	/// encrypts to `server`, which `store` admits.
	pub fn cms_client_config<P: HandshakeProvider>(
		server: &Arc<Certificate>,
		store: Arc<dyn CertificateTrust>,
		identity: ClientIdentity<P>,
	) -> ClientConfig<Cms, P> {
		let pinned = CmsServerIdentity::Certificate(Arc::clone(server));
		let trust = ProvisionedTrust { identity: pinned, store };
		ClientConfig::new(CmsClientSettings { trust, identity })
	}

	/// The configuration of a CMS server that holds the key of `materials`,
	/// runs `profiles` in preference order, and records no client as its peer.
	pub fn cms_server_config<P: HandshakeProvider>(
		materials: &ServerMaterials,
		profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> ServerConfig<Cms, P> {
		let key = Arc::clone(&materials.key_provider);
		let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");
		ServerConfig::new(CmsServerSettings, key, profiles)
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
		let trust_store = pinning_trust_store(&materials.certificate)?;

		let mut client = cms_client_config(&materials.certificate, trust_store, client_materials.identity());
		client.security_offer = Some(SecurityOffer::new(client_profiles));

		// The server learns the client certificate from the KeyExchange it
		// processes, as it does in production. Seeding it here would test a
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

//! The key materials, trust stores, handshake configs, and authorizers of the
//! transport, security, colony, and seam suites.

use core::borrow::Borrow;
use std::sync::Arc;

use tightbeam::{
	crypto::{
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		policy::{ProviderPolicy, VerificationPolicy},
		profiles::{DefaultCryptoProvider, SecurityProfileDesc, TightbeamProfile},
		sign::{ecdsa::Secp256k1SigningKey, SigningIdentity},
		x509::policy::{CertificateValidation, DirectTrustValidator},
		x509::store::{CertificateTrust, CertificateTrustBuilder, CertificateTrustStore, NoRevocation, TrustBuilder},
		x509::{KeyCurves, KeyPurposes, PeerCertificate, Signing},
	},
	oids::{AES_128_GCM, AES_128_WRAP},
	policy::{GatePolicy, SessionContext, TransitStatus},
	random::OsRng,
	testing::{
		error::TestingError,
		fixtures::{TestCertificate, TestKey},
	},
	x509::Certificate,
	Frame, TightBeamError,
};

#[cfg(feature = "transport-cms")]
use tightbeam::testing::TestCmsServer;

/// Builds the testing error that a threat scenario returns for an insecure
/// outcome, which becomes a spec `ModeMismatch`.
pub fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::UnexpectedOutcome(reason))
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
	/// The fixed server credentials: a self-signed certificate over
	/// [`TestKey::insecure_fixed_signing`], beside the CMS server of the name
	/// `tightbeam test server`.
	pub fn fixed() -> Self {
		Self::of(TestKey::insecure_fixed_signing())
	}

	/// The credentials of `signing_key` under `certificate`, in place of its
	/// self-signed certificate.
	pub fn presenting(signing_key: Secp256k1SigningKey, certificate: Certificate) -> Self {
		let certificate = Arc::new(certificate);
		Self { certificate, ..Self::of(signing_key) }
	}

	/// A self-signed certificate over `signing_key`, beside the CMS server of
	/// the name `tightbeam test server`.
	fn of(signing_key: Secp256k1SigningKey) -> Self {
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

	/// The fixed client identity, over the key of seed `0x0c` from
	/// [`fixed_signing_key`]. This identity alone holds that key, so the pin of
	/// another fixture refuses this client.
	pub fn fixed() -> Self {
		let signing_key = fixed_signing_key(0x0c);
		Self::from_signing_key(signing_key)
	}

	/// The identity of `signing_key` under `certificate`, in place of its
	/// self-signed certificate, for a client that presents a leaf of an
	/// authority.
	pub fn presenting(signing_key: Secp256k1SigningKey, certificate: Certificate) -> Self {
		let certificate = Arc::new(certificate);
		Self { certificate, ..Self::from_signing_key(signing_key) }
	}

	/// A self-signed certificate over `signing_key`, beside the provider that
	/// proves it.
	fn from_signing_key(signing_key: Secp256k1SigningKey) -> Self {
		let certificate = Arc::new(TestCertificate::self_signed(&signing_key));
		let key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
		Self { certificate, key_provider }
	}

	/// The certificate and its key as the one value a handshake client takes.
	pub fn identity(&self) -> SigningIdentity {
		let certificate = Arc::clone(&self.certificate);
		let key_provider = Arc::clone(&self.key_provider);
		SigningIdentity::new(certificate, key_provider).expect("the client key matches its certificate")
	}
}

/// A direct-trust validator that pins the given server certificate.
///
/// A handshake client fails closed without a validator (CWE-295), so every
/// session pins the identity of the server it dials.
pub fn pinning_validator(certificate: &Certificate) -> Arc<dyn CertificateValidation> {
	let trust_chain = vec![certificate.to_owned()];
	let data = DirectTrustValidator::default().with_trust_chain(trust_chain);
	let data = data.expect("a test certificate encodes");
	Arc::new(data)
}

/// A trust store that pins the given server certificate, for a CMS client.
pub fn pinning_trust_store(certificate: &Certificate) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	Ok(combined_trust(&[certificate]))
}

/// A trust store under the policy of the provider `P` that anchors each of
/// `certificates`.
pub fn trust_under<P>(certificates: impl IntoIterator<Item = impl Borrow<Certificate>>) -> Arc<dyn CertificateTrust>
where
	ProviderPolicy<P>: VerificationPolicy + 'static,
{
	Arc::new(store_under::<P>(certificates))
}

/// A trust store under the house policy that anchors every certificate of
/// `certs`.
pub fn combined_trust(certs: &[&Certificate]) -> Arc<dyn CertificateTrust> {
	trust_under::<DefaultCryptoProvider>(certs.iter().copied())
}

/// A client-certificate validator that anchors every certificate of `certs`.
///
/// It serves the inbound mutual-TLS accept plane
/// (`ClusterTlsConfig::client_authentication`). Export scenarios turn it on
/// so the gateway can recognize first-party origin sessions.
pub fn combined_validator(certs: &[&Certificate]) -> Arc<dyn CertificateValidation> {
	Arc::new(store_under::<DefaultCryptoProvider>(certs.iter().copied()))
}

/// The store under the policy of the provider `P` that anchors each of
/// `certificates`.
fn store_under<P>(certificates: impl IntoIterator<Item = impl Borrow<Certificate>>) -> CertificateTrustStore
where
	ProviderPolicy<P>: VerificationPolicy + 'static,
{
	let mut builder = CertificateTrustBuilder::new(ProviderPolicy::<P>::default(), KeyCurves::HOUSE, NoRevocation);
	for certificate in certificates {
		let certificate: &Certificate = certificate.borrow();
		let anchored = builder.with_certificate(certificate.to_owned());
		builder = anchored.expect("a test certificate anchors");
	}

	builder.build()
}

/// The secp256k1 signing key whose secret scalar is thirty-two `seed` octets.
///
/// The crate's `TestKey::fixed` builds the same key and is crate-private, so
/// the integration suites hold this copy. Seed `0x01` gives the key of
/// [`TestKey::insecure_fixed_signing`].
///
/// # Panics
///
/// - `seed` is `0x00` or `0xff`, whose octets name no scalar below the group order.
pub fn fixed_signing_key(seed: u8) -> Secp256k1SigningKey {
	let scalar = Secp256k1SigningKey::from_bytes(&[seed; 32].into());
	scalar.expect("a seed from 0x01 to 0xfe names a scalar")
}

/// A fresh random signing key, for an identity unrelated to every other one.
///
/// Each call draws its own key, so a scenario that holds the identity trusts
/// it alone, and a dial that a released port carries to the listener of
/// another scenario fails its handshake.
pub fn random_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// A self-signed test certificate over `signing_key`.
pub fn test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
	TestCertificate::self_signed(signing_key)
}

/// A collector gate that admits a frame whose signature verifies under one
/// certificate, and refuses every other frame with `PermissionDenied`.
///
/// The gate reads a frame as it arrives, so it verifies the signature over a
/// body that is ciphertext.
pub struct SignatureGate {
	/// The signer of each frame that the gate admits.
	signer: PeerCertificate<Signing<DefaultCryptoProvider>>,
}

impl SignatureGate {
	/// The gate of the signer that `certificate` names.
	pub fn of(certificate: impl Into<Arc<Certificate>>) -> Self {
		let signer = PeerCertificate::parse(certificate, KeyPurposes::HOUSE.signer);
		Self { signer: signer.expect("a fixture certificate admits the house signer purpose") }
	}
}

impl GatePolicy for SignatureGate {
	fn evaluate(&self, frame: Option<&Frame>, _session: &SessionContext) -> TransitStatus {
		let verified = frame.is_some_and(|frame| frame.verify(&self.signer).is_ok());
		if verified {
			TransitStatus::Ok
		} else {
			TransitStatus::PermissionDenied
		}
	}
}

/// The default profile descriptor, which every threat scenario shares.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

/// The weak profile (AES-128-GCM) of a downgrade test: the profile of the
/// AES-128 test provider.
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
	use std::sync::{Mutex, PoisonError};

	use tightbeam::asn1::OctetString;
	use tightbeam::marker::MaybeSendFuture;
	use tightbeam::transport::handshake::negotiation::{
		AuthorizationGrant, AuthorizationRefusal, TransportAuthorizer, TransportOffer,
	};
	use tightbeam::transport::handshake::receipt::{
		ApprovalRefusal, ReceiptApprover, SessionObserver, SessionOutcome, SessionReceipt,
	};
	use tightbeam::x509::Certificate;
	use tightbeam::TightBeamError;

	/// An authorizer that grants the requested budgets, with an optional
	/// settlement challenge, and keeps the default settlement.
	///
	/// The default settles a challenge-free receipt and refuses a challenged
	/// one, so an authorizer from `challenging` refuses every settlement.
	///
	/// The crate leaves the authorization hook to the application and ships no
	/// authorizer, so no real instance runs.
	pub struct GrantingAuthorizer {
		challenge: Option<OctetString>,
	}

	impl GrantingAuthorizer {
		/// An authorizer that grants the budgets with no settlement challenge.
		pub fn challenge_free() -> Self {
			Self { challenge: None }
		}

		/// An authorizer that grants the budgets with the settlement challenge
		/// `challenge`.
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

	/// An authorizer that grants budgets with a settlement challenge and
	/// records the client of every call to `settle`, so a scenario can prove
	/// whether the hook fired, and for which client. A spy that expects an
	/// answer refuses every other answer.
	///
	/// The crate leaves the authorization hook to the application and ships no
	/// authorizer, so no real instance runs.
	pub struct SettleSpyAuthorizer {
		challenge: OctetString,
		expected: Option<OctetString>,
		settled_clients: Mutex<Vec<Certificate>>,
	}

	impl SettleSpyAuthorizer {
		/// A spy that grants budgets with the given settlement challenge and
		/// settles any answer.
		pub fn challenging(challenge: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
			let challenge = challenge.as_ref();
			Ok(Self {
				challenge: OctetString::new(challenge)?,
				expected: None,
				settled_clients: Mutex::default(),
			})
		}

		/// A spy that grants budgets with the settlement challenge `challenge`
		/// and settles the answer `response` alone.
		pub fn expecting(challenge: impl AsRef<[u8]>, response: impl AsRef<[u8]>) -> Result<Self, TightBeamError> {
			let expected = Some(OctetString::new(response.as_ref())?);
			Ok(Self { expected, ..Self::challenging(challenge)? })
		}

		/// The number of calls that the `settle` hook received so far.
		pub fn settle_calls(&self) -> usize {
			self.settled_clients().len()
		}

		/// The client certificate that each call to the `settle` hook
		/// received, in order.
		pub fn settled_clients(&self) -> Vec<Certificate> {
			let settled = self.settled_clients.lock();
			settled.expect("no settlement panicked while holding the record").to_owned()
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
			response: Option<&'a [u8]>,
			client: &'a Certificate,
		) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
			let settled = self.settled_clients.lock();
			let mut settled = settled.expect("no settlement panicked while holding the record");
			settled.push(client.to_owned());

			let expected = self.expected.as_ref().map(OctetString::as_bytes);
			let admitted = expected.is_none() || expected == response;
			Box::pin(async move { admitted.then_some(()).ok_or(AuthorizationRefusal { code: u32::MAX }) })
		}
	}

	/// An approver that approves every receipt and answers its challenge with
	/// one fixed settlement answer.
	///
	/// The crate leaves the approval hook to the application and ships no
	/// approver, so no real instance runs.
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
	///
	/// The crate leaves the outcome hook to the application and ships no
	/// observer, so no real instance runs.
	#[derive(Default)]
	pub struct RecordingObserver {
		outcomes: Mutex<Vec<SessionOutcome>>,
	}

	impl RecordingObserver {
		/// A snapshot of the outcomes recorded so far.
		pub fn recorded(&self) -> Vec<SessionOutcome> {
			self.outcomes.lock().unwrap_or_else(PoisonError::into_inner).to_owned()
		}
	}

	impl SessionObserver for RecordingObserver {
		fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()> {
			Box::pin(async move {
				let mut outcomes = self.outcomes.lock().unwrap_or_else(PoisonError::into_inner);
				outcomes.push(outcome.to_owned());
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
	use tightbeam::der::{Any, Encode, Tag};
	use tightbeam::oids::DATA;
	use tightbeam::transport::handshake::{
		ClientConfig, ClientHello, HandshakeMessage, HandshakeProvider, Hpke, HpkeClientSettings, HpkeServerSettings,
		LearnedTrust, ServerConfig, SupportedProfiles,
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

	impl ServerMaterials {
		/// The configuration of an HPKE server that presents the certificate
		/// of these materials, runs `profiles` in preference order, and
		/// demands no client certificate.
		pub fn hpke_server_config<P: HandshakeProvider>(
			&self,
			profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		) -> ServerConfig<Hpke, P> {
			let settings = HpkeServerSettings::new();
			let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");

			let config = ServerConfig::new(settings, self.identity(), profiles, KeyPurposes::HOUSE);
			config.expect("a test server identity serves the server role")
		}
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

	use super::{ClientMaterials, ServerMaterials};

	/// A CMS client and server over the fixture server identity, beside the
	/// certificate of the fixed identity that the client presents.
	///
	/// Each endpoint is a configuration, so a suite sets its offers and hooks,
	/// then creates the handshake.
	pub struct CmsHandshakePair {
		/// The client configuration, which presents the fixed identity.
		pub client: ClientConfig<Cms, DefaultCryptoProvider>,
		/// The server configuration, which holds the fixture server identity.
		pub server: ServerConfig<Cms, DefaultCryptoProvider>,
		/// The certificate of the identity the client presents.
		#[allow(dead_code)]
		pub client_certificate: Arc<Certificate>,
	}

	impl ServerMaterials {
		/// The configuration of a CMS client that presents `identity` and
		/// seals to the CMS server of these materials. Their authority's store
		/// admits both server certificates: the one the client pins and the
		/// one the reply carries.
		pub fn cms_client_config<P: HandshakeProvider<Kem = DhKemSecp256k1>>(
			&self,
			identity: SigningIdentity,
		) -> ClientConfig<Cms, P> {
			let trust = self.cms.trust();
			let config = ClientConfig::new(CmsClientSettings { trust, identity }, KeyPurposes::HOUSE);
			config.expect("a test client identity serves the client role")
		}

		/// The configuration of a CMS server that holds the two identities of
		/// these materials, runs `profiles` in preference order, and records
		/// no client as its peer.
		pub fn cms_server_config<P: HandshakeProvider<Kem = DhKemSecp256k1>>(
			&self,
			profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		) -> ServerConfig<Cms, P> {
			let profiles = SupportedProfiles::new(profiles).expect("a server fixture runs at least one profile");
			let config = ServerConfig::new(CmsServerSettings, self.cms.pair(), profiles, KeyPurposes::HOUSE);
			config.expect("a test server pair serves the server role")
		}

		/// Builds a [`CmsHandshakePair`] over these materials.
		///
		/// - The client offers `client_profiles`, pins the server
		///   certificate, and presents [`ClientMaterials::fixed`].
		/// - The server runs `server_profiles` and authenticates its client under `peer_authentication`.
		pub fn cms_pair(
			&self,
			client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
			server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
			peer_authentication: PeerAuthentication,
		) -> CmsHandshakePair {
			let client_profiles: Vec<SecurityProfileDesc> = client_profiles.into_iter().collect();
			let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();
			let client_materials = ClientMaterials::fixed();
			let client_certificate = Arc::clone(&client_materials.certificate);

			let mut client = self.cms_client_config(client_materials.identity());
			client.security_offer = Some(SecurityOffer::new(client_profiles));

			// The server learns the client certificate from the closing it
			// opens, as in production. A seeded certificate would test a server
			// that already knows what the handshake establishes.
			let mut server = self.cms_server_config(server_profiles);
			server.peer_authentication = peer_authentication;

			CmsHandshakePair { client, server, client_certificate }
		}
	}
}

// Consumers (loopback, receipt fixtures, security threats) sit behind
// wider feature gates, so a narrow feature combination compiles the
// fixture unused.
#[allow(unused_imports)]
#[cfg(feature = "transport-cms")]
pub use cms_pair::*;

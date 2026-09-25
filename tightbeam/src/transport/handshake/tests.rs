//! Shared test utilities for handshake protocol tests.
//!
//! The module holds the fixtures, helper functions, and data structures that
//! every handshake test module shares, so the tests carry no duplicate setup.
#![allow(unused)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

use core::time::Duration;
use std::error::Error;
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::cert::IssuerAndSerialNumber;
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::policy::Secp256k1Policy;
use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use crate::der::asn1::BitString;
use crate::der::asn1::GeneralizedTime;
use crate::der::asn1::ObjectIdentifier;
use crate::der::{Decode, Encode};
use crate::oids::{
	AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA256, SIGNER_ECDSA_WITH_SHA3_256,
	SIGNER_ECDSA_WITH_SHA3_512,
};
use crate::random::{generate_nonce, OsRng};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::negotiation::{RunnableProfile, SecurityAccept};
use crate::transport::handshake::{ClientHello, ClientKeyExchange, PeerAuthentication, ServerHandshake};
use crate::transport::wire_der::WireDer;
use crate::x509::serial_number::SerialNumber;
use crate::x509::time::Time;
use crate::x509::time::Validity;
use crate::x509::Certificate;
use crate::x509::{name::RdnSequence, TbsCertificate, Version};

#[cfg(feature = "transport-ecies")]
mod ecies {
	pub use crate::crypto::ecies::Secp256k1EciesMessage;
	pub use crate::crypto::x509::policy::DirectTrustValidator;
	pub use crate::transport::handshake::client::EciesHandshakeClient;
	pub use crate::transport::handshake::server::EciesHandshakeServer;
}

#[cfg(feature = "transport-ecies")]
use ecies::*;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use crate::cms::signed_data::SignedData;
	pub use crate::crypto::sign::elliptic_curve::PublicKey;
	pub use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	pub use crate::transport::handshake::client::CmsHandshakeClient;
	pub use crate::transport::handshake::server::CmsHandshakeServer;
}

#[cfg(feature = "transport-cms")]
use cms::*;

/// Create a default test security profile for handshake tests.
pub fn create_default_test_profile() -> SecurityProfileDesc {
	RunnableProfile::<DefaultCryptoProvider>::native().descriptor()
}

/// Test certificate data, so every test creates certificates the same way.
#[derive(Debug, Clone)]
pub struct TestCertificate {
	/// The signing key whose public key the certificate carries.
	pub signing_key: Secp256k1SigningKey,
	/// The certificate over the public key of `signing_key`.
	pub certificate: Certificate,
}

/// Test handshake data that holds every random value and key a handshake
/// uses.
#[derive(Debug, Clone)]
pub struct TestHandshakeData {
	/// The random value the client contributes.
	pub client_random: [u8; 32],
	/// The random value the server contributes.
	pub server_random: [u8; 32],
	/// The random base session key.
	pub base_session_key: [u8; 32],
	/// The transcript hash computed over the test handshake messages.
	pub transcript_hash: [u8; 32],
}

/// Create a test certificate with a secp256k1 keypair.
///
/// Every handshake test creates its certificate this way. The certificate
/// uses minimal valid data and a long validity period.
pub fn create_test_certificate() -> TestCertificate {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = create_test_certificate_inner(&signing_key).expect("Test certificate creation should succeed");
	TestCertificate { signing_key, certificate }
}

/// Create a test certificate with the provided secp256k1 keypair.
///
/// The certificate uses the provided signing key, so its public key matches
/// the private key.
pub fn create_test_certificate_from_key(signing_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn Error>> {
	create_test_certificate_inner(signing_key)
}

/// Create a certificate from a signing key. The public certificate helpers
/// share this body.
fn create_test_certificate_inner(signing_key: &Secp256k1SigningKey) -> Result<Certificate, Box<dyn Error>> {
	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key.to_public_key_der()?;

	let tbs_cert = TbsCertificate {
		version: Version::V3,
		serial_number: SerialNumber::new(&[1])?,
		signature: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256, parameters: None },
		issuer: RdnSequence::default(),
		validity: Validity {
			not_before: Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(0))?),
			not_after: Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(u32::MAX as u64))?),
		},
		subject: RdnSequence::default(),
		subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())?,
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: None,
	};

	Ok(Certificate {
		tbs_certificate: tbs_cert,
		signature_algorithm: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256, parameters: None },
		signature: BitString::new(0, vec![0; 64])?,
	})
}

/// Generate random test handshake data.
///
/// The function creates cryptographically random values for the client
/// random, the server random, and the base session key, then computes the
/// transcript hash.
pub fn generate_test_handshake_data() -> Result<TestHandshakeData, Box<dyn Error>> {
	let client_random = generate_nonce::<32>(None)?;
	let server_random = generate_nonce::<32>(None)?;
	let base_session_key = generate_nonce::<32>(None)?;
	let transcript_hash = compute_test_transcript_hash(client_random, &server_random, [], []);

	Ok(TestHandshakeData { client_random, server_random, base_session_key, transcript_hash })
}

/// Compute a test transcript hash from the ClientHello DER, server random,
/// and SPKI bytes.
pub fn compute_test_transcript_hash(
	client_hello: impl AsRef<[u8]>,
	server_random: &[u8; 32],
	spki_bytes: impl AsRef<[u8]>,
	accept_der: impl AsRef<[u8]>,
) -> [u8; 32] {
	let client_hello = client_hello.as_ref();
	let spki_bytes = spki_bytes.as_ref();
	let accept_der = accept_der.as_ref();
	let mut data = Vec::with_capacity(client_hello.len() + 32 + spki_bytes.len() + accept_der.len());
	data.extend_from_slice(client_hello);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);
	data.extend_from_slice(accept_der);

	let digest_arr = Sha3_256::digest(&data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr);

	digest
}

/// Create a test ClientHello message with the given client random.
pub fn create_test_client_hello(client_random: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
	let client_hello = ClientHello {
		client_random: OctetString::new(*client_random)?,
		security_offer: None,
		transport_offer: None,
	};
	Ok(client_hello.to_der()?)
}

/// Create a test ServerHandshake message with the given parameters.
pub fn create_test_server_handshake(
	certificate: &Certificate,
	server_random: &[u8; 32],
	signature: impl AsRef<[u8]>,
) -> Result<Vec<u8>, Box<dyn Error>> {
	let signature = signature.as_ref();
	let server_handshake = ServerHandshake {
		certificate: certificate.to_owned(),
		server_random: OctetString::new(*server_random)?,
		signature: OctetString::new(signature)?,
		security_accept: Some(WireDer::new(SecurityAccept::new(create_default_test_profile()))?),
		client_cert_required: false,
		transport_accept: None,
		session_receipt: None,
	};

	Ok(server_handshake.to_der()?)
}

/// Create a test ClientKeyExchange message with the given encrypted data.
pub fn create_test_client_key_exchange(encrypted_data: impl AsRef<[u8]>) -> Result<ClientKeyExchange, Box<dyn Error>> {
	let encrypted_data = encrypted_data.as_ref();
	let client_kex = ClientKeyExchange {
		encrypted_data: OctetString::new(encrypted_data)?,
		#[cfg(feature = "x509")]
		client_certificate: None,
		#[cfg(feature = "x509")]
		client_signature: None,
	};

	Ok(client_kex)
}

/// Generate a random secp256k1 signing key for tests.
pub fn create_test_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// Create the SHA3-256 digest algorithm identifier for CMS operations.
pub fn create_sha3_256_digest_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None }
}

/// Create the ECDSA with SHA3-256 signature algorithm identifier for CMS
/// operations.
pub fn create_ecdsa_sha3_256_signature_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None }
}

/// A SignedData over `content` by a fresh test key, for a step that refuses
/// it by state before reading it.
#[cfg(feature = "transport-cms")]
pub fn create_test_signed_data(content: impl AsRef<[u8]>) -> SignedData {
	let signing_key = create_test_signing_key();
	let digest_alg = create_sha3_256_digest_alg();
	let signature_alg = create_ecdsa_sha3_256_signature_alg();
	let builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(&signing_key, digest_alg, signature_alg)
		.expect("the builder accepts a test key");

	builder.build(content).expect("the SignedData signs")
}

/// Create test key pairs for cryptographic operations.
///
/// The function returns a tuple with these parts, in order:
///
/// 1. the sender private key,
/// 2. the sender SPKI,
/// 3. the recipient private key, and
/// 4. the recipient public key.
pub fn create_test_keypair() -> (
	SecretKey,
	SubjectPublicKeyInfoOwned,
	SecretKey,
	elliptic_curve::PublicKey<Secp256k1>,
) {
	let sender_key = SecretKey::random(&mut OsRng);
	let sender_pubkey = sender_key.public_key();
	let sender_spki = SubjectPublicKeyInfoOwned::from_key(sender_pubkey).expect("SPKI creation should succeed");

	let recipient_key = SecretKey::random(&mut OsRng);
	let recipient_pubkey = recipient_key.public_key();

	(sender_key, sender_spki, recipient_key, recipient_pubkey)
}

/// Create test User Keying Material (UKM) for key agreement.
pub fn create_test_ukm() -> UserKeyingMaterial {
	let ukm_bytes = generate_nonce::<64>(None).expect("UKM generation should succeed");
	UserKeyingMaterial::new(ukm_bytes.to_vec()).expect("UKM creation should succeed")
}

/// Create test recipient identifier for CMS operations.
pub fn create_test_recipient_id() -> KeyAgreeRecipientIdentifier {
	use x509_cert::name::Name;
	use x509_cert::serial_number::SerialNumber;

	KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
		issuer: Name::default(),
		serial_number: SerialNumber::new(&[0x01]).expect("Serial number creation should succeed"),
	})
}

/// Create test key encryption algorithm identifier (AES-256 key wrap).
pub fn create_test_key_enc_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: AES_256_WRAP, parameters: None }
}

/// Convert a signing key into an `Arc<dyn SigningKeyProvider>`.
///
/// Tests and simple use cases use it to wrap a signing key in a provider
/// trait object.
pub fn into_provider(signing_key: Secp256k1SigningKey) -> Arc<dyn SigningKeyProvider> {
	Arc::new(Secp256k1KeyProvider::from(signing_key))
}

/// Mutual authentication against `validator` alone.
pub fn mutual_with(validator: impl CertificateValidation + 'static) -> PeerAuthentication {
	let validator: Arc<dyn CertificateValidation> = Arc::new(validator);
	PeerAuthentication::mutual([validator])
}

/// Builder for test ECIES handshake servers with default settings.
#[cfg(feature = "transport-ecies")]
pub struct TestEciesServerBuilder {
	key: Option<Secp256k1SigningKey>,
	cert: Option<Certificate>,
	aad_domain: Option<&'static [u8]>,
}

#[cfg(feature = "transport-ecies")]
impl TestEciesServerBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { key: None, cert: None, aad_domain: None }
	}

	/// Set a specific signing key for the server.
	pub fn with_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.key = Some(key);
		self
	}

	/// Set a specific certificate for the server.
	pub fn with_certificate(mut self, cert: Certificate) -> Self {
		self.cert = Some(cert);
		self
	}

	/// Set the AAD domain tag for ECIES operations.
	pub fn with_aad_domain(mut self, domain: &'static [u8]) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Build the ECIES handshake server.
	pub fn build(self) -> Result<EciesHandshakeServer<DefaultCryptoProvider>, Box<dyn Error>> {
		let test_cert_data = if let Some(cert) = self.cert {
			let key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
			TestCertificate { signing_key: key, certificate: cert }
		} else {
			self.key
				.map(|key| -> Result<TestCertificate, Box<dyn Error>> {
					let cert = create_test_certificate_from_key(&key)?;
					Ok(TestCertificate { signing_key: key, certificate: cert })
				})
				.transpose()?
				.unwrap_or_else(create_test_certificate)
		};

		let default_profile = create_default_test_profile();
		Ok(EciesHandshakeServer::new(
			into_provider(test_cert_data.signing_key),
			Arc::new(test_cert_data.certificate),
			self.aad_domain,
			PeerAuthentication::Anonymous,
		)
		.with_supported_profiles(vec![default_profile]))
	}
}

#[cfg(feature = "transport-ecies")]
impl Default for TestEciesServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test ECIES handshake clients with default settings.
#[cfg(feature = "transport-ecies")]
pub struct TestEciesClientBuilder {
	aad_domain: Option<&'static [u8]>,
	trusted_certificate: Option<Certificate>,
}

#[cfg(feature = "transport-ecies")]
impl TestEciesClientBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { aad_domain: None, trusted_certificate: None }
	}

	/// Set the AAD domain tag for ECIES operations.
	pub fn with_aad_domain(mut self, domain: &'static [u8]) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Trust the given server certificate (attaches a direct-trust validator).
	///
	/// The client fails closed without a validator, so any test that
	/// processes a `ServerHandshake` must pin the server certificate here.
	pub fn with_trusted_certificate(mut self, certificate: Certificate) -> Self {
		self.trusted_certificate = Some(certificate);
		self
	}

	/// Build the ECIES handshake client.
	pub fn build(self) -> EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage> {
		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(self.aad_domain);
		if let Some(certificate) = self.trusted_certificate {
			let validator = DirectTrustValidator::default().with_trust_chain(vec![certificate]);
			client = client.with_certificate_validator(Arc::new(validator));
		}

		client
	}
}

#[cfg(feature = "transport-ecies")]
impl Default for TestEciesClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test CMS handshake servers with default settings.
#[cfg(feature = "transport-cms")]
pub struct TestCmsServerBuilder {
	key: Option<Secp256k1SigningKey>,
	peer_authentication: PeerAuthentication,
}

#[cfg(feature = "transport-cms")]
impl TestCmsServerBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { key: None, peer_authentication: PeerAuthentication::Anonymous }
	}

	/// Set a specific signing key for the server.
	pub fn with_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.key = Some(key);
		self
	}

	/// Set how the server authenticates its client.
	pub fn with_peer_authentication(mut self, peer_authentication: PeerAuthentication) -> Self {
		self.peer_authentication = peer_authentication;
		self
	}

	/// Build the CMS handshake server.
	pub fn build(self) -> (CmsHandshakeServer<DefaultCryptoProvider>, PublicKey<k256::Secp256k1>) {
		let test_key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
		let verifying_key = *test_key.verifying_key();

		let public_key = PublicKey::<k256::Secp256k1>::from(verifying_key);
		let provider = into_provider(test_key);
		let server = CmsHandshakeServer::<DefaultCryptoProvider>::new(provider, self.peer_authentication);

		(server, public_key)
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for test CMS handshake clients with default settings.
#[cfg(feature = "transport-cms")]
pub struct TestCmsClientBuilder {
	client_key: Option<Secp256k1SigningKey>,
	server_cert: Option<Certificate>,
}

#[cfg(feature = "transport-cms")]
impl TestCmsClientBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { client_key: None, server_cert: None }
	}

	/// Set a specific client signing key.
	pub fn with_client_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.client_key = Some(key);
		self
	}

	/// Set a specific server certificate.
	pub fn with_server_cert(mut self, cert: Certificate) -> Self {
		self.server_cert = Some(cert);
		self
	}

	/// Build the CMS handshake client.
	///
	/// The build attaches a trust store that pins the server certificate,
	/// because the client fails closed without one.
	pub fn build(self) -> Result<CmsHandshakeClient<DefaultCryptoProvider>, Box<dyn Error>> {
		let client_key = self.client_key.unwrap_or_else(|| create_test_certificate().signing_key);
		let server_cert = match self.server_cert {
			Some(cert) => cert,
			None => create_test_certificate_from_key(&create_test_certificate().signing_key)?,
		};

		let trust_store = CertificateTrustBuilder::from(Secp256k1Policy)
			.with_certificate(server_cert.to_owned())?
			.build();

		let client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			into_provider(client_key),
			Arc::new(server_cert),
		)
		.with_trust_store(Arc::new(trust_store) as Arc<dyn CertificateTrust>);

		Ok(client)
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

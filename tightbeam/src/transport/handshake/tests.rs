//! Shared test utilities for handshake protocol tests.
//!
//! This module provides common test fixtures, helper functions, and data structures
//! used across all handshake test modules to reduce duplication and improve maintainability.
#![allow(unused)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::sync::Arc;

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::{
	OctetString, AES_256_GCM_OID, AES_256_WRAP_OID, HASH_SHA3_256_OID, SIGNER_ECDSA_WITH_SHA256_OID,
	SIGNER_ECDSA_WITH_SHA3_256_OID, SIGNER_ECDSA_WITH_SHA3_512_OID,
};
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::crypto::negotiation::SecurityAccept;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
use crate::der::asn1::BitString;
use crate::der::asn1::ObjectIdentifier;
use crate::der::{Decode, Encode};
use crate::random::OsRng;
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::server::EciesHandshakeServer;
use crate::transport::handshake::{ClientHello, ClientKeyExchange, ServerHandshake};
use crate::x509::serial_number::SerialNumber;
use crate::x509::time::Validity;
use crate::x509::Certificate;
use crate::x509::{name::RdnSequence, TbsCertificate};

#[cfg(feature = "transport-cms")]
use crate::crypto::sign::elliptic_curve::PublicKey;
#[cfg(feature = "time")]
use crate::der::asn1::GeneralizedTime;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::client::CmsHandshakeClientSecp256k1;
#[cfg(feature = "x509")]
use crate::transport::handshake::client::EciesHandshakeClientSecp256k1;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::server::CmsHandshakeServerSecp256k1;
#[cfg(feature = "time")]
use crate::x509::time::Time;

/// Create a default test security profile for handshake tests.
pub fn create_default_test_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: HASH_SHA3_256_OID,
		#[cfg(feature = "aead")]
		aead: Some(AES_256_GCM_OID),
		#[cfg(feature = "aead")]
		aead_key_size: Some(32), // AES-256 uses 32-byte keys
		#[cfg(feature = "signature")]
		signature: Some(SIGNER_ECDSA_WITH_SHA3_512_OID),
		key_wrap: None,
	}
}

/// Test certificate data structure for consistent certificate creation across tests.
#[derive(Debug, Clone)]
pub struct TestCertificate {
	pub signing_key: Secp256k1SigningKey,
	pub certificate: Certificate,
}

/// Test handshake data structure containing all the random values and keys used in a handshake.
#[derive(Debug, Clone)]
pub struct TestHandshakeData {
	pub client_random: [u8; 32],
	pub server_random: [u8; 32],
	pub base_session_key: [u8; 32],
	pub transcript_hash: [u8; 32],
}

/// Create a test certificate with a secp256k1 keypair.
///
/// This provides a consistent way to create test certificates across all handshake tests.
/// The certificate uses minimal valid data and a long validity period for testing.
pub fn create_test_certificate() -> TestCertificate {
	let signing_key = Secp256k1SigningKey::random(&mut OsRng);
	let certificate = create_test_certificate_inner(&signing_key);
	TestCertificate { signing_key, certificate }
}

/// Create a test certificate with the provided secp256k1 keypair.
///
/// This creates a certificate using the provided signing key, ensuring the
/// certificate's public key matches the private key.
pub fn create_test_certificate_from_key(signing_key: &Secp256k1SigningKey) -> Certificate {
	create_test_certificate_inner(signing_key)
}

/// Internal function to create a certificate from a signing key.
#[cfg(feature = "time")]
fn create_test_certificate_inner(signing_key: &Secp256k1SigningKey) -> Certificate {
	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key.to_public_key_der().unwrap();

	let tbs_cert = TbsCertificate {
		version: crate::x509::Version::V3,
		serial_number: SerialNumber::new(&[1]).unwrap(),
		signature: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256_OID, parameters: None },
		issuer: RdnSequence::default(),
		validity: Validity {
			not_before: Time::GeneralTime(
				GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap(),
			),
			not_after: Time::GeneralTime(
				GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(u32::MAX as u64)).unwrap(),
			),
		},
		subject: RdnSequence::default(),
		subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes()).unwrap(),
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: None,
	};

	Certificate {
		tbs_certificate: tbs_cert,
		signature_algorithm: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA256_OID, parameters: None },
		signature: BitString::new(0, vec![0; 64]).unwrap(),
	}
}

/// Generate random test handshake data.
///
/// Creates cryptographically random values for client random, server random,
/// and base session key, then computes the transcript hash.
pub fn generate_test_handshake_data() -> TestHandshakeData {
	let client_random = crate::random::generate_nonce::<32>(None).unwrap();
	let server_random = crate::random::generate_nonce::<32>(None).unwrap();
	let base_session_key = crate::random::generate_nonce::<32>(None).unwrap();

	let transcript_hash = compute_test_transcript_hash(&client_random, &server_random, &[]);

	TestHandshakeData { client_random, server_random, base_session_key, transcript_hash }
}

/// Compute a test transcript hash from client random, server random, and SPKI bytes.
///
/// This mirrors the transcript hash computation used in the actual handshake protocols.
pub fn compute_test_transcript_hash(client_random: &[u8; 32], server_random: &[u8; 32], spki_bytes: &[u8]) -> [u8; 32] {
	use crate::crypto::hash::{Digest, Sha3_256};

	let mut data = Vec::with_capacity(32 + 32 + spki_bytes.len());
	data.extend_from_slice(client_random);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);

	let digest_arr = Sha3_256::digest(&data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr);

	digest
}

/// Create a test ClientHello message with the given client random.
pub fn create_test_client_hello(client_random: &[u8; 32]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let client_hello = ClientHello { client_random: OctetString::new(*client_random)?, security_offer: None };
	Ok(client_hello.to_der()?)
}

/// Create a test ServerHandshake message with the given parameters.
pub fn create_test_server_handshake(
	certificate: &Certificate,
	server_random: &[u8; 32],
	signature: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let server_handshake = ServerHandshake {
		certificate: certificate.clone(),
		server_random: OctetString::new(*server_random)?,
		signature: OctetString::new(signature)?,
		security_accept: Some(SecurityAccept::new(create_default_test_profile())),
		client_cert_required: false,
	};

	Ok(server_handshake.to_der()?)
}

/// Create a test ClientKeyExchange message with the given encrypted data.
pub fn create_test_client_key_exchange(encrypted_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
	let client_kex = ClientKeyExchange {
		encrypted_data: OctetString::new(encrypted_data)?,
		#[cfg(feature = "x509")]
		client_certificate: None,
		#[cfg(feature = "x509")]
		client_signature: None,
	};

	Ok(client_kex.to_der()?)
}

/// Create a test signing key for cryptographic operations.
///
/// Generates a random secp256k1 signing key for use in tests.
pub fn create_test_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// Create SHA3-256 digest algorithm identifier for CMS operations.
pub fn create_sha3_256_digest_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: HASH_SHA3_256_OID, parameters: None }
}

/// Create ECDSA with SHA3-256 signature algorithm identifier for CMS operations.
pub fn create_ecdsa_sha3_256_signature_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
}

/// Create test key pairs for cryptographic operations.
///
/// Returns a tuple of (sender_private_key, sender_spki, recipient_private_key, recipient_public_key).
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
	let ukm_bytes = crate::random::generate_nonce::<64>(None).expect("UKM generation should succeed");
	UserKeyingMaterial::new(ukm_bytes.to_vec()).expect("UKM creation should succeed")
}

/// Create test recipient identifier for CMS operations.
pub fn create_test_recipient_id() -> KeyAgreeRecipientIdentifier {
	use x509_cert::name::Name;
	use x509_cert::serial_number::SerialNumber;

	KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(crate::cms::cert::IssuerAndSerialNumber {
		issuer: Name::default(),
		serial_number: SerialNumber::new(&[0x01]).expect("Serial number creation should succeed"),
	})
}

/// Create test key encryption algorithm identifier (AES-256 key wrap).
pub fn create_test_key_enc_alg() -> AlgorithmIdentifierOwned {
	AlgorithmIdentifierOwned { oid: AES_256_WRAP_OID, parameters: None }
}

// ============================================================================
// Test Fixture Builders
// ============================================================================

/// Builder for creating test ECIES handshake servers with sensible defaults.
#[cfg(feature = "x509")]
pub struct TestEciesServerBuilder {
	key: Option<Secp256k1SigningKey>,
	cert: Option<Certificate>,
	aad_domain: Option<Vec<u8>>,
}

#[cfg(feature = "x509")]
impl TestEciesServerBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { key: None, cert: None, aad_domain: Some(b"test-domain".to_vec()) }
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
	pub fn with_aad_domain(mut self, domain: Vec<u8>) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Build the ECIES handshake server.
	pub fn build(self) -> EciesHandshakeServer<DefaultCryptoProvider> {
		let test_cert_data = if let Some(cert) = self.cert {
			let key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
			TestCertificate { signing_key: key, certificate: cert }
		} else {
			self.key
				.map(|key| {
					let cert = create_test_certificate_from_key(&key);
					TestCertificate { signing_key: key, certificate: cert }
				})
				.unwrap_or_else(|| create_test_certificate())
		};

		let mut server = EciesHandshakeServer::new(
			Arc::new(test_cert_data.signing_key),
			Arc::new(test_cert_data.certificate),
			self.aad_domain,
			None, // No client validators in tests by default
		); // Add default test profile to ensure server always has supported profiles
		server = server.with_supported_profiles(vec![create_default_test_profile()]);

		server
	}
}

#[cfg(feature = "x509")]
impl Default for TestEciesServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for creating test ECIES handshake clients with sensible defaults.
#[cfg(feature = "x509")]
pub struct TestEciesClientBuilder {
	aad_domain: Option<Vec<u8>>,
}

#[cfg(feature = "x509")]
impl TestEciesClientBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self { aad_domain: Some(b"test-domain".to_vec()) }
	}

	/// Set the AAD domain tag for ECIES operations.
	pub fn with_aad_domain(mut self, domain: Vec<u8>) -> Self {
		self.aad_domain = Some(domain);
		self
	}

	/// Build the ECIES handshake client.
	pub fn build(self) -> EciesHandshakeClientSecp256k1 {
		EciesHandshakeClientSecp256k1::new(self.aad_domain)
	}
}

#[cfg(feature = "x509")]
impl Default for TestEciesClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for creating test CMS handshake servers with sensible defaults.
#[cfg(feature = "transport-cms")]
pub struct TestCmsServerBuilder {
	key: Option<Secp256k1SigningKey>,
	transcript_hash: Option<[u8; 32]>,
}

#[cfg(feature = "transport-cms")]
impl TestCmsServerBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self {
			key: None,
			transcript_hash: Some([1u8; 32]), // Default test transcript
		}
	}

	/// Set a specific signing key for the server.
	pub fn with_key(mut self, key: Secp256k1SigningKey) -> Self {
		self.key = Some(key);
		self
	}

	/// Set a specific transcript hash.
	pub fn with_transcript_hash(mut self, hash: [u8; 32]) -> Self {
		self.transcript_hash = Some(hash);
		self
	}

	/// Build the CMS handshake server.
	pub fn build(self) -> (CmsHandshakeServerSecp256k1, PublicKey<k256::Secp256k1>) {
		use std::sync::Arc;
		use CmsHandshakeServerSecp256k1;

		let test_key = self.key.unwrap_or_else(|| create_test_certificate().signing_key);
		let verifying_key = *test_key.verifying_key();
		let transcript_hash = self.transcript_hash.unwrap_or_else(|| [1u8; 32]);

		let public_key = PublicKey::<k256::Secp256k1>::from(verifying_key);
		let server = CmsHandshakeServerSecp256k1::new(Arc::new(test_key), transcript_hash, None);
		(server, public_key)
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsServerBuilder {
	fn default() -> Self {
		Self::new()
	}
}

/// Builder for creating test CMS handshake clients with sensible defaults.
#[cfg(feature = "transport-cms")]
pub struct TestCmsClientBuilder {
	client_key: Option<Secp256k1SigningKey>,
	server_cert: Option<Certificate>,
	transcript_hash: Option<[u8; 32]>,
}

#[cfg(feature = "transport-cms")]
impl TestCmsClientBuilder {
	/// Create a new builder with default settings.
	pub fn new() -> Self {
		Self {
			client_key: None,
			server_cert: None,
			transcript_hash: Some([1u8; 32]), // Default test transcript
		}
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

	/// Set a specific transcript hash.
	pub fn with_transcript_hash(mut self, hash: [u8; 32]) -> Self {
		self.transcript_hash = Some(hash);
		self
	}

	/// Build the CMS handshake client.
	pub fn build(self) -> CmsHandshakeClientSecp256k1 {
		let client_key = self.client_key.unwrap_or_else(|| create_test_certificate().signing_key);
		let server_cert = self
			.server_cert
			.unwrap_or_else(|| create_test_certificate_from_key(&create_test_certificate().signing_key));
		let transcript_hash = self.transcript_hash.unwrap_or([1u8; 32]);

		let mut client = CmsHandshakeClientSecp256k1::new(
			DefaultCryptoProvider::default(),
			client_key,
			Arc::new(server_cert),
			transcript_hash,
		);

		client
	}
}

#[cfg(feature = "transport-cms")]
impl Default for TestCmsClientBuilder {
	fn default() -> Self {
		Self::new()
	}
}

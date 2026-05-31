//! Shared fixtures for security threat integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use tightbeam::{
	crypto::{
		key::{Secp256k1KeyProvider, SigningKeyProvider},
		profiles::{SecurityProfileDesc, TightbeamProfile},
		sign::ecdsa::Secp256k1SigningKey,
	},
	oids::{AES_128_GCM, AES_256_GCM, CURVE_SECP256K1, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256},
	random::OsRng,
	testing::{
		error::{FdrConfigError, TestingError},
		utils::{create_test_certificate, create_test_signing_key},
	},
	x509::Certificate,
	TightBeamError,
};

/// Build the standard testing error used by threat scenarios to signal that an
/// insecure outcome was observed (turns into a spec `ModeMismatch`).
pub fn expectation_failure(reason: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "security_threat",
		reason,
	}))
}

/// Generated server-side credentials for handshake orchestration.
#[derive(Clone)]
pub struct ServerMaterials {
	pub certificate: Arc<Certificate>,
	pub key_provider: Arc<dyn SigningKeyProvider>,
	/// Secret key for test verification (ECIES decryption). Held in an `Arc`
	/// so the bundle is `Clone` without copying secret material.
	secret_key: Arc<k256::SecretKey>,
}

impl ServerMaterials {
	pub fn generate() -> Self {
		let signing_key = create_test_signing_key();
		let certificate = Arc::new(create_test_certificate(&signing_key));

		let secret_key_bytes = signing_key.to_bytes();
		let secret_key = k256::SecretKey::from_bytes(&secret_key_bytes).expect("valid secret key");

		let server_key = Secp256k1SigningKey::from(signing_key);
		let provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(server_key));
		Self { certificate, key_provider: provider, secret_key: Arc::new(secret_key) }
	}

	/// Secret key for ECIES decryption (test verification only).
	pub fn secret_key(&self) -> &k256::SecretKey {
		&self.secret_key
	}
}

/// Deterministic signing key (fixed seed) for stable single-identity fixtures.
pub fn deterministic_signing_key() -> Secp256k1SigningKey {
	create_test_signing_key()
}

/// Fresh random signing key for distinct, unrelated identities.
pub fn random_signing_key() -> Secp256k1SigningKey {
	Secp256k1SigningKey::random(&mut OsRng)
}

/// Self-signed test certificate for the given signing key.
pub fn test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
	create_test_certificate(signing_key)
}

/// Default profile descriptor shared across threats.
pub fn default_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&TightbeamProfile)
}

/// Strong profile (AES-256-GCM) for downgrade testing.
pub fn strong_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: HASH_SHA3_256,
		aead: Some(AES_256_GCM),
		aead_key_size: Some(32),
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

/// Weak profile (AES-128-GCM) for downgrade testing.
pub fn weak_security_profile() -> SecurityProfileDesc {
	SecurityProfileDesc {
		digest: HASH_SHA3_256,
		aead: Some(AES_128_GCM),
		aead_key_size: Some(16),
		signature: Some(SIGNER_ECDSA_WITH_SHA3_256),
		kdf: Some(HASH_SHA3_256),
		curve: Some(CURVE_SECP256K1),
		key_wrap: None,
		kem: None,
	}
}

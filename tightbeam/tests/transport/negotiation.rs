//! Integration test for security profile negotiation.
//!
//! Demonstrates how a server configured with multiple security profiles (AES-256-GCM with SHA3-512
//! and AES-128-GCM with SHA3-256) negotiates with a client that offers profiles in preference order.

#![cfg(all(feature = "transport", feature = "x509", feature = "aead"))]

use std::sync::Arc;
use tightbeam::crypto::aead::{Aes128Gcm, Aes128GcmOid, Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::curves::Secp256k1Oid;
use tightbeam::crypto::ecies::Secp256k1EciesMessage;
use tightbeam::crypto::hash::{Sha3_256, Sha3_512};
use tightbeam::crypto::kdf::{HkdfSha3_256, HkdfSha3_256Oid};
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::profiles::{
	AeadProvider, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, SecurityProfile, SecurityProfileDesc,
	SigningProvider,
};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::exactly;
use tightbeam::oids::{AES_128_WRAP, AES_256_WRAP};
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::config::ScenarioConf;
use tightbeam::testing::utils::{create_test_certificate, create_test_signing_key};
use tightbeam::transport::handshake::client::EciesHandshakeClient;
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::server::EciesHandshakeServer;
use tightbeam::transport::handshake::HandshakeFinalization;

// ============================================================================
// AES-256-GCM with SHA3-512 Profile
// ============================================================================

#[derive(Debug, Default, Clone, Copy)]
struct Aes256Sha3_512Profile;

impl SecurityProfile for Aes256Sha3_512Profile {
	type DigestOid = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type KdfOid = HkdfSha3_256Oid;
	type CurveOid = Secp256k1Oid;
	type KemOid = tightbeam::crypto::kem::Kyber1024Oid;
	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_256_WRAP);
}

#[derive(Debug, Default, Clone, Copy)]
struct Aes256Sha3_512Provider {
	profile: Aes256Sha3_512Profile,
}

impl DigestProvider for Aes256Sha3_512Provider {
	type Digest = Sha3_512;
}

impl AeadProvider for Aes256Sha3_512Provider {
	type AeadCipher = Aes256Gcm;
	type AeadOid = Aes256GcmOid;
}

impl SigningProvider for Aes256Sha3_512Provider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for Aes256Sha3_512Provider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for Aes256Sha3_512Provider {
	type Curve = k256::Secp256k1;
	type EciesMessage = Secp256k1EciesMessage;
}

impl CryptoProvider for Aes256Sha3_512Provider {
	type Profile = Aes256Sha3_512Profile;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

// ============================================================================
// AES-128-GCM with SHA3-256 Profile
// ============================================================================

#[derive(Debug, Default, Clone, Copy)]
struct Aes128Sha3_256Profile;

impl SecurityProfile for Aes128Sha3_256Profile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type KdfOid = HkdfSha3_256Oid;
	type CurveOid = Secp256k1Oid;
	type KemOid = tightbeam::crypto::kem::Kyber1024Oid;
	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_128_WRAP);
}

#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)]
struct Aes128Sha3_256Provider {
	profile: Aes128Sha3_256Profile,
}

impl DigestProvider for Aes128Sha3_256Provider {
	type Digest = Sha3_256;
}

impl AeadProvider for Aes128Sha3_256Provider {
	type AeadCipher = Aes128Gcm;
	type AeadOid = Aes128GcmOid;
}

impl SigningProvider for Aes128Sha3_256Provider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for Aes128Sha3_256Provider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for Aes128Sha3_256Provider {
	type Curve = k256::Secp256k1;
	type EciesMessage = Secp256k1EciesMessage;
}

impl CryptoProvider for Aes128Sha3_256Provider {
	type Profile = Aes128Sha3_256Profile;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

// ============================================================================
// Spec Definitions
// ============================================================================

tb_assert_spec! {
	pub ProfileNegotiationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("handshake_start", exactly!(1)),
			("client_hello_sent", exactly!(1)),
			("server_hello_received", exactly!(1)),
			("client_kex_sent", exactly!(1)),
			("server_kex_received", exactly!(1)),
			("handshake_complete", exactly!(1)),
			("profile_verified", exactly!(1))
		]
	}
}

// ============================================================================
// Integration Test
// ============================================================================

tb_scenario! {
	name: profile_negotiation,
	config: ScenarioConf::<()>::builder()
		.with_spec(ProfileNegotiationSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			trace.event("handshake_start")?;
			// Create profile descriptors
			let profile_aes256_sha512 = SecurityProfileDesc::from(&Aes256Sha3_512Profile);
			let profile_aes128_sha256 = SecurityProfileDesc::from(&Aes128Sha3_256Profile);

			// Setup server certificate and key
			let server_signing_key = create_test_signing_key();
			let server_cert = create_test_certificate(&server_signing_key);
			let signing_key = Secp256k1SigningKey::from(server_signing_key);
			let server_key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));

			// Create client with offer: [AES-256, AES-128] (AES-256 preferred)
			let client_offer = SecurityOffer::new(vec![profile_aes256_sha512, profile_aes128_sha256]);
			let mut client = EciesHandshakeClient::<Aes256Sha3_512Provider, Secp256k1EciesMessage>::new(None)
				.with_security_offer(client_offer);

			// Create server supporting: [AES-128, AES-256] (different order to test negotiation)
			let mut server = EciesHandshakeServer::<Aes256Sha3_512Provider>::new(
				Arc::clone(&server_key_provider),
				Arc::new(server_cert.clone()),
				None,
				None,
			)
			.with_supported_profiles(vec![profile_aes128_sha256, profile_aes256_sha512]);

			// Perform handshake
			trace.event("client_hello_sent")?;
			let client_hello = client.build_client_hello()?;

			trace.event("server_hello_received")?;
			let server_handshake = server.process_client_hello(&client_hello).await?;

			trace.event("client_kex_sent")?;
			let client_kex = client.process_server_handshake(&server_handshake).await?;

			trace.event("server_kex_received")?;
			server.process_client_key_exchange(&client_kex).await?;

			trace.event("handshake_complete")?;
			let _client_cipher = client.complete()?;
			let _server_cipher = server.complete()?;

			// Verify: Server selected client's first preference (AES-256-GCM/SHA3-512)
			if server.selected_profile() == Some(profile_aes256_sha512) &&
			   client.selected_profile() == Some(profile_aes256_sha512) {
				trace.event("profile_verified")?;
			}

			Ok(())
		}
	}
}

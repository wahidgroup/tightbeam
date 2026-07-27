//! Integration test for security profile negotiation.
//!
//! Demonstrates how a server configured with multiple security profiles
//! (AES-256-GCM with SHA3-512 and AES-128-GCM with SHA3-256) negotiates
//! with a client that offers profiles in preference order.

#![cfg(all(
	feature = "transport",
	feature = "transport-ecies",
	feature = "x509",
	feature = "aead",
	feature = "tokio"
))]

use std::sync::Arc;

use tightbeam::crypto::aead::{Aes128GcmOid, Aes256Gcm, Aes256GcmOid};
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
use tightbeam::testing::{
	utils::{create_test_certificate, create_test_signing_key},
	SetupEnv,
};
use tightbeam::transport::handshake::client::EciesHandshakeClient;
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::server::EciesHandshakeServer;
use tightbeam::transport::handshake::HandshakeFinalization;
use tightbeam::x509::Certificate;

use crate::common::security::pinning_validator;

use tightbeam::utils::urn::Urn;

pub(crate) const CLIENT_HELLO_SENT: Urn<'static> = Urn::new("test", "event:negotiation/client-hello-sent");
pub(crate) const CLIENT_KEX_SENT: Urn<'static> = Urn::new("test", "event:negotiation/client-kex-sent");
pub(crate) const HANDSHAKE_COMPLETE: Urn<'static> = Urn::new("test", "event:negotiation/handshake-complete");
pub(crate) const HANDSHAKE_START: Urn<'static> = Urn::new("test", "event:negotiation/handshake-start");
pub(crate) const PROFILE_VERIFIED: Urn<'static> = Urn::new("test", "event:negotiation/profile-verified");
pub(crate) const SERVER_HELLO_RECEIVED: Urn<'static> = Urn::new("test", "event:negotiation/server-hello-received");
pub(crate) const SERVER_KEX_RECEIVED: Urn<'static> = Urn::new("test", "event:negotiation/server-kex-received");

/// Stronger profile: AES-256-GCM with SHA3-512. Selected when both sides
/// offer it, because AES-128 fails the default 256-bit strength floor.
#[derive(Debug, Default, Clone, Copy)]
struct Aes256Sha3_512Profile;

impl SecurityProfile for Aes256Sha3_512Profile {
	type DigestOid = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type KdfOid = HkdfSha3_256Oid;
	type CurveOid = Secp256k1Oid;
	#[cfg(feature = "kem")]
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

/// Weaker profile: AES-128-GCM with SHA3-256. Present in both offers so
/// negotiation must prefer the stronger peer-shared profile.
#[derive(Debug, Default, Clone, Copy)]
struct Aes128Sha3_256Profile;

impl SecurityProfile for Aes128Sha3_256Profile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type KdfOid = HkdfSha3_256Oid;
	type CurveOid = Secp256k1Oid;
	#[cfg(feature = "kem")]
	type KemOid = tightbeam::crypto::kem::Kyber1024Oid;
	const KEY_WRAP_OID: Option<ObjectIdentifier> = Some(AES_128_WRAP);
}

fn preferred_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&Aes256Sha3_512Profile)
}

fn fallback_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&Aes128Sha3_256Profile)
}

fn server_materials() -> (Certificate, Arc<dyn SigningKeyProvider>) {
	let server_signing_key = create_test_signing_key();
	let server_cert = create_test_certificate(&server_signing_key);
	let signing_key = Secp256k1SigningKey::from(server_signing_key);
	let server_key_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));
	(server_cert, server_key_provider)
}

tb_assert_spec! {
	pub ProfileNegotiationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(HANDSHAKE_START, exactly!(1)),
			(CLIENT_HELLO_SENT, exactly!(1)),
			(SERVER_HELLO_RECEIVED, exactly!(1)),
			(CLIENT_KEX_SENT, exactly!(1)),
			(SERVER_KEX_RECEIVED, exactly!(1)),
			(HANDSHAKE_COMPLETE, exactly!(1)),
			(PROFILE_VERIFIED, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: profile_negotiation,
	spec: ProfileNegotiationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			trace.event(HANDSHAKE_START)?;

			let preferred = preferred_profile();
			let fallback = fallback_profile();
			let (server_cert, server_key_provider) = server_materials();

			// Client prefers AES-256; server lists AES-128 first. Strength
			// floor still selects AES-256 when both offer it.
			let client_offer = SecurityOffer::new(vec![preferred, fallback]);
			let server_profiles = vec![fallback, preferred];
			let validator = pinning_validator(&server_cert);

			let mut client = EciesHandshakeClient::<Aes256Sha3_512Provider, Secp256k1EciesMessage>::new(None)
				.with_security_offer(client_offer)
				.with_certificate_validator(validator);
			let mut server = EciesHandshakeServer::<Aes256Sha3_512Provider>::new(
				Arc::clone(&server_key_provider),
				Arc::new(server_cert.to_owned()),
				None,
				None,
			)
			.with_supported_profiles(server_profiles);

			let client_hello = client.build_client_hello()?;
			trace.event(CLIENT_HELLO_SENT)?;

			let server_handshake = server.process_client_hello(&client_hello).await?;
			trace.event(SERVER_HELLO_RECEIVED)?;

			let client_kex = client.process_server_handshake(&server_handshake).await?;
			trace.event(CLIENT_KEX_SENT)?;

			server.process_client_key_exchange(&client_kex).await?;
			trace.event(SERVER_KEX_RECEIVED)?;

			let _client_cipher = client.complete()?;
			let _server_cipher = server.complete()?;
			trace.event(HANDSHAKE_COMPLETE)?;

			let server_selected = server.selected_profile() == Some(preferred);
			let client_selected = client.selected_profile() == Some(preferred);
			trace.event_with(PROFILE_VERIFIED, &[], server_selected && client_selected)?;

			Ok(())
		}
	}
}

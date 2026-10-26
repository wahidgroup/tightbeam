//! An integration test of security profile negotiation.
//!
//! The test shows how a server configured with two security profiles
//! (AES-256-GCM with SHA3-512 and AES-128-GCM with SHA3-256) negotiates
//! with a client that offers profiles in preference order.

#![cfg(all(
	feature = "transport",
	feature = "transport-hpke",
	feature = "x509",
	feature = "aead",
	feature = "tokio"
))]

use tightbeam::crypto::aead::Aes128GcmOid;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{Aes128Wrap, SecurityProfile, SecurityProfileDesc};
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::testing::{Aes256Sha3_512Profile, Aes256Sha3_512Provider, TestIdentity};
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::{Handshake, Hpke, HpkeServerSettings, ServerConfig, SupportedProfiles};
use tightbeam::TightBeamError;

use crate::common::security::{hpke_client_config, pinning_validator};

/// The weaker profile is AES-128-GCM with SHA3-256. The client offer and the
/// server list both include it, and the test provider runs the stronger
/// profile alone, so negotiation must select the stronger profile.
#[derive(Debug, Default, Clone, Copy)]
struct Aes128Sha3_256Profile;

impl SecurityProfile for Aes128Sha3_256Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type Curve = k256::Secp256k1;
	type KeyWrapOid = Aes128Wrap;
}

fn preferred_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&Aes256Sha3_512Profile)
}

fn fallback_profile() -> SecurityProfileDesc {
	SecurityProfileDesc::from(&Aes128Sha3_256Profile)
}

fn server_identity() -> SigningIdentity {
	TestIdentity::insecure_fixed()
}

/// The server lists the weaker profile first, and the provider runs the
/// stronger profile alone, so both ends select the client's preferred profile.
#[tokio::test]
async fn profile_negotiation() -> Result<(), TightBeamError> {
	let preferred = preferred_profile();
	let fallback = fallback_profile();
	let server_identity = server_identity();

	// The client prefers AES-256 and the server lists AES-128 first, but the
	// provider runs AES-256 alone, so the server selects AES-256.
	let client_offer = SecurityOffer::new(vec![preferred, fallback]);
	let server_profiles = SupportedProfiles::new([fallback, preferred])?;
	let validator = pinning_validator(server_identity.certificate());

	let mut config = hpke_client_config::<Aes256Sha3_512Provider>(validator);
	config.security_offer = Some(client_offer);

	let mut client = Handshake::client(config);

	let settings = HpkeServerSettings::new();
	let purposes = KeyPurposes::HOUSE;
	let server_config =
		ServerConfig::<Hpke, Aes256Sha3_512Provider>::new(settings, server_identity, server_profiles, purposes)?;
	let mut server = Handshake::server(server_config);

	let opening = client.start()?;
	let reply = server.reply(opening).await?;
	let closing = client.respond(reply).await?;
	server.finish(closing).await?;

	// Completion moves the terms out, so the test reads the selection first.
	assert_eq!(
		server.selected_profile(),
		Some(preferred),
		"the server must select the profile its provider runs"
	);
	assert_eq!(
		client.selected_profile(),
		Some(preferred),
		"the client must admit that selection"
	);

	let _client_session = client.complete()?;
	let _server_session = server.complete()?;
	Ok(())
}

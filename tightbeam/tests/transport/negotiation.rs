//! Integration test for security profile negotiation.
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
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{Aes256Sha3_512Profile, Aes256Sha3_512Provider, SetupEnv, TestIdentity};
use tightbeam::transport::handshake::negotiation::SecurityOffer;
use tightbeam::transport::handshake::{Handshake, Hpke, HpkeServerSettings, ServerConfig, SupportedProfiles};
use tightbeam::urn::Urn;

use crate::common::security::{hpke_client_config, pinning_validator};

pub(crate) const CLIENT_HELLO_SENT: Urn<'static> = tightbeam::urn!("test", "event:negotiation/client-hello-sent");
pub(crate) const CLIENT_KEX_SENT: Urn<'static> = tightbeam::urn!("test", "event:negotiation/client-kex-sent");
pub(crate) const HANDSHAKE_COMPLETE: Urn<'static> = tightbeam::urn!("test", "event:negotiation/handshake-complete");
pub(crate) const HANDSHAKE_START: Urn<'static> = tightbeam::urn!("test", "event:negotiation/handshake-start");
pub(crate) const PROFILE_VERIFIED: Urn<'static> = tightbeam::urn!("test", "event:negotiation/profile-verified");
pub(crate) const SERVER_HELLO_RECEIVED: Urn<'static> =
	tightbeam::urn!("test", "event:negotiation/server-hello-received");
pub(crate) const SERVER_KEX_RECEIVED: Urn<'static> = tightbeam::urn!("test", "event:negotiation/server-kex-received");

/// The weaker profile is AES-128-GCM with SHA3-256. The client offer and the
/// server list both include it, and the test provider does not run it, so
/// negotiation must select the stronger profile.
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

tb_assert_spec! {
	pub ProfileNegotiationSpec,
	V(1,0,0): {
		mode: Accept,
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
			let server_identity = server_identity();

			// The client prefers AES-256 and the server lists AES-128 first.
			// The provider runs AES-256 alone, so the server still selects it.
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
			trace.event(CLIENT_HELLO_SENT)?;

			let reply = server.reply(opening).await?;
			trace.event(SERVER_HELLO_RECEIVED)?;

			let closing = client.respond(reply).await?;
			trace.event(CLIENT_KEX_SENT)?;

			server.finish(closing).await?;
			trace.event(SERVER_KEX_RECEIVED)?;

			// Completion moves the terms out, so the selection is read first.
			let server_selected = server.selected_profile() == Some(preferred);
			let client_selected = client.selected_profile() == Some(preferred);

			let _client_session = client.complete()?;
			let _server_session = server.complete()?;
			trace.event(HANDSHAKE_COMPLETE)?;
			trace.event_with(PROFILE_VERIFIED, &[], server_selected && client_selected)?;

			Ok(())
		}
	}
}

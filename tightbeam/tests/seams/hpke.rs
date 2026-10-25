//! The HPKE handshake runs here under [`OutsideProvider`], a provider an
//! outside crate defines that names no HPKE suite.
//!
//! The flow derives its handshake secret from the ephemeral-ephemeral
//! agreement alone, so the provider's signature, digest, KDF, AEAD, and key
//! wrap are all it runs.

use std::sync::Arc;

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::Encode;
use tightbeam::oids::{HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, Handshake, Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust, PeerAuthentication,
	Server, ServerConfig, SupportedProfiles,
};

use super::{outside_identity, run_legs, OutsideProvider, CONTENT, OUTSIDE_KDF};

/// A client of the HPKE flow under the outside provider.
type OutsideClient = Handshake<Client, Hpke, OutsideProvider>;

/// A server of the HPKE flow under the outside provider.
type OutsideServer = Handshake<Server, Hpke, OutsideProvider>;

/// A client that pins the certificate of `server` and presents `identity`,
/// beside a server that holds `server` and authenticates its client under
/// `peer_authentication`, both under the outside provider.
fn outside_pair(
	server: SigningIdentity,
	identity: Option<SigningIdentity>,
	peer_authentication: PeerAuthentication,
) -> (OutsideClient, OutsideServer) {
	let pinned = DirectTrustValidator::default().with_trust_chain([server.certificate().to_owned()]);
	let mut settings = HpkeClientSettings::new(LearnedTrust::new(pinned));
	settings.identity = identity;
	let client = ClientConfig::<Hpke, OutsideProvider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("an outside client identity serves the client role");

	let native = RunnableProfile::<OutsideProvider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let server_settings = HpkeServerSettings::new();
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Hpke, OutsideProvider>::new(server_settings, server, profiles, purposes);
	let mut server_config = server_config.expect("an outside server identity serves the server role");
	server_config.peer_authentication = peer_authentication;
	(Handshake::client(client), Handshake::server(server_config))
}

/// The HPKE flow runs under a provider with no HPKE suite, and the client's
/// first record opens under the server's session keys.
#[tokio::test]
async fn an_outside_provider_runs_the_hpke_flow() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_pair(outside_identity(), None, PeerAuthentication::Anonymous);
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.keys().recv().open(&mut record)?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The profile the HPKE flow agrees on names the outside signature, digest,
/// and KDF.
#[tokio::test]
async fn the_hpke_flow_agrees_on_the_outside_algorithms() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_pair(outside_identity(), None, PeerAuthentication::Anonymous);
	run_legs(&mut client, &mut server).await;

	let profile = client.selected_profile().ok_or("the client holds no agreed profile")?;
	let named = (profile.signature, profile.digest, profile.kdf);
	let outside = (Some(SIGNER_ECDSA_WITH_SHA3_512), Some(HASH_SHA3_512), Some(OUTSIDE_KDF));
	assert_eq!(named, outside);
	Ok(())
}

/// A mutual server under the outside provider records the certificate of a
/// client whose Finished the outside signature proves.
#[tokio::test]
async fn an_outside_server_admits_an_outside_client_over_hpke() {
	let client_identity = outside_identity();
	let expected = client_identity.certificate().to_owned();
	let mutual = PeerAuthentication::mutual([Arc::new(ExpiryValidator) as _]);
	let (mut client, mut server) = outside_pair(outside_identity(), Some(client_identity), mutual);
	run_legs(&mut client, &mut server).await;

	assert_eq!(server.peer_certificate(), Some(&expected));
}

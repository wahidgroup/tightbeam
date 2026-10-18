//! The HPKE handshake under [`OutsideProvider`], a provider an outside crate
//! defines that names no HPKE suite.
//!
//! The flow derives its handshake secret from the ephemeral-ephemeral
//! agreement alone, so the provider's signature, digest, KDF, AEAD, and key
//! wrap are all it runs.

use std::sync::Arc;

use tightbeam::crypto::aead::DecryptContent;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
use tightbeam::oids::{HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, Handshake, Hpke, HpkeClientSettings, HpkeServerSettings, LearnedTrust, PeerAuthentication,
	Server, ServerConfig, SupportedProfiles,
};

use super::{outside_identity, outside_policy, run_legs, OutsideProvider, CONTENT, OUTSIDE_KDF};

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
	let mut client = ClientConfig::<Hpke, OutsideProvider>::new(settings);
	client.profiles = outside_policy();

	let native = RunnableProfile::<OutsideProvider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let mut server_config = ServerConfig::<Hpke, OutsideProvider>::new(HpkeServerSettings::new(), server, profiles);
	server_config.policy = outside_policy();
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

	let record = client_session.keys().send().encrypt_next(CONTENT, None)?;
	let opened = server_session.keys().recv().decrypt_content(&record)?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
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

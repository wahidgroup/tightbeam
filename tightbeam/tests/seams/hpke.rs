//! The HPKE handshake runs here under [`OutsideProvider`], a provider an
//! outside crate defines that names no HPKE suite.
//!
//! The flow derives its handshake secret from the ephemeral-ephemeral
//! agreement alone, so the provider's signature, digest, KDF, AEAD, and key
//! wrap are all it runs.

use std::sync::Arc;

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::ExpiryValidator;
use tightbeam::transport::handshake::{
	Client, Handshake, HandshakeError, Hpke, HpkeServerSettings, PeerAuthentication, Server,
};
use tightbeam::x509::Certificate;

use super::{
	agreed_algorithms, first_record_opened, forged_identity, native_server, outside_identity, replied, run_legs,
	OutsideProvider, CLIENT_SEED, CONTENT, OUTSIDE_ALGORITHMS, SERVER_SEED,
};
use crate::common::result::TestResult;
use crate::common::security::{hpke_client_config, hpke_client_config_presenting, pinning_validator};

/// A client of the HPKE flow under the outside provider.
pub(super) type OutsideClient = Handshake<Client, Hpke, OutsideProvider>;

/// A server of the HPKE flow under the outside provider.
pub(super) type OutsideServer = Handshake<Server, Hpke, OutsideProvider>;

/// An anonymous client under the outside provider that pins `server`, the
/// certificate of its server.
pub(super) fn outside_client(server: &Certificate) -> OutsideClient {
	let config = hpke_client_config::<OutsideProvider>(pinning_validator(server));
	Handshake::client(config)
}

/// A server under the outside provider that holds `server` and
/// authenticates its client under `peer_authentication`.
pub(super) fn outside_server(server: SigningIdentity, peer_authentication: PeerAuthentication) -> OutsideServer {
	let mut config = native_server::<Hpke, OutsideProvider>(HpkeServerSettings::new(), server);
	config.peer_authentication = peer_authentication;
	Handshake::server(config)
}

/// An anonymous client that pins the certificate of `server`, beside an
/// anonymous server that holds `server`, both under the outside provider.
fn outside_pair(server: SigningIdentity) -> (OutsideClient, OutsideServer) {
	let client = outside_client(server.certificate());
	(client, outside_server(server, PeerAuthentication::Anonymous))
}

/// The HPKE flow runs under a provider with no HPKE suite, and the client's
/// first record opens under the server's session keys.
#[tokio::test]
async fn an_outside_provider_runs_the_hpke_flow() -> TestResult {
	let pair = outside_pair(outside_identity(SERVER_SEED));
	let opened = first_record_opened(pair).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The profile the HPKE flow agrees on names the outside signature, digest,
/// and KDF.
#[tokio::test]
async fn the_hpke_flow_agrees_on_the_outside_algorithms() {
	let (mut client, mut server) = outside_pair(outside_identity(SERVER_SEED));

	run_legs(&mut client, &mut server).await;
	assert_eq!(agreed_algorithms(&client), Some(OUTSIDE_ALGORITHMS));
}

/// A client that presents `client` and pins the certificate of `server`,
/// beside a mutual server that holds `server`, both under the outside
/// provider.
fn mutual_pair(server: SigningIdentity, client: SigningIdentity) -> (OutsideClient, OutsideServer) {
	let validator = pinning_validator(server.certificate());
	let config = hpke_client_config_presenting::<OutsideProvider>(validator, client);
	let mutual = PeerAuthentication::Anonymous.and(Arc::new(ExpiryValidator::default()));
	(Handshake::client(config), outside_server(server, mutual))
}

/// A mutual server under the outside provider records the certificate of a
/// client whose Finished the outside signature proves.
#[tokio::test]
async fn an_outside_server_admits_an_outside_client_over_hpke() {
	let client_identity = outside_identity(CLIENT_SEED);
	let expected = client_identity.certificate().to_owned();

	let (mut client, mut server) = mutual_pair(outside_identity(SERVER_SEED), client_identity);
	run_legs(&mut client, &mut server).await;
	assert_eq!(server.peer_certificate(), Some(&expected));
}

/// A mutual server under the outside provider refuses a Finished whose
/// signature another key made than the key the certificate of the client
/// names. The client above, which differs by its signing key alone, is the
/// positive control.
#[tokio::test]
async fn an_outside_server_refuses_a_finished_that_another_key_signed() -> TestResult {
	let (mut client, mut server) = mutual_pair(outside_identity(SERVER_SEED), forged_identity(CLIENT_SEED));
	let reply = replied(&mut client, &mut server).await;
	let closing = client.respond(reply).await?;

	let refused = server.finish(closing).await;
	assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
	Ok(())
}

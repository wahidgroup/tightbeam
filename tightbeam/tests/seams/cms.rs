//! The CMS handshake runs here under [`OutsideProvider`], a provider an
//! outside crate defines that names no HPKE suite.
//!
//! The server holds two identities of one subject under one authority:
//!
//! - its signing key, behind the outside signing backend, and
//! - its key-agreement key, behind [`OutsideAgreementBackend`](super::OutsideAgreementBackend).
//!
//! The opening seals the base secret to the key-agreement certificate through
//! the outside KEM, and the provider's signature, digest, KDF, AEAD, and key
//! wrap run the rest of the flow.

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::testing::TestCmsServer;
use tightbeam::transport::handshake::{Client, Cms, CmsIdentityPair, CmsServerSettings, Handshake, Server};

use super::{
	agreed_algorithms, cms_client, first_record_opened, native_server, outside_agreement_identity_of, outside_identity,
	outside_identity_of, run_legs, OutsideKem, OutsideProvider, CLIENT_SEED, CONTENT, OUTSIDE_ALGORITHMS,
};
use crate::common::result::TestResult;

/// A client of the CMS flow under the outside provider.
type OutsideClient = Handshake<Client, Cms, OutsideProvider>;

/// A server of the CMS flow under the outside provider.
type OutsideServer = Handshake<Server, Cms, OutsideProvider>;

/// The two identities of `server` under the outside provider: its signing
/// key behind the outside signing backend, and its key-agreement key behind
/// the outside key-agreement backend.
fn outside_pair(server: &TestCmsServer) -> CmsIdentityPair<OutsideKem> {
	let signing = outside_identity_of(server.signing.to_owned(), server.signing_key.to_owned());
	let key_agreement = outside_agreement_identity_of(server.key_agreement.to_owned(), &server.key_agreement_key);
	let pair = CmsIdentityPair::new(signing, key_agreement);
	pair.expect("the two server certificates name one subject with two keys")
}

/// A client that pins the key-agreement certificate of `server` against the
/// store of its authority and presents `identity`, beside a server that
/// holds both identities of `server`, both under the outside provider.
fn outside_handshakes(server: &TestCmsServer, identity: SigningIdentity) -> (OutsideClient, OutsideServer) {
	let client = cms_client::<OutsideProvider>(server.trust(), identity);
	let server_config = native_server::<Cms, OutsideProvider>(CmsServerSettings, outside_pair(server));
	(Handshake::client(client), Handshake::server(server_config))
}

/// A CMS server whose keys derive from its name, and whose certificates its
/// authority, `CN=outside server authority`, issued.
fn outside_server() -> TestCmsServer {
	TestCmsServer::generate("outside server")
}

/// The CMS flow runs under a provider with no HPKE suite and a key-agreement
/// backend outside the crate, and the client's first record opens under the
/// server's session keys.
#[tokio::test]
async fn an_outside_provider_runs_the_cms_flow() -> TestResult {
	let pair = outside_handshakes(&outside_server(), outside_identity(CLIENT_SEED));
	let opened = first_record_opened(pair).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The profile the CMS flow agrees on names the outside signature, digest,
/// and KDF.
#[tokio::test]
async fn the_cms_flow_agrees_on_the_outside_algorithms() {
	let (mut client, mut server) = outside_handshakes(&outside_server(), outside_identity(CLIENT_SEED));
	run_legs(&mut client, &mut server).await;
	assert_eq!(agreed_algorithms(&client), Some(OUTSIDE_ALGORITHMS));
}

/// The client records the server's signing certificate as its peer, the one
/// whose key signed the reply, rather than the key-agreement certificate the
/// opening sealed to.
#[tokio::test]
async fn an_outside_client_records_the_signing_certificate() {
	let server = outside_server();
	let (mut client, mut server_handshake) = outside_handshakes(&server, outside_identity(CLIENT_SEED));
	run_legs(&mut client, &mut server_handshake).await;
	assert_eq!(client.peer_certificate(), Some(&server.signing));
}

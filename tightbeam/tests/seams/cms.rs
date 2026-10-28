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

use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::Encode;
use tightbeam::oids::{HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::random::OsRng;
use tightbeam::testing::TestCmsServer;
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, Cms, CmsClientSettings, CmsIdentityPair, CmsServerSettings, Handshake, Server, ServerConfig,
	SupportedProfiles,
};

use super::{
	outside_agreement_identity_of, outside_identity, outside_identity_of, run_legs, OutsideKem, OutsideProvider,
	CONTENT, OUTSIDE_KDF,
};

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
	let settings = CmsClientSettings { trust: server.trust(), identity };
	let client = ClientConfig::<Cms, OutsideProvider>::new(settings, KeyPurposes::HOUSE);
	let client = client.expect("an outside client identity serves the client role");

	let native = RunnableProfile::<OutsideProvider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);

	let pair = outside_pair(server);
	let purposes = KeyPurposes::HOUSE;
	let server_config = ServerConfig::<Cms, OutsideProvider>::new(CmsServerSettings, pair, profiles, purposes);
	let server_config = server_config.expect("an outside server pair serves the server role");

	(Handshake::client(client), Handshake::server(server_config))
}

/// A CMS server of fresh keys, whose certificates a fresh authority,
/// `CN=outside server authority`, issued.
fn outside_server() -> TestCmsServer {
	let signing_key = SigningKey::random(&mut OsRng);
	let key_agreement_key = SigningKey::random(&mut OsRng);
	TestCmsServer::of("outside server", signing_key, key_agreement_key)
}

/// The CMS flow runs under a provider with no HPKE suite and a key-agreement
/// backend outside the crate, and the client's first record opens under the
/// server's session keys.
#[tokio::test]
async fn an_outside_provider_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_handshakes(&outside_server(), outside_identity());
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.into_keys().recv_mut().open(&mut record)?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The profile the CMS flow agrees on names the outside signature, digest,
/// and KDF.
#[tokio::test]
async fn the_cms_flow_agrees_on_the_outside_algorithms() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_handshakes(&outside_server(), outside_identity());
	run_legs(&mut client, &mut server).await;

	let profile = client.selected_profile().ok_or("the client holds no agreed profile")?;
	let named = (profile.signature, profile.digest, profile.kdf);
	let outside = (Some(SIGNER_ECDSA_WITH_SHA3_512), Some(HASH_SHA3_512), Some(OUTSIDE_KDF));
	assert_eq!(named, outside);
	Ok(())
}

/// The client records the server's signing certificate as its peer, the one
/// whose key signed the reply, rather than the key-agreement certificate the
/// opening sealed to.
#[tokio::test]
async fn an_outside_client_records_the_signing_certificate() {
	let server = outside_server();
	let (mut client, mut server_handshake) = outside_handshakes(&server, outside_identity());
	run_legs(&mut client, &mut server_handshake).await;
	assert_eq!(client.peer_certificate(), Some(&server.signing));
}

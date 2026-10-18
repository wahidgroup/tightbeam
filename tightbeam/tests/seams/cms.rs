//! The CMS handshake under [`OutsideProvider`], a provider an outside crate
//! defines that names no HPKE suite.
//!
//! The opening seals the base secret to the server's certificate through the
//! outside KEM, and the provider's signature, digest, KDF, AEAD, and key wrap
//! run the rest of the flow.

use std::sync::Arc;

use tightbeam::crypto::aead::DecryptContent;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
use tightbeam::oids::{HASH_SHA3_512, SIGNER_ECDSA_WITH_SHA3_512};
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, Cms, CmsClientSettings, CmsServerIdentity, CmsServerSettings, Handshake, ProvisionedTrust,
	Server, ServerConfig, SupportedProfiles,
};

use super::{outside_identity, outside_policy, run_legs, OutsideProvider, CONTENT, OUTSIDE_KDF};

/// A client of the CMS flow under the outside provider.
type OutsideClient = Handshake<Client, Cms, OutsideProvider>;

/// A server of the CMS flow under the outside provider.
type OutsideServer = Handshake<Server, Cms, OutsideProvider>;

/// A client that provisions the certificate of `server` and presents
/// `identity`, beside a server that holds `server`, both under the outside
/// provider.
fn outside_pair(server: SigningIdentity, identity: SigningIdentity) -> (OutsideClient, OutsideServer) {
	let store = CertificateTrustBuilder::from(Secp256k1Policy::default());
	let store = store.with_certificate(server.certificate().to_owned());
	let store = store.expect("the store holds the server certificate").build();
	let provisioned = CmsServerIdentity::Certificate(server.certificate_arc());
	let trust = ProvisionedTrust { identity: provisioned, store: Arc::new(store) };
	let mut client = ClientConfig::<Cms, OutsideProvider>::new(CmsClientSettings { trust, identity });
	client.profiles = outside_policy();

	let native = RunnableProfile::<OutsideProvider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);

	let mut server_config = ServerConfig::<Cms, OutsideProvider>::new(CmsServerSettings, server, profiles);
	server_config.policy = outside_policy();
	(Handshake::client(client), Handshake::server(server_config))
}

/// The CMS flow runs under a provider with no HPKE suite, and the client's
/// first record opens under the server's session keys.
#[tokio::test]
async fn an_outside_provider_runs_the_cms_flow() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_pair(outside_identity(), outside_identity());
	run_legs(&mut client, &mut server).await;

	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let record = client_session.keys().send().encrypt_next(CONTENT, None)?;
	let opened = server_session.keys().recv().decrypt_content(&record)?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The profile the CMS flow agrees on names the outside signature, digest,
/// and KDF.
#[tokio::test]
async fn the_cms_flow_agrees_on_the_outside_algorithms() -> Result<(), Box<dyn std::error::Error>> {
	let (mut client, mut server) = outside_pair(outside_identity(), outside_identity());
	run_legs(&mut client, &mut server).await;

	let profile = client.selected_profile().ok_or("the client holds no agreed profile")?;
	let named = (profile.signature, profile.digest, profile.kdf);
	let outside = (Some(SIGNER_ECDSA_WITH_SHA3_512), Some(HASH_SHA3_512), Some(OUTSIDE_KDF));
	assert_eq!(named, outside);
	Ok(())
}

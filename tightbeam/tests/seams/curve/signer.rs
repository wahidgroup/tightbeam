//! The handshake and the rekey run here under [`MixedProvider`], which signs
//! under ECDSA over P-384 and agrees over secp256k1. A P-384 key is no point
//! of secp256k1, so a client compares the server's ephemeral with the
//! server's key-agreement key alone.
//!
//! These suites run under it, each with a client that presents a P-384
//! identity:
//!
//! - both handshake flows, under mutual authentication, and
//! - an in-band renewal of a multiplexed session over TCP.

use std::error::Error;
use std::sync::Arc;

use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::hash::Sha3_512;
use tightbeam::crypto::hpke::{HkdfSha256, KEM_DHKEM_SECP256K1_HKDF_SHA256};
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{
	AeadProvider, Aes256Wrap, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, KeyWrapProvider,
	SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::DirectTrustValidator;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::transport::handshake::negotiation::RunnableProfile;
use tightbeam::transport::handshake::{
	Client, ClientConfig, Cms, CmsClientSettings, CmsServerSettings, Handshake, Hpke, HpkeClientSettings,
	HpkeServerSettings, LearnedTrust, PeerAuthentication, ProvisionedTrust, Server, ServerConfig, ServerFlow,
	SupportedProfiles,
};

use super::p384::{p384_cms_server, p384_identity, P384Signature, P384VerifyingKey};
use super::{admitted_and_opened, OutsideCmsServer, OutsideKem, OutsideKemOid, CONTENT};

/// The secp256k1 KEM of the outside arc.
impl OutsideKemOid for Secp256k1 {
	const KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.6");
}

/// DHKEM(secp256k1, HKDF-SHA256), the KEM of RFC 9180 §7.1 that
/// [`KEM_DHKEM_SECP256K1_HKDF_SHA256`] names, under the identifier of the
/// outside arc.
type MixedKem = OutsideKem<Secp256k1, HkdfSha256, KEM_DHKEM_SECP256K1_HKDF_SHA256>;

/// The profile of [`MixedProvider`]: the P-384 signature beside the
/// secp256k1 agreement.
#[derive(Debug, Default, Clone, Copy)]
struct MixedProfile;

impl SecurityProfile for MixedProfile {
	type Digest = Sha3_512;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = P384Signature;
	type Kdf = HkdfSha3_256;
	type Curve = Secp256k1;
	type KeyWrapOid = Aes256Wrap;
}

/// A provider an outside crate defines with its signer on P-384 and its
/// agreement on secp256k1, beside the house digest, AEAD, key wrap, and KDF.
///
/// It takes the P-384 signature and verifying key of [`p384`](super::p384),
/// and brings [`MixedKem`].
#[derive(Debug, Default, Clone, Copy)]
struct MixedProvider {
	profile: MixedProfile,
}

impl DigestProvider for MixedProvider {
	type Digest = Sha3_512;
}

impl AeadProvider for MixedProvider {
	type AeadCipher = Aes256Gcm;
}

impl KeyWrapProvider for MixedProvider {
	type KeyWrap = Aes256Wrap;
}

impl SigningProvider for MixedProvider {
	type Signature = P384Signature;
	type VerifyingKey = P384VerifyingKey;
}

impl KdfProvider for MixedProvider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for MixedProvider {
	type Curve = Secp256k1;
}

impl CryptoProvider for MixedProvider {
	type Profile = MixedProfile;
	type Kem = MixedKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The authentication of a server that admits `client` alone.
fn admitting(client: &SigningIdentity) -> PeerAuthentication {
	let pinned = DirectTrustValidator::default().with_trust_chain([client.certificate().to_owned()]);
	let pinned = pinned.expect("an outside certificate encodes");
	PeerAuthentication::Anonymous.and(Arc::new(pinned))
}

/// The configuration of a server of `flow` that holds `identity` and admits
/// `client` alone.
fn mutual_server<F: ServerFlow<MixedProvider>>(
	flow: F::Settings,
	identity: F::Identity,
	client: &SigningIdentity,
) -> ServerConfig<F, MixedProvider> {
	let native = RunnableProfile::<MixedProvider>::native().descriptor();
	let profiles = SupportedProfiles::from(native);
	let config = ServerConfig::<F, MixedProvider>::new(flow, identity, profiles, KeyPurposes::HOUSE);
	let mut config = config.expect("an outside server identity serves the server role");
	config.peer_authentication = admitting(client);
	config
}

/// An HPKE client that presents `client` and pins `server`, beside a server
/// that holds `server` and admits `client` alone.
fn mutual_hpke_pair(
	server: SigningIdentity,
	client: SigningIdentity,
) -> (Handshake<Client, Hpke, MixedProvider>, Handshake<Server, Hpke, MixedProvider>) {
	let pinned = DirectTrustValidator::default().with_trust_chain([server.certificate().to_owned()]);
	let server_config = mutual_server::<Hpke>(HpkeServerSettings::new(), server, &client);
	let trust = LearnedTrust::new(pinned.expect("an outside certificate encodes"));
	let settings = HpkeClientSettings { trust, identity: Some(client) };
	let client_config = ClientConfig::<Hpke, MixedProvider>::new(settings, KeyPurposes::HOUSE);
	let client_config = client_config.expect("an outside client serves the client role");
	(Handshake::client(client_config), Handshake::server(server_config))
}

/// A CMS client that presents `client` and pins the key-agreement
/// certificate of `server`, beside a server that holds `server` and admits
/// `client` alone.
fn mutual_cms_pair(
	server: OutsideCmsServer<MixedKem>,
	client: SigningIdentity,
) -> (Handshake<Client, Cms, MixedProvider>, Handshake<Server, Cms, MixedProvider>) {
	let server_config = mutual_server::<Cms>(CmsServerSettings, server.pair, &client);
	let trust = ProvisionedTrust::new(Arc::new(server.key_agreement), server.store);
	let trust = trust.expect("the store admits the outside key-agreement certificate");
	let settings = CmsClientSettings { trust, identity: client };
	let client_config = ClientConfig::<Cms, MixedProvider>::new(settings, KeyPurposes::HOUSE);
	let client_config = client_config.expect("an outside client serves the client role");
	(Handshake::client(client_config), Handshake::server(server_config))
}

/// The HPKE flow runs under mutual authentication with a P-384 signer on
/// both ends and a secp256k1 agreement: the server admits the client's
/// P-384 certificate, and the client's first record opens under the server's
/// session keys.
#[tokio::test]
async fn a_p384_signer_runs_the_hpke_flow_over_secp256k1() -> Result<(), Box<dyn Error>> {
	let client = p384_identity();
	let expected = client.certificate().to_owned();

	let outcome = admitted_and_opened(mutual_hpke_pair(p384_identity(), client)).await?;
	assert_eq!(outcome, (Some(expected), CONTENT.to_vec()));
	Ok(())
}

/// The CMS flow runs under mutual authentication with a P-384 signer on both
/// ends and a secp256k1 key-agreement backend behind the outside KEM: the
/// server admits the client's P-384 certificate, and the client's first
/// record opens under the server's session keys.
#[tokio::test]
async fn a_p384_signer_runs_the_cms_flow_over_secp256k1() -> Result<(), Box<dyn Error>> {
	let client = p384_identity();
	let expected = client.certificate().to_owned();

	let server = p384_cms_server::<MixedProvider>("mixed server");
	let outcome = admitted_and_opened(mutual_cms_pair(server, client)).await?;
	assert_eq!(outcome, (Some(expected), CONTENT.to_vec()));
	Ok(())
}

/// A session under the mixed provider renews its epoch in band, so the
/// client holds an epoch receipt other than the receipt of its handshake.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn a_p384_signer_renews_its_epoch_over_secp256k1() -> Result<(), Box<dyn Error>> {
	let renewed = super::renewal::renews_its_epoch::<MixedProvider>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

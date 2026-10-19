//! Sessions whose endpoints admit each role under an implementor's own key
//! purposes, set through the one carrier of each side.
//!
//! The server's purposes travel through `TransportEncryptionConfig`, and the
//! client's through `ClientBuilder` or `ConnectionPool`. Each certificate
//! names the own purpose of its role alone, so a session establishes only
//! when both carriers hold the own purposes.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::state::{DialableEncryption, EncryptedProtocolState};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedMessageIO, TransportEncryptionConfig, TransportError,
};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::common::security::{ClientMaterials, ServerMaterials};
use crate::transport::support::{
	await_ok, bind_mutual_listener_under, establish_mutual_transports_of, mux_offer, respond_echo,
	serve_one_handshake_message, MutualSessionHooks,
};

#[cfg(feature = "transport-cms")]
mod cms {
	pub use tightbeam::crypto::cms::KeyAgreementIdentity;
	pub use tightbeam::crypto::hpke::DhKemSecp256k1;
	pub use tightbeam::crypto::key::{DiffieHellman, Secp256k1KeyProvider};
	pub use tightbeam::crypto::sign::ecdsa::Secp256k1;
	pub use tightbeam::testing::{TestCmsServer, TestIdentity};
	pub use tightbeam::transport::handshake::{HandshakeProtocolKind, ProvisionedTrust};
	pub use tightbeam::transport::EncryptedProtocol;

	pub use crate::common::security::pinning_validator;
}

#[cfg(feature = "transport-cms")]
use cms::*;

/// An implementor's own purpose of the server role.
const OWN_SERVER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.10");

/// An implementor's own purpose of the client role.
const OWN_CLIENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.11");

/// The purposes of an implementor that names its own server and client roles.
const OWN_PURPOSES: KeyPurposes = KeyPurposes { server: OWN_SERVER, client: OWN_CLIENT, ..KeyPurposes::HOUSE };

/// A server and a client whose certificates each name the own purpose of
/// their role alone.
fn own_purpose_materials() -> (ServerMaterials, ClientMaterials) {
	let materials = ServerMaterials::generate().with_key_purpose(OWN_SERVER);
	let client_materials = ClientMaterials::generate().with_key_purpose(OWN_CLIENT);
	(materials, client_materials)
}

/// A store that trusts each of `certificates` by itself.
fn pinning_store(certificates: &[&Certificate]) -> Result<Arc<dyn CertificateTrust>, TightBeamError> {
	let mut builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	for certificate in certificates {
		builder = builder.with_certificate((*certificate).to_owned())?;
	}
	Ok(Arc::new(builder.build()))
}

/// Accept one connection on `listener`, and serve its two handshake
/// messages under `protocol` before the transport is handed back.
async fn serve_handshake(
	listener: TokioListener,
	protocol: impl FnOnce(TcpTransport<TokioStream>) -> TcpTransport<TokioStream>,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = protocol(transport);
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;
	Ok(transport)
}

/// Both endpoints admit each role under the implementor's own purposes, so a
/// session of certificates of those purposes establishes.
#[tokio::test]
async fn a_mutual_session_under_its_own_purposes_establishes() -> Result<(), TightBeamError> {
	let (materials, client_materials) = own_purpose_materials();
	let hooks = MutualSessionHooks::default();

	let session =
		establish_mutual_transports_of(mux_offer(1), mux_offer(1), hooks, &materials, &client_materials, OWN_PURPOSES);
	let session = session.await?;
	let peer = session.server.session_state().peer_certificate_arc();
	assert_eq!(peer, Some(Arc::clone(&client_materials.certificate)));
	Ok(())
}

/// The certificate of the implementor's own server purpose names no house
/// purpose, so the same server under the house purposes is refused where its
/// configuration becomes provisioning, before any connection.
#[test]
fn a_server_of_own_purposes_is_refused_under_the_house_purposes() {
	let (materials, _) = own_purpose_materials();
	let config = TransportEncryptionConfig::<DefaultCryptoProvider>::new(materials.identity());

	let refusal = DialableEncryption::try_from(config);
	assert!(matches!(
		refusal,
		Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
			CertificateValidationError::ExcludedKeyPurpose
		)))
	));
}

/// The certificate of the implementor's own client purpose names no house
/// purpose, so the same client under the house purposes is refused where its
/// provisioning is answered, before it sends.
#[tokio::test]
async fn a_client_of_own_purposes_is_refused_under_the_house_purposes() -> Result<(), TightBeamError> {
	let (materials, client_materials) = own_purpose_materials();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let stream = TcpStream::connect(listener.local_addr()?).await?;
	let builder = ClientBuilder::<TokioListener>::builder()
		.with_trust_store(pinning_store(&[&materials.certificate])?)
		.with_client_identity(client_materials.identity());

	let refusal = builder.adopt(TokioStream::from(stream));
	assert!(matches!(
		refusal,
		Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
			CertificateValidationError::ExcludedKeyPurpose
		)))
	));
	Ok(())
}

/// A pool answers its provisioning once, when it is built, so a pool of the
/// own client purpose under the house purposes refuses each dial.
#[tokio::test]
async fn a_pool_of_own_purposes_is_refused_under_the_house_purposes() -> Result<(), TightBeamError> {
	let (materials, client_materials) = own_purpose_materials();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let pool = ConnectionPool::<TokioListener>::builder()
		.with_trust_store(pinning_store(&[&materials.certificate])?)
		.with_client_identity(client_materials.identity())
		.build();
	let pool = Arc::new(pool);

	let refusal = pool.connect(TightBeamSocketAddr(listener.local_addr()?)).await;
	assert!(matches!(
		refusal,
		Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
			CertificateValidationError::ExcludedKeyPurpose
		)))
	));
	Ok(())
}

/// A pooled client carries the own purposes to every connection it dials, so
/// a frame round-trips to a server of those purposes.
#[tokio::test]
async fn a_pooled_session_under_its_own_purposes_round_trips() -> Result<(), TightBeamError> {
	let (materials, client_materials) = own_purpose_materials();
	let (listener, addr) = bind_mutual_listener_under(&materials, &client_materials.certificate, OWN_PURPOSES).await?;
	let server = tokio::spawn(async move {
		let transport = serve_handshake(listener, |transport| transport).await?;
		respond_echo(transport).await?;
		Ok::<_, TightBeamError>(())
	});

	let pool = ConnectionPool::<TokioListener>::builder()
		.with_trust_store(pinning_store(&[&materials.certificate])?)
		.with_client_identity(client_materials.identity())
		.with_key_purposes(OWN_PURPOSES)
		.build();
	let pool = Arc::new(pool);
	let mut pooled = pool.connect(TightBeamSocketAddr(addr)).await?;
	let reply = pooled.conn()?.emit(TestFrame::v0(Some("own-purposes"), None), None).await?;

	await_ok(server, "the pooled server task must not panic").await?;
	assert!(reply.is_some());
	Ok(())
}

/// A CMS server of `server` whose two certificates are `signing` and
/// `key_agreement`, which pins `client_certificate` and admits each role
/// under the own purposes.
#[cfg(feature = "transport-cms")]
async fn bind_cms_listener(
	server: &TestCmsServer,
	signing: &Certificate,
	key_agreement: &Certificate,
	client_certificate: &Certificate,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let backend = Secp256k1KeyProvider::from(server.key_agreement_key.to_owned());
	let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(backend);
	let key_agreement = KeyAgreementIdentity::<DhKemSecp256k1>::new(key_agreement.to_owned(), backend)?;
	let signing = TestIdentity::presenting(signing.to_owned(), &server.signing_key);

	let config = TransportEncryptionConfig::new(signing).with_key_agreement(key_agreement)?;
	let config = config.with_client_validators(vec![pinning_validator(client_certificate)]);
	let address = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, bound) = TokioListener::bind_with(address, config.with_key_purposes(OWN_PURPOSES)).await?;
	Ok((listener, *bound))
}

/// The CMS client pins the server's key-agreement certificate under the own
/// server purpose and admits the signing certificate of that purpose from the
/// reply, and the server reads its own pair and its client under the own
/// purposes, so the CMS session establishes.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_session_under_its_own_purposes_establishes() -> Result<(), TightBeamError> {
	let server = TestCmsServer::generate("tightbeam own purposes").with_key_purposes(&[OWN_SERVER]);
	let signing = server.signing.to_owned();
	let key_agreement = server.key_agreement.to_owned();
	let client_materials = ClientMaterials::generate().with_key_purpose(OWN_CLIENT);
	let (listener, addr) = bind_cms_listener(&server, &signing, &key_agreement, &client_materials.certificate).await?;
	let served = tokio::spawn(serve_handshake(listener, |transport| {
		transport.with_handshake_protocol(HandshakeProtocolKind::Cms)
	}));

	let trust = ProvisionedTrust::new(Arc::new(key_agreement), Arc::new(server.store()))?;
	let builder = ClientBuilder::<TokioListener>::builder()
		.with_client_identity(client_materials.identity())
		.with_cms_server(trust)
		.with_handshake_protocol(HandshakeProtocolKind::Cms)
		.with_key_purposes(OWN_PURPOSES);

	let stream = TcpStream::connect(addr).await?;
	let mut client = builder.adopt(TokioStream::from(stream))?.into_transport();
	client.perform_client_handshake().await?;

	let served = await_ok(served, "the CMS server task must not panic").await?;
	let peer = served.session_state().peer_certificate_arc();
	assert_eq!(peer, Some(Arc::clone(&client_materials.certificate)));
	Ok(())
}

/// A pool carries the trust of one pinned key-agreement certificate to every
/// CMS connection it dials, so a frame round-trips to the CMS server of the
/// own purposes through it.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_pooled_cms_session_under_its_own_purposes_round_trips() -> Result<(), TightBeamError> {
	let server = TestCmsServer::generate("tightbeam pooled own purposes").with_key_purposes(&[OWN_SERVER]);
	let signing = server.signing.to_owned();
	let key_agreement = server.key_agreement.to_owned();
	let client_materials = ClientMaterials::generate().with_key_purpose(OWN_CLIENT);
	let (listener, addr) = bind_cms_listener(&server, &signing, &key_agreement, &client_materials.certificate).await?;
	let served = tokio::spawn(async move {
		let cms = |transport: TcpTransport<TokioStream>| transport.with_handshake_protocol(HandshakeProtocolKind::Cms);
		let transport = serve_handshake(listener, cms).await?;
		respond_echo(transport).await?;
		Ok::<_, TightBeamError>(())
	});

	let trust = ProvisionedTrust::new(Arc::new(key_agreement), Arc::new(server.store()))?;
	let pool = ConnectionPool::<TokioListener>::builder()
		.with_client_identity(client_materials.identity())
		.with_cms_server(trust)
		.with_handshake_protocol(HandshakeProtocolKind::Cms)
		.with_key_purposes(OWN_PURPOSES)
		.build();

	let pool = Arc::new(pool);
	let mut pooled = pool.connect(TightBeamSocketAddr(addr)).await?;
	let reply = pooled.conn()?.emit(TestFrame::v0(Some("pooled-cms"), None), None).await?;
	await_ok(served, "the pooled CMS server task must not panic").await?;
	assert!(reply.is_some());
	Ok(())
}

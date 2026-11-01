//! Sessions whose endpoints admit each role under an implementor's own key
//! purposes, set through the one carrier of each side.
//!
//! The server's purposes travel through `TransportEncryptionConfig`, and the
//! client's through `ClientBuilder` or `ConnectionPool`. Each certificate
//! names the own purpose of its role alone, so a session establishes only
//! when both carriers hold the own purposes.

#![cfg(all(
	feature = "transport-hpke",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use std::sync::Arc;

use tokio::task::JoinHandle;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::transport::state::{DialableEncryption, EncryptedProtocolState};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, ConnectionPool, EncryptedMessageIO, TransportEncryptionConfig, TransportError,
};
use tightbeam::{Frame, TightBeamError};

use crate::common::poll::joined;
use crate::common::result::TestResult;
use crate::common::security::{combined_trust, ClientMaterials, ServerMaterials};
use crate::common::transport::{accept_handshaken, establish_mutual_transports_of, respond_echo, MutualSessionHooks};
use crate::transport::fixtures::loopback_streams;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use std::net::SocketAddr;

	pub use tokio::net::TcpStream;

	pub use tightbeam::testing::TestCmsServer;
	pub use tightbeam::transport::handshake::HandshakeProtocolKind;
	pub use tightbeam::x509::Certificate;

	pub use crate::common::security::pinning_validator;
	pub use crate::common::transport::{bind_on_loopback, TestCmsServerExt};
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
	let materials = ServerMaterials::fixed().with_key_purpose(OWN_SERVER);
	let client_materials = ClientMaterials::fixed().with_key_purpose(OWN_CLIENT);
	(materials, client_materials)
}

/// Whether `result` is the refusal of a certificate whose key purpose its
/// carrier excludes.
fn refused_for_its_purposes<T>(result: &Result<T, TransportError>) -> bool {
	matches!(
		result,
		Err(TransportError::HandshakeError(HandshakeError::CertificateValidationError(
			CertificateValidationError::ExcludedKeyPurpose
		)))
	)
}

/// Spawns a server that accepts one connection on `listener`, sets it up with
/// `configure`, serves its handshake, and echoes one request.
fn spawn_echo_server(
	listener: TokioListener,
	configure: impl FnOnce(TcpTransport<TokioStream>) -> TcpTransport<TokioStream> + Send + 'static,
) -> JoinHandle<Result<(), TightBeamError>> {
	tokio::spawn(async move {
		let transport = accept_handshaken(listener, configure).await?;
		respond_echo(transport).await?;
		Ok(())
	})
}

/// `builder` set to trust the certificate of `materials` and to present the
/// identity of `client_materials`.
fn dialing<B: ConnectionBuilder<TokioListener>>(
	builder: B,
	materials: &ServerMaterials,
	client_materials: &ClientMaterials,
) -> B {
	let builder = builder.with_trust_store(combined_trust(&[&materials.certificate]));
	builder.with_client_identity(client_materials.identity())
}

/// Both endpoints admit each role under the implementor's own purposes, so a
/// session of certificates of those purposes establishes.
#[tokio::test]
async fn a_mutual_session_under_its_own_purposes_establishes() -> TestResult {
	let (materials, client) = own_purpose_materials();
	let hooks = MutualSessionHooks::default();
	let client_offer = TransportOffer::mux(1);
	let server_offer = TransportOffer::mux(1);

	let session = establish_mutual_transports_of(client_offer, server_offer, hooks, &materials, &client, OWN_PURPOSES);
	let session = session.await?;
	let peer = session.server.session_state().peer_certificate_arc();
	assert_eq!(peer, Some(Arc::clone(&client.certificate)));
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
	assert!(refused_for_its_purposes(&refusal));
}

/// The certificate of the implementor's own client purpose names no house
/// purpose, so the same client under the house purposes is refused where its
/// provisioning is answered, before it sends.
#[tokio::test]
async fn a_client_of_own_purposes_is_refused_under_the_house_purposes() {
	let (materials, client_materials) = own_purpose_materials();
	let (stream, _accepted) = loopback_streams().await;
	let builder = dialing(ClientBuilder::<TokioListener>::builder(), &materials, &client_materials);

	let refusal = builder.adopt(TokioStream::from(stream));
	assert!(refused_for_its_purposes(&refusal));
}

/// A pool answers its provisioning once, when it is built, so a pool of the
/// own client purpose under the house purposes refuses each dial.
#[tokio::test]
async fn a_pool_of_own_purposes_is_refused_under_the_house_purposes() -> TestResult {
	let (materials, client_materials) = own_purpose_materials();
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
	let builder = dialing(ConnectionPool::<TokioListener>::builder(), &materials, &client_materials);

	let pool = Arc::new(builder.build());
	let refusal = pool.connect(TightBeamSocketAddr(listener.local_addr()?)).await;
	assert!(refused_for_its_purposes(&refusal));
	Ok(())
}

/// A pooled client carries the own purposes to every connection it dials, so
/// a frame round-trips to a server of those purposes.
#[tokio::test]
async fn a_pooled_session_under_its_own_purposes_round_trips() -> TestResult {
	let (materials, client_materials) = own_purpose_materials();
	let bound = materials.bind_mutual_listener_under(&client_materials.certificate, OWN_PURPOSES);
	let (listener, addr) = bound.await?;
	let server = spawn_echo_server(listener, |transport| transport);

	let builder = dialing(ConnectionPool::<TokioListener>::builder(), &materials, &client_materials);
	let pool = builder.with_key_purposes(OWN_PURPOSES).build();

	let pool = Arc::new(pool);
	let mut pooled = pool.connect(TightBeamSocketAddr(addr)).await?;
	let frame = TestFrame::v0(Some("own-purposes"), None);
	let reply = pooled.conn()?.emit(Frame::clone(&frame), None).await?;
	joined(server).await?;
	assert_eq!(reply, Some(frame));
	Ok(())
}

/// A CMS server of the two certificates of `server`, which pins `client` as
/// its one client and admits each role under the own purposes.
#[cfg(feature = "transport-cms")]
async fn bind_cms_listener(server: &TestCmsServer, client: &Certificate) -> (TokioListener, SocketAddr) {
	let config = server.encryption_config();

	let config = config.with_client_validators(vec![pinning_validator(client)]);
	let bound = bind_on_loopback(config.with_key_purposes(OWN_PURPOSES)).await;
	bound.expect("a loopback port binds")
}

/// A CMS server and a client whose certificates each name the own purpose of
/// their role alone.
#[cfg(feature = "transport-cms")]
fn own_purpose_cms() -> (TestCmsServer, ClientMaterials) {
	let server = TestCmsServer::generate("tightbeam own purposes").with_key_purposes(&[OWN_SERVER]);
	let client_materials = ClientMaterials::fixed().with_key_purpose(OWN_CLIENT);
	(server, client_materials)
}

/// `transport` set to run the CMS handshake.
#[cfg(feature = "transport-cms")]
fn cms_protocol(transport: TcpTransport<TokioStream>) -> TcpTransport<TokioStream> {
	transport.with_handshake_protocol(HandshakeProtocolKind::Cms)
}

/// The CMS client pins the server's key-agreement certificate under the own
/// server purpose and admits the signing certificate of that purpose from the
/// reply, and the server reads its own pair and its client under the own
/// purposes, so the CMS session establishes.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_session_under_its_own_purposes_establishes() -> TestResult {
	let (server, client_materials) = own_purpose_cms();
	let (listener, addr) = bind_cms_listener(&server, &client_materials.certificate).await;
	let served = tokio::spawn(accept_handshaken(listener, cms_protocol));

	let builder = ClientBuilder::<TokioListener>::builder();
	let builder = builder.with_client_identity(client_materials.identity());
	let builder = builder.with_cms_server(server.trust());
	let builder = builder.with_handshake_protocol(HandshakeProtocolKind::Cms);
	let builder = builder.with_key_purposes(OWN_PURPOSES);

	let stream = TcpStream::connect(addr).await?;
	let mut client = builder.adopt(TokioStream::from(stream))?.into_transport();
	client.perform_client_handshake().await?;

	let served = joined(served).await?;
	let peer = served.session_state().peer_certificate_arc();
	assert_eq!(peer, Some(Arc::clone(&client_materials.certificate)));
	Ok(())
}

/// A pool carries the trust of one pinned key-agreement certificate to every
/// CMS connection it dials, so a frame round-trips to the CMS server of the
/// own purposes through it.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_pooled_cms_session_under_its_own_purposes_round_trips() -> TestResult {
	let (server, client_materials) = own_purpose_cms();
	let (listener, addr) = bind_cms_listener(&server, &client_materials.certificate).await;
	let served = spawn_echo_server(listener, cms_protocol);

	let builder = ConnectionPool::<TokioListener>::builder();
	let builder = builder.with_client_identity(client_materials.identity());
	let builder = builder.with_cms_server(server.trust());
	let builder = builder.with_handshake_protocol(HandshakeProtocolKind::Cms);
	let pool = builder.with_key_purposes(OWN_PURPOSES).build();

	let pool = Arc::new(pool);
	let mut pooled = pool.connect(TightBeamSocketAddr(addr)).await?;
	let frame = TestFrame::v0(Some("pooled-cms"), None);
	let reply = pooled.conn()?.emit(Frame::clone(&frame), None).await?;
	joined(served).await?;
	assert_eq!(reply, Some(frame));
	Ok(())
}

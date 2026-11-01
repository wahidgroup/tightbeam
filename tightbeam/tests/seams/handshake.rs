//! The handshake drivers of the transport, which run an orchestrator an
//! outside crate writes.
//!
//! - [`EncryptedMessageIO::drive_client_handshake`] runs an outside [`ClientHandshakeProtocol`].
//! - A server transport runs an outside [`ServerHandshakeProtocol`] from its [`ServerHandshakeSlot`].
//!
//! Each outside orchestrator runs a house orchestrator of the HPKE flow under
//! [`OutsideProvider`] and records the profile of each session it completes.

use std::sync::{Arc, Mutex, PoisonError};

use tightbeam::crypto::profiles::SecurityProfileDesc;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::testing::TestFrame;
use tightbeam::transport::handshake::{
	BoxedServerHandshake, ClientHandshakeProtocol, EstablishedSession, HandshakeError, HandshakeMessage,
	PeerAuthentication, ServerHandshakeProtocol,
};
use tightbeam::transport::state::ServerHandshakeSlot;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{EncryptedMessageIO, MessageEmitter, TransportResult};
use tokio::task::JoinHandle;

use super::floor::{client_under, outside_listener};
use super::hpke::{outside_client, outside_server, OutsideClient, OutsideServer};
use super::{native_profile, OutsideProvider};
use crate::common::result::TestResult;
use crate::common::transport::respond_echo;

/// The profile of the last session an audited orchestrator completed.
#[derive(Clone, Default)]
struct Audit(Arc<Mutex<Option<SecurityProfileDesc>>>);

impl Audit {
	/// Record `profile` as the profile of a completed session.
	fn record(&self, profile: Option<SecurityProfileDesc>) {
		let mut agreed = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		*agreed = profile;
	}

	/// The profile of the last completed session, or `None` before a session
	/// completes.
	fn agreed(&self) -> Option<SecurityProfileDesc> {
		*self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

/// A client orchestrator an outside crate writes: it runs the house client
/// of the HPKE flow and audits the profile of each session it completes.
struct AuditedClient {
	inner: OutsideClient,
	audit: Audit,
}

impl ClientHandshakeProtocol for AuditedClient {
	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, HandshakeError>> {
		ClientHandshakeProtocol::start(&mut self.inner)
	}

	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, HandshakeError>> {
		ClientHandshakeProtocol::handle_response(&mut self.inner, msg)
	}

	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, HandshakeError>> {
		let Self { inner, audit } = *self;
		let agreed = ClientHandshakeProtocol::selected_profile(&inner);
		let completing = ClientHandshakeProtocol::complete(Box::new(inner));
		Box::pin(async move {
			let session = completing.await?;
			audit.record(agreed);
			Ok(session)
		})
	}

	fn is_complete(&self) -> bool {
		ClientHandshakeProtocol::is_complete(&self.inner)
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		ClientHandshakeProtocol::selected_profile(&self.inner)
	}
}

/// A server orchestrator an outside crate writes: it runs the house server
/// of the HPKE flow and audits the profile of each session it completes.
struct AuditedServer {
	inner: OutsideServer,
	audit: Audit,
}

impl ServerHandshakeProtocol for AuditedServer {
	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, HandshakeError>> {
		ServerHandshakeProtocol::handle_request(&mut self.inner, msg)
	}

	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, HandshakeError>> {
		let Self { inner, audit } = *self;
		let agreed = ServerHandshakeProtocol::selected_profile(&inner);
		let completing = ServerHandshakeProtocol::complete(Box::new(inner));
		Box::pin(async move {
			let session = completing.await?;
			audit.record(agreed);
			Ok(session)
		})
	}

	fn is_complete(&self) -> bool {
		ServerHandshakeProtocol::is_complete(&self.inner)
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		ServerHandshakeProtocol::selected_profile(&self.inner)
	}
}

/// A server under [`OutsideProvider`] that accepts one connection on
/// `listener`, places `handshake` in the slot of its transport, and echoes
/// the first frame it collects. `None` leaves the slot to the transport.
fn echo_one(
	listener: TokioListener<OutsideProvider>,
	handshake: Option<BoxedServerHandshake>,
) -> JoinHandle<TransportResult<()>> {
	tokio::spawn(async move {
		let (mut transport, _) = listener.accept().await?;
		if let Some(handshake) = handshake {
			transport.handshake_slot().install(handshake);
		}

		respond_echo(transport).await
	})
}

/// A client transport drives an outside client orchestrator through each
/// leg, installs the session it completes, and emits under that session.
#[tokio::test]
async fn a_client_transport_runs_an_outside_client_handshake() -> TestResult {
	let (server, listener, addr) = outside_listener::<OutsideProvider>().await;
	let _serving = echo_one(listener, None);
	let mut client = client_under::<OutsideProvider>(addr, &server).await;
	let audit = Audit::default();
	let audited = AuditedClient { inner: outside_client(server.certificate()), audit: audit.clone() };
	let frame = TestFrame::v0(Some("outside-client-handshake"), None);

	client.drive_client_handshake(Box::new(audited)).await?;

	let echoed = client.emit(frame.clone(), None).await?;
	assert_eq!(
		(audit.agreed(), echoed),
		(Some(native_profile::<OutsideProvider>()), Some(frame))
	);
	Ok(())
}

/// A server transport drives the outside server orchestrator in its slot
/// through each leg, and serves the session that orchestrator completes.
#[tokio::test]
async fn a_server_transport_runs_an_outside_server_handshake() -> TestResult {
	let (server, listener, addr) = outside_listener::<OutsideProvider>().await;
	let audit = Audit::default();
	let inner = outside_server(server.clone(), PeerAuthentication::Anonymous);
	let _serving = echo_one(listener, Some(Box::new(AuditedServer { inner, audit: audit.clone() })));
	let mut client = client_under::<OutsideProvider>(addr, &server).await;
	let frame = TestFrame::v0(Some("outside-server-handshake"), None);

	let echoed = client.emit(frame.clone(), None).await?;
	assert_eq!(
		(audit.agreed(), echoed),
		(Some(native_profile::<OutsideProvider>()), Some(frame))
	);
	Ok(())
}

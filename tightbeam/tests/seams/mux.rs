//! The dispatch seam of the multiplexed transport: a [`MuxDispatch`] an
//! outside crate writes, served end to end over a cleartext connection.

use std::sync::Arc;

use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestMessage;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxDispatch, MuxHandle, MuxRole, MuxTransport, SpawnedMux};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{EndpointConfig, ResponsePackage, TransportError, TransportFailure, TransportResult};
use tightbeam::{Frame, TightBeamError, Version};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// The id of a frame the outside dispatch refuses.
const REFUSED_ID: &[u8] = b"outside-refused";

/// The id of a frame the outside dispatch echoes.
const SERVED_ID: &[u8] = b"outside-served";

/// The dispatch an outside crate writes. It echoes each unary frame, and
/// fails a frame whose id is [`REFUSED_ID`] with `InvalidArgument`.
struct OutsideDispatch;

impl MuxDispatch for OutsideDispatch {
	async fn unary(&self, frame: Arc<Frame>) -> TransportResult<ResponsePackage> {
		if frame.metadata().id() == REFUSED_ID {
			return Err(TransportError::OperationFailed(TransportFailure::InvalidArgument));
		}

		Ok(ResponsePackage::new(TransitStatus::Ok, Some(Frame::clone(&frame))))
	}
}

/// The client end of a connection whose server runs [`OutsideDispatch`],
/// with the tasks that keep both ends running.
struct Served {
	handle: MuxHandle,
	_tasks: [JoinHandle<()>; 2],
	_serving: JoinHandle<TransportResult<()>>,
}

/// Connect a cleartext client to a cleartext server over a loopback socket,
/// and serve the server's peer streams with [`OutsideDispatch`].
async fn serve_outside_dispatch() -> Served {
	let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0")
		.await
		.expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");
	let accepted = tokio::spawn(async move { listener.accept().await });
	let stream = TcpStream::connect(addr).await.expect("the client reaches the listener");
	let client = TcpTransport::new(TokioStream::from(stream), EndpointConfig::<DefaultCryptoProvider>::cleartext());
	let joined = accepted.await.expect("the accept task runs to its end");
	let (server, _) = joined.expect("the listener accepts the client");

	let settings = MuxSettings::symmetric(4);
	let (reader, writer) = client.into_split().expect("a cleartext transport splits");
	let SpawnedMux { handle, reader_task: client_reader, .. } =
		MuxTransport::new(reader, writer, MuxRole::Client, settings).spawn();
	let (reader, writer) = server.into_split().expect("a cleartext transport splits");
	let SpawnedMux { responder, reader_task: server_reader, .. } =
		MuxTransport::new(reader, writer, MuxRole::Server, settings).spawn();
	let serving = tokio::spawn(responder.serve_with(OutsideDispatch));

	Served { handle, _tasks: [client_reader, server_reader], _serving: serving }
}

/// A frame whose id is `id`.
fn frame_of(id: &[u8]) -> Frame {
	let builder = FrameBuilder::from(Version::V2).with_id(id).with_order(1696521600);
	builder
		.with_message(TestMessage::sample(None))
		.build()
		.expect("the frame builds")
}

/// A stream the outside dispatch answers reaches the client end to end.
#[tokio::test]
async fn an_outside_dispatch_answers_a_stream_end_to_end() -> Result<(), TightBeamError> {
	let served = serve_outside_dispatch().await;
	let frame = frame_of(SERVED_ID);

	let echoed = served.handle.emit_on_stream(&frame).await?;
	assert_eq!(echoed, Some(frame));
	Ok(())
}

/// A stream whose dispatch fails reads the status of the failure, and the
/// stream after it on the same connection is served.
#[tokio::test]
async fn an_outside_dispatch_refuses_one_stream_and_serves_the_next() -> Result<(), TightBeamError> {
	let served = serve_outside_dispatch().await;
	let frame = frame_of(SERVED_ID);

	let refused = served.handle.emit_on_stream(&frame_of(REFUSED_ID)).await;
	let echoed = served.handle.emit_on_stream(&frame).await?;
	let refused = matches!(refused, Err(TransportError::OperationFailed(TransportFailure::InvalidArgument)));
	assert!(refused);
	assert_eq!(echoed, Some(frame));
	Ok(())
}

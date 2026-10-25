//! The seams of the multiplexed transport, served end to end over a
//! cleartext connection:
//!
//! - a [`MuxDispatch`] an outside crate writes, which answers the streams the server receives, and
//! - a [`CreditGrantor`] an outside crate writes, which raises the credit of each stream the server receives.

use core::time::Duration;
use std::error::Error;
use std::sync::{Arc, Mutex, PoisonError};

use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::constants::MIN_MUX_CHUNK_SIZE;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestMessage;
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{
	BufferedGrantor, CreditGrantor, MuxDispatch, MuxHandle, MuxRole, MuxTransport, SpawnedMux, StreamId,
};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{EndpointConfig, ResponsePackage, TransportError, TransportFailure, TransportResult};
use tightbeam::{Frame, TightBeamError, Version};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The id of a frame the outside dispatch refuses.
const REFUSED_ID: &[u8] = b"outside-refused";

/// The id of a frame the outside dispatch echoes.
const SERVED_ID: &[u8] = b"outside-served";

/// The longest wait for a stream whose sender waits on credit.
const CREDIT_BOUND: Duration = Duration::from_secs(5);

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

/// The credit policy an outside crate writes. It raises the limit of a stream
/// to one chunk past what the stream received, so the sender holds one chunk
/// in flight at a time, and it records each stream and count it is asked
/// about.
#[derive(Default)]
struct OneAhead {
	asked: Mutex<Vec<(StreamId, u64)>>,
}

impl OneAhead {
	/// The stream and the received count of the first time the transport
	/// asked for a grant.
	fn first_asked(&self) -> Option<(StreamId, u64)> {
		let asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
		asked.first().copied()
	}
}

impl CreditGrantor for OneAhead {
	fn replenish(&self, stream_id: StreamId, received: u64, _limit: u64) -> Option<u64> {
		let mut asked = self.asked.lock().unwrap_or_else(PoisonError::into_inner);
		asked.push((stream_id, received));
		Some(received.saturating_add(1))
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
/// both under `settings`, and serve the server's peer streams with
/// [`OutsideDispatch`] under the credit that `grantor` grants.
async fn serve_outside_dispatch_under(settings: MuxSettings, grantor: Arc<dyn CreditGrantor>) -> Served {
	let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0")
		.await
		.expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");
	let accepted = tokio::spawn(async move { listener.accept().await });
	let stream = TcpStream::connect(addr).await.expect("the client reaches the listener");
	let client = TcpTransport::new(TokioStream::from(stream), EndpointConfig::<DefaultCryptoProvider>::cleartext());
	let joined = accepted.await.expect("the accept task runs to its end");
	let (server, _) = joined.expect("the listener accepts the client");

	let (reader, writer) = client.into_split().expect("a cleartext transport splits");
	let SpawnedMux { handle, reader_task: client_reader, .. } =
		MuxTransport::new(reader, writer, MuxRole::Client, settings).spawn();
	let (reader, writer) = server.into_split().expect("a cleartext transport splits");
	let server = MuxTransport::new(reader, writer, MuxRole::Server, settings).with_credit_grantor(grantor);
	let SpawnedMux { responder, reader_task: server_reader, .. } = server.spawn();
	let serving = tokio::spawn(responder.serve_with(OutsideDispatch));

	Served { handle, _tasks: [client_reader, server_reader], _serving: serving }
}

/// Serve [`OutsideDispatch`] as [`serve_outside_dispatch_under`] does, under
/// the default settings of a link and the house grantor.
async fn serve_outside_dispatch() -> Served {
	let grantor = Arc::new(BufferedGrantor::default());
	serve_outside_dispatch_under(MuxSettings::symmetric(4), grantor).await
}

/// The settings of a narrow link: the smallest chunk a link negotiates, and
/// one chunk of initial credit on each stream.
fn narrow_settings() -> MuxSettings {
	let mut settings = MuxSettings::symmetric(4);
	settings.send_chunk_size = MIN_MUX_CHUNK_SIZE;
	settings.recv_chunk_size = MIN_MUX_CHUNK_SIZE;
	settings.initial_send_credit = 1;
	settings.initial_recv_credit = 1;
	settings
}

/// A frame whose id is `id`.
fn frame_of(id: &[u8]) -> Frame {
	let builder = FrameBuilder::from(Version::V2).with_id(id).with_order(1696521600);
	builder
		.with_message(TestMessage::sample(None))
		.build()
		.expect("the frame builds")
}

/// A frame whose message alone fills four chunks of [`MIN_MUX_CHUNK_SIZE`].
fn wide_frame() -> Frame {
	let content = "w".repeat(4096);
	let builder = FrameBuilder::from(Version::V2).with_id(SERVED_ID).with_order(1696521600);
	let builder = builder.with_message(TestMessage::sample(Some(&content)));
	builder.build().expect("the frame builds")
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

/// A frame of more than four chunks crosses a stream whose initial credit is
/// one chunk, under the credit that an outside grantor raises at the server.
/// The server first asks the grantor once the first chunk of the first client
/// stream arrives.
#[tokio::test]
async fn an_outside_grantor_raises_the_credit_of_a_stream() -> Result<(), Box<dyn Error>> {
	let grantor = Arc::new(OneAhead::default());
	let lent: Arc<OneAhead> = Arc::clone(&grantor);
	let served = serve_outside_dispatch_under(narrow_settings(), lent).await;
	let frame = wide_frame();

	let echoed = timeout(CREDIT_BOUND, served.handle.emit_on_stream(&frame)).await??;
	let first_asked = grantor.first_asked();
	assert_eq!((echoed, first_asked), (Some(frame), Some((StreamId::new(1), 1))));
	Ok(())
}

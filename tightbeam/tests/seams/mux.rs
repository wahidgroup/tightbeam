//! The seams of the multiplexed transport, served end to end. The first two
//! run over a cleartext connection:
//!
//! - a [`MuxDispatch`] an outside crate writes, which answers the streams the server receives,
//! - a [`CreditGrantor`] an outside crate writes, which raises the credit of each stream it serves, and
//! - a [`MuxAcceptor`] an outside crate writes over the house transport, whose gate sees its mutual peer.

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
	BufferedGrantor, CreditGrantor, MuxDispatch, MuxDrivers, MuxHandle, MuxRole, MuxTransport, SpawnedMux, StreamId,
};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{EndpointConfig, ResponsePackage, TransportError, TransportFailure, TransportResult};
use tightbeam::{Frame, TightBeamError, Version};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

#[cfg(feature = "transport-hpke")]
mod acceptor_seam {
	pub use core::future::Future;

	pub use tightbeam::marker::MaybeSend;
	pub use tightbeam::policy::{GatePolicy, SessionContext};
	pub use tightbeam::transport::handshake::negotiation::TransportOffer;
	pub use tightbeam::transport::multiplex::{
		CallContext, GatedHalves, MuxAcceptor, MuxCapable, MuxRekeyContext, MuxService,
	};
	pub use tightbeam::transport::policy::CollectorGateConfig;
	pub use tightbeam::x509::Certificate;

	pub use crate::transport::support::{establish_mutual_transports, MutualSessionHooks};
}

#[cfg(feature = "transport-hpke")]
use acceptor_seam::*;

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
/// with the drivers and the task that keep both ends running.
struct Served {
	handle: MuxHandle,
	_drivers: [MuxDrivers; 2],
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
	let SpawnedMux { handle, drivers: client_drivers, .. } =
		MuxTransport::new(reader, writer, MuxRole::Client, settings).spawn();
	let (reader, writer) = server.into_split().expect("a cleartext transport splits");
	let server = MuxTransport::new(reader, writer, MuxRole::Server, settings).with_credit_grantor(grantor);
	let SpawnedMux { responder, drivers: server_drivers, .. } = server.spawn();
	let serving = tokio::spawn(responder.serve_with(OutsideDispatch));

	Served { handle, _drivers: [client_drivers, server_drivers], _serving: serving }
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
	let settings = MuxSettings::symmetric(4).with_chunk_size(MIN_MUX_CHUNK_SIZE);
	settings.with_initial_credit(1)
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

/// An acceptor an outside crate writes over the house transport. It takes
/// each part of the seam from the transport it wraps, its session context
/// among them.
#[cfg(feature = "transport-hpke")]
struct OutsideAcceptor(TcpTransport<TokioStream>);

#[cfg(feature = "transport-hpke")]
impl MuxCapable for OutsideAcceptor {
	fn with_mux_offer(self, offer: Option<Arc<TransportOffer>>) -> Self {
		Self(MuxCapable::with_mux_offer(self.0, offer))
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		MuxCapable::negotiated_mux(&self.0)
	}
}

#[cfg(feature = "transport-hpke")]
impl MuxAcceptor for OutsideAcceptor {
	type EnvelopeReader = <TcpTransport<TokioStream> as MuxAcceptor>::EnvelopeReader;
	type EnvelopeWriter = <TcpTransport<TokioStream> as MuxAcceptor>::EnvelopeWriter;

	fn negotiate_mux(&mut self) -> impl Future<Output = TransportResult<Option<MuxSettings>>> + MaybeSend {
		self.0.negotiate_mux()
	}

	fn take_rekey(&mut self) -> TransportResult<Option<MuxRekeyContext>> {
		MuxAcceptor::take_rekey(&mut self.0)
	}

	fn session_context(&self) -> SessionContext {
		MuxAcceptor::session_context(&self.0)
	}

	fn into_gated_halves(self) -> TransportResult<GatedHalves<Self>> {
		self.0.into_gated_halves()
	}

	fn into_envelope_halves(self) -> TransportResult<(Self::EnvelopeReader, Self::EnvelopeWriter)> {
		MuxAcceptor::into_envelope_halves(self.0)
	}
}

/// A gate an outside crate writes. It admits every request and records the
/// peer certificate of the session it gates.
#[cfg(feature = "transport-hpke")]
#[derive(Clone, Default)]
struct PeerRecord(Arc<Mutex<Option<Certificate>>>);

#[cfg(feature = "transport-hpke")]
impl PeerRecord {
	/// The peer certificate of the last session the gate saw, or `None`
	/// before a gated request or for a session that named no peer.
	fn seen(&self) -> Option<Certificate> {
		let seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		seen.clone()
	}
}

#[cfg(feature = "transport-hpke")]
impl GatePolicy for PeerRecord {
	fn evaluate(&self, _message: Option<&Frame>, session: &SessionContext) -> TransitStatus {
		let mut seen = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		*seen = session.peer_certificate().cloned();
		TransitStatus::Ok
	}
}

/// A service that echoes each unary frame.
#[cfg(feature = "transport-hpke")]
struct Echo;

#[cfg(feature = "transport-hpke")]
impl MuxService for Echo {
	async fn unary(&self, frame: Frame, _cx: CallContext) -> Result<Option<Frame>, TightBeamError> {
		Ok(Some(frame))
	}
}

/// An outside acceptor serves its collector gate the client that the mutual
/// session authenticated, as the house transport names it.
#[cfg(feature = "transport-hpke")]
#[tokio::test]
async fn an_outside_acceptor_serves_its_gate_the_peer_it_names() -> Result<(), Box<dyn Error>> {
	let offer = TransportOffer::mux(4);
	let session = establish_mutual_transports(offer.clone(), offer, MutualSessionHooks::default()).await?;
	let record = PeerRecord::default();
	let server = OutsideAcceptor(session.server.with_collector_gate(record.clone()));
	let settings = server.negotiated_mux().ok_or("the session negotiated multiplexing")?;
	let _serving = tokio::spawn(server.serve(settings, Echo, None));
	let SpawnedMux { handle, drivers: _drivers, .. } = session.client.into_mux(MuxRole::Client)?.spawn();
	let client = Certificate::clone(&session.client_certificate);
	let frame = frame_of(SERVED_ID);

	let echoed = handle.emit_on_stream(&frame).await?;
	assert_eq!((echoed, record.seen()), (Some(frame), Some(client)));
	Ok(())
}

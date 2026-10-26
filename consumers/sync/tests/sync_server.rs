//! These tests run the sync `server!` accept loop on `std`, without `tokio`.

use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::instrumentation::events;
use tightbeam::runtime::rt;
use tightbeam::server;
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::TestFrame;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::policy::TimeoutConfig;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{EndpointConfig, MessageEmitter, TransportError, TransportResult};
use tightbeam::urn::Urn;
use tightbeam::Frame;

/// Emits a frame labelled `label` over `stream` and returns it with the
/// server's reply.
fn echo(stream: NetTcpStream, label: &str) -> (Frame, Option<Frame>) {
	let mut client = TcpTransport::new(stream, EndpointConfig::<DefaultCryptoProvider>::cleartext());

	let frame = TestFrame::v0(Some(label), None);
	let echoed = rt::block_on(client.emit(frame.to_owned(), None)).expect("the server answers the frame");
	(frame, echoed)
}

/// Drains `trace` and counts the `GATE_ACCEPT` events it recorded.
fn gate_accepts(trace: &TraceCollector) -> usize {
	trace
		.drain_events()
		.iter()
		.filter(|event| event.urn == events::GATE_ACCEPT)
		.count()
}

/// One frame round-trips through the sync accept loop: the server thread
/// echoes and the client observes the same frame back.
#[test]
fn sync_server_echoes_over_std_tcp() -> TransportResult<()> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;

	thread::spawn(move || {
		let server = TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(listener);
		server! {
			TcpListener: server,
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
	});

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-echo");
	assert_eq!(echoed, Some(frame), "sync server! loop should echo the frame");
	Ok(())
}

/// The cleartext single-flight plane audits gate verdicts: an accepted
/// frame records `GATE_ACCEPT` on the server's collector.
#[test]
fn sync_server_audits_gate_verdicts() -> TransportResult<()> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	thread::spawn(move || {
		let server = TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(listener);
		server! {
			TcpListener: server,
			policies: { with_trace: [ audit.share() ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
	});

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-audit");
	assert_eq!(echoed, Some(frame), "audited sync exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// Connects to a `bind_cleartext` arm's listener, which comes up on the server
/// thread after the test has reserved its port.
fn connect_with_retry(addr: SocketAddr) -> NetTcpStream {
	for _ in 0..50 {
		if let Ok(stream) = NetTcpStream::connect(addr) {
			return stream;
		}
		thread::sleep(Duration::from_millis(20));
	}
	NetTcpStream::connect(addr).expect("the bind arm's listener comes up within a second")
}

/// The `bind_cleartext` arm binds the address itself and serves the same echo
/// loop.
#[test]
fn sync_server_bind_echoes() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;

	thread::spawn(move || -> TransportResult<()> {
		server! {
			TcpListener<NetTcpListener>: bind_cleartext TightBeamSocketAddr(addr),
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
		Ok(())
	});

	let (frame, echoed) = echo(connect_with_retry(addr), "sync-bind");
	assert_eq!(echoed, Some(frame), "bind server! loop should echo the frame");
	Ok(())
}

/// The `bind_cleartext` arm with policies applies them to every accepted
/// transport.
#[test]
fn sync_server_bind_applies_policies() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	thread::spawn(move || -> TransportResult<()> {
		server! {
			TcpListener<NetTcpListener>: bind_cleartext TightBeamSocketAddr(addr),
			policies: { with_trace: [ audit.share() ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
		Ok(())
	});

	let (frame, echoed) = echo(connect_with_retry(addr), "sync-bind-audit");
	assert_eq!(echoed, Some(frame), "audited bind exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// The `protocol .. bind_cleartext` arm binds before it returns and serves the
/// echo loop on a thread of its own.
#[test]
fn sync_server_protocol_bind_echoes() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;

	server! {
		protocol TcpListener<NetTcpListener>: bind_cleartext TightBeamSocketAddr(addr),
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	};

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-bind");
	assert_eq!(echoed, Some(frame), "protocol bind server! loop should echo the frame");
	Ok(())
}

/// The `protocol .. bind_cleartext` arm with policies applies them to every
/// accepted transport.
#[test]
fn sync_server_protocol_bind_applies_policies() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	server! {
		protocol TcpListener<NetTcpListener>: bind_cleartext TightBeamSocketAddr(addr),
		policies: { with_trace: [ audit.share() ] },
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	};

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-bind-audit");
	assert_eq!(echoed, Some(frame), "audited protocol bind exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// Returns the handler events that one call to a blocking `server!` records
/// on the trail of its connection, in order, under a trace whose config sets
/// `enable_internal_detail` to `detail`.
fn blocking_handler_span(detail: bool) -> TransportResult<Vec<Urn<'static>>> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;
	let trace = TestTrace::with_detail(detail);
	let audit = trace.share();

	thread::spawn(move || {
		let server = TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(listener);
		server! {
			TcpListener: server,
			policies: { with_trace: [ audit.share() ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
	});

	// The loop records the exit of its handler before it sends the answer,
	// so the answer orders the span ahead of the drain below.
	echo(NetTcpStream::connect(addr)?, "sync-handler-span");

	Ok(TestTrace::trail(&trace, &[events::HANDLER_ENTER, events::HANDLER_EXIT]))
}

/// A blocking `server!` records the span of its handler when the trace config
/// sets the detail flag, and leaves the trail empty when the config clears it.
#[test]
fn sync_server_records_its_handler_span_under_the_detail_flag_alone() -> TransportResult<()> {
	let detailed = blocking_handler_span(true)?;
	let plain = blocking_handler_span(false)?;
	assert_eq!([detailed, plain], [vec![events::HANDLER_ENTER, events::HANDLER_EXIT], vec![]]);
	Ok(())
}

/// How long a client past the cap waits before the test reads its silence as
/// the cap that holds it.
const CAP_WAIT: Duration = Duration::from_millis(500);

/// A listener whose first accept fails, as a descriptor shortage fails one,
/// and whose later accepts take the connections of the socket it holds.
struct FailingOnceListener {
	listener: TcpListener<NetTcpListener, DefaultCryptoProvider>,
	failed: AtomicBool,
}

impl FailingOnceListener {
	/// Serves `listener` in the clear, after one failed accept.
	fn over(listener: NetTcpListener) -> Self {
		let listener = TcpListener::from_listener_cleartext(listener);
		Self { listener, failed: AtomicBool::new(false) }
	}

	/// Fails the first call, and takes one connection of the socket on each
	/// later call.
	fn accept(&self) -> TransportResult<TcpTransport<NetTcpStream, DefaultCryptoProvider>> {
		if !self.failed.swap(true, Ordering::SeqCst) {
			return Err(TransportError::ConnectionFailed);
		}

		self.listener.accept()
	}
}

/// The loop waits out a failed accept and accepts again, so one failure
/// leaves the server serving.
#[test]
fn sync_server_serves_after_a_failed_accept() -> TransportResult<()> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;

	thread::spawn(move || {
		let server = FailingOnceListener::over(listener);
		server! {
			TcpListener: server,
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
	});

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-after-failure");
	assert_eq!(echoed, Some(frame));
	Ok(())
}

/// With `max_connections: [ 1 ]` the loop serves one connection at a time, so
/// a second connection waits in the listener backlog, unanswered, while the
/// first one lives. The first connection gets its echo, so the loop serves.
#[test]
fn sync_server_holds_a_connection_past_its_cap() -> TransportResult<()> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;

	thread::spawn(move || {
		let server = TcpListener::<_, DefaultCryptoProvider>::from_listener_cleartext(listener);
		server! {
			TcpListener: server,
			policies: { max_connections: [ 1 ] },
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
	});

	let mut held = TcpTransport::new(
		NetTcpStream::connect(addr)?,
		EndpointConfig::<DefaultCryptoProvider>::cleartext(),
	);
	let admitted = TestFrame::v0(Some("sync-within-cap"), None);
	let echoed = rt::block_on(held.emit(admitted.to_owned(), None))?;

	let waiting = NetTcpStream::connect(addr)?;
	let queued = TcpTransport::new(waiting, EndpointConfig::<DefaultCryptoProvider>::cleartext());
	let mut queued = queued.with_timeout(CAP_WAIT);
	let frame = TestFrame::v0(Some("sync-past-cap"), None);
	let starved = rt::block_on(queued.emit(frame, None));

	// A read past the timeout of a std socket fails with `WouldBlock` on Unix
	// and with `TimedOut` on Windows.
	let timed_out = matches!(
		&starved,
		Err(TransportError::IoError(error)) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
	);
	assert_eq!(echoed, Some(admitted), "the connection within the cap must get its echo");
	assert!(
		timed_out,
		"the connection past the cap must time out unanswered, got {starved:?}"
	);
	Ok(())
}

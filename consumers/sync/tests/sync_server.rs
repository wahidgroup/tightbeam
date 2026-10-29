//! These tests run the sync `server!` accept loop and the thread spawn of
//! `runtime::rt` on `std`, without `tokio`.

use std::error::Error;
use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
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
use tightbeam::transport::{EndpointConfig, MessageEmitter, TransportError, TransportFailure, TransportResult};
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

/// One frame round-trips through the sync accept loop.
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

/// The `protocol .. bind_cleartext` arm binds before it returns. It serves the
/// echo loop on its own thread and returns the result of that spawn.
#[test]
fn sync_server_protocol_bind_echoes() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;

	server! {
		protocol TcpListener<NetTcpListener>: bind_cleartext TightBeamSocketAddr(addr),
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	}?;

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
	}?;

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-bind-audit");
	assert_eq!(echoed, Some(frame), "audited protocol bind exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// A cleartext listener on a free port of the loopback address, with that
/// address.
fn cleartext_listener() -> TransportResult<(TcpListener<NetTcpListener, DefaultCryptoProvider>, SocketAddr)> {
	let listener = NetTcpListener::bind("127.0.0.1:0")?;
	let addr = listener.local_addr()?;
	Ok((TcpListener::from_listener_cleartext(listener), addr))
}

/// The `protocol` arm serves the listener it takes on its own thread and
/// returns the result of that spawn.
#[test]
fn sync_server_protocol_echoes() -> TransportResult<()> {
	let (server, addr) = cleartext_listener()?;

	server! {
		protocol TcpListener<NetTcpListener>: server,
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	}?;

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol");
	assert_eq!(echoed, Some(frame), "protocol server! loop should echo the frame");
	Ok(())
}

/// The `protocol` arm with policies applies them to every transport that the
/// listener it takes accepts.
#[test]
fn sync_server_protocol_applies_policies() -> TransportResult<()> {
	let (server, addr) = cleartext_listener()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	server! {
		protocol TcpListener<NetTcpListener>: server,
		policies: { with_trace: [ audit.share() ] },
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	}?;

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-audit");
	assert_eq!(echoed, Some(frame), "audited protocol exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// The `protocol` arm with channels drops both, because only the tokio loop
/// reports through them. It serves the echo loop on its own thread.
#[test]
fn sync_server_protocol_channels_echoes() -> TransportResult<()> {
	let (server, addr) = cleartext_listener()?;
	let (errors, _error_reports) = rt::channel::<TransportError>(1);
	let (oks, _ok_reports) = rt::channel::<()>(1);

	server! {
		protocol TcpListener<NetTcpListener>: server,
		channels: { error: errors, ok: oks },
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	}?;

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-channels");
	assert_eq!(echoed, Some(frame), "protocol server! loop with channels should echo the frame");
	Ok(())
}

/// The `protocol` arm with channels and policies applies the policies to every
/// transport that the listener it takes accepts.
#[test]
fn sync_server_protocol_channels_applies_policies() -> TransportResult<()> {
	let (server, addr) = cleartext_listener()?;
	let (errors, _error_reports) = rt::channel::<TransportError>(1);
	let (oks, _ok_reports) = rt::channel::<()>(1);
	let trace = TraceCollector::new();
	let audit = trace.share();

	server! {
		protocol TcpListener<NetTcpListener>: server,
		channels: { error: errors, ok: oks },
		policies: { with_trace: [ audit.share() ] },
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	}?;

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-channels-audit");
	assert_eq!(echoed, Some(frame), "audited protocol exchange with channels should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

/// Returns the handler events, in order, that one blocking `server!` call
/// records on its connection's trail, with `enable_internal_detail` set to
/// `detail`.
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
	/// Wraps `listener` as a cleartext listener whose first accept fails.
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
/// a second waits unanswered in the backlog while the first lives and gets its
/// echo. The timed-out exchange leaves the stream at an unknown position, so
/// the transport fails the session and refuses the next emit before it writes.
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
	let mut queued = queued.with_timeout(CAP_WAIT)?;
	let frame = TestFrame::v0(Some("sync-past-cap"), None);
	let starved = rt::block_on(queued.emit(frame, None));
	let after_starved = TestFrame::v0(Some("sync-after-starved"), None);
	let refused = rt::block_on(queued.emit(after_starved, None));

	let timed_out = matches!(
		&starved,
		Err(TransportError::OperationFailed(TransportFailure::DeadlineExceeded))
	);
	assert_eq!(echoed, Some(admitted), "the connection within the cap must get its echo");
	assert!(
		timed_out,
		"the connection past the cap must time out unanswered, got {starved:?}"
	);
	assert!(
		matches!(refused, Err(TransportError::ConnectionFailed)),
		"the connection whose exchange broke must refuse the next emit, got {refused:?}"
	);
	Ok(())
}

/// The std runtime runs a spawned closure on a thread of its own, and the join
/// of its handle waits for the closure to end.
#[test]
fn the_std_runtime_spawns_a_closure_on_a_thread_of_its_own() -> Result<(), Box<dyn Error>> {
	let caller = thread::current().id();
	let (sender, receiver) = mpsc::channel();
	let handle = rt::spawn(move || {
		// The receiver lives until the test reads it, so the send lands.
		let _sent = sender.send(thread::current().id());
	})?;

	rt::join(handle)?;

	assert_ne!(receiver.recv()?, caller);
	Ok(())
}

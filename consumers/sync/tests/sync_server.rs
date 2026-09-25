//! Sync (`std`-without-`tokio`) `server!` accept-loop coverage.

use std::net::{SocketAddr, TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::thread;
use std::time::Duration;

use tightbeam::instrumentation::events;
use tightbeam::runtime::rt;
use tightbeam::server;
use tightbeam::testing::TestFrame;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{EndpointConfig, MessageEmitter, TransportResult};
use tightbeam::Frame;

/// Emits a frame labelled `label` over `stream` and returns it with the
/// server's reply.
fn echo(stream: NetTcpStream, label: &str) -> (Frame, Option<Frame>) {
	let mut client = TcpTransport::new(stream, EndpointConfig::cleartext());

	let frame = TestFrame::v0(Some(label), None);
	let echoed = rt::block_on(client.emit(frame.to_owned(), None)).expect("the server answers the frame");
	(frame, echoed)
}

/// Drains `trace` and counts the `GATE_ACCEPT` events it had recorded.
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
		let server = TcpListener::from_listener(listener);
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
		let server = TcpListener::from_listener(listener);
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

/// Connects to a `bind` arm's listener, which comes up on the server thread
/// after the test has reserved its port.
fn connect_with_retry(addr: SocketAddr) -> NetTcpStream {
	for _ in 0..50 {
		if let Ok(stream) = NetTcpStream::connect(addr) {
			return stream;
		}
		thread::sleep(Duration::from_millis(20));
	}
	NetTcpStream::connect(addr).expect("the bind arm's listener comes up within a second")
}

/// The `bind` arm binds the address itself and serves the same echo loop.
#[test]
fn sync_server_bind_echoes() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;

	thread::spawn(move || -> TransportResult<()> {
		server! {
			TcpListener<NetTcpListener>: bind TightBeamSocketAddr(addr),
			handle: |frame: Frame| async move { Ok(Some(frame)) }
		}
		Ok(())
	});

	let (frame, echoed) = echo(connect_with_retry(addr), "sync-bind");
	assert_eq!(echoed, Some(frame), "bind server! loop should echo the frame");
	Ok(())
}

/// The `bind` arm with policies applies them to every accepted transport.
#[test]
fn sync_server_bind_applies_policies() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	thread::spawn(move || -> TransportResult<()> {
		server! {
			TcpListener<NetTcpListener>: bind TightBeamSocketAddr(addr),
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

/// The `protocol .. bind` arm binds before it returns and serves the echo
/// loop on a thread of its own.
#[test]
fn sync_server_protocol_bind_echoes() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;

	server! {
		protocol TcpListener<NetTcpListener>: bind TightBeamSocketAddr(addr),
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	};

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-bind");
	assert_eq!(echoed, Some(frame), "protocol bind server! loop should echo the frame");
	Ok(())
}

/// The `protocol .. bind` arm with policies applies them to every accepted
/// transport.
#[test]
fn sync_server_protocol_bind_applies_policies() -> TransportResult<()> {
	let addr = NetTcpListener::bind("127.0.0.1:0")?.local_addr()?;
	let trace = TraceCollector::new();
	let audit = trace.share();

	server! {
		protocol TcpListener<NetTcpListener>: bind TightBeamSocketAddr(addr),
		policies: { with_trace: [ audit.share() ] },
		handle: |frame: Frame| async move { Ok(Some(frame)) }
	};

	let (frame, echoed) = echo(NetTcpStream::connect(addr)?, "sync-protocol-bind-audit");
	assert_eq!(echoed, Some(frame), "audited protocol bind exchange should still echo");
	assert_eq!(gate_accepts(&trace), 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

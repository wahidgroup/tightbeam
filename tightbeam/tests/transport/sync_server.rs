//! Sync (`std`-without-`tokio`) `server!` accept-loop coverage.
//!
//! The async expansion is exercised by every scenario suite; this test
//! pins the sync expansion, which otherwise only compiles when an
//! embedder builds without `tokio`.

#![cfg(all(
	feature = "tcp",
	feature = "transport-policy",
	feature = "x509",
	feature = "testing",
	feature = "instrument",
	not(feature = "tokio")
))]

use std::net::{TcpListener as NetTcpListener, TcpStream as NetTcpStream};
use std::thread;

use tightbeam::instrumentation::events;
use tightbeam::runtime::rt;
use tightbeam::server;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::sync::{TcpListener, TcpTransport};
use tightbeam::transport::{MessageEmitter, TransportResult};
use tightbeam::Frame;

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

	let stream = NetTcpStream::connect(addr)?;
	let mut client = TcpTransport::from(stream);

	let frame = create_v0_tightbeam(Some("sync-echo"), None);
	let echoed = rt::block_on(client.emit(frame.to_owned(), None))?;
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

	let stream = NetTcpStream::connect(addr)?;
	let mut client = TcpTransport::from(stream);

	let frame = create_v0_tightbeam(Some("sync-audit"), None);
	let echoed = rt::block_on(client.emit(frame.to_owned(), None))?;
	assert_eq!(echoed, Some(frame), "audited sync exchange should still echo");

	let accepts = trace
		.drain_events()
		.iter()
		.filter(|event| event.urn == events::GATE_ACCEPT)
		.count();
	assert_eq!(accepts, 1, "one accepted frame should record one GATE_ACCEPT");
	Ok(())
}

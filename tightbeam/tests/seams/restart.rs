//! The restart policies of the transport, as an outside crate writes them.
//!
//! - An outside [`RestartPolicy`] decides whether [`MessageEmitter::emit`] sends a refused frame again.
//! - An outside [`JitterStrategy`] spreads the delay of a house backoff policy.

#![cfg(all(feature = "tcp", feature = "tokio"))]

use core::time::Duration;
use std::net::SocketAddr;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestFrame;
use tightbeam::transport::policy::{JitterStrategy, RestartConfig, RestartLinearBackoff, RestartPolicy, RetryAction};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{EndpointConfig, MessageCollector, MessageEmitter, TransportFailure, TransportResult};
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

/// A restart policy an outside crate writes: when the server refuses the first
/// send as unavailable, it sends the frame again at once, and it stops on every
/// other failure and every later attempt.
struct RetryUnavailable;

impl RestartPolicy for RetryUnavailable {
	fn evaluate(&self, frame: Box<Frame>, failure: &TransportFailure, attempt: usize) -> RetryAction {
		match (failure, attempt) {
			(TransportFailure::Unavailable, 0) => RetryAction::Retry { frame, delay: Duration::ZERO },
			_ => RetryAction::NoRetry,
		}
	}
}

/// A jitter strategy an outside crate writes: it caps each delay at a
/// ceiling, so each peer waits at most the ceiling.
struct CappedJitter {
	ceiling_ms: u64,
}

impl JitterStrategy for CappedJitter {
	fn apply(&self, base_delay: u64) -> u64 {
		base_delay.min(self.ceiling_ms)
	}
}

/// A cleartext server on a loopback port that refuses the first frame it
/// collects as unavailable and echoes the second, and the address it binds.
async fn refuse_once_then_echo() -> (JoinHandle<TransportResult<()>>, SocketAddr) {
	let bound = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await;
	let listener = bound.expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");

	let serving = tokio::spawn(async move {
		let (mut transport, _) = listener.accept().await?;
		// The server refuses the first frame whatever it carries.
		let _refused = transport.collect_message().await?;
		transport.send_response(TransitStatus::Unavailable, None).await?;

		let (frame, status) = transport.collect_message().await?;
		transport.send_response(status, Some(Frame::clone(&frame))).await
	});
	(serving, addr)
}

/// A cleartext client transport connected to `addr`.
async fn cleartext_client(addr: SocketAddr) -> TcpTransport<TokioStream, DefaultCryptoProvider> {
	let stream = TcpStream::connect(addr).await.expect("the client reaches the listener");
	TcpTransport::new(TokioStream::from(stream), EndpointConfig::<DefaultCryptoProvider>::cleartext())
}

/// A client under an outside restart policy sends again the frame the server
/// refuses as unavailable, and reads the echo of the second send.
#[tokio::test]
async fn an_outside_restart_policy_resends_a_refused_frame() -> Result<(), TightBeamError> {
	let (_serving, addr) = refuse_once_then_echo().await;
	let mut client = cleartext_client(addr).await.with_restart(RetryUnavailable);
	let frame = TestFrame::v0(Some("outside-restart"), None);

	let echoed = client.emit(frame.clone(), None).await?;
	assert_eq!(echoed, Some(frame));
	Ok(())
}

/// A house linear backoff applies an outside jitter to its delay, so the
/// retry waits the 40 ms ceiling of the jitter in place of the 100 ms step.
#[test]
fn a_house_backoff_applies_an_outside_jitter() {
	let jitter = CappedJitter { ceiling_ms: 40 };
	let policy = RestartLinearBackoff::new(1, Duration::from_millis(100), 1, Some(Box::new(jitter)));
	let frame = Box::new(TestFrame::v0(Some("outside-jitter"), None));

	let action = policy.evaluate(frame.clone(), &TransportFailure::Unavailable, 0);
	assert_eq!(action, RetryAction::Retry { frame, delay: Duration::from_millis(40) });
}

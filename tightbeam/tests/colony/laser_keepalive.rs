//! The mux keepalive and the reply deadline over an in-memory laser link, on
//! the paused clock of the test. Every read deadline, every reply deadline,
//! and every probe runs on that clock, so the events hold their order on a
//! loaded host.

use core::time::Duration;
use std::sync::Arc;

use tightbeam::clock::{Clock, ManualClock};
use tightbeam::testing::TestFrame;
use tightbeam::transport::envelopes::{MuxEnvelope, MuxPingPackage};
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport, SpawnedMux};
use tightbeam::transport::policy::TimeoutConfig;
use tightbeam::transport::{
	EndpointConfig, EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError, TransportFailure, TransportResult,
};
use tokio::time::{sleep, timeout, Instant};

use crate::colony::laser_protocol::{LaserStream, LaserTransport};
use crate::common::result::TestResult;

/// The operation timeout of both ends of a link.
const IDLE_DEADLINE: Duration = Duration::from_secs(9);

/// How many streams each end of a link admits.
const STREAM_CAP: u32 = 4;

/// One end of a cleartext link, which reads under [`IDLE_DEADLINE`].
fn idle_end(stream: LaserStream, role: MuxRole) -> SpawnedMux {
	capped_end(stream, role, STREAM_CAP)
}

/// One end of a cleartext link, which reads under [`IDLE_DEADLINE`] and
/// admits `cap` streams each way.
fn capped_end(stream: LaserStream, role: MuxRole, cap: u32) -> SpawnedMux {
	let transport: LaserTransport = LaserTransport::new(stream, EndpointConfig::cleartext());
	let checked = transport.with_timeout(IDLE_DEADLINE);
	let timed = checked.expect("the deadline agrees with the defaults");
	let (reader, writer) = timed.into_split().expect("a cleartext transport splits");
	let settings = MuxSettings::symmetric(cap);

	MuxTransport::new(reader, writer, role, settings).spawn()
}

/// Both ends of a cleartext link, the client first.
fn idle_pair() -> (SpawnedMux, SpawnedMux) {
	let (client, server) = LaserStream::pair();

	(idle_end(client, MuxRole::Client), idle_end(server, MuxRole::Server))
}

/// A split hands its writer the clock of the endpoint, so a plane over the
/// half reads the clock the endpoint reads.
#[tokio::test(start_paused = true)]
async fn a_split_hands_its_writer_the_clock_of_the_endpoint() -> TestResult {
	let clock = Arc::new(ManualClock::default());
	clock.advance(Duration::from_secs(3600));
	let (near, _far) = LaserStream::pair();
	let endpoint = EndpointConfig::cleartext().with_clock(Arc::clone(&clock) as Arc<dyn Clock>);
	let transport: LaserTransport = LaserTransport::new(near, endpoint);

	let (_reader, writer) = transport.into_split()?;

	assert_eq!(EnvelopeSink::clock(&writer).monotonic(), clock.monotonic());
	Ok(())
}

/// One end that runs the keepalive holds an idle link past the read deadline
/// of both ends.
#[tokio::test(start_paused = true)]
async fn an_idle_link_outlives_its_deadline_under_a_keepalive() -> TestResult {
	let (client, _server) = idle_pair();
	let pulse = tokio::spawn(client.handle.clone().keep_alive());

	sleep(IDLE_DEADLINE * 3).await;

	client.handle.ping().await?;
	assert!(!pulse.is_finished());

	pulse.abort();
	Ok(())
}

/// A peer that drops the ack of its first probe, as a peer past its ack cap
/// does, and answers each probe after it.
async fn answer_after_the_first(stream: LaserStream) -> TransportResult<()> {
	let transport: LaserTransport = LaserTransport::new(stream, EndpointConfig::cleartext());
	let (mut reader, mut writer) = transport.with_timeout(IDLE_DEADLINE)?.into_split()?;

	reader.read_envelope().await?;

	loop {
		let TransportEnvelope::Mux(MuxEnvelope::Ping(probe)) = reader.read_envelope().await? else {
			return Err(TransportError::InvalidState);
		};

		let ack = MuxPingPackage::new(true, probe.opaque());
		writer.write_envelope(ack.into()).await?;
	}
}

/// The probe after an unanswered one draws an ack inside the read deadline, so
/// one dropped ack leaves the link up.
#[tokio::test(start_paused = true)]
async fn an_unanswered_probe_leaves_the_link_inside_its_deadline() -> TestResult {
	let (near, far) = LaserStream::pair();
	let client = idle_end(near, MuxRole::Client);
	let peer = tokio::spawn(answer_after_the_first(far));
	let pulse = tokio::spawn(client.handle.clone().keep_alive());

	sleep(IDLE_DEADLINE * 2).await;

	client.handle.ping().await?;
	assert!(!pulse.is_finished());

	pulse.abort();
	peer.abort();
	Ok(())
}

/// The first probe leaves at once, so a keepalive that starts late in the
/// deadline holds the link.
#[tokio::test(start_paused = true)]
async fn a_keepalive_started_late_holds_the_link() -> TestResult {
	let (client, _server) = idle_pair();

	sleep(IDLE_DEADLINE - Duration::from_secs(2)).await;

	let pulse = tokio::spawn(client.handle.clone().keep_alive());

	sleep(IDLE_DEADLINE * 2).await;

	client.handle.ping().await?;
	assert!(!pulse.is_finished());

	pulse.abort();
	Ok(())
}

/// With no keepalive, the same link ends at its read deadline, so the keepalive
/// alone holds the link in the tests above.
#[tokio::test(start_paused = true)]
async fn an_idle_link_ends_at_its_deadline_without_a_keepalive() {
	let (client, _server) = idle_pair();

	sleep(IDLE_DEADLINE * 3).await;

	let pinged = client.handle.ping().await;
	assert!(matches!(pinged, Err(TransportError::ConnectionClosed)));
}

/// A failed ping ends the keepalive, so its task ends with the link.
#[tokio::test(start_paused = true)]
async fn a_keepalive_ends_when_its_peer_goes() -> TestResult {
	let (client, server) = idle_pair();
	let pulse = tokio::spawn(client.handle.clone().keep_alive());

	drop(server);

	let ended = timeout(IDLE_DEADLINE, pulse).await??;
	assert!(matches!(ended, TransportError::ConnectionClosed));
	Ok(())
}

/// A local shutdown drains the link and closes it inside one pace, so the next
/// probe meets the closed link, and the keepalive ends with the close.
#[tokio::test(start_paused = true)]
async fn a_keepalive_ends_with_the_close_of_a_local_shutdown() -> TestResult {
	let (client, _server) = idle_pair();
	let pulse = tokio::spawn(client.handle.clone().keep_alive());
	sleep(Duration::from_secs(1)).await;

	client.handle.shutdown().await?;

	let ended = timeout(IDLE_DEADLINE, pulse).await??;
	assert!(matches!(ended, TransportError::ConnectionClosed));
	Ok(())
}

/// Whether `outcome` failed at a deadline.
pub(super) fn ended_at_deadline<T>(outcome: &TransportResult<T>) -> bool {
	let Err(TransportError::OperationFailed(failure)) = outcome else {
		return false;
	};

	*failure == TransportFailure::DeadlineExceeded
}

/// Whether `span` passed on the paused clock since `started`, to the
/// millisecond that the clock moves by.
pub(super) fn lasted(started: Instant, span: Duration) -> bool {
	let elapsed = started.elapsed();
	elapsed >= span && elapsed - span < Duration::from_millis(1)
}

/// A request whose peer never answers ends at the read deadline of the link,
/// while the keepalive keeps the link itself up.
#[tokio::test(start_paused = true)]
async fn an_unanswered_request_ends_at_the_read_deadline() -> TestResult {
	let (client, _server) = idle_pair();
	let pulse = tokio::spawn(client.handle.clone().keep_alive());
	let frame = TestFrame::v0(Some("unanswered"), None);

	let started = Instant::now();
	let emitted = timeout(IDLE_DEADLINE * 3, client.handle.emit_on_stream(&frame)).await?;
	let at_deadline = ended_at_deadline(&emitted);
	assert!(at_deadline, "the request ends at the deadline, not with the link");
	assert!(lasted(started, IDLE_DEADLINE), "the request waits one deadline for its reply");

	client.handle.ping().await?;
	pulse.abort();
	Ok(())
}

/// The reply of a streamed request waits from the close of the request, so a
/// request body that stays open past the deadline keeps its reply, and the
/// reply then ends one deadline after the close.
#[tokio::test(start_paused = true)]
async fn an_unanswered_stream_ends_one_deadline_after_its_close() -> TestResult {
	let (client, _server) = idle_pair();
	let pulse = tokio::spawn(client.handle.clone().keep_alive());

	let (mut sink, response) = client.handle.open_stream()?;
	let response = tokio::spawn(response);
	sink.push(b"open").await?;

	sleep(IDLE_DEADLINE * 2).await;
	assert!(!response.is_finished(), "the wait for the reply starts at the close");

	sink.close().await?;

	let closed = Instant::now();
	let answered = timeout(IDLE_DEADLINE * 3, response).await??;
	assert!(ended_at_deadline(&answered), "the reply ends at the deadline after the close");
	assert!(lasted(closed, IDLE_DEADLINE), "the reply waits one deadline from the close");

	client.handle.ping().await?;
	pulse.abort();
	Ok(())
}

/// A reply that the deadline cuts off cancels its stream, which frees the one
/// slot of a link that admits one stream.
#[tokio::test(start_paused = true)]
async fn a_reply_cut_off_at_the_deadline_frees_its_slot() -> TestResult {
	let (near, far) = LaserStream::pair();
	let client = capped_end(near, MuxRole::Client, 1);
	let _server = capped_end(far, MuxRole::Server, 1);
	let pulse = tokio::spawn(client.handle.clone().keep_alive());
	let frame = TestFrame::v0(Some("unanswered"), None);

	let emitted = timeout(IDLE_DEADLINE * 3, client.handle.emit_on_stream(&frame)).await?;
	assert!(ended_at_deadline(&emitted), "the request ends at the deadline");
	assert!(client.handle.has_stream_headroom(), "the cancel frees the slot of the request");

	pulse.abort();
	Ok(())
}

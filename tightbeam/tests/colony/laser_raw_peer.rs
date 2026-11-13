//! The near end of an in-memory laser link against a raw far end, which reads
//! and writes cleartext frames by hand. The link wakes the reader on each
//! write alone, so a frame splits at the byte a test chooses, and the events
//! hold their order on a loaded host.

use core::future::ready;
use core::time::Duration;
use std::sync::Arc;

use tightbeam::constants::MIN_MUX_CHUNK_SIZE;
use tightbeam::der::{Encode, Error as DerError};
use tightbeam::policy::TransitStatus;
use tightbeam::testing::TestFrame;
use tightbeam::transport::envelopes::{
	CancelReason, MuxCreditPackage, MuxDataPackage, MuxEnvelope, MuxOpenPackage, MuxPingPackage, MuxStreamKind,
};
use tightbeam::transport::handshake::negotiation::MuxSettings;
use tightbeam::transport::multiplex::{MuxRole, MuxTransport, SpawnedMux};
use tightbeam::transport::policy::TimeoutConfig;
use tightbeam::transport::{
	Arrived, AsyncByteRead, AsyncByteWrite, EndpointConfig, ResponsePackage, SplittableStream, TransportEnvelope,
	TransportError, WireEnvelope,
};
use tightbeam::Frame;
use tokio::time::{sleep, timeout, Instant};

use crate::colony::laser_keepalive::{ended_at_deadline, lasted};
use crate::colony::laser_protocol::{LaserReadHalf, LaserStream, LaserTransport, LaserWriteHalf};
use crate::common::poll::within_hang_guard;
use crate::common::result::TestResult;

/// The operation timeout of the near end.
const READ_DEADLINE: Duration = Duration::from_secs(9);

/// The chunks that a stream of the near end sends before the far end grants
/// more.
const CREDIT_WINDOW: u64 = 2;

/// The opaque of the probe that the far end splits across two writes.
const SPLIT_PROBE: u64 = 0x5EED;

/// The near end of a cleartext link in `role`: a mux that reads under
/// [`READ_DEADLINE`], whose streams send [`CREDIT_WINDOW`] chunks of
/// [`MIN_MUX_CHUNK_SIZE`] before a grant.
fn near_end(stream: LaserStream, role: MuxRole) -> Result<SpawnedMux, TransportError> {
	let transport: LaserTransport = LaserTransport::new(stream, EndpointConfig::cleartext());
	let (reader, writer) = transport.with_timeout(READ_DEADLINE)?.into_split()?;
	let settings = MuxSettings::symmetric(4)
		.with_chunk_size(MIN_MUX_CHUNK_SIZE)
		.with_initial_credit(CREDIT_WINDOW);

	Ok(MuxTransport::new(reader, writer, role, settings).spawn())
}

/// Both ends of a laser link: the near end in `role`, and the raw far end.
fn raw_link(role: MuxRole) -> Result<(SpawnedMux, RawPeer), TransportError> {
	let (near, far) = LaserStream::pair();
	Ok((near_end(near, role)?, RawPeer::of(far)))
}

/// The bytes of `envelope` as one cleartext frame.
fn cleartext_frame(envelope: impl Into<TransportEnvelope>) -> Result<Vec<u8>, DerError> {
	WireEnvelope::Cleartext(envelope.into()).to_der()
}

/// A request frame that spans more chunks than [`CREDIT_WINDOW`].
fn wide_request() -> Frame {
	let label = "w".repeat(4 * MIN_MUX_CHUNK_SIZE as usize);
	TestFrame::v0(Some(&label), None)
}

/// The request that asks the near server for a reply wider than
/// [`CREDIT_WINDOW`].
fn ask_wide() -> Frame {
	TestFrame::v0(Some("wide"), None)
}

/// The answer of the near server: [`wide_request`] to [`ask_wide`], and the
/// request itself to any other.
fn answer(request: Arc<Frame>) -> core::future::Ready<ResponsePackage> {
	let reply = if *request == ask_wide() {
		wide_request()
	} else {
		Frame::clone(&request)
	};

	ready(ResponsePackage::new(TransitStatus::Ok, Some(reply)))
}

/// The Open of the unary request `request` on `stream_id`, as one frame.
fn unary_open(stream_id: u32, request: &Frame) -> Result<MuxOpenPackage, DerError> {
	MuxOpenPackage::new(stream_id, true, MuxStreamKind::Unary, request.to_der()?)
}

/// The far end of a laser link, which reads and writes cleartext frames by
/// hand. A real mux far end writes each frame whole and grants credit on
/// receipt, so it cannot split a frame at a chosen byte or hold a grant for a
/// set span.
struct RawPeer {
	reader: LaserReadHalf,
	writer: LaserWriteHalf,
}

impl RawPeer {
	/// The far end over `stream`.
	fn of(stream: LaserStream) -> Self {
		let (reader, writer) = stream.into_split();
		Self { reader, writer }
	}

	/// Writes `bytes` as they are, a whole frame or a part of one.
	async fn write(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
		self.writer.write_all(bytes).await
	}

	/// Writes `envelope` as one cleartext frame.
	async fn send(&mut self, envelope: impl Into<TransportEnvelope>) -> Result<(), TransportError> {
		let frame = cleartext_frame(envelope)?;
		self.write(&frame).await
	}

	/// Reads the next cleartext envelope, or `None` once the link ends or a
	/// frame does not decode.
	async fn next(&mut self) -> Option<TransportEnvelope> {
		let mut head = [0u8; 2];
		self.reader.read_exact(&mut head).await.ok()?;

		let [tag, first] = head;
		let mut frame = vec![tag, first];
		let mut length = usize::from(first);
		if first & 0x80 != 0 {
			let mut octets = vec![0u8; usize::from(first & 0x7f)];
			self.reader.read_exact(&mut octets).await.ok()?;
			frame.extend_from_slice(&octets);
			length = octets.iter().fold(0, |length, octet| length << 8 | usize::from(*octet));
		}

		let mut content = vec![0u8; length];
		self.reader.read_exact(&mut content).await.ok()?;
		frame.extend_from_slice(&content);

		match WireEnvelope::arrive(&mut frame).ok()? {
			Arrived::Cleartext(envelope) => Some(envelope),
			Arrived::Encrypted(_) => None,
		}
	}

	/// Reads until a credit grant for stream 1, and answers whether one came
	/// before the link ended.
	async fn granted(&mut self) -> bool {
		while let Some(envelope) = self.next().await {
			if let TransportEnvelope::Mux(MuxEnvelope::Credit(grant)) = envelope {
				if grant.stream_id() == 1 {
					return true;
				}
			}
		}

		false
	}

	/// Reads until the cancel of `stream_id`, and answers its reason, or `None`
	/// once the link ends first.
	async fn cancelled(&mut self, stream_id: u32) -> Option<CancelReason> {
		while let Some(envelope) = self.next().await {
			if let TransportEnvelope::Mux(MuxEnvelope::Cancel(cancel)) = envelope {
				if cancel.stream_id() == stream_id {
					return Some(cancel.reason());
				}
			}
		}

		None
	}

	/// Reads until the `End` of `stream_id`, and answers whether it came with
	/// an Ok status before the link ended.
	async fn answered(&mut self, stream_id: u32) -> bool {
		while let Some(envelope) = self.next().await {
			if let TransportEnvelope::Mux(MuxEnvelope::End(end)) = envelope {
				if end.stream_id() == stream_id {
					return end.status() == TransitStatus::Ok;
				}
			}
		}

		false
	}

	/// Reads until the ack of the probe `opaque`, and answers whether it came
	/// before the link ended.
	async fn acks(&mut self, opaque: u64) -> bool {
		while let Some(envelope) = self.next().await {
			if let TransportEnvelope::Mux(MuxEnvelope::Ping(probe)) = envelope {
				if probe.ack() && probe.opaque() == opaque {
					return true;
				}
			}
		}

		false
	}

	/// Answers each probe until the link ends, and holds stream 1 at
	/// [`CREDIT_WINDOW`] chunks. It grants the stream more credit `grant`
	/// after the window fills, or never with `None`.
	async fn serve(mut self, grant: Option<Duration>) {
		let mut received = 0;
		while let Some(envelope) = self.next().await {
			let sent = match envelope {
				TransportEnvelope::Mux(MuxEnvelope::Ping(probe)) if !probe.ack() => {
					self.send(MuxPingPackage::new(true, probe.opaque())).await
				}
				TransportEnvelope::Mux(MuxEnvelope::Open(_) | MuxEnvelope::Data(_)) => {
					received += 1;
					self.grant_at_window(received, grant).await
				}
				_ => Ok(()),
			};
			if sent.is_err() {
				return;
			}
		}
	}

	/// Grants stream 1 more credit `grant` after `received` reaches the window.
	async fn grant_at_window(&mut self, received: u64, grant: Option<Duration>) -> Result<(), TransportError> {
		let Some(after) = grant.filter(|_| received == CREDIT_WINDOW) else {
			return Ok(());
		};

		sleep(after).await;
		self.send(MuxCreditPackage::new(1, CREDIT_WINDOW * 8)).await
	}
}

/// A far end that splits a frame across two writes, with a drain report of a
/// body between them, still delivers the frame whole. The read in flight keeps
/// the bytes of the first write, so the probe in the frame draws its ack.
///
/// The report raises the credit of the reply, so the grant shows that the
/// reader served the report while its read held the head of the probe.
#[tokio::test]
async fn a_frame_split_around_a_drain_report_arrives_whole() -> TestResult {
	let (client, mut peer) = raw_link(MuxRole::Client)?;

	// The first push opens stream 1, so the reply chunk below has a body.
	let (mut sink, mut body) = client.handle.open_duplex()?;
	sink.push(b"open").await?;

	let reply = cleartext_frame(MuxDataPackage::new(1, false, b"reply".to_vec())?)?;
	let probe = cleartext_frame(MuxPingPackage::new(false, SPLIT_PROBE))?;
	let (head, tail) = probe.split_at(probe.len() / 2);

	// The reader takes the reply whole and starts on the head of the probe,
	// and the drain report of the reply chunk comes while that read waits.
	peer.write(&[reply.as_slice(), head].concat()).await?;

	let chunk = body.chunk().await?;
	assert_eq!(chunk.as_deref(), Some(b"reply".as_slice()));

	let granted = within_hang_guard(peer.granted(), "the far end reads the grant or the end of the link").await;
	assert!(granted, "the drain report of the reply chunk raises its credit");

	peer.write(tail).await?;

	let acked = within_hang_guard(peer.acks(SPLIT_PROBE), "the far end reads the ack or the end of the link").await;
	assert!(acked, "the probe split around the drain report draws its ack");
	Ok(())
}

/// A frame that never ends ends the link one read deadline after its read
/// starts. The drain reports that come between keep the one read and its
/// deadline.
#[tokio::test(start_paused = true)]
async fn a_trickled_frame_ends_the_link_one_deadline_after_its_read_starts() -> TestResult {
	let (client, mut peer) = raw_link(MuxRole::Client)?;

	let (mut sink, mut body) = client.handle.open_duplex()?;
	sink.push(b"open").await?;

	let first = cleartext_frame(MuxDataPackage::new(1, false, b"first".to_vec())?)?;
	let second = cleartext_frame(MuxDataPackage::new(1, false, b"second".to_vec())?)?;
	let probe = cleartext_frame(MuxPingPackage::new(false, SPLIT_PROBE))?;
	let (head, _tail) = probe.split_at(probe.len() / 2);

	peer.write(&[first.as_slice(), second.as_slice(), head].concat()).await?;

	let read_started = Instant::now();

	body.chunk().await?;
	sleep(READ_DEADLINE * 2 / 3).await;
	body.chunk().await?;

	let ended = timeout(READ_DEADLINE * 3, client.handle.ping()).await?;
	let closed = matches!(ended, Err(TransportError::ConnectionClosed));
	assert!(closed, "the stalled read ends the link");
	let on_time = lasted(read_started, READ_DEADLINE);
	assert!(on_time, "the link ends one deadline after the read starts");
	Ok(())
}

/// A send that waits on credit the far end never grants ends at the read
/// deadline of the link, while the far end keeps the link itself up.
#[tokio::test(start_paused = true)]
async fn a_send_without_credit_ends_at_the_read_deadline() -> TestResult {
	let (client, peer) = raw_link(MuxRole::Client)?;
	let peer = tokio::spawn(peer.serve(None));
	let pulse = tokio::spawn(client.handle.clone().keep_alive());
	let request = wide_request();

	let started = Instant::now();
	let emitted = timeout(READ_DEADLINE * 3, client.handle.emit_on_stream(&request)).await?;
	assert!(ended_at_deadline(&emitted), "the send ends at the deadline");
	assert!(lasted(started, READ_DEADLINE), "the send waits one deadline for credit");

	pulse.abort();
	peer.abort();
	Ok(())
}

/// The reply of a request whose send waits on credit counts its deadline from
/// the last chunk, so a request that a late grant holds keeps the whole
/// deadline for its reply.
#[tokio::test(start_paused = true)]
async fn a_late_grant_moves_the_reply_deadline_to_the_last_chunk() -> TestResult {
	let (client, peer) = raw_link(MuxRole::Client)?;
	let grant_after = READ_DEADLINE * 2 / 3;
	let peer = tokio::spawn(peer.serve(Some(grant_after)));
	let pulse = tokio::spawn(client.handle.clone().keep_alive());
	let request = wide_request();

	let started = Instant::now();
	let emitted = timeout(READ_DEADLINE * 3, client.handle.emit_on_stream(&request)).await?;
	assert!(ended_at_deadline(&emitted), "the unanswered reply ends at the deadline");

	let reply_deadline = grant_after + READ_DEADLINE;
	let on_time = lasted(started, reply_deadline);
	assert!(on_time, "the reply deadline counts from the last chunk");

	pulse.abort();
	peer.abort();
	Ok(())
}

/// A reply that waits on credit the far end never grants ends its own stream
/// with a `Timeout` cancel, and the near server answers the next request.
#[tokio::test(start_paused = true)]
async fn a_reply_without_credit_ends_its_stream_alone() -> TestResult {
	let (server, mut peer) = raw_link(MuxRole::Server)?;
	let SpawnedMux { responder, .. } = server;
	let served = tokio::spawn(responder.serve(answer));

	peer.send(unary_open(1, &ask_wide())?).await?;
	// A probe inside the deadline keeps the reads of the server alive, so the
	// reply's own deadline ends the stream.
	sleep(READ_DEADLINE * 2 / 3).await;
	peer.send(MuxPingPackage::new(false, SPLIT_PROBE)).await?;

	let cancelled = within_hang_guard(peer.cancelled(1), "the far end reads the cancel or the end").await;
	assert_eq!(cancelled, Some(CancelReason::Timeout));

	peer.send(unary_open(3, &TestFrame::v0(Some("narrow"), None))?).await?;

	let answered = within_hang_guard(peer.answered(3), "the far end reads the answer or the end").await;
	assert!(answered, "the server answers the next request on the same link");

	served.abort();
	Ok(())
}

//! Reader driver: routes inbound envelopes, reassembles chunked
//! payloads under granted credit, and buffers control-plane replies
//! so a full writer queue never parks the read loop.

use core::future::poll_fn;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::future::{select, Either};
use futures::{pin_mut, SinkExt, StreamExt};

use super::body::{stream_body, BodyEvent, DrainNote, ForwardedStream, StreamBody};
use super::flow::{cap_as_usize, payload_credits, BufferedGrantor, CreditGrantor};
use super::outbound::Outbound;
use super::shared::{cancel_error, MuxShared, OpenSlot, PeerStream, StreamOutcome};
use super::writer::{goaway_best_effort, goaway_package};
use crate::der::Decode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxCancelPackage, MuxCreditPackage, MuxDataPackage, MuxEndPackage, MuxEnvelope,
	MuxOpenPackage, MuxPingPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::EnvelopeSource;
use crate::transport::multiplex::StreamId;
use crate::transport::{TransportError, TransportResult};
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::flow::renewal_floor;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::shared::RekeyPhase;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::writer::open_renewal;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::constants::DEFAULT_REKEY_MIN_SPEND_RECORDS;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::RecvCipher;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::envelopes::{
	MuxRekeyAckPackage, MuxRekeyDonePackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage,
	MUX_APPLICATION_CODE_FLOOR,
};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::{EpochInstall, RekeyDriver, ServerAckOutcome};

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// Ping acks the reader buffers while the writer queue is full.
/// Probes beyond this backlog draw no ack, so a ping flood against a
/// saturated connection extracts nothing (CVE-2019-9512).
const MAX_PENDING_PING_ACKS: usize = 4;

/// Peer-initiated event routed from the reader to the responder.
pub(super) enum InboundEvent {
	/// Unary-kind stream reassembled into its message frame
	Request(u32, Arc<Frame>),
	/// Streaming or duplex kind: the body forwards chunks as they
	/// arrive; the kind fixes the reply shape
	StreamOpen(u32, MuxStreamKind, StreamBody),
	Cancel(u32),
}

/// GoAway reason for a settlement or approval refusal: application
/// codes (at or above [`MUX_APPLICATION_CODE_FLOOR`]) pass through,
/// everything else is a settlement failure.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn refusal_reason(code: u32) -> GoAwayReason {
	if code >= MUX_APPLICATION_CODE_FLOOR {
		return GoAwayReason::Application(code);
	}

	GoAwayReason::SettlementFailed
}

/// Receiver-side reassembly state for one inbound stream direction.
struct RecvStream {
	/// Chunks concatenated in arrival order (the AEAD channel already
	/// proves order and completeness)
	buffer: Vec<u8>,
	/// Chunks accepted so far
	received: u64,
	/// Absolute cumulative chunk limit granted to the sender
	limit: u64,
	/// Hard byte ceiling on `buffer` (credit grants cannot raise this)
	max_bytes: usize,
}

impl RecvStream {
	fn new(limit: u64) -> Self {
		Self::with_ceiling(limit, crate::constants::MAX_MUX_REASSEMBLY_BYTES)
	}

	fn with_ceiling(limit: u64, max_bytes: usize) -> Self {
		Self { buffer: Vec::new(), received: 0, limit, max_bytes }
	}

	/// Account one accepted chunk against the granted limit and
	/// buffer it. `false` means the sender overran its credit or the
	/// hard reassembly byte ceiling.
	fn accept_chunk(&mut self, payload: &[u8]) -> bool {
		self.received = self.received.saturating_add(1);
		if self.received > self.limit {
			return false;
		}
		if self.buffer.len().saturating_add(payload.len()) > self.max_bytes {
			return false;
		}

		self.buffer.extend_from_slice(payload);

		true
	}
}

/// Reader driver: routes inbound envelopes off the read half.
///
/// Responses resolve their pending stream (unknown IDs silently
/// discarded: cancel/response races are benign). Requests flow to the
/// [`MuxResponder`]. Chunked payloads reassemble here, bounded by the
/// credit this endpoint granted. The [`CreditGrantor`] decides when to
/// raise a stream's limit. Protocol violations answer with a GoAway
/// and fail the driver. Spawn [`MuxReaderDriver::drive`] on the
/// caller's executor.
pub struct MuxReaderDriver<R>
where
	R: EnvelopeSource,
{
	reader: R,
	shared: Arc<MuxShared>,
	inbound: mpsc::Sender<InboundEvent>,
	outbound: mpsc::Sender<Outbound>,
	grantor: Arc<dyn CreditGrantor>,
	/// Concurrent peer-initiated streams accepted (locally advertised).
	/// Bounds `peer_reassembly` so partial opens cannot hold state
	/// beyond the cap
	/// ([RFC 9113 § 5.1.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2)
	/// stream accounting analog).
	peer_cap: u32,
	/// Largest chunk payload accepted inbound (locally advertised)
	recv_chunk_size: usize,
	/// Initial chunk limit granted to each inbound stream direction
	initial_recv_credit: u64,
	/// Credits the peer may still spend inbound. `None` = unmetered
	recv_budget: Option<u64>,
	/// Reassembly of peer-initiated request streams
	peer_reassembly: HashMap<u32, RecvStream>,
	/// Streaming peer-initiated requests: chunks forward to the
	/// handler's [`StreamBody`] instead of reassembling. Holds only
	/// peer-initiated stream IDs; locally-initiated duplex replies
	/// live in the shared `duplex_recv` registry.
	peer_bodies: HashMap<u32, ForwardedStream>,
	/// Reassembly of responses to locally-initiated streams
	local_reassembly: HashMap<u32, RecvStream>,
	/// Consumption reports from live stream bodies. Outstanding
	/// notes are bounded by forwarded chunks, which grants bound
	/// by the per-stream windows.
	drained: mpsc::UnboundedReceiver<DrainNote>,
	/// Cloned into each body; holding one end keeps `drained` open
	/// for the driver's lifetime
	drain_feedback: mpsc::UnboundedSender<DrainNote>,
	/// Control commands buffered while the writer queue is full so
	/// the read loop never parks
	/// ([RFC 9113 § 5.2.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2)).
	/// Bounded: grants coalesce per stream and evict when the stream
	/// closes, ping acks are capped, rekey legs are one-in-flight
	pending_control: VecDeque<Outbound>,
	/// Role-fixed rekey exchange; `None` keeps every rekey leg an
	/// unsolicited protocol violation
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	rekey: Option<RekeyDriver>,
	/// Client epoch state held between the `RekeyAck` and the
	/// server's `RekeyDone`: the receive cipher installs and the
	/// receipt rotates only at the `RekeyDone` boundary
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pending_install: Option<PendingDone>,
	/// Negotiated inbound budget, restored at each epoch boundary
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	initial_recv_budget: Option<u64>,
	/// Receive-direction records left at which the client opens a
	/// renewal (tracks the peer's send counter)
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	renewal_floor: u64,
	/// Receive-direction records left at the last epoch install,
	/// for the server's minimum-spend flood bound
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	epoch_recv_baseline: u64,
}

/// Client epoch state parked between `RekeyAck` and `RekeyDone`.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
struct PendingDone {
	recv_cipher: RecvCipher,
	receipt: StoredReceipt,
}

/// Drain buffered control into the writer queue. Cancellation-safe:
/// a command leaves the buffer only after its slot is reserved.
async fn flush_control(outbound: &mut mpsc::Sender<Outbound>, pending: &mut VecDeque<Outbound>) -> TransportResult<()> {
	while !pending.is_empty() {
		let ready = poll_fn(|cx| outbound.poll_ready(cx)).await;
		if ready.is_err() {
			return Err(TransportError::ConnectionClosed);
		}

		let Some(command) = pending.pop_front() else {
			return Ok(());
		};

		outbound.start_send(command).map_err(|_| TransportError::ConnectionClosed)?;
	}

	Ok(())
}

/// Whether `command` is a buffered credit grant for `stream_id`.
fn is_credit_grant_for(command: &Outbound, stream_id: u32) -> bool {
	matches!(
		command,
		Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
			if package.stream_id() == stream_id
	)
}

/// Whether `command` is a buffered ping ack.
fn is_ping_ack(command: &Outbound) -> bool {
	matches!(command, Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(_))))
}

/// One unit of read-loop work (see [`MuxReaderDriver::next_event`]).
enum ReaderEvent {
	Envelope(TransportEnvelope),
	/// A stream body reported consumer progress
	Drained(DrainNote),
	/// Buffered control flushed into the writer queue
	Flushed,
}

/// The driver holds a feedback sender for the body channel, so the
/// note stream outlives every body.
fn drain_event(note: Option<DrainNote>) -> ReaderEvent {
	match note {
		Some(note) => ReaderEvent::Drained(note),
		None => ReaderEvent::Flushed,
	}
}

impl<R> MuxReaderDriver<R>
where
	R: EnvelopeSource,
{
	/// Assemble the reader driver over its shared state and
	/// channels: the single construction point, so a new field has
	/// exactly one home.
	pub(super) fn new(
		reader: R,
		shared: Arc<MuxShared>,
		inbound: mpsc::Sender<InboundEvent>,
		outbound: mpsc::Sender<Outbound>,
		settings: &MuxSettings,
	) -> Self {
		let (drain_feedback, drained) = mpsc::unbounded();

		Self {
			reader,
			shared,
			inbound,
			outbound,
			grantor: Arc::new(BufferedGrantor::default()),
			peer_cap: settings.peer_initiated_cap,
			recv_chunk_size: cap_as_usize(settings.recv_chunk_size).max(1),
			initial_recv_credit: settings.initial_recv_credit.max(1),
			recv_budget: settings.recv_budget,
			peer_reassembly: HashMap::new(),
			peer_bodies: HashMap::new(),
			local_reassembly: HashMap::new(),
			drained,
			drain_feedback,
			pending_control: VecDeque::new(),
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			rekey: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			pending_install: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			initial_recv_budget: settings.recv_budget,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			renewal_floor: renewal_floor(settings.drain_reserve_records()),
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			epoch_recv_baseline: 0,
		}
	}

	/// Drain-note sender for bodies created outside the reader
	/// (refcount bump, not a data copy).
	pub(super) fn drain_feedback(&self) -> mpsc::UnboundedSender<DrainNote> {
		self.drain_feedback.clone()
	}

	/// Override the receiver-side stream credit policy.
	pub(super) fn set_grantor(&mut self, grantor: Arc<dyn CreditGrantor>) {
		self.grantor = grantor;
	}

	/// Attach in-band rekey: seed the receipt accessor from the
	/// handshake artifact, stamp the epoch baseline off the receive
	/// cipher's remaining records, and (client role) open admissions
	/// gating for renewals.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn attach_rekey(&mut self, driver: RekeyDriver, receipt: StoredReceipt) {
		self.shared.rotate_receipt(receipt);
		self.epoch_recv_baseline = self.reader.remaining_records();

		if matches!(&driver, RekeyDriver::Client(_)) {
			self.shared.mark_rekey_client();
		}
		self.rekey = Some(driver);
	}

	/// Run the driver until the connection ends. Pending streams observe
	/// the failure.
	pub async fn drive(mut self) -> TransportResult<()> {
		let result = self.route_envelopes().await;

		self.shared.fail_all_pending();

		result
	}

	/// Route inbound envelopes to their pending streams or handlers,
	/// interleaving body-drain reports into credit replenishment.
	async fn route_envelopes(&mut self) -> TransportResult<()> {
		loop {
			match self.next_event().await? {
				ReaderEvent::Envelope(envelope) => {
					let TransportEnvelope::Mux(mux) = envelope else {
						return Err(self.protocol_violation());
					};
					self.route_mux(mux).await?;
				}
				ReaderEvent::Drained(note) => self.grant_streaming(note)?,
				ReaderEvent::Flushed => {}
			}

			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			self.watch_recv_records()?;
		}
	}

	/// Route one inbound mux envelope.
	async fn route_mux(&mut self, mux: MuxEnvelope) -> TransportResult<()> {
		match mux {
			MuxEnvelope::End(package) => self.route_end(package),
			MuxEnvelope::Open(package) => self.route_open(package).await,
			MuxEnvelope::Data(package) => self.route_data(package).await,
			MuxEnvelope::Credit(package) => {
				self.shared.apply_credit_grant(package.stream_id(), package.limit());
				Ok(())
			}
			MuxEnvelope::Cancel(package) => self.route_cancel(package).await,
			MuxEnvelope::Ping(package) => self.route_ping(package),
			MuxEnvelope::GoAway(package) => {
				self.shared.fail_pending_above(package.last_stream_id(), package.reason());
				self.shared.fail_duplex_above(package.last_stream_id());
				// Responses to streams the peer will never answer
				// are no longer coming: drop their partial buffers
				self.local_reassembly.retain(|id, _| self.shared.is_pending(*id));
				Ok(())
			}
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			MuxEnvelope::RekeyRequest(package) => self.route_rekey_request(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			MuxEnvelope::RekeyResponse(package) => self.route_rekey_response(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			MuxEnvelope::RekeyAck(package) => self.route_rekey_ack(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			MuxEnvelope::RekeyDone(package) => self.route_rekey_done(package),
			// No rekey exchange can be driven on this build:
			// any rekey leg is unsolicited and fails closed.
			#[cfg(not(any(feature = "transport-cms", feature = "transport-ecies")))]
			MuxEnvelope::RekeyRequest(_)
			| MuxEnvelope::RekeyResponse(_)
			| MuxEnvelope::RekeyAck(_)
			| MuxEnvelope::RekeyDone(_) => Err(self.protocol_violation()),
		}
	}

	/// Receive-direction renewal trigger: the client's receive
	/// counter tracks the server's send counter on the ordered
	/// channel, so approaching the record limit here opens a
	/// renewal without any wire addition.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn watch_recv_records(&mut self) -> TransportResult<()> {
		if self.reader.remaining_records() > self.renewal_floor {
			return Ok(());
		}
		let Some(RekeyDriver::Client(exchange)) = self.rekey.as_ref() else {
			return Ok(());
		};
		let Some(request) = open_renewal(&self.shared, exchange) else {
			return Ok(());
		};

		self.queue_control(request)
	}

	/// Drain gracefully on a settlement or approval refusal,
	/// preserving the connection long enough for owed traffic and
	/// the recorded evidence to survive the disagreement.
	///
	/// Runs on the read loop, so the GoAway buffers through
	/// [`Self::queue_command`] rather than awaiting a full outbound
	/// queue (RFC 9113 §5.2: reads must continue under write
	/// backpressure or mutually saturated peers deadlock).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn drain_refused(&mut self, code: u32) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		self.shared.emit_event(events::MUX_REKEY_REFUSED);

		let Some(package) = goaway_package(&self.shared, refusal_reason(code)) else {
			return Ok(());
		};

		self.queue_control(package.into())
	}

	/// Server leg: issue the epoch receipt for a renewal request.
	///
	/// Rekey-flood bound (CWE-400): a request while an exchange is
	/// in flight, or before the peer spent
	/// [`DEFAULT_REKEY_MIN_SPEND_RECORDS`] records since the last
	/// install, is a protocol violation.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn route_rekey_request(&mut self, package: MuxRekeyRequestPackage) -> TransportResult<()> {
		let spent = self.epoch_recv_baseline.saturating_sub(self.reader.remaining_records());
		let issued = {
			let Some(RekeyDriver::Server(exchange)) = self.rekey.as_mut() else {
				return Err(self.protocol_violation());
			};
			if exchange.exchange_in_flight() || spent < DEFAULT_REKEY_MIN_SPEND_RECORDS {
				None
			} else {
				Some(exchange.process_request(&package).await)
			}
		};

		match issued {
			Some(Ok(response)) => {
				#[cfg(feature = "instrument")]
				self.shared.emit_event(events::MUX_REKEY_RECEIPT_ISSUED);

				let envelope = TransportEnvelope::from(response);
				self.queue_control(envelope)
			}
			Some(Err(HandshakeError::SettlementRejected { code })) => self.drain_refused(code),
			Some(Err(_)) => {
				#[cfg(feature = "instrument")]
				self.shared.emit_event(events::MUX_REKEY_VERIFY_FAILED);

				Err(self.protocol_violation())
			}
			None => Err(self.protocol_violation()),
		}
	}

	/// Client leg: verify and countersign the epoch receipt, park
	/// new c2s admissions, and hand the `RekeyAck` plus fresh send
	/// cipher to the writer (which holds it until owed chunks
	/// quiesce). The receive-side install waits for `RekeyDone`.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn route_rekey_response(&mut self, package: MuxRekeyResponsePackage) -> TransportResult<()> {
		if self.shared.rekey_phase() != RekeyPhase::AwaitingResponse {
			return Err(self.protocol_violation());
		}
		let Some(RekeyDriver::Client(exchange)) = self.rekey.as_ref() else {
			return Err(self.protocol_violation());
		};

		let exchange = Arc::clone(exchange);
		let mut guard = exchange.lock().await;
		let processed = guard.process_response(package).await;

		drop(guard);

		match processed {
			Ok((ack, install)) => {
				#[cfg(feature = "instrument")]
				self.shared.emit_event(events::MUX_REKEY_RECEIPT_COUNTERSIGNED);

				let EpochInstall { send_cipher, recv_cipher, receipt, epoch: _ } = install;

				self.pending_install = Some(PendingDone { recv_cipher, receipt });
				// Park before the ack is queued: no admission can
				// debit the old epoch once the ack is in motion
				self.shared.begin_ack_flush();

				let ack_envelope = TransportEnvelope::from(ack);
				let install = Outbound::EnvelopeThenInstall(ack_envelope, Box::new(send_cipher));
				self.queue_command(install)
			}
			Err(HandshakeError::ApprovalRefused { code }) => {
				self.shared.finish_renewal();
				self.drain_refused(code)
			}
			Err(_) => {
				#[cfg(feature = "instrument")]
				self.shared.emit_event(events::MUX_REKEY_VERIFY_FAILED);

				Err(self.protocol_violation())
			}
		}
	}

	/// Server leg: settle the countersignature and switch epochs.
	///
	/// The receive cipher installs even on a settlement refusal:
	/// the client switched its send direction at the `RekeyAck`
	/// boundary, so the refusal's GoAway drain must stay
	/// decryptable. A rejected settlement drains instead of
	/// resetting budgets.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn route_rekey_ack(&mut self, package: MuxRekeyAckPackage) -> TransportResult<()> {
		let settled = {
			let Some(RekeyDriver::Server(exchange)) = self.rekey.as_mut() else {
				return Err(self.protocol_violation());
			};

			exchange.process_ack(package).await
		};
		let Ok(outcome) = settled else {
			#[cfg(feature = "instrument")]
			self.shared.emit_event(events::MUX_REKEY_VERIFY_FAILED);

			return Err(self.protocol_violation());
		};

		let ServerAckOutcome { install, rejection } = outcome;
		let EpochInstall { send_cipher, recv_cipher, receipt, epoch: _ } = install;
		self.reader.install_recv_cipher(recv_cipher)?;
		self.epoch_recv_baseline = self.reader.remaining_records();

		if let Some(code) = rejection {
			return self.drain_refused(code);
		}

		// Budget boundary at `RekeyDone`: the strict c2s park
		// guarantees nothing is in flight across the inbound reset,
		// and every post-reset outbound debit queues behind the
		// `RekeyDone` about to be enqueued
		self.renew_epoch_terms(receipt);

		let done_package = MuxRekeyDonePackage::default();
		let done_envelope = TransportEnvelope::from(done_package);

		let install = Outbound::EnvelopeThenInstall(done_envelope, Box::new(send_cipher));
		self.queue_command(install)
	}

	/// Client leg: `RekeyDone` activates the new epoch - receive
	/// cipher installs, budgets reset, the receipt rotates, and
	/// parked admissions resume.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn route_rekey_done(&mut self, _package: MuxRekeyDonePackage) -> TransportResult<()> {
		if self.shared.rekey_phase() != RekeyPhase::AwaitingDone {
			return Err(self.protocol_violation());
		}
		let Some(PendingDone { recv_cipher, receipt }) = self.pending_install.take() else {
			return Err(self.protocol_violation());
		};

		self.reader.install_recv_cipher(recv_cipher)?;
		self.renew_epoch_terms(receipt);
		self.shared.finish_renewal();

		Ok(())
	}

	/// Activate a fresh epoch's terms: both budgets reset to the
	/// negotiated figures and the dual-signed receipt rotates
	/// (credit-match invariant keeps epoch terms equal to the
	/// initial ones).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn renew_epoch_terms(&mut self, receipt: StoredReceipt) {
		self.recv_budget = self.initial_recv_budget;
		self.shared.reset_send_budget();
		self.shared.rotate_receipt(receipt);

		#[cfg(feature = "instrument")]
		self.shared.emit_event(events::MUX_REKEY_RENEWED);
	}

	/// Enforce the advertised chunk ceiling and debit the inbound
	/// session budget for one chunk. Both overruns are protocol
	/// violations: the sender knows the ceiling and its own grant.
	fn charge_inbound_chunk(&mut self, payload: &[u8]) -> TransportResult<()> {
		if payload.len() > self.recv_chunk_size {
			return Err(self.protocol_violation());
		}
		let Some(balance) = self.recv_budget else {
			return Ok(());
		};

		let credits = payload_credits(payload.len(), self.recv_chunk_size, self.shared.credit_unit);
		if credits > balance {
			return Err(self.protocol_violation());
		}

		self.recv_budget = Some(balance - credits);
		Ok(())
	}

	/// Await the next unit of read-loop work: an inbound envelope, a
	/// body-drain report, or a completed control flush. The read
	/// never parks behind the flush or the drain reports.
	async fn next_event(&mut self) -> TransportResult<ReaderEvent> {
		let Self { reader, drained, outbound, pending_control, .. } = self;

		let read = reader.read_envelope();
		let note = drained.next();
		pin_mut!(read, note);

		if pending_control.is_empty() {
			return match select(read, note).await {
				Either::Left((envelope, _)) => Ok(ReaderEvent::Envelope(envelope?)),
				Either::Right((note, _)) => Ok(drain_event(note)),
			};
		}

		let flush = flush_control(outbound, pending_control);
		pin_mut!(flush);

		match select(read, select(note, flush)).await {
			Either::Left((envelope, _)) => Ok(ReaderEvent::Envelope(envelope?)),
			Either::Right((Either::Left((note, _)), _)) => Ok(drain_event(note)),
			Either::Right((Either::Right((flushed, _)), _)) => {
				flushed?;
				Ok(ReaderEvent::Flushed)
			}
		}
	}

	/// Replenish a streaming stream's credit from consumer progress.
	/// Whether this endpoint initiated the stream picks the ledger:
	/// peer-initiated request bodies live in `peer_bodies`,
	/// locally-initiated duplex reply bodies in the shared duplex registry.
	///
	/// Grants clamp to `consumed + window` - the body channel's
	/// absorption ceiling. Thus, no [`CreditGrantor`] implementation
	/// can grant a conforming peer past the channel's capacity. The
	/// clamp is also what bounds the unbounded drain-note channel:
	/// notes only arise from chunks this grant ceiling admitted, so
	/// outstanding notes never exceed the per-stream windows.
	fn grant_streaming(&mut self, note: DrainNote) -> TransportResult<()> {
		let limits = if self.shared.role.initiates(note.stream_id) {
			self.shared.duplex_limits(note.stream_id)
		} else {
			self.peer_bodies.get(&note.stream_id).map(ForwardedStream::limits)
		};
		let Some((limit, window)) = limits else {
			return Ok(());
		};

		let granted = self.grantor.replenish(StreamId::new(note.stream_id), note.consumed, limit);
		let Some(new_limit) = granted else {
			return Ok(());
		};

		let new_limit = new_limit.min(note.consumed.saturating_add(window));
		if new_limit <= limit {
			return Ok(());
		}

		if self.shared.role.initiates(note.stream_id) {
			self.shared.set_duplex_limit(note.stream_id, new_limit);
		} else if let Some(stream) = self.peer_bodies.get_mut(&note.stream_id) {
			stream.raise_limit(new_limit);
		}

		self.queue_credit(note.stream_id, new_limit)
	}

	/// Hand a control command to the writer, buffering on a full
	/// queue instead of parking the read loop.
	fn queue_command(&mut self, command: Outbound) -> TransportResult<()> {
		if !self.pending_control.is_empty() {
			self.pending_control.push_back(command);
			return Ok(());
		}

		match self.outbound.try_send(command) {
			Ok(()) => Ok(()),
			Err(refused) if refused.is_full() => {
				self.pending_control.push_back(refused.into_inner());
				Ok(())
			}
			Err(_) => Err(TransportError::ConnectionClosed),
		}
	}

	/// Hand a control envelope to the writer, buffering on a full
	/// queue instead of parking the read loop.
	fn queue_control(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		self.queue_command(Outbound::Envelope(envelope))
	}

	/// Queue a credit grant, superseding any buffered grant for the
	/// same stream: `Credit` is an absolute limit, only the newest matters.
	fn queue_credit(&mut self, stream_id: u32, new_limit: u64) -> TransportResult<()> {
		self.evict_credit(stream_id);
		self.queue_control(MuxCreditPackage::new(stream_id, new_limit).into())
	}

	/// Drop any buffered grant for `stream_id`. Called when the stream
	/// closes: ids never recur, so a leftover grant is dead weight that
	/// would accumulate across stream churn under writer backpressure.
	fn evict_credit(&mut self, stream_id: u32) {
		self.pending_control
			.retain(|envelope| !is_credit_grant_for(envelope, stream_id));
	}

	/// Queue a ping ack; probes beyond [`MAX_PENDING_PING_ACKS`] draw no ack.
	fn queue_ping_ack(&mut self, package: MuxPingPackage) -> TransportResult<()> {
		let buffered_acks = self.pending_control.iter().filter(|envelope| is_ping_ack(envelope)).count();
		if buffered_acks >= MAX_PENDING_PING_ACKS {
			return Ok(());
		}

		self.queue_control(package.into())
	}

	/// Consult the grantor and queue a credit grant when it raises
	/// the stream's limit.
	fn maybe_grant(&mut self, stream_id: u32, stream: &mut RecvStream) -> TransportResult<()> {
		// No further grants once the byte ceiling is full: raising the
		// chunk window cannot admit more payload past max_bytes.
		if stream.buffer.len() >= stream.max_bytes {
			return Ok(());
		}

		let granted = self.grantor.replenish(StreamId::new(stream_id), stream.received, stream.limit);
		let Some(new_limit) = granted else {
			return Ok(());
		};
		if new_limit <= stream.limit {
			return Ok(());
		}

		stream.limit = new_limit;

		self.queue_credit(stream_id, new_limit)
	}

	/// Decode a reassembled stream payload into its message frame.
	///
	/// Empty payload = message-less trailer. Version validation happens
	/// here rather than at the io layer because chunked payloads only
	/// become a frame after reassembly.
	fn decode_stream_frame(&mut self, payload: &[u8]) -> TransportResult<Option<Frame>> {
		if payload.is_empty() {
			return Ok(None);
		}

		let frame = match Frame::from_der(payload) {
			Ok(frame) => frame,
			Err(_) => return Err(self.protocol_violation()),
		};
		if !frame.validate_version_compatibility() {
			return Err(self.protocol_violation());
		}

		Ok(Some(frame))
	}

	fn route_end(&mut self, package: MuxEndPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		if !self.shared.role.initiates(stream_id) {
			return Err(self.protocol_violation());
		}

		self.evict_credit(stream_id);

		// The sender debited its ledgers for this record whether or
		// not the stream is still pending, so account it either way
		if !package.payload().is_empty() {
			self.charge_inbound_chunk(package.payload())?;
		}

		// Duplex reply: the trailer closes the body, Ok as a clean
		// end, anything else as its transport error
		if let Some(forwarder) = self.shared.take_duplex(stream_id) {
			self.shared.remove_pending(stream_id);
			return self.finish_duplex_body(forwarder, &package);
		}

		// Resolve before decoding: stale ends are discarded without
		// inspecting their payload, and non-Ok trailers never
		// contribute a frame, so garbage bytes on either cannot tear
		// down the connection.
		let Some(sender) = self.shared.remove_pending(stream_id) else {
			self.local_reassembly.remove(&stream_id);
			return Ok(());
		};

		let mut stream = self.take_local_reassembly(stream_id);
		if !package.payload().is_empty() && !stream.accept_chunk(package.payload()) {
			return Err(self.protocol_violation());
		}

		let message = match package.status() {
			TransitStatus::Ok => self.decode_stream_frame(&stream.buffer)?,
			_ => None,
		};

		let response = ResponsePackage::new(package.status(), message);
		let _ = sender.send(StreamOutcome::Response(response));
		Ok(())
	}

	/// Close a duplex reply body from its `End` trailer: forward the
	/// final inline chunk when present, then the terminal event.
	fn finish_duplex_body(&mut self, mut forwarder: ForwardedStream, package: &MuxEndPackage) -> TransportResult<()> {
		if !package.payload().is_empty() && !forwarder.accept_and_forward(package.payload()) {
			return Err(self.protocol_violation());
		}

		let terminal = match package.status() {
			TransitStatus::Ok => BodyEvent::End,
			status => BodyEvent::Failed(TransportError::from(status)),
		};
		let _ = forwarder.forward(terminal);

		Ok(())
	}

	async fn route_open(&mut self, package: MuxOpenPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		match self.shared.register_peer_stream(stream_id) {
			Ok(PeerStream::Accept) => self.accept_peer_open(stream_id, package).await,
			Ok(PeerStream::RejectDraining) => self.reject_draining_open(stream_id, package),
			Err(_) => Err(self.protocol_violation()),
		}
	}

	/// Accept a peer open, routed by the kind the initiating call
	/// stamped on the record: unary streams reassemble into one frame,
	/// streaming and duplex kinds forward chunks as they arrive.
	async fn accept_peer_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		match package.kind() {
			MuxStreamKind::Unary => self.accept_unary_open(stream_id, package).await,
			MuxStreamKind::Streaming | MuxStreamKind::Duplex => self.accept_streaming_open(stream_id, package).await,
		}
	}

	/// Accept a unary-kind open: dispatch whole-frame opens, otherwise
	/// park the first chunk under the peer-initiated reassembly cap.
	async fn accept_unary_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		self.charge_inbound_chunk(package.payload())?;
		if package.last() {
			// Whole frame in one chunk: the credit floor of one admits
			// it without touching reassembly
			return self.dispatch_request(stream_id, package.payload()).await;
		}

		// A conforming sender keeps its in-flight opens under the cap
		// it was advertised, so one more partial stream is a
		// violation, not backpressure
		if self.live_peer_streams() >= cap_as_usize(self.peer_cap) {
			return Err(self.protocol_violation());
		}

		let stream = RecvStream::new(self.initial_recv_credit);
		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.peer_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Streams currently held open by the peer, across both
	/// consumption paths (mixed kinds share one flood bound).
	fn live_peer_streams(&self) -> usize {
		self.peer_bodies.len().saturating_add(self.peer_reassembly.len())
	}

	/// Accept a streaming- or duplex-kind open: chunks forward to
	/// the handler's [`StreamBody`] as they arrive, no reassembly.
	/// The initial grant window doubles as the body channel bound;
	/// further grants follow consumer drain (see
	/// [`Self::grant_streaming`]).
	async fn accept_streaming_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		self.charge_inbound_chunk(package.payload())?;

		// Same partial-open flood bound as unary reassembly
		if !package.last() && self.live_peer_streams() >= cap_as_usize(self.peer_cap) {
			return Err(self.protocol_violation());
		}

		let (body, mut forwarder) = stream_body(
			OpenSlot::assigned(stream_id),
			self.initial_recv_credit,
			self.drain_feedback.clone(),
		);
		if !forwarder.accept_and_forward(package.payload()) {
			return Err(self.protocol_violation());
		}

		if package.last() {
			let _ = forwarder.forward(BodyEvent::End);
		} else {
			self.peer_bodies.insert(stream_id, forwarder);
		}

		self.dispatch_stream_open(stream_id, package.kind(), body).await
	}

	/// Hand a fresh streaming body to the responder, refusing the
	/// stream when no responder serves this connection.
	async fn dispatch_stream_open(
		&mut self,
		stream_id: u32,
		kind: MuxStreamKind,
		body: StreamBody,
	) -> TransportResult<()> {
		let event = InboundEvent::StreamOpen(stream_id, kind, body);
		if self.inbound.send(event).await.is_err() {
			self.peer_bodies.remove(&stream_id);
			self.refuse_stream(stream_id)?;
		}

		Ok(())
	}

	/// Refuse an open past our GoAway watermark. The chunk still
	/// crossed the wire under the sender's ledgers, so debit inbound.
	fn reject_draining_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		self.shared.emit_event(events::MUX_OPEN_DRAINING);

		self.charge_inbound_chunk(package.payload())?;
		self.refuse_stream(stream_id)?;

		Ok(())
	}

	async fn route_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();

		// Empty payloads travel only in trailers: a `last`-flagged
		// empty record closes a request body whose end was not known
		// at the final push (see `RequestSink::close`)
		if package.payload().is_empty() && !package.last() {
			return Err(self.protocol_violation());
		}

		if self.shared.role.peer().initiates(stream_id) {
			return self.route_request_data(package).await;
		}
		if self.shared.role.initiates(stream_id) {
			return self.route_response_data(package).await;
		}

		Err(self.protocol_violation())
	}

	/// Append `payload` into `stream` or fail closed on credit overrun.
	fn accept_chunk_or_violate(&mut self, mut stream: RecvStream, payload: &[u8]) -> TransportResult<RecvStream> {
		if !stream.accept_chunk(payload) {
			return Err(self.protocol_violation());
		}

		Ok(stream)
	}

	/// Detach a locally-initiated stream's reassembly, starting a
	/// fresh one at the initial credit on its first chunk.
	fn take_local_reassembly(&mut self, stream_id: u32) -> RecvStream {
		self.local_reassembly
			.remove(&stream_id)
			.unwrap_or_else(|| RecvStream::new(self.initial_recv_credit))
	}

	/// Accept a non-final chunk and raise credit when the grantor asks.
	/// Caller parks the returned stream in the right reassembly map.
	fn park_reassembly(&mut self, stream_id: u32, stream: RecvStream, payload: &[u8]) -> TransportResult<RecvStream> {
		let mut stream = self.accept_chunk_or_violate(stream, payload)?;
		self.maybe_grant(stream_id, &mut stream)?;

		Ok(stream)
	}

	/// Continuation chunk of a peer-initiated request.
	async fn route_request_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		self.charge_inbound_chunk(package.payload())?;

		if self.peer_bodies.contains_key(&stream_id) {
			return self.forward_request_chunk(&package);
		}

		let Some(stream) = self.peer_reassembly.remove(&stream_id) else {
			// A refused or cancelled stream still flushing chunks it
			// had credit for. Anything beyond the high-water mark
			// never opened
			if stream_id <= self.shared.last_peer_stream_id() {
				return Ok(());
			}

			return Err(self.protocol_violation());
		};

		if package.last() {
			// Final chunk: dispatch without a credit raise - the stream
			// is leaving reassembly
			let stream = self.accept_chunk_or_violate(stream, package.payload())?;
			self.evict_credit(stream_id);
			return self.dispatch_request(stream_id, &stream.buffer).await;
		}

		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.peer_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Forward one streaming request chunk into its body channel.
	/// Overrunning the granted limit is a violation exactly as in
	/// reassembly. A dropped body (refused at the cap or abandoned
	/// by its handler) evicts the forwarder: the stream's remaining
	/// flushes route through the tolerated refused-stream path
	/// instead of being copied into a dead channel, and consumed
	/// credit stays consumed (no refunds).
	fn forward_request_chunk(&mut self, package: &MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		let Some(stream) = self.peer_bodies.get_mut(&stream_id) else {
			return Err(self.protocol_violation());
		};

		if stream.severed() {
			self.peer_bodies.remove(&stream_id);
			self.evict_credit(stream_id);
			return Ok(());
		}

		if !stream.accept_and_forward(package.payload()) {
			return Err(self.protocol_violation());
		}

		if package.last() {
			if let Some(mut stream) = self.peer_bodies.remove(&stream_id) {
				let _ = stream.forward(BodyEvent::End);
			}
			self.evict_credit(stream_id);
		}

		Ok(())
	}

	/// Continuation chunk of a response to a locally-initiated stream.
	/// The responder grammar terminates with `End`, never `Data(last)`.
	async fn route_response_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		self.charge_inbound_chunk(package.payload())?;

		if package.last() {
			return Err(self.protocol_violation());
		}

		// Duplex reply: forward into the body instead of reassembling
		if let Some(accepted) = self.shared.forward_duplex_chunk(stream_id, package.payload()) {
			if !accepted {
				return Err(self.protocol_violation());
			}

			return Ok(());
		}

		// Stale flush of a stream this endpoint already resolved
		if !self.shared.is_pending(stream_id) {
			self.local_reassembly.remove(&stream_id);
			self.evict_credit(stream_id);
			return Ok(());
		}

		let stream = self.take_local_reassembly(stream_id);
		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.local_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Decode a fully reassembled request and hand it to the responder.
	async fn dispatch_request(&mut self, stream_id: u32, payload: &[u8]) -> TransportResult<()> {
		let frame = match self.decode_stream_frame(payload)? {
			Some(frame) => frame,
			// A request stream must carry a message
			None => return Err(self.protocol_violation()),
		};

		let event = InboundEvent::Request(stream_id, Arc::new(frame));
		if self.inbound.send(event).await.is_err() {
			// No responder is serving this connection
			self.refuse_stream(stream_id)?;
		}

		Ok(())
	}

	async fn route_cancel(&mut self, package: MuxCancelPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		if self.shared.role.initiates(stream_id) {
			// Peer cancelled/refused a stream we initiated
			self.local_reassembly.remove(&stream_id);
			if let Some(mut forwarder) = self.shared.take_duplex(stream_id) {
				let _ = forwarder.forward(BodyEvent::Failed(cancel_error(package.reason())));
			}
			self.evict_credit(stream_id);
			self.shared.resolve(stream_id, StreamOutcome::Cancelled(package.reason()));
			return Ok(());
		}
		if self.shared.role.peer().initiates(stream_id) {
			// Peer withdrew its own request: drop any partial
			// reassembly or streaming body (the dropped sender ends
			// the body), release the response ledger, abort the handler
			self.peer_reassembly.remove(&stream_id);
			self.peer_bodies.remove(&stream_id);
			self.evict_credit(stream_id);
			self.shared.finish_send_stream(stream_id);

			let _ = self.inbound.send(InboundEvent::Cancel(stream_id)).await;
			return Ok(());
		}

		Err(self.protocol_violation())
	}

	/// Answer a peer probe with its ack. Terminates here: pings never
	/// reach the responder or the application handler.
	fn route_ping(&mut self, package: MuxPingPackage) -> TransportResult<()> {
		if package.ack() {
			self.shared.resolve_ping(package.opaque());
			return Ok(());
		}

		// After our GoAway the writer's remaining records are reserved for
		// owed stream traffic (see `MuxSettings::drain_reserve_records`),
		// so peer probes draw no acks. Combined with the capped ack backlog
		// this bounds what a ping flood can extract (CVE-2019-9512).
		if self.shared.shutdown_begun() {
			return Ok(());
		}

		self.queue_ping_ack(MuxPingPackage::new(true, package.opaque()))
	}

	/// Refuse a peer-initiated stream with a `Rejected` cancel. Rides
	/// the control buffer: a refusal lost to a full writer queue would
	/// leave the peer's stream pending forever.
	fn refuse_stream(&mut self, stream_id: u32) -> TransportResult<()> {
		let package = MuxCancelPackage::new(stream_id, CancelReason::Rejected);
		self.queue_control(package.into())
	}

	fn protocol_violation(&mut self) -> TransportError {
		#[cfg(feature = "instrument")]
		self.shared.emit_event(events::MUX_PROTOCOL_ERROR);

		let last = self.shared.last_peer_stream_id();
		goaway_best_effort(&self.shared, &self.outbound, last, GoAwayReason::ProtocolError);

		TransportError::InvalidMessage
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, Future};
	use core::pin::Pin;
	use core::sync::atomic::{AtomicUsize, Ordering};
	use core::task::Poll;

	use super::super::testing::{body_fixture, noop_cx, poll_chunk};
	use super::*;
	use crate::transport::multiplex::MuxRole;
	use crate::utils::marker::MaybeSend;

	#[test]
	fn test_recv_stream_enforces_granted_limit() {
		let mut stream = RecvStream::new(2);
		assert!(stream.accept_chunk(b"ab"));
		assert!(stream.accept_chunk(b"cd"));
		assert!(!stream.accept_chunk(b"ef"));
		assert_eq!(stream.buffer.as_slice(), b"abcd");
	}

	// Unary reassembly must refuse past a hard byte ceiling even when
	// the grantor keeps raising the chunk limit (CWE-770).
	#[test]
	fn test_recv_stream_rejects_past_reassembly_ceiling() {
		let ceiling = 256usize;
		let mut stream = RecvStream::with_ceiling(1, ceiling);
		let chunk = [0u8; 64];
		let mut accepted = 0usize;
		loop {
			if stream.received >= stream.limit {
				stream.limit = stream.received.saturating_add(1);
			}
			if !stream.accept_chunk(&chunk) {
				break;
			}

			accepted = accepted.saturating_add(1);
			assert!(accepted.saturating_mul(chunk.len()) <= ceiling);
		}

		assert!(stream.buffer.len() <= ceiling);
		assert!(accepted > 0);
	}

	/// Source scripted with a fixed sequence, then pending forever.
	struct ScriptedSource {
		envelopes: VecDeque<TransportEnvelope>,
		delivered: Arc<AtomicUsize>,
	}

	impl EnvelopeSource for ScriptedSource {
		fn read_envelope(&mut self) -> impl Future<Output = TransportResult<TransportEnvelope>> + MaybeSend {
			let next = self.envelopes.pop_front();
			let delivered = Arc::clone(&self.delivered);
			async move {
				match next {
					Some(envelope) => {
						delivered.fetch_add(1, Ordering::SeqCst);
						Ok(envelope)
					}
					None => pending().await,
				}
			}
		}
	}

	/// Grantor that raises the limit on every consultation.
	struct AlwaysGrant;

	impl CreditGrantor for AlwaysGrant {
		fn replenish(&self, _stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
			Some(limit.max(received).saturating_add(1))
		}
	}

	struct ReaderFixture {
		driver: MuxReaderDriver<ScriptedSource>,
		outbound: mpsc::Receiver<Outbound>,
		/// Held open so the driver never sees a closed inbound channel.
		inbound: mpsc::Receiver<InboundEvent>,
		delivered: Arc<AtomicUsize>,
	}

	/// Reader driver over a scripted source whose outbound queue is
	/// already full (single slot taken by a filler envelope).
	fn reader_with_full_queue(envelopes: Vec<TransportEnvelope>) -> ReaderFixture {
		let settings = MuxSettings::symmetric(4);
		let (mut outbound_sender, outbound_receiver) = mpsc::channel(0);
		let (inbound_sender, inbound_receiver) = mpsc::channel(4);
		let delivered = Arc::new(AtomicUsize::new(0));

		let filler = MuxPingPackage::new(false, u64::MAX);
		assert!(outbound_sender.try_send(Outbound::Envelope(filler.into())).is_ok());
		assert!(outbound_sender
			.try_send(Outbound::Envelope(MuxPingPackage::new(false, 0).into()))
			.is_err());

		let mut driver = MuxReaderDriver::new(
			ScriptedSource { envelopes: envelopes.into(), delivered: Arc::clone(&delivered) },
			Arc::new(MuxShared::new(MuxRole::Server, &settings)),
			inbound_sender,
			outbound_sender,
			&settings,
		);
		driver.grantor = Arc::new(AlwaysGrant);

		ReaderFixture { driver, outbound: outbound_receiver, inbound: inbound_receiver, delivered }
	}

	fn poll_times<F>(future: &mut Pin<Box<F>>, times: usize)
	where
		F: Future,
	{
		let mut cx = noop_cx();
		for _ in 0..times {
			let _ = future.as_mut().poll(&mut cx);
		}
	}

	/// Fixture unary open package for stream 1 carrying a four-byte payload.
	fn open_package() -> MuxOpenPackage {
		MuxOpenPackage::new(1, false, MuxStreamKind::Unary, vec![0u8; 4]).expect("fixture payload fits an open package")
	}

	// Empty payloads are trailer-only grammar: an empty data record
	// without the `last` flag is a protocol violation (the `last`
	// form is the request body's close trailer).
	#[test]
	fn test_reader_rejects_empty_data_without_last_flag() -> TransportResult<()> {
		let open = open_package();
		let empty = MuxDataPackage::new(1, false, Vec::new())?;
		let fixture = reader_with_full_queue(vec![open.into(), empty.into()]);

		let mut driver = Box::pin(fixture.driver.drive());
		let mut cx = noop_cx();

		let outcome = driver.as_mut().poll(&mut cx);
		assert!(matches!(outcome, Poll::Ready(Err(TransportError::InvalidMessage))));
		Ok(())
	}

	// A refusal cancel drawn while the writer queue is full buffers
	// in the control queue instead of vanishing: a lost refusal
	// leaves the peer's stream pending forever.
	#[test]
	fn test_refusal_cancel_buffers_when_queue_full() -> TransportResult<()> {
		let mut fixture = reader_with_full_queue(vec![]);

		fixture.driver.refuse_stream(1)?;

		assert!(matches!(
			fixture.driver.pending_control.front(),
			Some(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package))))
				if package.stream_id() == 1
		));
		Ok(())
	}

	// The h2 deadlock lesson ([RFC 9113 § 5.2.2](https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2)): a full outbound
	// queue must never park the read loop, or two mutually parked
	// endpoints deadlock. Credit grants and ping acks buffer locally
	// instead.
	#[test]
	fn test_reader_reads_while_outbound_queue_full() {
		let open = open_package();
		let probe = MuxPingPackage::new(false, 7);
		let fixture = reader_with_full_queue(vec![open.into(), probe.into()]);
		let delivered = Arc::clone(&fixture.delivered);

		let mut driver = Box::pin(fixture.driver.drive());
		poll_times(&mut driver, 8);

		assert_eq!(delivered.load(Ordering::SeqCst), 2);
	}

	#[test]
	fn test_buffered_control_flushes_as_capacity_returns() {
		let open = open_package();
		let probe = MuxPingPackage::new(false, 7);
		let mut fixture = reader_with_full_queue(vec![open.into(), probe.into()]);

		let mut driver = Box::pin(fixture.driver.drive());
		poll_times(&mut driver, 4);

		let filler = fixture.outbound.try_recv();
		assert!(matches!(
			filler,
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(_))))
		));

		poll_times(&mut driver, 4);

		let grant = fixture.outbound.try_recv();
		assert!(matches!(
			grant,
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package))))
				if package.stream_id() == 1
		));

		poll_times(&mut driver, 4);

		let ack = fixture.outbound.try_recv();
		assert!(matches!(
			ack,
			Ok(Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(package))))
				if package.ack() && package.opaque() == 7
		));
	}

	#[test]
	fn test_buffered_credit_grants_coalesce_per_stream() -> TransportResult<()> {
		let mut fixture = reader_with_full_queue(Vec::new());
		fixture.driver.queue_credit(1, 2)?;
		fixture.driver.queue_credit(3, 2)?;
		fixture.driver.queue_credit(1, 4)?;

		let buffered: Vec<_> = fixture.driver.pending_control.iter().collect();
		assert_eq!(buffered.len(), 2);
		assert!(is_credit_grant_for(buffered[0], 3));
		assert!(matches!(
			buffered[1],
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
				if package.stream_id() == 1 && package.limit() == 4
		));

		Ok(())
	}

	// Stream ids never repeat, so per-stream coalescing alone lets
	// grants for dead streams pile up under stream churn while the
	// writer stays backpressured. Closing a stream must drop its
	// buffered grant.
	#[test]
	fn test_buffered_grant_evicted_when_stream_closes() -> TransportResult<()> {
		let mut fixture = reader_with_full_queue(Vec::new());
		fixture.driver.queue_credit(1, 2)?;
		fixture.driver.queue_credit(2, 2)?;
		fixture.driver.queue_credit(3, 2)?;

		let mut peer_cancel = Box::pin(fixture.driver.route_cancel(MuxCancelPackage::new(1, 0u32)));
		poll_times(&mut peer_cancel, 1);
		drop(peer_cancel);

		let mut local_cancel = Box::pin(fixture.driver.route_cancel(MuxCancelPackage::new(2, 0u32)));
		poll_times(&mut local_cancel, 1);
		drop(local_cancel);

		let buffered: Vec<_> = fixture.driver.pending_control.iter().collect();
		assert_eq!(buffered.len(), 1);
		assert!(is_credit_grant_for(buffered[0], 3));

		Ok(())
	}

	/// Grantor that always answers with an unbounded raise.
	struct GreedyGrant;

	impl CreditGrantor for GreedyGrant {
		fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
			Some(u64::MAX)
		}
	}

	// No grantor implementation may outgrow the body channel:
	// streaming grants clamp to the consumed watermark plus the
	// channel window.
	#[test]
	fn test_streaming_grant_clamps_to_channel_window() -> TransportResult<()> {
		let mut fixture = reader_with_full_queue(Vec::new());
		fixture.driver.grantor = Arc::new(GreedyGrant);
		let (_body, forwarder, _notes) = body_fixture(5, 2);
		fixture.driver.peer_bodies.insert(5, forwarder);

		fixture.driver.grant_streaming(DrainNote { stream_id: 5, consumed: 1 })?;

		let limit = fixture.driver.peer_bodies.get(&5).map(|stream| stream.limits().0);
		assert_eq!(limit, Some(3));
		let buffered: Vec<_> = fixture.driver.pending_control.iter().collect();
		assert_eq!(buffered.len(), 1);
		assert!(matches!(
			buffered[0],
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
				if package.stream_id() == 5 && package.limit() == 3
		));

		Ok(())
	}

	#[test]
	fn test_streaming_open_forwards_chunks_without_reassembly() {
		let open =
			MuxOpenPackage::new(1, false, MuxStreamKind::Streaming, vec![1u8; 4]).expect("fixture open fits a package");
		let data = MuxDataPackage::new(1, true, vec![2u8; 4]).expect("fixture chunk fits a package");
		let mut fixture = reader_with_full_queue(vec![open.into(), data.into()]);

		let mut driver = Box::pin(fixture.driver.drive());
		poll_times(&mut driver, 8);
		drop(driver);

		let dispatched = fixture.inbound.try_recv();
		assert!(matches!(
			dispatched,
			Ok(InboundEvent::StreamOpen(1, MuxStreamKind::Streaming, _))
		));
		let Ok(InboundEvent::StreamOpen(_, _, mut body)) = dispatched else {
			return;
		};

		let first = poll_chunk(&mut body);
		assert!(matches!(first, Poll::Ready(Ok(Some(chunk))) if chunk == [1u8; 4]));
		let second = poll_chunk(&mut body);
		assert!(matches!(second, Poll::Ready(Ok(Some(chunk))) if chunk == [2u8; 4]));
		assert!(matches!(poll_chunk(&mut body), Poll::Ready(Ok(None))));
	}

	// A refused or abandoned body evicts its forwarder on the next
	// chunk: later flushes route through the tolerated
	// refused-stream path instead of a dead channel.
	#[test]
	fn test_forward_request_chunk_evicts_severed_body() {
		let mut fixture = reader_with_full_queue(Vec::new());
		let (body, forwarder, _notes) = body_fixture(1, 4);
		drop(body);
		fixture.driver.peer_bodies.insert(1, forwarder);

		let package = MuxDataPackage::new(1, false, vec![7u8; 4]).expect("fixture chunk fits a package");
		let routed = fixture.driver.forward_request_chunk(&package);

		assert!(routed.is_ok());
		assert!(fixture.driver.peer_bodies.is_empty());
	}

	#[test]
	fn test_ping_ack_backlog_is_capped() -> TransportResult<()> {
		let mut fixture = reader_with_full_queue(Vec::new());
		for opaque in 0..8 {
			fixture.driver.queue_ping_ack(MuxPingPackage::new(true, opaque))?;
		}

		let buffered_acks = fixture
			.driver
			.pending_control
			.iter()
			.filter(|envelope| is_ping_ack(envelope))
			.count();
		assert_eq!(buffered_acks, MAX_PENDING_PING_ACKS);

		Ok(())
	}
}

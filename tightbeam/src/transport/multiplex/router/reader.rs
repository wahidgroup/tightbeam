//! The reader driver, which routes inbound envelopes, reassembles chunked
//! payloads under granted credit, and buffers control-plane replies so the
//! read loop keeps running while the writer queue is full.

use core::convert::Infallible;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::future::{select, Either};
use futures::{pin_mut, SinkExt, StreamExt};

use super::body::{BodyEvent, DrainNote, ForwardedStream, StreamBody};
use super::flow::{cap_as_usize, BufferedGrantor, ChunkSize};
use super::link::MuxLink;
use super::outbound::Outbound;
use super::reassembly::{Reassembly, ReassemblyBudget};
use super::shared::{OpenSlot, PeerStream, StreamOutcome};
use crate::der::Decode;
use crate::policy::TransitStatus;
use crate::transport::envelopes::{
	CancelReason, GoAwayReason, MuxCancelPackage, MuxCreditPackage, MuxDataPackage, MuxEndPackage, MuxEnvelope,
	MuxOpenPackage, MuxPingPackage, MuxStreamKind, ResponsePackage, TransportEnvelope,
};
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::EnvelopeSource;
use crate::transport::multiplex::{CreditGrantor, StreamId, StreamRoute};
use crate::transport::{TransportError, TransportResult};
use crate::Frame;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use super::flow::renewal_floor;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::constants::DEFAULT_REKEY_MIN_SPEND_RECORDS;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::aead::RecvCipher;
#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::envelopes::{
	MuxRekeyAckPackage, MuxRekeyDonePackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage,
	MUX_APPLICATION_CODE_FLOOR,
};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::receipt::StoredReceipt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::rekey::{EpochInstall, RekeyDriver, RequestAnswer, ServerAckOutcome};

/// The cap on the ping acks that the reader buffers while the writer queue is
/// full.
///
/// Probes beyond this backlog draw no ack, so a ping flood against a
/// saturated connection extracts nothing.
///
/// # Sources
///
/// - CVE-2019-9512, HTTP/2 Ping Flood: <https://nvd.nist.gov/vuln/detail/CVE-2019-9512>
const MAX_PENDING_PING_ACKS: usize = 4;

/// Why the reader of a connection stopped, as the label of
/// `CONNECTION_CLOSED` names it.
#[cfg(feature = "instrument")]
enum ReaderEnd {
	/// The reader refused what the peer sent: a break of the mux grammar, an
	/// envelope that does not decode, a frame that ends early, or an envelope
	/// that the read step refuses, which `TRANSPORT_ENVELOPE_REFUSED` names.
	InvalidMessage,
	/// The connection ended under the reader, such as a close by the peer, a
	/// read failure, a stall past the read deadline, or a writer driver that
	/// is gone.
	ConnectionClosed,
}

#[cfg(feature = "instrument")]
impl ReaderEnd {
	/// The label that names this end.
	fn label(&self) -> &'static str {
		match self {
			Self::InvalidMessage => "invalid-message",
			Self::ConnectionClosed => "connection-closed",
		}
	}
}

/// The end of a reader that `error` ended: a refusal of what the peer sent,
/// by [`TransportError::peer_refusal`], or else a connection that ended.
#[cfg(feature = "instrument")]
impl From<&TransportError> for ReaderEnd {
	fn from(error: &TransportError) -> Self {
		match error.peer_refusal() {
			Some(_) => Self::InvalidMessage,
			None => Self::ConnectionClosed,
		}
	}
}

/// A peer-initiated event that the reader routes to the responder.
pub enum InboundEvent {
	/// A unary-kind stream, reassembled into its message frame.
	Request(u32, Arc<Frame>),
	/// A streaming-kind or duplex-kind stream, whose body forwards chunks as
	/// they arrive.
	///
	/// The kind fixes the reply shape, and the route carries the grpc-style
	/// dispatch target the initiator stamped on the Open. The body is boxed so
	/// the event stays the size of its other variants on the inbound queue.
	StreamOpen(u32, MuxStreamKind, Box<StreamBody>, StreamRoute),
	/// The peer cancelled a stream it initiated.
	Cancel(u32),
}

/// Maps the code of a settlement or approval refusal to its GoAway reason.
///
/// Application codes at or above [`MUX_APPLICATION_CODE_FLOOR`] pass through,
/// and every other code is a settlement failure.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn refusal_reason(code: u32) -> GoAwayReason {
	if code >= MUX_APPLICATION_CODE_FLOOR {
		return GoAwayReason::Application(code);
	}

	GoAwayReason::SettlementFailed
}

/// The receiver-side state of one inbound stream direction: the credit this
/// endpoint granted it, and the bytes it reassembled.
struct RecvStream {
	/// The chunks, concatenated in arrival order under the stream and
	/// connection ceilings. The AEAD channel already proves order and
	/// completeness.
	bytes: Reassembly,
	/// The count of chunks accepted so far.
	received: u64,
	/// The absolute cumulative chunk limit granted to the sender.
	limit: u64,
}

impl RecvStream {
	fn new(limit: u64, budget: Arc<ReassemblyBudget>) -> Self {
		Self { bytes: Reassembly::new(budget), received: 0, limit }
	}

	/// Accounts one accepted chunk against the granted limit and buffers it.
	///
	/// Returns `false` when the sender overran its credit, the hard reassembly
	/// byte ceiling, or the connection ceiling.
	fn accept_chunk(&mut self, payload: impl AsRef<[u8]>) -> bool {
		self.received = self.received.saturating_add(1);
		if self.received > self.limit {
			return false;
		}

		self.bytes.append(payload).is_ok()
	}
}

/// The reader driver, which routes inbound envelopes off the read half.
///
/// Spawn [`MuxReaderDriver::drive`] on the caller's executor.
///
/// - Responses resolve their pending stream. The driver discards an unknown
///   ID silently, because cancel and response races are benign.
/// - Requests flow to the [`crate::transport::multiplex::MuxResponder`].
/// - Chunked payloads reassemble here, bounded by the credit this endpoint
///   granted. The [`CreditGrantor`] decides when to raise a stream's limit.
/// - Protocol violations answer with a GoAway and fail the driver.
pub struct MuxReaderDriver<R>
where
	R: EnvelopeSource,
{
	reader: R,
	link: MuxLink,
	inbound: mpsc::Sender<InboundEvent>,
	grantor: Arc<dyn CreditGrantor>,
	/// The concurrent peer-initiated streams accepted, as advertised locally.
	/// The cap bounds `peer_reassembly`, so partial opens hold no state beyond
	/// it, under the stream accounting of [RFC 9113 § 5.1.2][rfc9113-5.1.2].
	///
	/// [rfc9113-5.1.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.1.2
	peer_cap: u32,
	/// The largest chunk payload accepted inbound, as advertised locally.
	recv_chunk_size: ChunkSize,
	/// The initial chunk limit granted to each inbound stream direction.
	initial_recv_credit: u64,
	/// The credits that the peer has left to spend inbound, or `None` when the
	/// session is unmetered.
	recv_budget: Option<u64>,
	/// The reassembly of peer-initiated request streams.
	peer_reassembly: HashMap<u32, RecvStream>,
	/// The streaming peer-initiated requests, whose chunks forward to the
	/// handler's [`StreamBody`] instead of reassembling. The map holds only
	/// peer-initiated stream IDs, and locally-initiated duplex replies live in
	/// the shared `duplex_recv` registry.
	peer_bodies: HashMap<u32, ForwardedStream>,
	/// The reassembly of responses to locally-initiated streams.
	local_reassembly: HashMap<u32, RecvStream>,
	/// The consumption reports from live stream bodies, one channel slot per
	/// body. A body whose slot is taken reports its current count once the
	/// slot frees ([`StreamBody`]), so a stalled read loop holds at most one
	/// note per live body.
	drained: mpsc::Receiver<DrainNote>,
	/// The control commands buffered while the writer queue is full, so the
	/// read loop keeps running. [RFC 9113 § 5.2.2][rfc9113-5.2.2] warns of the
	/// deadlock a parked reader causes.
	///
	/// The buffer is bounded:
	///
	/// - Grants coalesce per stream and evict when the stream closes.
	/// - Ping acks and refusals are capped.
	/// - Rekey legs hold one exchange in flight at a time.
	///
	/// [rfc9113-5.2.2]: https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2
	pending_control: VecDeque<Outbound>,
	/// The role-fixed rekey exchange. `None` keeps every rekey leg an
	/// unsolicited protocol violation.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	rekey: Option<RekeyDriver>,
	/// The client epoch state held between the `RekeyAck` and the server's
	/// `RekeyDone`. The receive cipher installs and the receipt rotates only at
	/// the `RekeyDone` boundary.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pending_install: Option<PendingDone>,
	/// The negotiated inbound budget, restored at each epoch boundary.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	initial_recv_budget: Option<u64>,
	/// The receive-direction records left at which the client opens a renewal.
	/// The figure tracks the peer's send counter.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	renewal_floor: u64,
	/// The receive-direction records left at the last epoch install, for the
	/// server's minimum-spend flood bound.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	epoch_recv_baseline: u64,
}

/// The client epoch state parked between `RekeyAck` and `RekeyDone`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
struct PendingDone {
	recv_cipher: RecvCipher,
	receipt: StoredReceipt,
}

/// One unit of read-loop work (see [`MuxReaderDriver::next_event`]).
enum ReaderEvent {
	/// An inbound envelope off the read half.
	Envelope(TransportEnvelope),
	/// A stream body reported consumer progress.
	Drained(DrainNote),
	/// Buffered control flushed into the writer queue.
	Flushed,
}

impl ReaderEvent {
	/// Reads one drain report off the note stream.
	///
	/// The driver holds a feedback sender for the body channel, so the note
	/// stream outlives every body, and [`None`] therefore means that the flush
	/// completed.
	fn drained(note: Option<DrainNote>) -> Self {
		match note {
			Some(note) => Self::Drained(note),
			None => Self::Flushed,
		}
	}
}

/// The connection fails when its reader goes, however it goes.
///
/// A returned [`drive`](MuxReaderDriver::drive), a `drive` future dropped in
/// the middle of a read, and a driver that never ran all leave nothing to
/// resolve a stream or a ping. The sweep runs here, so each of them records
/// the end.
impl<R> Drop for MuxReaderDriver<R>
where
	R: EnvelopeSource,
{
	fn drop(&mut self) {
		self.link.shared().fail_all_pending();
	}
}

impl<R> MuxReaderDriver<R>
where
	R: EnvelopeSource,
{
	/// Assembles the reader driver over its shared state and channels.
	///
	/// This is the single construction point, so a new field has exactly one
	/// home.
	pub(crate) fn new(
		reader: R,
		link: MuxLink,
		inbound: mpsc::Sender<InboundEvent>,
		drained: mpsc::Receiver<DrainNote>,
		settings: &MuxSettings,
	) -> Self {
		Self {
			reader,
			link,
			inbound,
			grantor: Arc::new(BufferedGrantor::default()),
			peer_cap: settings.peer_initiated_cap(),
			recv_chunk_size: ChunkSize::new(cap_as_usize(settings.recv_chunk_size())),
			initial_recv_credit: settings.initial_recv_credit(),
			recv_budget: settings.recv_budget(),
			peer_reassembly: HashMap::new(),
			peer_bodies: HashMap::new(),
			local_reassembly: HashMap::new(),
			drained,
			pending_control: VecDeque::new(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			rekey: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			pending_install: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			initial_recv_budget: settings.recv_budget(),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			renewal_floor: renewal_floor(settings.drain_reserve_records()),
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			epoch_recv_baseline: 0,
		}
	}

	/// Overrides the receiver-side stream credit policy.
	pub fn set_grantor(&mut self, grantor: Arc<dyn CreditGrantor>) {
		self.grantor = grantor;
	}

	/// Attaches in-band rekey in three steps:
	///
	/// 1. Seed the receipt accessor from the handshake artifact.
	/// 2. Stamp the epoch baseline from the remaining records of the receive cipher.
	/// 3. Mark the rekey attached, which in the client role opens admissions gating for renewals.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn attach_rekey(&mut self, driver: RekeyDriver, receipt: Arc<StoredReceipt>) {
		self.link.shared().rotate_receipt(receipt);
		self.epoch_recv_baseline = self.reader.remaining_records();
		self.link.shared().mark_rekey_attached();
		self.rekey = Some(driver);
	}

	/// Runs the driver until the connection ends, and returns the error that
	/// ended it.
	///
	/// The connection's trail records the end as `CONNECTION_CLOSED`, labelled
	/// with why the reader stopped. The driver then drops, and its drop fails
	/// every pending stream and ping.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- the peer broke the mux protocol,
	///   and the reader queued a best-effort GoAway.
	/// - [`TransportError::ConnectionClosed`] -- the writer driver is gone.
	/// - The read or receive-cipher install failure of the [`EnvelopeSource`].
	/// - The injected error, when the runtime fault model injects a fault at
	///   the record of the end, in place of the error that ended the reader.
	pub async fn drive(mut self) -> TransportResult<()> {
		let Err(ended) = self.route_envelopes().await;

		#[cfg(feature = "instrument")]
		self.record_end(&ended)?;

		Err(ended)
	}

	/// Records the end of this reader on the connection's trail, as
	/// `CONNECTION_CLOSED`, labelled with why `error` ended it.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the record.
	#[cfg(feature = "instrument")]
	fn record_end(&self, error: &TransportError) -> TransportResult<()> {
		let Some(trace) = self.link.shared().trace.as_ref() else {
			return Ok(());
		};

		let end = ReaderEnd::from(error);
		Ok(trace.emit_event_with_evidence(events::CONNECTION_CLOSED, end.label(), None)?)
	}

	/// Routes inbound envelopes to their pending streams or handlers, and
	/// interleaves body-drain reports into credit replenishment, until an
	/// error ends the connection.
	async fn route_envelopes(&mut self) -> TransportResult<Infallible> {
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

			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			self.watch_recv_records()?;
		}
	}

	/// Routes one inbound mux envelope.
	async fn route_mux(&mut self, mux: MuxEnvelope) -> TransportResult<()> {
		match mux {
			MuxEnvelope::End(package) => self.route_end(package),
			MuxEnvelope::Open(package) => self.route_open(package).await,
			MuxEnvelope::Data(package) => self.route_data(package).await,
			MuxEnvelope::Credit(package) => {
				self.link.shared().apply_credit_grant(package.stream_id(), package.limit());
				Ok(())
			}
			MuxEnvelope::Cancel(package) => self.route_cancel(package).await,
			MuxEnvelope::Ping(package) => self.route_ping(package),
			MuxEnvelope::GoAway(package) => {
				let shared = self.link.shared();
				// Every stream above the watermark ends before a fault at the
				// record of the GoAway returns.
				let received = shared.fail_pending_above(package.last_stream_id(), package.reason());
				shared.fail_duplex_above(package.last_stream_id());
				// The peer will never answer these streams, so the reader drops
				// their partial response buffers.
				self.local_reassembly.retain(|id, _| shared.is_pending(*id));
				received
			}
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			MuxEnvelope::RekeyRequest(package) => self.route_rekey_request(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			MuxEnvelope::RekeyResponse(package) => self.route_rekey_response(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			MuxEnvelope::RekeyAck(package) => self.route_rekey_ack(package).await,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			MuxEnvelope::RekeyDone(package) => self.route_rekey_done(package),
			// This build drives no rekey exchange, so any rekey leg is
			// unsolicited and fails closed.
			#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
			MuxEnvelope::RekeyRequest(_)
			| MuxEnvelope::RekeyResponse(_)
			| MuxEnvelope::RekeyAck(_)
			| MuxEnvelope::RekeyDone(_) => Err(self.protocol_violation()),
		}
	}

	/// Opens a renewal from the receive direction.
	///
	/// The client's receive counter tracks the server's send counter on the
	/// ordered channel, so a renewal opens here as the record limit nears, with
	/// no wire addition.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn watch_recv_records(&mut self) -> TransportResult<()> {
		if self.reader.remaining_records() > self.renewal_floor {
			return Ok(());
		}
		let Some(exchange) = self.rekey.as_ref().and_then(RekeyDriver::renewal_opener) else {
			return Ok(());
		};
		let Some(request) = self.link.shared().open_renewal(exchange)? else {
			return Ok(());
		};

		self.queue_control(request)
	}

	/// Drains on a settlement or approval refusal, and keeps the connection up
	/// long enough for owed traffic and the recorded evidence to survive the
	/// disagreement.
	///
	/// # Backpressure
	///
	/// This runs on the read loop, so the GoAway buffers through
	/// [`Self::queue_command`], and the loop awaits no full outbound queue.
	/// Reads must continue under write backpressure, or mutually saturated
	/// peers deadlock (RFC 9113 §5.2).
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn drain_refused(&mut self, code: u32) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		self.link.shared().emit_event(events::MUX_REKEY_REFUSED)?;

		let reason = refusal_reason(code);
		let Some(package) = self.link.shared().goaway_package(reason) else {
			return Ok(());
		};

		self.queue_control(package.into())?;

		#[cfg(feature = "instrument")]
		self.link.shared().emit_goaway_event(events::MUX_GOAWAY_SENT, reason)?;

		Ok(())
	}

	/// Routes a renewal request on the server leg and issues its epoch receipt.
	///
	/// The rekey-flood bound (CWE-400) makes a request a protocol violation in
	/// two cases:
	///
	/// - The server's half answers that an exchange is in flight.
	/// - The peer has spent fewer than [`DEFAULT_REKEY_MIN_SPEND_RECORDS`] records since the last install.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn route_rekey_request(&mut self, package: MuxRekeyRequestPackage) -> TransportResult<()> {
		let spent = self.epoch_recv_baseline.saturating_sub(self.reader.remaining_records());
		let issued = {
			let Some(driver) = self.rekey.as_mut() else {
				return Err(self.protocol_violation());
			};
			if spent < DEFAULT_REKEY_MIN_SPEND_RECORDS {
				None
			} else {
				driver.process_request(&package).await
			}
		};

		match issued {
			Some(Ok(RequestAnswer::Issued(response))) => {
				#[cfg(feature = "instrument")]
				self.link.shared().emit_event(events::MUX_REKEY_RECEIPT_ISSUED)?;

				let envelope = TransportEnvelope::from(response);
				self.queue_control(envelope)
			}
			Some(Err(HandshakeError::SettlementRejected { code })) => self.drain_refused(code),
			Some(Err(_)) => {
				#[cfg(feature = "instrument")]
				self.link.shared().emit_event(events::MUX_REKEY_VERIFY_FAILED)?;

				Err(self.protocol_violation())
			}
			Some(Ok(RequestAnswer::InFlight)) | None => Err(self.protocol_violation()),
		}
	}

	/// Routes the response on the client leg of the rekey exchange, in order:
	///
	/// 1. Park new c2s admissions.
	/// 2. Verify and countersign the epoch receipt.
	/// 3. Hand the `RekeyAck` and the fresh send cipher to the writer, which
	///    holds them until owed chunks quiesce.
	///
	/// The receive-side install waits for `RekeyDone`.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn route_rekey_response(&mut self, package: MuxRekeyResponsePackage) -> TransportResult<()> {
		// The admission of the response parks new c2s admissions before the
		// driver verifies it, so no admission can debit the old epoch once the
		// ack is in motion.
		if !self.link.shared().admit_rekey_response() {
			return Err(self.protocol_violation());
		}
		let Some(driver) = self.rekey.as_mut() else {
			return Err(self.protocol_violation());
		};

		let Some(processed) = driver.process_response(package).await else {
			return Err(self.protocol_violation());
		};

		match processed {
			Ok((ack, install)) => {
				#[cfg(feature = "instrument")]
				self.link.shared().emit_event(events::MUX_REKEY_RECEIPT_COUNTERSIGNED)?;

				let EpochInstall { send_cipher, recv_cipher, receipt, epoch: _ } = install;

				self.pending_install = Some(PendingDone { recv_cipher, receipt });

				let ack_envelope = TransportEnvelope::from(ack);
				let install = Outbound::EnvelopeThenInstall(ack_envelope, Box::new(send_cipher));
				self.queue_command(install)
			}
			Err(HandshakeError::ApprovalRefused { code }) => {
				self.link.shared().finish_renewal();
				self.drain_refused(code)
			}
			Err(_) => {
				#[cfg(feature = "instrument")]
				self.link.shared().emit_event(events::MUX_REKEY_VERIFY_FAILED)?;

				Err(self.protocol_violation())
			}
		}
	}

	/// Routes the `RekeyAck` on the server leg: it settles the countersignature
	/// and switches epochs.
	///
	/// The receive cipher installs even on a settlement refusal, because the
	/// client switched its send direction at the `RekeyAck` boundary and the
	/// GoAway drain of the refusal must stay decryptable. A rejected
	/// settlement drains instead of resetting budgets.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn route_rekey_ack(&mut self, package: MuxRekeyAckPackage) -> TransportResult<()> {
		let settled = {
			let Some(driver) = self.rekey.as_mut() else {
				return Err(self.protocol_violation());
			};

			driver.process_ack(package).await
		};
		let Some(settled) = settled else {
			return Err(self.protocol_violation());
		};
		let Ok(outcome) = settled else {
			#[cfg(feature = "instrument")]
			self.link.shared().emit_event(events::MUX_REKEY_VERIFY_FAILED)?;

			return Err(self.protocol_violation());
		};

		let ServerAckOutcome { install, rejection } = outcome;
		let EpochInstall { send_cipher, recv_cipher, receipt, epoch: _ } = install;
		self.reader.install_recv_cipher(recv_cipher)?;
		self.epoch_recv_baseline = self.reader.remaining_records();

		if let Some(code) = rejection {
			return self.drain_refused(code);
		}

		// The budget boundary sits at `RekeyDone`. The strict c2s park keeps
		// nothing in flight across the inbound reset, and every post-reset
		// outbound debit queues behind the `RekeyDone` about to be enqueued.
		self.renew_epoch_terms(receipt)?;

		let done_package = MuxRekeyDonePackage::default();
		let done_envelope = TransportEnvelope::from(done_package);
		let install = Outbound::EnvelopeThenInstall(done_envelope, Box::new(send_cipher));
		self.queue_command(install)
	}

	/// Routes the `RekeyDone` of the client leg, which activates the new epoch.
	///
	/// The receive cipher installs, budgets reset, the receipt rotates, and
	/// parked admissions resume.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn route_rekey_done(&mut self, _package: MuxRekeyDonePackage) -> TransportResult<()> {
		let Some(PendingDone { recv_cipher, receipt }) = self.pending_install.take() else {
			return Err(self.protocol_violation());
		};

		// The new epoch's receive cipher and budget take over before the
		// renewal closes, so an admission it releases debits the new epoch.
		self.reader.install_recv_cipher(recv_cipher)?;
		self.recv_budget = self.initial_recv_budget;
		// A `RekeyDone` out of order closes nothing and ends the connection.
		if !self.link.shared().complete_renewal(receipt) {
			return Err(self.protocol_violation());
		}

		#[cfg(feature = "instrument")]
		self.link.shared().emit_event(events::MUX_REKEY_RENEWED)?;

		Ok(())
	}

	/// Activates the terms of a fresh epoch.
	///
	/// Both budgets reset to the negotiated figures, and the dual-signed
	/// receipt rotates. The credit-match invariant keeps epoch terms equal to
	/// the initial ones.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at
	///   the event of the renewal, after the terms changed.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn renew_epoch_terms(&mut self, receipt: StoredReceipt) -> TransportResult<()> {
		self.recv_budget = self.initial_recv_budget;
		self.link.shared().reset_send_budget();
		self.link.shared().rotate_receipt(receipt);

		#[cfg(feature = "instrument")]
		self.link.shared().emit_event(events::MUX_REKEY_RENEWED)?;
		Ok(())
	}

	/// Enforces the advertised chunk ceiling and debits the inbound session
	/// budget for one chunk.
	///
	/// Both overruns are protocol violations, because the sender knows the
	/// ceiling and its own grant.
	fn charge_inbound_chunk(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		if payload.len() > self.recv_chunk_size.get() {
			return Err(self.protocol_violation());
		}
		let Some(balance) = self.recv_budget else {
			return Ok(());
		};

		let credits = self.recv_chunk_size.credits(payload.len(), self.link.shared().credit_unit);
		let Some(remaining) = balance.checked_sub(credits) else {
			return Err(self.protocol_violation());
		};

		self.recv_budget = Some(remaining);
		Ok(())
	}

	/// Awaits the next unit of read-loop work: an inbound envelope, a
	/// body-drain report, or a completed control flush. The read races the
	/// flush and the drain reports, and the first one ready wins.
	async fn next_event(&mut self) -> TransportResult<ReaderEvent> {
		let Self { reader, drained, link, pending_control, .. } = self;

		let read = reader.read_envelope();
		let note = drained.next();
		pin_mut!(read, note);

		if pending_control.is_empty() {
			return match select(read, note).await {
				Either::Left((envelope, _)) => Ok(ReaderEvent::Envelope(envelope?)),
				Either::Right((note, _)) => Ok(ReaderEvent::drained(note)),
			};
		}

		let flush = link.flush_control(pending_control);
		pin_mut!(flush);

		match select(read, select(note, flush)).await {
			Either::Left((envelope, _)) => Ok(ReaderEvent::Envelope(envelope?)),
			Either::Right((Either::Left((note, _)), _)) => Ok(ReaderEvent::drained(note)),
			Either::Right((Either::Right((flushed, _)), _)) => {
				flushed?;
				Ok(ReaderEvent::Flushed)
			}
		}
	}

	/// Replenishes a streaming stream's credit from consumer progress.
	///
	/// Whether this endpoint initiated the stream picks the ledger:
	/// peer-initiated request bodies live in `peer_bodies`, and
	/// locally-initiated duplex reply bodies in the shared duplex registry.
	///
	/// # Clamp
	///
	/// Grants clamp to `consumed + window`, the body channel's absorption
	/// ceiling, so no [`CreditGrantor`] implementation can grant a conforming
	/// peer past the channel's capacity.
	///
	/// The drain-note channel is bounded on its own: each body owns one slot
	/// and coalesces newer reports into one pending note, so the clamp bounds
	/// the chunks and the channel bounds the notes.
	fn grant_streaming(&mut self, note: DrainNote) -> TransportResult<()> {
		let limits = if self.link.shared().role().initiates(note.stream_id) {
			self.link.shared().duplex_limits(note.stream_id)
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

		if self.link.shared().role().initiates(note.stream_id) {
			self.link.shared().set_duplex_limit(note.stream_id, new_limit);
		} else if let Some(stream) = self.peer_bodies.get_mut(&note.stream_id) {
			stream.raise_limit(new_limit);
		}

		self.queue_credit(note.stream_id, new_limit)
	}

	/// Hands a control command to the writer, and buffers it on a full queue,
	/// so the read loop keeps running.
	fn queue_command(&mut self, command: Outbound) -> TransportResult<()> {
		if !self.pending_control.is_empty() {
			self.pending_control.push_back(command);
			return Ok(());
		}

		match self.link.try_send(command) {
			Ok(()) => Ok(()),
			Err(refused) if refused.is_full() => {
				self.pending_control.push_back(refused.into_inner());
				Ok(())
			}
			Err(_) => Err(TransportError::ConnectionClosed),
		}
	}

	/// Hands a control envelope to the writer, and buffers it on a full queue,
	/// so the read loop keeps running.
	fn queue_control(&mut self, envelope: TransportEnvelope) -> TransportResult<()> {
		self.queue_command(Outbound::Envelope(envelope))
	}

	/// Queues a credit grant, which supersedes any buffered grant for the same
	/// stream, because `Credit` is an absolute limit and only the newest
	/// matters.
	fn queue_credit(&mut self, stream_id: u32, new_limit: u64) -> TransportResult<()> {
		self.evict_credit(stream_id);
		self.queue_control(MuxCreditPackage::new(stream_id, new_limit).into())
	}

	/// Drops any buffered grant for `stream_id` when the stream closes.
	///
	/// Stream IDs never recur, so a leftover grant is dead weight that would
	/// accumulate across stream churn under writer backpressure.
	fn evict_credit(&mut self, stream_id: u32) {
		self.pending_control.retain(|envelope| !envelope.is_credit_grant_for(stream_id));
	}

	/// Queues `envelope` while fewer than `cap` buffered commands satisfy
	/// `in_class`, and drops it otherwise.
	///
	/// A peer that provokes one class of control faster than a stalled
	/// writer drains it buys no memory past the cap (CWE-770).
	fn queue_capped(
		&mut self,
		envelope: TransportEnvelope,
		in_class: impl Fn(&Outbound) -> bool,
		cap: usize,
	) -> TransportResult<()> {
		let buffered = self.pending_control.iter().filter(|command| in_class(command)).count();
		if buffered >= cap {
			return Ok(());
		}

		self.queue_control(envelope)
	}

	/// Queues a ping ack. Probes beyond [`MAX_PENDING_PING_ACKS`] draw no ack.
	fn queue_ping_ack(&mut self, package: MuxPingPackage) -> TransportResult<()> {
		self.queue_capped(package.into(), Outbound::is_ping_ack, MAX_PENDING_PING_ACKS)
	}

	/// Consults the grantor and queues a credit grant when it raises the
	/// stream's limit.
	fn maybe_grant(&mut self, stream_id: u32, stream: &mut RecvStream) -> TransportResult<()> {
		// Grants stop once the byte ceiling is full, because raising the chunk
		// window admits no payload past it.
		if stream.bytes.is_full() {
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

	/// Decodes a reassembled stream payload into its message frame.
	///
	/// An empty payload is a message-less trailer. The frame decoder rejects a
	/// frame that carries a field its version forbids, and this router answers
	/// that refusal as a protocol violation.
	fn decode_stream_frame(&mut self, payload: impl AsRef<[u8]>) -> TransportResult<Option<Frame>> {
		let payload = payload.as_ref();
		if payload.is_empty() {
			return Ok(None);
		}

		let frame = match Frame::from_der(payload) {
			Ok(frame) => frame,
			Err(_) => return Err(self.protocol_violation()),
		};

		Ok(Some(frame))
	}

	/// Resolves a locally-initiated stream from its `End` trailer.
	fn route_end(&mut self, package: MuxEndPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		if !self.link.shared().role().initiates(stream_id) {
			return Err(self.protocol_violation());
		}

		self.evict_credit(stream_id);

		// The sender debited its ledgers for this record whether or not the
		// stream is pending, so the reader accounts it either way.
		if !package.payload().is_empty() {
			self.charge_inbound_chunk(package.payload())?;
		}

		// A duplex reply trailer closes the body, as a clean end on Ok and as
		// its transport error on any other status.
		if let Some(forwarder) = self.link.shared().take_duplex(stream_id) {
			self.link.shared().remove_pending(stream_id);
			return self.finish_duplex_body(forwarder, &package);
		}

		// The stream resolves before the decode. The reader discards a stale
		// end with its payload unread, and a non-Ok trailer contributes no
		// frame, so garbage bytes on either cannot tear down the connection.
		let Some(sender) = self.link.shared().remove_pending(stream_id) else {
			self.local_reassembly.remove(&stream_id);
			return Ok(());
		};

		let mut stream = self.take_local_reassembly(stream_id);
		if !package.payload().is_empty() && !stream.accept_chunk(package.payload()) {
			return Err(self.protocol_violation());
		}

		let message = match package.status() {
			TransitStatus::Ok => self.decode_stream_frame(stream.bytes.as_slice())?,
			_ => None,
		};

		let response = ResponsePackage::new(package.status(), message);
		// The initiator may have dropped its future, a cancel this response
		// lost the race to.
		let _ = sender.send(StreamOutcome::Response(response));
		Ok(())
	}

	/// Closes a duplex reply body from its `End` trailer: it forwards the final
	/// inline chunk when present, then the terminal event.
	fn finish_duplex_body(&mut self, mut forwarder: ForwardedStream, package: &MuxEndPackage) -> TransportResult<()> {
		if !package.payload().is_empty() && !forwarder.accept_and_forward(package.payload()) {
			return Err(self.protocol_violation());
		}

		let terminal = match package.status() {
			TransitStatus::Ok => BodyEvent::End,
			status => BodyEvent::Failed(TransportError::from(status)),
		};
		// A reply body already dropped has no reader for the terminal event,
		// and the stream closes either way.
		let _ = forwarder.forward(terminal);

		Ok(())
	}

	/// Registers a peer open, then accepts it or refuses it past the GoAway
	/// watermark.
	async fn route_open(&mut self, package: MuxOpenPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		match self.link.shared().register_peer_stream(stream_id) {
			Ok(PeerStream::Accept) => self.accept_peer_open(stream_id, package).await,
			Ok(PeerStream::RejectDraining) => self.reject_draining_open(stream_id, package),
			Err(_) => Err(self.protocol_violation()),
		}
	}

	/// Accepts a peer open, routed by the kind the initiating call stamped on
	/// the record.
	///
	/// Unary streams reassemble into one frame, while streaming and duplex
	/// kinds forward chunks as they arrive.
	async fn accept_peer_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		match package.kind() {
			MuxStreamKind::Unary => self.accept_unary_open(stream_id, package).await,
			MuxStreamKind::Streaming | MuxStreamKind::Duplex => self.accept_streaming_open(stream_id, package).await,
		}
	}

	/// Accepts a unary-kind open: it dispatches a whole-frame open, or parks
	/// the first chunk under the peer-initiated reassembly cap.
	async fn accept_unary_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		self.charge_inbound_chunk(package.payload())?;
		if package.last() {
			// A whole frame in one chunk fits the credit floor of one, so it
			// skips reassembly.
			return self.dispatch_request(stream_id, package.payload()).await;
		}

		// A conforming sender keeps its in-flight opens under the cap that this
		// endpoint advertised, so one more partial stream is a violation and
		// not backpressure.
		if self.live_peer_streams() >= cap_as_usize(self.peer_cap) {
			return Err(self.protocol_violation());
		}

		let stream = RecvStream::new(self.initial_recv_credit, self.link.shared().reassembly_budget());
		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.peer_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Counts the streams the peer holds open across both consumption paths, so
	/// mixed kinds share one flood bound.
	fn live_peer_streams(&self) -> usize {
		self.peer_bodies.len().saturating_add(self.peer_reassembly.len())
	}

	/// Accepts a streaming-kind or duplex-kind open, whose chunks forward to
	/// the handler's [`StreamBody`] as they arrive instead of reassembling.
	///
	/// The initial grant window doubles as the body channel bound, and further
	/// grants follow consumer drain through [`Self::grant_streaming`].
	async fn accept_streaming_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		self.charge_inbound_chunk(package.payload())?;

		// The same partial-open flood bound applies as for unary reassembly.
		if !package.last() && self.live_peer_streams() >= cap_as_usize(self.peer_cap) {
			return Err(self.protocol_violation());
		}

		let (body, mut forwarder) = StreamBody::pair(
			OpenSlot::assigned(stream_id),
			self.initial_recv_credit,
			self.link.drain_feedback(),
			self.link.shared().reassembly_budget(),
		);
		if !forwarder.accept_and_forward(package.payload()) {
			return Err(self.protocol_violation());
		}

		let kind = package.kind();
		let route = StreamRoute::from_parts(package.target().cloned(), package.hops_remaining());

		if package.last() {
			// The reader hands the body to the handler below, and a handler
			// that drops it unread has closed the stream either way.
			let _ = forwarder.forward(BodyEvent::End);
		} else {
			self.peer_bodies.insert(stream_id, forwarder);
		}

		self.dispatch_stream_open(stream_id, kind, body, route).await
	}

	/// Hands a fresh streaming body to the responder, and refuses the stream
	/// when no responder serves this connection.
	async fn dispatch_stream_open(
		&mut self,
		stream_id: u32,
		kind: MuxStreamKind,
		body: StreamBody,
		route: StreamRoute,
	) -> TransportResult<()> {
		let event = InboundEvent::StreamOpen(stream_id, kind, Box::new(body), route);
		if self.inbound.send(event).await.is_err() {
			self.peer_bodies.remove(&stream_id);
			self.refuse_stream(stream_id)?;
		}

		Ok(())
	}

	/// Refuses an open past this endpoint's GoAway watermark.
	///
	/// The chunk crossed the wire under the sender's ledgers, so the reader
	/// debits it inbound.
	fn reject_draining_open(&mut self, stream_id: u32, package: MuxOpenPackage) -> TransportResult<()> {
		#[cfg(feature = "instrument")]
		self.link.shared().emit_event(events::MUX_OPEN_DRAINING)?;

		self.charge_inbound_chunk(package.payload())?;
		self.refuse_stream(stream_id)?;

		Ok(())
	}

	/// Routes a `Data` record by the side that initiated its stream.
	async fn route_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();

		// Empty payloads travel only in trailers. A `last`-flagged empty
		// record closes a request body whose final push carried no `last`
		// flag (see `RequestSink::close`).
		if package.payload().is_empty() && !package.last() {
			return Err(self.protocol_violation());
		}

		if self.link.shared().role().peer().initiates(stream_id) {
			return self.route_request_data(package).await;
		}
		if self.link.shared().role().initiates(stream_id) {
			return self.route_response_data(package).await;
		}

		Err(self.protocol_violation())
	}

	/// Appends `payload` into `stream`, or fails closed on a credit overrun.
	fn accept_chunk_or_violate(
		&mut self,
		mut stream: RecvStream,
		payload: impl AsRef<[u8]>,
	) -> TransportResult<RecvStream> {
		let payload = payload.as_ref();
		if !stream.accept_chunk(payload) {
			return Err(self.protocol_violation());
		}

		Ok(stream)
	}

	/// Detaches a locally-initiated stream's reassembly, and starts a fresh one
	/// at the initial credit on its first chunk.
	fn take_local_reassembly(&mut self, stream_id: u32) -> RecvStream {
		self.local_reassembly
			.remove(&stream_id)
			.unwrap_or_else(|| RecvStream::new(self.initial_recv_credit, self.link.shared().reassembly_budget()))
	}

	/// Accepts a non-final chunk and raises credit when the grantor asks.
	///
	/// The caller parks the returned stream in the right reassembly map.
	fn park_reassembly(
		&mut self,
		stream_id: u32,
		stream: RecvStream,
		payload: impl AsRef<[u8]>,
	) -> TransportResult<RecvStream> {
		let payload = payload.as_ref();
		let mut stream = self.accept_chunk_or_violate(stream, payload)?;
		self.maybe_grant(stream_id, &mut stream)?;

		Ok(stream)
	}

	/// Routes a continuation chunk of a peer-initiated request.
	async fn route_request_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		self.charge_inbound_chunk(package.payload())?;

		if self.peer_bodies.contains_key(&stream_id) {
			return self.forward_request_chunk(&package);
		}

		let Some(stream) = self.peer_reassembly.remove(&stream_id) else {
			// A refused or cancelled stream may flush the chunks it had credit
			// for. A stream beyond the high-water mark never opened.
			if stream_id <= self.link.shared().last_peer_stream_id() {
				return Ok(());
			}

			return Err(self.protocol_violation());
		};

		if package.last() {
			// The final chunk dispatches without a credit raise, because the
			// stream is leaving reassembly.
			let stream = self.accept_chunk_or_violate(stream, package.payload())?;
			self.evict_credit(stream_id);
			return self.dispatch_request(stream_id, stream.bytes.as_slice()).await;
		}

		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.peer_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Forwards one streaming request chunk into its body channel.
	///
	/// - An overrun of the granted limit is a violation, as in reassembly.
	/// - A dropped body, refused at the cap or abandoned by its handler, evicts
	///   the forwarder. The stream's remaining flushes then route through the
	///   tolerated refused-stream path in place of a copy into a dead channel,
	///   and consumed credit stays consumed, with no refund.
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
				// A handler that dropped the body has no reader for `End`,
				// and a dropped body is a closed stream either way.
				let _ = stream.forward(BodyEvent::End);
			}
			self.evict_credit(stream_id);
		}

		Ok(())
	}

	/// Routes a continuation chunk of a response to a locally-initiated stream.
	///
	/// The responder grammar terminates with `End`, so a `Data(last)` record
	/// is a protocol violation.
	async fn route_response_data(&mut self, package: MuxDataPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		self.charge_inbound_chunk(package.payload())?;

		if package.last() {
			return Err(self.protocol_violation());
		}

		// A duplex reply forwards into the body instead of reassembling.
		if let Some(accepted) = self.link.shared().forward_duplex_chunk(stream_id, package.payload()) {
			if !accepted {
				return Err(self.protocol_violation());
			}

			return Ok(());
		}

		// This is a stale flush of a stream this endpoint already resolved.
		if !self.link.shared().is_pending(stream_id) {
			self.local_reassembly.remove(&stream_id);
			self.evict_credit(stream_id);
			return Ok(());
		}

		let stream = self.take_local_reassembly(stream_id);
		let stream = self.park_reassembly(stream_id, stream, package.payload())?;
		self.local_reassembly.insert(stream_id, stream);

		Ok(())
	}

	/// Decodes a fully reassembled request and hands it to the responder.
	async fn dispatch_request(&mut self, stream_id: u32, payload: impl AsRef<[u8]>) -> TransportResult<()> {
		let payload = payload.as_ref();
		let frame = match self.decode_stream_frame(payload)? {
			Some(frame) => frame,
			// A request stream must carry a message.
			None => return Err(self.protocol_violation()),
		};

		let event = InboundEvent::Request(stream_id, Arc::new(frame));
		if self.inbound.send(event).await.is_err() {
			// No responder is serving this connection.
			self.refuse_stream(stream_id)?;
		}

		Ok(())
	}

	/// Tears down a stream the peer cancelled, on either side of the
	/// connection.
	async fn route_cancel(&mut self, package: MuxCancelPackage) -> TransportResult<()> {
		let stream_id = package.stream_id();
		if self.link.shared().role().initiates(stream_id) {
			// The peer cancelled or refused a stream this endpoint initiated.
			self.local_reassembly.remove(&stream_id);

			if let Some(mut forwarder) = self.link.shared().take_duplex(stream_id) {
				// A reply body already dropped has no reader for the failure,
				// and the stream is cancelled either way.
				let _ = forwarder.forward(BodyEvent::Failed(package.reason().cancel_error()));
			}

			self.evict_credit(stream_id);

			let outcome = StreamOutcome::Cancelled(package.reason());
			self.link.shared().resolve(stream_id, outcome);

			return Ok(());
		}
		if self.link.shared().role().peer().initiates(stream_id) {
			// The peer withdrew its own request, so the reader drops any
			// partial reassembly or streaming body, releases the response
			// ledger, and aborts the handler. The dropped sender ends the body.
			self.peer_reassembly.remove(&stream_id);
			self.peer_bodies.remove(&stream_id);
			self.evict_credit(stream_id);
			self.link.shared().finish_send_stream(stream_id);

			// A responder that has ended has no handler left to abort, so the
			// cancel has nothing to reach.
			let _ = self.inbound.send(InboundEvent::Cancel(stream_id)).await;
			return Ok(());
		}

		Err(self.protocol_violation())
	}

	/// Answers a peer probe with its ack.
	///
	/// Pings terminate at the reader, ahead of the responder and the
	/// application handler.
	///
	/// # Flood bound
	///
	/// - After this endpoint's GoAway, the writer reserves its remaining
	///   records for owed stream traffic (see
	///   [`MuxSettings::drain_reserve_records`]), so peer probes draw no acks.
	/// - The ack backlog is capped at [`MAX_PENDING_PING_ACKS`].
	///
	/// Together they bound what a ping flood can extract (CVE-2019-9512).
	fn route_ping(&mut self, package: MuxPingPackage) -> TransportResult<()> {
		if package.ack() {
			self.link.shared().resolve_ping(package.opaque());
			return Ok(());
		}

		if self.link.shared().shutdown_begun() {
			return Ok(());
		}

		self.queue_ping_ack(MuxPingPackage::new(true, package.opaque()))
	}

	/// Refuses a peer-initiated stream with a `Rejected` cancel.
	///
	/// The cancel goes through the control buffer, because a refusal lost to a
	/// full writer queue would leave a conforming peer's stream pending
	/// forever.
	///
	/// # Backlog
	///
	/// A conforming peer holds at most `peer_cap` opens in flight, so that
	/// many buffered refusals cover every stream it can have outstanding. An
	/// open beyond that backlog comes from a peer flooding past its cap or
	/// past this endpoint's GoAway, and it draws no cancel for two reasons:
	///
	/// - The GoAway already disowns everything above its watermark.
	/// - A zero-credit open then extracts nothing from a stalled writer
	///   (CWE-770), as with the ping-ack backlog.
	fn refuse_stream(&mut self, stream_id: u32) -> TransportResult<()> {
		let package = MuxCancelPackage::new(stream_id, CancelReason::Rejected);
		self.queue_capped(package.into(), Outbound::is_refusal, cap_as_usize(self.peer_cap))
	}

	/// Sends a best-effort `ProtocolError` GoAway and returns the error that
	/// fails the driver. A fault the trace injects at either event is that
	/// error.
	fn protocol_violation(&mut self) -> TransportError {
		#[cfg(feature = "instrument")]
		if let Err(fault) = self.link.shared().emit_event(events::MUX_PROTOCOL_ERROR) {
			return fault;
		}

		let last = self.link.shared().last_peer_stream_id();
		if let Err(fault) = self.link.goaway_best_effort(last, GoAwayReason::ProtocolError) {
			return fault;
		}

		TransportError::InvalidMessage
	}
}

#[cfg(test)]
mod tests {
	use core::future::{pending, Future};
	use core::sync::atomic::{AtomicUsize, Ordering};
	use core::task::Poll;

	use futures::channel::oneshot;

	use super::super::shared::MuxShared;
	use super::super::testing::{body_fixture, noop_cx, poll_times, FIXTURE_PEER_CAP};
	use super::*;
	use crate::transport::multiplex::MuxRole;
	use crate::utils::marker::MaybeSend;

	#[test]
	fn test_recv_stream_enforces_granted_limit() {
		let mut stream = RecvStream::new(2, Arc::new(ReassemblyBudget::default()));
		assert!(stream.accept_chunk(b"ab"));
		assert!(stream.accept_chunk(b"cd"));
		assert!(!stream.accept_chunk(b"ef"));
		assert_eq!(stream.bytes.as_slice(), b"abcd");
	}

	// A peer that spreads its payload across many streams must hit the same
	// total as one stream reaching its own ceiling. A per-stream ceiling alone
	// multiplies by the number of streams opened (CWE-770).
	#[test]
	fn connection_ceiling_binds_across_streams() {
		let connection_ceiling = 256usize;
		let budget = Arc::new(ReassemblyBudget::with_ceiling(connection_ceiling));
		let chunk = [0u8; 64];

		// Eight streams, each far below its own ceiling, together stop at the
		// connection ceiling after four chunks.
		let mut streams: Vec<RecvStream> = (0..8).map(|_| RecvStream::new(u64::MAX, Arc::clone(&budget))).collect();

		let mut charged = 0usize;
		for stream in &mut streams {
			if stream.accept_chunk(chunk) {
				charged += chunk.len();
			}
		}

		assert_eq!(charged, connection_ceiling);
		assert_eq!(budget.used(), connection_ceiling);
	}

	// A dropped stream returns its bytes, so a long-lived connection that
	// opens and closes streams does not exhaust the budget.
	#[test]
	fn dropping_a_stream_returns_its_bytes() {
		let budget = Arc::new(ReassemblyBudget::with_ceiling(128));
		{
			let mut stream = RecvStream::new(u64::MAX, Arc::clone(&budget));
			assert!(stream.accept_chunk([0u8; 128]));
			assert_eq!(budget.used(), 128);
		}

		assert_eq!(budget.used(), 0);

		let mut reused = RecvStream::new(u64::MAX, Arc::clone(&budget));
		assert!(reused.accept_chunk([0u8; 128]));
	}

	// Unary reassembly must refuse past a hard byte ceiling even when
	// the grantor keeps raising the chunk limit (CWE-770).
	#[test]
	fn test_recv_stream_rejects_past_reassembly_ceiling() {
		let ceiling = 256usize;
		let bytes = Reassembly::with_ceiling(ceiling, Arc::new(ReassemblyBudget::default()));
		let mut stream = RecvStream { bytes, received: 0, limit: 1 };
		let chunk = [0u8; 64];
		let mut accepted = 0usize;
		loop {
			if stream.received >= stream.limit {
				stream.limit = stream.received.saturating_add(1);
			}
			if !stream.accept_chunk(chunk) {
				break;
			}

			accepted = accepted.saturating_add(1);
			assert!(accepted.saturating_mul(chunk.len()) <= ceiling);
		}

		assert!(stream.bytes.as_slice().len() <= ceiling);
		assert!(accepted > 0);
	}

	/// An envelope source that yields a fixed sequence and then stays pending
	/// forever.
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

	/// A grantor that raises the limit on every consultation.
	struct AlwaysGrant;

	impl CreditGrantor for AlwaysGrant {
		fn replenish(&self, _stream_id: StreamId, received: u64, limit: u64) -> Option<u64> {
			Some(limit.max(received).saturating_add(1))
		}
	}

	/// The reader driver under test, with the far ends of its channels.
	struct ReaderFixture {
		/// The driver over the scripted source.
		driver: MuxReaderDriver<ScriptedSource>,
		/// The receiving end of the full outbound queue.
		outbound: mpsc::Receiver<Outbound>,
		/// The receiving end of the inbound channel, held to keep it open.
		inbound: mpsc::Receiver<InboundEvent>,
		/// The count of envelopes that the source has delivered.
		delivered: Arc<AtomicUsize>,
	}

	/// A reader driver over a scripted source whose outbound queue is already
	/// full, with its single slot taken by a filler envelope.
	fn reader_with_full_queue(envelopes: impl IntoIterator<Item = TransportEnvelope>) -> ReaderFixture {
		let envelopes: Vec<TransportEnvelope> = envelopes.into_iter().collect();
		let settings = MuxSettings::symmetric(FIXTURE_PEER_CAP);
		let (mut outbound_sender, outbound_receiver) = mpsc::channel(0);
		let (inbound_sender, inbound_receiver) = mpsc::channel(4);
		let delivered = Arc::new(AtomicUsize::new(0));

		let filler = MuxPingPackage::new(false, u64::MAX);
		assert!(outbound_sender.try_send(Outbound::Envelope(filler.into())).is_ok());
		assert!(outbound_sender
			.try_send(Outbound::Envelope(MuxPingPackage::new(false, 0).into()))
			.is_err());

		let shared = Arc::new(MuxShared::new(MuxRole::Server, &settings));
		let (link, drained) = MuxLink::new(shared, outbound_sender);
		let mut driver = MuxReaderDriver::new(
			ScriptedSource { envelopes: envelopes.into(), delivered: Arc::clone(&delivered) },
			link,
			inbound_sender,
			drained,
			&settings,
		);
		driver.grantor = Arc::new(AlwaysGrant);

		ReaderFixture { driver, outbound: outbound_receiver, inbound: inbound_receiver, delivered }
	}

	/// A fixture unary open package for stream 1 that carries a four-byte
	/// payload.
	fn open_package() -> MuxOpenPackage {
		MuxOpenPackage::new(1, false, MuxStreamKind::Unary, vec![0u8; 4]).expect("fixture payload fits an open package")
	}

	// Empty payloads are trailer-only grammar, so an empty data record without
	// the `last` flag is a protocol violation. The `last` form is the close
	// trailer of a request body.
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

	// A refusal cancel drawn while the writer queue is full buffers in the
	// control queue instead of vanishing, because a lost refusal leaves the
	// peer's stream pending forever.
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

	/// A full outbound queue must never park the read loop, or two mutually
	/// parked endpoints deadlock. Credit grants and ping acks buffer locally
	/// instead.
	///
	/// # Sources
	///
	/// - RFC 9113 § 5.2.2, the h2 flow-control deadlock:
	///   <https://datatracker.ietf.org/doc/html/rfc9113#section-5.2.2>
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
		assert!(buffered[0].is_credit_grant_for(3));
		assert!(matches!(
			buffered[1],
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
				if package.stream_id() == 1 && package.limit() == 4
		));

		Ok(())
	}

	// Stream IDs never repeat, so per-stream coalescing alone lets grants for
	// dead streams pile up under churn while the writer stays backpressured.
	// A stream that closes must drop its buffered grant.
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
		assert!(buffered[0].is_credit_grant_for(3));

		Ok(())
	}

	/// A grantor that always answers with an unbounded raise.
	struct GreedyGrant;

	impl CreditGrantor for GreedyGrant {
		fn replenish(&self, _stream_id: StreamId, _received: u64, _limit: u64) -> Option<u64> {
			Some(u64::MAX)
		}
	}

	// Streaming grants clamp to the consumed watermark plus the channel window,
	// so no grantor implementation can outgrow the body channel.
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
		let kind = MuxStreamKind::Streaming;
		let open = MuxOpenPackage::new(1, false, kind, vec![1u8; 4]).expect("fixture open fits a package");
		let data = MuxDataPackage::new(1, true, vec![2u8; 4]).expect("fixture chunk fits a package");
		let mut fixture = reader_with_full_queue(vec![open.into(), data.into()]);

		let mut driver = Box::pin(fixture.driver.drive());
		poll_times(&mut driver, 8);
		drop(driver);

		let dispatched = fixture.inbound.try_recv();
		assert!(matches!(
			dispatched,
			Ok(InboundEvent::StreamOpen(1, MuxStreamKind::Streaming, _, _))
		));

		let Ok(InboundEvent::StreamOpen(_, _, mut body, _)) = dispatched else {
			return;
		};

		let first = body.poll_chunk_now();
		assert!(matches!(first, Poll::Ready(Ok(Some(chunk))) if chunk == [1u8; 4]));

		let second = body.poll_chunk_now();
		assert!(matches!(second, Poll::Ready(Ok(Some(chunk))) if chunk == [2u8; 4]));
		assert!(matches!(body.poll_chunk_now(), Poll::Ready(Ok(None))));
	}

	// A refused or abandoned body evicts its forwarder on the next chunk, so
	// later flushes route through the tolerated refused-stream path instead
	// of a dead channel.
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

	/// Refuses every stream in `stream_ids` on the fixture's driver, as a
	/// flood of opens past the cap would.
	fn refuse_streams(fixture: &mut ReaderFixture, stream_ids: &[u32]) {
		for stream_id in stream_ids {
			fixture
				.driver
				.refuse_stream(*stream_id)
				.expect("a refusal is buffered or dropped");
		}
	}

	/// A peer that keeps opening streams into this endpoint's drain, or past
	/// the cap that this endpoint advertised, costs itself nothing per open, so
	/// the refusals it can buffer while the writer is stalled stop at the
	/// fixture's peer cap (CWE-770).
	#[test]
	fn test_refusal_backlog_is_capped_at_the_peer_cap() {
		let mut fixture = reader_with_full_queue(Vec::new());
		refuse_streams(&mut fixture, &[1, 2, 3, 4, 5, 6, 7, 8]);

		let buffered_refusals = fixture
			.driver
			.pending_control
			.iter()
			.filter(|command| command.is_refusal())
			.count();
		assert_eq!(u32::try_from(buffered_refusals), Ok(FIXTURE_PEER_CAP));
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
			.filter(|envelope| envelope.is_ping_ack())
			.count();
		assert_eq!(buffered_acks, MAX_PENDING_PING_ACKS);
		Ok(())
	}

	// A reader future dropped in the middle of a read never returns from
	// `drive`, and the connection has ended all the same.
	#[test]
	fn test_dropped_drive_fails_the_connection() {
		let fixture = reader_with_full_queue([]);
		let shared = Arc::clone(fixture.driver.link.shared());

		let mut driving = Box::pin(fixture.driver.drive());
		poll_times(&mut driving, 1);
		drop(driving);

		let (sender, _ack) = oneshot::channel();
		let pinged = shared.allocate_ping(sender);
		assert!(matches!(pinged, Err(TransportError::ConnectionClosed)));
	}

	// The reader names its end by the error that ended it: a refusal of what
	// the peer sent, or a connection that ended under the reader.
	#[cfg(feature = "instrument")]
	crate::tb_cases! {
		fn a_reader_end_is_named_by_the_error_that_ended_it((error, label): (TransportError, &str)) {
			assert_eq!(ReaderEnd::from(&error).label(), label);
		}
		cases {
			broken_grammar => (TransportError::InvalidMessage, "invalid-message"),
			undecodable_envelope => (crate::der::Error::from(crate::der::ErrorKind::Failed).into(), "invalid-message"),
			record_out_of_sequence => (crate::transport::TransportFailure::TamperDetected.into(), "invalid-message"),
			envelope_past_its_ceiling => (
				TransportError::OperationFailed(crate::transport::TransportFailure::SizeExceeded),
				"invalid-message"
			),
			cleartext_on_an_encrypted_half => (TransportError::MissingEncryption, "invalid-message"),
			record_on_a_cleartext_half => (crate::transport::TransportFailure::EncryptionFailed.into(), "invalid-message"),
			record_past_the_volume_bound => (crate::transport::TransportFailure::RekeyRequired.into(), "invalid-message"),
			closed_by_the_peer => (TransportError::ConnectionClosed, "connection-closed"),
			stalled_past_the_deadline => (crate::transport::TransportFailure::DeadlineExceeded.into(), "connection-closed"),
		}
	}
}

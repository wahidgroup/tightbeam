//! Outbound command plane: the writer driver that serializes every
//! envelope, plus the GoAway and renewal helpers that feed its queue.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::{SinkExt, Stream};

use super::outbound::{outbound_handle, Outbound};
use super::shared::{MuxShared, RekeyPhase};
use crate::transport::envelopes::{GoAwayPackage, GoAwayReason, TransportEnvelope};
use crate::transport::io::EnvelopeSink;
use crate::transport::multiplex::MuxRole;
use crate::transport::{TransportError, TransportResult};

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::flow::renewal_floor;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::SendCipher;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::ClientRekeyExchange;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use futures::lock::Mutex as FuturesMutex;

#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use crate::constants::DEFAULT_REKEY_DEADLINE_SECS;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use core::time::Duration;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use std::time::Instant;

#[cfg(feature = "instrument")]
use crate::instrumentation::events;

/// Halt the allocator and build the GoAway, once per connection.
/// `None` when shutdown already began.
pub(super) fn goaway_package(shared: &MuxShared, reason: GoAwayReason) -> Option<GoAwayPackage> {
	let last_peer = shared.begin_shutdown()?;

	#[cfg(feature = "instrument")]
	shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason);

	Some(GoAwayPackage::new(last_peer, reason))
}

/// Queue a GoAway with `reason` and halt the allocator, exactly once
/// per connection. Shared by graceful shutdown and the budget drain.
pub(super) async fn drain_with_reason(
	shared: &MuxShared,
	outbound: &mpsc::Sender<Outbound>,
	reason: GoAwayReason,
) -> TransportResult<()> {
	let Some(package) = goaway_package(shared, reason) else {
		return Ok(());
	};

	let mut outbound = outbound_handle(outbound);
	outbound
		.send(Outbound::Envelope(package.into()))
		.await
		.map_err(|_| TransportError::ConnectionClosed)?;

	Ok(())
}

/// Best-effort GoAway on a fault path: the notice rides `try_send`
/// so it never parks the faulting loop - the connection is ending
/// either way.
pub(super) fn goaway_best_effort(
	shared: &MuxShared,
	outbound: &mpsc::Sender<Outbound>,
	last_stream_id: u32,
	reason: GoAwayReason,
) {
	#[cfg(feature = "instrument")]
	shared.emit_goaway_event(events::MUX_GOAWAY_SENT, reason);
	#[cfg(not(feature = "instrument"))]
	let _ = shared;

	let package = GoAwayPackage::new(last_stream_id, reason);
	let _ = outbound_handle(outbound).try_send(Outbound::Envelope(package.into()));
}

/// Open a renewal exactly once: readiness check and phase
/// transition happen while holding the exchange, so concurrent
/// triggers collapse to a single `RekeyRequest`. A contended exchange
/// means a renewal is already being processed, which makes opening moot.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(super) fn open_renewal(
	shared: &MuxShared,
	exchange: &FuturesMutex<Box<dyn ClientRekeyExchange>>,
) -> Option<TransportEnvelope> {
	let mut guard = exchange.try_lock()?;
	let request = shared.enter_renewal(|| guard.start_renewal().ok())?;

	#[cfg(feature = "instrument")]
	shared.emit_event(events::MUX_REKEY_REQUESTED);

	let envelope = TransportEnvelope::from(request);
	Some(envelope)
}

/// On a budget at the drain reserve, renew in band when possible,
/// otherwise GoAway drain (no rekey materials).
pub(super) async fn renew_or_drain(shared: &MuxShared, outbound: &mpsc::Sender<Outbound>) -> TransportResult<()> {
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	if shared.renewal_ready() {
		// A full queue drops the trigger: the budget stays at
		// the reserve, so the next debit re-fires it
		let _ = outbound_handle(outbound).try_send(Outbound::StartRenewal);
		return Ok(());
	}

	drain_with_reason(shared, outbound, GoAwayReason::BudgetExhausted).await
}

/// One unit of writer work, resolved by [`MuxWriterDriver::poll_step`].
enum WriterStep {
	Command(Outbound),
	/// Owed c2s chunks quiesced: the held `RekeyAck` may go out
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	WriteAck,
	/// The renewal deadline elapsed: drain the connection
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	RenewalExpired,
	Closed,
}

/// Writer driver: single serialization point for the connection.
///
/// Drains the outbound queue and writes each envelope through the
/// [`EnvelopeSink`] (encrypting or cleartext). Spawn
/// [`MuxWriterDriver::drive`] on the caller's executor.
pub struct MuxWriterDriver<W>
where
	W: EnvelopeSink,
{
	writer: W,
	commands: mpsc::Receiver<Outbound>,
	shared: Arc<MuxShared>,
	/// Records reserved for draining before the send cipher halts.
	/// See [`MuxSettings::drain_reserve_records`] for the bound derivation.
	drain_headroom: u64,
	/// Client half of the rekey exchange, shared with the reader
	/// driver. The writer only ever `try_lock`s it, for the
	/// synchronous [`ClientRekeyExchange::start_renewal`]
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	exchange: Option<Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>>,
	/// `RekeyAck` held back until owed c2s chunks quiesce, with the
	/// fresh send cipher it switches to (the ack must trail every
	/// old-epoch data chunk on the wire)
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pending_ack: Option<(TransportEnvelope, Box<SendCipher>)>,
	/// When the in-flight renewal was first observed, for the
	/// deadline that bounds a stalled exchange
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	renewal_started: Option<Instant>,
	/// Time budget for one renewal exchange before the connection
	/// drains (default [`DEFAULT_REKEY_DEADLINE_SECS`])
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	renewal_deadline: Duration,
}

impl<W> MuxWriterDriver<W>
where
	W: EnvelopeSink,
{
	/// Assemble the writer driver over the outbound queue's receiving
	/// end: the single construction point, so a new field has exactly
	/// one home.
	pub(super) fn new(
		writer: W,
		commands: mpsc::Receiver<Outbound>,
		shared: Arc<MuxShared>,
		drain_headroom: u64,
	) -> Self {
		Self {
			writer,
			commands,
			shared,
			drain_headroom,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			exchange: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
			pending_ack: None,
			#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
			renewal_started: None,
			#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
			renewal_deadline: Duration::from_secs(DEFAULT_REKEY_DEADLINE_SECS),
		}
	}

	/// Attach the client half of the rekey exchange (refcount bump).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(super) fn set_exchange(&mut self, exchange: Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>) {
		self.exchange = Some(exchange);
	}

	/// Override the time budget for one renewal exchange.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	pub(super) fn set_renewal_deadline(&mut self, deadline: Duration) {
		self.renewal_deadline = deadline;
	}

	/// Run the driver until shutdown or write failure.
	pub async fn drive(mut self) -> TransportResult<()> {
		loop {
			match self.next_step().await {
				WriterStep::Command(Outbound::Envelope(envelope)) => {
					self.writer.write_envelope(envelope).await?;
					self.enforce_rekey_limit().await?;
				}
				#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				WriterStep::Command(Outbound::EnvelopeThenInstall(envelope, cipher)) => {
					self.handle_install(envelope, cipher).await?;
				}
				#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				WriterStep::Command(Outbound::StartRenewal) => self.try_open_renewal().await?,
				#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
				WriterStep::WriteAck => self.write_pending_ack().await?,
				#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
				WriterStep::RenewalExpired => self.fail_renewal().await?,
				WriterStep::Command(Outbound::Close) | WriterStep::Closed => break,
			}
		}

		Ok(())
	}

	/// Next unit of work. With a renewal in flight and a timer
	/// available, the wait is bounded by the renewal deadline so a
	/// peer that never answers cannot park the connection forever.
	async fn next_step(&mut self) -> WriterStep {
		#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
		if let Some(deadline) = self.renewal_deadline() {
			let timeout = deadline.into();
			let wait = poll_fn(|cx| self.poll_step(cx));
			let step = tokio::time::timeout_at(timeout, wait).await;
			return step.unwrap_or(WriterStep::RenewalExpired);
		}

		poll_fn(|cx| self.poll_step(cx)).await
	}

	/// Queued commands first; once the queue is momentarily empty,
	/// a held `RekeyAck` goes out if owed chunks have quiesced.
	/// The ordering guarantees every data envelope enqueued before
	/// the quiesce point precedes the ack on the wire.
	fn poll_step(&mut self, cx: &mut Context<'_>) -> Poll<WriterStep> {
		match Pin::new(&mut self.commands).poll_next(cx) {
			Poll::Ready(Some(command)) => return Poll::Ready(WriterStep::Command(command)),
			Poll::Ready(None) => return Poll::Ready(WriterStep::Closed),
			Poll::Pending => {}
		}

		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		if self.pending_ack.is_some() && self.shared.poll_chunks_quiesced(cx) {
			return Poll::Ready(WriterStep::WriteAck);
		}

		Poll::Pending
	}

	/// Deadline of the in-flight renewal, stamped on first
	/// observation and cleared when the exchange concludes.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	fn renewal_deadline(&mut self) -> Option<Instant> {
		if self.exchange.is_none() || self.shared.rekey_phase() == RekeyPhase::Idle {
			self.renewal_started = None;
			return None;
		}

		let started = *self.renewal_started.get_or_insert_with(Instant::now);
		Some(started + self.renewal_deadline)
	}

	/// Write the key-switch marker and install the fresh send
	/// cipher at the exact wire boundary. The server's `RekeyDone`
	/// writes immediately, while the client's `RekeyAck` waits out owed
	/// c2s chunks first.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn handle_install(&mut self, envelope: TransportEnvelope, cipher: Box<SendCipher>) -> TransportResult<()> {
		if self.shared.role == MuxRole::Client {
			self.pending_ack = Some((envelope, cipher));
			return Ok(());
		}

		self.writer.write_envelope(envelope).await?;
		self.writer.install_send_cipher(*cipher)
	}

	/// Owed chunks quiesced: the `RekeyAck` goes out and the send
	/// direction switches to the fresh epoch cipher (counter reset
	/// with the fresh key, NIST SP 800-38D § 8.2.1).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn write_pending_ack(&mut self) -> TransportResult<()> {
		let Some((envelope, cipher)) = self.pending_ack.take() else {
			return Ok(());
		};

		self.writer.write_envelope(envelope).await?;
		self.writer.install_send_cipher(*cipher)?;
		self.shared.mark_ack_written();

		Ok(())
	}

	/// Open a renewal if none is in flight (handle-side budget
	/// trigger; the phase check deduplicates concurrent triggers).
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn try_open_renewal(&mut self) -> TransportResult<()> {
		let Some(exchange) = self.exchange.as_ref() else {
			return Ok(());
		};
		let Some(request) = open_renewal(&self.shared, exchange) else {
			return Ok(());
		};

		self.writer.write_envelope(request).await
	}

	/// Renewal deadline elapsed: drain via GoAway and wake parked
	/// admissions/chunks so owed traffic can flush.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	async fn fail_renewal(&mut self) -> TransportResult<()> {
		self.pending_ack = None;
		self.renewal_started = None;

		if let Some(package) = goaway_package(&self.shared, GoAwayReason::Shutdown) {
			let envelope = TransportEnvelope::from(package);
			self.writer.write_envelope(envelope).await?;
		}

		self.shared.finish_renewal();

		Ok(())
	}

	/// [RFC 9846 § 5.5](https://datatracker.ietf.org/doc/html/rfc9846#section-5.5):
	/// act before the send cipher reaches its record limit.
	///
	/// A client with rekey materials opens an in-band renewal at a
	/// headroom above the drain threshold ([`DEFAULT_REKEY_RENEWAL_ALLOWANCE`]
	/// records of slack for the exchange legs). Sessions without rekey
	/// materials drain via GoAway while enough records remain to answer
	/// in-flight peer streams and flush registered-but-unsent chunks, then
	/// the caller reestablishes the session.
	async fn enforce_rekey_limit(&mut self) -> TransportResult<()> {
		let drain_floor = self.drain_headroom.saturating_add(self.shared.unsent_chunks());
		let remaining = self.writer.remaining_records();

		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		if let Some(exchange) = self.exchange.as_ref() {
			if remaining > renewal_floor(drain_floor) {
				return Ok(());
			}
			if let Some(request) = open_renewal(&self.shared, exchange) {
				return self.writer.write_envelope(request).await;
			}
			if remaining > drain_floor {
				return Ok(());
			}
			if self.shared.rekey_phase() != RekeyPhase::Idle {
				self.shared.park_hard_floor();
				return Ok(());
			}
		}

		if remaining > drain_floor {
			return Ok(());
		}

		// Bypass the command queue: at the record ceiling the queue
		// may already be full of owed stream traffic.
		if let Some(package) = goaway_package(&self.shared, GoAwayReason::Shutdown) {
			let envelope = TransportEnvelope::from(package);
			self.writer.write_envelope(envelope).await?;
		}

		Ok(())
	}
}

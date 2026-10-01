//! Outbound command plane.
//!
//! [`MuxWriterDriver`] serializes every envelope. The GoAway and renewal
//! helpers on [`MuxShared`] feed its queue.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use super::shared::RekeyPhase;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use crate::constants::DEFAULT_REKEY_DEADLINE_SECS;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use core::time::Duration;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use std::time::Instant;

use futures::channel::mpsc;
use futures::Stream;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use futures::lock::Mutex as FuturesMutex;

use super::outbound::Outbound;
use super::shared::MuxShared;
use crate::transport::envelopes::{GoAwayPackage, GoAwayReason, TransportEnvelope};
use crate::transport::io::EnvelopeSink;
use crate::transport::multiplex::MuxRole;
use crate::transport::TransportResult;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::flow::renewal_floor;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::SendCipher;
#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::ClientRekeyExchange;

/// One unit of writer work, resolved by [`MuxWriterDriver::poll_step`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
enum WriterStep {
	/// A command from the outbound queue.
	Command(Outbound),
	/// Owed c2s chunks have quiesced, so the held `RekeyAck` may go out.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	WriteAck,
	/// The renewal deadline elapsed, so the connection drains.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	RenewalExpired,
	/// Every sender is gone and the outbound queue has ended.
	Closed,
}

/// Writer driver, the single serialization point for the connection.
///
/// The driver drains the outbound queue and writes each envelope through the
/// [`EnvelopeSink`], encrypted or in cleartext. Spawn
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
	/// Client half of the rekey exchange, shared with the reader driver. The
	/// writer only calls `try_lock` on it, for the synchronous
	/// [`ClientRekeyExchange::start_renewal`].
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	exchange: Option<Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>>,
	/// `RekeyAck` held back until owed c2s chunks quiesce, with the fresh send
	/// cipher it switches to. The ack must trail every old-epoch data chunk on
	/// the wire.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pending_ack: Option<(TransportEnvelope, Box<SendCipher>)>,
	/// The instant the in-flight renewal was first observed, which starts the
	/// deadline that bounds a stalled exchange.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	renewal_started: Option<Instant>,
	/// Time budget for one renewal exchange before the connection drains. The
	/// default is [`DEFAULT_REKEY_DEADLINE_SECS`].
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	renewal_deadline: Duration,
}

impl<W> MuxWriterDriver<W>
where
	W: EnvelopeSink,
{
	/// Assemble the writer driver over the receiving end of the outbound queue.
	///
	/// This is the single construction point, so a new field has exactly one
	/// home.
	///
	/// - `drain_headroom`: the records reserved for draining before the send cipher halts.
	pub fn new(writer: W, commands: mpsc::Receiver<Outbound>, shared: Arc<MuxShared>, drain_headroom: u64) -> Self {
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

	/// Attach a shared handle to the client half of the rekey exchange.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) fn set_exchange(&mut self, exchange: Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>) {
		self.exchange = Some(exchange);
	}

	/// Override the time budget for one renewal exchange.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	pub fn set_renewal_deadline(&mut self, deadline: Duration) {
		self.renewal_deadline = deadline;
	}

	/// Run the driver until shutdown or write failure.
	///
	/// # Errors
	///
	/// - The first write or send-cipher install failure from the [`EnvelopeSink`].
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

	/// Wait for the next unit of work.
	///
	/// With a renewal in flight and a timer available, the renewal deadline
	/// bounds the wait, so a peer that never answers cannot park the
	/// connection forever.
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

	/// Poll for the next unit of work in a fixed order:
	///
	/// 1. A queued command.
	/// 2. When the queue is momentarily empty, a held `RekeyAck` whose owed chunks have quiesced.
	///
	/// The order guarantees that every data envelope enqueued before the
	/// quiesce point precedes the ack on the wire.
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

	/// Write the key-switch marker and install the fresh send cipher at the
	/// exact wire boundary.
	///
	/// The server's `RekeyDone` writes immediately, while the client's
	/// `RekeyAck` waits out owed c2s chunks first.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn handle_install(&mut self, envelope: TransportEnvelope, cipher: Box<SendCipher>) -> TransportResult<()> {
		if self.shared.role == MuxRole::Client {
			self.pending_ack = Some((envelope, cipher));
			return Ok(());
		}

		self.writer.write_envelope(envelope).await?;
		self.writer.install_send_cipher(*cipher)
	}

	/// Write the held `RekeyAck` once owed chunks have quiesced, and switch the
	/// send direction to the fresh epoch cipher.
	///
	/// The record counter resets together with the fresh key.
	///
	/// # Sources
	///
	/// - NIST SP 800-38D § 8.2.1, deterministic IV construction:
	///   <https://csrc.nist.gov/publications/detail/sp/800-38d/final>
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

	/// Open a renewal on the handle-side budget trigger when none is in flight.
	/// The phase check deduplicates concurrent triggers.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	async fn try_open_renewal(&mut self) -> TransportResult<()> {
		let Some(exchange) = self.exchange.as_ref() else {
			return Ok(());
		};
		let Some(request) = self.shared.open_renewal(exchange) else {
			return Ok(());
		};

		self.writer.write_envelope(request).await
	}

	/// Drain with a GoAway after the renewal deadline elapses, and wake parked
	/// admissions and chunks so owed traffic can flush.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	async fn fail_renewal(&mut self) -> TransportResult<()> {
		self.pending_ack = None;
		self.renewal_started = None;

		if let Some(package) = self.shared.goaway_package(GoAwayReason::Shutdown) {
			let envelope = TransportEnvelope::from(package);
			self.writer.write_envelope(envelope).await?;
		}

		self.shared.finish_renewal();

		Ok(())
	}

	/// Act before the send cipher reaches its record limit.
	///
	/// - A client with rekey materials opens an in-band renewal at a headroom
	///   above the drain threshold, with [`DEFAULT_REKEY_RENEWAL_ALLOWANCE`]
	///   records of slack for the exchange legs.
	/// - A session without rekey materials drains via GoAway while enough
	///   records remain to answer in-flight peer streams and flush
	///   registered-but-unsent chunks. The caller then reestablishes the
	///   session.
	///
	/// # Sources
	///
	/// - RFC 9846 § 5.5, AEAD limits: <https://datatracker.ietf.org/doc/html/rfc9846#section-5.5>
	async fn enforce_rekey_limit(&mut self) -> TransportResult<()> {
		let drain_floor = self.drain_headroom.saturating_add(self.shared.unsent_chunks());
		let remaining = self.writer.remaining_records();

		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		if let Some(exchange) = self.exchange.as_ref() {
			if remaining > renewal_floor(drain_floor) {
				return Ok(());
			}
			if let Some(request) = self.shared.open_renewal(exchange) {
				return self.writer.write_envelope(request).await;
			}
			if remaining > drain_floor {
				return Ok(());
			}
			if self.shared.park_hard_floor() {
				return Ok(());
			}
		}

		if remaining > drain_floor {
			return Ok(());
		}

		// Bypass the command queue, because at the record ceiling the queue
		// may already be full of owed stream traffic.
		if let Some(package) = self.shared.goaway_package(GoAwayReason::Shutdown) {
			let envelope = TransportEnvelope::from(package);
			self.writer.write_envelope(envelope).await?;
		}

		Ok(())
	}
}

impl MuxShared {
	/// Halt the allocator and build the GoAway, once per connection.
	///
	/// Returns `None` when shutdown already began.
	pub(crate) fn goaway_package(&self, reason: GoAwayReason) -> Option<GoAwayPackage> {
		let last_peer = self.begin_shutdown()?;

		#[cfg(feature = "instrument")]
		self.emit_goaway_event(events::MUX_GOAWAY_SENT, reason);

		Some(GoAwayPackage::new(last_peer, reason))
	}

	/// Open a renewal exactly once and return its `RekeyRequest` envelope.
	///
	/// The readiness check and the phase transition happen while the exchange
	/// is held, so concurrent triggers collapse to a single `RekeyRequest`. A
	/// contended exchange means a renewal is already in progress, so opening
	/// is moot and the call returns `None`.
	pub(crate) fn open_renewal(
		&self,
		exchange: &FuturesMutex<Box<dyn ClientRekeyExchange>>,
	) -> Option<TransportEnvelope> {
		let mut guard = exchange.try_lock()?;
		let request = self.enter_renewal(|| guard.start_renewal().ok())?;

		#[cfg(feature = "instrument")]
		self.emit_event(events::MUX_REKEY_REQUESTED);

		let envelope = TransportEnvelope::from(request);
		Some(envelope)
	}
}

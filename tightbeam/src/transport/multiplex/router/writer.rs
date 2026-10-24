//! Outbound command plane.
//!
//! [`MuxWriterDriver`] serializes every envelope. The GoAway and renewal
//! helpers on [`MuxShared`] feed its queue.

use core::future::poll_fn;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::Arc;

#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
use core::time::Duration;

use futures::channel::mpsc;
use futures::Stream;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use futures::lock::Mutex as FuturesMutex;

use super::outbound::Outbound;
use super::shared::MuxShared;
use crate::transport::envelopes::{GoAwayPackage, GoAwayReason, TransportEnvelope};
use crate::transport::io::EnvelopeSink;
use crate::transport::TransportResult;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use super::flow::renewal_floor;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
use super::shared::RekeyPhase;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
use crate::constants::DEFAULT_REKEY_DEADLINE_SECS;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::aead::SendCipher;
#[cfg(feature = "instrument")]
use crate::instrumentation::events;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::rekey::ClientRekeyExchange;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
use crate::utils::time::{Clock, MonotonicInstant};

/// One unit of writer work, resolved by [`MuxWriterDriver::poll_step`].
enum WriterStep {
	/// A command from the outbound queue.
	Command(Outbound),
	/// Owed c2s chunks have quiesced, so the held `RekeyAck` may go out.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	WriteAck,
	/// The renewal deadline elapsed, so the connection drains.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
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
	/// Records reserved for the drain before the send cipher halts.
	/// See [`MuxSettings::drain_reserve_records`] for the bound derivation.
	drain_headroom: u64,
	/// Client half of the rekey exchange, shared with the reader driver. The
	/// writer only calls `try_lock` on it, for the synchronous
	/// [`ClientRekeyExchange::start_renewal`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	exchange: Option<Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>>,
	/// `RekeyAck` held back until owed c2s chunks quiesce, with the fresh send
	/// cipher it switches to. The ack must trail every old-epoch data chunk on
	/// the wire.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pending_ack: Option<(TransportEnvelope, Box<SendCipher>)>,
	/// The instant the driver first observed the in-flight renewal, which
	/// starts the deadline that bounds a stalled exchange.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	renewal_started: Option<MonotonicInstant>,
	/// Time budget for one renewal exchange before the connection drains. The
	/// default is [`DEFAULT_REKEY_DEADLINE_SECS`].
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	renewal_deadline: Duration,
	/// The clock the renewal deadline is stamped on and waited out on. It is
	/// the clock of the link the driver writes to, unless
	/// [`MuxTransport::with_clock`] replaced it.
	///
	/// [`MuxTransport::with_clock`]: super::transport::MuxTransport::with_clock
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	clock: Arc<dyn Clock>,
}

/// The connection fails when its writer goes, however it goes.
///
/// A writer that is gone sends no request, no credit, and no ack, so nothing
/// that waits on the peer can finish. The reader records its own end the same
/// way, and either one ends the connection.
impl<W> Drop for MuxWriterDriver<W>
where
	W: EnvelopeSink,
{
	fn drop(&mut self) {
		self.shared.fail_all_pending();
	}
}

impl<W> MuxWriterDriver<W>
where
	W: EnvelopeSink,
{
	/// Assemble the writer driver over the receiving end of the outbound queue.
	///
	/// This is the single construction point, so a new field has exactly one
	/// home. The driver adopts the clock of the link it writes to, so the
	/// renewal deadline runs on the clock the endpoint reads.
	///
	/// - `drain_headroom`: the records reserved for the drain before the send cipher halts.
	pub fn new(writer: W, commands: mpsc::Receiver<Outbound>, shared: Arc<MuxShared>, drain_headroom: u64) -> Self {
		#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
		let clock = writer.clock();

		Self {
			writer,
			commands,
			shared,
			drain_headroom,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			exchange: None,
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			pending_ack: None,
			#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
			renewal_started: None,
			#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
			renewal_deadline: Duration::from_secs(DEFAULT_REKEY_DEADLINE_SECS),
			#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
			clock,
		}
	}

	/// Attach the shared handle to the client half of the rekey exchange, the
	/// half [`RekeyDriver::renewal_opener`] yields, or `None` for a server.
	///
	/// [`RekeyDriver::renewal_opener`]: crate::transport::rekey::RekeyDriver::renewal_opener
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn set_exchange(&mut self, exchange: Option<Arc<FuturesMutex<Box<dyn ClientRekeyExchange>>>>) {
		self.exchange = exchange;
	}

	/// Override the time budget for one renewal exchange.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	pub fn set_renewal_deadline(&mut self, deadline: Duration) {
		self.renewal_deadline = deadline;
	}

	/// Replace the clock the renewal deadline runs on.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	pub fn set_clock(&mut self, clock: Arc<dyn Clock>) {
		self.clock = clock;
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
				#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				WriterStep::Command(Outbound::EnvelopeThenInstall(envelope, cipher)) => {
					self.handle_install(envelope, cipher).await?;
				}
				#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				WriterStep::Command(Outbound::StartRenewal) => self.try_open_renewal().await?,
				#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
				WriterStep::WriteAck => self.write_pending_ack().await?,
				#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
				WriterStep::RenewalExpired => self.fail_renewal().await?,
				WriterStep::Command(Outbound::Close) | WriterStep::Closed => break,
			}
		}

		Ok(())
	}

	/// Wait for the next unit of work.
	///
	/// With a renewal in flight and a timer available, the renewal deadline
	/// bounds the wait, so a peer that never answers parks the connection only
	/// until that deadline. The wait runs on the driver's clock, so a test that
	/// installed a manual clock reaches the deadline by advancing it.
	async fn next_step(&mut self) -> WriterStep {
		#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
		if let Some(deadline) = self.renewal_deadline() {
			let clock = Arc::clone(&self.clock);
			let budget = deadline.saturating_duration_since(clock.monotonic());
			let mut expiry = clock.sleep(budget);

			// The queued work takes the first poll, as in a timeout, so a
			// command that is already ready wins over a deadline reached in the
			// same instant.
			return poll_fn(|cx| {
				if let Poll::Ready(step) = self.poll_step(cx) {
					return Poll::Ready(step);
				}

				expiry.as_mut().poll(cx).map(|()| WriterStep::RenewalExpired)
			})
			.await;
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

		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		if self.pending_ack.is_some() && self.shared.poll_chunks_quiesced(cx) {
			return Poll::Ready(WriterStep::WriteAck);
		}

		Poll::Pending
	}

	/// Deadline of the in-flight renewal, stamped on first observation from
	/// the driver's clock and cleared when the exchange concludes. A deadline
	/// past every reading of the clock never arrives, so it is `None`.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	fn renewal_deadline(&mut self) -> Option<MonotonicInstant> {
		if self.exchange.is_none() || self.shared.rekey_phase() == RekeyPhase::Idle {
			self.renewal_started = None;
			return None;
		}

		let started = *self.renewal_started.get_or_insert_with(|| self.clock.monotonic());
		started.checked_add(self.renewal_deadline)
	}

	/// Write the key-switch marker and install the fresh send cipher at the
	/// exact wire boundary.
	///
	/// The server's `RekeyDone` writes immediately, while the client's
	/// `RekeyAck` waits out owed c2s chunks first.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn handle_install(&mut self, envelope: TransportEnvelope, cipher: Box<SendCipher>) -> TransportResult<()> {
		if self.shared.role().holds_key_switch() {
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
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	async fn try_open_renewal(&mut self) -> TransportResult<()> {
		let Some(exchange) = self.exchange.as_ref() else {
			return Ok(());
		};
		let Some(request) = self.shared.open_renewal(exchange)? else {
			return Ok(());
		};

		self.writer.write_envelope(request).await
	}

	/// Drain with a GoAway after the renewal deadline elapses, and wake parked
	/// admissions and chunks so owed traffic can flush.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	async fn fail_renewal(&mut self) -> TransportResult<()> {
		self.pending_ack = None;
		self.renewal_started = None;

		if let Some(package) = self.shared.goaway_package(GoAwayReason::Shutdown) {
			let envelope = TransportEnvelope::from(package);
			self.writer.write_envelope(envelope).await?;

			#[cfg(feature = "instrument")]
			self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, GoAwayReason::Shutdown)?;
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

		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		if let Some(exchange) = self.exchange.as_ref() {
			if remaining > renewal_floor(drain_floor) {
				return Ok(());
			}
			if let Some(request) = self.shared.open_renewal(exchange)? {
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

			#[cfg(feature = "instrument")]
			self.shared.emit_goaway_event(events::MUX_GOAWAY_SENT, GoAwayReason::Shutdown)?;
		}

		Ok(())
	}
}

impl MuxShared {
	/// Halt the allocator and build the GoAway, once per connection.
	///
	/// Returns `None` when shutdown already began. The caller records
	/// `MUX_GOAWAY_SENT` once it queued or wrote the package, so a fault the
	/// trace injects at the record leaves the GoAway on its way.
	pub(crate) fn goaway_package(&self, reason: GoAwayReason) -> Option<GoAwayPackage> {
		let last_peer = self.begin_shutdown()?;

		Some(GoAwayPackage::new(last_peer, reason))
	}

	/// Open a renewal exactly once and return its `RekeyRequest` envelope.
	///
	/// The readiness check and the phase transition happen while this call
	/// holds the exchange, so concurrent triggers collapse to a single
	/// `RekeyRequest`. A contended exchange means a renewal is already in
	/// progress, so opening is moot and the call returns `None`.
	///
	/// # Errors
	///
	/// - The injected error, when the runtime fault model injects a fault at the event of the request.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn open_renewal(
		&self,
		exchange: &FuturesMutex<Box<dyn ClientRekeyExchange>>,
	) -> TransportResult<Option<TransportEnvelope>> {
		let Some(mut guard) = exchange.try_lock() else {
			return Ok(None);
		};
		let Some(request) = self.enter_renewal(|| guard.start_renewal().ok()) else {
			return Ok(None);
		};

		#[cfg(feature = "instrument")]
		self.emit_event(events::MUX_REKEY_REQUESTED)?;

		let envelope = TransportEnvelope::from(request);
		Ok(Some(envelope))
	}
}

#[cfg(all(
	test,
	feature = "tokio",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
mod tests {
	use core::future::Future;
	use core::task::Poll;
	use std::sync::Arc;

	use futures::channel::{mpsc, oneshot};
	use futures::lock::Mutex as FuturesMutex;

	use super::super::testing::{client_shared, noop_cx};
	use super::super::transport::MuxTransport;
	use super::*;
	use crate::transport::envelopes::{
		MuxPingPackage, MuxRekeyAckPackage, MuxRekeyRequestPackage, MuxRekeyResponsePackage,
	};
	use crate::transport::handshake::HandshakeError;
	use crate::transport::multiplex::{MuxRekeyContext, MuxRole, MuxSettings};
	use crate::transport::rekey::tests::{rekey_pair, run_exchange};
	use crate::transport::rekey::{EpochInstall, RekeyDriver};
	use crate::transport::{EnvelopeSource, TransportError};
	use crate::utils::marker::MaybeSendFuture;
	use crate::utils::time::ManualClock;

	/// A sink that accepts every envelope and every send cipher, and reports
	/// unlimited records.
	struct OpenSink;

	impl EnvelopeSink for OpenSink {
		async fn write_envelope(&mut self, _envelope: TransportEnvelope) -> TransportResult<()> {
			Ok(())
		}

		fn remaining_records(&self) -> u64 {
			u64::MAX
		}

		fn install_send_cipher(&mut self, _cipher: SendCipher) -> TransportResult<()> {
			Ok(())
		}
	}

	/// A sink split from a connection that reads `self.0`.
	struct ClockedSink(Arc<ManualClock>);

	impl EnvelopeSink for ClockedSink {
		async fn write_envelope(&mut self, _envelope: TransportEnvelope) -> TransportResult<()> {
			Ok(())
		}

		fn remaining_records(&self) -> u64 {
			u64::MAX
		}

		fn clock(&self) -> Arc<dyn Clock> {
			Arc::clone(&self.0) as Arc<dyn Clock>
		}
	}

	/// A client exchange that refuses every leg, in place of the handle whose
	/// presence the deadline checks.
	struct StalledExchange;

	impl ClientRekeyExchange for StalledExchange {
		fn start_renewal(&mut self) -> Result<MuxRekeyRequestPackage, HandshakeError> {
			Err(HandshakeError::InvalidState)
		}

		fn process_response<'a>(
			&'a mut self,
			_response: MuxRekeyResponsePackage,
		) -> MaybeSendFuture<'a, Result<(MuxRekeyAckPackage, EpochInstall), HandshakeError>> {
			Box::pin(async { Err(HandshakeError::InvalidState) })
		}
	}

	/// A source for a transport whose reader stays undriven in every test. A
	/// read on it reports a closed connection.
	struct IdleSource;

	impl EnvelopeSource for IdleSource {
		async fn read_envelope(&mut self) -> TransportResult<TransportEnvelope> {
			Err(TransportError::ConnectionClosed)
		}
	}

	/// A driver over `sink` with a renewal in flight, an empty queue, and a
	/// renewal budget of `deadline`, beside the queue's sender, which keeps the
	/// queue open. The driver reads the clock its sink carries.
	fn stalled_driver<W: EnvelopeSink>(sink: W, deadline: Duration) -> (MuxWriterDriver<W>, mpsc::Sender<Outbound>) {
		let shared = client_shared();
		shared.enter_renewal(|| Some(())).expect("an idle connection enters renewal");

		let (sender, commands) = mpsc::channel(1);
		let mut driver = MuxWriterDriver::new(sink, commands, shared, 0);
		driver.set_exchange(Some(Arc::new(FuturesMutex::new(Box::new(StalledExchange)))));
		driver.set_renewal_deadline(deadline);
		(driver, sender)
	}

	/// A writer that is gone can send nothing, so the connection it served
	/// has failed, however the writer went.
	#[test]
	fn a_dropped_writer_fails_the_connection() {
		let (driver, _queue) = stalled_driver(OpenSink, Duration::from_secs(30));
		let shared = Arc::clone(&driver.shared);

		drop(driver);

		let (sender, _ack) = oneshot::channel();
		let pinged = shared.allocate_ping(sender);
		assert!(matches!(pinged, Err(TransportError::ConnectionClosed)));
	}

	/// A driver assembled over a link adopts the clock that link carries, so
	/// the renewal deadline runs on the endpoint's clock with no call that a
	/// construction site could leave out.
	#[test]
	fn a_driver_adopts_the_clock_of_its_link() {
		let clock = Arc::new(ManualClock::default());
		let sink = ClockedSink(Arc::clone(&clock));
		let (mut driver, _queue) = stalled_driver(sink, Duration::from_secs(30));
		let mut step = Box::pin(driver.next_step());
		let mut cx = noop_cx();
		let before = step.as_mut().poll(&mut cx);

		clock.advance(Duration::from_secs(30));

		let after = step.as_mut().poll(&mut cx);
		assert!(before.is_pending());
		assert!(matches!(after, Poll::Ready(WriterStep::RenewalExpired)));
	}

	/// A clock set on the transport replaces the one the writer adopted from
	/// its link, so a caller that assembles a transport by hand names the
	/// clock its renewal deadline runs on.
	#[test]
	fn a_transport_clock_replaces_the_one_the_link_carries() {
		let link_clock = Arc::new(ManualClock::default());
		let replacement = Arc::new(ManualClock::default());
		replacement.advance(Duration::from_secs(3600));

		let settings = MuxSettings::symmetric(4);
		let mux = MuxTransport::new(IdleSource, ClockedSink(link_clock), MuxRole::Client, settings);
		let mux = mux.with_clock(Arc::clone(&replacement) as Arc<dyn Clock>);

		let (_handle, _reader, writer, _responder) = mux.into_parts();
		assert_eq!(writer.clock.monotonic(), replacement.monotonic());
	}

	/// Whether the writer of a transport that `with_rekey` assembles from
	/// `driver` holds its key-switch marker after `install`, the install of
	/// the half `driver` holds at the end of one exchange.
	async fn holds_key_switch(driver: RekeyDriver, install: EpochInstall) -> bool {
		let EpochInstall { send_cipher, receipt, .. } = install;
		let context = MuxRekeyContext { driver, receipt: Arc::new(receipt) };
		let mux = MuxTransport::with_rekey(IdleSource, OpenSink, context, MuxSettings::symmetric(4));
		let (_handle, _reader, mut writer, _responder) = mux.into_parts();
		let envelope = TransportEnvelope::from(MuxPingPackage::new(false, 0));

		let installed = writer.handle_install(envelope, Box::new(send_cipher)).await;
		installed.expect("the writer takes the install");
		writer.pending_ack.is_some()
	}

	/// A transport assembled from a client's rekey context holds its
	/// key-switch marker until its owed chunks quiesce, as the client role
	/// does, since the context alone decides the role.
	#[tokio::test]
	async fn a_client_rekey_context_assembles_a_client_transport() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let (install, _) = run_exchange(&mut client, &mut server).await?;
		assert!(holds_key_switch(RekeyDriver::client(client), install).await);
		Ok(())
	}

	/// A transport assembled from a server's rekey context writes its
	/// key-switch marker at once, as the server role does.
	#[tokio::test]
	async fn a_server_rekey_context_assembles_a_server_transport() -> Result<(), Box<dyn std::error::Error>> {
		let (mut client, mut server) = rekey_pair()?;
		let (_, install) = run_exchange(&mut client, &mut server).await?;
		assert!(!holds_key_switch(RekeyDriver::server(server), install).await);
		Ok(())
	}

	/// The renewal deadline is stamped and waited out on the driver's clock,
	/// so a stalled exchange expires when that clock reaches the deadline and
	/// not before.
	#[test]
	fn a_stalled_renewal_expires_on_the_drivers_clock() {
		let clock = Arc::new(ManualClock::default());
		let (mut driver, _queue) = stalled_driver(OpenSink, Duration::from_secs(30));
		driver.set_clock(Arc::clone(&clock) as Arc<dyn Clock>);

		let mut step = Box::pin(driver.next_step());
		let mut cx = noop_cx();
		let before = step.as_mut().poll(&mut cx);

		clock.advance(Duration::from_secs(30));

		let after = step.as_mut().poll(&mut cx);
		assert!(before.is_pending());
		assert!(matches!(after, Poll::Ready(WriterStep::RenewalExpired)));
	}
}

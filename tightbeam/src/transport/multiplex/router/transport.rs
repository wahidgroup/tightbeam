//! The transport assembly, which connects the shared state, both drivers, the
//! client handle, and the responder over split envelope halves.

use std::sync::Arc;

#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
use core::time::Duration;

use futures::channel::mpsc;

use super::flow::cap_as_usize;
use super::handle::MuxHandle;
use super::link::MuxLink;
use super::reader::MuxReaderDriver;
use super::responder::MuxResponder;
use super::shared::MuxShared;
use super::writer::MuxWriterDriver;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::multiplex::{CreditGrantor, MuxRole};

#[cfg(feature = "tokio")]
use crate::runtime::rt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::multiplex::MuxRekeyContext;

/// A multiplexed transport assembled from split envelope halves and
/// [`MuxSettings`].
pub struct MuxTransport<R, W>
where
	R: EnvelopeSource,
	W: EnvelopeSink,
{
	handle: MuxHandle,
	reader: MuxReaderDriver<R>,
	writer: MuxWriterDriver<W>,
	responder: MuxResponder,
}

impl<R, W> MuxTransport<R, W>
where
	R: EnvelopeSource,
	W: EnvelopeSink,
{
	/// Assemble a multiplexed transport over split halves.
	///
	/// - `role` fixes odd or even stream IDs and MUST match the endpoint's
	///   connection role, where the initiator is the client. A transport with
	///   in-band rekey takes the role of its context ([`Self::with_rekey`]).
	/// - On encrypted halves, `settings` MUST come from [`negotiated_mux`]. A
	///   peer that never negotiated multiplexing rejects every muxed envelope
	///   as invalid.
	/// - Cleartext halves have no negotiation, so both endpoints MUST agree on
	///   the settings out of band ([`MuxSettings::symmetric`]).
	/// - The renewal deadline runs on the clock of `writer` ([`EnvelopeSink::clock`]), its endpoint's clock.
	///
	/// [`negotiated_mux`]: crate::transport::TcpTransport::negotiated_mux
	pub fn new(reader: R, writer: W, role: MuxRole, settings: MuxSettings) -> Self {
		let outbound_capacity =
			cap_as_usize(settings.local_initiated_cap().saturating_add(settings.peer_initiated_cap())).max(1);
		let inbound_capacity = cap_as_usize(settings.peer_initiated_cap()).max(1);
		let (outbound_sender, outbound_receiver) = mpsc::channel(outbound_capacity);
		let (inbound_sender, inbound_receiver) = mpsc::channel(inbound_capacity);

		// The mux plane records into the connection collector that the halves
		// carried across the split.
		#[cfg(not(feature = "instrument"))]
		let shared = MuxShared::new(role, &settings);
		#[cfg(feature = "instrument")]
		let shared = {
			let mut shared = MuxShared::new(role, &settings);
			shared.trace = reader.trace().or_else(|| writer.trace());
			shared
		};

		let shared = Arc::new(shared);
		let drain_headroom = settings.drain_reserve_records();
		let writer = MuxWriterDriver::new(writer, outbound_receiver, Arc::clone(&shared), drain_headroom);
		let (link, drained) = MuxLink::new(shared, outbound_sender);
		let reader = MuxReaderDriver::new(reader, link.clone(), inbound_sender, drained, &settings);
		let handle = MuxHandle::new(link.clone());
		let responder = MuxResponder::new(inbound_receiver, link, settings.peer_initiated_cap());

		Self { handle, reader, writer, responder }
	}

	/// Assemble a multiplexed transport with in-band rekey over split halves,
	/// for receipt-bearing sessions only. The transport takes the role of the
	/// half `context` holds, so its stream IDs and its rekey exchange share one
	/// role.
	///
	/// The receipt in `context` seeds [`MuxHandle::session_receipt`], and each
	/// completed renewal overwrites it. `settings` follow [`Self::new`].
	///
	/// # Exchange halves
	///
	/// - The reader, the writer, and the budget trigger share the client half.
	///   The reader drives the legs, and the writer holds the record-watermark
	///   trigger.
	/// - The server half lives in the reader alone.
	///
	/// # Renewal deadline
	///
	/// The renewal deadline (`with_renewal_deadline`, tokio-only) bounds how
	/// long a peer that never answers a renewal can park this endpoint's data
	/// at the hard floor. A build without tokio has no timer, so the
	/// application MUST put its own timeout around each emit future. A
	/// cancelled emit frees its stream slot.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::handshake::negotiation::MuxSettings;
	/// use tightbeam::transport::multiplex::{MuxConnector, MuxRole, MuxTransport};
	/// use tightbeam::transport::TransportResult;
	///
	/// // A dialed connection that negotiated `settings`, assembled in the role
	/// // of the rekey context its handshake left, or as a client without one.
	/// fn assemble<T: MuxConnector>(
	///     mut connection: T,
	///     settings: MuxSettings,
	/// ) -> TransportResult<MuxTransport<T::EnvelopeReader, T::EnvelopeWriter>> {
	///     let rekey = connection.take_rekey()?;
	///     let (reader, writer) = connection.into_envelope_halves()?;
	///     let mux = match rekey {
	///         Some(context) => MuxTransport::with_rekey(reader, writer, context, settings),
	///         None => MuxTransport::new(reader, writer, MuxRole::Client, settings),
	///     };
	///     Ok(mux)
	/// }
	/// ```
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub fn with_rekey(reader: R, writer: W, context: MuxRekeyContext, settings: MuxSettings) -> Self {
		let MuxRekeyContext { driver, receipt } = context;
		let mut transport = Self::new(reader, writer, driver.role(), settings);
		let opener = driver.renewal_opener().map(Arc::clone);
		transport.writer.set_exchange(opener);
		transport.reader.attach_rekey(driver, receipt);

		transport
	}

	/// Assemble a transport over split halves in `role`, or with in-band
	/// rekey ([`Self::with_rekey`]) when `rekey` holds a context, which brings
	/// the role it was detached for.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn assemble(
		reader: R,
		writer: W,
		role: MuxRole,
		settings: MuxSettings,
		rekey: Option<MuxRekeyContext>,
	) -> Self {
		match rekey {
			Some(context) => Self::with_rekey(reader, writer, context, settings),
			None => Self::new(reader, writer, role, settings),
		}
	}

	/// Override the time budget for one in-band renewal exchange. The default
	/// is [`DEFAULT_REKEY_DEADLINE_SECS`] seconds, and expiry drains the
	/// connection on the GoAway path.
	///
	/// [`DEFAULT_REKEY_DEADLINE_SECS`]: crate::constants::DEFAULT_REKEY_DEADLINE_SECS
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-hpke")))]
	#[must_use]
	pub fn with_renewal_deadline(mut self, deadline: Duration) -> Self {
		self.writer.set_renewal_deadline(deadline);
		self
	}

	/// Override the peer cancel budget, which hardens the connection against
	/// CVE-2023-44487 Rapid Reset.
	pub fn with_cancel_budget(mut self, budget: u32) -> Self {
		self.responder.set_cancel_budget(budget);
		self
	}

	/// Override the receiver-side stream credit policy. The default is a
	/// [`BufferedGrantor`] with a window of [`DEFAULT_MUX_STREAM_CREDIT`]
	/// chunks.
	///
	/// [`BufferedGrantor`]: crate::transport::multiplex::BufferedGrantor
	/// [`DEFAULT_MUX_STREAM_CREDIT`]: crate::constants::DEFAULT_MUX_STREAM_CREDIT
	#[must_use]
	pub fn with_credit_grantor(mut self, grantor: Arc<dyn CreditGrantor>) -> Self {
		self.reader.set_grantor(grantor);
		self
	}

	/// Clone the client handle and leave the transport whole. The clone raises
	/// the reference counts of an `Arc` and a channel.
	pub fn handle(&self) -> MuxHandle {
		self.handle.clone()
	}

	/// Decompose into the handle, the two drivers, and the responder.
	pub fn into_parts(self) -> (MuxHandle, MuxReaderDriver<R>, MuxWriterDriver<W>, MuxResponder) {
		(self.handle, self.reader, self.writer, self.responder)
	}
}

#[cfg(feature = "tokio")]
impl<R, W> MuxTransport<R, W>
where
	R: EnvelopeSource + Send + 'static,
	W: EnvelopeSink + Send + 'static,
{
	/// Spawn both drivers on the runtime and hand back the live plane.
	///
	/// Driver failures resolve pending streams through the shared state
	/// (`fail_all_pending`). [`SpawnedMux::drivers`] owns both tasks: the
	/// reader doubles as the connection's liveness witness, and the drop of
	/// the drivers ends the connection.
	pub fn spawn(self) -> SpawnedMux {
		let (handle, reader_driver, writer_driver, responder) = self.into_parts();
		let reader = rt::spawn(async move {
			// A reader failure has already resolved every pending stream
			// through the shared state, so the task has nowhere else to
			// report it.
			let _ = reader_driver.drive().await;
		});

		let writer = rt::spawn(async move {
			// A writer failure ends the connection, and the reader task is
			// the liveness witness, so the writer task has nothing left to
			// report.
			let _ = writer_driver.drive().await;
		});

		SpawnedMux { handle, responder, drivers: MuxDrivers { reader, writer } }
	}

	/// Apply the optional cancel budget, then spawn both drivers through
	/// [`MuxTransport::spawn`].
	#[cfg(pooled_mux)]
	pub(crate) fn spawn_with(mut self, cancel_budget: Option<u32>) -> SpawnedMux {
		if let Some(budget) = cancel_budget {
			self = self.with_cancel_budget(budget);
		}

		self.spawn()
	}
}

/// A live mux plane, with both drivers spawned and ready to emit and serve.
///
/// [`MuxTransport::spawn`] produces it.
#[cfg(feature = "tokio")]
pub struct SpawnedMux {
	/// The client handle that emits on streams.
	pub handle: MuxHandle,
	/// The server dispatcher of peer-initiated streams.
	pub responder: MuxResponder,
	/// The two driver tasks of the connection. Their drop ends the
	/// connection, so a holder keeps them for as long as it emits or serves.
	pub drivers: MuxDrivers,
}

/// The reader and the writer task of one multiplexed connection.
///
/// The drop of the value aborts both tasks, so the connection ends with the
/// owner that holds the drivers (CWE-772).
///
/// # Examples
///
/// ```
/// use tightbeam::transport::multiplex::SpawnedMux;
///
/// /// Whether the connection of `spawned` died.
/// fn died(spawned: &SpawnedMux) -> bool {
///     spawned.drivers.is_finished()
/// }
/// ```
#[cfg(feature = "tokio")]
pub struct MuxDrivers {
	reader: rt::JoinHandle,
	writer: rt::JoinHandle,
}

#[cfg(feature = "tokio")]
impl MuxDrivers {
	/// Whether the reader of the connection ended, which witnesses that the
	/// connection died.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::multiplex::MuxDrivers;
	///
	/// /// Whether a pool must evict the connection that `drivers` runs.
	/// fn evicts(drivers: &MuxDrivers) -> bool {
	///     drivers.is_finished()
	/// }
	/// ```
	#[must_use]
	pub fn is_finished(&self) -> bool {
		self.reader.is_finished()
	}

	/// Waits for the writer to end, and then ends the reader with the drop.
	///
	/// [`MuxHandle::close`] queues the close that the writer ends on, so every
	/// envelope queued before it reaches the peer first. The writer bounds
	/// each write by its operation deadline.
	#[cfg(pooled_mux)]
	pub(crate) async fn finish(mut self) {
		// A writer that panicked has ended all the same, so its join outcome
		// carries nothing that the close acts on.
		let _ended = (&mut self.writer).await;
	}
}

/// The drop aborts both tasks through the runtime interface.
#[cfg(feature = "tokio")]
impl Drop for MuxDrivers {
	fn drop(&mut self) {
		rt::abort(&self.reader);
		rt::abort(&self.writer);
	}
}

//! The transport assembly, which connects the shared state, both drivers, the
//! client handle, and the responder over split envelope halves.

use std::sync::Arc;

use futures::channel::mpsc;

use super::flow::{cap_as_usize, CreditGrantor};
use super::handle::MuxHandle;
use super::link::MuxLink;
use super::reader::MuxReaderDriver;
use super::responder::MuxResponder;
use super::shared::MuxShared;
use super::writer::MuxWriterDriver;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::io::{EnvelopeSink, EnvelopeSource};
use crate::transport::multiplex::MuxRole;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::multiplex::MuxRekeyContext;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::rekey::RekeyDriver;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use crate::utils::time::Clock;
#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
use core::time::Duration;

#[cfg(feature = "tokio")]
use crate::runtime::rt;

/// Multiplexed transport assembled from split envelope halves and
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
	///   connection role, where the initiator is the client.
	/// - On encrypted halves, `settings` MUST come from [`negotiated_mux`]. A
	///   peer that never negotiated multiplexing rejects every muxed envelope
	///   as invalid.
	/// - On cleartext halves there is no negotiation, so both endpoints MUST
	///   agree on the same settings out of band ([`MuxSettings::symmetric`]).
	///
	/// [`negotiated_mux`]: crate::transport::TcpTransport::negotiated_mux
	pub fn new(reader: R, writer: W, role: MuxRole, settings: MuxSettings) -> Self {
		let outbound_capacity =
			cap_as_usize(settings.local_initiated_cap.saturating_add(settings.peer_initiated_cap)).max(1);
		let inbound_capacity = cap_as_usize(settings.peer_initiated_cap).max(1);
		let (outbound_sender, outbound_receiver) = mpsc::channel(outbound_capacity);
		let (inbound_sender, inbound_receiver) = mpsc::channel(inbound_capacity);

		// Instrumentation inherits the connection collector that the halves
		// carried across the split, so the mux plane takes no collector of its
		// own.
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
		let responder = MuxResponder::new(inbound_receiver, link, settings.peer_initiated_cap);

		Self { handle, reader, writer, responder }
	}

	/// Attach in-band rekey, for receipt-bearing sessions only.
	///
	/// The call seeds the handle receipt accessor from the handshake artifact,
	/// and each completed renewal overwrites it.
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
	/// at the hard floor. A build without tokio has no timer here, so the
	/// embedding application MUST bound parked emits itself by wrapping emit
	/// futures in its own timeout. A cancelled emit frees its stream slot.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[must_use]
	pub fn with_rekey(mut self, context: MuxRekeyContext) -> Self {
		let MuxRekeyContext { driver, receipt } = context;
		if let RekeyDriver::Client(exchange) = &driver {
			self.writer.set_exchange(Arc::clone(exchange));
		}
		self.reader.attach_rekey(driver, receipt);

		self
	}

	/// Override the time budget for one in-band renewal exchange. The default
	/// is [`DEFAULT_REKEY_DEADLINE_SECS`] seconds, and expiry drains the
	/// connection on the GoAway path.
	///
	/// [`DEFAULT_REKEY_DEADLINE_SECS`]: crate::constants::DEFAULT_REKEY_DEADLINE_SECS
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	#[must_use]
	pub fn with_renewal_deadline(mut self, deadline: Duration) -> Self {
		self.writer.set_renewal_deadline(deadline);
		self
	}

	/// Replace the clock the renewal deadline is measured and waited on.
	///
	/// The writer adopts the clock of the link it writes to
	/// ([`EnvelopeSink::clock`]), so an endpoint needs no call here. A test
	/// installs a [`ManualClock`](crate::utils::time::ManualClock) and
	/// advances it to the deadline instead of waiting it out.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	#[must_use]
	pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
		self.writer.set_clock(clock);
		self
	}

	/// Override the peer cancel budget (CVE-2023-44487 hardening).
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

	/// Clone the client handle without decomposing the transport
	/// (`Arc` + channel refcount bumps).
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
	/// (`fail_all_pending`), so the tasks are fire-and-forget. The reader task
	/// doubles as the connection's liveness witness
	/// ([`SpawnedMux::reader_task`]), and the writer task ends on its own when
	/// the connection dies.
	pub fn spawn(self) -> SpawnedMux {
		let (handle, reader_driver, writer_driver, responder) = self.into_parts();
		let reader_task = rt::spawn(async move {
			// A reader failure has already resolved every pending stream
			// through the shared state, so the task has nowhere else to
			// report it.
			let _ = reader_driver.drive().await;
		});

		rt::spawn(async move {
			// A writer failure ends the connection, and the reader task is
			// the liveness witness, so the writer task has nothing left to
			// report.
			let _ = writer_driver.drive().await;
		});

		SpawnedMux { handle, responder, reader_task }
	}

	/// Apply the optional cancel budget and rekey context, then spawn both
	/// drivers through [`MuxTransport::spawn`].
	#[cfg(pooled_mux)]
	pub(crate) fn spawn_with(mut self, cancel_budget: Option<u32>, rekey: Option<MuxRekeyContext>) -> SpawnedMux {
		if let Some(budget) = cancel_budget {
			self = self.with_cancel_budget(budget);
		}
		if let Some(context) = rekey {
			self = self.with_rekey(context);
		}

		self.spawn()
	}
}

/// A running mux plane, with both drivers spawned and ready to emit and serve.
///
/// [`MuxTransport::spawn`] produces it.
#[cfg(feature = "tokio")]
pub struct SpawnedMux {
	/// Client-side handle for emitting on streams.
	pub handle: MuxHandle,
	/// Server-side dispatcher for peer-initiated streams.
	pub responder: MuxResponder,
	/// The reader driver's task, which finishes when the connection dies, so
	/// holders use it as the connection's liveness witness.
	pub reader_task: rt::JoinHandle,
}

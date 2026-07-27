//! Transport assembly: wires the shared state, both drivers, the
//! client handle, and the responder over split envelope halves.

use std::sync::Arc;

use futures::channel::mpsc;

use super::flow::{cap_as_usize, CreditGrantor};
use super::handle::MuxHandle;
use super::outbound::outbound_handle;
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
use core::time::Duration;

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
	/// `role` fixes odd/even stream IDs and MUST match the endpoint's
	/// connection role (initiator = client). On encrypted halves,
	/// `settings` MUST come from
	/// [`negotiated_mux`](crate::transport::TcpTransport::negotiated_mux).
	/// A peer that never negotiated multiplexing rejects every muxed
	/// envelope as invalid. On cleartext halves there is no
	/// negotiation: both endpoints MUST agree on the same settings out
	/// of band ([`MuxSettings::symmetric`]).
	pub fn new(reader: R, writer: W, role: MuxRole, settings: MuxSettings) -> Self {
		let outbound_capacity =
			cap_as_usize(settings.local_initiated_cap.saturating_add(settings.peer_initiated_cap)).max(1);
		let inbound_capacity = cap_as_usize(settings.peer_initiated_cap).max(1);
		let (outbound_sender, outbound_receiver) = mpsc::channel(outbound_capacity);
		let (inbound_sender, inbound_receiver) = mpsc::channel(inbound_capacity);

		// Seam instrumentation inherits the connection collector the
		// halves carried across the split; no separate injection.
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
		let reader = MuxReaderDriver::new(
			reader,
			Arc::clone(&shared),
			inbound_sender,
			outbound_handle(&outbound_sender),
			&settings,
		);
		let handle = MuxHandle::new(Arc::clone(&shared), outbound_handle(&outbound_sender), reader.drain_feedback());
		let writer = MuxWriterDriver::new(writer, outbound_receiver, Arc::clone(&shared), drain_headroom);
		let responder = MuxResponder::new(inbound_receiver, outbound_sender, shared, settings.peer_initiated_cap);

		Self { handle, reader, writer, responder }
	}

	/// Attach in-band rekey (receipt-bearing sessions only).
	/// Seeds the handle receipt accessor from the handshake artifact;
	/// each completed renewal overwrites it.
	///
	/// The client half of the exchange is shared between the reader
	/// (drives the legs), the writer (record-watermark trigger),
	/// and the budget trigger. The server half lives in the reader
	/// alone.
	///
	/// # Renewal deadline
	///
	/// The renewal deadline (`with_renewal_deadline`, tokio-only)
	/// bounds how long a peer that never answers a renewal can park
	/// this endpoint's data at the hard floor. Builds without tokio
	/// have no timer here: the embedding application MUST bound
	/// parked emits itself by wrapping emit futures in its own
	/// timeout (a cancelled emit frees its stream slot).
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

	/// Override the time budget for one in-band renewal exchange
	/// (default [`DEFAULT_REKEY_DEADLINE_SECS`](crate::constants::DEFAULT_REKEY_DEADLINE_SECS)).
	/// Expiry drains the
	/// connection on the GoAway path.
	#[cfg(all(feature = "tokio", any(feature = "transport-cms", feature = "transport-ecies")))]
	#[must_use]
	pub fn with_renewal_deadline(mut self, deadline: Duration) -> Self {
		self.writer.set_renewal_deadline(deadline);
		self
	}

	/// Override the peer cancel budget (CVE-2023-44487 hardening).
	pub fn with_cancel_budget(mut self, budget: u32) -> Self {
		self.responder.set_cancel_budget(budget);
		self
	}

	/// Override the receiver-side stream credit policy (default:
	/// [`BufferedGrantor`] with a
	/// [`DEFAULT_MUX_STREAM_CREDIT`]-chunk window).
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

	/// Decompose into the handle, the two drivers to spawn, and
	/// the responder.
	pub fn into_parts(self) -> (MuxHandle, MuxReaderDriver<R>, MuxWriterDriver<W>, MuxResponder) {
		(self.handle, self.reader, self.writer, self.responder)
	}
}

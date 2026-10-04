//! Writer-queue command protocol.
//!
//! [`Outbound`] is the one vocabulary that every producer shares with the
//! writer driver. The producers are the handle, the sinks, the reader, and
//! the responder.

use crate::transport::envelopes::{CancelReason, MuxEnvelope, TransportEnvelope};

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::aead::SendCipher;

/// One command a producer queues for the writer driver.
pub enum Outbound {
	/// Write the envelope to the connection.
	Envelope(TransportEnvelope),
	/// Write the envelope, then switch the send direction to the new epoch
	/// cipher. The switch sits at the client `RekeyAck` boundary or the server
	/// `RekeyDone` boundary.
	///
	/// # Sources
	///
	/// - RFC 9846 § 4.7.3, the TLS KeyUpdate message:
	///   <https://datatracker.ietf.org/doc/html/rfc9846#section-4.7.3>
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	EnvelopeThenInstall(TransportEnvelope, Box<SendCipher>),
	/// Budget-watermark renewal trigger from a handle, on which the writer
	/// opens the exchange.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	StartRenewal,
	/// Stop the writer driver, which ends its run with `Ok(())`.
	Close,
}

impl Outbound {
	/// Whether this command is a buffered credit grant for `stream_id`.
	pub(crate) fn is_credit_grant_for(&self, stream_id: u32) -> bool {
		matches!(
			self,
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Credit(package)))
				if package.stream_id() == stream_id
		)
	}

	/// Whether this command is a buffered ping ack.
	pub(crate) fn is_ping_ack(&self) -> bool {
		matches!(self, Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Ping(_))))
	}

	/// Whether this command is a buffered refusal of a peer stream.
	pub(crate) fn is_refusal(&self) -> bool {
		matches!(
			self,
			Outbound::Envelope(TransportEnvelope::Mux(MuxEnvelope::Cancel(package)))
				if package.reason() == CancelReason::Rejected
		)
	}
}

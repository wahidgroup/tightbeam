//! [`TransportLimits`] holds every ceiling a transport enforces: the largest
//! envelope on the wire in each wire mode and in the handshake, and the
//! deadline of one operation and of the whole handshake.

use core::time::Duration;

use crate::constants::{
	DEFAULT_HANDSHAKE_MAX_WIRE, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_CLEARTEXT_ENVELOPE,
	DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_OPERATION_TIMEOUT,
};
use crate::transport::envelopes::WireMode;

/// Every ceiling a transport enforces, in one value.
///
/// Each field is a plain `usize` or `Duration`, so every transport holds a
/// value for every limit, and an unset limit is unrepresentable.
///
/// [`Default`] is the one place that chooses these values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
	/// The ceiling in bytes of a cleartext envelope on the wire.
	pub cleartext_envelope: usize,
	/// The ceiling in bytes of an encrypted envelope on the wire.
	pub encrypted_envelope: usize,
	/// The ceiling in bytes of one handshake-phase message on the wire.
	pub handshake_wire: usize,
	/// The deadline of a dial, and of a single read or write on the transport.
	///
	/// The blocking transport arms it on its stream, and the async transport
	/// arms it under `tokio`. An async build without `tokio` has no timer, so
	/// the application owns the deadline there.
	pub operation_timeout: Duration,
	/// The deadline of the whole handshake exchange.
	///
	/// It binds as [`Self::operation_timeout`] does: the blocking transport
	/// arms it on its stream, and the async transport arms it under `tokio`.
	/// An async build without `tokio` leaves it to the application.
	pub handshake_timeout: Duration,
}

impl TransportLimits {
	/// Returns the largest envelope this endpoint reads before the parse
	/// decides which ceiling applies.
	///
	/// A reader learns whether the bytes are a cleartext or an encrypted
	/// envelope only once it has them, so it admits the larger ceiling, and the
	/// per-mode check runs once the reader knows the wire form.
	#[must_use]
	pub fn max_envelope(&self) -> usize {
		if self.encrypted_envelope > self.cleartext_envelope {
			self.encrypted_envelope
		} else {
			self.cleartext_envelope
		}
	}

	/// The ceiling in bytes of a wire envelope of `mode`. A write and a read
	/// both take their ceiling from here.
	pub(crate) const fn envelope_ceiling(&self, mode: WireMode) -> usize {
		match mode {
			WireMode::Cleartext => self.cleartext_envelope,
			WireMode::Encrypted => self.encrypted_envelope,
		}
	}
}

impl Default for TransportLimits {
	fn default() -> Self {
		Self {
			cleartext_envelope: DEFAULT_MAX_CLEARTEXT_ENVELOPE,
			encrypted_envelope: DEFAULT_MAX_ENCRYPTED_ENVELOPE,
			handshake_wire: DEFAULT_HANDSHAKE_MAX_WIRE,
			operation_timeout: DEFAULT_OPERATION_TIMEOUT,
			handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
		}
	}
}

//! [`TransportLimits`] holds every ceiling a transport enforces: the largest
//! envelope on the wire in each wire mode and in the handshake, and the
//! deadline of one operation and of the whole handshake.

use core::ops::Deref;
use core::time::Duration;

use crate::constants::{
	DEFAULT_HANDSHAKE_MAX_WIRE, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_CLEARTEXT_ENVELOPE,
	DEFAULT_MAX_ENCRYPTED_ENVELOPE, DEFAULT_OPERATION_TIMEOUT,
};
use crate::transport::envelopes::{WireEnvelope, WireMode};
use crate::transport::error::{LimitsRefusal, TransportError};
use crate::transport::TransportResult;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::Encode;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::envelopes::TransportEnvelope;

/// Every ceiling a transport enforces, in one value.
///
/// Each field is a plain `usize` or `Duration`, so an unset limit is
/// unrepresentable. [`Default`] is the one place that chooses the values.
/// [`Self::checked`] admits a set whose ceilings agree as a [`CheckedLimits`],
/// the form that each endpoint configuration and every transport hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportLimits {
	/// The ceiling in bytes of a cleartext envelope on the wire.
	pub cleartext_envelope: usize,
	/// The ceiling in bytes of an encrypted envelope on the wire.
	pub encrypted_envelope: usize,
	/// The ceiling in bytes of one handshake-phase message, in the transport
	/// envelope it travels in. The writer admits that envelope, and a
	/// handshaking reader caps it.
	pub handshake_wire: usize,
	/// The deadline of a dial, and of a single read or write on the transport.
	///
	/// The blocking transport arms it on its stream, and the async transport
	/// arms it under `tokio`. An async build without `tokio` has no timer, so
	/// the application owns the deadline there.
	pub operation_timeout: Duration,
	/// The deadline of the whole handshake exchange. It binds as
	/// [`Self::operation_timeout`] does.
	pub handshake_timeout: Duration,
}

impl TransportLimits {
	/// Returns this set as [`CheckedLimits`] when its ceilings agree:
	///
	/// - No ceiling is zero, because a zero ceiling refuses every envelope or every operation it bounds.
	/// - A handshake message at [`Self::handshake_wire`] fits [`Self::cleartext_envelope`] on the wire.
	///
	/// A handshake travels in cleartext, and a reader checks the cleartext
	/// ceiling after the handshake cap, so the second rule lets every
	/// handshake message that the writer admits reach the peer.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidLimits`] with [`LimitsRefusal::ZeroCeiling`] -- a ceiling is zero.
	/// - [`TransportError::InvalidLimits`] with
	///   [`LimitsRefusal::HandshakePastCleartext`] -- a handshake message of
	///   `handshake_wire` octets passes `cleartext_envelope` on the wire.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::transport::{LimitsRefusal, TransportError, TransportLimits};
	///
	/// // A handshake ceiling past the cleartext ceiling admits a handshake
	/// // message that the reader of the peer refuses.
	/// let inverted = TransportLimits { handshake_wire: 1 << 20, ..TransportLimits::default() };
	/// let refused = inverted.checked();
	/// assert!(matches!(refused, Err(TransportError::InvalidLimits(LimitsRefusal::HandshakePastCleartext))));
	///
	/// let limits = TransportLimits::default();
	/// assert_eq!(*limits.checked()?, limits);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn checked(self) -> TransportResult<CheckedLimits> {
		let ceilings = [self.cleartext_envelope, self.encrypted_envelope, self.handshake_wire];
		let deadlines = [self.operation_timeout, self.handshake_timeout];
		if ceilings.contains(&0) || deadlines.contains(&Duration::ZERO) {
			return Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling));
		}

		let handshake_on_wire = WireEnvelope::cleartext_len(self.handshake_wire);
		if !handshake_on_wire.is_ok_and(|len| len <= self.cleartext_envelope) {
			return Err(TransportError::InvalidLimits(LimitsRefusal::HandshakePastCleartext));
		}

		Ok(CheckedLimits(self))
	}

	/// The largest envelope this endpoint reads before the parse picks a
	/// ceiling.
	///
	/// A reader knows the wire mode only once it has the bytes, so it admits
	/// the larger ceiling and runs the per-mode check after the parse.
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

	/// Admits `envelope`, the transport envelope of one handshake message, to
	/// the wire. Every handshake message an endpoint sends takes its ceiling
	/// from here, and a handshaking reader caps the same envelope
	/// ([`SessionPhase::read_policy`]), so a message that one end sends is one
	/// that the other end reads.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidMessage`] -- `envelope` passes [`Self::handshake_wire`].
	/// - [`TransportError::DerError`] -- the length of `envelope` fails to encode.
	///
	/// [`SessionPhase::read_policy`]: crate::transport::state::SessionPhase::read_policy
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn admit_handshake_wire(&self, envelope: &TransportEnvelope) -> TransportResult<()> {
		let envelope_len = usize::try_from(envelope.encoded_len()?)?;
		if envelope_len > self.handshake_wire {
			return Err(TransportError::InvalidMessage);
		}

		Ok(())
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

/// A [`TransportLimits`] whose ceilings agree, which
/// [`TransportLimits::checked`] alone returns.
///
/// Each endpoint configuration, every transport, and the
/// [`EnvelopeBuilder`](crate::transport::EnvelopeBuilder) hold their limits
/// as this proof, and each reads the ceilings it holds through [`Deref`].
///
/// # Examples
///
/// ```
/// use tightbeam::transport::{CheckedLimits, TransportLimits};
///
/// let limits: CheckedLimits = TransportLimits::default().checked()?;
/// assert_eq!(*limits, TransportLimits::default());
/// assert_eq!(limits, CheckedLimits::default());
/// # Ok::<(), tightbeam::transport::TransportError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckedLimits(TransportLimits);

/// The default limits, whose ceilings agree.
impl Default for CheckedLimits {
	fn default() -> Self {
		Self(TransportLimits::default())
	}
}

impl Deref for CheckedLimits {
	type Target = TransportLimits;

	fn deref(&self) -> &TransportLimits {
		&self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// A set whose ceilings agree passes the check whole: the defaults, so an
	// endpoint that configures no limits holds an agreeing set, and a
	// handshake ceiling whose wire form meets the cleartext ceiling exactly.
	crate::tb_cases! {
		fn an_agreeing_set_passes_the_check(limits: TransportLimits) -> crate::testing::TestResult {
			let checked = limits.checked()?;
			assert_eq!(*checked, limits);
			Ok(())
		}
		cases {
			the_defaults => TransportLimits::default(),
			a_handshake_wire_form_at_the_cleartext_ceiling => TransportLimits {
				handshake_wire: 16_384,
				cleartext_envelope: 16_388,
				..TransportLimits::default()
			},
		}
	}

	// Each case is a set with one ceiling at zero, which refuses every
	// envelope or every operation it bounds.
	crate::tb_cases! {
		fn a_zero_ceiling_is_refused(limits: TransportLimits) {
			let refused = limits.checked();
			assert!(matches!(refused, Err(TransportError::InvalidLimits(LimitsRefusal::ZeroCeiling))));
		}
		cases {
			cleartext_envelope => TransportLimits { cleartext_envelope: 0, ..TransportLimits::default() },
			encrypted_envelope => TransportLimits { encrypted_envelope: 0, ..TransportLimits::default() },
			handshake_wire => TransportLimits { handshake_wire: 0, ..TransportLimits::default() },
			operation_timeout => TransportLimits { operation_timeout: Duration::ZERO, ..TransportLimits::default() },
			handshake_timeout => TransportLimits { handshake_timeout: Duration::ZERO, ..TransportLimits::default() },
		}
	}

	// Each case is (handshake ceiling, cleartext ceiling). A handshake message
	// of 16,384 octets takes 16,388 on the wire: the `[0]` tag, a length of
	// three octets, and the envelope.
	crate::tb_cases! {
		fn a_handshake_ceiling_past_the_cleartext_ceiling_on_the_wire_is_refused(
			(handshake_wire, cleartext_envelope): (usize, usize)
		) {
			let limits = TransportLimits { handshake_wire, cleartext_envelope, ..TransportLimits::default() };
			let refused = limits.checked();
			assert!(matches!(refused, Err(TransportError::InvalidLimits(LimitsRefusal::HandshakePastCleartext))));
		}
		cases {
			by_the_outer_header => (16_384, 16_387),
			at_equal_ceilings => (16_384, 16_384),
			inverted => (1 << 20, 128 * 1024),
			past_the_der_length_range => (usize::MAX, usize::MAX),
		}
	}
}

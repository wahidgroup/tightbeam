//! Envelope builder for constructing wire-level envelopes.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::{AuthEnvelopedData, Frame};
use crate::builder::TypeBuilder;
use crate::der::Encode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::{CheckedLimits, ResponsePackage, TransportEnvelope, TransportResult, WireEnvelope, WireMode};
use crate::TightBeamError;

use crate::crypto::aead::SendCipher;

#[derive(Debug)]
pub(crate) enum EnvelopePayload {
	Request { message: Box<Frame> },
	Response { package: ResponsePackage },
	Transport { envelope: TransportEnvelope },
}

impl EnvelopePayload {
	pub(crate) fn materialize(self) -> TransportEnvelope {
		match self {
			Self::Request { message } => TransportEnvelope::new_request(*message),
			Self::Response { package } => TransportEnvelope::from(package),
			Self::Transport { envelope } => envelope,
		}
	}
}

/// How an envelope leaves the builder: in the clear, or as one record under a
/// send cipher.
///
/// The encrypted form holds its cipher, so an encrypted envelope always names
/// the cipher that seals it.
#[derive(Clone, Copy)]
pub(crate) enum Sealing<'a> {
	/// The envelope travels in the clear.
	Cleartext,
	/// The envelope travels as one record that the cipher seals.
	Encrypted(&'a SendCipher),
}

impl Sealing<'_> {
	/// The wire mode of this sealing, whose ceiling the wire form must fit.
	const fn mode(&self) -> WireMode {
		match self {
			Self::Cleartext => WireMode::Cleartext,
			Self::Encrypted(_) => WireMode::Encrypted,
		}
	}
}

/// The builder of a [`WireEnvelope`], with shared size validation and
/// encryption.
pub struct EnvelopeBuilder<'a> {
	pub(crate) payload: EnvelopePayload,
	pub(crate) limits: CheckedLimits,
	sealing: Sealing<'a>,
}

impl<'a> EnvelopeBuilder<'a> {
	fn new(payload: EnvelopePayload) -> Self {
		Self { payload, limits: CheckedLimits::default(), sealing: Sealing::Cleartext }
	}

	/// Create a builder configured for a request frame.
	pub fn request(message: Frame) -> Self {
		Self::new(EnvelopePayload::Request { message: Box::new(message) })
	}

	/// Create a builder configured for a response package.
	pub fn response(package: ResponsePackage) -> Self {
		Self::new(EnvelopePayload::Response { package })
	}

	/// Create a builder around an existing transport envelope.
	pub fn transport(envelope: TransportEnvelope) -> Self {
		Self::new(EnvelopePayload::Transport { envelope })
	}

	/// Sends the envelope in the clear, which a builder does unless
	/// [`Self::sealed_by`] names a cipher.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::transport::{EnvelopeBuilder, WireEnvelope};
	///
	/// let wire = EnvelopeBuilder::request(TestFrame::v0(None, None)).cleartext().finish()?;
	/// assert!(matches!(wire, WireEnvelope::Cleartext(_)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn cleartext(self) -> Self {
		self.with_sealing(Sealing::Cleartext)
	}

	/// Seals the envelope under `cipher` as one record, which takes the next
	/// sequence number of the cipher.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::aead::{RecordDirection, RuntimeAead, SendCipher};
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::testing::TestFrame;
	/// use tightbeam::transport::{EnvelopeBuilder, WireEnvelope};
	///
	/// let key = RuntimeAead::new::<DefaultCryptoProvider>(vec![0u8; 32])?;
	/// let cipher = SendCipher::new(key, 0, RecordDirection::ClientToServer);
	///
	/// let wire = EnvelopeBuilder::request(TestFrame::v0(None, None)).sealed_by(&cipher).finish()?;
	/// assert!(matches!(wire, WireEnvelope::Encrypted(_)));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn sealed_by(self, cipher: &'a SendCipher) -> Self {
		self.with_sealing(Sealing::Encrypted(cipher))
	}

	/// Sends the envelope as `sealing` names.
	pub(crate) fn with_sealing(mut self, sealing: Sealing<'a>) -> Self {
		self.sealing = sealing;
		self
	}

	/// Replace every ceiling this envelope is measured against with `limits`,
	/// a set whose ceilings agree ([`TransportLimits::checked`]).
	///
	/// [`TransportLimits::checked`]: crate::transport::TransportLimits::checked
	pub fn with_limits(mut self, limits: CheckedLimits) -> Self {
		self.limits = limits;
		self
	}

	/// Finalize the builder into its wire form. A sealing under a cipher seals
	/// the envelope, and the call refuses a wire form past the envelope
	/// ceiling of its mode.
	///
	/// # Errors
	///
	/// - [`TransportError::MessageNotSent`] -- a request did not encode, seal,
	///   or fit its ceiling, and its frame travels with the error.
	/// - The error that the same failure of a response or a transport envelope converts into.
	pub fn finish(self) -> TransportResult<WireEnvelope> {
		let EnvelopeBuilder { payload, limits, sealing } = self;

		let envelope = payload.materialize();
		let with_frame = Self::frame_error_context(&envelope);

		let wire = match sealing {
			Sealing::Cleartext => WireEnvelope::Cleartext(envelope),
			Sealing::Encrypted(cipher) => {
				let encrypted = Self::encrypt(envelope, cipher, &with_frame)?;
				WireEnvelope::Encrypted(encrypted)
			}
		};

		// The ceiling names the wire form, so the tag and wrapper are inside
		// the measurement. `encoded_len` computes it without building a
		// buffer.
		let ceiling = limits.envelope_ceiling(sealing.mode());
		let wire_len = u32::from(wire.encoded_len().map_err(|_| with_frame(TransportFailure::EncodingFailed))?);
		if wire_len as usize > ceiling {
			return Err(with_frame(TransportFailure::SizeExceeded));
		}

		Ok(wire)
	}

	/// Error constructor that returns the caller's frame with the failure, so a
	/// refused request need not be reconstructed to retry.
	fn frame_error_context(envelope: &TransportEnvelope) -> impl Fn(TransportFailure) -> TransportError {
		let request_frame = envelope.request_frame().map(Arc::clone);

		move |failure: TransportFailure| -> TransportError {
			request_frame
				.as_ref()
				.map(Arc::clone)
				.map(|arc| {
					// The clone runs on the error path alone, off the hot path.
					let frame = Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone());
					failure.with_frame(frame)
				})
				.unwrap_or_else(|| failure.into())
		}
	}

	/// Encode and seal one envelope with the session's send cipher.
	///
	/// The encoded envelope moves into the record, which encrypts it in place.
	fn encrypt(
		envelope: TransportEnvelope,
		cipher: &SendCipher,
		with_frame: &impl Fn(TransportFailure) -> TransportError,
	) -> TransportResult<AuthEnvelopedData> {
		let encoded = envelope.to_der().map_err(|_| with_frame(TransportFailure::EncodingFailed))?;

		// The send cipher owns the record sequence and draws each record's
		// content key.
		cipher.encrypt_next(encoded).map_err(|error| {
			// Rekey exhaustion stays distinguishable: the caller must
			// reestablish the session, not retry the write.
			let failure = match error {
				TightBeamError::RekeyRequired => TransportFailure::RekeyRequired,
				_ => TransportFailure::EncryptionFailed,
			};
			with_frame(failure)
		})
	}
}

impl<'a> TypeBuilder<WireEnvelope> for EnvelopeBuilder<'a> {
	type Error = TransportError;

	fn build(self) -> TransportResult<WireEnvelope> {
		self.finish()
	}
}

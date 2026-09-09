//! Envelope builder for constructing wire-level envelopes.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::builder::TypeBuilder;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::der::Encode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::{ResponsePackage, TransportEnvelope, TransportLimits, TransportResult, WireEnvelope, WireMode};
use crate::TightBeamError;

#[cfg(feature = "x509")]
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

/// Builder responsible for constructing `WireEnvelope` instances with shared
/// size validation and encryption logic.
pub struct EnvelopeBuilder<'a> {
	pub(crate) payload: EnvelopePayload,
	pub(crate) encryptor: Option<&'a SendCipher>,
	pub(crate) limits: TransportLimits,
	pub(crate) wire_mode: WireMode,
}

impl<'a> EnvelopeBuilder<'a> {
	fn new(payload: EnvelopePayload) -> Self {
		Self {
			payload,
			encryptor: None,
			limits: TransportLimits::default(),
			wire_mode: WireMode::Cleartext,
		}
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

	pub fn with_encryptor(mut self, encryptor: &'a SendCipher) -> Self {
		self.encryptor = Some(encryptor);
		self
	}

	/// Replace every ceiling this envelope is measured against.
	pub fn with_limits(mut self, limits: TransportLimits) -> Self {
		self.limits = limits;
		self
	}

	pub fn with_wire_mode(mut self, mode: WireMode) -> Self {
		self.wire_mode = mode;
		self
	}

	/// Finalize the builder, returning a `WireEnvelope`.
	pub fn finish(self) -> TransportResult<WireEnvelope> {
		let EnvelopeBuilder { payload, encryptor, limits, wire_mode } = self;

		let envelope = payload.materialize();
		let with_frame = Self::frame_error_context(&envelope);

		let (wire, ceiling) = match wire_mode {
			WireMode::Cleartext => (WireEnvelope::Cleartext(envelope), limits.cleartext_envelope),
			WireMode::Encrypted => {
				let encrypted = Self::encrypt(envelope, encryptor, &with_frame)?;
				(WireEnvelope::Encrypted(encrypted), limits.encrypted_envelope)
			}
		};

		// The ceiling names the wire form, so the tag and wrapper are inside the
		// measurement. `encoded_len` computes it without building a buffer.
		let wire_len = u32::from(wire.encoded_len().map_err(|_| with_frame(TransportFailure::EncodingFailed))?);
		if wire_len as usize > ceiling {
			return Err(with_frame(TransportFailure::SizeExceeded));
		}

		Ok(wire)
	}

	/// Error constructor that returns the caller's frame with the failure, so a
	/// refused request need not be reconstructed to retry.
	fn frame_error_context(envelope: &TransportEnvelope) -> impl Fn(TransportFailure) -> TransportError {
		let request_frame = match envelope {
			TransportEnvelope::Request(pkg) => Some(Arc::clone(&pkg.message)),
			_ => None,
		};

		move |failure: TransportFailure| -> TransportError {
			request_frame
				.as_ref()
				.map(Arc::clone)
				.map(|arc| {
					// Non-hot path clone
					let frame = Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone());
					failure.with_frame(frame)
				})
				.unwrap_or_else(|| failure.into())
		}
	}

	/// Encode and seal one envelope with the session's send cipher.
	fn encrypt(
		envelope: TransportEnvelope,
		encryptor: Option<&'a SendCipher>,
		with_frame: &impl Fn(TransportFailure) -> TransportError,
	) -> TransportResult<EncryptedContentInfo> {
		let encoded = envelope.to_der().map_err(|_| with_frame(TransportFailure::EncodingFailed))?;

		// The send cipher owns the counter nonce. No random nonce is drawn.
		let encryptor = encryptor.ok_or_else(|| with_frame(TransportFailure::EncryptorUnavailable))?;
		encryptor.encrypt_next(&encoded, None).map_err(|error| {
			// Rekey exhaustion stays distinguishable: the caller must
			// reestablish the session, not retry the write.
			let failure = match error {
				#[cfg(feature = "aead")]
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

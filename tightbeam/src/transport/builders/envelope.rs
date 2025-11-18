//! Envelope builder for constructing wire-level envelopes.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::Frame;
use crate::builder::TypeBuilder;
use crate::der::Encode;
use crate::transport::error::{TransportError, TransportFailure};
use crate::transport::{ResponsePackage, TransportEnvelope, TransportResult, WireEnvelope, WireMode};

/// Helper to unwrap an Arc<Frame> to an owned Frame.
#[inline]
fn unwrap_arc_frame(arc: Arc<Frame>) -> Frame {
	Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone())
}

#[cfg(feature = "x509")]
use crate::crypto::aead::RuntimeAead;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum EnvelopePayload {
	Request { message: Frame },
	Response { package: ResponsePackage },
	Transport { envelope: TransportEnvelope },
}

impl EnvelopePayload {
	pub(crate) fn materialize(self) -> TransportEnvelope {
		match self {
			Self::Request { message } => TransportEnvelope::new_request(message),
			Self::Response { package } => TransportEnvelope::from(package),
			Self::Transport { envelope } => envelope,
		}
	}
}

/// Builder responsible for constructing `WireEnvelope` instances with shared
/// size validation and encryption logic.
pub struct EnvelopeBuilder<'a> {
	pub(crate) payload: EnvelopePayload,
	pub(crate) encryptor: Option<&'a RuntimeAead>,
	pub(crate) max_cleartext_envelope: Option<usize>,
	pub(crate) max_encrypted_envelope: Option<usize>,
	pub(crate) wire_mode: WireMode,
}

/// Size limits for cleartext and encrypted envelopes.
#[derive(Clone, Copy, Default)]
pub struct EnvelopeLimits {
	cleartext: Option<usize>,
	encrypted: Option<usize>,
}

impl EnvelopeLimits {
	pub fn new() -> Self {
		Self::default()
	}

	pub fn from_pair(cleartext: Option<usize>, encrypted: Option<usize>) -> Self {
		Self { cleartext, encrypted }
	}

	pub fn with_cleartext(mut self, limit: Option<usize>) -> Self {
		self.cleartext = limit;
		self
	}

	pub fn with_encrypted(mut self, limit: Option<usize>) -> Self {
		self.encrypted = limit;
		self
	}

	pub fn apply<'a>(self, builder: EnvelopeBuilder<'a>) -> EnvelopeBuilder<'a> {
		let builder = if let Some(max) = self.cleartext {
			builder.with_max_cleartext_envelope(max)
		} else {
			builder
		};

		if let Some(max) = self.encrypted {
			builder.with_max_encrypted_envelope(max)
		} else {
			builder
		}
	}
}

impl<'a> EnvelopeBuilder<'a> {
	fn new(payload: EnvelopePayload) -> Self {
		Self {
			payload,
			encryptor: None,
			max_cleartext_envelope: None,
			max_encrypted_envelope: None,
			wire_mode: WireMode::Cleartext,
		}
	}

	/// Create a builder configured for a request frame.
	pub fn request(message: Frame) -> Self {
		Self::new(EnvelopePayload::Request { message })
	}

	/// Create a builder configured for a response package.
	pub fn response(package: ResponsePackage) -> Self {
		Self::new(EnvelopePayload::Response { package })
	}

	/// Create a builder around an existing transport envelope.
	pub fn transport(envelope: TransportEnvelope) -> Self {
		Self::new(EnvelopePayload::Transport { envelope })
	}

	pub fn with_encryptor(mut self, encryptor: &'a RuntimeAead) -> Self {
		self.encryptor = Some(encryptor);
		self
	}

	pub fn with_max_cleartext_envelope(mut self, max: usize) -> Self {
		self.max_cleartext_envelope = Some(max);
		self
	}

	pub fn with_max_encrypted_envelope(mut self, max: usize) -> Self {
		self.max_encrypted_envelope = Some(max);
		self
	}

	pub fn with_wire_mode(mut self, mode: WireMode) -> Self {
		self.wire_mode = mode;
		self
	}

	/// Finalize the builder, returning a `WireEnvelope`.
	pub fn finish(self) -> TransportResult<WireEnvelope> {
		let EnvelopeBuilder { payload, encryptor, max_cleartext_envelope, max_encrypted_envelope, wire_mode } = self;

		let envelope = payload.materialize();
		match wire_mode {
			WireMode::Cleartext => Self::build_cleartext(envelope, max_cleartext_envelope),
			WireMode::Encrypted => Self::build_encrypted(envelope, max_encrypted_envelope, encryptor),
		}
	}

	fn build_cleartext(envelope: TransportEnvelope, max_cleartext: Option<usize>) -> TransportResult<WireEnvelope> {
		let request_frame = match &envelope {
			TransportEnvelope::Request(pkg) => Some(pkg.message.clone()),
			_ => None,
		};

		let request_frame_owned = request_frame.map(unwrap_arc_frame);
		let encoded = envelope
			.to_der()
			.map_err(|err| Self::map_der_error(request_frame_owned.as_ref(), err))?;

		if let Some(max) = max_cleartext {
			if encoded.len() > max {
				return Err(TransportFailure::SizeExceeded.with_optional_frame(request_frame_owned));
			}
		}

		Ok(WireEnvelope::Cleartext(envelope))
	}

	fn build_encrypted(
		envelope: TransportEnvelope,
		max_encrypted: Option<usize>,
		encryptor: Option<&'a RuntimeAead>,
	) -> TransportResult<WireEnvelope> {
		let request_frame = match &envelope {
			TransportEnvelope::Request(pkg) => Some(pkg.message.clone()),
			_ => None,
		};

		let request_frame_owned = request_frame.map(unwrap_arc_frame);
		let encoded = envelope
			.to_der()
			.map_err(|err| Self::map_der_error(request_frame_owned.as_ref(), err))?;

		if let Some(max) = max_encrypted {
			if encoded.len() > max {
				return Err(TransportFailure::SizeExceeded.with_optional_frame(request_frame_owned));
			}
		}

		let nonce = match crate::random::generate_nonce::<12>(None) {
			Ok(n) => n,
			Err(_) => return Err(TransportFailure::NonceGenerationFailed.with_optional_frame(request_frame_owned)),
		};

		let encryptor = match encryptor {
			Some(e) => e,
			None => return Err(TransportFailure::EncryptorUnavailable.with_optional_frame(request_frame_owned)),
		};

		let encrypted = match encryptor.encrypt_content(&encoded, nonce, None) {
			Ok(e) => e,
			Err(_) => return Err(TransportFailure::EncryptionFailed.with_optional_frame(request_frame_owned)),
		};

		Ok(WireEnvelope::Encrypted(encrypted))
	}

	fn map_der_error(frame: Option<&Frame>, err: der::Error) -> TransportError {
		frame
			.map(|message| TransportFailure::EncodingFailed.with_frame(message.clone()))
			.unwrap_or_else(|| TransportError::from(err))
	}
}

impl<'a> TypeBuilder<WireEnvelope> for EnvelopeBuilder<'a> {
	type Error = TransportError;

	fn build(self) -> TransportResult<WireEnvelope> {
		self.finish()
	}
}

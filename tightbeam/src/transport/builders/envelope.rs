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

	fn encode_and_validate(
		envelope: &TransportEnvelope,
		max_size: Option<usize>,
	) -> TransportResult<(Vec<u8>, impl Fn(TransportFailure) -> TransportError + '_)> {
		let request_frame = match envelope {
			TransportEnvelope::Request(pkg) => Some(Arc::clone(&pkg.message)),
			_ => None,
		};

		let with_frame = move |failure: TransportFailure| -> TransportError {
			request_frame
				.clone() // Arc clone
				.map(|arc| {
					// Non-hot path clone
					let frame = Arc::try_unwrap(arc).unwrap_or_else(|a| (*a).clone());
					failure.with_frame(frame)
				})
				.unwrap_or_else(|| failure.into())
		};

		let encoded = envelope.to_der().map_err(|_| with_frame(TransportFailure::EncodingFailed))?;
		if let Some(max) = max_size {
			if encoded.len() > max {
				return Err(with_frame(TransportFailure::SizeExceeded));
			}
		}

		Ok((encoded, with_frame))
	}

	fn build_cleartext(envelope: TransportEnvelope, max_cleartext: Option<usize>) -> TransportResult<WireEnvelope> {
		let _ = Self::encode_and_validate(&envelope, max_cleartext)?;
		Ok(WireEnvelope::Cleartext(envelope))
	}

	fn build_encrypted(
		envelope: TransportEnvelope,
		max_encrypted: Option<usize>,
		encryptor: Option<&'a RuntimeAead>,
	) -> TransportResult<WireEnvelope> {
		let (encoded, with_frame) = Self::encode_and_validate(&envelope, max_encrypted)?;
		let nonce = crate::random::generate_nonce::<12>(None)
			.map_err(|_| with_frame(TransportFailure::NonceGenerationFailed))?;

		let encryptor = encryptor.ok_or_else(|| with_frame(TransportFailure::EncryptorUnavailable))?;
		let encrypted = encryptor
			.encrypt_content(&encoded, nonce, None)
			.map_err(|_| with_frame(TransportFailure::EncryptionFailed))?;

		Ok(WireEnvelope::Encrypted(encrypted))
	}
}

impl<'a> TypeBuilder<WireEnvelope> for EnvelopeBuilder<'a> {
	type Error = TransportError;

	fn build(self) -> TransportResult<WireEnvelope> {
		self.finish()
	}
}

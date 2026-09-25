//! The TightBeam frame and its metadata.
//!
//! [`Frame`] and [`Metadata`] keep their fields private to this module.
//! A frame enters through [`FrameBuilder`](crate::builder::frame::FrameBuilder)
//! or through the DER decoder, and both run the §5.6 version check. Every
//! in-place change runs through a method defined in this module or its
//! children, so no code outside them can give a frame a field its
//! version forbids.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::{CompressedData, DigestInfo, EncryptedContentInfo, MessagePriority, SignerInfo, Version};
use crate::der::{Tag, TagNumber};
use crate::matrix::MatrixDyn;
use crate::version::GatedField;
use crate::wire::wire_sequence;

#[cfg(feature = "builder")]
use crate::builder::error::{BuildError, MetadataError};
#[cfg(feature = "builder")]
use crate::builder::MetadataBuilder;

mod compress;

#[cfg(feature = "aead")]
mod aead;
#[cfg(feature = "digest")]
mod integrity;
#[cfg(any(feature = "digest", feature = "signature"))]
mod scaffold;
#[cfg(feature = "signature")]
mod signature;

#[cfg(feature = "digest")]
pub(crate) use scaffold::FrameIntegrityScaffold;

/// Metadata structure for message handling.
///
/// The frame version determines which fields are present.
///
/// ASN.1 Definition:
/// ```asn1
/// Metadata ::= SEQUENCE {
///     id               OCTET STRING,
///     order            INTEGER,
///     compactness      CompressedData OPTIONAL,
///     integrity        [0] DigestInfo OPTIONAL,
///     confidentiality  [1] EncryptedContentInfo OPTIONAL,
///     priority         [2] MessagePriority OPTIONAL,
///     lifetime         [3] INTEGER OPTIONAL,
///     previousFrame    [4] DigestInfo OPTIONAL,
///     matrix           [5] Matrix OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Metadata {
	id: Vec<u8>,
	order: u64,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	compactness: Option<CompressedData>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	integrity: Option<DigestInfo>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	confidentiality: Option<EncryptedContentInfo>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	priority: Option<MessagePriority>,
	lifetime: Option<u64>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	previous_frame: Option<DigestInfo>,
	matrix: Option<MatrixDyn>,
}

wire_sequence!(Metadata {
	id: octets,
	order: plain,
	compactness: plain,
	integrity: ctx(TagNumber::N0),
	confidentiality: ctx(TagNumber::N1),
	priority: ctx(TagNumber::N2),
	lifetime: ctx(TagNumber::N3),
	previous_frame: ctx(TagNumber::N4),
	matrix: ctx(TagNumber::N5),
});

impl Metadata {
	/// Metadata with an empty id, order zero, and no optional field, which
	/// every version carries.
	fn empty() -> Self {
		Self {
			id: Vec::new(),
			order: 0,
			compactness: None,
			integrity: None,
			confidentiality: None,
			priority: None,
			lifetime: None,
			previous_frame: None,
			matrix: None,
		}
	}

	/// The message identifier.
	///
	/// Receivers use it for idempotence and to correlate a response with its
	/// request.
	pub fn id(&self) -> &[u8] {
		&self.id
	}

	/// The protocol-opaque ordering value, such as a Unix timestamp or a
	/// per-channel counter.
	pub fn order(&self) -> u64 {
		self.order
	}

	/// The compression parameters when the message body is compressed.
	pub fn compactness(&self) -> Option<&CompressedData> {
		self.compactness.as_ref()
	}

	/// The Message Integrity (MI) commitment over the message body (V1+).
	///
	/// This digest is not Frame Integrity. It covers the message, and it still
	/// verifies after a decryption in place.
	pub fn integrity(&self) -> Option<&DigestInfo> {
		self.integrity.as_ref()
	}

	/// The encryption parameters when the message body is encrypted (V1+).
	///
	/// The ciphertext itself travels in [`Frame::message`].
	pub fn confidentiality(&self) -> Option<&EncryptedContentInfo> {
		self.confidentiality.as_ref()
	}

	/// The delivery priority (V2+).
	pub fn priority(&self) -> Option<MessagePriority> {
		self.priority
	}

	/// The time-to-live in seconds (V2+).
	pub fn lifetime(&self) -> Option<u64> {
		self.lifetime
	}

	/// The digest of the prior frame in a hash chain (V2+).
	///
	/// This digest links frames. It is neither Message Integrity nor Frame
	/// Integrity.
	pub fn previous_frame(&self) -> Option<&DigestInfo> {
		self.previous_frame.as_ref()
	}

	/// The routing matrix (V3+).
	pub fn matrix(&self) -> Option<&MatrixDyn> {
		self.matrix.as_ref()
	}

	/// The first field present here that `version` does not carry.
	fn forbidden_field(&self, version: Version) -> Option<GatedField> {
		let present = [
			(GatedField::MessageIntegrity, self.integrity.is_some()),
			(GatedField::Confidentiality, self.confidentiality.is_some()),
			(GatedField::Priority, self.priority.is_some()),
			(GatedField::Lifetime, self.lifetime.is_some()),
			(GatedField::PreviousFrame, self.previous_frame.is_some()),
			(GatedField::Matrix, self.matrix.is_some()),
		];

		first_forbidden(version, present)
	}
}

#[cfg(feature = "builder")]
impl TryFrom<MetadataBuilder> for Metadata {
	type Error = BuildError;

	/// Assemble the metadata a builder describes.
	///
	/// # Errors
	///
	/// - [`MetadataError::MissingId`] or [`MetadataError::MissingOrder`] when a required field is
	///   unset.
	/// - [`MetadataError::UnsupportedField`] when a set field is gated above the builder's version.
	fn try_from(builder: MetadataBuilder) -> Result<Self, Self::Error> {
		let MetadataBuilder {
			version,
			id,
			order,
			integrity,
			compactness,
			confidentiality,
			priority,
			lifetime,
			previous_frame,
			matrix,
		} = builder;

		let id = id.ok_or(BuildError::InvalidMetadata(MetadataError::MissingId))?;
		let order = order.ok_or(BuildError::InvalidMetadata(MetadataError::MissingOrder))?;
		let metadata = Self {
			id,
			order,
			compactness,
			integrity,
			confidentiality,
			priority,
			lifetime,
			previous_frame,
			matrix,
		};

		if let Some(field) = metadata.forbidden_field(version) {
			return Err(BuildError::InvalidMetadata(MetadataError::UnsupportedField { field, version }));
		}

		Ok(metadata)
	}
}

/// Core TightBeam message structure.
///
/// The version field determines which metadata fields the frame may carry.
/// The signature covers the version, the metadata, the message, and the
/// frame integrity.
///
/// ASN.1 Definition:
/// ```asn1
/// Frame ::= SEQUENCE {
///     version        Version,
///     metadata       Metadata,
///     message        OCTET STRING,
///     integrity      [0] DigestInfo OPTIONAL,
///     nonrepudiation [1] SignerInfo OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Frame {
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	version: Version,
	metadata: Metadata,
	message: Vec<u8>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	integrity: Option<DigestInfo>,
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	nonrepudiation: Option<SignerInfo>,
}

wire_sequence!(Frame {
	version: plain,
	metadata: plain,
	message: octets,
	integrity: ctx(TagNumber::N0),
	nonrepudiation: ctx(TagNumber::N1),
} where Frame::refuse_forbidden);

/// The transform a frame body still needs before a decode.
///
/// Read through [`Frame::body_transform`]. Each caller maps this to its
/// own policy: the router refuses, a servlet applies the transform.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BodyTransform {
	/// Encrypted. Decrypting also inflates a body that was compressed
	/// before encryption.
	Decrypt,
	/// Compressed only.
	Inflate,
}

impl Frame {
	/// Assemble a frame from parts the builder produced.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError::UnsupportedVersion`] when a part carries a field that `version` forbids.
	#[cfg(feature = "builder")]
	pub(crate) fn assemble(
		version: Version,
		metadata: Metadata,
		message: impl Into<Vec<u8>>,
		integrity: Option<DigestInfo>,
	) -> crate::error::Result<Self> {
		let message = message.into();
		let frame = Self { version, metadata, message, integrity, nonrepudiation: None };
		frame.refuse(frame.forbidden_field())?;

		Ok(frame)
	}

	/// A V0 hop-local frame that carries already-encoded bytes.
	///
	/// A V0 frame with no optional field is valid under every §5.6 rule, so
	/// this constructor cannot fail.
	#[cfg(feature = "colony")]
	pub(crate) fn v0(id: impl AsRef<[u8]>, message: impl Into<Vec<u8>>) -> Self {
		let mut metadata = Metadata::empty();
		metadata.id = id.as_ref().to_vec();

		let message = message.into();
		Self { version: Version::V0, metadata, message, integrity: None, nonrepudiation: None }
	}

	/// The protocol version, which gates the optional fields this frame
	/// carries.
	pub fn version(&self) -> Version {
		self.version
	}

	/// The frame metadata.
	pub fn metadata(&self) -> &Metadata {
		&self.metadata
	}

	/// The message body bytes.
	///
	/// These bytes are ciphertext while [`Metadata::confidentiality`] is set,
	/// and compressed while [`Metadata::compactness`] is set.
	pub fn message(&self) -> &[u8] {
		&self.message
	}

	/// Take the message body and drop the rest of the frame.
	pub fn into_message(mut self) -> Vec<u8> {
		core::mem::take(&mut self.message)
	}

	/// The Frame Integrity (FI) digest over the version and the metadata (V1+).
	///
	/// FI does not cover the message body. Verify FI before a decryption in
	/// place, because decryption rewrites the metadata.
	pub fn integrity(&self) -> Option<&DigestInfo> {
		self.integrity.as_ref()
	}

	/// The signature over the to-be-signed encoding of this frame (V1+).
	pub fn nonrepudiation(&self) -> Option<&SignerInfo> {
		self.nonrepudiation.as_ref()
	}

	/// The transform this body still needs before a decode.
	///
	/// [`None`] means the body is already decodable. Confidentiality is
	/// reported first: an encrypted body may also be compressed, and the
	/// inflate follows the decrypt rather than replacing it.
	#[must_use]
	pub fn body_transform(&self) -> Option<BodyTransform> {
		if self.metadata.confidentiality.is_some() {
			return Some(BodyTransform::Decrypt);
		}
		if self.metadata.compactness.is_some() {
			return Some(BodyTransform::Inflate);
		}

		None
	}

	/// DER encoding of the `SignerIdentifier` this frame claims.
	///
	/// Per-signer budgets, replay slots, refusal journals, and gossip
	/// attribution all key on the signer, so they key on these bytes and
	/// agree on what one signer is. [`None`] where the frame carries no
	/// signature or the identifier does not encode.
	#[must_use]
	pub fn signer_id(&self) -> Option<Vec<u8>> {
		let signer_info = self.nonrepudiation.as_ref()?;
		crate::der::Encode::to_der(&signer_info.sid).ok()
	}

	/// The first field this frame carries that its version forbids.
	fn forbidden_field(&self) -> Option<GatedField> {
		let present = [
			(GatedField::FrameIntegrity, self.integrity.is_some()),
			(GatedField::Nonrepudiation, self.nonrepudiation.is_some()),
		];

		self.metadata
			.forbidden_field(self.version)
			.or_else(|| first_forbidden(self.version, present))
	}

	/// Refuse to add `field` when this frame's version does not carry it.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError::UnsupportedVersion`] naming the frame
	///   version and the version that introduced the field.
	#[cfg(any(feature = "aead", feature = "signature"))]
	fn ensure_allows(&self, field: GatedField) -> crate::error::Result<()> {
		let forbidden = (!self.version.allows(field)).then_some(field);
		self.refuse(forbidden)
	}

	/// Refuse `forbidden` when it names a field this frame's version does not
	/// carry.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError::UnsupportedVersion`] naming the frame
	///   version and the version that introduced the field.
	#[cfg(any(feature = "builder", feature = "aead", feature = "signature"))]
	fn refuse(&self, forbidden: Option<GatedField>) -> crate::error::Result<()> {
		let Some(field) = forbidden else {
			return Ok(());
		};

		let versions = crate::error::ReceivedExpectedError::from((self.version, field.since()));
		Err(crate::TightBeamError::UnsupportedVersion(versions))
	}

	/// The decoder check that rejects a frame carrying a forbidden field, as
	/// §5.6 requires.
	fn refuse_forbidden(&self) -> crate::der::Result<()> {
		match self.forbidden_field() {
			Some(_) => Err(Tag::Sequence.value_error()),
			None => Ok(()),
		}
	}
}

impl From<Frame> for Metadata {
	fn from(mut frame: Frame) -> Self {
		core::mem::replace(&mut frame.metadata, Metadata::empty())
	}
}

crate::impl_from!(Frame, tb => Version: tb.version);

/// The first field that is present and that `version` does not carry.
fn first_forbidden<const N: usize>(version: Version, present: [(GatedField, bool); N]) -> Option<GatedField> {
	present
		.into_iter()
		.find(|&(field, is_present)| is_present && !version.allows(field))
		.map(|(field, _)| field)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::{Decode, Encode};
	use crate::testing::{TestDigest, TestSigner};

	/// A frame at `version` that carries `field`, built without the
	/// constructor's check.
	fn carrying(version: Version, field: GatedField) -> Frame {
		let mut frame = Frame {
			version,
			metadata: Metadata::empty(),
			message: Vec::new(),
			integrity: None,
			nonrepudiation: None,
		};

		match field {
			GatedField::MessageIntegrity => frame.metadata.integrity = Some(TestDigest::info()),
			GatedField::Confidentiality => frame.metadata.confidentiality = Some(sealed_content()),
			GatedField::FrameIntegrity => frame.integrity = Some(TestDigest::info()),
			GatedField::Nonrepudiation => frame.nonrepudiation = Some(TestSigner::info()),
			GatedField::Priority => frame.metadata.priority = Some(MessagePriority::Standard),
			GatedField::Lifetime => frame.metadata.lifetime = Some(60),
			GatedField::PreviousFrame => frame.metadata.previous_frame = Some(TestDigest::info()),
			GatedField::Matrix => frame.metadata.matrix = Some(MatrixDyn::default()),
		}

		frame
	}

	fn sealed_content() -> EncryptedContentInfo {
		let content_enc_alg = crate::spki::AlgorithmIdentifierOwned { oid: crate::oids::DATA, parameters: None };
		EncryptedContentInfo { content_type: crate::oids::DATA, content_enc_alg, encrypted_content: None }
	}

	macro_rules! gate_tests {
		($($name:ident: $field:expr, forbidden at $forbidding:expr,)*) => {
			$(
				mod $name {
					use super::*;

					#[test]
					fn the_decoder_refuses_it_below_its_version() -> crate::error::Result<()> {
						let encoded = carrying($forbidding, $field).to_der()?;
						assert!(Frame::from_der(&encoded).is_err());
						Ok(())
					}

					#[test]
					fn the_decoder_accepts_it_at_its_version() -> crate::error::Result<()> {
						let frame = carrying($field.since(), $field);
						let decoded = Frame::from_der(&frame.to_der()?)?;
						assert_eq!(decoded, frame);
						Ok(())
					}
				}
			)*
		};
	}

	gate_tests! {
		message_integrity: GatedField::MessageIntegrity, forbidden at Version::V0,
		confidentiality: GatedField::Confidentiality, forbidden at Version::V0,
		frame_integrity: GatedField::FrameIntegrity, forbidden at Version::V0,
		nonrepudiation: GatedField::Nonrepudiation, forbidden at Version::V0,
		priority: GatedField::Priority, forbidden at Version::V1,
		lifetime: GatedField::Lifetime, forbidden at Version::V1,
		previous_frame: GatedField::PreviousFrame, forbidden at Version::V1,
		matrix: GatedField::Matrix, forbidden at Version::V2,
	}

	#[cfg(feature = "builder")]
	#[test]
	fn assembly_refuses_a_field_below_its_version() {
		let integrity = Some(TestDigest::info());
		let result = Frame::assemble(Version::V0, Metadata::empty(), Vec::new(), integrity);
		assert!(matches!(
			result,
			Err(crate::TightBeamError::UnsupportedVersion(ref versions))
				if versions.received == Version::V0 && versions.expected == Version::V1
		));
	}
}

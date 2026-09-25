use crate::asn1::Version;
#[cfg(feature = "signature")]
use crate::der::asn1::{ContextSpecificRef, OctetStringRef};
use crate::der::{Encode, EncodeValue, FixedTag, Length, Tag, Writer};
#[cfg(feature = "signature")]
use crate::der::{TagMode, TagNumber};
#[cfg(feature = "signature")]
use crate::DigestInfo;
use crate::Metadata;

/// The envelope view, the version and the metadata, that Frame Integrity
/// (FI) covers.
///
/// This view has no message field, so FI cannot cover the message.
/// It borrows the frame fields, so the builder and the verifier hash one
/// zero-copy encoding and the digest preimage cannot drift.
#[cfg(feature = "digest")]
pub(crate) struct FrameIntegrityScaffold<'a> {
	pub(crate) version: &'a Version,
	pub(crate) metadata: &'a Metadata,
}

#[cfg(feature = "digest")]
impl FixedTag for FrameIntegrityScaffold<'_> {
	const TAG: Tag = Tag::Sequence;
}

#[cfg(feature = "digest")]
impl EncodeValue for FrameIntegrityScaffold<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.version.encoded_len()? + self.metadata.encoded_len()?
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.version.encode(encoder)?;
		self.metadata.encode(encoder)?;
		Ok(())
	}
}

/// The to-be-signed view of a [`Frame`](crate::Frame), which holds its
/// first four fields.
///
/// This view has no `nonrepudiation` field, so a signature cannot cover
/// itself. It borrows the frame and reuses each field's encoder, so the TBS
/// bytes cannot drift from the DER encoding that `wire_sequence!` produces
/// for a frame. The message field MUST encode as an `OCTET STRING` to match
/// the frame's wire form.
#[cfg(feature = "signature")]
pub(crate) struct TbsScaffold<'a> {
	pub(crate) version: &'a Version,
	pub(crate) metadata: &'a Metadata,
	pub(crate) message: &'a [u8],
	pub(crate) integrity: Option<&'a DigestInfo>,
}

#[cfg(feature = "signature")]
impl<'a> TbsScaffold<'a> {
	/// Wrap the frame integrity in its EXPLICIT `[0]` tag.
	fn tagged_integrity(integrity: &'a DigestInfo) -> ContextSpecificRef<'a, DigestInfo> {
		ContextSpecificRef { tag_number: TagNumber::N0, tag_mode: TagMode::Explicit, value: integrity }
	}
}

#[cfg(feature = "signature")]
impl FixedTag for TbsScaffold<'_> {
	const TAG: Tag = Tag::Sequence;
}

#[cfg(feature = "signature")]
impl EncodeValue for TbsScaffold<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		let mut len = (self.version.encoded_len()? + self.metadata.encoded_len()?)?;
		len = (len + OctetStringRef::new(self.message)?.encoded_len()?)?;

		if let Some(integrity) = self.integrity {
			len = (len + Self::tagged_integrity(integrity).encoded_len()?)?;
		}

		Ok(len)
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		self.version.encode(encoder)?;
		self.metadata.encode(encoder)?;
		OctetStringRef::new(self.message)?.encode(encoder)?;

		if let Some(integrity) = self.integrity {
			Self::tagged_integrity(integrity).encode(encoder)?;
		}

		Ok(())
	}
}

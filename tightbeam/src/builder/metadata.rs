#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::{AuthEnvelopedData, WireDer};
use crate::builder::error::BuildError;
use crate::matrix::MatrixDyn;
use crate::{CompressedData, DigestInfo, MessagePriority, Metadata, Version};

/// A fluent builder for TightBeam metadata.
pub struct MetadataBuilder {
	pub(crate) version: Version,
	pub(crate) id: Option<Vec<u8>>,
	pub(crate) order: Option<u64>,
	pub(crate) integrity: Option<DigestInfo>,
	pub(crate) compactness: Option<CompressedData>,
	pub(crate) confidentiality: Option<WireDer<AuthEnvelopedData>>,
	pub(crate) priority: Option<MessagePriority>,
	pub(crate) lifetime: Option<u64>,
	pub(crate) previous_frame: Option<DigestInfo>,
	pub(crate) matrix: Option<MatrixDyn>,
}

impl From<Version> for MetadataBuilder {
	fn from(version: Version) -> Self {
		Self {
			version,
			id: None,
			order: None,
			integrity: None,
			compactness: None,
			confidentiality: None,
			priority: None,
			lifetime: None,
			previous_frame: None,
			matrix: None,
		}
	}
}

impl MetadataBuilder {
	/// Sets the message ID from bytes, so a caller can make a send idempotent.
	pub fn with_id(mut self, id: impl AsRef<[u8]>) -> Self {
		self.id = Some(id.as_ref().to_vec());
		self
	}

	/// Sets the order.
	///
	/// The value is protocol-opaque: any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When the caller sets no
	/// order, the frame build defaults it to the current Unix time in seconds.
	pub fn with_order(mut self, order: u64) -> Self {
		self.order = Some(order);
		self
	}

	/// Sets the integrity information.
	pub fn with_integrity_info(mut self, hash: DigestInfo) -> Self {
		self.integrity = Some(hash);
		self
	}

	/// Sets the compression information.
	pub fn with_compactness_info(mut self, compression: CompressedData) -> Self {
		self.compactness = Some(compression);
		self
	}

	/// Sets the envelope of the encrypted body, its ciphertext detached into
	/// the message, beside the DER it encodes as.
	pub fn with_confidentiality_info(mut self, encryption: WireDer<AuthEnvelopedData>) -> Self {
		self.confidentiality = Some(encryption);
		self
	}

	/// Sets the message priority, which a V2 or later frame permits.
	pub fn with_priority(mut self, priority: MessagePriority) -> Self {
		self.priority = Some(priority);
		self
	}

	/// Sets the time-to-live in seconds, which a V2 or later frame permits.
	pub fn with_lifetime(mut self, seconds: u64) -> Self {
		self.lifetime = Some(seconds);
		self
	}

	/// Sets the previous hash reference, which a V2 or later frame permits.
	pub fn previous_frame(mut self, previous: DigestInfo) -> Self {
		self.previous_frame = Some(previous);
		self
	}

	/// Sets the routing matrix, which a V3 or later frame permits.
	pub fn with_matrix(mut self, matrix: MatrixDyn) -> Self {
		self.matrix = Some(matrix);
		self
	}

	/// Builds the metadata for the protocol version of the builder.
	///
	/// # Errors
	/// - [`BuildError::InvalidMetadata`] -- the builder has no id or no order,
	///   or a set field is gated above the builder's version.
	pub fn build(self) -> Result<Metadata, BuildError> {
		Metadata::try_from(self)
	}

	/// Returns whether the ID is set.
	pub fn has_id(&self) -> bool {
		self.id.is_some()
	}

	/// Returns whether the priority is set.
	pub fn has_priority(&self) -> bool {
		self.priority.is_some()
	}

	/// Returns whether the order is set.
	pub fn has_order(&self) -> bool {
		self.order.is_some()
	}

	/// Returns whether the lifetime is set.
	pub fn has_lifetime(&self) -> bool {
		self.lifetime.is_some()
	}

	/// Returns whether the previous hash is set.
	pub fn has_previous(&self) -> bool {
		self.previous_frame.is_some()
	}

	/// Returns whether the matrix is set.
	pub fn has_matrix(&self) -> bool {
		self.matrix.is_some()
	}

	/// Returns whether the compression information is set.
	pub fn has_compression(&self) -> bool {
		self.compactness.is_some()
	}

	/// Returns whether the integrity information is set.
	pub fn has_integrity(&self) -> bool {
		self.integrity.is_some()
	}
}

#[cfg(test)]
mod tests {
	use crate::asn1::GatedField;
	use crate::builder::error::MetadataError;
	use crate::testing::{TestDigest, TestFrame, TestResult};

	use super::*;

	/// The optional fields a metadata build carries: its integrity, priority,
	/// lifetime, previous frame, and matrix.
	type Carried = (
		Option<DigestInfo>,
		Option<MessagePriority>,
		Option<u64>,
		Option<DigestInfo>,
		Option<MatrixDyn>,
	);

	/// A 2x2 zero matrix, the fixture of the builder chains.
	fn fixture_matrix() -> MatrixDyn {
		MatrixDyn::try_from(2u8).expect("2 is a valid matrix dimension")
	}

	/// Returns a builder of `version` that holds the id `test-id` and the
	/// order [`TestFrame::ORDER`].
	fn ordered(version: Version) -> MetadataBuilder {
		MetadataBuilder::from(version).with_id("test-id").with_order(TestFrame::ORDER)
	}

	/// Returns the optional fields that `metadata` carries.
	fn carried(metadata: &Metadata) -> Carried {
		let integrity = metadata.integrity().cloned();
		let previous_frame = metadata.previous_frame().cloned();
		let matrix = metadata.matrix().cloned();
		(integrity, metadata.priority(), metadata.lifetime(), previous_frame, matrix)
	}

	// One structure serves every version, as in X.509. Each case is a builder
	// of one version with fields that the version admits, beside the fields
	// its build carries. V0 admits no integrity, so its case sets none.
	crate::tb_cases! {
		fn a_metadata_build_carries_the_fields_its_version_admits((builder, expected): (MetadataBuilder, Carried))
			-> TestResult
		{
			let metadata = builder.build()?;
			assert_eq!(carried(&metadata), expected);
			Ok(())
		}
		cases {
			v0 => (ordered(Version::V0), (None, None, None, None, None)),
			v1 => (
				ordered(Version::V1).with_integrity_info(TestDigest::info()),
				(Some(TestDigest::info()), None, None, None, None),
			),
			v2 => (
				ordered(Version::V2)
					.with_integrity_info(TestDigest::info())
					.with_priority(MessagePriority::LowLatency)
					.with_lifetime(3600),
				(Some(TestDigest::info()), Some(MessagePriority::LowLatency), Some(3600), None, None),
			),
			v3 => (
				ordered(Version::V3)
					.with_integrity_info(TestDigest::info())
					.with_priority(MessagePriority::LowLatency)
					.with_lifetime(3600)
					.with_matrix(fixture_matrix()),
				(Some(TestDigest::info()), Some(MessagePriority::LowLatency), Some(3600), None, Some(fixture_matrix())),
			),
		}
	}

	// Each case is a builder short of a required field or holding a field
	// that its version forbids, beside the metadata error of its build.
	crate::tb_cases! {
		fn an_incomplete_or_gated_metadata_build_is_refused((builder, expected): (MetadataBuilder, MetadataError)) {
			let result = builder.build();

			assert!(matches!(result, Err(BuildError::InvalidMetadata(ref err)) if *err == expected));
		}
		cases {
			v0_missing_id => (
				MetadataBuilder::from(Version::V0).with_order(TestFrame::ORDER),
				MetadataError::MissingId,
			),
			v0_missing_order => (
				MetadataBuilder::from(Version::V0).with_id("test-id"),
				MetadataError::MissingOrder,
			),
			v1_missing_id => (
				MetadataBuilder::from(Version::V1).with_order(TestFrame::ORDER),
				MetadataError::MissingId,
			),
			v1_missing_order => (
				MetadataBuilder::from(Version::V1).with_id("test-id"),
				MetadataError::MissingOrder,
			),
			v2_missing_id => (
				MetadataBuilder::from(Version::V2).with_order(TestFrame::ORDER),
				MetadataError::MissingId,
			),
			v2_missing_order => (
				MetadataBuilder::from(Version::V2).with_id("test-id"),
				MetadataError::MissingOrder,
			),
			v0_rejects_integrity => (
				ordered(Version::V0).with_integrity_info(TestDigest::info()),
				MetadataError::UnsupportedField { field: GatedField::MessageIntegrity, version: Version::V0 },
			),
			v0_rejects_priority => (
				ordered(Version::V0).with_priority(MessagePriority::LowLatency),
				MetadataError::UnsupportedField { field: GatedField::Priority, version: Version::V0 },
			),
			v1_rejects_lifetime => (
				ordered(Version::V1).with_lifetime(3600),
				MetadataError::UnsupportedField { field: GatedField::Lifetime, version: Version::V1 },
			),
			v0_rejects_previous_frame => (
				ordered(Version::V0).previous_frame(TestDigest::info()),
				MetadataError::UnsupportedField { field: GatedField::PreviousFrame, version: Version::V0 },
			),
			v2_rejects_matrix => (
				ordered(Version::V2).with_matrix(MatrixDyn::default()),
				MetadataError::UnsupportedField { field: GatedField::Matrix, version: Version::V2 },
			),
		}
	}
}

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
	use super::*;
	use crate::asn1::GatedField;
	use crate::builder::error::MetadataError;
	use crate::testing::TestDigest;

	/// A 2x2 zero matrix, the fixture of the builder chains.
	fn fixture_matrix() -> MatrixDyn {
		MatrixDyn::try_from(2u8).expect("2 is a valid matrix dimension")
	}

	macro_rules! test_metadata_builder {
		($test_name:ident, $version:expr, $builder:expr) => {
			#[test]
			fn $test_name() {
				let metadata = $builder
					.build()
					.expect(concat!("Failed to build ", stringify!($version), " metadata"));

				// One structure serves every version, as in X.509, so the
				// assertions branch on the version.
				match $version {
					Version::V0 => {
						assert!(metadata.priority().is_none());
						assert!(metadata.lifetime().is_none());
						assert!(metadata.previous_frame().is_none());
						assert!(metadata.matrix().is_none());
					}
					Version::V1 => {
						assert!(metadata.priority().is_none());
						assert!(metadata.lifetime().is_none());
						assert!(metadata.previous_frame().is_none());
						assert!(metadata.matrix().is_none());
					}
					Version::V2 => {
						assert!(metadata.priority().is_some());
						assert!(metadata.matrix().is_none());
					}
					Version::V3 => {
						assert!(metadata.priority().is_some());
						assert!(metadata.matrix().is_some());
					}
				}
			}
		};
	}

	// V0 permits no integrity info. The rejection tests below cover a V0
	// builder that sets one.
	test_metadata_builder!(
		test_metadata_builder_v0,
		Version::V0,
		MetadataBuilder::from(Version::V0)
			.with_id("test-id-v0")
			.with_order(1696521600u64)
	);

	test_metadata_builder!(
		test_metadata_builder_v1,
		Version::V1,
		MetadataBuilder::from(Version::V1)
			.with_id("test-id-v1")
			.with_order(1696521600u64)
			.with_integrity_info(TestDigest::info())
	);

	test_metadata_builder!(
		test_metadata_builder_v2,
		Version::V2,
		MetadataBuilder::from(Version::V2)
			.with_id("test-id-v2")
			.with_order(1696521600u64)
			.with_integrity_info(TestDigest::info())
			.with_priority(MessagePriority::LowLatency)
			.with_lifetime(3600)
	);

	test_metadata_builder!(
		test_metadata_builder_v3,
		Version::V3,
		MetadataBuilder::from(Version::V3)
			.with_id("test-id-v3")
			.with_order(1696521600u64)
			.with_integrity_info(TestDigest::info())
			.with_priority(MessagePriority::LowLatency)
			.with_lifetime(3600)
			.with_matrix(fixture_matrix())
	);

	#[test]
	fn test_metadata_builder_missing_required_fields() {
		let result = MetadataBuilder::from(Version::V0).with_id("test-id").build();
		assert!(matches!(result, Err(BuildError::InvalidMetadata(MetadataError::MissingOrder))));
	}

	mod errors {
		use super::*;

		/// The builder of one case, and the error that its build returns.
		type ErrorCase = (MetadataBuilder, MetadataError);

		crate::tb_cases! {
			fn test_metadata_validation_errors((builder, expected): ErrorCase) {
				let result = builder.build();
				assert!(matches!(result, Err(BuildError::InvalidMetadata(ref err)) if *err == expected));
			}
			cases {
				v0_missing_id => (MetadataBuilder::from(Version::V0).with_order(1696521600), MetadataError::MissingId),
				v0_missing_order => (
					MetadataBuilder::from(Version::V0).with_id("test-id"),
					MetadataError::MissingOrder,
				),
				v1_missing_id => (MetadataBuilder::from(Version::V1).with_order(1696521600), MetadataError::MissingId),
				v1_missing_order => (
					MetadataBuilder::from(Version::V1).with_id("test-id"),
					MetadataError::MissingOrder,
				),
				v2_missing_id => (MetadataBuilder::from(Version::V2).with_order(1696521600), MetadataError::MissingId),
				v2_missing_order => (
					MetadataBuilder::from(Version::V2).with_id("test-id"),
					MetadataError::MissingOrder,
				),
				v0_rejects_integrity => (
					MetadataBuilder::from(Version::V0)
						.with_id("test-id")
						.with_order(1696521600)
						.with_integrity_info(TestDigest::info()),
					MetadataError::UnsupportedField { field: GatedField::MessageIntegrity, version: Version::V0 },
				),
				v0_rejects_priority => (
					MetadataBuilder::from(Version::V0)
						.with_id("test-id")
						.with_order(1696521600)
						.with_priority(MessagePriority::LowLatency),
					MetadataError::UnsupportedField { field: GatedField::Priority, version: Version::V0 },
				),
				v1_rejects_lifetime => (
					MetadataBuilder::from(Version::V1).with_id("test-id").with_order(1696521600).with_lifetime(3600),
					MetadataError::UnsupportedField { field: GatedField::Lifetime, version: Version::V1 },
				),
				v0_rejects_previous_frame => (
					MetadataBuilder::from(Version::V0)
						.with_id("test-id")
						.with_order(1696521600)
						.previous_frame(TestDigest::info()),
					MetadataError::UnsupportedField { field: GatedField::PreviousFrame, version: Version::V0 },
				),
				v2_rejects_matrix => (
					MetadataBuilder::from(Version::V2)
						.with_id("test-id")
						.with_order(1696521600)
						.with_matrix(MatrixDyn::default()),
					MetadataError::UnsupportedField { field: GatedField::Matrix, version: Version::V2 },
				),
			}
		}
	}
}

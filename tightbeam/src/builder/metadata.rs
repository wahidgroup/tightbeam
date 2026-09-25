#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::builder::error::BuildError;
use crate::cms::enveloped_data::EncryptedContentInfo;
use crate::matrix::MatrixDyn;
use crate::{CompressedData, DigestInfo, MessagePriority, Metadata, Version};

/// A fluent builder for TightBeam metadata.
pub struct MetadataBuilder {
	pub(crate) version: Version,
	pub(crate) id: Option<Vec<u8>>,
	pub(crate) order: Option<u64>,
	pub(crate) integrity: Option<DigestInfo>,
	pub(crate) compactness: Option<CompressedData>,
	pub(crate) confidentiality: Option<EncryptedContentInfo>,
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
	/// Set the message ID from bytes.
	/// This is useful for idempotence.
	pub fn with_id(mut self, id: impl AsRef<[u8]>) -> Self {
		self.id = Some(id.as_ref().to_vec());
		self
	}

	/// Set the order.
	///
	/// The value is protocol-opaque: any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted, the
	/// frame build defaults it to the current Unix time in seconds.
	pub fn with_order(mut self, order: u64) -> Self {
		self.order = Some(order);
		self
	}

	/// Set the integrity information
	pub fn with_integrity_info(mut self, hash: DigestInfo) -> Self {
		self.integrity = Some(hash);
		self
	}

	/// Set the compression information
	pub fn with_compactness_info(mut self, compression: CompressedData) -> Self {
		self.compactness = Some(compression);
		self
	}

	/// Set the encryption information
	pub fn with_confidentiality_info(mut self, encryption: EncryptedContentInfo) -> Self {
		self.confidentiality = Some(encryption);
		self
	}

	/// Set the message priority (V2+ only)
	pub fn with_priority(mut self, priority: MessagePriority) -> Self {
		self.priority = Some(priority);
		self
	}

	/// Set the time-to-live in seconds (V2+ only)
	pub fn with_lifetime(mut self, seconds: u64) -> Self {
		self.lifetime = Some(seconds);
		self
	}

	/// Set the previous hash reference (V2+ only)
	pub fn previous_frame(mut self, previous: DigestInfo) -> Self {
		self.previous_frame = Some(previous);
		self
	}

	/// Set the routing matrix (V3+ only)
	pub fn with_matrix(mut self, matrix: MatrixDyn) -> Self {
		self.matrix = Some(matrix);
		self
	}

	/// Build the metadata based on the protocol version
	///
	/// # Errors
	/// Returns an error if required fields are missing, or if a set field is
	/// not permitted by the specified version
	pub fn build(self) -> Result<Metadata, BuildError> {
		Metadata::try_from(self)
	}

	/// Check if ID is set
	pub fn has_id(&self) -> bool {
		self.id.is_some()
	}

	/// Check if priority is set
	pub fn has_priority(&self) -> bool {
		self.priority.is_some()
	}

	// Check if order is set
	pub fn has_order(&self) -> bool {
		self.order.is_some()
	}

	/// Check if lifetime is set
	pub fn has_lifetime(&self) -> bool {
		self.lifetime.is_some()
	}

	/// Check if previous hash is set
	pub fn has_previous(&self) -> bool {
		self.previous_frame.is_some()
	}

	/// Check if matrix is set
	pub fn has_matrix(&self) -> bool {
		self.matrix.is_some()
	}

	/// Check if compression is set
	pub fn has_compression(&self) -> bool {
		self.compactness.is_some()
	}

	/// Check if integrity info is set
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

	/// Fixture 2x2 zero matrix for builder chains.
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

				// X.509-style: single structure, validate based on version
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

	// V0 permits no integrity info; setting one is covered by the rejection
	// tests below.
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

		struct ErrorTestCase {
			name: &'static str,
			builder: fn() -> MetadataBuilder,
			expected_error: MetadataError,
		}

		#[test]
		fn test_metadata_validation_errors() {
			let test_cases = [
				ErrorTestCase {
					name: "V0 missing id",
					builder: || MetadataBuilder::from(Version::V0).with_order(1696521600),
					expected_error: MetadataError::MissingId,
				},
				ErrorTestCase {
					name: "V0 missing order",
					builder: || MetadataBuilder::from(Version::V0).with_id("test-id"),
					expected_error: MetadataError::MissingOrder,
				},
				ErrorTestCase {
					name: "V1 missing id",
					builder: || MetadataBuilder::from(Version::V1).with_order(1696521600),
					expected_error: MetadataError::MissingId,
				},
				ErrorTestCase {
					name: "V1 missing order",
					builder: || MetadataBuilder::from(Version::V1).with_id("test-id"),
					expected_error: MetadataError::MissingOrder,
				},
				ErrorTestCase {
					name: "V2 missing id",
					builder: || MetadataBuilder::from(Version::V2).with_order(1696521600),
					expected_error: MetadataError::MissingId,
				},
				ErrorTestCase {
					name: "V2 missing order",
					builder: || MetadataBuilder::from(Version::V2).with_id("test-id"),
					expected_error: MetadataError::MissingOrder,
				},
				ErrorTestCase {
					name: "V0 rejects integrity",
					builder: || {
						MetadataBuilder::from(Version::V0)
							.with_id("test-id")
							.with_order(1696521600)
							.with_integrity_info(TestDigest::info())
					},
					expected_error: MetadataError::UnsupportedField {
						field: GatedField::MessageIntegrity,
						version: Version::V0,
					},
				},
				ErrorTestCase {
					name: "V0 rejects priority",
					builder: || {
						MetadataBuilder::from(Version::V0)
							.with_id("test-id")
							.with_order(1696521600)
							.with_priority(MessagePriority::LowLatency)
					},
					expected_error: MetadataError::UnsupportedField {
						field: GatedField::Priority,
						version: Version::V0,
					},
				},
				ErrorTestCase {
					name: "V1 rejects lifetime",
					builder: || {
						MetadataBuilder::from(Version::V1)
							.with_id("test-id")
							.with_order(1696521600)
							.with_lifetime(3600)
					},
					expected_error: MetadataError::UnsupportedField {
						field: GatedField::Lifetime,
						version: Version::V1,
					},
				},
				ErrorTestCase {
					name: "V0 rejects previous_frame",
					builder: || {
						MetadataBuilder::from(Version::V0)
							.with_id("test-id")
							.with_order(1696521600)
							.previous_frame(TestDigest::info())
					},
					expected_error: MetadataError::UnsupportedField {
						field: GatedField::PreviousFrame,
						version: Version::V0,
					},
				},
				ErrorTestCase {
					name: "V2 rejects matrix",
					builder: || {
						MetadataBuilder::from(Version::V2)
							.with_id("test-id")
							.with_order(1696521600)
							.with_matrix(MatrixDyn::default())
					},
					expected_error: MetadataError::UnsupportedField { field: GatedField::Matrix, version: Version::V2 },
				},
			];

			for case in test_cases {
				let result = (case.builder)().build();
				assert!(
					matches!(result, Err(BuildError::InvalidMetadata(ref err)) if *err == case.expected_error),
					"{}",
					case.name
				);
			}
		}
	}
}

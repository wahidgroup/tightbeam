#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::builder::error::{BuildError, MetadataError};
use crate::der::asn1::Null;
use crate::matrix::MatrixDyn;
use crate::{
	Asn1Matrix, CompressionInfo, EncryptionInfo, IntegrityInfo, MessagePriority, Metadata, SignatureInfo, Version,
};

/// A fluent builder for TightBeam metadata.
pub struct MetadataBuilder {
	version: Version,
	id: Option<Vec<u8>>,
	order: Option<u64>,
	integrity: Option<IntegrityInfo>,
	confidentiality: Option<EncryptionInfo>,
	nonrepudiation: Option<SignatureInfo>,
	compactness: Option<CompressionInfo>,
	priority: Option<MessagePriority>,
	lifetime: Option<u64>,
	previous_frame: Option<IntegrityInfo>,
	matrix: Option<MatrixDyn>,
}

impl From<Version> for MetadataBuilder {
	fn from(version: Version) -> Self {
		Self {
			version,
			id: None,
			order: None,
			integrity: None,
			confidentiality: None,
			nonrepudiation: None,
			compactness: None,
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

	/// Set the order
	/// Commonly a Unix timestamp
	pub fn with_order(mut self, seconds: u64) -> Self {
		self.order = Some(seconds);
		self
	}

	/// Set the integrity information
	pub fn with_integrity_info(mut self, hash: IntegrityInfo) -> Self {
		self.integrity = Some(hash);
		self
	}

	/// Set the encryption information
	pub fn with_confidentiality_info(mut self, encryption: EncryptionInfo) -> Self {
		self.confidentiality = Some(encryption);
		self
	}

	/// Set the signature information
	pub fn with_nonrepudiation_info(mut self, signature: SignatureInfo) -> Self {
		self.nonrepudiation = Some(signature);
		self
	}

	/// Set the compression information
	pub fn with_compactness_info(mut self, compression: CompressionInfo) -> Self {
		self.compactness = Some(compression);
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
	pub fn previous_frame(mut self, previous: IntegrityInfo) -> Self {
		self.previous_frame = Some(previous);
		self
	}

	/// Set custom flags (V2+ only)
	pub fn with_matrix(mut self, matrix: MatrixDyn) -> Self {
		self.matrix = Some(matrix);
		self
	}

	/// Build the metadata based on the protocol version
	///
	/// # Errors
	/// Returns an error if required fields are missing for the specified
	/// version
	pub fn build(self) -> Result<Metadata, BuildError> {
		let id = self.id.ok_or(BuildError::InvalidMetadata(MetadataError::MissingId))?;
		let order = self.order.ok_or(BuildError::InvalidMetadata(MetadataError::MissingTimestamp))?;
		let compression = self.compactness.unwrap_or(CompressionInfo::NONE(Null));
		let matrix = if let Some(m) = self.matrix {
			Some(Asn1Matrix::try_from(m)?)
		} else {
			None
		};

		match self.version {
			Version::V0 => {
				// V0: Core fields only
				Ok(Metadata {
					id,
					order,
					compactness: compression,
					integrity: None,
					confidentiality: None,
					priority: None,
					lifetime: None,
					previous_frame: None,
					matrix: None,
				})
			}
			Version::V1 => {
				// V1: Core fields + encryption
				let encryption = self
					.confidentiality
					.ok_or(BuildError::InvalidMetadata(MetadataError::MissingEncryption))?;

				Ok(Metadata {
					id,
					order,
					compactness: compression,
					integrity: self.integrity,
					confidentiality: Some(encryption),
					priority: None,
					lifetime: None,
					previous_frame: None,
					matrix: None,
				})
			}
			Version::V2 => {
				// V2: All fields
				let encryption = self
					.confidentiality
					.ok_or(BuildError::InvalidMetadata(MetadataError::MissingEncryption))?;
				let hash = self.integrity.ok_or(BuildError::InvalidMetadata(MetadataError::MissingHash))?;
				let priority = self.priority.unwrap_or(MessagePriority::Normal);

				Ok(Metadata {
					id,
					order,
					compactness: compression,
					integrity: Some(hash),
					confidentiality: Some(encryption),
					priority: Some(priority),
					lifetime: self.lifetime,
					previous_frame: self.previous_frame,
					matrix,
				})
			}
		}
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

	/// Check if TTL is set
	pub fn has_ttl(&self) -> bool {
		self.lifetime.is_some()
	}

	/// Check if previous hash is set
	pub fn has_previous(&self) -> bool {
		self.previous_frame.is_some()
	}

	/// Check if flags are set
	pub fn has_flags(&self) -> bool {
		self.matrix.is_some()
	}

	/// Check if compression is set
	pub fn has_compression(&self) -> bool {
		self.compactness.is_some()
	}

	/// Check if encryption is set
	pub fn has_encryption(&self) -> bool {
		self.confidentiality.is_some()
	}

	/// Check if signature is set
	pub fn has_signature(&self) -> bool {
		self.nonrepudiation.is_some()
	}

	/// Check if hash is set
	pub fn has_hash(&self) -> bool {
		self.integrity.is_some()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::{create_test_encryption_info, create_test_hash_info, create_test_signature_info};

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
						assert!(metadata.confidentiality.is_none());
						assert!(metadata.priority.is_none());
						assert!(metadata.lifetime.is_none());
						assert!(metadata.previous_frame.is_none());
						assert!(metadata.matrix.is_none());
					}
					Version::V1 => {
						assert!(metadata.confidentiality.is_some());
						assert!(metadata.priority.is_none());
						assert!(metadata.lifetime.is_none());
						assert!(metadata.previous_frame.is_none());
						assert!(metadata.matrix.is_none());
					}
					Version::V2 => {
						assert!(metadata.confidentiality.is_some());
						assert!(metadata.priority.is_some());
					}
				}
			}
		};
	}

	test_metadata_builder!(
		test_metadata_builder_v0,
		Version::V0,
		MetadataBuilder::from(Version::V0)
			.with_id("test-id-v0")
			.with_order(1696521600u64)
			.with_integrity_info(create_test_hash_info())
	);

	test_metadata_builder!(
		test_metadata_builder_v1,
		Version::V1,
		MetadataBuilder::from(Version::V1)
			.with_id("test-id-v1")
			.with_order(1696521600u64)
			.with_integrity_info(create_test_hash_info())
			.with_confidentiality_info(create_test_encryption_info())
			.with_nonrepudiation_info(create_test_signature_info())
	);

	test_metadata_builder!(
		test_metadata_builder_v2,
		Version::V2,
		MetadataBuilder::from(Version::V2)
			.with_id("test-id-v2")
			.with_order(1696521600u64)
			.with_integrity_info(create_test_hash_info())
			.with_confidentiality_info(create_test_encryption_info())
			.with_nonrepudiation_info(create_test_signature_info())
			.with_priority(MessagePriority::High)
			.with_lifetime(3600)
	);

	#[test]
	fn test_metadata_builder_missing_required_fields() {
		let result = MetadataBuilder::from(Version::V0).with_id("test-id").build();

		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			BuildError::InvalidMetadata(MetadataError::MissingTimestamp)
		));
	}

	#[test]
	fn test_metadata_builder_v1_missing_encryption() {
		let result = MetadataBuilder::from(Version::V1)
			.with_id("test-id")
			.with_order(1696521600u64)
			.with_integrity_info(create_test_hash_info())
			.with_nonrepudiation_info(create_test_signature_info())
			.build();

		assert!(result.is_err());
		assert!(matches!(
			result.unwrap_err(),
			BuildError::InvalidMetadata(MetadataError::MissingEncryption)
		));
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
					expected_error: MetadataError::MissingTimestamp,
				},
				ErrorTestCase {
					name: "V1 missing id",
					builder: || {
						MetadataBuilder::from(Version::V1)
							.with_order(1696521600)
							.with_confidentiality_info(create_test_encryption_info())
					},
					expected_error: MetadataError::MissingId,
				},
				ErrorTestCase {
					name: "V1 missing order",
					builder: || {
						MetadataBuilder::from(Version::V1)
							.with_id("test-id")
							.with_confidentiality_info(create_test_encryption_info())
					},
					expected_error: MetadataError::MissingTimestamp,
				},
				ErrorTestCase {
					name: "V1 missing encryption",
					builder: || {
						MetadataBuilder::from(Version::V1)
							.with_id("test-id")
							.with_order(1696521600)
							.with_integrity_info(create_test_hash_info())
							.with_nonrepudiation_info(create_test_signature_info())
					},
					expected_error: MetadataError::MissingEncryption,
				},
				ErrorTestCase {
					name: "V2 missing id",
					builder: || {
						MetadataBuilder::from(Version::V2)
							.with_order(1696521600)
							.with_integrity_info(create_test_hash_info())
							.with_confidentiality_info(create_test_encryption_info())
					},
					expected_error: MetadataError::MissingId,
				},
				ErrorTestCase {
					name: "V2 missing order",
					builder: || {
						MetadataBuilder::from(Version::V2)
							.with_id("test-id")
							.with_integrity_info(create_test_hash_info())
							.with_confidentiality_info(create_test_encryption_info())
					},
					expected_error: MetadataError::MissingTimestamp,
				},
				ErrorTestCase {
					name: "V2 missing hash",
					builder: || {
						MetadataBuilder::from(Version::V2)
							.with_id("test-id")
							.with_order(1696521600)
							.with_confidentiality_info(create_test_encryption_info())
					},
					expected_error: MetadataError::MissingHash,
				},
				ErrorTestCase {
					name: "V2 missing encryption",
					builder: || {
						MetadataBuilder::from(Version::V2)
							.with_id("test-id")
							.with_order(1696521600)
							.with_integrity_info(create_test_hash_info())
					},
					expected_error: MetadataError::MissingEncryption,
				},
			];

			for case in test_cases {
				let result = (case.builder)().build();
				assert!(result.is_err(), "Test case '{}' should have failed", case.name);

				match result.unwrap_err() {
					BuildError::InvalidMetadata(err) => {
						assert_eq!(
							err, case.expected_error,
							"Test case '{}' failed: expected {:?}, got {:?}",
							case.name, case.expected_error, err
						);
					}
					other => panic!("Test case '{}' failed: expected InvalidMetadata, got {:?}", case.name, other),
				}
			}
		}
	}
}

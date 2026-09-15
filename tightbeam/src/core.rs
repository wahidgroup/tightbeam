#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::{EncodeValue, Tagged};
use crate::error::Result;
use crate::{Frame, Metadata, Version};

#[cfg(feature = "crypto")]
use crate::crypto::profiles::SecurityProfile;

/// Decompresses message bodies.
///
/// A single always-present trait so downstream code compiles identically
/// under every feature combination.
pub trait Inflator {
	/// Decompress `data`, returning the decompressed bytes.
	///
	/// # Errors
	///
	/// Returns an error when the underlying codec rejects the input.
	fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// A marker trait for types that can be used as the body of a TightBeam
/// message.
pub trait Message:
	EncodeValue + Tagged + for<'a> crate::der::Decode<'a> + Clone + PartialEq + core::fmt::Debug + Sized + Send + Sync
{
	/// Minimum version required to send this message type.
	const MIN_VERSION: Version = Version::V0;
	/// Whether this message type requires non-repudiation (signing).
	const MUST_BE_NON_REPUDIABLE: bool = false;
	/// Whether this message type requires confidentiality (encryption).
	const MUST_BE_CONFIDENTIAL: bool = false;
	/// Whether this message type requires compression.
	const MUST_BE_COMPRESSED: bool = false;
	/// Whether this message type requires prioritization.
	const MUST_BE_PRIORITIZED: bool = false;
	/// Whether this message type requires message integrity (hashing).
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	/// Whether this message type requires frame integrity (hashing).
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;

	/// Whether this message type has a custom security profile that
	/// constrains algorithms.
	const HAS_PROFILE: bool = false;

	/// The security profile that constrains which cryptographic algorithms
	/// can be used with this message type. Defaults to TightbeamProfile.
	#[cfg(feature = "crypto")]
	type Profile: SecurityProfile;
}

/// A trait for types that represent a TightBeam message with associated data.
pub trait TightBeamLike:
	crate::der::Encode
	+ for<'a> crate::der::Decode<'a>
	+ Clone
	+ core::fmt::Debug
	+ PartialEq
	+ Into<Metadata>
	+ Into<Version>
{
}

impl TightBeamLike for Frame {}

/// Outcome of an integrity verification check.
#[cfg(feature = "digest")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVerdict {
	/// Recomputed digest matches the stored value.
	Verified,
	/// The frame carries no integrity value to check.
	Absent,
	/// The stored digest was produced by a different algorithm than `D`.
	AlgorithmMismatch,
	/// Recomputed digest differs because the covered bytes changed after
	/// digesting.
	Mismatch,
}

#[cfg(feature = "digest")]
impl IntegrityVerdict {
	/// `true` only for [`IntegrityVerdict::Verified`].
	pub fn is_verified(self) -> bool {
		matches!(self, IntegrityVerdict::Verified)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::{
		string::{String, ToString},
		vec,
		vec::Vec,
	};

	use crate::testing::{TestKey, TestMessage};
	use crate::Beamable;
	use crate::MessagePriority;
	use crate::{EncryptedContentInfo, SignerInfo};

	use super::*;

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct SimpleMessage {
		id: u64,
		name: String,
	}

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct NestedMessage {
		value: u32,
		data: Vec<u8>,
		flag: bool,
	}

	/// Pin `decoded` to the type of `original`. With reduced feature sets the
	/// `serde_json` dev-dependency's `PartialEq<Value>` impls for integers make
	/// a bare `assert_eq!` on `decode`'s inferred output ambiguous.
	fn assert_round_trip<T: PartialEq + core::fmt::Debug>(original: &T, decoded: &T) {
		assert_eq!(original, decoded);
	}

	/// Macro to generate encode/decode round-trip tests.
	macro_rules! test_encode_decode {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $value;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded = crate::decode(&encoded)?;
					assert_round_trip(&original, &decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_encode_decode! {
		encode_decode_simple_message: SimpleMessage {
			id: 42,
			name: "test".to_string(),
		},
		encode_decode_simple_message_zero: SimpleMessage {
			id: 0,
			name: String::new(),
		},
		encode_decode_simple_message_large: SimpleMessage {
			id: u64::MAX,
			name: "a very long name with many characters".to_string(),
		},
		encode_decode_nested_message: NestedMessage {
			value: 12345,
			data: vec![1, 2, 3, 4, 5],
			flag: true,
		},
		encode_decode_nested_message_false: NestedMessage {
			value: 0,
			data: Vec::new(),
			flag: false,
		},
		encode_decode_u32: 42u32,
		encode_decode_u64: 9876543210u64,
		encode_decode_bool_true: true,
		encode_decode_bool_false: false,
	}

	/// Macro to generate decode failure tests.
	macro_rules! test_decode_failure {
		($($name:ident: $data:expr => $type:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let result: Result<$type> = crate::decode($data);
					assert!(result.is_err());
				}
			)*
		};
	}

	test_decode_failure! {
		decode_invalid_der_should_fail: &vec![0xFF, 0xFF, 0xFF] => u32,
		decode_empty_should_fail: &vec![] => u32,
		decode_invalid_sequence: &vec![0x30, 0xFF] => SimpleMessage,
		decode_wrong_type: &vec![0x02, 0x01, 0x2A] => SimpleMessage, // INTEGER instead of SEQUENCE
	}

	#[test]
	fn decode_truncated_should_fail() -> Result<()> {
		let original = SimpleMessage { id: 100, name: "test".to_string() };
		let mut encoded = crate::encode(&original)?;
		encoded.truncate(5);

		let result: Result<SimpleMessage> = crate::decode(&encoded);
		assert!(result.is_err());

		Ok(())
	}

	/// Macro to generate TightBeam encode/decode round-trip tests.
	macro_rules! test_tightbeam_roundtrip {
		($($name:ident: $tightbeam:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $tightbeam;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded: Frame = crate::decode(&encoded)?;
					assert_eq!(original, decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_roundtrip! {
		tightbeam_v0_minimal: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "test-001",
					order: 1696521600,
					message: message,
			}?
		},
		tightbeam_v0_large_value: {
			let message = TestMessage::sample(Some(&("A".repeat(1000))));
			compose! {
				V0:
					id: "test-002",
					order: 1696521700,
					message: message
			}?
		},
		tightbeam_v1_encrypted: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			compose! {
				V1: id: "test-003",
					order: 1696521800,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key
			}?
		},
		tightbeam_v2_full: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			compose! {
				V2: id: "test-004",
					order: 1696521900,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::HighThroughput,
					lifetime: 3600
			}?
		},
	}

	/// Macro to test TightBeam conversions.
	macro_rules! test_tightbeam_conversions {
		($($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let _converted: $target = tightbeam.clone().into();

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_conversions! {
		tightbeam_to_metadata_v0: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "meta-001",
					order: 1000,
					message: message
			}?
		} => Metadata,
		tightbeam_to_protocol_version: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			compose! {
				V2:
					id: "ver-001",
					order: 2000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::Expedited,
					lifetime: 60
			}?
		} => Version,
	}

	/// Macro to test TightBeam TryFrom conversions (owned only).
	macro_rules! test_tightbeam_try_conversions {
		(success: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_ok());

					Ok(())
				}
			)*
		};
		(failure: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_err());

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_try_conversions! {
		success:
		tightbeam_v1_to_signature_info: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			compose! {
				V1: id: "sig-001",
					order: 3000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key
			}?
		} => SignerInfo,
		tightbeam_v2_to_encryption_info: {
			use crate::crypto::aead::Aes256GcmOid;
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			compose! {
				V2:
					id: "enc-001",
					order: 4000,
					message: message,
					confidentiality<Aes256GcmOid, _>: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::LowLatency,
					lifetime: 120
			}?
		} => EncryptedContentInfo,
	}

	test_tightbeam_try_conversions! {
		failure: // These conversions should fail due to missing fields.
		tightbeam_v0_to_signature_info_fails: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "fail-001",
					order: 5000,
					message: message
			}?
		} => SignerInfo,
		tightbeam_v0_to_encryption_info_fails: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "fail-002",
					order: 6000,
					message: message
			}?
		} => EncryptedContentInfo,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile = 1)]
	struct NumericProfileMessage {
		id: u64,
		data: String,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile(crate::crypto::profiles::TightbeamProfile))]
	struct TypeProfileMessage {
		id: u64,
		data: String,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct NoProfileMessage {
		id: u64,
		data: String,
	}

	#[test]
	#[allow(clippy::assertions_on_constants)]
	fn test_profile_types() {
		// Every message type must expose a Profile type that implements
		// SecurityProfile.
		fn assert_security_profile<P: crate::crypto::profiles::SecurityProfile>() {}

		assert_security_profile::<<NumericProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<TypeProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<NoProfileMessage as crate::Message>::Profile>();

		// A type-based profile resolves to the named profile type.
		assert_eq!(
			core::any::TypeId::of::<<TypeProfileMessage as crate::Message>::Profile>(),
			core::any::TypeId::of::<crate::crypto::profiles::TightbeamProfile>()
		);

		assert!(!NumericProfileMessage::HAS_PROFILE);
		assert!(TypeProfileMessage::HAS_PROFILE);
		assert!(!NoProfileMessage::HAS_PROFILE);
	}
}

#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-exports
#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der::{Decode, Encode};
use crate::der::{DecodeValue, EncodeValue, Header, Length, Reader, Tag, Tagged, Writer};
use crate::error::Result;
use crate::matrix::MatrixError;
use crate::Asn1Matrix;

#[cfg(feature = "signature")]
use crate::SignerInfo;

#[cfg(feature = "signature")]
pub type SignatureVerifier = Box<dyn FnOnce(&[u8], &SignerInfo) -> Result<()>>;
#[cfg(feature = "digest")]
pub type Digestor = Box<dyn FnOnce(&[u8]) -> Result<crate::DigestInfo>>;

impl Asn1Matrix {
	/// Validate invariants per spec.
	pub fn validate(&self) -> Result<()> {
		if self.n == 0 {
			return Err(MatrixError::InvalidN(self.n).into());
		}

		let n2 = (self.n as usize) * (self.n as usize);
		if self.data.len() != n2 {
			return Err(MatrixError::LengthMismatch { n: self.n, len: self.data.len() }.into());
		}

		Ok(())
	}
}

impl Tagged for Asn1Matrix {
	fn tag(&self) -> Tag {
		Tag::Sequence
	}
}

impl<'a> DecodeValue<'a> for Asn1Matrix {
	fn decode_value<R: Reader<'a>>(reader: &mut R, _header: Header) -> crate::der::Result<Self> {
		reader.sequence(|seq: &mut der::NestedReader<'_, R>| {
			let n = u8::decode(seq)?;
			let data_os = crate::der::asn1::OctetString::decode(seq)?;

			// Validate per spec
			if n == 0 {
				return Err(crate::der::ErrorKind::Value { tag: Tag::Integer }.into());
			}

			let data = data_os.as_bytes();
			let n2 = (n as usize) * (n as usize);
			if data.len() != n2 {
				return Err(crate::der::ErrorKind::Length { tag: Tag::OctetString }.into());
			}

			Ok(Self { n, data: data.to_vec() })
		})
	}
}

impl EncodeValue for Asn1Matrix {
	fn value_len(&self) -> crate::der::Result<Length> {
		// INTEGER(n) + OCTET STRING(data)
		let n_len = self.n.encoded_len()?;
		// Validate before encoding
		if self.n == 0 {
			return Err(crate::der::ErrorKind::Value { tag: Tag::Integer }.into());
		}

		let n2 = (self.n as usize) * (self.n as usize);
		if self.data.len() != n2 {
			return Err(crate::der::ErrorKind::Length { tag: Tag::OctetString }.into());
		}

		let os = crate::der::asn1::OctetString::new(self.data.as_slice())?;
		let os_len = os.encoded_len()?;
		let total = (n_len + os_len)?;
		Ok(total)
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		// Encode fields inside SEQUENCE
		self.n.encode(encoder)?;

		let os = crate::der::asn1::OctetString::new(self.data.as_slice())?;
		os.encode(encoder)
	}
}

impl<'a> Decode<'a> for Asn1Matrix {
	fn decode<R: Reader<'a>>(reader: &mut R) -> crate::der::Result<Self> {
		let header = reader.peek_header()?;
		Self::decode_value(reader, header)
	}
}

/// Create a SignatureInfo by signing data
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! sign {
	($signer:expr, $data:expr) => {{
		let unsigned_bytes = $crate::encode(&$data)?;
		$signer(&unsigned_bytes)
	}};
}

/// Macro to sign a document and insert the signature
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! notarize {
	// Pattern for Signatory trait objects (takes a reference)
	(tbs: $tbs:expr, position: $position:ident, signer: & $signer:expr) => {{
		use $crate::crypto::sign::Signatory;

		let unsigned_bytes = $crate::encode(&$tbs)?;
		let $position = Some($signer.to_signer_info(&unsigned_bytes)?);

		let mut tbs = $tbs;
		tbs.$position = $position;
		Ok::<_, $crate::TightBeamError>(tbs)
	}};

	// Pattern for callable (Box<dyn FnOnce> or closures)
	(tbs: $tbs:expr, position: $position:ident, signer: $signer:expr) => {{
		let unsigned_bytes = $crate::encode(&$tbs)?;
		let $position = Some($signer(&unsigned_bytes)?);

		let mut tbs = $tbs;
		tbs.$position = $position;
		Ok::<_, $crate::TightBeamError>(tbs)
	}};
}

#[cfg(feature = "compress")]
#[macro_export]
macro_rules! compress {
	($alg:ident, $data:expr) => {{
		$crate::utils::compress($data, $crate::AlgorithmIdentifierOwned::$alg)
	}};
}

#[cfg(feature = "compress")]
#[macro_export]
macro_rules! decompress {
	($alg:ident, $data:expr) => {{
		$crate::utils::decompress($data, $crate::AlgorithmIdentifierOwned::$alg)
	}};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! rwlock {
	// Single declaration with default
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new($default)))
					.clone()
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(Default::default())))
					.clone()
			}
		}
	};

	// Multiple declarations
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::rwlock!($name: $ty $(= $default)?);
		)+
	};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! mutex {
	// Single declaration with default
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new($default)))
					.clone()
			}
		}
	};

	// Single declaration without default (uses Default trait)
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Default::default())))
					.clone()
			}
		}
	};

	// Multiple declarations
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::mutex!($name: $ty $(= $default)?);
		)+
	};
}

/// Extension trait for Frame to add compute_hash method
#[cfg(feature = "digest")]
pub trait FrameHashExt {
	/// Compute hash of the frame using the specified digest algorithm
	fn compute_hash<D>(&self) -> Result<crate::DigestInfo>
	where
		D: digest::Digest + crate::der::oid::AssociatedOid;
}

#[cfg(feature = "digest")]
impl FrameHashExt for crate::Frame {
	fn compute_hash<D>(&self) -> Result<crate::DigestInfo>
	where
		D: digest::Digest + crate::der::oid::AssociatedOid,
	{
		let encoded = crate::encode(self)?;
		crate::utils::digest::<D>(&encoded)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::string::ToString;

	#[cfg(feature = "signature")]
	mod notarize {
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::error::Result;

		#[test]
		fn test_notarize_macro() -> Result<()> {
			let mut tbs = crate::testing::create_v0_tightbeam(None, None);
			tbs.nonrepudiation = None; // Ensure no signature initially

			let secret_bytes = [1u8; 32];
			let signing_key = Secp256k1SigningKey::from_bytes(&secret_bytes.into())?;

			// Use & to match the first pattern (Signatory trait)
			let notarized = notarize!(tbs: tbs, position: nonrepudiation, signer: &signing_key)?;
			assert!(notarized.nonrepudiation.is_some());

			Ok(())
		}
	}

	mod validation {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::testing::{create_test_cipher_key, create_test_signing_key};
		use crate::Version;

		#[test]
		fn test_message_traits() {
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			// Helper to compose frames based on requirements
			#[allow(clippy::too_many_arguments)]
			fn compose_frame(
				test_name: &str,
				message: impl crate::Message,
				cipher: &Aes256Gcm,
				signing_key: &Secp256k1SigningKey,
				confidential: bool,
				nonrepudiable: bool,
				message_integrity: bool,
				frame_integrity: bool,
			) -> crate::error::Result<crate::Frame> {
				match (confidential, nonrepudiable, message_integrity, frame_integrity) {
					(true, true, true, true) => crate::compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256,
						frame_integrity: type Sha3_256
					},
					(true, false, true, _) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						message_integrity: type Sha3_256
					},
					(true, false, false, _) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher
					},
					(false, true, true, _) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256
					},
					(false, true, false, _) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						nonrepudiation<Secp256k1Signature, _>: signing_key
					},
					(false, false, true, true) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						message_integrity: type Sha3_256,
						frame_integrity: type Sha3_256
					},
					(false, false, true, false) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						message_integrity: type Sha3_256
					},
					(false, false, false, true) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						frame_integrity: type Sha3_256
					},
					(false, false, false, false) => crate::compose! {
						V0: id: test_name, order: 1u64, message: message.clone()
					},
					(true, true, true, false) => crate::compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256
					},
					(true, true, false, true) => crate::compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						frame_integrity: type Sha3_256
					},
					(true, true, false, false) => crate::compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key
					},
				}
			}

			// Test cases: (name, attrs, confidential, nonrepudiable, message_integrity, frame_integrity, min_version)
			let test_cases = [
				("BasicMessage", "", false, false, false, false, Version::V0),
				(
					"ConfidentialMessage",
					"confidential, min_version = \"V1\"",
					true,
					false,
					false,
					false,
					Version::V1,
				),
				(
					"NonrepudiableMessage",
					"nonrepudiable, min_version = \"V1\"",
					false,
					true,
					false,
					false,
					Version::V1,
				),
				(
					"FullSecurityMessage",
					"confidential, nonrepudiable, message_integrity, frame_integrity, min_version = \"V2\"",
					true,
					true,
					true,
					true,
					Version::V2,
				),
			];

			for (name, _attrs, confidential, nonrepudiable, message_integrity, frame_integrity, min_version) in
				test_cases
			{
				// Create test message with constants determined at compile time
				macro_rules! test_message_case {
					($conf:expr, $nonrep:expr, $msg_int:expr, $frame_int:expr, $min_ver:ident) => {{
						use $crate::core::Message;
						#[derive(Clone, Debug, PartialEq, der::Sequence)]
						struct TestMsg {
							content: String,
						}
						impl crate::Message for TestMsg {
							const MUST_BE_CONFIDENTIAL: bool = $conf;
							const MUST_BE_NON_REPUDIABLE: bool = $nonrep;
							const MUST_BE_COMPRESSED: bool = false;
							const MUST_BE_PRIORITIZED: bool = false;
							const MUST_HAVE_MESSAGE_INTEGRITY: bool = $msg_int;
							const MUST_HAVE_FRAME_INTEGRITY: bool = $frame_int;
							const MIN_VERSION: Version = Version::$min_ver;
						}

						// Test 1: Verify constants
						let message = TestMsg { content: format!("test {}", name) };
						assert_eq!(TestMsg::MUST_BE_CONFIDENTIAL, confidential);
						assert_eq!(TestMsg::MUST_BE_NON_REPUDIABLE, nonrepudiable);
						assert_eq!(TestMsg::MUST_HAVE_MESSAGE_INTEGRITY, message_integrity);
						assert_eq!(TestMsg::MUST_HAVE_FRAME_INTEGRITY, frame_integrity);
						assert_eq!(TestMsg::MIN_VERSION, min_version);

						// Test 2: Verify frame composition
						let result = compose_frame(
							name,
							message.clone(),
							&cipher,
							&signing_key,
							confidential,
							nonrepudiable,
							message_integrity,
							frame_integrity,
						);
						assert!(result.is_ok());

						let frame = result.unwrap();
						assert_eq!(frame.nonrepudiation.is_some(), nonrepudiable);

						// Test 3: Verify version enforcement
						if min_version > Version::V0 {
							let result_v0 = crate::compose! {
								V0: id: name, order: 1u64, message: message.clone()
							};
							assert!(result_v0.is_err());
						}
					}};
				}

				match (confidential, nonrepudiable, message_integrity, frame_integrity, min_version) {
					(false, false, false, false, Version::V0) => test_message_case!(false, false, false, false, V0),
					(true, false, false, false, Version::V1) => test_message_case!(true, false, false, false, V1),
					(false, true, false, false, Version::V1) => test_message_case!(false, true, false, false, V1),
					(true, true, true, true, Version::V2) => test_message_case!(true, true, true, true, V2),
					_ => panic!("Unhandled test case combination"),
				}
			}
		}
	}
}

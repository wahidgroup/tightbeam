#[cfg(not(feature = "std"))]
extern crate alloc;

// Re-exports
#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::der::{Decode, Encode};
use crate::der::{DecodeValue, EncodeValue, Header, Length, Reader, Tag, Tagged, Writer};
use crate::error::Result;
use crate::matrix::MatrixError;
use crate::{Asn1Matrix, Frame};

#[cfg(feature = "signature")]
use crate::{SignerInfo, TightBeamError};

pub type SignatureVerifier<E = TightBeamError> = Box<dyn FnOnce(&[u8], &SignerInfo) -> core::result::Result<(), E>>;
#[cfg(feature = "digest")]
pub type Digestor<E = TightBeamError> = Box<dyn FnOnce(&[u8]) -> core::result::Result<crate::DigestInfo, E>>;
#[cfg(feature = "kdf")]
pub type KeyDeriver<E = TightBeamError> = Box<dyn Fn(&[u8], &[u8], &[u8], usize) -> core::result::Result<Vec<u8>, E>>;
#[cfg(feature = "aead")]
pub type KeyWrapper<E = TightBeamError> = Box<dyn Fn(&[u8], &[u8]) -> core::result::Result<Vec<u8>, E>>;

impl AsRef<Frame> for Frame {
	fn as_ref(&self) -> &Frame {
		self
	}
}

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

impl Default for Asn1Matrix {
	fn default() -> Self {
		Self { n: 1, data: Vec::new() }
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
					|> std::sync::Arc::clone
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
}

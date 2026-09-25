#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(
	not(feature = "std"),
	any(feature = "signature", feature = "digest", feature = "aead")
))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "aead"))]
use alloc::vec::Vec;

#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Frame;

#[cfg(feature = "digest")]
use crate::error::Result;
#[cfg(feature = "signature")]
use crate::SignerInfo;
#[cfg(any(feature = "signature", feature = "digest", feature = "aead"))]
use crate::TightBeamError;

#[cfg(feature = "signature")]
pub type SignatureVerifier<E = TightBeamError> = Box<dyn FnOnce(&[u8], &SignerInfo) -> core::result::Result<(), E>>;
#[cfg(feature = "digest")]
pub type Digestor<E = TightBeamError> = Box<dyn FnOnce(&[u8]) -> core::result::Result<crate::DigestInfo, E>>;
#[cfg(feature = "aead")]
pub type KeyWrapper<E = TightBeamError> = Box<dyn Fn(&[u8], &[u8]) -> core::result::Result<Vec<u8>, E>>;

impl AsRef<Frame> for Frame {
	fn as_ref(&self) -> &Frame {
		self
	}
}

/// Create a SignatureInfo by signing data.
#[macro_export]
#[cfg(feature = "signature")]
macro_rules! sign {
	($signer:expr, $data:expr) => {{
		let unsigned_bytes = $crate::encode(&$data)?;
		$signer(&unsigned_bytes)
	}};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! rwlock {
	// This arm takes a single declaration with a default.
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new($default)))
				)
			}
		}
	};

	// This arm takes a single declaration without a default, so it uses
	// `Default`.
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::RwLock<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::RwLock<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::RwLock::new(Default::default())))
				)
			}
		}
	};

	// This arm takes several declarations.
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::rwlock!($name: $ty $(= $default)?);
		)+
	};
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! mutex {
	// This arm takes a single declaration with a default.
	($name:ident: $ty:ty = $default:expr) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new($default)))
				)
			}
		}
	};

	// This arm takes a single declaration without a default, so it uses
	// `Default`.
	($name:ident: $ty:ty) => {
		paste::paste! {
			static [<$name _CELL>]: std::sync::OnceLock<std::sync::Arc<std::sync::Mutex<$ty>>> = std::sync::OnceLock::new();

			#[allow(non_snake_case)]
			fn $name() -> std::sync::Arc<std::sync::Mutex<$ty>> {
				std::sync::Arc::clone(
					[<$name _CELL>].get_or_init(|| std::sync::Arc::new(std::sync::Mutex::new(Default::default())))
				)
			}
		}
	};

	// This arm takes several declarations.
	($($name:ident: $ty:ty $(= $default:expr)?),+ $(,)?) => {
		$(
			$crate::mutex!($name: $ty $(= $default)?);
		)+
	};
}

/// Extension trait for `Frame` that adds the `compute_hash` method.
#[cfg(feature = "digest")]
pub trait FrameHashExt {
	/// Compute the hash of the frame with the digest algorithm `D`.
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

	#[cfg(feature = "std")]
	mod statics {
		#[derive(Debug, Default, PartialEq)]
		struct Counter(u64);

		rwlock!(SHARED_RWLOCK_DEFAULTED: Counter = Counter(7));
		rwlock!(SHARED_RWLOCK: Counter);
		mutex!(SHARED_MUTEX_DEFAULTED: Counter = Counter(7));
		mutex!(SHARED_MUTEX: Counter);
		rwlock! {
			MULTI_RWLOCK_A: Counter,
			MULTI_RWLOCK_B: Counter = Counter(3),
		}
		mutex! {
			MULTI_MUTEX_A: Counter,
			MULTI_MUTEX_B: Counter = Counter(3),
		}

		#[test]
		fn rwlock_arms_initialize_and_share_state() -> crate::error::Result<()> {
			assert_eq!(*SHARED_RWLOCK_DEFAULTED().read()?, Counter(7));
			assert_eq!(*SHARED_RWLOCK().read()?, Counter(0));
			assert_eq!(*MULTI_RWLOCK_A().read()?, Counter(0));
			assert_eq!(*MULTI_RWLOCK_B().read()?, Counter(3));

			SHARED_RWLOCK().write()?.0 = 42;
			assert_eq!(*SHARED_RWLOCK().read()?, Counter(42));

			Ok(())
		}

		#[test]
		fn mutex_arms_initialize_and_share_state() -> crate::error::Result<()> {
			assert_eq!(*SHARED_MUTEX_DEFAULTED().lock()?, Counter(7));
			assert_eq!(*SHARED_MUTEX().lock()?, Counter(0));
			assert_eq!(*MULTI_MUTEX_A().lock()?, Counter(0));
			assert_eq!(*MULTI_MUTEX_B().lock()?, Counter(3));

			SHARED_MUTEX().lock()?.0 = 42;
			assert_eq!(*SHARED_MUTEX().lock()?, Counter(42));

			Ok(())
		}
	}
}

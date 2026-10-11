#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "zeroize")]
pub use zeroize::{Zeroize, ZeroizeOnDrop};

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

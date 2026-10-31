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
		use std::sync::{Arc, Mutex, RwLock};

		use crate::error::Result;

		#[derive(Debug, Default, PartialEq)]
		struct Counter(u64);

		/// The accessor of a static lock that `rwlock!` or `mutex!` declares.
		type Accessor<L> = fn() -> Arc<L>;

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

		// The write tests alone take these locks, so a parallel run leaves the
		// declared values that the other tests read in place.
		rwlock!(WRITTEN_RWLOCK: Counter);
		mutex!(WRITTEN_MUTEX: Counter);

		// Each arm of `rwlock!` starts its lock at the value the declaration
		// names, or at `Default` where it names none.
		crate::tb_cases! {
			fn a_rwlock_starts_at_its_declared_value((lock, start): (Accessor<RwLock<Counter>>, Counter)) -> Result<()> {
				let held = lock();
				assert_eq!(*held.read()?, start);
				Ok(())
			}
			cases {
				defaulted => (SHARED_RWLOCK_DEFAULTED, Counter(7)),
				plain => (SHARED_RWLOCK, Counter(0)),
				multi_plain => (MULTI_RWLOCK_A, Counter(0)),
				multi_defaulted => (MULTI_RWLOCK_B, Counter(3)),
			}
		}

		// Each arm of `mutex!` starts its lock at the value the declaration
		// names, or at `Default` where it names none.
		crate::tb_cases! {
			fn a_mutex_starts_at_its_declared_value((lock, start): (Accessor<Mutex<Counter>>, Counter)) -> Result<()> {
				let held = lock();
				assert_eq!(*held.lock()?, start);
				Ok(())
			}
			cases {
				defaulted => (SHARED_MUTEX_DEFAULTED, Counter(7)),
				plain => (SHARED_MUTEX, Counter(0)),
				multi_plain => (MULTI_MUTEX_A, Counter(0)),
				multi_defaulted => (MULTI_MUTEX_B, Counter(3)),
			}
		}

		/// Each call of a `rwlock!` accessor hands out the one lock of its
		/// static, so a write through one handle is what the next one reads.
		#[test]
		fn a_rwlock_write_is_shared() -> Result<()> {
			WRITTEN_RWLOCK().write()?.0 = 42;

			assert_eq!(*WRITTEN_RWLOCK().read()?, Counter(42));
			Ok(())
		}

		/// Each call of a `mutex!` accessor hands out the one lock of its
		/// static, so a write through one handle is what the next one reads.
		#[test]
		fn a_mutex_write_is_shared() -> Result<()> {
			WRITTEN_MUTEX().lock()?.0 = 42;

			assert_eq!(*WRITTEN_MUTEX().lock()?, Counter(42));
			Ok(())
		}
	}
}

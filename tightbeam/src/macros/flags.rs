#[macro_export]
macro_rules! flags {
	($flagset_type:ty: $($flag:expr),* $(,)?) => {{
		let mut flagset = <$flagset_type>::default();
		$(
			<$flagset_type as $crate::flags::FlagSet<_>>::set(&mut flagset, $flag);
		)*
		flagset
	}};
}

/// Define a named flag set over an ordered list of flag types.
///
/// Each registered type is assigned the slot matching its position in the
/// declaration, and gets its own [`FlagSet`](crate::flags::FlagSet)
/// implementation, so flag lookups are resolved at compile time. Setting a
/// flag of an unregistered type is rejected by the compiler:
///
/// ```compile_fail
/// use tightbeam::flags::FlagSet;
///
/// #[derive(Default, Clone, Copy)]
/// enum Registered {
///     #[default]
///     Off,
///     On,
/// }
///
/// impl From<Registered> for u8 {
///     fn from(flag: Registered) -> u8 {
///         flag as u8
///     }
/// }
///
/// #[derive(Default, Clone, Copy)]
/// enum Unregistered {
///     #[default]
///     Off,
///     On,
/// }
///
/// impl From<Unregistered> for u8 {
///     fn from(flag: Unregistered) -> u8 {
///         flag as u8
///     }
/// }
///
/// tightbeam::flagset!(MyFlags: Registered);
///
/// let mut flags = MyFlags::default();
/// FlagSet::set(&mut flags, Unregistered::On);
/// ```
#[macro_export]
macro_rules! flagset {
	($name:ident: $first:ty $(, $rest:ty)* $(,)?) => {
		#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
		pub struct $name {
			flags: $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }>,
		}

		impl Default for $name {
			fn default() -> Self {
				Self {
					flags: $crate::flags::Flags::default(),
				}
			}
		}

		impl From<$name> for $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }> {
			fn from(flagset: $name) -> $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }> {
				flagset.flags
			}
		}

		impl From<Vec<u8>> for $name {
		fn from(bytes: Vec<u8>) -> Self {
			Self {
				flags: $crate::flags::Flags::from(bytes.as_slice()),
			}
		}
		}

		impl From<&[u8]> for $name {
		 fn from(bytes: &[u8]) -> Self {
			Self {
				flags: $crate::flags::Flags::from(bytes),
			}
		 }
		}

		impl From<Option<Vec<u8>>> for $name {
			fn from(bytes: Option<Vec<u8>>) -> Self {
				match bytes {
					Some(bytes) => Self::from(bytes),
					None => Self::default(),
				}
			}
		}

		$crate::flagset!(@flag_impls $name, 0, $first $(, $rest)*);

		impl From<$name> for Vec<u8> {
		 fn from(flagset: $name) -> Vec<u8> {
			Vec::from(flagset.flags)
		 }
		}

		impl From<$name> for $crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }> {
			fn from(flagset: $name) -> Self {
				Self::from(flagset.flags)
			}
		}

		impl From<&$name> for $crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }> {
			fn from(flagset: &$name) -> Self {
				Self::from(&flagset.flags)
			}
		}

		// MatrixDyn -> FlagSet (read diagonal; ignore off-diagonals; clamp to min(n, N))
		impl From<$crate::matrix::MatrixDyn> for $name {
			fn from(m: $crate::matrix::MatrixDyn) -> Self {
				Self::from(&m)
			}
		}

		impl From<&$crate::matrix::MatrixDyn> for $name {
			fn from(m: &$crate::matrix::MatrixDyn) -> Self {
				let n = $crate::matrix::MatrixLike::n(m);
				let dim = ::core::cmp::min(n as usize, $crate::flagset!(@count $first $(, $rest)*));
				let mut flags = $crate::flags::Flags::<{ $crate::flagset!(@count $first $(, $rest)*) }>::default();
				for __idx in 0..dim {
					flags.set_at(__idx, $crate::matrix::MatrixLike::get(m, __idx as u8, __idx as u8));
				}
				Self { flags }
			}
		}

		// Matrix<N> -> FlagSet (exact size; read diagonal)
		impl From<$crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }>> for $name {
			fn from(m: $crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }>) -> Self {
				Self::from(&m)
			}
		}

		impl From<&$crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }>> for $name {
			fn from(m: &$crate::matrix::Matrix<{ $crate::flagset!(@count $first $(, $rest)*) }>) -> Self {
				let mut flags = $crate::flags::Flags::<{ $crate::flagset!(@count $first $(, $rest)*) }>::default();
				for __idx in 0..($crate::flagset!(@count $first $(, $rest)*) as usize) {
					flags.set_at(__idx, $crate::matrix::MatrixLike::get(m, __idx as u8, __idx as u8));
				}
				Self { flags }
			}
		}

		impl $crate::matrix::MatrixLike for $name {
			fn n(&self) -> u8 {
				$crate::flagset!(@count $first $(, $rest)*) as u8
			}

			fn get(&self, r: u8, c: u8) -> u8 {
				$crate::matrix::MatrixLike::get(&self.flags, r, c)
			}

			fn set(&mut self, r: u8, c: u8, value: u8) {
				$crate::matrix::MatrixLike::set(&mut self.flags, r, c, value);
			}

			fn fill(&mut self, value: u8) {
				$crate::matrix::MatrixLike::fill(&mut self.flags, value);
			}
		}

		// Add TryFrom for MatrixDyn
		impl TryFrom<$name> for $crate::matrix::MatrixDyn {
			type Error = $crate::matrix::MatrixError;

			fn try_from(flagset: $name) -> Result<Self, Self::Error> {
				$crate::matrix::MatrixDyn::try_from(flagset.flags)
			}
		}

		impl TryFrom<&$name> for $crate::matrix::MatrixDyn {
			type Error = $crate::matrix::MatrixError;

			fn try_from(flagset: &$name) -> Result<Self, Self::Error> {
				$crate::matrix::MatrixDyn::try_from(&flagset.flags)
			}
		}
	 };

	(@count $first:ty) => { 1 };
	(@count $first:ty, $($rest:ty),*) => { 1 + $crate::flagset!(@count $($rest),*) };

	// One `FlagSet<$ty>` impl per registered type, with the slot fixed at
	// expansion time.
	(@flag_impls $name:ident, $pos:expr, $ty:ty) => {
		impl $crate::flags::FlagSet<$ty> for $name {
			fn set(&mut self, flag: $ty) {
				self.flags.set_at($pos, flag.into());
			}

			fn unset(&mut self) {
				self.flags.set_at($pos, <$ty as Default>::default().into());
			}

			fn contains(&self, flag: $ty) -> bool {
				let stored_value = self.flags.get_at($pos);
				let flag_value: u8 = flag.into();
				let default_value: u8 = <$ty as Default>::default().into();

				// A zero slot means "never set", which matches the type's
				// default value.
				if stored_value == flag_value {
					true
				} else if stored_value == 0 {
					flag_value == default_value
				} else {
					false
				}
			}
		}
	};

	(@flag_impls $name:ident, $pos:expr, $ty:ty, $($rest:ty),*) => {
		$crate::flagset!(@flag_impls $name, $pos, $ty);
		$crate::flagset!(@flag_impls $name, $pos + 1, $($rest),*);
	};
}

#[cfg(test)]
mod tests {
	use crate::flags::FlagSet;

	#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
	enum Status {
		#[default]
		Inactive = 0,
		Enabled = 1,
	}

	impl From<Status> for u8 {
		fn from(flag: Status) -> u8 {
			flag as u8
		}
	}

	impl PartialEq<u8> for Status {
		fn eq(&self, other: &u8) -> bool {
			(*self as u8) == *other
		}
	}

	// `SubStatus` deliberately ends with `Status`: any name-suffix-based
	// slot dispatch aliases the two types.
	#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
	enum SubStatus {
		#[default]
		None = 0,
		Active = 2,
	}

	impl From<SubStatus> for u8 {
		fn from(flag: SubStatus) -> u8 {
			flag as u8
		}
	}

	impl PartialEq<u8> for SubStatus {
		fn eq(&self, other: &u8) -> bool {
			(*self as u8) == *other
		}
	}

	crate::flagset!(SuffixFlags: Status, SubStatus);

	#[test]
	fn suffix_named_types_use_distinct_slots() {
		let mut set = SuffixFlags::default();

		FlagSet::set(&mut set, Status::Enabled);
		FlagSet::set(&mut set, SubStatus::Active);

		assert!(FlagSet::contains(&set, Status::Enabled));
		assert!(FlagSet::contains(&set, SubStatus::Active));
	}

	#[test]
	fn unset_clears_only_its_own_slot() {
		let mut set = SuffixFlags::default();

		FlagSet::set(&mut set, Status::Enabled);
		FlagSet::set(&mut set, SubStatus::Active);

		<SuffixFlags as FlagSet<SubStatus>>::unset(&mut set);

		assert!(FlagSet::contains(&set, Status::Enabled));
		assert!(!FlagSet::contains(&set, SubStatus::Active));
	}
}

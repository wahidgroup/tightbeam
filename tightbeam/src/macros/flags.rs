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
/// Each registered type takes the slot of its position in the declaration and
/// gets its own [`FlagSet`](crate::flags::FlagSet) implementation, so the
/// compiler resolves each flag lookup. The compiler refuses a flag of an
/// unregistered type:
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
///
/// # Visibility
///
/// The declaration opens with an optional visibility, and the generated
/// `struct` carries it, so the caller decides where the flag set is reachable
/// from. An omitted visibility keeps the type private to the declaring module.
///
/// ```
/// use tightbeam::flags::FlagSet;
///
/// #[derive(Default, Clone, Copy)]
/// pub enum Mode {
///     #[default]
///     Off,
///     On,
/// }
///
/// impl From<Mode> for u8 {
///     fn from(flag: Mode) -> u8 {
///         flag as u8
///     }
/// }
///
/// tightbeam::flagset!(pub(crate) CrateFlags: Mode);
///
/// let mut flags = CrateFlags::default();
/// FlagSet::set(&mut flags, Mode::On);
/// assert!(FlagSet::contains(&flags, Mode::On));
/// ```
#[macro_export]
macro_rules! flagset {
	($vis:vis $name:ident: $first:ty $(, $rest:ty)* $(,)?) => {
		#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
		$vis struct $name {
			flags: $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }>,
		}

		// Each slot holds the default of its type, as `FlagSet::unset` writes
		// it, so a never-set slot reads as that variant alone.
		impl Default for $name {
			fn default() -> Self {
				let mut flagset = Self { flags: $crate::flags::Flags::default() };
				<Self as $crate::flags::FlagSet<$first>>::unset(&mut flagset);
				$( <Self as $crate::flags::FlagSet<$rest>>::unset(&mut flagset); )*
				flagset
			}
		}

		impl From<$name> for $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }> {
			fn from(flagset: $name) -> $crate::flags::Flags<{ $crate::flagset!(@count $first $(, $rest)*) }> {
				flagset.flags
			}
		}

		impl ::core::convert::TryFrom<&[u8]> for $name {
			type Error = $crate::flags::FlagsError;

			/// # Errors
			///
			/// - [`FlagsError::LengthMismatch`](crate::flags::FlagsError) -- the
			///   slice does not name exactly this set's flags.
			fn try_from(bytes: &[u8]) -> ::core::result::Result<Self, Self::Error> {
				::core::result::Result::Ok(Self { flags: ::core::convert::TryFrom::try_from(bytes)? })
			}
		}

		impl ::core::convert::TryFrom<Vec<u8>> for $name {
			type Error = $crate::flags::FlagsError;

			/// # Errors
			///
			/// - [`FlagsError::LengthMismatch`](crate::flags::FlagsError) -- the
			///   bytes do not name exactly this set's flags.
			fn try_from(bytes: Vec<u8>) -> ::core::result::Result<Self, Self::Error> {
				::core::convert::TryFrom::try_from(bytes.as_slice())
			}
		}

		impl ::core::convert::TryFrom<Option<Vec<u8>>> for $name {
			type Error = $crate::flags::FlagsError;

			/// Absence is the default set. Present bytes must name the set
			/// exactly.
			///
			/// # Errors
			///
			/// - [`FlagsError::LengthMismatch`](crate::flags::FlagsError) --
			///   present bytes do not name exactly this set's flags.
			fn try_from(bytes: Option<Vec<u8>>) -> ::core::result::Result<Self, Self::Error> {
				match bytes {
					Some(bytes) => ::core::convert::TryFrom::try_from(bytes),
					None => ::core::result::Result::Ok(Self::default()),
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

		// A flag set reads a matrix's diagonal. Each flag is positional, so a
		// matrix whose dimension is not the flag count is refused.
		impl ::core::convert::TryFrom<$crate::matrix::MatrixDyn> for $name {
			type Error = $crate::matrix::MatrixError;

			fn try_from(m: $crate::matrix::MatrixDyn) -> ::core::result::Result<Self, Self::Error> {
				Self::try_from(&m)
			}
		}

		impl ::core::convert::TryFrom<&$crate::matrix::MatrixDyn> for $name {
			type Error = $crate::matrix::MatrixError;

			fn try_from(m: &$crate::matrix::MatrixDyn) -> ::core::result::Result<Self, Self::Error> {
				let expected = $crate::flagset!(@count $first $(, $rest)*);
				let n = $crate::matrix::MatrixLike::n(m);
				if n as usize != expected {
					return ::core::result::Result::Err($crate::matrix::MatrixError::DimensionMismatch { expected, n });
				}

				let mut flags = $crate::flags::Flags::<{ $crate::flagset!(@count $first $(, $rest)*) }>::default();
				for __idx in 0..n {
					flags.set_at(__idx as usize, $crate::matrix::MatrixLike::get(m, __idx, __idx));
				}

				::core::result::Result::Ok(Self { flags })
			}
		}

		// A `Matrix<N>` of the exact flag count converts into the flag set,
		// which reads its diagonal.
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

		// The flag set converts back into a `MatrixDyn` through its flags.
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
				stored_value == flag_value
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
	use crate::matrix::{MatrixDyn, MatrixError};
	use crate::testing::TestResult;
	use crate::Flaggable;

	#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Flaggable)]
	#[repr(u8)]
	enum Status {
		#[default]
		Inactive = 0,
		Enabled = 1,
	}

	// `SubStatus` deliberately ends with `Status`: any name-suffix-based
	// slot dispatch aliases the two types.
	#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Flaggable)]
	#[repr(u8)]
	enum SubStatus {
		#[default]
		None = 0,
		Active = 2,
	}

	crate::flagset!(SuffixFlags: Status, SubStatus);

	/// Each registered type takes the slot of its position, so a type whose
	/// name ends with the name of another keeps a slot of its own.
	#[test]
	fn suffix_named_types_use_distinct_slots() {
		let mut set = SuffixFlags::default();

		FlagSet::set(&mut set, Status::Enabled);
		FlagSet::set(&mut set, SubStatus::Active);

		assert!(FlagSet::contains(&set, Status::Enabled));
		assert!(FlagSet::contains(&set, SubStatus::Active));
	}

	/// Each flag is positional, so a matrix of another dimension is refused
	/// rather than clamped.
	#[test]
	fn a_flagset_refuses_a_matrix_of_another_dimension() -> TestResult {
		let four_by_four = MatrixDyn::try_from(4u8)?;
		let refused = SuffixFlags::try_from(&four_by_four);
		assert!(matches!(refused, Err(MatrixError::DimensionMismatch { expected: 2, n: 4 })));
		Ok(())
	}

	/// An unset writes the default of its own type into its own slot, so the
	/// flag of the other type stays set.
	#[test]
	fn unset_clears_only_its_own_slot() {
		let mut set = SuffixFlags::default();

		FlagSet::set(&mut set, Status::Enabled);
		FlagSet::set(&mut set, SubStatus::Active);

		<SuffixFlags as FlagSet<SubStatus>>::unset(&mut set);

		assert!(FlagSet::contains(&set, Status::Enabled));
		assert!(!FlagSet::contains(&set, SubStatus::Active));
	}

	/// A flag type whose default is the variant with the non-zero value.
	#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Flaggable)]
	#[repr(u8)]
	enum Mode {
		Zero = 0,
		#[default]
		One = 1,
	}

	crate::flagset!(ModeFlags: Mode);

	// A slot holds one variant at a time. A never-set slot holds the default
	// variant, and a slot set to the variant whose value is zero holds that
	// variant.
	crate::tb_cases! {
		fn a_slot_holds_one_variant_alone((flags, held): (ModeFlags, (bool, bool))) {
			let zero_and_one = (FlagSet::contains(&flags, Mode::Zero), FlagSet::contains(&flags, Mode::One));
			assert_eq!(zero_and_one, held);
		}
		cases {
			never_set => (ModeFlags::default(), (false, true)),
			set_to_the_zero_variant => (crate::flags!(ModeFlags: Mode::Zero), (true, false)),
		}
	}
}

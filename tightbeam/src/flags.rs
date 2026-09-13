//! Diagonal-flag view over the N×N matrix wire format.
//!
//! [`Flags<N>`] stores N position-stable flag bytes and presents them through
//! [`MatrixLike`] as the diagonal (r == c) of an N×N matrix, matching the
//! profile convention documented on [`MatrixDyn`](crate::matrix::MatrixDyn):
//! off-diagonal cells read as 0 and writes to them are no-ops.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::matrix::{Matrix, MatrixLike};
use crate::Errorizable;

/// Why a byte slice could not become a [`Flags<N>`].
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagsError {
	/// Flags are position-stable, so a slice of the wrong length names
	/// different flags than the caller meant. Padding or truncating it would
	/// silently change which flag each byte sets.
	#[error("flags: expected {expected} bytes, got {len}")]
	LengthMismatch { expected: usize, len: usize },
}

/// A fixed-size array of flags, where each flag is a `u8`
///
/// This struct provides a compile-time sized container for storing flag values.
/// Each position in the array can hold a single `u8` flag value. The size `N`
/// is determined at compile time, ensuring zero-cost abstractions.
///
/// The wire format bounds the dimension to 1..=255; constructing a flag set
/// with `N` outside that range is rejected at compile time:
///
/// ```compile_fail
/// use tightbeam::flags::Flags;
///
/// let rejected = Flags::<256>::default();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Flags<const N: usize>([u8; N]);

impl<const N: usize> Flags<N> {
	/// Compile-time guard: the wire format bounds the dimension to 1..=255
	/// (`MatrixLike::n` returns `u8`). Evaluated by every constructor so an
	/// out-of-range `N` is rejected at monomorphization.
	const VALID_N: () = assert!(N >= 1 && N <= 255, "Flags dimension must be 1..=255");

	pub fn set_at(&mut self, pos: usize, value: u8) {
		if pos < N {
			self.0[pos] = value;
		}
	}

	pub fn get_at(&self, pos: usize) -> u8 {
		if pos < N {
			self.0[pos]
		} else {
			0
		}
	}
}

impl<const N: usize> Default for Flags<N> {
	fn default() -> Self {
		const { Self::VALID_N };
		Self([0u8; N])
	}
}

impl<const N: usize> From<Flags<N>> for Vec<u8> {
	fn from(flags: Flags<N>) -> Self {
		flags.0.to_vec()
	}
}

impl<T, const N: usize> From<[T; N]> for Flags<N>
where
	T: Into<u8>,
{
	fn from(arr: [T; N]) -> Self {
		const { Self::VALID_N };
		let mut bytes = [0u8; N];
		for (i, item) in arr.into_iter().enumerate() {
			bytes[i] = item.into();
		}
		Flags(bytes)
	}
}

impl<const N: usize> TryFrom<&[u8]> for Flags<N> {
	type Error = FlagsError;

	/// # Errors
	///
	/// - [`FlagsError::LengthMismatch`] when the slice is not exactly `N`
	///   bytes. A shorter slice cannot say which flags it omits and a longer
	///   one cannot say which to drop.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		const { Self::VALID_N };

		let array: [u8; N] = bytes
			.try_into()
			.map_err(|_| FlagsError::LengthMismatch { expected: N, len: bytes.len() })?;

		Ok(Self(array))
	}
}

impl<const N: usize> AsRef<[u8]> for Flags<N> {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Trait for types that can store and query flags of type T.
///
/// This trait provides a common interface for flag storage containers
/// that can hold flags of a specific type and query their presence.
pub trait FlagSet<T> {
	/// Set a flag of type T in the flag set
	///
	/// # Arguments
	/// * `flag` - The flag value to store
	fn set(&mut self, flag: T);

	/// Unset a flag of type T by setting it to its default value.
	fn unset(&mut self);

	/// Check if a flag of type T is present in the flag set
	///
	/// # Arguments
	/// * `flag` - The flag value to check for
	///
	/// # Returns
	/// `true` if the flag is present, `false` otherwise
	fn contains(&self, flag: T) -> bool;
}

impl<const N: usize> MatrixLike for Flags<N> {
	fn n(&self) -> u8 {
		N as u8
	}

	fn get(&self, r: u8, c: u8) -> u8 {
		if r == c && (r as usize) < N {
			self.0[r as usize]
		} else {
			0
		}
	}

	fn set(&mut self, r: u8, c: u8, value: u8) {
		if r == c && (r as usize) < N {
			self.0[r as usize] = value;
		}
	}

	fn fill(&mut self, value: u8) {
		for i in 0..N {
			self.0[i] = value;
		}
	}
}

macro_rules! flags_to_matrix_impl {
	($flags:expr, $matrix_type:ty, $n:expr) => {{
		let mut m = <$matrix_type>::default();
		for i in 0..$n {
			m.set(i as u8, i as u8, $flags.get_at(i));
		}
		m
	}};
}

macro_rules! flags_to_matrix_dyn_impl {
	($flags:expr, $n:expr) => {{
		let n = $n as u8;
		let mut m = crate::matrix::MatrixDyn::try_from(n)?;
		for i in 0..$n {
			m.set(i as u8, i as u8, $flags.get_at(i));
		}
		Ok(m)
	}};
}

impl<const N: usize> From<crate::flags::Flags<N>> for Matrix<N> {
	fn from(flags: crate::flags::Flags<N>) -> Self {
		flags_to_matrix_impl!(flags, Matrix<N>, N)
	}
}

impl<const N: usize> From<&crate::flags::Flags<N>> for Matrix<N> {
	fn from(flags: &crate::flags::Flags<N>) -> Self {
		flags_to_matrix_impl!(flags, Matrix<N>, N)
	}
}

impl<const N: usize> TryFrom<crate::flags::Flags<N>> for crate::matrix::MatrixDyn {
	type Error = crate::matrix::MatrixError;

	fn try_from(flags: crate::flags::Flags<N>) -> Result<Self, Self::Error> {
		flags_to_matrix_dyn_impl!(flags, N)
	}
}

impl<const N: usize> TryFrom<&crate::flags::Flags<N>> for crate::matrix::MatrixDyn {
	type Error = crate::matrix::MatrixError;

	fn try_from(flags: &crate::flags::Flags<N>) -> Result<Self, Self::Error> {
		flags_to_matrix_dyn_impl!(flags, N)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// Flags are position-stable, so padding a short slice or dropping the tail
	// of a long one silently changes which flag each byte sets.
	#[test]
	fn a_slice_shorter_than_the_set_is_refused() {
		let refused = Flags::<4>::try_from([1u8, 2].as_slice());
		assert_eq!(refused, Err(FlagsError::LengthMismatch { expected: 4, len: 2 }));
	}

	#[test]
	fn a_slice_longer_than_the_set_is_refused() {
		let refused = Flags::<2>::try_from([1u8, 2, 3, 4].as_slice());
		assert_eq!(refused, Err(FlagsError::LengthMismatch { expected: 2, len: 4 }));
	}

	#[test]
	fn a_slice_of_exactly_the_set_length_is_accepted() {
		let accepted = Flags::<3>::try_from([7u8, 8, 9].as_slice()).expect("three bytes name three flags");
		assert_eq!(accepted.get_at(0), 7);
		assert_eq!(accepted.get_at(2), 9);
	}
}

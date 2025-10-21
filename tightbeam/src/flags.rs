//! Flags utilize the Matrix to create Flat World.

use crate::matrix::{Matrix, MatrixLike};

/// A fixed-size array of flags, where each flag is a `u8`
///
/// This struct provides a compile-time sized container for storing flag values.
/// Each position in the array can hold a single `u8` flag value. The size `N`
/// is determined at compile time, ensuring zero-cost abstractions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Flags<const N: usize>([u8; N]);

impl<const N: usize> Flags<N> {
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
		let mut bytes = [0u8; N];
		for (i, item) in arr.into_iter().enumerate() {
			bytes[i] = item.into();
		}
		Flags(bytes)
	}
}

impl<const N: usize> From<&[u8]> for Flags<N> {
	fn from(bytes: &[u8]) -> Self {
		let mut array = [0; N];
		let len = bytes.len().min(N);
		array[..len].copy_from_slice(&bytes[..len]);
		Self(array)
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

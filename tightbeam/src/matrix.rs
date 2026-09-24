#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::Errorizable;

pub type MatrixResult<T> = core::result::Result<T, MatrixError>;

#[derive(Errorizable, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatrixError {
	#[error("matrix: n MUST be in 1..=255 (got {0})")]
	InvalidN(u8),
	#[error("matrix: data length MUST equal n*n (n={n}, len={len})")]
	LengthMismatch { n: u8, len: usize },
	#[error("matrix: dimension MUST equal {expected} (got {n})")]
	DimensionMismatch { expected: usize, n: u8 },
}

/// Rejects a dimension outside `1..=255` when evaluated in a const block.
///
/// [`MatrixLike::n`] reports the dimension as a `u8`, so this is the wire
/// format's bound, and every fixed-size wire type checks it here.
pub(crate) const fn assert_wire_dimension<const N: usize>() {
	assert!(N >= 1 && N <= 255, "a wire dimension must be 1..=255");
}

/// Common interface for row-major N×N flag matrices with `u8` cells.
pub trait MatrixLike {
	/// Return the dimension `N` of the N×N matrix.
	fn n(&self) -> u8;

	/// Return the cell at row `r` and column `c`, or 0 when the cell is out of
	/// bounds.
	fn get(&self, r: u8, c: u8) -> u8;

	/// Set the cell at row `r` and column `c` to `value`. An out-of-bounds
	/// write does nothing.
	fn set(&mut self, r: u8, c: u8, value: u8);

	/// Fill every cell with `value`.
	fn fill(&mut self, value: u8);

	/// Clear every cell to zero.
	fn clear(&mut self) {
		self.fill(0);
	}
}

/// Conversion of a matrix type into a [`MatrixDyn`].
///
/// The trait avoids the `Infallible` error type when a `MatrixDyn` converts to
/// itself.
pub trait IntoMatrixDyn {
	fn into_matrix_dyn(self) -> Result<MatrixDyn, MatrixError>;
}

// A `MatrixDyn` converts to itself, so the conversion cannot fail.
impl IntoMatrixDyn for MatrixDyn {
	fn into_matrix_dyn(self) -> Result<MatrixDyn, MatrixError> {
		Ok(self)
	}
}

// Every other `MatrixLike` type converts through `TryFrom`.
impl<M> IntoMatrixDyn for M
where
	M: MatrixLike,
	MatrixDyn: TryFrom<M, Error = MatrixError>,
{
	fn into_matrix_dyn(self) -> Result<MatrixDyn, MatrixError> {
		MatrixDyn::try_from(self)
	}
}

/// Runtime-sized N×N matrix of u8 flags (row-major).
///
/// This is the wire type for the V3 metadata matrix. Its fields are private
/// and [`MatrixDyn::from_row_major`] is the only way to build one, so
/// `data.len() == n * n` holds for every value that exists.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct MatrixDyn {
	n: u8,
	data: Vec<u8>,
}

impl Default for MatrixDyn {
	/// Smallest valid matrix (1×1, zeroed) so the `data.len() == n*n`
	/// invariant holds for every reachable value.
	fn default() -> Self {
		Self { n: 1, data: vec![0u8; 1] }
	}
}

impl MatrixDyn {
	/// Construct a matrix from `n * n` row-major bytes.
	///
	/// The length MUST be `n * n`, and any other length returns `None`.
	pub fn from_row_major(n: u8, bytes: impl Into<Vec<u8>>) -> Option<Self> {
		let bytes: Vec<u8> = bytes.into();
		if n == 0 {
			return None;
		}

		let n_usize = n as usize;
		if bytes.len() == n_usize * n_usize {
			Some(Self { n, data: bytes })
		} else {
			None
		}
	}

	/// Defense in depth: bounds by the actual buffer as well as `n`, so a
	/// value constructed in violation of the `data.len() == n*n` invariant
	/// cannot produce an out-of-bounds index.
	#[inline]
	fn idx(&self, r: u8, c: u8) -> Option<usize> {
		let n = self.n as usize;
		let (ru, cu) = (r as usize, c as usize);
		(ru < n && cu < n).then(|| ru * n + cu).filter(|i| *i < self.data.len())
	}

	/// Borrow the underlying row-major bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.data
	}

	/// Borrow the underlying row-major bytes mutably.
	pub fn as_bytes_mut(&mut self) -> &mut [u8] {
		&mut self.data
	}

	/// Borrow a single row as a slice.
	pub fn row(&self, r: u8) -> Option<&[u8]> {
		if r >= self.n {
			return None;
		}

		let n = self.n as usize;
		let start = r as usize * n;
		self.data.get(start..start + n)
	}
}

impl crate::der::FixedTag for MatrixDyn {
	const TAG: crate::der::Tag = crate::der::Tag::Sequence;
}

impl<'a> crate::der::DecodeValue<'a> for MatrixDyn {
	/// Read `n` and the row-major bytes, then hand both to the one
	/// constructor, which owns the length check.
	fn decode_value<R: crate::der::Reader<'a>>(
		reader: &mut R,
		_header: crate::der::Header,
	) -> crate::der::Result<Self> {
		use crate::der::asn1::OctetString;
		use crate::der::Decode;

		let n = u8::decode(reader)?;
		let data = OctetString::decode(reader)?;
		Self::from_row_major(n, data.as_bytes().to_vec())
			.ok_or_else(|| crate::der::ErrorKind::Length { tag: crate::der::Tag::OctetString }.into())
	}
}

impl crate::der::EncodeValue for MatrixDyn {
	fn value_len(&self) -> crate::der::Result<crate::der::Length> {
		use crate::der::asn1::OctetString;
		use crate::der::Encode;

		let n_len = self.n.encoded_len()?;
		let data_len = OctetString::new(self.data.as_slice())?.encoded_len()?;
		n_len + data_len
	}

	fn encode_value(&self, encoder: &mut impl crate::der::Writer) -> crate::der::Result<()> {
		use crate::der::asn1::OctetString;
		use crate::der::Encode;

		self.n.encode(encoder)?;
		OctetString::new(self.data.as_slice())?.encode(encoder)
	}
}

impl MatrixLike for MatrixDyn {
	fn n(&self) -> u8 {
		self.n
	}

	fn get(&self, r: u8, c: u8) -> u8 {
		self.idx(r, c).map(|i| self.data[i]).unwrap_or(0)
	}

	fn set(&mut self, r: u8, c: u8, value: u8) {
		if let Some(i) = self.idx(r, c) {
			self.data[i] = value;
		}
	}

	fn fill(&mut self, value: u8) {
		for b in &mut self.data {
			*b = value;
		}
	}
}

/// Compile-time N×N matrix of u8 flags (row-major).
///
/// The wire format bounds the dimension to 1..=255. A matrix with `N`
/// outside that range fails to compile:
///
/// ```compile_fail
/// use tightbeam::matrix::Matrix;
///
/// let rejected = Matrix::<256>::new();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matrix<const N: usize> {
	data: [[u8; N]; N],
}

impl<const N: usize> Default for Matrix<N> {
	fn default() -> Self {
		const { assert_wire_dimension::<N>() };
		Self { data: [[0u8; N]; N] }
	}
}

impl<const N: usize> Matrix<N> {
	/// Create a zero-initialized matrix.
	pub fn new() -> Self {
		Self::default()
	}

	/// Borrow a row by index.
	pub fn row(&self, r: u8) -> Option<&[u8; N]> {
		if (r as usize) < N {
			Some(&self.data[r as usize])
		} else {
			None
		}
	}
}

impl<const N: usize> MatrixLike for Matrix<N> {
	fn n(&self) -> u8 {
		N as u8
	}

	fn get(&self, r: u8, c: u8) -> u8 {
		if (r as usize) < N && (c as usize) < N {
			self.data[r as usize][c as usize]
		} else {
			0
		}
	}

	fn set(&mut self, r: u8, c: u8, value: u8) {
		if (r as usize) < N && (c as usize) < N {
			self.data[r as usize][c as usize] = value;
		}
	}

	fn fill(&mut self, value: u8) {
		for r in 0..N {
			for c in 0..N {
				self.data[r][c] = value;
			}
		}
	}
}

macro_rules! validate_n {
	($n:expr) => {
		if $n == 0 {
			return Err(MatrixError::InvalidN($n));
		}
	};
}

impl<const N: usize> TryFrom<&[u8]> for Matrix<N> {
	type Error = MatrixError;

	/// Read `N * N` row-major bytes.
	///
	/// # Errors
	///
	/// - [`MatrixError::LengthMismatch`] when the slice is not exactly `N * N`
	///   bytes. Padding or dropping bytes would move every cell after the first
	///   difference.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		const { assert_wire_dimension::<N>() };

		// The const block above bounds `N` to `1..=255`, so it fits a `u8`.
		let n = N as u8;
		if bytes.len() != N * N {
			return Err(MatrixError::LengthMismatch { n, len: bytes.len() });
		}

		let mut matrix = Self::default();
		for (row, chunk) in matrix.data.iter_mut().zip(bytes.chunks_exact(N)) {
			row.copy_from_slice(chunk);
		}

		Ok(matrix)
	}
}

impl TryFrom<u8> for MatrixDyn {
	type Error = MatrixError;
	fn try_from(n: u8) -> Result<Self, Self::Error> {
		validate_n!(n);

		let n_usize = n as usize;
		let data = vec![0u8; n_usize * n_usize];
		Ok(Self { n, data })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	#[cfg(feature = "std")]
	fn default_matrix_dyn_upholds_invariant() {
		let matrix = MatrixDyn::default();
		assert_eq!(matrix.n(), 1);
		assert_eq!(matrix.as_bytes(), &[0u8]);
		assert_eq!(matrix.get(0, 0), 0);
		assert!(matrix.row(0).is_some());
	}

	#[test]
	#[cfg(feature = "std")]
	fn a_default_matrix_is_the_smallest_valid_one() -> crate::error::Result<()> {
		let matrix = MatrixDyn::default();
		assert_eq!(matrix.n(), 1);
		assert_eq!(matrix.get(0, 0), 0);
		assert!(matrix.row(0).is_some());
		Ok(())
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_matrix_like_reality_end_to_end() -> crate::error::Result<()> {
		// Build a 3×3 from row-major bytes 0..9
		let bytes: Vec<u8> = (0u8..9u8).collect();
		let mut dyn_m = MatrixDyn::from_row_major(3, bytes.clone()).expect("n*n bytes");
		let mut stat_m = Matrix::<3>::try_from(bytes.as_slice())?;

		// Paint identity for any MatrixLike without recursion.
		fn paint_diag<M: MatrixLike>(m: &mut M) {
			let n = m.n();
			// Zero the off-diagonal cells first.
			m.clear();
			for i in 0..n {
				m.set(i, i, 1);
			}
		}

		// Check the dimensions.
		assert_eq!(dyn_m.n(), 3);
		assert_eq!(stat_m.n(), 3);

		// The row views match the source bytes.
		assert_eq!(
			dyn_m.row(1).ok_or(crate::testing::error::TestingError::InvariantViolated)?,
			&[3, 4, 5]
		);
		assert_eq!(
			stat_m
				.row(1)
				.ok_or(crate::testing::error::TestingError::InvariantViolated)?
				.as_slice(),
			&[3, 4, 5]
		);

		// Check indexing.
		assert_eq!(dyn_m.get(2, 2), 8);
		assert_eq!(stat_m.get(0, 2), 2);

		// Paint the identity on both matrices.
		paint_diag(&mut dyn_m);
		paint_diag(&mut stat_m);

		// The diagonal is 1 and every other cell is 0.
		for r in 0..3 {
			for c in 0..3 {
				let dv = dyn_m.get(r, c);
				let sv = stat_m.get(r, c);
				if r == c {
					assert_eq!(dv, 1);
					assert_eq!(sv, 1);
				} else {
					assert_eq!(dv, 0);
					assert_eq!(sv, 0);
				}
			}
		}

		// Check fill and clear.
		dyn_m.fill(7);
		for r in 0..3 {
			for c in 0..3 {
				assert_eq!(dyn_m.get(r, c), 7);
			}
		}
		dyn_m.clear();
		for r in 0..3 {
			for c in 0..3 {
				assert_eq!(dyn_m.get(r, c), 0);
			}
		}

		// Check the byte view length and the static reconstruction.
		assert_eq!(dyn_m.as_bytes().len(), 9);

		let stat_bytes = Matrix::<3>::try_from(bytes.as_slice())?;
		assert_eq!(
			stat_bytes
				.row(0)
				.ok_or(crate::testing::error::TestingError::InvariantViolated)?,
			&[0, 1, 2]
		);

		// The constructor rejects an invalid length.
		assert!(MatrixDyn::from_row_major(3, vec![0u8; 8]).is_none());

		Ok(())
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_matrix_specification_compliance() -> crate::error::Result<()> {
		// Test data for several matrix sizes.
		let test_matrices = vec![
			(1u8, vec![42u8]),
			(2u8, vec![1, 2, 3, 4]),
			(3u8, (0u8..9u8).collect()),
			(255u8, vec![0u8; 255 * 255]),
		];

		// Test 1: Wire format compliance (n ∈ [1, 255], data.len == n*n)
		for (n, data) in &test_matrices {
			let expected_len = (*n as usize) * (*n as usize);
			assert_eq!(data.len(), expected_len);

			let matrix_dyn =
				MatrixDyn::from_row_major(*n, data.clone()).expect("n*n bytes is the shape the constructor accepts");
			assert_eq!(matrix_dyn.n(), *n);
			assert_eq!(matrix_dyn.as_bytes(), data.as_slice());
		}

		// Test 2: Error handling for an invalid n (n == 0).
		let invalid_n = MatrixDyn::try_from(0u8);
		assert!(invalid_n.is_err());

		// Test 3: Error handling for a length mismatch.
		let invalid_length = MatrixDyn::from_row_major(2, vec![1, 2, 3]); // 3 != 2*2
		assert!(invalid_length.is_none());

		// Test 4: Row-major ordering is preserved.
		// The fill values are row 0 = [10, 11, 12], row 1 = [20, 21, 22], and
		// row 2 = [30, 31, 32].
		let matrix_3x3 = MatrixDyn::try_from(3u8)?;
		let mut test_matrix = matrix_3x3;
		for r in 0..3 {
			for c in 0..3 {
				let value = (r + 1) * 10 + c;
				test_matrix.set(r, c, value);
			}
		}

		// Verify row-major layout
		let expected_bytes = vec![10, 11, 12, 20, 21, 22, 30, 31, 32];
		assert_eq!(test_matrix.as_bytes(), expected_bytes.as_slice());

		// Test 5: MatrixLike trait compliance
		let mut matrix = MatrixDyn::try_from(2u8)?;

		// Test the get and set operations.
		matrix.set(0, 1, 99);
		assert_eq!(matrix.get(0, 1), 99);

		// Test out-of-bounds behavior. A get returns 0 and a set does nothing.
		assert_eq!(matrix.get(5, 5), 0);
		matrix.set(5, 5, 123); // Should be no-op

		// Test fill operation
		matrix.fill(77);
		for r in 0..2 {
			for c in 0..2 {
				assert_eq!(matrix.get(r, c), 77);
			}
		}

		// Test clear operation
		matrix.clear();
		for r in 0..2 {
			for c in 0..2 {
				assert_eq!(matrix.get(r, c), 0);
			}
		}

		// Test 6: Conversion consistency between Matrix<N> and MatrixDyn
		let static_matrix = Matrix::<3>::try_from([1, 2, 3, 4, 5, 6, 7, 8, 9].as_slice())?;
		let dynamic_matrix = MatrixDyn::from_row_major(3, vec![1, 2, 3, 4, 5, 6, 7, 8, 9])
			.ok_or(MatrixError::LengthMismatch { n: 3, len: 9 })?;
		for r in 0..3 {
			for c in 0..3 {
				assert_eq!(static_matrix.get(r, c), dynamic_matrix.get(r, c));
			}
		}

		Ok(())
	}

	/// A slice of the wrong length is refused rather than padded or cut, so
	/// no cell moves.
	#[test]
	fn a_matrix_refuses_a_slice_of_the_wrong_length() {
		let short = Matrix::<3>::try_from([0u8; 5].as_slice());
		assert!(matches!(short, Err(MatrixError::LengthMismatch { n: 3, len: 5 })));

		let long = Matrix::<3>::try_from([0u8; 10].as_slice());
		assert!(matches!(long, Err(MatrixError::LengthMismatch { n: 3, len: 10 })));
	}
}

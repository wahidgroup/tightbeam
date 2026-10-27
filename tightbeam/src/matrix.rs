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

/// The common interface of row-major N×N flag matrices with `u8` cells.
pub trait MatrixLike {
	/// Returns the dimension `N` of the N×N matrix.
	fn n(&self) -> u8;

	/// Returns the cell at row `r` and column `c`, or 0 when the cell is out of
	/// bounds.
	fn get(&self, r: u8, c: u8) -> u8;

	/// Sets the cell at row `r` and column `c` to `value`. An out-of-bounds
	/// write leaves the matrix unchanged.
	fn set(&mut self, r: u8, c: u8, value: u8);

	/// Fills every cell with `value`.
	fn fill(&mut self, value: u8);

	/// Clears every cell to zero.
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

// A `MatrixDyn` converts to itself, so the conversion always succeeds.
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

/// A runtime-sized N×N matrix of `u8` flags in row-major order.
///
/// This is the wire type for the V3 metadata matrix. Its fields are private,
/// and each constructor builds exactly `n * n` cells, so `data.len() == n * n`
/// holds for every value that exists. The DER decode runs through
/// [`MatrixDyn::from_row_major`], and `TryFrom<u8>` and `Default` fill zeros.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct MatrixDyn {
	n: u8,
	data: Vec<u8>,
}

impl Default for MatrixDyn {
	/// The smallest valid matrix (1×1, zeroed), so the `data.len() == n*n`
	/// invariant holds for every reachable value.
	fn default() -> Self {
		Self { n: 1, data: vec![0u8; 1] }
	}
}

impl MatrixDyn {
	/// Constructs a matrix from `n * n` row-major bytes.
	///
	/// The length MUST be `n * n`. A zero `n` or another length returns `None`.
	pub fn from_row_major(n: u8, bytes: impl Into<Vec<u8>>) -> Option<Self> {
		let bytes: Vec<u8> = bytes.into();
		if n == 0 {
			return None;
		}

		let n_usize = n as usize;
		if n_usize.checked_mul(n_usize) == Some(bytes.len()) {
			Some(Self { n, data: bytes })
		} else {
			None
		}
	}

	/// Defense in depth: the index checks the buffer length as well as `n`,
	/// so a value built in violation of the `data.len() == n*n` invariant
	/// cannot produce an out-of-bounds index.
	#[inline]
	fn idx(&self, r: u8, c: u8) -> Option<usize> {
		let n = self.n as usize;
		let (ru, cu) = (r as usize, c as usize);

		let index = (ru < n && cu < n).then(|| ru.checked_mul(n)?.checked_add(cu)).flatten();
		index.filter(|i| *i < self.data.len())
	}

	/// Borrows the underlying row-major bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.data
	}

	/// Borrows the underlying row-major bytes mutably.
	pub fn as_bytes_mut(&mut self) -> &mut [u8] {
		&mut self.data
	}

	/// Borrows a single row as a slice.
	pub fn row(&self, r: u8) -> Option<&[u8]> {
		if r >= self.n {
			return None;
		}

		let n = self.n as usize;
		let start = (r as usize).checked_mul(n)?;
		let end = start.checked_add(n)?;
		self.data.get(start..end)
	}
}

impl crate::der::FixedTag for MatrixDyn {
	const TAG: crate::der::Tag = crate::der::Tag::Sequence;
}

impl<'a> crate::der::DecodeValue<'a> for MatrixDyn {
	/// Reads `n` and the row-major bytes within the length of the `SEQUENCE`,
	/// then hands both to the one constructor, which owns the length check.
	fn decode_value<R: crate::der::Reader<'a>>(reader: &mut R, header: crate::der::Header) -> crate::der::Result<Self> {
		use crate::der::asn1::OctetString;
		use crate::der::Decode;

		reader.read_nested(header.length, |reader| {
			let n = u8::decode(reader)?;
			let data = OctetString::decode(reader)?;
			Self::from_row_major(n, data.as_bytes().to_vec())
				.ok_or_else(|| crate::der::ErrorKind::Length { tag: crate::der::Tag::OctetString }.into())
		})
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
		let cell = self.idx(r, c).and_then(|i| self.data.get(i));
		cell.copied().unwrap_or(0)
	}

	fn set(&mut self, r: u8, c: u8, value: u8) {
		if let Some(cell) = self.idx(r, c).and_then(|i| self.data.get_mut(i)) {
			*cell = value;
		}
	}

	fn fill(&mut self, value: u8) {
		for b in &mut self.data {
			*b = value;
		}
	}
}

/// A compile-time N×N matrix of `u8` flags in row-major order.
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
	/// Creates a zero-initialized matrix.
	pub fn new() -> Self {
		Self::default()
	}

	/// Borrows a row by index.
	pub fn row(&self, r: u8) -> Option<&[u8; N]> {
		self.data.get(r as usize)
	}
}

impl<const N: usize> MatrixLike for Matrix<N> {
	fn n(&self) -> u8 {
		N as u8
	}

	fn get(&self, r: u8, c: u8) -> u8 {
		let cell = self.data.get(r as usize).and_then(|row| row.get(c as usize));
		cell.copied().unwrap_or(0)
	}

	fn set(&mut self, r: u8, c: u8, value: u8) {
		if let Some(cell) = self.data.get_mut(r as usize).and_then(|row| row.get_mut(c as usize)) {
			*cell = value;
		}
	}

	fn fill(&mut self, value: u8) {
		self.data.as_flattened_mut().fill(value);
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

	/// Reads `N * N` row-major bytes.
	///
	/// # Errors
	///
	/// - [`MatrixError::LengthMismatch`] -- the slice is not exactly `N * N`
	///   bytes. A pad or a cut would move every cell after the first
	///   difference.
	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		const { assert_wire_dimension::<N>() };

		// The const block above bounds `N` to `1..=255`, so it fits a `u8`.
		let n = N as u8;
		if bytes.len() != const { N * N } {
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
		#[expect(
			clippy::arithmetic_side_effects,
			reason = "n is a u8, so n * n is at most 65,025"
		)]
		let data = vec![0u8; n_usize * n_usize];
		Ok(Self { n, data })
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A matrix `SEQUENCE` whose length claims no octets, ahead of the `n`
	/// and the octets of a 2 × 2 matrix of zeros.
	const MATRIX_OF_EMPTY_LENGTH: [u8; 11] = [0x30, 0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00];

	/// The decode reads within the length the `SEQUENCE` declares
	/// (X.690 § 8.1.3), so a length that holds none of the fields is refused.
	#[test]
	fn a_matrix_whose_length_holds_no_fields_is_refused() {
		let refused = <MatrixDyn as crate::der::Decode>::from_der(&MATRIX_OF_EMPTY_LENGTH);
		let refusal = refused.map_err(|error| error.kind());
		assert!(matches!(refusal, Err(crate::der::ErrorKind::Incomplete { .. })));
	}

	#[test]
	#[cfg(feature = "std")]
	fn default_matrix_dyn_upholds_invariant() {
		let matrix = MatrixDyn::default();
		assert_eq!(matrix.n(), 1);
		assert_eq!(matrix.as_bytes(), &[0u8]);
		assert_eq!(matrix.get(0, 0), 0);
		assert!(matrix.row(0).is_some());
	}

	/// A column past the dimension reads zero, not the first cell of the next
	/// row.
	#[test]
	#[cfg(feature = "std")]
	fn a_column_past_the_dimension_reads_zero() -> Result<(), MatrixError> {
		let mut matrix = MatrixDyn::try_from(2u8)?;
		matrix.set(1, 0, 5);

		assert_eq!(matrix.get(0, 2), 0);
		Ok(())
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
		// Both matrices start as a 3×3 grid of the row-major bytes 0..9.
		let bytes: Vec<u8> = (0u8..9u8).collect();
		let mut dyn_m = MatrixDyn::from_row_major(3, bytes.clone()).expect("n*n bytes");
		let mut stat_m = Matrix::<3>::try_from(bytes.as_slice())?;

		// Paint the identity on any `MatrixLike`.
		fn paint_diag<M: MatrixLike>(m: &mut M) {
			let n = m.n();
			// Clear every cell first, so each off-diagonal cell reads zero.
			m.clear();
			for i in 0..n {
				m.set(i, i, 1);
			}
		}

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

		assert_eq!(dyn_m.get(2, 2), 8);
		assert_eq!(stat_m.get(0, 2), 2);

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

	// Wire format compliance (n ∈ [1, 255], data.len == n*n), for four
	// matrix sizes from 1 to 255.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn test_matrix_wire_format_compliance((n, data): (u8, Vec<u8>)) -> crate::error::Result<()> {
			let expected_len = (n as usize) * (n as usize);
			assert_eq!(data.len(), expected_len);

			let shaped = MatrixDyn::from_row_major(n, data.clone());
			let matrix_dyn = shaped.ok_or(crate::testing::error::TestingError::InvariantViolated)?;
			assert_eq!(matrix_dyn.n(), n);
			assert_eq!(matrix_dyn.as_bytes(), data.as_slice());
			Ok(())
		}
		cases {
			one => (1u8, vec![42u8]),
			two => (2u8, vec![1, 2, 3, 4]),
			three => (3u8, (0u8..9u8).collect()),
			largest => (255u8, vec![0u8; 255 * 255]),
		}
	}

	#[test]
	#[cfg(feature = "std")]
	fn test_matrix_specification_compliance() -> crate::error::Result<()> {
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

		let expected_bytes = vec![10, 11, 12, 20, 21, 22, 30, 31, 32];
		assert_eq!(test_matrix.as_bytes(), expected_bytes.as_slice());

		// Test 5: MatrixLike trait compliance.
		let mut matrix = MatrixDyn::try_from(2u8)?;

		matrix.set(0, 1, 99);
		assert_eq!(matrix.get(0, 1), 99);

		// Out of bounds, a get returns 0 and a set leaves the matrix unchanged.
		assert_eq!(matrix.get(5, 5), 0);
		matrix.set(5, 5, 123);

		matrix.fill(77);
		for r in 0..2 {
			for c in 0..2 {
				assert_eq!(matrix.get(r, c), 77);
			}
		}

		matrix.clear();
		for r in 0..2 {
			for c in 0..2 {
				assert_eq!(matrix.get(r, c), 0);
			}
		}

		// Test 6: Conversion consistency between Matrix<N> and MatrixDyn.
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

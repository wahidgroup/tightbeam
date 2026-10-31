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

/// A fixed-size matrix converts into the wire type cell for cell, so it goes
/// into a frame through [`IntoMatrixDyn`].
///
/// ```
/// use tightbeam::matrix::{Matrix, MatrixDyn, MatrixLike};
///
/// let mut fixed = Matrix::<2>::default();
/// fixed.set(1, 0, 4);
///
/// let carried = MatrixDyn::try_from(&fixed)?;
/// assert_eq!(carried.as_bytes(), &[0, 0, 4, 0]);
/// # Ok::<(), tightbeam::matrix::MatrixError>(())
/// ```
impl<const N: usize> TryFrom<&Matrix<N>> for MatrixDyn {
	type Error = MatrixError;

	/// Copies the `N * N` cells of `matrix` in row-major order.
	///
	/// # Errors
	///
	/// The copy returns `Ok` for every `Matrix<N>`, because a dimension outside
	/// `1..=255` fails to compile.
	fn try_from(matrix: &Matrix<N>) -> Result<Self, Self::Error> {
		const { assert_wire_dimension::<N>() };

		// The const block above bounds `N` to `1..=255`, so it fits a `u8`.
		let n = N as u8;
		let data = matrix.data.as_flattened().to_vec();
		Ok(Self { n, data })
	}
}

impl<const N: usize> TryFrom<Matrix<N>> for MatrixDyn {
	type Error = MatrixError;

	/// Copies the `N * N` cells of `matrix` in row-major order, as the
	/// conversion of a `&Matrix<N>` does.
	fn try_from(matrix: Matrix<N>) -> Result<Self, Self::Error> {
		Self::try_from(&matrix)
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
	use crate::testing::TestResult;

	use super::*;

	/// A matrix `SEQUENCE` whose length claims no octets, ahead of the `n`
	/// and the octets of a 2 × 2 matrix of zeros.
	const MATRIX_OF_EMPTY_LENGTH: [u8; 11] = [0x30, 0x00, 0x02, 0x01, 0x02, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00];

	/// The row-major octets 0 to 8 that each 3 × 3 matrix of the tests starts
	/// from.
	const COUNTING: [u8; 9] = [0, 1, 2, 3, 4, 5, 6, 7, 8];

	/// A 3 × 3 dynamic matrix of [`COUNTING`].
	fn counting_dyn() -> MatrixDyn {
		MatrixDyn::from_row_major(3, COUNTING).expect("nine octets fill a 3 × 3 matrix")
	}

	/// A 3 × 3 static matrix of [`COUNTING`].
	fn counting_static() -> Matrix<3> {
		Matrix::<3>::try_from(COUNTING.as_slice()).expect("nine octets fill a 3 × 3 matrix")
	}

	/// A 2 × 2 dynamic matrix of the octets 1 to 4.
	fn two_by_two() -> MatrixDyn {
		MatrixDyn::from_row_major(2, [1, 2, 3, 4]).expect("four octets fill a 2 × 2 matrix")
	}

	/// The cells of `matrix`, read through [`MatrixLike::get`] in row-major
	/// order.
	fn cells(matrix: &dyn MatrixLike) -> Vec<u8> {
		let n = matrix.n();
		let positions = (0..n).flat_map(|row| (0..n).map(move |col| (row, col)));
		positions.map(|(row, col)| matrix.get(row, col)).collect()
	}

	/// The cells of `matrix` after a clear and a set of 1 on each cell of its
	/// diagonal.
	fn painted_identity(mut matrix: Box<dyn MatrixLike>) -> Vec<u8> {
		matrix.clear();
		for index in 0..matrix.n() {
			matrix.set(index, index, 1);
		}

		cells(matrix.as_ref())
	}

	/// Writes each `(row, column, value)` of `writes` into `matrix`, in order.
	fn set_cells(matrix: &mut dyn MatrixLike, writes: &[(u8, u8, u8)]) {
		for &(row, col, value) in writes {
			matrix.set(row, col, value);
		}
	}

	/// The decode reads within the length the `SEQUENCE` declares
	/// (X.690 § 8.1.3), so a length that holds none of the fields is refused
	/// where the body ends, at octet 2, short of the octet 3 that the first
	/// field needs.
	#[test]
	fn a_matrix_whose_length_holds_no_fields_is_refused() {
		let refused = <MatrixDyn as crate::der::Decode>::from_der(&MATRIX_OF_EMPTY_LENGTH);
		let refusal = refused.map_err(|error| error.kind());
		let incomplete = crate::der::ErrorKind::Incomplete { expected_len: 3u8.into(), actual_len: 2u8.into() };
		assert_eq!(refusal, Err(incomplete));
	}

	/// The default matrix is the smallest valid one: one row of one zero cell.
	#[test]
	#[cfg(feature = "std")]
	fn a_default_matrix_is_the_smallest_valid_one() {
		let matrix = MatrixDyn::default();
		assert_eq!(matrix.n(), 1);
		assert_eq!(matrix.as_bytes(), &[0u8]);
		assert_eq!(matrix.get(0, 0), 0);
		assert_eq!(matrix.row(0), Some(&[0u8][..]));
	}

	// A cell past the dimension reads zero, not the cell that its flat index
	// reaches in a later row. The flat index of (0, 2) reaches the 5 at (1, 0).
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn a_cell_past_the_dimension_reads_zero((row, col): (u8, u8)) -> TestResult {
			let mut matrix = MatrixDyn::try_from(2u8)?;
			matrix.set(1, 0, 5);

			assert_eq!(matrix.get(row, col), 0);
			Ok(())
		}
		cases {
			column => (0, 2),
			row_and_column => (5, 5),
		}
	}

	// A matrix of each kind reports the dimension it was built at.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn a_matrix_reports_its_dimension(matrix: Box<dyn MatrixLike>) {
			assert_eq!(matrix.n(), 3);
		}
		cases {
			dynamic => Box::new(counting_dyn()),
			fixed => Box::new(counting_static()),
		}
	}

	// A matrix of each kind reads back, cell by cell, the row-major octets it
	// was built from, so the two kinds agree on every cell.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn every_cell_reads_its_row_major_octet(matrix: Box<dyn MatrixLike>) {
			assert_eq!(cells(matrix.as_ref()), COUNTING);
		}
		cases {
			dynamic => Box::new(counting_dyn()),
			fixed => Box::new(counting_static()),
		}
	}

	// A row view of a dynamic matrix borrows the cells of that row.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn a_dynamic_row_view_borrows_its_cells((row, expected): (u8, [u8; 3])) {
			assert_eq!(counting_dyn().row(row), Some(expected.as_slice()));
		}
		cases {
			first => (0, [0, 1, 2]),
			second => (1, [3, 4, 5]),
		}
	}

	// A row view of a static matrix borrows the cells of that row.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn a_static_row_view_borrows_its_cells((row, expected): (u8, [u8; 3])) {
			assert_eq!(counting_static().row(row), Some(&expected));
		}
		cases {
			first => (0, [0, 1, 2]),
			second => (1, [3, 4, 5]),
		}
	}

	// The identity painted on a matrix of each kind holds 1 on the diagonal
	// and 0 in every other cell.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn painting_the_identity_clears_every_cell_off_the_diagonal(matrix: Box<dyn MatrixLike>) {
			assert_eq!(painted_identity(matrix), [1, 0, 0, 0, 1, 0, 0, 0, 1]);
		}
		cases {
			dynamic => Box::new(counting_dyn()),
			fixed => Box::new(counting_static()),
		}
	}

	// A fill writes its value into every cell.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn fill_sets_every_cell((build, value, filled): (fn() -> MatrixDyn, u8, Vec<u8>)) {
			let mut matrix = build();
			matrix.fill(value);
			assert_eq!(matrix.as_bytes(), filled);
		}
		cases {
			three_sevens => (counting_dyn, 7, vec![7; 9]),
			two_seventy_sevens => (two_by_two, 77, vec![77; 4]),
		}
	}

	// A clear writes zero into every cell.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn clear_zeroes_every_cell((build, zeroed): (fn() -> MatrixDyn, Vec<u8>)) {
			let mut matrix = build();
			matrix.clear();
			assert_eq!(matrix.as_bytes(), zeroed);
		}
		cases {
			three => (counting_dyn, vec![0; 9]),
			two => (two_by_two, vec![0; 4]),
		}
	}

	// A matrix of each `n` in 1 to 255 holds the n × n row-major octets it is
	// given, so its wire form keeps `data.len() == n * n`.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn a_matrix_holds_its_n_squared_row_major_octets((n, data): (u8, Vec<u8>)) {
			let matrix = MatrixDyn::from_row_major(n, data.as_slice());
			let held = matrix.as_ref().map(|matrix| (matrix.n(), matrix.as_bytes()));
			assert_eq!(held, Some((n, data.as_slice())));
		}
		cases {
			one => (1, vec![42]),
			two => (2, vec![1, 2, 3, 4]),
			three => (3, COUNTING.to_vec()),
			largest => (255, vec![0; 65_025]),
		}
	}

	// The constructor refuses a length other than n × n.
	#[cfg(feature = "std")]
	crate::tb_cases! {
		fn from_row_major_refuses_a_length_other_than_n_squared((n, data): (u8, Vec<u8>)) {
			assert_eq!(MatrixDyn::from_row_major(n, data), None);
		}
		cases {
			three_by_eight => (3, vec![0; 8]),
			two_by_three => (2, vec![1, 2, 3]),
		}
	}

	/// A matrix of dimension zero holds no cell, so the conversion refuses it.
	#[test]
	fn a_matrix_of_n_zero_is_refused() {
		assert_eq!(MatrixDyn::try_from(0u8), Err(MatrixError::InvalidN(0)));
	}

	/// A set writes each cell at its row-major position.
	#[test]
	#[cfg(feature = "std")]
	fn set_writes_row_major() -> TestResult {
		let mut matrix = MatrixDyn::try_from(3u8)?;
		let writes = [
			(0, 0, 10),
			(0, 1, 11),
			(0, 2, 12),
			(1, 0, 20),
			(1, 1, 21),
			(1, 2, 22),
			(2, 0, 30),
			(2, 1, 31),
			(2, 2, 32),
		];

		set_cells(&mut matrix, &writes);

		assert_eq!(matrix.as_bytes(), [10, 11, 12, 20, 21, 22, 30, 31, 32]);
		Ok(())
	}

	/// A get reads the value that a set wrote to the same cell.
	#[test]
	#[cfg(feature = "std")]
	fn get_reads_what_set_wrote() -> TestResult {
		let mut matrix = MatrixDyn::try_from(2u8)?;
		matrix.set(0, 1, 99);
		assert_eq!(matrix.get(0, 1), 99);
		Ok(())
	}

	/// A set past the dimension leaves every cell as it was.
	#[test]
	#[cfg(feature = "std")]
	fn an_out_of_bounds_set_leaves_the_matrix_unchanged() {
		let mut matrix = two_by_two();
		matrix.set(5, 5, 123);
		assert_eq!(matrix.as_bytes(), [1, 2, 3, 4]);
	}

	// A slice of the wrong length is refused rather than padded or cut, so no
	// cell moves.
	crate::tb_cases! {
		fn a_matrix_refuses_a_slice_of_the_wrong_length(len: usize) {
			let refused = Matrix::<3>::try_from(&[0u8; 10][..len]);
			assert_eq!(refused, Err(MatrixError::LengthMismatch { n: 3, len }));
		}
		cases {
			short => 5,
			long => 10,
		}
	}

	/// A fixed-size matrix composes into a V3 frame, which carries its cells
	/// in row-major order.
	#[test]
	#[cfg(all(feature = "builder", feature = "testing"))]
	fn a_fixed_size_matrix_composes_into_a_v3_frame() -> TestResult {
		let mut matrix = Matrix::<3>::default();
		matrix.set(0, 1, 2);
		matrix.set(2, 0, 7);

		let message = crate::testing::TestMessage::sample(None);
		let frame = compose! { V3: id: "fixed", order: 1, message: message, matrix: matrix }?;

		let carried = frame.metadata().matrix().map(MatrixDyn::as_bytes);
		assert_eq!(carried, Some(&[0, 2, 0, 0, 0, 0, 7, 0, 0][..]));
		Ok(())
	}
}

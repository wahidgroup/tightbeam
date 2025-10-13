use crate::{Asn1Matrix, Errorizable};

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum MatrixError {
	#[cfg_attr(feature = "derive", error("Asn1Matrix: n MUST be in 1..=255 (got {0})"))]
	InvalidN(u8),
	#[cfg_attr(
		feature = "derive",
		error("Asn1Matrix: data length MUST equal n*n (n={n}, len={len})")
	)]
	LengthMismatch { n: u8, len: usize },
}

#[cfg(all(not(feature = "derive")))]
impl core::fmt::Display for MatrixError {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			MatrixError::InvalidN(n) => write!(f, "Asn1Matrix: n MUST be in 1..=255 (got {n})"),
			MatrixError::LengthMismatch { n, len } => {
				write!(f, "Asn1Matrix: data length MUST equal n*n (n={n}, len={len})")
			}
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for MatrixError {}

/// A common interface for NxN flag matrices (u8 cells), row-major.
pub trait MatrixLike {
	/// Dimension N (matrix is N×N).
	fn n(&self) -> u8;

	/// Get cell (row r, col c). Out-of-bounds returns 0.
	fn get(&self, r: u8, c: u8) -> u8;

	/// Set cell (row r, col c) to value. Out-of-bounds is a no-op.
	fn set(&mut self, r: u8, c: u8, value: u8);

	/// Fill all cells with value.
	fn fill(&mut self, value: u8);

	/// Clear all cells to zero.
	fn clear(&mut self) {
		self.fill(0);
	}
}

/// Runtime-sized N×N matrix of u8 flags (row-major).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatrixDyn {
	n: u8,
	data: Vec<u8>,
}

impl Default for MatrixDyn {
	fn default() -> Self {
		Self { n: 1, data: Vec::new() }
	}
}

impl MatrixDyn {
	/// Construct from row-major bytes. Length MUST be n*n.
	pub fn from_row_major(n: u8, bytes: Vec<u8>) -> Option<Self> {
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

	#[inline]
	fn idx(&self, r: u8, c: u8) -> Option<usize> {
		let n = self.n as usize;
		let (ru, cu) = (r as usize, c as usize);
		if ru < n && cu < n {
			Some(ru * n + cu)
		} else {
			None
		}
	}

	/// Borrow the underlying row-major bytes.
	pub fn as_bytes(&self) -> &[u8] {
		&self.data
	}

	/// Mutable borrow of row-major bytes.
	pub fn as_bytes_mut(&mut self) -> &mut [u8] {
		&mut self.data
	}

	/// Borrow a single row as a slice.
	pub fn row(&self, r: u8) -> Option<&[u8]> {
		let n = self.n as u8;
		if r >= n {
			return None;
		}
		let start = (r * n) as usize;
		Some(&self.data[start..start + n as usize])
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Matrix<const N: usize> {
	data: [[u8; N]; N],
}

impl<const N: usize> Default for Matrix<N> {
	fn default() -> Self {
		Self { data: [[0u8; N]; N] }
	}
}

impl<const N: usize> Matrix<N> {
	/// Create a zero-initialized matrix.
	pub fn new() -> Self {
		Self::default()
	}

	/// Construct from row-major bytes; extra bytes are ignored, missing are zeroed.
	pub fn from_row_major(bytes: &[u8]) -> Self {
		let mut m = Self::default();
		let mut i = 0usize;
		for r in 0..N {
			for c in 0..N {
				if i < bytes.len() {
					m.data[r][c] = bytes[i];
				}
				i += 1;
			}
		}
		m
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
				self.data[r as usize][c as usize] = value;
			}
		}
	}
}

impl TryFrom<Asn1Matrix> for MatrixDyn {
	type Error = MatrixError;
	fn try_from(m: Asn1Matrix) -> Result<Self, Self::Error> {
		let n = m.n;
		if n == 0 {
			return Err(MatrixError::InvalidN(n));
		}

		let mut m = m;
		let data = core::mem::take(&mut m.data);
		let n2 = (n * n) as usize;
		if data.len() != n2 {
			return Err(MatrixError::LengthMismatch { n, len: data.len() });
		}

		MatrixDyn::from_row_major(n, data).ok_or(MatrixError::LengthMismatch { n, len: n2 })
	}
}

impl TryFrom<&Asn1Matrix> for MatrixDyn {
	type Error = MatrixError;
	fn try_from(m: &Asn1Matrix) -> Result<Self, Self::Error> {
		let n = m.n;
		if n == 0 {
			return Err(MatrixError::InvalidN(n));
		}
		
		let n_u8 = n as u8;
		let n2 = (n_u8 * n_u8) as usize;
		if m.data.len() != n2 {
			return Err(MatrixError::LengthMismatch { n, len: m.data.len() });
		}

		let mut md = MatrixDyn::try_from(n)?;
		let mut i = 0usize;
		for r in 0..n_u8 {
			for c in 0..n_u8 {
				md.set(r as u8, c as u8, m.data[i]);
				i += 1;
			}
		}
		Ok(md)
	}
}

impl TryFrom<Option<Asn1Matrix>> for MatrixDyn {
	type Error = MatrixError;
	fn try_from(m: Option<Asn1Matrix>) -> Result<Self, Self::Error> {
		match m {
			Some(m) => Self::try_from(m),
			None => Ok(Default::default()),
		}
	}
}

impl TryFrom<u8> for MatrixDyn {
	type Error = MatrixError;
	fn try_from(n: u8) -> Result<Self, Self::Error> {
		if n == 0 {
			return Err(MatrixError::InvalidN(n));
		}

		let n_usize = n as usize;
		let data = vec![0u8; n_usize * n_usize];
		Ok(Self { n, data })
	}
}

impl TryFrom<MatrixDyn> for Asn1Matrix {
    type Error = crate::matrix::MatrixError;
    
    fn try_from(matrix: MatrixDyn) -> Result<Self, Self::Error> {
        let n = matrix.n();
        if n == 0 {
            return Err(crate::matrix::MatrixError::InvalidN(n));
        }

        let mut data = Vec::with_capacity((n as usize) * (n as usize));
        for r in 0..n {
            for c in 0..n {
                data.push(matrix.get(r, c));
            }
        }
        Ok(Self { n, data })
    }
}

#[cfg(test)]
mod tests {
	use super::*;

	crate::test_case! {
		name: test_matrixlike_reality_end_to_end,
		features: ["std"],
		setup: || {
			// Build a 3×3 from row-major bytes 0..9
			let bytes: Vec<u8> = (0u8..9u8).collect();
			let dyn_ok = MatrixDyn::from_row_major(3, bytes.clone()).expect("n*n bytes");
			let stat_ok: Matrix<3> = Matrix::<3>::from_row_major(&bytes);
			(dyn_ok, stat_ok, bytes)
		},
		assertions: |triple| {
			let (mut dyn_m, mut stat_m, bytes) = triple;

			// Paint identity for any MatrixLike without recursion.
			fn paint_diag<M: MatrixLike>(m: &mut M) {
				let n = m.n();
				// Ensure non-diagonal cells are zeroed
				m.clear();
				for i in 0..n {
					m.set(i, i, 1);
				}
			}

			// Dimensions
			assert_eq!(dyn_m.n(), 3);
			assert_eq!(stat_m.n(), 3);

			// Row views match source bytes
			assert_eq!(dyn_m.row(1).unwrap(), &[3, 4, 5]);
			assert_eq!(stat_m.row(1).unwrap().as_slice(), &[3, 4, 5]);

			// Indexing
			assert_eq!(dyn_m.get(2, 2), 8);
			assert_eq!(stat_m.get(0, 2), 2);

			// Paint identity on both
			paint_diag(&mut dyn_m);
			paint_diag(&mut stat_m);

			// Validate diagonal = 1, others = 0
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

			// Fill and clear
			dyn_m.fill(7);
			for r in 0..3 { for c in 0..3 { assert_eq!(dyn_m.get(r, c), 7); } }
			dyn_m.clear();
			for r in 0..3 { for c in 0..3 { assert_eq!(dyn_m.get(r, c), 0); } }

			// Byte view length and static reconstruction
			assert_eq!(dyn_m.as_bytes().len(), 9);
			let stat_bytes = Matrix::<3>::from_row_major(&bytes);
			assert_eq!(stat_bytes.row(0).unwrap(), &[0, 1, 2]);

			// Invalid constructor length rejected
			assert!(MatrixDyn::from_row_major(3, vec![0u8; 8]).is_none());

			Ok(())
		}
	}
}

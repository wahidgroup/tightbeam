use tightbeam::matrix::{Matrix, MatrixLike};

/// Enumeration of all fault types supported by the rover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultType {
	/// Low battery/power fault - Resolves after recharged
	LowPower,
	/// Communications system fault - Resolves after retry
	Communications,
	/// Thermal anomaly - Resolves after random time
	Thermal,
}

impl FaultType {
	/// Get the matrix cell coordinates for this fault type.
	/// Returns (row, col) tuple.
	fn matrix_coords(&self) -> (u8, u8) {
		match self {
			FaultType::LowPower => (0, 0),
			FaultType::Communications => (0, 1),
			FaultType::Thermal => (0, 2),
		}
	}

	/// Get all fault types as an iterator.
	pub fn all() -> impl Iterator<Item = FaultType> {
		[FaultType::LowPower, FaultType::Communications, FaultType::Thermal]
			.iter()
			.copied()
	}
}

/// Encapsulates rover fault state and telemetry in a 3x3 matrix representation.
///
/// Matrix layout:
/// - Cell [0,0]: Low Power fault (0=inactive, 1=active)
/// - Cell [0,1]: Communications fault (0=inactive, 1=active)  
/// - Cell [0,2]: Thermal fault (0=inactive, 1=active)
/// - Cell [1,0]: Battery percentage (0-100)
/// - Remaining cells: Reserved for future use
///
/// This provides a clean abstraction for encoding fault flags and telemetry into
/// the Frame.matrix field while maintaining separation of concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrix {
	matrix: Matrix<3>,
}

impl FaultMatrix {
	/// Create a new FaultMatrix with no faults.
	pub fn new() -> Self {
		Self { matrix: Matrix::<3>::new() }
	}

	/// Check if any fault is active.
	pub fn has_fault(&self) -> bool {
		FaultType::all().any(|ft| self.is_fault_active(ft))
	}

	/// Check if a specific fault type is active.
	pub fn is_fault_active(&self, fault_type: FaultType) -> bool {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.get(r, c) != 0
	}

	/// Set a specific fault type to active.
	pub fn set_fault(&mut self, fault_type: FaultType) {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.set(r, c, 1);
	}

	/// Clear a specific fault type (set to inactive).
	pub fn clear_fault(&mut self, fault_type: FaultType) {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.set(r, c, 0);
	}

	/// Get all active faults as an iterator.
	pub fn active_faults(&self) -> impl Iterator<Item = FaultType> + '_ {
		FaultType::all().filter(move |&ft| self.is_fault_active(ft))
	}

	/// Clear all faults.
	pub fn clear_all(&mut self) {
		self.matrix.clear();
	}

	/// Get the underlying matrix for inspection.
	pub fn as_matrix(&self) -> &Matrix<3> {
		&self.matrix
	}

	/// Set battery percentage (0-100).
	/// Stored in cell [1,0] of the matrix.
	pub fn set_battery_percent(&mut self, percent: u8) {
		self.matrix.set(1, 0, percent.min(100));
	}

	/// Get battery percentage (0-100).
	/// Retrieved from cell [1,0] of the matrix.
	pub fn battery_percent(&self) -> u8 {
		self.matrix.get(1, 0)
	}
}

impl Default for FaultMatrix {
	fn default() -> Self {
		Self::new()
	}
}

/// Convert FaultMatrix to Matrix<3> for frame composition.
impl From<FaultMatrix> for Matrix<3> {
	fn from(fault: FaultMatrix) -> Self {
		fault.matrix
	}
}

/// Extract FaultMatrix from Matrix<3>.
impl From<Matrix<3>> for FaultMatrix {
	fn from(matrix: Matrix<3>) -> Self {
		Self { matrix }
	}
}

/// Extract FaultMatrix from &Matrix<3>.
impl From<&Matrix<3>> for FaultMatrix {
	fn from(matrix: &Matrix<3>) -> Self {
		Self { matrix: *matrix }
	}
}

/// Convert FaultMatrix to MatrixDyn for frame composition.
impl TryFrom<FaultMatrix> for tightbeam::matrix::MatrixDyn {
	type Error = tightbeam::TightBeamError;

	fn try_from(fault: FaultMatrix) -> Result<Self, Self::Error> {
		let matrix_3: Matrix<3> = fault.into();
		let n = 3u8;
		let mut data = Vec::with_capacity(9);
		for r in 0..n {
			for c in 0..n {
				data.push(matrix_3.get(r, c));
			}
		}
		tightbeam::matrix::MatrixDyn::from_row_major(n, data).ok_or_else(|| tightbeam::TightBeamError::InvalidBody)
	}
}

/// Extract FaultMatrix from Option<Asn1Matrix> (from frame metadata).
impl TryFrom<&Option<tightbeam::Asn1Matrix>> for FaultMatrix {
	type Error = tightbeam::TightBeamError;

	fn try_from(matrix_opt: &Option<tightbeam::Asn1Matrix>) -> Result<Self, Self::Error> {
		match matrix_opt {
			Some(asn1_matrix) if asn1_matrix.n == 3 => {
				// Convert Asn1Matrix to Matrix<3>
				use tightbeam::matrix::MatrixDyn;
				let matrix_dyn = MatrixDyn::try_from(asn1_matrix)?;

				// Create Matrix<3> from row-major data
				let mut matrix = Matrix::<3>::new();
				for r in 0..3 {
					for c in 0..3 {
						matrix.set(r, c, matrix_dyn.get(r, c));
					}
				}

				Ok(Self { matrix })
			}
			Some(_) => Ok(Self::new()), // Ignore non-3x3 matrices
			None => Ok(Self::new()),    // No matrix = no faults
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_fault_matrix_operations() {
		let mut fm = FaultMatrix::new();
		assert!(!fm.has_fault());

		// Test setting individual faults
		fm.set_fault(FaultType::LowPower);
		assert!(fm.has_fault());
		assert!(fm.is_fault_active(FaultType::LowPower));
		assert!(!fm.is_fault_active(FaultType::Communications));
		assert!(!fm.is_fault_active(FaultType::Thermal));

		fm.set_fault(FaultType::Communications);
		assert!(fm.is_fault_active(FaultType::LowPower));
		assert!(fm.is_fault_active(FaultType::Communications));
		assert!(!fm.is_fault_active(FaultType::Thermal));

		// Test clearing individual faults
		fm.clear_fault(FaultType::LowPower);
		assert!(!fm.is_fault_active(FaultType::LowPower));
		assert!(fm.is_fault_active(FaultType::Communications));

		fm.set_fault(FaultType::Thermal);
		assert!(fm.is_fault_active(FaultType::Communications));
		assert!(fm.is_fault_active(FaultType::Thermal));

		// Test clear all
		fm.clear_all();
		assert!(!fm.has_fault());
	}

	#[test]
	fn test_fault_type_enum() {
		let mut fm = FaultMatrix::new();

		// Test enum-based API
		fm.set_fault(FaultType::LowPower);
		assert!(fm.is_fault_active(FaultType::LowPower));
		assert!(!fm.is_fault_active(FaultType::Communications));

		fm.set_fault(FaultType::Communications);
		fm.set_fault(FaultType::Thermal);

		// Test active_faults iterator
		let active: Vec<FaultType> = fm.active_faults().collect();
		assert_eq!(active.len(), 3);
		assert!(active.contains(&FaultType::LowPower));
		assert!(active.contains(&FaultType::Communications));
		assert!(active.contains(&FaultType::Thermal));

		// Clear one fault
		fm.clear_fault(FaultType::Communications);
		let active: Vec<FaultType> = fm.active_faults().collect();
		assert_eq!(active.len(), 2);
		assert!(!active.contains(&FaultType::Communications));
	}

	#[test]
	fn test_matrix_conversion() {
		let mut fm = FaultMatrix::new();
		fm.set_fault(FaultType::LowPower);
		fm.set_fault(FaultType::Thermal);

		// Convert to Matrix<3>
		let matrix: Matrix<3> = fm.into();
		assert_eq!(matrix.get(0, 0), 1); // LowPower
		assert_eq!(matrix.get(0, 1), 0); // Communications (not set)
		assert_eq!(matrix.get(0, 2), 1); // Thermal

		// Convert back
		let fm2 = FaultMatrix::from(matrix);
		assert_eq!(fm, fm2);
	}

	#[test]
	fn test_fault_independence() {
		let mut fm = FaultMatrix::new();

		// Setting one fault should not affect others
		fm.set_fault(FaultType::LowPower);
		assert!(fm.is_fault_active(FaultType::LowPower));
		assert!(!fm.is_fault_active(FaultType::Communications));
		assert!(!fm.is_fault_active(FaultType::Thermal));

		fm.set_fault(FaultType::Thermal);
		assert!(fm.is_fault_active(FaultType::LowPower));
		assert!(!fm.is_fault_active(FaultType::Communications));
		assert!(fm.is_fault_active(FaultType::Thermal));

		// Clearing one fault should not affect others
		fm.clear_fault(FaultType::LowPower);
		assert!(!fm.is_fault_active(FaultType::LowPower));
		assert!(!fm.is_fault_active(FaultType::Communications));
		assert!(fm.is_fault_active(FaultType::Thermal));
	}
}

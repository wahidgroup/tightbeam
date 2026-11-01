use tightbeam::matrix::{Matrix, MatrixLike};

/// A fault of the rover, which raises one flag of a [`FaultMatrix`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultType {
	/// The battery charge is low. The fault clears once the battery is full.
	LowPower,
	/// The communications system has failed.
	Communications,
	/// The rover reads a thermal anomaly.
	Thermal,
}

impl FaultType {
	/// The cell of the flag of this fault, as its row and its column.
	fn matrix_coords(&self) -> (u8, u8) {
		match self {
			FaultType::LowPower => (0, 0),
			FaultType::Communications => (0, 1),
			FaultType::Thermal => (0, 2),
		}
	}

	/// Each fault, in the order of its column in the matrix.
	pub fn all() -> impl Iterator<Item = FaultType> {
		[FaultType::LowPower, FaultType::Communications, FaultType::Thermal]
			.iter()
			.copied()
	}
}

/// The fault flags and the battery charge of the rover, in a 3x3 matrix.
///
/// Matrix layout:
/// - Cell [0,0]: Low Power fault (0=inactive, 1=active)
/// - Cell [0,1]: Communications fault (0=inactive, 1=active)
/// - Cell [0,2]: Thermal fault (0=inactive, 1=active)
/// - Cell [1,0]: Battery percentage (0-100)
/// - Remaining cells: 0
///
/// The type encodes the fault flags and the telemetry into the `matrix` field
/// of a Frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaultMatrix {
	matrix: Matrix<3>,
}

impl FaultMatrix {
	/// A matrix with no fault flag raised.
	pub fn new() -> Self {
		Self { matrix: Matrix::<3>::new() }
	}

	/// Whether any fault flag is raised.
	pub fn has_fault(&self) -> bool {
		FaultType::all().any(|ft| self.is_fault_active(ft))
	}

	/// Whether the flag of `fault_type` is raised.
	pub fn is_fault_active(&self, fault_type: FaultType) -> bool {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.get(r, c) != 0
	}

	/// Raises the flag of `fault_type`.
	pub fn set_fault(&mut self, fault_type: FaultType) {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.set(r, c, 1);
	}

	/// Lowers the flag of `fault_type`.
	pub fn clear_fault(&mut self, fault_type: FaultType) {
		let (r, c) = fault_type.matrix_coords();
		self.matrix.set(r, c, 0);
	}

	/// The faults whose flags are raised, in the order of [`FaultType::all`].
	pub fn active_faults(&self) -> impl Iterator<Item = FaultType> + '_ {
		FaultType::all().filter(move |&ft| self.is_fault_active(ft))
	}

	/// Clears every cell, so each flag is lowered and the battery charge is 0.
	pub fn clear_all(&mut self) {
		self.matrix.clear();
	}

	/// The matrix that holds the flags and the battery charge.
	pub fn as_matrix(&self) -> &Matrix<3> {
		&self.matrix
	}

	/// Sets the battery charge in cell [1,0], capped at 100 percent.
	pub fn set_battery_percent(&mut self, percent: u8) {
		self.matrix.set(1, 0, percent.min(100));
	}

	/// The battery charge in cell [1,0], in percent.
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
		let matrix_dyn = tightbeam::matrix::MatrixDyn::try_from(matrix_3)?;
		Ok(matrix_dyn)
	}
}

/// Extract FaultMatrix from the metadata matrix.
impl TryFrom<&Option<tightbeam::matrix::MatrixDyn>> for FaultMatrix {
	type Error = tightbeam::TightBeamError;

	fn try_from(matrix_opt: &Option<tightbeam::matrix::MatrixDyn>) -> Result<Self, Self::Error> {
		match matrix_opt {
			Some(wire_matrix) if wire_matrix.n() == 3 => {
				let mut matrix = Matrix::<3>::new();
				for r in 0..3 {
					for c in 0..3 {
						matrix.set(r, c, wire_matrix.get(r, c));
					}
				}

				Ok(Self { matrix })
			}
			// A matrix of another size holds no flag.
			Some(_) => Ok(Self::new()),
			// A frame with no matrix holds no fault.
			None => Ok(Self::new()),
		}
	}
}

mod tests {
	use tightbeam::tb_cases;

	use super::*;
	use crate::common::result::TestResult;

	/// A matrix with every fault raised.
	fn all_raised() -> FaultMatrix {
		let mut fm = FaultMatrix::new();
		for fault in FaultType::all() {
			fm.set_fault(fault);
		}

		fm
	}

	/// A matrix that raised every fault, then cleared them all.
	fn cleared_all() -> FaultMatrix {
		let mut fm = all_raised();
		fm.clear_all();
		fm
	}

	// Setting a fault on a fresh matrix raises the flag of that fault alone.
	tb_cases! {
		fn setting_a_fault_raises_its_flag_alone(fault: FaultType) {
			let mut fm = FaultMatrix::new();
			fm.set_fault(fault);
			assert_eq!(fm.active_faults().collect::<Vec<_>>(), [fault]);
		}
		cases {
			low_power => FaultType::LowPower,
			communications => FaultType::Communications,
			thermal => FaultType::Thermal,
		}
	}

	// Clearing a fault on a matrix with every fault raised lowers the flag of
	// that fault alone, and the others stay in the order of `FaultType::all`.
	tb_cases! {
		fn clearing_a_fault_lowers_its_flag_alone((fault, left): (FaultType, Vec<FaultType>)) {
			let mut fm = all_raised();
			fm.clear_fault(fault);
			assert_eq!(fm.active_faults().collect::<Vec<_>>(), left);
		}
		cases {
			low_power => (FaultType::LowPower, vec![FaultType::Communications, FaultType::Thermal]),
			communications => (FaultType::Communications, vec![FaultType::LowPower, FaultType::Thermal]),
			thermal => (FaultType::Thermal, vec![FaultType::LowPower, FaultType::Communications]),
		}
	}

	// A matrix that raises no flag holds no fault.
	tb_cases! {
		fn a_matrix_with_no_raised_flag_holds_no_fault(matrix: FaultMatrix) {
			assert!(!matrix.has_fault());
		}
		cases {
			fresh => FaultMatrix::new(),
			cleared_all => cleared_all(),
		}
	}

	// The flag of a fault sits at its cell of the matrix layout, and every
	// other cell holds 0. Each row names the nine cells in row-major order.
	tb_cases! {
		fn a_fault_flag_sits_at_its_matrix_cell((fault, cells): (FaultType, [u8; 9])) -> TestResult {
			let expected = Matrix::<3>::try_from(cells.as_slice())?;
			let mut fm = FaultMatrix::new();
			fm.set_fault(fault);

			let matrix = Matrix::<3>::from(fm);
			assert_eq!(matrix, expected);
			Ok(())
		}
		cases {
			low_power => (FaultType::LowPower, [1, 0, 0, 0, 0, 0, 0, 0, 0]),
			communications => (FaultType::Communications, [0, 1, 0, 0, 0, 0, 0, 0, 0]),
			thermal => (FaultType::Thermal, [0, 0, 1, 0, 0, 0, 0, 0, 0]),
		}
	}

	/// A fault matrix round trips through the dynamic matrix that a frame
	/// carries, with its raised flags intact.
	#[test]
	fn a_fault_matrix_round_trips_through_its_matrix() -> TestResult {
		let mut fm = FaultMatrix::new();
		fm.set_fault(FaultType::LowPower);
		fm.set_fault(FaultType::Thermal);

		let carried = Some(tightbeam::matrix::MatrixDyn::try_from(fm)?);
		let round_trip = FaultMatrix::try_from(&carried)?;
		let raised: Vec<FaultType> = round_trip.active_faults().collect();
		assert_eq!(round_trip, fm);
		assert_eq!(raised, [FaultType::LowPower, FaultType::Thermal]);
		Ok(())
	}
}

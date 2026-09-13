use tightbeam::utils::BasisPoints;

// Basis points run 0 to 10000. The range check runs in a `const` block, so an
// out-of-range literal fails here rather than panicking at run time.
const REJECTED: BasisPoints = tightbeam::bps!(10001);

fn main() {
	let _ = REJECTED;
}

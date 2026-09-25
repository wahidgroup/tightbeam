//! The verification harness sits outside `default`, so a default build cannot
//! name it.

use tightbeam::testing::fixtures::TestKey;

fn main() {
	let _key = TestKey::insecure_fixed_signing();
}

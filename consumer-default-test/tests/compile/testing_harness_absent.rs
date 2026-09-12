//! The verification harness sits outside `default`, so a default build cannot
//! name it.

use tightbeam::testing::utils::create_test_signing_key;

fn main() {
	let _key = create_test_signing_key();
}

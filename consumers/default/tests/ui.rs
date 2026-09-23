//! The default feature set MUST NOT reach the verification harness.

/// The `testing` module is unreachable from a default build.
#[test]
fn the_default_build_cannot_name_the_verification_harness() {
	let cases = trybuild::TestCases::new();
	cases.compile_fail("tests/compile/testing_harness_absent.rs");
}

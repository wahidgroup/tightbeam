#[test]
fn compile_fail_algorithm_mismatch() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/algorithm_mismatch.rs");
}

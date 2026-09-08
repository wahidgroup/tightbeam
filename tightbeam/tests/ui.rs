#![deny(clippy::unwrap_used)]

/// Every fixture under `tests/compile/` MUST fail to compile.
#[test]
fn compile_fail_fixtures() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/*.rs");
}

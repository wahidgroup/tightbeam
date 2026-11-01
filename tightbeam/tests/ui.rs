#![deny(clippy::unwrap_used)]

/// Every fixture under `tests/compile/` MUST fail to compile.
#[test]
fn every_compile_fixture_fails_to_compile() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/*.rs");
}

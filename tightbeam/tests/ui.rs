#[test]
fn compile_fail_algorithm_mismatch() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/algorithm_mismatch.rs");
}

#[test]
fn compile_fail_encryptor_oid_mismatch() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/encryptor_oid_mismatch.rs");
}

#[test]
fn compile_fail_digest_mismatch() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/digest_mismatch.rs");
}

#[test]
fn compile_fail_signature_mismatch() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/signature_mismatch.rs");
}

#[test]
fn compile_fail_compose_unknown_key() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/compose_unknown_key.rs");
}

#[test]
fn compile_fail_cert_missing_spki() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/cert_missing_spki.rs");
}

#[test]
fn compile_fail_profile_conflict() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/profile_conflict.rs");
}

#[test]
fn compile_fail_assert_spec_version_order() {
	let t = trybuild::TestCases::new();
	t.compile_fail("tests/compile/assert_spec_version_order.rs");
}

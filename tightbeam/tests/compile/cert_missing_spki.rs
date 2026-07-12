use core::time::Duration;
use tightbeam::cert;

fn main() {
	let signing_key = tightbeam::testing::create_test_signing_key();

	// Root profile requires an explicit subject_public_key
	// This should fail to compile with the dedicated diagnostic arm
	let _ = cert! {
		profile: Root,
		subject: "CN=Test Root",
		serial: 1u64,
		duration: Duration::from_secs(3600),
		signer: &signing_key
	};
}

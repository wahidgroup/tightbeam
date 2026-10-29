use tightbeam::transport::policy::RestartExponentialBackoff;

fn main() {
	// The base delay is a `Duration`, so a bare count of milliseconds, which
	// a call site could swap with the attempt count, fails to compile.
	let _policy = RestartExponentialBackoff::new(4, 1000, None);
}

use tightbeam::transport::policy::RestartExponentialBackoff;

fn main() {
	// The base delay field is a `Duration`, so a bare count of milliseconds,
	// which a struct literal could swap with the attempt count, fails to
	// compile.
	let _policy = RestartExponentialBackoff { max_attempts: 4, base_delay: 1000, jitter: None };
}

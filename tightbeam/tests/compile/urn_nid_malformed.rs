use tightbeam::urn::Urn;

// RFC 8141 s2.1: a NID starts with a letter or a digit. `-bad` does not, so
// this literal must fail where it is written rather than at a `verify` call
// downstream.
const REJECTED: Urn<'static> = tightbeam::urn!("-bad", "resource");

fn main() {
	let _ = REJECTED;
}

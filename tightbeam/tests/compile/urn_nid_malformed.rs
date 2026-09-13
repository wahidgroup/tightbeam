use tightbeam::utils::urn::Urn;

// RFC 8141 s2.1: a NID starts with a letter. `9bad` does not, so this literal
// must fail where it is written rather than at a `verify` call downstream.
const REJECTED: Urn<'static> = tightbeam::urn!("9bad", "resource");

fn main() {
	let _ = REJECTED;
}

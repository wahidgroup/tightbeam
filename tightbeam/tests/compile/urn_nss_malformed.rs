use tightbeam::urn::Urn;

// RFC 8141 s2: an NSS is a run of RFC 3986 pchar and `/`. A space is no
// pchar, so this literal must fail where it is written.
const REJECTED: Urn<'static> = tightbeam::urn!("test", "a b");

fn main() {
	let _ = REJECTED;
}

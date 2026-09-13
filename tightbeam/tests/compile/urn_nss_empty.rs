use tightbeam::utils::urn::Urn;

// An empty NSS names no resource.
const REJECTED: Urn<'static> = tightbeam::urn!("test", "");

fn main() {
	let _ = REJECTED;
}

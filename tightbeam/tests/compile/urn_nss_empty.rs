use tightbeam::utils::urn::Urn;

// An empty NSS names no resource.
const REJECTED: Urn<'static> = Urn::new("test", "");

fn main() {
	let _ = REJECTED;
}

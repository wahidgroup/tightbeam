use tightbeam::crypto::commitment::{CommitmentSalt, HidingSalt};
use tightbeam::crypto::secret::SecretSlice;

fn main() {
	// A hiding salt carries at least MIN_SALT_SIZE bytes, and
	// `CommitmentSalt::parse` is what enforces that. Either construction
	// below would put a one-byte salt into a commitment that claims to hide
	// its body, so neither may compile.
	let too_short: SecretSlice<u8> = vec![0u8; 1].into();
	let _wrong_payload = CommitmentSalt::Hiding(too_short);

	let also_too_short: SecretSlice<u8> = vec![0u8; 1].into();
	let _minted_directly = HidingSalt(also_too_short);
}

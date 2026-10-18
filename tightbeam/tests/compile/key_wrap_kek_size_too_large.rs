use tightbeam::crypto::common::typenum::U65536;
use tightbeam::crypto::key::KeyError;
use tightbeam::crypto::profiles::{Aes256Wrap, KeyWrapAlgorithm};
use tightbeam::ZeroizingBytes;

// A wrap whose KEK is 65536 octets
struct OversizedKekWrap;

impl KeyWrapAlgorithm for OversizedKekWrap {
	type Oid = Aes256Wrap;
	// ERROR: `kekLength` is INTEGER (1..65535) (RFC 9629 §3)
	type KekSize = U65536;

	fn wrap(kek: &[u8], key: &[u8]) -> Result<Vec<u8>, KeyError> {
		Aes256Wrap::wrap(kek, key)
	}

	fn unwrap(kek: &[u8], wrapped: &[u8]) -> Result<ZeroizingBytes, KeyError> {
		Aes256Wrap::unwrap(kek, wrapped)
	}
}

fn main() {}

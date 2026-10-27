use tightbeam::crypto::common::typenum::U65536;
use tightbeam::crypto::key::KeyError;
use tightbeam::crypto::profiles::{Aes256Wrap, Kek, KeyWrapAlgorithm};
use tightbeam::ZeroizingBytes;

// A wrap whose KEK is 65536 octets.
struct OversizedKekWrap;

impl KeyWrapAlgorithm for OversizedKekWrap {
	type Oid = Aes256Wrap;
	// ERROR: `kekLength` is INTEGER (1..65535) (RFC 9629 §3).
	type KekSize = U65536;

	fn wrap(_kek: &Kek<'_, Self>, key: &[u8]) -> Result<Vec<u8>, KeyError> {
		Ok(key.to_vec())
	}

	fn unwrap(_kek: &Kek<'_, Self>, wrapped: &[u8]) -> Result<ZeroizingBytes, KeyError> {
		Ok(ZeroizingBytes::new(wrapped.to_vec()))
	}
}

fn main() {}

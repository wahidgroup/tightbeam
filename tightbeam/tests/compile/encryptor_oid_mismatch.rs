use tightbeam::crypto::aead::{Aes128GcmOid, Encryptor};
use tightbeam::testing::TestKey;

fn main() {
	// The in-memory key of the house provider seals under AES-256-GCM.
	// Must fail to compile: Encryptor binds an encryptor to its canonical OID.
	let (_, cipher) = TestKey::insecure_fixed_cipher();
	let _ = Encryptor::<Aes128GcmOid>::encrypt_content(&cipher, b"x".to_vec(), None, None);
}

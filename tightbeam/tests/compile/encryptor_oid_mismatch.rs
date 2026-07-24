use tightbeam::crypto::aead::{Aes128Gcm, Aes256GcmOid, Encryptor, KeyInit};

fn main() {
	// AES-128-GCM cipher paired with an AES-256-GCM OID marker.
	// Must fail to compile: Encryptor binds cipher type to its canonical OID.
	let cipher = Aes128Gcm::new(&[0u8; 16].into());
	let _ = Encryptor::<Aes256GcmOid>::encrypt_content(&cipher, b"x", &[0u8; 12], None);
}

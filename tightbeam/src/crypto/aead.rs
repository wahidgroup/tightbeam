// Re-exports
pub use aead::*;
#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};

#[cfg(feature = "aes-gcm")]
use der::oid::{AssociatedOid, ObjectIdentifier};

/// Create a wrapper type for AES-256-GCM with the OID
/// Note: The `aes-gcm` crate does not implement `AssociatedOid` directly.
#[cfg(feature = "aes-gcm")]
pub struct Aes256GcmOid;

#[cfg(feature = "aes-gcm")]
impl AssociatedOid for Aes256GcmOid {
	const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");
}

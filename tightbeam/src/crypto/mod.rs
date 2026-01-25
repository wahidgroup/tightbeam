mod utils;

/// Macro to define OID wrapper types with `AssociatedOid` implementation.
///
/// This reduces boilerplate for creating simple marker types that implement
/// the `AssociatedOid` trait.
#[macro_export]
macro_rules! define_oid_wrapper {
	// Variant with doc comment and inline OID string
	($(#[$meta:meta])* $name:ident, $oid_str:literal) => {
		$(#[$meta])*
		pub struct $name;
		$(#[$meta])*
		impl $crate::der::oid::AssociatedOid for $name {
			const OID: $crate::asn1::ObjectIdentifier =
				$crate::asn1::ObjectIdentifier::new_unwrap($oid_str);
		}
	};
	// Variant with doc comment and OID constant reference
	($(#[$meta:meta])* $name:ident, $oid_const:path) => {
		$(#[$meta])*
		pub struct $name;
		$(#[$meta])*
		impl $crate::der::oid::AssociatedOid for $name {
			const OID: $crate::asn1::ObjectIdentifier = $oid_const;
		}
	};
}

pub mod key;
pub mod policy;
pub mod profiles;
pub mod secret;

#[cfg(feature = "aead")]
pub mod aead;
#[cfg(feature = "ecdh")]
pub mod curves;
#[cfg(feature = "ecies")]
pub mod ecies;
#[cfg(feature = "digest")]
pub mod hash;
#[cfg(feature = "kdf")]
pub mod kdf;
#[cfg(feature = "kem")]
pub mod kem;
#[cfg(feature = "signature")]
pub mod sign;
#[cfg(feature = "x509")]
pub mod x509;

// Re-exports
pub use crypto_common as common;

#[cfg(feature = "secp256k1")]
pub const ECDSA_PUBKEY_SIZE: usize = 33;
#[cfg(feature = "secp256k1")]
pub const ECDSA_SECRET_SIZE: usize = 32;

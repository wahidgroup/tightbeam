/// Define an OID marker type that implements `AssociatedOid`.
///
/// The macro writes the boilerplate of a simple marker type and its
/// `AssociatedOid` implementation.
#[macro_export]
macro_rules! define_oid_wrapper {
	// This arm takes doc attributes and an inline OID string.
	($(#[$meta:meta])* $name:ident, $oid_str:literal) => {
		$(#[$meta])*
		pub struct $name;
		$(#[$meta])*
		impl $crate::der::oid::AssociatedOid for $name {
			const OID: $crate::asn1::ObjectIdentifier =
				$crate::asn1::ObjectIdentifier::new_unwrap($oid_str);
		}
	};
	// This arm takes doc attributes and a path to an OID constant.
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
#[cfg(feature = "digest")]
pub mod commitment;
#[cfg(feature = "ecies")]
pub mod ecies;
#[cfg(any(feature = "digest", feature = "sha3"))]
pub mod hash;
#[cfg(feature = "kdf")]
pub mod kdf;
#[cfg(feature = "signature")]
pub mod sign;
#[cfg(feature = "x509")]
pub mod x509;

pub use crypto_common as common;
pub use subtle;

#[cfg(feature = "kdf")]
pub use hkdf;
#[cfg(feature = "secp256k1")]
pub use k256;

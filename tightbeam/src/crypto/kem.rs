pub use kem::*;

use crate::der::oid::{AssociatedOid, ObjectIdentifier};
use crate::oids::KEM_ML_KEM_1024;

/// Wrapper type for ML-KEM-1024 (Kyber-1024) with the OID.
///
/// ML-KEM-1024 is the NIST post-quantum Key Encapsulation Mechanism
/// (formerly known as Kyber-1024). This is the KEM specified in Signal's
/// PQXDH protocol.
pub struct Kyber1024Oid;

impl AssociatedOid for Kyber1024Oid {
	const OID: ObjectIdentifier = KEM_ML_KEM_1024;
}

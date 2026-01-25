pub use kem::*;

use crate::oids::KEM_ML_KEM_1024;

crate::define_oid_wrapper!(
	/// Wrapper type for ML-KEM-1024 (Kyber-1024) with the OID.
	///
	/// ML-KEM-1024 is the NIST post-quantum Key Encapsulation Mechanism
	/// (formerly known as Kyber-1024). This is the KEM specified in Signal's
	/// PQXDH protocol.
	Kyber1024Oid,
	KEM_ML_KEM_1024
);

//! Elliptic curve OID type wrappers

use crate::oids::{CURVE_NIST_P256, CURVE_SECP256K1, CURVE_X25519};

crate::define_oid_wrapper!(
	/// secp256k1 curve OID wrapper (Bitcoin/Ethereum standard)
	Secp256k1Oid,
	CURVE_SECP256K1
);

crate::define_oid_wrapper!(
	/// X25519 curve OID wrapper (Curve25519 for ECDH)
	X25519Oid,
	CURVE_X25519
);

crate::define_oid_wrapper!(
	/// NIST P-256 (secp256r1) curve OID wrapper
	NistP256Oid,
	CURVE_NIST_P256
);

//! Elliptic curve OID type wrappers

use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::oids::{CURVE_NIST_P256, CURVE_SECP256K1, CURVE_X25519};

/// secp256k1 curve OID wrapper (Bitcoin/Ethereum standard)
pub struct Secp256k1Oid;

impl AssociatedOid for Secp256k1Oid {
	const OID: ObjectIdentifier = CURVE_SECP256K1;
}

/// X25519 curve OID wrapper (Curve25519 for ECDH)
pub struct X25519Oid;

impl AssociatedOid for X25519Oid {
	const OID: ObjectIdentifier = CURVE_X25519;
}

/// NIST P-256 (secp256r1) curve OID wrapper
pub struct NistP256Oid;

impl AssociatedOid for NistP256Oid {
	const OID: ObjectIdentifier = CURVE_NIST_P256;
}

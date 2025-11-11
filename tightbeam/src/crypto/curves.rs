//! Elliptic curve OID type wrappers

use crate::asn1::{CURVE_NIST_P256_OID, CURVE_SECP256K1_OID, CURVE_X25519_OID};
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;

/// secp256k1 curve OID wrapper (Bitcoin/Ethereum standard)
pub struct Secp256k1Oid;

impl AssociatedOid for Secp256k1Oid {
	const OID: ObjectIdentifier = CURVE_SECP256K1_OID;
}

/// X25519 curve OID wrapper (Curve25519 for ECDH)
pub struct X25519Oid;

impl AssociatedOid for X25519Oid {
	const OID: ObjectIdentifier = CURVE_X25519_OID;
}

/// NIST P-256 (secp256r1) curve OID wrapper
pub struct NistP256Oid;

impl AssociatedOid for NistP256Oid {
	const OID: ObjectIdentifier = CURVE_NIST_P256_OID;
}

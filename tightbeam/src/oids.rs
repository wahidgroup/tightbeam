//! ASN.1 Object Identifiers (OIDs) for TightBeam
//!
//! This module contains all ASN.1 Object Identifiers used throughout the TightBeam
//! protocol implementation. OIDs are used to identify cryptographic algorithms,
//! data formats, and protocol elements in a standardized way.

#![allow(dead_code)]

use crate::der::asn1::ObjectIdentifier;

// ============================================================================
// ASN.1 Object Identifiers (OIDs)
// ============================================================================

/// id-data
/// See `<https://datatracker.ietf.org/doc/html/rfc5652>`
/// See `<https://oid-base.com/get/1.2.840.113549.1.7.1>`
pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// id-envelopedData
/// See `<https://datatracker.ietf.org/doc/html/rfc5652>`
/// See `<https://oid-base.com/get/1.2.840.113549.1.7.3>`
pub const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

/// id-ct-compressedData OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
pub const COMPRESSION_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.9");

/// id-alg-zlibCompress OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
pub const COMPRESSION_ZLIB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.8");

/// OID for zstd compression defined in RFC 8878
/// See `<https://datatracker.ietf.org/doc/html/rfc8878>`
/// See `<https://oid-base.com/get/1.3.6.1.4.1.50274.1.1>`
pub const COMPRESSION_ZSTD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3");

/// sha-256
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.2.1>`
pub const HASH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// sha3-256
/// See `<https://datatracker.ietf.org/doc/html/rfc6234>`
pub const HASH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// sha3-384
/// See `<https://datatracker.ietf.org/doc/html/rfc6234>`
pub const HASH_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// sha3-512
/// See `<https://datatracker.ietf.org/doc/html/rfc6234>`
pub const HASH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

/// ecdsa-with-SHA256
/// See `<https://oid-base.com/get/1.2.840.10045.4.3.2>`
pub const SIGNER_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA3-256 (kept for backwards compatibility, maps to same OID as ecdsa-with-SHA256)
/// See `<https://oid-base.com/get/1.2.840.10045.4.3.2>`
pub const SIGNER_ECDSA_WITH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10");

/// ecdsa-with-SHA3-512
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.3.10>`
pub const SIGNER_ECDSA_WITH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.12");

/// id-aes128-gcm - AES-GCM with 128-bit key
/// See RFC 5084 - https://datatracker.ietf.org/doc/html/rfc5084
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.6>`
pub const AES_128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");

/// id-aes256-gcm - AES-GCM with 256-bit key
/// See RFC 5084 - https://datatracker.ietf.org/doc/html/rfc5084
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.46>`
pub const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

/// id-aes128-wrap - AES Key Wrap with 128-bit key
/// See RFC 3394 - https://datatracker.ietf.org/doc/html/rfc3394
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.5>`
pub const AES_128_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5");

/// id-aes192-wrap - AES Key Wrap with 192-bit key
/// See RFC 3394 - https://datatracker.ietf.org/doc/html/rfc3394
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.25>`
pub const AES_192_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25");

/// id-aes256-wrap - AES Key Wrap with 256-bit key
/// See RFC 3394 - https://datatracker.ietf.org/doc/html/rfc3394
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.45>`
pub const AES_256_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45");

/// secp256k1 - Elliptic curve for Bitcoin/Ethereum
/// See `<https://oid-base.com/get/1.3.132.0.10>`
pub const CURVE_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

/// secp256r1 (NIST P-256) - Elliptic curve
/// See `<https://oid-base.com/get/1.2.840.10045.3.1.7>`
pub const CURVE_NIST_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// secp384r1 (NIST P-384) - Elliptic curve
/// See `<https://oid-base.com/get/1.3.132.0.34>`
pub const CURVE_NIST_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// secp521r1 (NIST P-521) - Elliptic curve
/// See `<https://oid-base.com/get/1.3.132.0.35>`
pub const CURVE_NIST_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// X25519 - Curve25519 for ECDH (used with Ed25519 signatures)
/// See RFC 8410 - `<https://datatracker.ietf.org/doc/html/rfc8410>`
/// See `<https://oid-base.com/get/1.3.101.110>`
pub const CURVE_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

// ============================================================================
// Transport Handshake Attribute OIDs (FULL_CMS profile)
// ============================================================================
// Enterprise arc placeholder: 1.3.6.1.4.1.55555.1.x
// Replace 55555 with assigned enterprise number before production.

/// Handshake protocol version OID
pub const HANDSHAKE_PROTOCOL_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.1");

/// Handshake algorithm profile OID
pub const HANDSHAKE_ALGORITHM_PROFILE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.2");

/// Handshake client nonce OID
pub const HANDSHAKE_CLIENT_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.3");

/// Handshake select version OID
pub const HANDSHAKE_SELECT_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.4");

/// Handshake select algorithm OID
pub const HANDSHAKE_SELECT_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.5");

/// Handshake server nonce OID
pub const HANDSHAKE_SERVER_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.6");

/// Handshake abort alert OID
pub const HANDSHAKE_ABORT_ALERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.7");

/// Handshake transcript hash OID
pub const HANDSHAKE_TRANSCRIPT_HASH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.8");

/// Handshake supported curves OID
pub const HANDSHAKE_SUPPORTED_CURVES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.9");

/// Handshake selected curve OID
pub const HANDSHAKE_SELECTED_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.10");

/// Handshake security offer OID
pub const HANDSHAKE_SECURITY_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.11");

/// Handshake security accept OID
pub const HANDSHAKE_SECURITY_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.12");

/// Composite profile OID (ECIES(secp256k1) + HKDF(SHA3-256) + AES-256-GCM)
pub const HANDSHAKE_PROFILE_ECIES_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.100");

/// Client certificate OID
pub const CLIENT_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.13");

/// Client signature OID
pub const CLIENT_SIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.14");

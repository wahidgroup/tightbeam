//! ASN.1 Object Identifiers (OIDs) for TightBeam
//!
//! This module contains all ASN.1 Object Identifiers used throughout the TightBeam
//! protocol implementation. OIDs are used to identify cryptographic algorithms,
//! data formats, and protocol elements in a standardized way.

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
///     pkcs(1)  pkcs-9(9)       smime(16)  ct(1) 9
/// }
/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
pub const COMPRESSION_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.9");

/// id-alg-zlibCompress OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
pub const COMPRESSION_ZLIB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.8");

/// Zstandard (zstd) compression, RFC 8878.
///
/// RFC 8878 defines the format and media type only. Neither IETF nor the
/// S/MIME algorithm registry (RFC 7107) assigns an OID for zstd. This value
/// lives under the same placeholder enterprise arc as the handshake attribute
/// OIDs below and MUST be replaced together with them once a Private
/// Enterprise Number is assigned.
/// See `<https://datatracker.ietf.org/doc/html/rfc8878>`
pub const COMPRESSION_ZSTD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.2.1");

/// sha-256
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.2.1>`
pub const HASH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// id-sha3-256 (NIST CSOR hash algorithms arc)
/// See `<https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>`
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.2.8>`
pub const HASH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// id-sha3-384 (NIST CSOR hash algorithms arc)
/// See `<https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>`
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.2.9>`
pub const HASH_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// id-sha3-512 (NIST CSOR hash algorithms arc)
/// See `<https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>`
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.2.10>`
pub const HASH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

/// ecdsa-with-SHA256
/// See `<https://oid-base.com/get/1.2.840.10045.4.3.2>`
pub const SIGNER_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// ecdsa-with-SHA3-256
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.3.10>`
pub const SIGNER_ECDSA_WITH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10");

/// ecdsa-with-SHA3-512
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.3.12>`
pub const SIGNER_ECDSA_WITH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.12");

/// id-aes128-gcm - AES-GCM with 128-bit key
/// See RFC 5084 - <https://datatracker.ietf.org/doc/html/rfc5084>
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.6>`
pub const AES_128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");

/// id-aes256-gcm - AES-GCM with 256-bit key
/// See RFC 5084 - <https://datatracker.ietf.org/doc/html/rfc5084>
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.46>`
pub const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

/// id-aes128-wrap - AES Key Wrap with 128-bit key
/// See RFC 3394 - <https://datatracker.ietf.org/doc/html/rfc3394>
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.5>`
pub const AES_128_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5");

/// id-aes192-wrap - AES Key Wrap with 192-bit key
/// See RFC 3394 - <https://datatracker.ietf.org/doc/html/rfc3394>
/// See `<https://oid-base.com/get/2.16.840.1.101.3.4.1.25>`
pub const AES_192_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25");

/// id-aes256-wrap - AES Key Wrap with 256-bit key
/// See RFC 3394 - <https://datatracker.ietf.org/doc/html/rfc3394>
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

/// ML-KEM-1024 (formerly Kyber-1024) - NIST-standardized post-quantum KEM
/// FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
/// Used in Signal's PQXDH protocol for hybrid classical+PQ key agreement
/// See `<https://csrc.nist.gov/pubs/fips/203/final>`
pub const KEM_ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.4");

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

/// Handshake transport capability offer OID (multiplexing)
pub const HANDSHAKE_TRANSPORT_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.15");

/// Handshake transport capability accept OID (multiplexing)
pub const HANDSHAKE_TRANSPORT_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.16");

/// Session receipt signature OID: server signature in the server's
/// handshake message, client countersignature in the client's.
pub const RECEIPT_SIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.17");

/// Session receipt ancillary response OID. In CMS carriage the value is
/// an `EnvelopedData` (RFC 5652 s6) encrypted to the server certificate.
pub const RECEIPT_RESPONSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.18");

/// Session receipt body OID (CMS attribute carriage)
pub const SESSION_RECEIPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.55555.1.19");

#[cfg(test)]
mod tests {
	use super::*;

	/// Regression pin: every OID constant is asserted against its
	/// dotted-decimal value so an accidental edit cannot silently change what
	/// is used for transport.
	#[test]
	fn oid_values_are_pinned() {
		let pinned: &[(ObjectIdentifier, &str)] = &[
			(DATA, "1.2.840.113549.1.7.1"),
			(ENVELOPED_DATA, "1.2.840.113549.1.7.3"),
			(COMPRESSION_CONTENT, "1.2.840.113549.1.9.16.1.9"),
			(COMPRESSION_ZLIB, "1.2.840.113549.1.9.16.3.8"),
			(COMPRESSION_ZSTD, "1.3.6.1.4.1.55555.2.1"),
			(HASH_SHA256, "2.16.840.1.101.3.4.2.1"),
			(HASH_SHA3_256, "2.16.840.1.101.3.4.2.8"),
			(HASH_SHA3_384, "2.16.840.1.101.3.4.2.9"),
			(HASH_SHA3_512, "2.16.840.1.101.3.4.2.10"),
			(SIGNER_ECDSA_WITH_SHA256, "1.2.840.10045.4.3.2"),
			(SIGNER_ECDSA_WITH_SHA3_256, "2.16.840.1.101.3.4.3.10"),
			(SIGNER_ECDSA_WITH_SHA3_512, "2.16.840.1.101.3.4.3.12"),
			(AES_128_GCM, "2.16.840.1.101.3.4.1.6"),
			(AES_256_GCM, "2.16.840.1.101.3.4.1.46"),
			(AES_128_WRAP, "2.16.840.1.101.3.4.1.5"),
			(AES_192_WRAP, "2.16.840.1.101.3.4.1.25"),
			(AES_256_WRAP, "2.16.840.1.101.3.4.1.45"),
			(CURVE_SECP256K1, "1.3.132.0.10"),
			(CURVE_NIST_P256, "1.2.840.10045.3.1.7"),
			(CURVE_NIST_P384, "1.3.132.0.34"),
			(CURVE_NIST_P521, "1.3.132.0.35"),
			(CURVE_X25519, "1.3.101.110"),
			(KEM_ML_KEM_1024, "2.16.840.1.101.3.4.4.4"),
			(HANDSHAKE_PROTOCOL_VERSION, "1.3.6.1.4.1.55555.1.1"),
			(HANDSHAKE_ALGORITHM_PROFILE, "1.3.6.1.4.1.55555.1.2"),
			(HANDSHAKE_CLIENT_NONCE, "1.3.6.1.4.1.55555.1.3"),
			(HANDSHAKE_SELECT_VERSION, "1.3.6.1.4.1.55555.1.4"),
			(HANDSHAKE_SELECT_ALGORITHM, "1.3.6.1.4.1.55555.1.5"),
			(HANDSHAKE_SERVER_NONCE, "1.3.6.1.4.1.55555.1.6"),
			(HANDSHAKE_ABORT_ALERT, "1.3.6.1.4.1.55555.1.7"),
			(HANDSHAKE_TRANSCRIPT_HASH, "1.3.6.1.4.1.55555.1.8"),
			(HANDSHAKE_SUPPORTED_CURVES, "1.3.6.1.4.1.55555.1.9"),
			(HANDSHAKE_SELECTED_CURVE, "1.3.6.1.4.1.55555.1.10"),
			(HANDSHAKE_SECURITY_OFFER, "1.3.6.1.4.1.55555.1.11"),
			(HANDSHAKE_SECURITY_ACCEPT, "1.3.6.1.4.1.55555.1.12"),
			(HANDSHAKE_PROFILE_ECIES_GCM, "1.3.6.1.4.1.55555.1.100"),
			(CLIENT_CERTIFICATE, "1.3.6.1.4.1.55555.1.13"),
			(CLIENT_SIGNATURE, "1.3.6.1.4.1.55555.1.14"),
			(HANDSHAKE_TRANSPORT_OFFER, "1.3.6.1.4.1.55555.1.15"),
			(HANDSHAKE_TRANSPORT_ACCEPT, "1.3.6.1.4.1.55555.1.16"),
			(RECEIPT_SIGNATURE, "1.3.6.1.4.1.55555.1.17"),
			(RECEIPT_RESPONSE, "1.3.6.1.4.1.55555.1.18"),
			(SESSION_RECEIPT, "1.3.6.1.4.1.55555.1.19"),
		];

		for (oid, expected) in pinned {
			assert_eq!(*oid, ObjectIdentifier::new_unwrap(expected));
		}
	}
}

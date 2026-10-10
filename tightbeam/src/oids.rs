//! ASN.1 object identifiers (OIDs) for TightBeam.
//!
//! The module holds every OID the TightBeam protocol implementation names. An
//! OID identifies a cryptographic algorithm, a data format, or a protocol
//! element.
//!
//! ## Private arc
//!
//! Wahid Group, LLC holds IANA PEN 64586, so its arc is `1.3.6.1.4.1.64586`.
//!
//! - `.1` holds the handshake and session attributes, which are the transport
//!   handshake attribute OIDs of the FULL_CMS profile.
//! - `.2` holds the algorithms, such as zstd.

use crate::der::asn1::ObjectIdentifier;

/// The CMS `id-data` content type.
///
/// # Sources
///
/// - RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.113549.1.7.1>
pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// The CMS `id-envelopedData` content type.
///
/// # Sources
///
/// - RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.113549.1.7.3>
pub const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

/// The CMS `id-ct-compressedData` content type.
///
/// ```text
/// id-ct-compressedData OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  ct(1) 9
/// }
/// ```
///
/// # Sources
///
/// - RFC 3274, Compressed Data Content Type for CMS: <https://datatracker.ietf.org/doc/html/rfc3274>
pub const COMPRESSION_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.9");

/// The CMS `id-alg-zlibCompress` compression algorithm.
///
/// ```text
/// id-alg-zlibCompress OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
/// ```
///
/// # Sources
///
/// - RFC 3274, Compressed Data Content Type for CMS: <https://datatracker.ietf.org/doc/html/rfc3274>
pub const COMPRESSION_ZLIB: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.8");

/// Zstandard (zstd) compression.
///
/// RFC 8878 defines the format and the media type only, and neither the IETF
/// nor the S/MIME algorithm registry (RFC 7107) assigns an OID for zstd. This
/// OID is therefore assigned under Wahid Group, LLC IANA PEN 64586, in the
/// algorithms arc `.2`.
///
/// # Sources
///
/// - RFC 8878, Zstandard Compression and the `application/zstd` Media Type:
///   <https://datatracker.ietf.org/doc/html/rfc8878>
pub const COMPRESSION_ZSTD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.2.1");

/// The SHA-256 hash algorithm (`sha-256`).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.2.1>
pub const HASH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");

/// The SHA3-256 hash algorithm (`id-sha3-256`), in the NIST CSOR hash
/// algorithms arc.
///
/// # Sources
///
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.2.8>
pub const HASH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");

/// The SHA3-384 hash algorithm (`id-sha3-384`), in the NIST CSOR hash
/// algorithms arc.
///
/// # Sources
///
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.2.9>
pub const HASH_SHA3_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.9");

/// The SHA3-512 hash algorithm (`id-sha3-512`), in the NIST CSOR hash
/// algorithms arc.
///
/// # Sources
///
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.2.10>
pub const HASH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.10");

/// The ECDSA with SHA-256 signature algorithm (`ecdsa-with-SHA256`).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/1.2.840.10045.4.3.2>
pub const SIGNER_ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

/// The ECDSA with SHA3-256 signature algorithm (`ecdsa-with-SHA3-256`).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.3.10>
pub const SIGNER_ECDSA_WITH_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.10");

/// The ECDSA with SHA3-512 signature algorithm (`ecdsa-with-SHA3-512`).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.3.12>
pub const SIGNER_ECDSA_WITH_SHA3_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.12");

/// AES-GCM with a 128-bit key (`id-aes128-gcm`).
///
/// # Sources
///
/// - RFC 5084, AES-CCM and AES-GCM in CMS: <https://datatracker.ietf.org/doc/html/rfc5084>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.1.6>
pub const AES_128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");

/// AES-GCM with a 256-bit key (`id-aes256-gcm`).
///
/// # Sources
///
/// - RFC 5084, AES-CCM and AES-GCM in CMS: <https://datatracker.ietf.org/doc/html/rfc5084>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.1.46>
pub const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

/// AES Key Wrap with a 128-bit key (`id-aes128-wrap`).
///
/// # Sources
///
/// - RFC 3394, AES Key Wrap Algorithm: <https://datatracker.ietf.org/doc/html/rfc3394>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.1.5>
pub const AES_128_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.5");

/// AES Key Wrap with a 192-bit key (`id-aes192-wrap`).
///
/// # Sources
///
/// - RFC 3394, AES Key Wrap Algorithm: <https://datatracker.ietf.org/doc/html/rfc3394>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.1.25>
pub const AES_192_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.25");

/// AES Key Wrap with a 256-bit key (`id-aes256-wrap`).
///
/// # Sources
///
/// - RFC 3394, AES Key Wrap Algorithm: <https://datatracker.ietf.org/doc/html/rfc3394>
/// - OID repository entry: <https://oid-base.com/get/2.16.840.1.101.3.4.1.45>
pub const AES_256_WRAP: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45");

/// The secp256k1 elliptic curve, which Bitcoin and Ethereum use.
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/1.3.132.0.10>
pub const CURVE_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");

/// The secp256r1 elliptic curve (NIST P-256).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/1.2.840.10045.3.1.7>
pub const CURVE_NIST_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The secp384r1 elliptic curve (NIST P-384).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/1.3.132.0.34>
pub const CURVE_NIST_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");

/// The secp521r1 elliptic curve (NIST P-521).
///
/// # Sources
///
/// - OID repository entry: <https://oid-base.com/get/1.3.132.0.35>
pub const CURVE_NIST_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");

/// X25519, which is Curve25519 for ECDH. It is used with Ed25519 signatures.
///
/// # Sources
///
/// - RFC 8410, X25519 and Ed25519 algorithm identifiers: <https://datatracker.ietf.org/doc/html/rfc8410>
/// - OID repository entry: <https://oid-base.com/get/1.3.101.110>
pub const CURVE_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// ML-KEM-1024 (`id-alg-ml-kem-1024`), the post-quantum KEM that NIST
/// standardized from Kyber-1024.
///
/// # Sources
///
/// - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - RFC 9935, ML-KEM algorithm identifiers: <https://datatracker.ietf.org/doc/html/rfc9935>
pub const KEM_ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

/// The handshake attribute that carries the protocol version.
pub const HANDSHAKE_PROTOCOL_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.1");

/// The handshake attribute that carries the algorithm profile.
pub const HANDSHAKE_ALGORITHM_PROFILE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.2");

/// The handshake attribute that carries the client nonce.
pub const HANDSHAKE_CLIENT_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.3");

/// The handshake attribute that carries the selected version.
pub const HANDSHAKE_SELECT_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.4");

/// The handshake attribute that carries the selected algorithm.
pub const HANDSHAKE_SELECT_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.5");

/// The handshake attribute that carries the server nonce.
pub const HANDSHAKE_SERVER_NONCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.6");

/// The handshake attribute that carries an abort alert.
pub const HANDSHAKE_ABORT_ALERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.7");

/// The handshake attribute that carries the transcript hash.
pub const HANDSHAKE_TRANSCRIPT_HASH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.8");

/// The handshake attribute that carries the supported curves.
pub const HANDSHAKE_SUPPORTED_CURVES: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.9");

/// The handshake attribute that carries the selected curve.
pub const HANDSHAKE_SELECTED_CURVE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.10");

/// The handshake attribute that carries the security offer.
pub const HANDSHAKE_SECURITY_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.11");

/// The handshake attribute that carries the security accept.
pub const HANDSHAKE_SECURITY_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.12");

/// The composite profile of ECIES over secp256k1, HKDF with SHA3-256, and
/// AES-256-GCM.
pub const HANDSHAKE_PROFILE_ECIES_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.100");

/// The handshake attribute that carries the client certificate.
pub const CLIENT_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.13");

/// The handshake attribute that carries the client signature.
pub const CLIENT_SIGNATURE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.14");

/// The handshake attribute that carries the transport capability offer for
/// multiplexing.
pub const HANDSHAKE_TRANSPORT_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.15");

/// The handshake attribute that carries the transport capability accept for
/// multiplexing.
pub const HANDSHAKE_TRANSPORT_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.16");

// 1.3.6.1.4.1.64586.1.17 is reserved for the retired bare receipt signature.
// Receipt signatures travel as SignerInfos inside the receipt SignedData
// artifact.

/// Session receipt acknowledgement OID. The value is an OCTET STRING holding
/// the AEAD ciphertext, under a key derived from the handshake secret, of the
/// client's receipt `SignerInfo` (countersignature plus confidential
/// settlement answer).
pub const RECEIPT_ACK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.18");

/// Session receipt artifact OID (CMS attribute carriage). The value is
/// the receipt `SignedData`
/// ([RFC 5652 §5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)).
pub const SESSION_RECEIPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.19");

/// `eContentType` of the session receipt body inside the receipt
/// SignedData artifact.
pub const SESSION_RECEIPT_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.20");

/// Signed attribute binding a receipt `SignerInfo` to its role
/// (INTEGER: 0 server, 1 client) so one party's signature cannot be
/// spliced into the other role (CWE-347).
pub const RECEIPT_ROLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.21");

/// Signed attribute carrying the client's settlement answer (OCTET STRING)
/// inside its receipt `SignerInfo`, binding the answer to the countersignature
/// the standard CMS way.
pub const RECEIPT_ANSWER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.22");

/// Server ephemeral public key OID (CMS attribute carriage). The value is an
/// `OriginatorPublicKey` ([RFC 5652 §6.2.2][rfc5652-6.2.2]) on the server
/// Finished, inside the transcript the Finished signs.
///
/// [rfc5652-6.2.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.2
pub const HANDSHAKE_SERVER_EPHEMERAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.23");

/// Key-confirmation tag OID (CMS attribute carriage). The value is a 32-byte
/// OCTET STRING on the client Finished, derived from the handshake secret and
/// the transcript hash.
pub const HANDSHAKE_KEY_CONFIRMATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.24");

/// PKCS #9 content-type signed attribute ([RFC 5652 §11.1][rfc5652-11.1]).
///
/// [rfc5652-11.1]: https://datatracker.ietf.org/doc/html/rfc5652#section-11.1
pub const ATTR_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// PKCS #9 message-digest signed attribute ([RFC 5652 §11.2][rfc5652-11.2]).
///
/// [rfc5652-11.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-11.2
pub const ATTR_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

#[cfg(test)]
mod tests {
	use super::*;

	/// The test pins every OID constant to its dotted-decimal value, so an
	/// accidental edit cannot silently change an identifier that peers
	/// exchange.
	#[test]
	fn oid_values_are_pinned() {
		let pinned: &[(ObjectIdentifier, &str)] = &[
			(DATA, "1.2.840.113549.1.7.1"),
			(ENVELOPED_DATA, "1.2.840.113549.1.7.3"),
			(COMPRESSION_CONTENT, "1.2.840.113549.1.9.16.1.9"),
			(COMPRESSION_ZLIB, "1.2.840.113549.1.9.16.3.8"),
			(COMPRESSION_ZSTD, "1.3.6.1.4.1.64586.2.1"),
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
			(KEM_ML_KEM_1024, "2.16.840.1.101.3.4.4.3"),
			(HANDSHAKE_PROTOCOL_VERSION, "1.3.6.1.4.1.64586.1.1"),
			(HANDSHAKE_ALGORITHM_PROFILE, "1.3.6.1.4.1.64586.1.2"),
			(HANDSHAKE_CLIENT_NONCE, "1.3.6.1.4.1.64586.1.3"),
			(HANDSHAKE_SELECT_VERSION, "1.3.6.1.4.1.64586.1.4"),
			(HANDSHAKE_SELECT_ALGORITHM, "1.3.6.1.4.1.64586.1.5"),
			(HANDSHAKE_SERVER_NONCE, "1.3.6.1.4.1.64586.1.6"),
			(HANDSHAKE_ABORT_ALERT, "1.3.6.1.4.1.64586.1.7"),
			(HANDSHAKE_TRANSCRIPT_HASH, "1.3.6.1.4.1.64586.1.8"),
			(HANDSHAKE_SUPPORTED_CURVES, "1.3.6.1.4.1.64586.1.9"),
			(HANDSHAKE_SELECTED_CURVE, "1.3.6.1.4.1.64586.1.10"),
			(HANDSHAKE_SECURITY_OFFER, "1.3.6.1.4.1.64586.1.11"),
			(HANDSHAKE_SECURITY_ACCEPT, "1.3.6.1.4.1.64586.1.12"),
			(HANDSHAKE_PROFILE_ECIES_GCM, "1.3.6.1.4.1.64586.1.100"),
			(CLIENT_CERTIFICATE, "1.3.6.1.4.1.64586.1.13"),
			(CLIENT_SIGNATURE, "1.3.6.1.4.1.64586.1.14"),
			(HANDSHAKE_TRANSPORT_OFFER, "1.3.6.1.4.1.64586.1.15"),
			(HANDSHAKE_TRANSPORT_ACCEPT, "1.3.6.1.4.1.64586.1.16"),
			(RECEIPT_ACK, "1.3.6.1.4.1.64586.1.18"),
			(SESSION_RECEIPT, "1.3.6.1.4.1.64586.1.19"),
			(SESSION_RECEIPT_CONTENT, "1.3.6.1.4.1.64586.1.20"),
			(RECEIPT_ROLE, "1.3.6.1.4.1.64586.1.21"),
			(RECEIPT_ANSWER, "1.3.6.1.4.1.64586.1.22"),
			(HANDSHAKE_SERVER_EPHEMERAL, "1.3.6.1.4.1.64586.1.23"),
			(HANDSHAKE_KEY_CONFIRMATION, "1.3.6.1.4.1.64586.1.24"),
			(ATTR_CONTENT_TYPE, "1.2.840.113549.1.9.3"),
			(ATTR_MESSAGE_DIGEST, "1.2.840.113549.1.9.4"),
		];

		for (oid, expected) in pinned {
			assert_eq!(*oid, ObjectIdentifier::new_unwrap(expected));
		}
	}
}

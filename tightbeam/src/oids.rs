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
//! - `.1` holds the handshake, session, and record attributes, content types, and profiles.
//! - `.1.100` is reserved, because published releases assign it to another key exchange profile.
//! - `.2` holds the algorithms, such as zstd and DHKEM over secp256k1.
//! - `.2.2` is reserved, because published releases assign it to an HPKE suite.
//! - `.3` holds the key purposes of `extendedKeyUsage` (RFC 5280 §4.2.1.12).

use crate::der::asn1::ObjectIdentifier;

/// The CMS `id-data` content type.
///
/// # Sources
///
/// - RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.113549.1.7.1>
pub const DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// The CMS `id-signedData` content type.
///
/// # Sources
///
/// - RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.113549.1.7.2>
pub const SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// The CMS `id-envelopedData` content type.
///
/// # Sources
///
/// - RFC 5652, Cryptographic Message Syntax: <https://datatracker.ietf.org/doc/html/rfc5652>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.113549.1.7.3>
pub const ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.3");

/// The CMS `id-ct-authEnvelopedData` content type.
///
/// ```text
/// id-ct-authEnvelopedData OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  ct(1) 23
/// }
/// ```
///
/// # Sources
///
/// - RFC 5083 §2.1, CMS Authenticated-Enveloped-Data:
///   <https://datatracker.ietf.org/doc/html/rfc5083#section-2.1>
pub const AUTH_ENVELOPED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.23");

/// The `OtherRecipientInfo` type of a `KEMRecipientInfo`, `id-ori-kem`.
///
/// ```text
/// id-ori-kem OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  id-ori(13) 3
/// }
/// ```
///
/// # Sources
///
/// - RFC 9629 §3, Using KEM Algorithms in CMS: <https://datatracker.ietf.org/doc/html/rfc9629#section-3>
pub const ORI_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.13.3");

/// The CMS `id-ct-compressedData` content type.
///
/// It names a `ContentInfo` that carries a `CompressedData`. The
/// `eContentType` inside names the compressed content, which is `id-data` for
/// a frame body (RFC 3274 §1.1).
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
/// nor the S/MIME algorithm registry (RFC 7107) assigns an OID for zstd.
/// Wahid Group, LLC therefore assigns this OID under its IANA PEN 64586, in
/// the algorithms arc `.2`.
///
/// # Sources
///
/// - RFC 8878, Zstandard Compression and the `application/zstd` Media Type:
///   <https://datatracker.ietf.org/doc/html/rfc8878>
pub const COMPRESSION_ZSTD: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.2.1");

/// DHKEM(secp256k1, HKDF-SHA256), HPKE KEM `0x0016`, as the `kem` of a CMS
/// `KEMRecipientInfo`. Its parameters are absent.
///
/// No registry assigns an OID to a DHKEM over secp256k1. Wahid Group, LLC
/// therefore assigns this OID under its IANA PEN 64586, in the algorithms arc
/// `.2`, and `docs/dhkem-secp256k1.md` specifies its use in the shape of
/// RFC 9629 §6.1.
///
/// # Sources
///
/// - RFC 9629 §6.1, the KEM algorithm class: <https://datatracker.ietf.org/doc/html/rfc9629#section-6.1>
/// - RFC 9180 §4.1, DH-based KEM: <https://datatracker.ietf.org/doc/html/rfc9180#section-4.1>
/// - draft-wahby-cfrg-hpke-kem-secp256k1-01:
///   <https://datatracker.ietf.org/doc/html/draft-wahby-cfrg-hpke-kem-secp256k1-01>
pub const DHKEM_SECP256K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.2.3");

/// The hybrid key exchange of ML-KEM-768 and ECDH over secp256k1, as the
/// key exchange a security profile negotiates and as the `kem` of its
/// `KemCiphertext` reply. Its parameters are absent.
///
/// No registry assigns an OID to a hybrid over secp256k1. Wahid Group, LLC
/// therefore assigns this OID under its IANA PEN 64586, in the algorithms arc
/// `.2`, and `docs/handshake.md` specifies its shares and its combiner.
///
/// # Sources
///
/// - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard:
///   <https://csrc.nist.gov/pubs/fips/203/final>
/// - NIST SP 800-227 §4.6, multi-algorithm KEMs: <https://csrc.nist.gov/pubs/sp/800/227/final>
pub const KEM_SECP256K1_ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.2.4");

/// The key purpose of a tightbeam frame and colony signer, as a
/// `KeyPurposeId` of `extendedKeyUsage`.
///
/// No registry names a purpose for a CMS frame signer, and RFC 5280 lets any
/// organization define one. Wahid Group, LLC therefore assigns this OID under
/// its IANA PEN 64586, in the key purposes arc `.3`.
///
/// # Sources
///
/// - RFC 5280 §4.2.1.12, Extended Key Usage: <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12>
pub const KEY_PURPOSE_SIGNER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.3.1");

/// HKDF with SHA3-256 (`id-alg-hkdf-with-sha3-256`), in the S/MIME algorithms
/// arc. A security profile names its key derivation function by this OID.
///
/// # Sources
///
/// - RFC 9688 §5.1, HKDF with SHA3: <https://datatracker.ietf.org/doc/html/rfc9688#section-5.1>
/// - IANA, SMI Security for S/MIME Algorithms:
///   <https://www.iana.org/assignments/smi-numbers/smi-numbers.xhtml>
pub const HKDF_SHA3_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.33");

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

/// The `c-TwoCurve` arc of ANSI X9.62, `characteristic-two` curves, whose
/// children are curves over a binary field.
///
/// # Sources
///
/// - RFC 3279 §2.3.5, the X9.62 curve arcs: <https://datatracker.ietf.org/doc/html/rfc3279#section-2.3.5>
/// - OID repository entry: <https://oid-base.com/get/1.2.840.10045.3.0>
pub const CURVE_X962_C_TWO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.0");

/// The SEC 2 curves over a binary field, `sect113r1` through `sect571r1`,
/// under the `ellipticCurve` arc `1.3.132.0`.
///
/// # Sources
///
/// - SEC 2 v1.0 Appendix A, the curve OIDs: <https://www.secg.org/SEC2-Ver-1.0.pdf>
/// - RFC 5480 §2.1.1.1, the named curves of PKIX:
///   <https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1.1>
pub const BINARY_FIELD_CURVES: [ObjectIdentifier; 18] = [
	ObjectIdentifier::new_unwrap("1.3.132.0.1"),
	ObjectIdentifier::new_unwrap("1.3.132.0.2"),
	ObjectIdentifier::new_unwrap("1.3.132.0.3"),
	ObjectIdentifier::new_unwrap("1.3.132.0.4"),
	ObjectIdentifier::new_unwrap("1.3.132.0.5"),
	ObjectIdentifier::new_unwrap("1.3.132.0.15"),
	ObjectIdentifier::new_unwrap("1.3.132.0.16"),
	ObjectIdentifier::new_unwrap("1.3.132.0.17"),
	ObjectIdentifier::new_unwrap("1.3.132.0.22"),
	ObjectIdentifier::new_unwrap("1.3.132.0.23"),
	ObjectIdentifier::new_unwrap("1.3.132.0.24"),
	ObjectIdentifier::new_unwrap("1.3.132.0.25"),
	ObjectIdentifier::new_unwrap("1.3.132.0.26"),
	ObjectIdentifier::new_unwrap("1.3.132.0.27"),
	ObjectIdentifier::new_unwrap("1.3.132.0.36"),
	ObjectIdentifier::new_unwrap("1.3.132.0.37"),
	ObjectIdentifier::new_unwrap("1.3.132.0.38"),
	ObjectIdentifier::new_unwrap("1.3.132.0.39"),
];

/// X25519, which is Curve25519 for ECDH. It pairs with Ed25519 signatures.
///
/// # Sources
///
/// - RFC 8410, X25519 and Ed25519 algorithm identifiers: <https://datatracker.ietf.org/doc/html/rfc8410>
/// - OID repository entry: <https://oid-base.com/get/1.3.101.110>
pub const CURVE_X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

/// ML-KEM-768 (`id-alg-ml-kem-768`), the post-quantum KEM that NIST
/// standardized from Kyber-768.
///
/// # Sources
///
/// - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard:
///   <https://csrc.nist.gov/pubs/fips/203/final>
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - RFC 9935, ML-KEM algorithm identifiers: <https://datatracker.ietf.org/doc/html/rfc9935>
pub const KEM_ML_KEM_768: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// ML-KEM-1024 (`id-alg-ml-kem-1024`), the post-quantum KEM that NIST
/// standardized from Kyber-1024.
///
/// # Sources
///
/// - FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard:
///   <https://csrc.nist.gov/pubs/fips/203/final>
/// - NIST Computer Security Objects Register, algorithm registration:
///   <https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration>
/// - RFC 9935, ML-KEM algorithm identifiers: <https://datatracker.ietf.org/doc/html/rfc9935>
pub const KEM_ML_KEM_1024: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

/// The handshake attribute that carries the protocol version.
pub const HANDSHAKE_PROTOCOL_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.1");

/// The handshake attribute that carries the algorithm profile.
pub const HANDSHAKE_ALGORITHM_PROFILE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.2");

// 1.3.6.1.4.1.64586.1.3 is reserved for the client nonce attribute. A new
// attribute takes a new arc, so each arc keeps one meaning.

/// The handshake attribute that carries the selected version.
pub const HANDSHAKE_SELECT_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.4");

/// The handshake attribute that carries the selected algorithm.
pub const HANDSHAKE_SELECT_ALGORITHM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.5");

// 1.3.6.1.4.1.64586.1.6 is reserved for the server nonce attribute.

/// The handshake attribute that carries an abort alert.
pub const HANDSHAKE_ABORT_ALERT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.7");

/// The handshake attribute that carries the transcript hash.
pub const HANDSHAKE_TRANSCRIPT_HASH: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.8");

// 1.3.6.1.4.1.64586.1.9 is reserved for the supported curves attribute, and
// 1.3.6.1.4.1.64586.1.10 for the selected curve attribute. A profile names
// its curve.

/// The handshake attribute that carries the security offer.
pub const HANDSHAKE_SECURITY_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.11");

/// The handshake attribute that carries the security accept.
pub const HANDSHAKE_SECURITY_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.12");

/// The composite profile of HPKE over secp256k1, HKDF with SHA3-256, and
/// AES-256-GCM.
pub const HANDSHAKE_PROFILE_HPKE_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.101");

/// The handshake attribute that carries the transport capability offer for
/// multiplexing.
pub const HANDSHAKE_TRANSPORT_OFFER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.15");

/// The handshake attribute that carries the transport capability accept for
/// multiplexing.
pub const HANDSHAKE_TRANSPORT_ACCEPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.16");

// 1.3.6.1.4.1.64586.1.13 and 1.3.6.1.4.1.64586.1.14 are reserved for the
// client certificate and client signature attributes of published releases.
// Both protocols seal the client identity under the handshake secret.

// 1.3.6.1.4.1.64586.1.17 is reserved for the bare receipt signature of
// published releases. Receipt signatures travel as SignerInfos inside the
// receipt SignedData artifact.

/// The OID of the session receipt acknowledgement. The value is an OCTET
/// STRING that holds the DER of an `AuthEnvelopedData`. The envelope seals the
/// client's receipt `SignerInfo` (the countersignature and the confidential
/// settlement answer) under a key derived from the handshake secret.
pub const RECEIPT_ACK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.18");

/// The OID of the session receipt artifact, carried as a CMS attribute. The
/// value is the receipt `SignedData`
/// ([RFC 5652 §5](https://datatracker.ietf.org/doc/html/rfc5652#section-5)).
pub const SESSION_RECEIPT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.19");

/// The `eContentType` of the session receipt body inside the receipt
/// SignedData artifact.
pub const SESSION_RECEIPT_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.20");

/// The signed attribute that binds a receipt `SignerInfo` to its role
/// (INTEGER: 0 server, 1 client), so one party's signature cannot be
/// spliced into the other role (CWE-347).
pub const RECEIPT_ROLE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.21");

/// The signed attribute that carries the client's settlement answer (OCTET
/// STRING) inside its receipt `SignerInfo`, so the countersignature covers the
/// answer the standard CMS way.
pub const RECEIPT_ANSWER: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.22");

/// The OID of the server ephemeral public key, carried as a CMS attribute.
/// The value is an `OriginatorPublicKey` ([RFC 5652 §6.2.2][rfc5652-6.2.2]) on
/// the server Finished, inside the transcript the Finished signs.
///
/// [rfc5652-6.2.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.2
pub const HANDSHAKE_SERVER_EPHEMERAL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.23");

/// The OID of the key-confirmation tag, carried as a CMS attribute. The value
/// is an OCTET STRING as wide as the negotiated digest: an HMAC under a key of
/// the handshake secret. The closing carries the client's tag, and the HPKE
/// reply carries the server Finished.
pub const HANDSHAKE_KEY_CONFIRMATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.24");

/// The content type of the CMS opening, sealed in its `AuthEnvelopedData`.
/// The content carries the client's base secret and its agreement ephemeral.
pub const HANDSHAKE_OPENING_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.25");

/// The content type of the HPKE reply, signed in its `SignedData`. The
/// content is the `ServerHandshake`, which carries the server ephemeral and
/// the negotiated terms.
pub const HANDSHAKE_REPLY_CONTENT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.26");

/// The record attribute that carries the epoch and the sequence number of
/// one record, an authenticated attribute of its `AuthEnvelopedData`. The
/// value is `RecordSequence ::= SEQUENCE { epoch INTEGER, sequence INTEGER }`.
pub const RECORD_SEQUENCE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.27");

/// The OID of the server's share of a KEM exchange, carried as a CMS attribute
/// on the server Finished, inside the transcript the Finished signs. The value
/// is a [`KemCiphertext`](crate::crypto::exchange::KemCiphertext): the `kem`
/// and `kemct` fields of a KEM recipient ([RFC 9629 §3][rfc9629-3]). A DH
/// exchange carries its share under [`HANDSHAKE_SERVER_EPHEMERAL`] instead.
///
/// [rfc9629-3]: https://datatracker.ietf.org/doc/html/rfc9629#section-3
pub const HANDSHAKE_SERVER_KEM_CIPHERTEXT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.28");

/// The PKCS #9 content-type signed attribute ([RFC 5652 §11.1][rfc5652-11.1]).
///
/// [rfc5652-11.1]: https://datatracker.ietf.org/doc/html/rfc5652#section-11.1
pub const ATTR_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");

/// The PKCS #9 message-digest signed attribute
/// ([RFC 5652 §11.2][rfc5652-11.2]).
///
/// [rfc5652-11.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-11.2
pub const ATTR_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

/// The CMS algorithm identifier protection signed attribute,
/// `id-aa-CMSAlgorithmProtection` ([RFC 6211 §2][rfc6211-2]).
///
/// [rfc6211-2]: https://datatracker.ietf.org/doc/html/rfc6211#section-2
pub const ATTR_CMS_ALGORITHM_PROTECTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.52");

/// The arcs of the private arc that no constant takes. Each one is reserved
/// for the meaning that a published release assigns it, so each arc keeps one
/// meaning.
#[cfg(test)]
const RESERVED_ARCS: [ObjectIdentifier; 9] = [
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.3"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.6"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.9"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.10"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.13"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.14"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.17"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.100"),
	ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.2.2"),
];

#[cfg(test)]
mod tests {
	use super::*;

	/// The 18 SEC 2 curves over a binary field (SEC 2 v1.0 Appendix A).
	const SEC2_BINARY_FIELD_CURVES: [ObjectIdentifier; 18] = [
		ObjectIdentifier::new_unwrap("1.3.132.0.1"),  // sect163k1
		ObjectIdentifier::new_unwrap("1.3.132.0.2"),  // sect163r1
		ObjectIdentifier::new_unwrap("1.3.132.0.3"),  // sect239k1
		ObjectIdentifier::new_unwrap("1.3.132.0.4"),  // sect113r1
		ObjectIdentifier::new_unwrap("1.3.132.0.5"),  // sect113r2
		ObjectIdentifier::new_unwrap("1.3.132.0.15"), // sect163r2
		ObjectIdentifier::new_unwrap("1.3.132.0.16"), // sect283k1
		ObjectIdentifier::new_unwrap("1.3.132.0.17"), // sect283r1
		ObjectIdentifier::new_unwrap("1.3.132.0.22"), // sect131r1
		ObjectIdentifier::new_unwrap("1.3.132.0.23"), // sect131r2
		ObjectIdentifier::new_unwrap("1.3.132.0.24"), // sect193r1
		ObjectIdentifier::new_unwrap("1.3.132.0.25"), // sect193r2
		ObjectIdentifier::new_unwrap("1.3.132.0.26"), // sect233k1
		ObjectIdentifier::new_unwrap("1.3.132.0.27"), // sect233r1
		ObjectIdentifier::new_unwrap("1.3.132.0.36"), // sect409k1
		ObjectIdentifier::new_unwrap("1.3.132.0.37"), // sect409r1
		ObjectIdentifier::new_unwrap("1.3.132.0.38"), // sect571k1
		ObjectIdentifier::new_unwrap("1.3.132.0.39"), // sect571r1
	];

	// Each OID constant holds its dotted-decimal value, so an edit that changes
	// an identifier that peers exchange fails the row of that constant. Each
	// reserved arc stays apart from the constants, so each arc keeps one
	// meaning.
	crate::tb_cases! {
		fn each_oid_constant_holds_its_dotted_value((oid, dotted): (ObjectIdentifier, &str)) {
			assert_eq!(ObjectIdentifier::new(dotted), Ok(oid));
			assert!(!RESERVED_ARCS.contains(&oid));
		}
		cases {
			data => (DATA, "1.2.840.113549.1.7.1"),
			signed_data => (SIGNED_DATA, "1.2.840.113549.1.7.2"),
			enveloped_data => (ENVELOPED_DATA, "1.2.840.113549.1.7.3"),
			auth_enveloped_data => (AUTH_ENVELOPED_DATA, "1.2.840.113549.1.9.16.1.23"),
			ori_kem => (ORI_KEM, "1.2.840.113549.1.9.16.13.3"),
			compression_content => (COMPRESSION_CONTENT, "1.2.840.113549.1.9.16.1.9"),
			compression_zlib => (COMPRESSION_ZLIB, "1.2.840.113549.1.9.16.3.8"),
			hkdf_sha3_256 => (HKDF_SHA3_256, "1.2.840.113549.1.9.16.3.33"),
			compression_zstd => (COMPRESSION_ZSTD, "1.3.6.1.4.1.64586.2.1"),
			dhkem_secp256k1 => (DHKEM_SECP256K1, "1.3.6.1.4.1.64586.2.3"),
			kem_secp256k1_ml_kem_768 => (KEM_SECP256K1_ML_KEM_768, "1.3.6.1.4.1.64586.2.4"),
			key_purpose_signer => (KEY_PURPOSE_SIGNER, "1.3.6.1.4.1.64586.3.1"),
			hash_sha256 => (HASH_SHA256, "2.16.840.1.101.3.4.2.1"),
			hash_sha3_256 => (HASH_SHA3_256, "2.16.840.1.101.3.4.2.8"),
			hash_sha3_384 => (HASH_SHA3_384, "2.16.840.1.101.3.4.2.9"),
			hash_sha3_512 => (HASH_SHA3_512, "2.16.840.1.101.3.4.2.10"),
			signer_ecdsa_with_sha256 => (SIGNER_ECDSA_WITH_SHA256, "1.2.840.10045.4.3.2"),
			signer_ecdsa_with_sha3_256 => (SIGNER_ECDSA_WITH_SHA3_256, "2.16.840.1.101.3.4.3.10"),
			signer_ecdsa_with_sha3_512 => (SIGNER_ECDSA_WITH_SHA3_512, "2.16.840.1.101.3.4.3.12"),
			aes_128_gcm => (AES_128_GCM, "2.16.840.1.101.3.4.1.6"),
			aes_256_gcm => (AES_256_GCM, "2.16.840.1.101.3.4.1.46"),
			aes_128_wrap => (AES_128_WRAP, "2.16.840.1.101.3.4.1.5"),
			aes_192_wrap => (AES_192_WRAP, "2.16.840.1.101.3.4.1.25"),
			aes_256_wrap => (AES_256_WRAP, "2.16.840.1.101.3.4.1.45"),
			curve_secp256k1 => (CURVE_SECP256K1, "1.3.132.0.10"),
			curve_nist_p256 => (CURVE_NIST_P256, "1.2.840.10045.3.1.7"),
			curve_nist_p384 => (CURVE_NIST_P384, "1.3.132.0.34"),
			curve_nist_p521 => (CURVE_NIST_P521, "1.3.132.0.35"),
			curve_x962_c_two => (CURVE_X962_C_TWO, "1.2.840.10045.3.0"),
			curve_x25519 => (CURVE_X25519, "1.3.101.110"),
			kem_ml_kem_768 => (KEM_ML_KEM_768, "2.16.840.1.101.3.4.4.2"),
			kem_ml_kem_1024 => (KEM_ML_KEM_1024, "2.16.840.1.101.3.4.4.3"),
			handshake_protocol_version => (HANDSHAKE_PROTOCOL_VERSION, "1.3.6.1.4.1.64586.1.1"),
			handshake_algorithm_profile => (HANDSHAKE_ALGORITHM_PROFILE, "1.3.6.1.4.1.64586.1.2"),
			handshake_select_version => (HANDSHAKE_SELECT_VERSION, "1.3.6.1.4.1.64586.1.4"),
			handshake_select_algorithm => (HANDSHAKE_SELECT_ALGORITHM, "1.3.6.1.4.1.64586.1.5"),
			handshake_abort_alert => (HANDSHAKE_ABORT_ALERT, "1.3.6.1.4.1.64586.1.7"),
			handshake_transcript_hash => (HANDSHAKE_TRANSCRIPT_HASH, "1.3.6.1.4.1.64586.1.8"),
			handshake_security_offer => (HANDSHAKE_SECURITY_OFFER, "1.3.6.1.4.1.64586.1.11"),
			handshake_security_accept => (HANDSHAKE_SECURITY_ACCEPT, "1.3.6.1.4.1.64586.1.12"),
			handshake_profile_hpke_gcm => (HANDSHAKE_PROFILE_HPKE_GCM, "1.3.6.1.4.1.64586.1.101"),
			handshake_transport_offer => (HANDSHAKE_TRANSPORT_OFFER, "1.3.6.1.4.1.64586.1.15"),
			handshake_transport_accept => (HANDSHAKE_TRANSPORT_ACCEPT, "1.3.6.1.4.1.64586.1.16"),
			receipt_ack => (RECEIPT_ACK, "1.3.6.1.4.1.64586.1.18"),
			session_receipt => (SESSION_RECEIPT, "1.3.6.1.4.1.64586.1.19"),
			session_receipt_content => (SESSION_RECEIPT_CONTENT, "1.3.6.1.4.1.64586.1.20"),
			receipt_role => (RECEIPT_ROLE, "1.3.6.1.4.1.64586.1.21"),
			receipt_answer => (RECEIPT_ANSWER, "1.3.6.1.4.1.64586.1.22"),
			handshake_server_ephemeral => (HANDSHAKE_SERVER_EPHEMERAL, "1.3.6.1.4.1.64586.1.23"),
			handshake_key_confirmation => (HANDSHAKE_KEY_CONFIRMATION, "1.3.6.1.4.1.64586.1.24"),
			handshake_opening_content => (HANDSHAKE_OPENING_CONTENT, "1.3.6.1.4.1.64586.1.25"),
			handshake_reply_content => (HANDSHAKE_REPLY_CONTENT, "1.3.6.1.4.1.64586.1.26"),
			record_sequence => (RECORD_SEQUENCE, "1.3.6.1.4.1.64586.1.27"),
			handshake_server_kem_ciphertext => (HANDSHAKE_SERVER_KEM_CIPHERTEXT, "1.3.6.1.4.1.64586.1.28"),
			attr_content_type => (ATTR_CONTENT_TYPE, "1.2.840.113549.1.9.3"),
			attr_message_digest => (ATTR_MESSAGE_DIGEST, "1.2.840.113549.1.9.4"),
			attr_cms_algorithm_protection => (ATTR_CMS_ALGORITHM_PROTECTION, "1.2.840.113549.1.9.52"),
		}
	}

	/// The test pins the 18 SEC 2 curves over a binary field, which a key
	/// refuses, to their dotted-decimal values (SEC 2 v1.0 Appendix A).
	#[test]
	fn binary_field_curves_are_pinned() {
		assert_eq!(BINARY_FIELD_CURVES, SEC2_BINARY_FIELD_CURVES);
	}
}

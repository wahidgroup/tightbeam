#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

// Re-exports
pub use crate::cms::compressed_data::CompressedData;
pub use crate::cms::content_info::ContentInfo;
pub use crate::cms::enveloped_data::EncryptedContentInfo;
pub use crate::cms::signed_data::{EncapsulatedContentInfo, SignerInfo};
pub use crate::der::asn1::OctetString;
pub use crate::der::asn1::*;
pub use crate::der::{Choice, Enumerated, Sequence};
pub use crate::pkcs12::digest_info::DigestInfo;
pub use crate::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
pub use crate::x509::ext::pkix::HashAlgorithm;
pub use crate::x509::ext::pkix::SignatureAlgorithm;

/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
/// id-ct-compressedData OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
pub const COMPRESSION_CONTENT_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// See `<https://datatracker.ietf.org/doc/html/rfc3274>`
/// id-alg-zlibCompress OBJECT IDENTIFIER ::= {
///     iso(1)   member-body(2)  us(840)    rsadsi(113549)
///     pkcs(1)  pkcs-9(9)       smime(16)  alg(3) 8
/// }
pub const COMPRESSION_ZSTD_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.3.8");
/// sha3-256
/// See `<https://datatracker.ietf.org/doc/html/rfc6234>`
pub const HASH_SHA3_256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8");
/// ecdsa-with-SHA256
/// See `<https://oid-base.com/get/1.2.840.10045.4.3.2>`
pub const SIGNER_ECDSA_WITH_SHA3_256_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// id-data
/// See `<https://datatracker.ietf.org/doc/html/rfc5652>`
/// See `<https://oid-base.com/get/1.2.840.113549.1.7.1>`
pub const DATA_OID: der::asn1::ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");

/// Protocol version determines metadata structure and features
///
/// ASN.1 Definition:
/// ```asn1
/// Version ::= ENUMERATED {
///     v0(0),
///     v1(1),
///     v2(2)
/// }
/// ```
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
	V0 = 0,
	V1 = 1,
	V2 = 2,
}

/// Message priority levels (V2+)
///
/// Priority levels inspired by various standards:
/// - RFC 3246: Expedited Forwarding PHB
/// - RFC 2474: Differentiated Services Field
/// - X.400/X.420: Message Handling Systems
/// - SIP RFC 3261: Session priority mechanisms
///
/// Values arranged from highest (0) to lowest (5) priority:
/// - Critical: System/security alerts, emergency notifications
/// - Top: High-priority interactive traffic, real-time responses
/// - High: Important business messages, time-sensitive data
/// - Normal: Standard message traffic (default)
/// - Low: Non-urgent notifications, background updates
/// - Bulk: Batch processing, large data transfers, logs
/// - Heartbeat: Keep-alive signals, periodic status updates
///
/// ASN.1 Definition:
/// ```asn1
/// MessagePriority ::= ENUMERATED {
///     critical(0),
///     top(1),
///     high(2),
///     normal(3),
///     low(4),
///     bulk(5),
///     heartbeat(6)
/// }
/// ```
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
	Critical = 0,
	Top = 1,
	High = 2,
	Normal = 3,
	Low = 4,
	Bulk = 5,
	Heartbeat = 6,
}

/// NxN matrix control flags
///
/// ASN.1 Definition:
/// ```asn1
/// Matrix ::= SEQUENCE {
///     n     INTEGER (1..255),
///     data  OCTET STRING (SIZE(1..(255*255)))  -- MUST be exactly n*n octets; row-major
/// }
/// ```
///
/// Notes:
/// - n MUST be in 1..=255.
/// - data MUST be exactly n*n octets, row-major (cell (r,c) at offset r*n + c).
/// - Encoders MUST only emit conforming lengths; decoders MUST reject
///   non-conforming lengths.
/// - Semantics of cell values are profile-defined. By default, off-diagonal
///   cells are unspecified.
/// - Profiles MAY map position-stable flags onto the diagonal (r == c); unset
///   is 0, set/non-default is non-zero.
/// - Intermediaries MUST preserve bytes unless a profile defines deterministic
///   merge rules.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Asn1Matrix {
	/// Dimension N (1..=255)
	pub n: u8,
	/// Row-major bytes; MUST be exactly n*n octets
	pub data: Vec<u8>,
}

/// Metadata structure for message handling
/// Version determines which fields are present
///
/// ASN.1 Definition:
/// ```asn1
/// Metadata ::= SEQUENCE {
///     id               OCTET STRING,
///     order            INTEGER,
///     compactness      CompressedData OPTIONAL,
///     integrity        [0] DigestInfo OPTIONAL,
///     confidentiality  [1] EncryptedContentInfo OPTIONAL,
///     priority         [2] MessagePriority OPTIONAL,
///     lifetime         [3] INTEGER OPTIONAL,
///     previousFrame    [4] DigestInfo OPTIONAL,
///     matrix           [5] Matrix OPTIONAL
/// }
/// ```
#[derive(der::Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Metadata {
	// Core fields (V0+)
	pub id: Vec<u8>,
	pub order: u64,
	#[asn1(optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub compactness: Option<CompressedData>,

	// V1+ fields
	#[asn1(context_specific = "0", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub integrity: Option<DigestInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub confidentiality: Option<EncryptedContentInfo>,

	// V2+ fields
	#[asn1(context_specific = "2", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub priority: Option<MessagePriority>,
	#[asn1(context_specific = "3", optional = "true")]
	pub lifetime: Option<u64>,
	#[asn1(context_specific = "4", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub previous_frame: Option<DigestInfo>,
	#[asn1(context_specific = "5", optional = "true")]
	pub matrix: Option<Asn1Matrix>,
}

/// Core TightBeam message structure
/// The version field explicitly determines which metadata variant to use
/// The signature signs the entire message (version + metadata + body)
///
/// ASN.1 Definition:
/// ```asn1
/// Frame ::= SEQUENCE {
///     version        Version,
///     metadata       Metadata,
///     message        OCTET STRING,
///     integrity      [0] DigestInfo OPTIONAL,
///     nonrepudiation [1] SignerInfo OPTIONAL
/// }
/// ```
#[derive(der::Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Frame {
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub version: Version,
	pub metadata: Metadata,
	pub message: Vec<u8>,
	#[asn1(context_specific = "0", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub integrity: Option<DigestInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub nonrepudiation: Option<SignerInfo>,
}

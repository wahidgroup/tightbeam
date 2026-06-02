// TODO Why do I need this?
#![allow(unused_assignments)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

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

/// id-data
/// Protocol version determines metadata structure and features
///
/// ASN.1 Definition:
/// ```asn1
/// Version ::= ENUMERATED {
///     v0(0),
///     v1(1),
///     v2(2),
///     v3(3)
/// }
/// ```
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
	V0 = 0,
	V1 = 1,
	V2 = 2,
	V3 = 3,
}

/// Message priority levels (V2+)
///
/// IETF Differentiated Services (DiffServ) architecture.
/// Each level maps to a DiffServ Per-Hop Behavior (PHB) or service class.
///
/// Mapping (lowest to highest priority):
/// - LowEffort: LE PHB (RFC 8622) -- background, non-urgent traffic, logs
/// - Standard: Default Forwarding / CS0 (RFC 2474) -- best-effort default
/// - HighThroughput: High-Throughput Data / AF1 (RFC 4594) -- batch, large transfers
/// - LowLatency: Real-Time Interactive / CS4 (RFC 4594) -- time-sensitive data
/// - Expedited: Expedited Forwarding (RFC 3246) -- real-time interactive responses
/// - NetworkControl: Network Control / CS6-CS7 (RFC 2474, RFC 4594) -- control
///   plane, security/emergency alerts, keep-alive signals
///
/// Secondary mapping: ITU-T X.400/X.420 message importance (low/normal/high).
///
/// ASN.1 Definition:
/// ```asn1
/// MessagePriority ::= ENUMERATED {
///     lowEffort(0),
///     standard(1),
///     highThroughput(2),
///     lowLatency(3),
///     expedited(4),
///     networkControl(5)
/// }
/// ```
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
	LowEffort = 0,
	Standard = 1,
	HighThroughput = 2,
	LowLatency = 3,
	Expedited = 4,
	NetworkControl = 5,
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
#[derive(der::Sequence, Default, Debug, Clone, PartialEq, Eq)]
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

	// V3+ fields
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

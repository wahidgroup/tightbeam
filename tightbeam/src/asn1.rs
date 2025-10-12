#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

pub use spki::AlgorithmIdentifier;

use crate::der::asn1::Null;
use crate::der::{Choice, Enumerated, Sequence};

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

/// Compression algorithms
/// 
/// ASN.1 Definition:
/// ```asn1
/// CompressionAlgorithm ::= ENUMERATED {
///     none(0),
///     zstd(1)
/// }
/// ```
#[cfg(feature = "compress")]
#[repr(u8)]
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CompressionAlgorithm {
	NONE = 0,
	ZSTD = 1,
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

/// Gzip compression information
/// 
/// ASN.1 Definition:
/// ```asn1
/// GzipInfo ::= SEQUENCE {
///     level         INTEGER,
///     originalSize  INTEGER
/// }
/// ```
#[cfg(feature = "gzip")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct GzipInfo {
	pub level: u8,
	pub original_size: u64,
}

/// Zstandard compression information
/// 
/// ASN.1 Definition:
/// ```asn1
/// ZstdInfo ::= SEQUENCE {
///     level         INTEGER,
///     originalSize  INTEGER
/// }
/// ```
#[cfg(feature = "zstd")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct ZstdInfo {
	pub level: u8,
	pub original_size: u64,
}

/// Compression information using CHOICE for different algorithms
/// 
/// ASN.1 Definition:
/// ```asn1
/// CompressionInfo ::= CHOICE {
///     none  NULL,
///     zstd  ZstdInfo,
///     gzip  GzipInfo
/// }
/// ```
#[derive(Choice, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub enum CompressionInfo {
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	NONE(Null),
	#[cfg(feature = "zstd")]
	ZSTD(ZstdInfo),
	// TODO
	#[cfg(feature = "gzip")]
	GZIP(GzipInfo),
}

/// Encryption information for confidentiality
/// 
/// ASN.1 Definition:
/// ```asn1
/// EncryptionInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     parameters  ANY DEFINED BY algorithm
/// }
/// ```
#[cfg(feature = "zeroize")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct EncryptionInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
	T: zeroize::Zeroize,
{
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub algorithm: AlgorithmIdentifier<A>,
	pub parameters: T,
}

/// Encryption information for confidentiality
/// 
/// ASN.1 Definition:
/// ```asn1
/// EncryptionInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     parameters  ANY DEFINED BY algorithm
/// }
/// ```
#[cfg(not(feature = "zeroize"))]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct EncryptionInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
{
	pub algorithm: AlgorithmIdentifier<A>,
	pub parameters: T,
}

/// Hash information for integrity validation
/// 
/// ASN.1 Definition:
/// ```asn1
/// IntegrityInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     parameters  ANY DEFINED BY algorithm
/// }
/// ```
#[cfg(feature = "zeroize")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct IntegrityInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
	T: zeroize::Zeroize,
{
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub algorithm: AlgorithmIdentifier<A>,
	pub parameters: T,
}

/// Hash information for integrity validation
/// 
/// ASN.1 Definition:
/// ```asn1
/// IntegrityInfo ::= SEQUENCE {
///     algorithm   AlgorithmIdentifier,
///     parameters  ANY DEFINED BY algorithm
/// }
/// ```
#[cfg(not(feature = "zeroize"))]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct IntegrityInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
{
	pub algorithm: AlgorithmIdentifier<A>,
	pub parameters: T,
}

/// Signature information for non-repudiation
/// 
/// ASN.1 Definition:
/// ```asn1
/// SignatureInfo ::= SEQUENCE {
///     signatureAlgorithm  AlgorithmIdentifier,
///     signature           OCTET STRING
/// }
/// ```
#[cfg(feature = "zeroize")]
#[derive(Sequence, Debug, Clone, PartialEq, Eq, zeroize::ZeroizeOnDrop)]
pub struct SignatureInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
	T: zeroize::Zeroize,
{
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub signature_algorithm: AlgorithmIdentifier<A>,
	pub signature: T,
}

/// Signature information for non-repudiation
/// 
/// ASN.1 Definition:
/// ```asn1
/// SignatureInfo ::= SEQUENCE {
///     signatureAlgorithm  AlgorithmIdentifier,
///     signature           OCTET STRING
/// }
/// ```
#[cfg(not(feature = "zeroize"))]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct SignatureInfo<A = crate::der::asn1::Any, T = Vec<u8>>
where
	for<'a> A: crate::der::Choice<'a> + crate::der::Encode,
	for<'a> T: crate::der::Decode<'a> + crate::der::Encode,
{
	pub signature_algorithm: AlgorithmIdentifier<A>,
	pub signature: T,
}

/// Metadata structure for message handling
/// Version determines which fields are present
/// 
/// ASN.1 Definition:
/// ```asn1
/// Metadata ::= SEQUENCE {
///     id               OCTET STRING,
///     order            INTEGER,
///     compactness      CompressionInfo,
///     integrity        [0] IntegrityInfo OPTIONAL,
///     confidentiality  [1] EncryptionInfo OPTIONAL,
///     priority         [2] MessagePriority OPTIONAL,
///     lifetime         [3] INTEGER OPTIONAL,
///     previousFrame    [4] IntegrityInfo OPTIONAL,
///     stage            [5] OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Metadata {
	// Core fields (V0+)
	pub id: Vec<u8>,
	pub order: u64,
	pub compactness: CompressionInfo,

	// V1+ fields
	#[asn1(context_specific = "0", optional = "true")]
	pub integrity: Option<IntegrityInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	pub confidentiality: Option<EncryptionInfo>,

	// V2+ fields
	#[asn1(context_specific = "2", optional = "true")]
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub priority: Option<MessagePriority>,
	#[asn1(context_specific = "3", optional = "true")]
	pub lifetime: Option<u64>,
	#[asn1(context_specific = "4", optional = "true")]
	pub previous_frame: Option<IntegrityInfo>,
	#[asn1(context_specific = "5", optional = "true")]
	pub stage: Option<Vec<u8>>,
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
///     integrity      [0] IntegrityInfo OPTIONAL,
///     nonrepudiation [1] SignatureInfo OPTIONAL
/// }
/// ```
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "zeroize", derive(zeroize::ZeroizeOnDrop))]
pub struct Frame {
	#[cfg_attr(feature = "zeroize", zeroize(skip))]
	pub version: Version,
	pub metadata: Metadata,
	pub message: Vec<u8>,
	#[asn1(context_specific = "0", optional = "true")]
	pub integrity: Option<IntegrityInfo>,
	#[asn1(context_specific = "1", optional = "true")]
	pub nonrepudiation: Option<SignatureInfo>,
}

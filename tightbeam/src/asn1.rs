// Re-exports
pub use crate::cms::compressed_data::CompressedData;
pub use crate::cms::content_info::ContentInfo;
pub use crate::cms::enveloped_data::EncryptedContentInfo;
pub use crate::cms::signed_data::{EncapsulatedContentInfo, SignerInfo};
pub use crate::der::asn1::{Any, BitString, ObjectIdentifier, OctetString};
pub use crate::der::{Choice, Enumerated, Sequence};
pub use crate::spki::{AlgorithmIdentifier, AlgorithmIdentifierOwned};
pub use pkcs12::digest_info::DigestInfo;

pub use crate::frame::{BodyTransform, Frame, Metadata};
pub use crate::version::GatedField;

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

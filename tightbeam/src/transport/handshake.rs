#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::{ObjectIdentifier, OctetString};
use crate::der::Sequence;
use crate::Beamable;

// ============================================================================
// TLS 1.2 ServerKeyExchange / ClientKeyExchange (RFC 5246, RFC 5480)
// ============================================================================

/// ServerECDHParams - Elliptic Curve Diffie-Hellman parameters sent by server
/// Per RFC 5246 Section 7.4.3 and RFC 5480 for EC parameters
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct ServerECDHParams {
	/// Named curve OID (e.g., secp256k1)
	pub curve: ObjectIdentifier,
	/// Uncompressed EC point (server's public key)
	/// Format: 0x04 || x || y (65 bytes for secp256k1)
	pub public: OctetString,
}

/// ClientECDHParams - Client's Elliptic Curve Diffie-Hellman public key
/// Per RFC 5246 Section 7.4.7
#[derive(Sequence, Debug, Clone, PartialEq)]
pub struct ClientECDHParams {
	/// Uncompressed EC point (client's public key)
	/// Format: 0x04 || x || y (65 bytes for secp256k1)
	pub public: OctetString,
}

/// ServerKeyExchange message for ECDHE key exchange
/// Per RFC 5246 Section 7.4.3
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerKeyExchange {
	/// ECDH parameters (curve + server public key)
	pub params: ServerECDHParams,
	/// Digital signature over (client_random || server_random || params)
	/// Signature algorithm determined by server certificate
	pub signature: OctetString,
}

/// ClientKeyExchange message for ECDHE key exchange
/// Per RFC 5246 Section 7.4.7
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	/// Client's ECDH public key
	pub params: ClientECDHParams,
}

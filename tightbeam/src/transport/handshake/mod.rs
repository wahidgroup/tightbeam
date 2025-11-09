//! TightBeam handshake protocols for establishing secure communication channels.
//!
//! This module implements two handshake protocols:
//! - **ECIES-based**: Lightweight elliptic curve integrated encryption
//! - **CMS-based**: Full X.509 PKI with signed/enveloped data
//!
//! Both protocols establish authenticated, encrypted sessions and support
//! cryptographic algorithm negotiation between client and server.
//!
//! # Architecture
//!
//! The handshake layer uses a layered architecture with the `CryptoProvider` trait
//! as the abstraction boundary:
//!
//! ```text
//!                    Client Request Flow
//!                           │
//!                           ▼
//!              ┌────────────────────────┐
//!              │   TCP Transport Layer  │
//!              └───────────┬────────────┘
//!                          │
//!                          ▼
//!         ┌─────────────────────────────────┐
//!         │  Handshake Orchestrators        │
//!         │  ┌───────────────────────────┐  │
//!         │  │ EciesHandshakeClient<P>   │  │
//!         │  │ EciesHandshakeServer<P>   │  │
//!         │  │ CmsHandshakeClient<P>     │  │
//!         │  │ CmsHandshakeServer<P>     │  │
//!         │  └───────────────────────────┘  │
//!         │  (P: CryptoProvider)            │
//!         └─────────┬─────────────────┬─────┘
//!                   │                 │
//!         ┌─────────┴──────┐  ┌───────┴──────┐
//!         │ Build Messages │  │ Process Msgs │
//!         │                │  │              │
//!         ▼                │  │              ▼
//!      ┌──────────────┐    │  │    ┌──────────────────┐
//!      │   Builders   │◄───┘  └───►│   Processors     │
//!      ├──────────────┤            ├──────────────────┤
//!      │ • Kari<P>    │            │ • KariRecipient  │
//!      │ • EnvData<P> │            │ • EnvDataProc    │
//!      │ • SignedData │            │ • SignedDataProc │
//!      │   <P>        │            │   (Trait Objs)   │
//!      └──────┬───────┘            └────────┬─────────┘
//!             │                             │
//!             │    ┌────────────────────┐   │
//!             └───►│  CryptoProvider    │◄──┘
//!                  ├────────────────────┤
//!                  │ Associated Types:  │
//!                  │ • Curve            │
//!                  │ • Digest           │
//!                  │ • Kdf              │
//!                  │ • AeadCipher       │
//!                  │ • Signature        │
//!                  │ • SigningKey       │
//!                  │ • VerifyingKey     │
//!                  └────────────────────┘
//!                           │
//!                           ▼
//!               Concrete Implementations
//!              (e.g., DefaultCryptoProvider)
//! ```
//!
//! ## Design Principles
//!
//! - **Compile-time abstraction**: Orchestrators and builders are generic over
//!   `CryptoProvider`, enabling zero-cost algorithm selection at compile time.
//!
//! - **Runtime flexibility**: Processors use trait objects for dynamic dispatch,
//!   allowing protocol handling with heterogeneous implementations.
//!
//! - **Type safety**: Associated types in `CryptoProvider` ensure all cryptographic
//!   components are compatible (e.g., signature algorithm matches curve type).
//!
//! - **Memory safety**: Sensitive material (session keys, private keys) is wrapped
//!   in `Secret<T>` with automatic zeroing on drop.
//!
//! ## Protocol Selection
//!
//! Choose a protocol based on your requirements:
//!
//! | Protocol | Use Case | Overhead | PKI Required |
//! |----------|----------|----------|--------------|
//! | ECIES    | IoT, embedded, performance-critical | Low | Optional |
//! | CMS      | Enterprise PKI, compliance | Higher | Yes |
//!
//! ## Cryptographic Negotiation
//!
//! Both protocols support negotiation via `SecurityOffer` (client) and
//! `SecurityAccept` (server) messages. This allows endpoints to agree on:
//! - Digest algorithm (e.g., SHA3-256)
//! - AEAD cipher (e.g., AES-256-GCM)
//! - Signature algorithm (e.g., ECDSA-with-SHA3-256)
//! - Key wrapping algorithm (for CMS)
//!
//! ### ECIES Protocol Negotiation
//!
//! ECIES implements full wire-level negotiation:
//! - Client sends `SecurityOffer` in `ClientHello` message
//! - Server selects compatible profile from client's offer
//! - Server responds with `SecurityAccept` in `ServerHandshake` message
//! - Client validates server's selection matches offered profiles
//!
//! ### CMS Protocol Negotiation
//!
//! CMS implements wire-level negotiation via EnvelopedData unprotected attributes:
//! - Client sends `SecurityOffer` in KeyExchange EnvelopedData unprotected attributes
//! - Server extracts offer and selects compatible profile using `select_profile()`
//! - Server stores selected profile (accessible via handshake state)
//! - If no offer provided, server uses dealer's choice mode (first configured profile)
//!
//! The server uses `with_supported_profiles()` to configure acceptable profiles.
//! If no profiles are configured when an offer is received, negotiation fails.
//!
//! ## State Machine
//!
//! Handshakes follow a strict state machine to prevent protocol violations:
//! - **Client**: Init → HelloSent → KeyExchangeSent → Complete
//! - **Server**: Init → ServerHelloSent → KeyExchangeReceived → Complete
//!
//! Invalid state transitions return `HandshakeError::InvalidState`.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc as ArcAlloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
pub use std::sync::Arc;
#[cfg(not(feature = "std"))]
pub use ArcAlloc as Arc;

mod attributes;
mod common;
mod error;
mod utils;

#[cfg(test)]
mod tests;

pub mod client;
pub mod server;
pub mod state;

#[cfg(feature = "transport-cms")]
pub mod builders;
#[cfg(feature = "transport-cms")]
pub mod kari;
#[cfg(feature = "transport-cms")]
pub mod processors;

pub use attributes::*;
pub use common::{HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation};
pub use error::HandshakeError;
pub use utils::{aes_256_gcm_algorithm, aes_gcm_decrypt, aes_gcm_encrypt, generate_cek};

#[cfg(feature = "transport-cms")]
pub use builders::{KariBuilderError, TightBeamKariBuilder};
#[cfg(feature = "transport-cms")]
pub use kari::{kari_unwrap, kari_wrap};
#[cfg(feature = "transport-cms")]
pub use processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};

use crate::asn1::OctetString;
use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use crate::crypto::negotiation::{SecurityAccept, SecurityOffer};
use crate::der::{Decode, Encode, Enumerated, Sequence};
use crate::transport::error::TransportError;
use crate::x509::Certificate;
use crate::Beamable;

#[cfg(feature = "std")]
use std::time::Instant;

// ============================================================================
// Server key abstraction for handshake (sign + decrypt)
// ============================================================================

/// Helper trait for cloning boxed ServerHandshakeKey trait objects.
#[cfg(feature = "x509")]
pub trait CloneServerHandshakeKey {
	fn clone_box(&self) -> Box<dyn ServerHandshakeKey>;
}

#[cfg(feature = "x509")]
impl<T> CloneServerHandshakeKey for T
where
	T: ServerHandshakeKey + Clone + 'static,
{
	fn clone_box(&self) -> Box<dyn ServerHandshakeKey> {
		Box::new(self.clone())
	}
}

/// Server-side key operations for handshake protocols.
///
/// This trait provides curve-agnostic abstractions for cryptographic operations
/// needed during server-side handshakes. Implementations handle the curve-specific
/// details internally while exposing a uniform interface.
///
/// The trait is designed to keep private key material encapsulated - all operations
/// that require the private key are performed within the trait methods, and the
/// key itself is never exposed.
#[cfg(feature = "x509")]
pub trait ServerHandshakeKey: Send + Sync + CloneServerHandshakeKey {
	/// Sign a 32-byte server challenge for ECIES handshake.
	///
	/// Used during the server handshake to sign the transcript hash (derived from
	/// client random, server random, and server public key).
	///
	/// # Parameters
	/// - `msg`: 32-byte message to sign (typically a transcript hash)
	///
	/// # Returns
	/// Signature bytes in the curve's native format
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Decrypt an ECIES-encrypted message for ECIES handshake.
	///
	/// The message format is curve-specific (e.g., for secp256k1, it's a
	/// Secp256k1EciesMessage containing ephemeral public key, encrypted data,
	/// and authentication tag).
	///
	/// # Parameters
	/// - `encrypted_bytes`: The complete ECIES message in serialized form
	/// - `aad`: Optional additional authenticated data
	///
	/// # Returns
	/// Decrypted plaintext wrapped in a Secret for memory safety
	fn decrypt_ecies(
		&self,
		encrypted_bytes: &[u8],
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<Vec<u8>>, HandshakeError>;

	/// This creates a complete CMS SignedData with the server's signature,
	/// including proper digest and signature algorithm identifiers. The
	/// signature algorithm is determined by the key type.
	///
	/// # Parameters
	/// - `content`: The data to sign (typically a transcript hash)
	/// - `digest_alg`: Algorithm identifier for the digest algorithm
	/// - `signature_alg`: Algorithm identifier for the signature algorithm
	///
	/// # Returns
	/// DER-encoded CMS SignedData structure
	#[cfg(feature = "transport-cms")]
	fn build_cms_signed_data(
		&self,
		content: &[u8],
		digest_alg: &crate::spki::AlgorithmIdentifierOwned,
		signature_alg: &crate::spki::AlgorithmIdentifierOwned,
	) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Get the digest algorithm identifier used by this key.
	///
	/// Returns the OID and parameters for the digest algorithm (e.g., SHA3-256).
	#[cfg(feature = "transport-cms")]
	fn digest_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned;

	/// Get the signature algorithm identifier used by this key.
	///
	/// Returns the OID and parameters for the signature algorithm (e.g., ecdsa-with-SHA3-256).
	#[cfg(feature = "transport-cms")]
	fn signature_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned;

	/// Create a CMS client handshake orchestrator.
	///
	/// This allows the key implementation to instantiate a CMS client with the appropriate
	/// concrete key type, working around the limitation that CMS clients need the actual
	/// signing key type rather than a trait object.
	///
	/// # Parameters
	/// - `server_cert`: The server's certificate for key agreement
	/// - `validators`: Optional certificate validators to apply during handshake
	///
	/// # Returns
	/// A boxed CMS client handshake orchestrator implementing ClientHandshakeProtocol
	#[cfg(feature = "transport-cms")]
	fn create_cms_client(
		&self,
		server_cert: Arc<crate::x509::Certificate>,
		validators: Option<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
	) -> core::result::Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError>>, HandshakeError>;

	/// Create a CMS server handshake orchestrator.
	///
	/// This allows the key implementation to instantiate a CMS server with the appropriate
	/// concrete key type, working around the limitation that the server needs the actual
	/// signing key type (not a trait object) to extract the secret key for KARI operations.
	///
	/// # Parameters
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	///
	/// # Returns
	/// A boxed CMS server handshake orchestrator implementing ServerHandshakeProtocol
	#[cfg(feature = "transport-cms")]
	fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>>>,
	) -> core::result::Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError>>, HandshakeError>;
}

#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl ServerHandshakeKey for crate::crypto::sign::ecdsa::Secp256k1SigningKey {
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::Signer;
		let sig: Secp256k1Signature = self.try_sign(msg)?;
		Ok(sig.to_bytes().to_vec())
	}

	fn decrypt_ecies(
		&self,
		encrypted_bytes: &[u8],
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<Vec<u8>>, HandshakeError> {
		use crate::crypto::ecies::decrypt;
		use crate::crypto::secret::ToInsecure;

		// Parse the ECIES message from bytes
		let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)?;

		// Convert to SecretKey for ECIES decryption
		let scalar = self.as_nonzero_scalar();
		let sk = k256::SecretKey::from(scalar);

		// Decrypt
		let decrypted = decrypt(&sk, &encrypted_message, aad)?;

		// Convert Secret<[u8]> to Secret<Vec<u8>>
		let vec = decrypted.to_insecure().to_vec();
		Ok(crate::crypto::secret::Secret::new(Box::new(vec)))
	}

	#[cfg(feature = "transport-cms")]
	fn build_cms_signed_data(
		&self,
		content: &[u8],
		digest_alg: &crate::spki::AlgorithmIdentifierOwned,
		signature_alg: &crate::spki::AlgorithmIdentifierOwned,
	) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::transport::handshake::builders::TightBeamSignedDataBuilder;

		// Create builder with concrete signature and digest types
		let mut builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider>::new(
			self.clone(),
			digest_alg.clone(),
			signature_alg.clone(),
		)?;

		// Build and return DER-encoded SignedData
		builder.build_der(content)
	}

	#[cfg(feature = "transport-cms")]
	fn digest_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned {
		crate::spki::AlgorithmIdentifierOwned { oid: crate::HASH_SHA3_256_OID, parameters: None }
	}

	#[cfg(feature = "transport-cms")]
	fn signature_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned {
		crate::spki::AlgorithmIdentifierOwned { oid: crate::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
	}

	#[cfg(feature = "transport-cms")]
	fn create_cms_client(
		&self,
		server_cert: Arc<crate::x509::Certificate>,
		validators: Option<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>,
	) -> core::result::Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError>>, HandshakeError> {
		use crate::crypto::profiles::DefaultCryptoProvider;

		let provider = DefaultCryptoProvider::default();
		let mut client =
			crate::transport::handshake::client::CmsHandshakeClient::new(provider, self.clone(), server_cert);

		// Apply validators if provided
		if let Some(validator) = validators {
			client = client.with_certificate_validator(validator);
		}

		Ok(Box::new(client))
	}

	#[cfg(feature = "transport-cms")]
	fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn crate::crypto::x509::policy::CertificateValidation>>>>,
	) -> core::result::Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError>>, HandshakeError> {
		use crate::crypto::profiles::DefaultCryptoProvider;

		let server = crate::transport::handshake::server::CmsHandshakeServer::<DefaultCryptoProvider, Self>::new(
			self.clone(),
			client_validators,
		);

		Ok(Box::new(server))
	}
}

// ============================================================================
// TCP Handshake State Machine
// ============================================================================
/// State tracking for TCP connection handshake process with optional timeout tracking.
/// This is distinct from the protocol-level HandshakeState in state.rs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakeState {
	#[default]
	None,
	#[cfg(feature = "std")]
	AwaitingServerResponse {
		initiated_at: Instant,
	},
	#[cfg(not(feature = "std"))]
	AwaitingServerResponse {
		initiated_at: u64,
	},
	#[cfg(feature = "std")]
	AwaitingClientFinish {
		initiated_at: Instant,
	},
	#[cfg(not(feature = "std"))]
	AwaitingClientFinish {
		initiated_at: u64,
	},
	Complete,
}

// ============================================================================
// Alert codes for CMS-based handshake abort signaling
// ============================================================================
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeAlert {
	/// Client authentication required but missing certificate/signature
	AuthRequired = 1,
	/// Protocol version mismatch between client and server
	VersionMismatch = 2,
	/// Algorithm (profile OID) mismatch
	AlgorithmMismatch = 3,
	/// Decryption failure (ECIES / AEAD)
	DecryptFail = 4,
	/// Finished (transcript hash) MAC/signature verification failure
	FinishedIntegrityFail = 5,
}

// ============================================================================
// Handshake Protocol Abstraction
// ============================================================================

/// Client-side handshake protocol trait.
///
/// Supports multi-round handshakes where the client may need to send multiple
/// messages before completing the handshake.
pub trait ClientHandshakeProtocol: Send {
	type Error: Into<TransportError> + Send;

	/// Start the handshake, returns the first message to send to the server.
	fn start<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>>;

	/// Handle a response from the server.
	///
	/// Returns `Some(Vec<u8>)` if the client needs to send another message,
	/// or `None` if the client has no more messages to send.
	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a;

	/// Complete the handshake and extract the session key as RuntimeAead.
	///
	/// Should be called after the handshake is complete (when `is_complete()` returns true).
	/// Returns a RuntimeAead containing the negotiated cipher with the derived session key.
	/// The cipher type is determined by the CryptoProvider's AeadCipher associated type,
	/// and the OID is taken from the negotiated security profile.
	#[cfg(feature = "aead")]
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = Result<crate::crypto::aead::RuntimeAead, Self::Error>> + Send + 'a>,
	>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;

	/// Get the negotiated security profile.
	///
	/// Returns `Some(SecurityProfileDesc)` containing the negotiated algorithm OIDs
	/// after successful profile negotiation during handshake. Returns `None` if
	/// negotiation has not occurred yet.
	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc>;
}

/// Server-side handshake protocol trait.
///
/// Supports multi-round handshakes where the server may need to handle multiple
/// requests from the client before completing the handshake.
pub trait ServerHandshakeProtocol: Send {
	type Error: Into<TransportError> + Send;

	/// Handle a request from the client.
	///
	/// Can be called multiple times for multi-round handshakes.
	/// Returns `Some(Vec<u8>)` if the server needs to send a response,
	/// or `None` if the server has no response to send.
	fn handle_request<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a;

	/// Complete the handshake and extract the session key as RuntimeAead.
	///
	/// Should be called after the handshake is complete (when `is_complete()` returns true).
	/// Returns a RuntimeAead containing the negotiated cipher with the derived session key.
	/// The cipher type is determined by the CryptoProvider's AeadCipher associated type,
	/// and the OID is taken from the negotiated security profile.
	#[cfg(feature = "aead")]
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = Result<crate::crypto::aead::RuntimeAead, Self::Error>> + Send + 'a>,
	>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;

	/// Get the validated peer certificate from mutual authentication.
	///
	/// Returns `Some(Certificate)` if the client provided a certificate during the handshake
	/// and it was successfully validated. Returns `None` if no client certificate was provided
	/// or mutual authentication was not configured.
	///
	/// The peer certificate represents the authenticated identity of the client and should
	/// be treated as immutable for the lifetime of the connection.
	#[cfg(feature = "x509")]
	fn peer_certificate(&self) -> Option<&Certificate>;

	/// Get the negotiated security profile.
	///
	/// Returns `Some(SecurityProfileDesc)` containing the negotiated algorithm OIDs
	/// after successful profile negotiation during handshake. Returns `None` if
	/// negotiation has not occurred yet.
	fn selected_profile(&self) -> Option<crate::crypto::profiles::SecurityProfileDesc>;
}

// ============================================================================
// Protocol Selection Enums
// ============================================================================

/// Specifies which handshake protocol to use (ECIES or CMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeProtocolKind {
	/// Use ECIES-based handshake (default, lighter weight)
	Ecies,
	/// Use CMS-based handshake (full X.509 PKI support)
	Cms,
}

impl Default for HandshakeProtocolKind {
	fn default() -> Self {
		Self::Ecies
	}
}

// ============================================================================
// TLS-like ECIES + Server Randomness Protocol Structures
// ============================================================================

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	pub client_random: OctetString,
	#[asn1(optional = "true")]
	pub security_offer: Option<SecurityOffer>,
}

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	#[cfg(feature = "x509")]
	pub certificate: Certificate,
	pub server_random: OctetString,
	pub signature: OctetString,
	#[asn1(optional = "true")]
	pub security_accept: Option<SecurityAccept>,
	/// Indicates if the server requires client certificate for mutual authentication.
	/// When true, client must provide certificate in ClientKeyExchange.
	pub client_cert_required: bool,
}

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	pub encrypted_data: OctetString,
	/// Optional client certificate for mutual authentication.
	/// Included when server indicates client_cert in ServerHandshake.
	#[cfg(feature = "x509")]
	#[asn1(optional = "true")]
	pub client_certificate: Option<Certificate>,
	/// Signature over the handshake transcript (ClientHello || ServerHandshake || encrypted_data)
	/// proving possession of the client certificate's private key.
	#[cfg(feature = "x509")]
	#[asn1(optional = "true")]
	pub client_signature: Option<OctetString>,
}

// ============================================================================
// TryFrom conversions for ECIES <-> CMS types
// ============================================================================

/// Convert ClientHello to SignedData (opaque wrapper)
impl TryFrom<&ClientHello> for crate::cms::signed_data::SignedData {
	type Error = HandshakeError;

	fn try_from(hello: &ClientHello) -> Result<Self, Self::Error> {
		let message_der = hello.to_der()?;
		let octet_string = OctetString::new(message_der)?;
		let econtent = crate::der::Any::from_der(&octet_string.to_der()?)?;

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: Default::default(),
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: crate::asn1::DATA_OID,
				econtent: Some(econtent),
			},
			certificates: None,
			crls: None,
			signer_infos: SignerInfos::try_from(Vec::new())?,
		})
	}
}

/// Extract ClientHello from SignedData
impl TryFrom<&crate::cms::signed_data::SignedData> for ClientHello {
	type Error = HandshakeError;

	fn try_from(signed_data: &crate::cms::signed_data::SignedData) -> Result<Self, Self::Error> {
		let econtent_any = signed_data
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::InvalidServerKeyExchange)?;

		// econtent_any is the full DER encoding of an OCTET STRING
		let octet_string = OctetString::from_der(econtent_any.to_der()?.as_ref())?;
		Ok(ClientHello::from_der(octet_string.as_bytes())?)
	}
}

/// Convert ServerHandshake to SignedData (opaque wrapper)
impl TryFrom<&ServerHandshake> for crate::cms::signed_data::SignedData {
	type Error = HandshakeError;

	fn try_from(handshake: &ServerHandshake) -> Result<Self, Self::Error> {
		let message_der = handshake.to_der()?;
		let octet_string = OctetString::new(message_der)?;
		let econtent = crate::der::Any::from_der(&octet_string.to_der()?)?;

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: Default::default(),
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: crate::asn1::DATA_OID,
				econtent: Some(econtent),
			},
			certificates: None,
			crls: None,
			signer_infos: SignerInfos::try_from(Vec::new())?,
		})
	}
}

/// Extract ServerHandshake from SignedData
impl TryFrom<&crate::cms::signed_data::SignedData> for ServerHandshake {
	type Error = HandshakeError;

	fn try_from(signed_data: &crate::cms::signed_data::SignedData) -> Result<Self, Self::Error> {
		let econtent_any = signed_data
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::InvalidServerKeyExchange)?;

		// econtent_any is the full DER encoding of an OCTET STRING
		let octet_string = OctetString::from_der(econtent_any.to_der()?.as_ref())?;
		Ok(ServerHandshake::from_der(octet_string.as_bytes())?)
	}
}

/// Convert ClientKeyExchange to EnvelopedData (opaque wrapper for ECIES ciphertext)
impl TryFrom<&ClientKeyExchange> for crate::cms::enveloped_data::EnvelopedData {
	type Error = HandshakeError;

	fn try_from(kex: &ClientKeyExchange) -> Result<Self, Self::Error> {
		use crate::cms::content_info::CmsVersion;
		use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfos};
		use crate::der::asn1::OctetString;

		// Build unprotected attributes for client certificate and signature
		#[cfg(feature = "x509")]
		let unprotected_attrs = {
			use crate::der::asn1::SetOfVec;
			use x509_cert::attr::{Attribute, AttributeValue, Attributes};

			let mut attrs = Vec::new();

			if let Some(cert) = &kex.client_certificate {
				let cert_der = cert.to_der()?;
				// Wrap certificate DER in OCTET STRING since certs are SEQUENCE internally
				let cert_octet = OctetString::new(cert_der)?;
				let cert_der_wrapped = cert_octet.to_der()?;
				let cert_any = crate::der::Any::new(crate::der::Tag::OctetString, cert_der_wrapped)?;
				let cert_values = SetOfVec::try_from(vec![AttributeValue::from(cert_any)])?;
				attrs.push(Attribute { oid: crate::asn1::transport::CLIENT_CERTIFICATE_OID, values: cert_values });
			}

			if let Some(sig) = &kex.client_signature {
				// Signature is already an OCTET STRING
				let sig_der = sig.to_der()?;
				let sig_any = crate::der::Any::new(crate::der::Tag::OctetString, sig_der)?;
				let sig_values = SetOfVec::try_from(vec![AttributeValue::from(sig_any)])?;
				attrs.push(Attribute { oid: crate::asn1::transport::CLIENT_SIGNATURE_OID, values: sig_values });
			}

			if attrs.is_empty() {
				None
			} else {
				Some(Attributes::try_from(attrs)?)
			}
		};

		#[cfg(not(feature = "x509"))]
		let unprotected_attrs = None;

		Ok(EnvelopedData {
			version: CmsVersion::V0,
			originator_info: None,
			recip_infos: RecipientInfos::try_from(Vec::new())?,
			encrypted_content: EncryptedContentInfo {
				content_type: crate::asn1::DATA_OID,
				content_enc_alg: crate::transport::handshake::utils::aes_256_gcm_algorithm(),
				encrypted_content: Some(OctetString::new(kex.encrypted_data.as_bytes())?),
			},
			unprotected_attrs,
		})
	}
}

/// Extract ClientKeyExchange from EnvelopedData
impl TryFrom<&crate::cms::enveloped_data::EnvelopedData> for ClientKeyExchange {
	type Error = HandshakeError;

	fn try_from(enveloped_data: &crate::cms::enveloped_data::EnvelopedData) -> Result<Self, Self::Error> {
		let encrypted_bytes = enveloped_data
			.encrypted_content
			.encrypted_content
			.as_ref()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.as_bytes();

		// Extract client certificate and signature from unprotected_attrs
		#[cfg(feature = "x509")]
		let (client_certificate, client_signature) = {
			use crate::der::Decode;
			use x509_cert::Certificate;

			let mut cert = None;
			let mut sig = None;

			if let Some(attrs) = &enveloped_data.unprotected_attrs {
				for attr in attrs.iter() {
					if attr.oid == crate::asn1::transport::CLIENT_CERTIFICATE_OID {
						if let Some(value) = attr.values.iter().next() {
							let octet_bytes = value.value();
							let cert_octet = OctetString::from_der(octet_bytes)?;
							cert = Some(Certificate::from_der(cert_octet.as_bytes())?);
						}
					} else if attr.oid == crate::asn1::transport::CLIENT_SIGNATURE_OID {
						if let Some(value) = attr.values.iter().next() {
							let octet_bytes = value.value();
							sig = Some(OctetString::from_der(octet_bytes)?);
						}
					}
				}
			}

			(cert, sig)
		};

		Ok(ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		})
	}
}

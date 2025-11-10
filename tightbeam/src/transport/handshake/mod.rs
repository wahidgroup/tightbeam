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
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfos};
use crate::cms::signed_data::SignedData;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignerInfos};
use crate::crypto::aead::RuntimeAead;
use crate::crypto::negotiation::{SecurityAccept, SecurityOffer};
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::asn1::SetOfVec;
use crate::der::{Decode, Encode, Enumerated, Sequence};
use crate::transport::error::TransportError;
use crate::transport::handshake::error::Result;
use crate::Beamable;

#[cfg(feature = "std")]
use std::time::Instant;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
use crate::crypto::ecies::Secp256k1EciesMessage;
#[cfg(all(feature = "x509", feature = "secp256k1"))]
use crate::crypto::profiles::DefaultCryptoProvider;
#[cfg(all(feature = "x509", feature = "secp256k1"))]
use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
#[cfg(feature = "x509")]
use crate::crypto::x509::attr::{Attribute, AttributeValue, Attributes};
#[cfg(all(feature = "x509", feature = "secp256k1", feature = "transport-cms"))]
use crate::transport::handshake::client::CmsHandshakeClient;
#[cfg(all(feature = "x509", feature = "secp256k1"))]
use crate::transport::handshake::client::EciesHandshakeClient;
#[cfg(all(feature = "x509", feature = "secp256k1"))]
use crate::transport::handshake::server::{CmsHandshakeServer, EciesHandshakeServer};
#[cfg(feature = "x509")]
use crate::x509::Certificate;

// Type aliases for complex generic types to improve readability
#[cfg(all(feature = "x509", feature = "secp256k1"))]
type DefaultEciesServer = EciesHandshakeServer<DefaultCryptoProvider, Secp256k1SigningKey>;

#[cfg(all(feature = "x509", feature = "secp256k1"))]
type DefaultEciesClient = EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage, Secp256k1SigningKey>;

#[cfg(all(feature = "x509", feature = "secp256k1", feature = "transport-cms"))]
type DefaultCmsServer = CmsHandshakeServer<DefaultCryptoProvider, Secp256k1SigningKey>;

// ============================================================================
// Server key abstraction for handshake (sign + decrypt)
// ============================================================================

/// Server-side key operations for handshake protocols.
///
/// This trait provides a factory interface for creating protocol-specific handshake
/// orchestrators. Each implementation encapsulates a signing key and creates concrete
/// servers that borrow the key, ensuring zero-copy key management and proper encapsulation.
///
/// The encapsulated design ensures that private key material is never exposed through
/// the trait interface - orchestrators borrow the key from their factory.
#[cfg(feature = "x509")]
pub trait ServerHandshakeKey: Send + Sync {
	/// Create an ECIES server handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `server_cert`: The server's certificate to send to client
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption
	/// - `supported_profiles`: Security profiles for negotiation
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	///
	/// # Returns
	/// An ECIES server handshake orchestrator that borrows the encapsulated key
	fn create_ecies_server(
		&self,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		supported_profiles: Vec<SecurityProfileDesc>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>>;

	/// Create an ECIES client handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key for mutual authentication,
	/// ensuring zero-copy key management.
	///
	/// # Parameters
	/// - `server_cert`: Optional server certificate to validate
	/// - `client_cert`: Optional client certificate for mutual auth
	/// - `aad_domain_tag`: Optional domain tag for ECIES encryption
	/// - `validator`: Optional certificate validator for server certificate
	///
	/// # Returns
	/// An ECIES client handshake orchestrator that borrows the encapsulated key
	fn create_ecies_client(
		&self,
		server_cert: Option<Arc<Certificate>>,
		client_cert: Option<Arc<Certificate>>,
		aad_domain_tag: Option<&'static [u8]>,
		validator: Option<Arc<dyn CertificateValidation>>,
	) -> Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send>>;

	/// Create a CMS client handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `server_cert`: The server's certificate for key agreement
	/// - `validators`: Optional certificate validators to apply during handshake
	///
	/// # Returns
	/// A CMS client handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	fn create_cms_client(
		&self,
		server_cert: Arc<Certificate>,
		validators: Option<Arc<dyn CertificateValidation>>,
	) -> Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send>>;

	/// Create a CMS server handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	///
	/// # Returns
	/// A CMS server handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>>;
}

/// Encapsulated server key manager for handshake protocols.
///
/// This struct encapsulates a signing key and provides factory methods to create
/// handshake orchestrators that borrow the key by reference, ensuring zero-copy
/// key management and proper encapsulation.
///
/// The key material is never exposed through the public API - orchestrators
/// get shared ownership via Arc cloning.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct ServerKeyManager {
	signing_key: Arc<Secp256k1SigningKey>,
}

#[cfg(feature = "x509")]
impl ServerKeyManager {
	/// Create a new key manager with the given signing key.
	///
	/// The key is encapsulated and will never be exposed through the public API.
	pub fn new(signing_key: Secp256k1SigningKey) -> Self {
		Self { signing_key: Arc::new(signing_key) }
	}
}

#[cfg(feature = "x509")]
impl ServerKeyManager {
	/// Create an ECIES server handshake orchestrator using the encapsulated key.
	///
	/// The orchestrator borrows the signing key by reference, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `server_cert`: The server's certificate to send to client
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption
	/// - `supported_profiles`: Security profiles for negotiation
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	///
	/// # Returns
	/// An ECIES server handshake orchestrator that borrows the encapsulated key
	pub fn create_ecies_server<'a>(
		&'a self,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		supported_profiles: Vec<SecurityProfileDesc>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<DefaultEciesServer> {
		let server =
			DefaultEciesServer::new(Arc::clone(&self.signing_key), server_cert, aad_domain_tag, client_validators)
				.with_supported_profiles(supported_profiles);

		Ok(server)
	}

	/// Create an ECIES client handshake orchestrator using the encapsulated key.
	///
	/// The orchestrator borrows the signing key by reference for mutual authentication,
	/// ensuring zero-copy key management.
	///
	/// # Parameters
	/// - `server_cert`: Optional server certificate to validate
	/// - `client_cert`: Optional client certificate for mutual auth
	/// - `aad_domain_tag`: Optional domain tag for ECIES encryption
	/// - `validator`: Optional certificate validator for server certificate
	///
	/// # Returns
	/// An ECIES client handshake orchestrator that borrows the encapsulated key
	pub fn create_ecies_client<'a>(
		&'a self,
		_server_cert: Option<Arc<Certificate>>,
		client_cert: Option<Arc<Certificate>>,
		aad_domain_tag: Option<&'static [u8]>,
		validator: Option<Arc<dyn CertificateValidation>>,
	) -> Result<DefaultEciesClient> {
		// Create client with mutual auth (K = Arc reference to encapsulated signing key)
		let signing_key = client_cert.as_ref().map(|_| Arc::clone(&self.signing_key));
		let client = DefaultEciesClient::new_with_identity(aad_domain_tag, client_cert.clone(), signing_key);

		// Apply certificate validator if provided
		let client = if let Some(val) = validator {
			client.with_certificate_validator(val)
		} else {
			client
		};

		Ok(client)
	}

	/// Create a CMS client handshake orchestrator using the encapsulated key.
	///
	/// The orchestrator borrows the signing key by reference, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `server_cert`: The server's certificate for key agreement
	/// - `validators`: Optional certificate validators to apply during handshake
	///
	/// # Returns
	/// A CMS client handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	pub fn create_cms_client<'a>(
		&'a self,
		_server_cert: Arc<Certificate>,
		validators: Option<Arc<dyn CertificateValidation>>,
	) -> Result<CmsHandshakeClient<DefaultCryptoProvider>> {
		let provider = DefaultCryptoProvider::default();
		let mut client = CmsHandshakeClient::new(provider, (*self.signing_key).clone(), _server_cert);

		// Apply validators if provided
		if let Some(validator) = validators {
			client = client.with_certificate_validator(validator);
		}

		Ok(client)
	}

	/// Create a CMS server handshake orchestrator using the encapsulated key.
	///
	/// The orchestrator borrows the signing key by reference, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	///
	/// # Returns
	/// A CMS server handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	pub fn create_cms_server<'a>(
		&'a self,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<DefaultCmsServer> {
		let server = DefaultCmsServer::new((*self.signing_key).clone(), client_validators);
		Ok(server)
	}
}

#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl ServerHandshakeKey for Secp256k1SigningKey {
	fn create_ecies_server(
		&self,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		supported_profiles: Vec<SecurityProfileDesc>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>> {
		let server = DefaultEciesServer::new(Arc::new(self.clone()), server_cert, aad_domain_tag, client_validators)
			.with_supported_profiles(supported_profiles);

		Ok(Box::new(server))
	}

	fn create_ecies_client(
		&self,
		_server_cert: Option<Arc<Certificate>>,
		client_cert: Option<Arc<Certificate>>,
		aad_domain_tag: Option<&'static [u8]>,
		validator: Option<Arc<dyn CertificateValidation>>,
	) -> Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send>> {
		let signing_key = client_cert.as_ref().map(|_| Arc::new(self.clone()));
		let client = DefaultEciesClient::new_with_identity(aad_domain_tag, client_cert.clone(), signing_key);

		let client = if let Some(val) = validator {
			client.with_certificate_validator(val)
		} else {
			client
		};

		Ok(Box::new(client))
	}

	#[cfg(feature = "transport-cms")]
	fn create_cms_client(
		&self,
		server_cert: Arc<Certificate>,
		validators: Option<Arc<dyn CertificateValidation>>,
	) -> Result<Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send>> {
		let provider = DefaultCryptoProvider::default();
		let mut client = CmsHandshakeClient::new(provider, self.clone(), server_cert);

		if let Some(validator) = validators {
			client = client.with_certificate_validator(validator);
		}

		Ok(Box::new(client))
	}

	#[cfg(feature = "transport-cms")]
	fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send>> {
		let server = DefaultCmsServer::new(self.clone(), client_validators);
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
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = ::core::result::Result<Vec<u8>, Self::Error>> + Send + 'a>>;

	/// Handle a response from the server.
	///
	/// Returns `Some(Vec<u8>)` if the client needs to send another message,
	/// or `None` if the client has no more messages to send.
	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = ::core::result::Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>,
	>
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
		Box<dyn core::future::Future<Output = ::core::result::Result<RuntimeAead, Self::Error>> + Send + 'a>,
	>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;

	/// Get the negotiated security profile.
	///
	/// Returns `Some(SecurityProfileDesc)` containing the negotiated algorithm OIDs
	/// after successful profile negotiation during handshake. Returns `None` if
	/// negotiation has not occurred yet.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
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
	) -> core::pin::Pin<
		Box<dyn core::future::Future<Output = ::core::result::Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>,
	>
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
		Box<dyn core::future::Future<Output = ::core::result::Result<RuntimeAead, Self::Error>> + Send + 'a>,
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

/// Helper function to convert any encodable type to SignedData (opaque wrapper)
fn encodable_to_signed_data<T: Encode>(message: &T) -> Result<SignedData> {
	let message_der = message.to_der()?;
	let octet_string = OctetString::new(message_der)?;
	let econtent = crate::der::Any::from_der(&octet_string.to_der()?)?;

	Ok(SignedData {
		version: CmsVersion::V1,
		digest_algorithms: Default::default(),
		encap_content_info: EncapsulatedContentInfo { econtent_type: crate::asn1::DATA_OID, econtent: Some(econtent) },
		certificates: None,
		crls: None,
		signer_infos: SignerInfos::try_from(Vec::new())?,
	})
}

/// Helper function to extract any decodable type from SignedData
fn signed_data_to_decodable<T: for<'a> Decode<'a>>(signed_data: &SignedData) -> Result<T> {
	let econtent_any = signed_data
		.encap_content_info
		.econtent
		.as_ref()
		.ok_or(HandshakeError::InvalidServerKeyExchange)?;

	// econtent_any is the full DER encoding of an OCTET STRING
	let octet_string = OctetString::from_der(econtent_any.to_der()?.as_ref())?;
	Ok(T::from_der(octet_string.as_bytes())?)
}

/// Convert ClientHello to SignedData (opaque wrapper)
impl TryFrom<&ClientHello> for SignedData {
	type Error = HandshakeError;

	fn try_from(hello: &ClientHello) -> ::core::result::Result<Self, Self::Error> {
		encodable_to_signed_data(hello)
	}
}

/// Extract ClientHello from SignedData
impl TryFrom<&SignedData> for ClientHello {
	type Error = HandshakeError;

	fn try_from(signed_data: &SignedData) -> ::core::result::Result<Self, Self::Error> {
		signed_data_to_decodable(signed_data)
	}
}

/// Convert ServerHandshake to SignedData (opaque wrapper)
impl TryFrom<&ServerHandshake> for SignedData {
	type Error = HandshakeError;

	fn try_from(handshake: &ServerHandshake) -> ::core::result::Result<Self, Self::Error> {
		encodable_to_signed_data(handshake)
	}
}

/// Extract ServerHandshake from SignedData
impl TryFrom<&SignedData> for ServerHandshake {
	type Error = HandshakeError;

	fn try_from(signed_data: &SignedData) -> ::core::result::Result<Self, Self::Error> {
		signed_data_to_decodable(signed_data)
	}
}

/// Helper function to build unprotected attributes for ClientKeyExchange
#[cfg(feature = "x509")]
fn build_client_key_exchange_attrs(kex: &ClientKeyExchange) -> Result<Option<x509_cert::attr::Attributes>> {
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
		Ok(None)
	} else {
		Ok(Some(Attributes::try_from(attrs)?))
	}
}

/// Helper function to parse unprotected attributes from EnvelopedData
#[cfg(feature = "x509")]
fn parse_client_key_exchange_attrs(
	enveloped_data: &crate::cms::enveloped_data::EnvelopedData,
) -> Result<(Option<Certificate>, Option<OctetString>)> {
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

	Ok((cert, sig))
}

/// Convert ClientKeyExchange to EnvelopedData (opaque wrapper for ECIES ciphertext)
impl TryFrom<&ClientKeyExchange> for crate::cms::enveloped_data::EnvelopedData {
	type Error = HandshakeError;

	fn try_from(kex: &ClientKeyExchange) -> ::core::result::Result<Self, Self::Error> {
		// Build unprotected attributes for client certificate and signature
		#[cfg(feature = "x509")]
		let unprotected_attrs = build_client_key_exchange_attrs(kex)?;

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

	fn try_from(
		enveloped_data: &crate::cms::enveloped_data::EnvelopedData,
	) -> ::core::result::Result<Self, Self::Error> {
		let encrypted_bytes = enveloped_data
			.encrypted_content
			.encrypted_content
			.as_ref()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.as_bytes();

		// Extract client certificate and signature from unprotected_attrs
		#[cfg(feature = "x509")]
		let (client_certificate, client_signature) = parse_client_key_exchange_attrs(enveloped_data)?;

		Ok(ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		})
	}
}

//! TightBeam handshake protocols for establishing secure communication channels.
//!
//! This module implements two handshake protocols:
//! - **ECIES-based**: Lightweight elliptic curve integrated encryption
//! - **CMS-based**: Full X.509 PKI with signed/enveloped data
//!
//! Both protocols establish authenticated, encrypted sessions and support
//! cryptographic algorithm negotiation between client and server.
//!
//! # Protocol Capabilities
//!
//! TightBeam provides security with flexible deployment options:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                        TIGHTBEAM HANDSHAKE CAPABILITIES                │
//! ├────────────────────────────────────────────────────────────────────────┤
//! │  AUTHENTICATION           ENCRYPTION          NEGOTIATION              │
//! │  • Server authentication  • Session keys      • Algorithm selection    │
//! │  • Mutual authentication  • Forward secrecy   • Profile negotiation    │
//! │  • Certificate validation • AEAD ciphers      • Dealer's choice mode   │
//! │  • Transcript integrity   • Perfect secrecy   • Wire-level protocol    │
//! └────────────────────────────────────────────────────────────────────────┘
//!
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                          HANDSHAKE FLOW                                │
//! ├────────────────────────────────────────────────────────────────────────┤
//! │                                                                        │
//! │ Client ─────────────────────────── Server                              │
//! │  │                           │                                         │
//! │  │── ClientHello ───────────►│  (client_rand, security_offer?)         │
//! │  │                           │                                         │
//! │  │◄─ ServerHandshake ────────│  (server_rand, cert, sig, accept?, ma?) │
//! │  │                           │                                         │
//! │  │── ClientKeyExchange ─────►│  (encrypted_key, [cert, sig]?)          │
//! │  │                           │                                         │
//! │  │ ◄═ Session Established ═► │  (AEAD keys derived)                    │
//! │  │                           │                                         │
//! │  └───────────────────────────┘                                         │
//! └────────────────────────────────────────────────────────────────────────┘
//! **Legend:**
//! - `[]` = optional fields, only present if mutual authentication is required
//! - Arrows show message direction and content
//! - Session establishment occurs after successful key exchange
//! ```
//!
//! # Architecture
//!
//! The handshake layer uses a layered architecture with the `CryptoProvider`
//! trait as the abstraction boundary:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                          APPLICATION LAYER                             │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    TCP Transport Layer                          │   │
//! │  └─────────────────────┬───────────────────────┬───────────────────┘   │
//! │                        │                       │                       │
//! │  ┌─────────────────────▼───────┐    ┌──────────▼────────┐              │
//! │  │   Handshake Orchestrators   │    │   CryptoProvider  │              │
//! │  │  ┌────────────────────────┐ │    │  ┌─────────────┐  │              │
//! │  │  │ EciesHandshakeClient<P>│ │    │  │  Curve      │  │              │
//! │  │  │ EciesHandshakeServer<P>│ │    │  │  Digest     │  │              │
//! │  │  │ CmsHandshakeClient<P>  │ │    │  │  KDF        │  │              │
//! │  │  │ CmsHandshakeServer<P>  │ │    │  │  AEAD       │  │              │
//! │  │  └────────────────────────┘ │    │  │  Signature  │  │              │
//! │  │         (Generic)           │    │  │  SigningKey │  │              │
//! │  └─────────────────────────────┘    │  └─────────────┘  │              │
//! │                                     │    (Associated)   │              │
//! │  ┌─────────────────────────────┐    └───────────────────┘              │
//! │  │        Builders &           │                                       │
//! │  │       Processors            │                                       │
//! │  │  ┌───────────────────────┐  │                                       │
//! │  │  │ KariBuilder<P>        │  │                                       │
//! │  │  │ EnvDataBuilder<P>     │  │                                       │
//! │  │  │ KariRecipient         │  │                                       │
//! │  │  │ EnvDataProcessor      │  │                                       │
//! │  │  └───────────────────────┘  │                                       │
//! │  │   (Compile-time Generic)    │                                       │
//! │  └─────────────────────────────┘                                       │
//! └────────────────────────────────────────────────────────────────────────┘
//!
//! ## Key:
//! P = CryptoProvider trait,
//! <P> = Compile-time generic,
//! (Trait Obj) = Runtime dispatch
//! ```
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
//! - If no offer provided, server uses first configured profile
//!
//! The server uses `with_supported_profiles()` to configure acceptable profiles.
//! If no profiles are configured when an offer is received, negotiation fails.
//!
//! ## State Machine
//!
//! Handshakes follow a strict state machine to prevent protocol violations.
//! Each role machine is deliberately the *union* of the ECIES and CMS message
//! flows. The orchestrator owns selecting the correct sequence for its
//! protocol (see [`state`]):
//! - **Client**: Init -> HelloSent -> ServerHelloReceived -> KeyExchangeSent ->
//!   ServerFinishedReceived -> ClientFinishedSent -> Completed, with ECIES
//!   short-circuits Init -> KeyExchangeSent and KeyExchangeSent -> Completed
//! - **Server**: Init -> ClientHelloReceived -> ServerHelloSent ->
//!   KeyExchangeReceived -> ServerFinishedSent -> ClientFinishedReceived ->
//!   Completed, with the matching ECIES short-circuits
//! - Any non-terminal state may classify to the Aborted or Failed terminals
//!
//! Invalid state transitions return `HandshakeError::InvalidState`.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

#[cfg(not(feature = "std"))]
pub(crate) use alloc::sync::Arc;
#[cfg(feature = "std")]
pub(crate) use std::sync::Arc;

mod attributes;
mod common;
mod error;
mod utils;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) use utils::HandshakeOctets;
#[cfg(all(
	feature = "x509",
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) use utils::HandshakeVerifyingKey;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod wire;

#[cfg(test)]
mod tests;

pub mod client;
pub mod negotiation;
pub mod receipt;
pub mod server;
pub mod state;

pub mod primitives;

#[cfg(feature = "transport-cms")]
pub mod builders;
#[cfg(feature = "transport-cms")]
pub mod kari;
#[cfg(feature = "transport-cms")]
pub mod processors;

pub use common::{
	DirectionalCiphers, EpochMaterials, HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation,
};
pub use error::HandshakeError;
pub(crate) use utils::aes_256_gcm_algorithm;

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
mod mux {
	pub(crate) use super::common::derive_directional_from_oid;
	pub(crate) use super::utils::compute_transcript_digest;
}

#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-ecies")
))]
pub(crate) use mux::*;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub use attributes::HandshakeAttribute;
#[cfg(feature = "transport-cms")]
pub use builders::{KariBuilderError, TightBeamKariBuilder};
#[cfg(feature = "transport-cms")]
pub use kari::{kari_unwrap, kari_wrap};
#[cfg(all(feature = "transport-cms", feature = "kem", feature = "unstable-pqxdh"))]
pub use kari::{kari_unwrap_hybrid, kari_wrap_hybrid};
#[cfg(feature = "transport-cms")]
pub use processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};

use core::marker::PhantomData;
use core::result::Result as CoreResult;

use crate::asn1::OctetString;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfos};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use crate::crypto::aead::SessionKeys;
use crate::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider, SecurityProfileDesc};
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::asn1::SetOfVec;
use crate::der::{Any, Decode, Encode, Enumerated, Sequence, Tag};
use crate::oids::{CLIENT_CERTIFICATE, CLIENT_SIGNATURE, DATA};
use crate::transport::error::TransportError;
use crate::transport::handshake::error::Result;
use crate::transport::handshake::negotiation::{
	MuxSettings, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::utils::marker::{MaybeSend, MaybeSendFuture};
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod transport {
	pub use crate::crypto::aead::KeyInit;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
	pub use crate::crypto::sign::Verifier;
	pub use crate::transport::handshake::negotiation::TransportAuthorizer;
	pub use crate::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use transport::*;

#[cfg(feature = "transport-cms")]
mod cms {
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::spki::EncodePublicKey;
	pub use crate::transport::handshake::server::CmsHandshakeServer;
}

#[cfg(feature = "transport-cms")]
use cms::*;

#[cfg(feature = "transport-ecies")]
mod ecies {
	pub use crate::cms::signed_data::SignerInfo;
	pub use crate::crypto::ecies::{EciesEphemeral, EciesMessageOps, EciesPublicKeyOps};
	pub use crate::crypto::sign::SignatureEncoding;
	pub use crate::transport::handshake::client::{EciesHandshakeClient, ExtractVerifyingKey};
	pub use crate::transport::handshake::server::EciesHandshakeServer;
}

#[cfg(feature = "transport-ecies")]
use ecies::*;

#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
use std::time::Instant;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::crypto::x509::attr::{Attribute, AttributeValue, Attributes};
	pub use crate::x509::Certificate;

	#[cfg(feature = "secp256k1")]
	pub use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use crate::transport::state::ClientIdentity;
}

#[cfg(feature = "x509")]
use x509::*;

/// Server-side key operations for handshake protocols.
///
/// This trait provides a factory interface for creating protocol-specific
/// handshake orchestrators. Each implementation encapsulates a signing key
/// and creates concrete servers that borrow the key, ensuring zero-copy key
/// management and proper encapsulation.
#[cfg(feature = "x509")]
pub trait ServerHandshakeKey: Send + Sync {
	/// ECIES server orchestrator borrowing the encapsulated signing key.
	fn create_ecies_server(
		&self,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		supported_profiles: Vec<SecurityProfileDesc>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Result<BoxedServerHandshake>;

	/// ECIES client orchestrator borrowing the encapsulated signing key.
	fn create_ecies_client(
		self: &Arc<Self>,
		server_cert: Option<Arc<Certificate>>,
		client_cert: Option<Arc<Certificate>>,
		aad_domain_tag: Option<&'static [u8]>,
		validator: Option<Arc<dyn CertificateValidation>>,
	) -> Result<BoxedClientHandshake>;

	/// Create a CMS client handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Returns
	/// A CMS client handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	fn create_cms_client(self: &Arc<Self>, config: CmsClientConfig) -> Result<BoxedClientHandshake>;

	/// Create a CMS server handshake orchestrator.
	///
	/// The orchestrator borrows the encapsulated signing key, ensuring zero-copy
	/// key management and proper encapsulation.
	///
	/// # Parameters
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	/// - `supported_profiles`: Security profiles for negotiation
	///
	/// # Returns
	/// A CMS server handshake orchestrator that borrows the encapsulated key
	#[cfg(feature = "transport-cms")]
	fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
		supported_profiles: Vec<SecurityProfileDesc>,
	) -> Result<BoxedServerHandshake>;
}

/// Provisioned server identity for a CMS client handshake.
///
/// The session key is encrypted to the identity's leaf certificate, so it
/// must be supplied up front rather than learned from the wire.
#[cfg(feature = "transport-cms")]
pub enum CmsServerIdentity {
	/// A bare server certificate, evaluated directly against the trust store.
	Certificate(Arc<Certificate>),
	/// Full server chain, ordered root to leaf. Path validation runs over the
	/// chain ([RFC 5280 §6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1))
	/// and the leaf becomes the encryption target.
	Chain(Arc<[Certificate]>),
}

#[cfg(feature = "transport-cms")]
impl From<Arc<Certificate>> for CmsServerIdentity {
	fn from(certificate: Arc<Certificate>) -> Self {
		Self::Certificate(certificate)
	}
}

#[cfg(feature = "transport-cms")]
impl From<Arc<[Certificate]>> for CmsServerIdentity {
	fn from(chain: Arc<[Certificate]>) -> Self {
		Self::Chain(chain)
	}
}

/// Configuration for a CMS client handshake orchestrator.
///
/// CMS is a key-transport handshake: the client encrypts the session key to
/// the server's public key in its first message, so the server identity must
/// be provisioned up front rather than learned from the wire.
#[cfg(feature = "transport-cms")]
pub struct CmsClientConfig {
	/// The provisioned server identity the session key is encrypted to.
	pub server_identity: CmsServerIdentity,
	/// Trust store that authenticates the server identity. Mandatory:
	/// a CMS handshake without a trust store cannot authenticate anyone
	/// (CWE-295).
	pub trust_store: Arc<dyn CertificateTrust>,
	/// Profiles offered to the server for negotiation.
	pub security_offer: Option<SecurityOffer>,
	/// Transport capabilities (multiplexing) offered to the server.
	pub transport_offer: Option<TransportOffer>,
	/// Client certificate embedded in the Finished message for mutual
	/// authentication.
	pub client_certificate: Option<Arc<Certificate>>,
	/// Receipt approver consulted before countersigning a session
	/// receipt. `None` fails closed on challenge-bearing receipts.
	pub receipt_approver: Option<Arc<dyn ReceiptApprover>>,
}

/// Encapsulated server key manager for handshake protocols.
///
/// This struct encapsulates a key provider and provides factory methods to create
/// handshake orchestrators that use the provider for cryptographic operations,
/// ensuring proper encapsulation and enabling HSM/KMS integration.
///
/// The key material is never exposed through the public API - orchestrators
/// get shared ownership via Arc cloning.
#[cfg(feature = "x509")]
pub struct HandshakeKeyManager<P: CryptoProvider> {
	provider: Arc<dyn SigningKeyProvider>,
	_phantom: PhantomData<P>,
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> Clone for HandshakeKeyManager<P> {
	fn clone(&self) -> Self {
		Self { provider: Arc::clone(&self.provider), _phantom: PhantomData }
	}
}

#[cfg(feature = "x509")]
impl From<Secp256k1SigningKey> for HandshakeKeyManager<DefaultCryptoProvider> {
	fn from(signing_key: Secp256k1SigningKey) -> Self {
		let provider = Secp256k1KeyProvider::from(signing_key);
		Self { provider: Arc::new(provider), _phantom: PhantomData }
	}
}

#[cfg(feature = "x509")]
impl From<Secp256k1KeyProvider> for HandshakeKeyManager<DefaultCryptoProvider> {
	fn from(provider: Secp256k1KeyProvider) -> Self {
		Self { provider: Arc::new(provider), _phantom: PhantomData }
	}
}

#[cfg(feature = "x509")]
impl From<Arc<dyn SigningKeyProvider>> for HandshakeKeyManager<DefaultCryptoProvider> {
	fn from(provider: Arc<dyn SigningKeyProvider>) -> Self {
		Self { provider, _phantom: PhantomData }
	}
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider> HandshakeKeyManager<P> {
	/// The signing key provider this manager was built from.
	///
	/// An endpoint that signs control frames reads the provider from the
	/// manager that already holds it, rather than keeping a second handle.
	pub fn provider(&self) -> &dyn SigningKeyProvider {
		self.provider.as_ref()
	}
}

#[cfg(feature = "x509")]
impl<P: CryptoProvider + Send + Sync + 'static> HandshakeKeyManager<P> {
	pub fn new(provider: Arc<dyn SigningKeyProvider>) -> Self {
		Self { provider, _phantom: PhantomData }
	}

	/// Shared handle to the encapsulated signing provider, for
	/// post-handshake signers (in-band epoch renewals). The key
	/// material itself stays behind the provider abstraction.
	#[cfg(all(
		feature = "transport-multiplex",
		any(feature = "transport-cms", feature = "transport-ecies")
	))]
	pub(crate) fn signing_provider(&self) -> Arc<dyn SigningKeyProvider> {
		Arc::clone(&self.provider)
	}

	/// ECIES server orchestrator via the encapsulated key provider.
	#[cfg(feature = "transport-ecies")]
	#[allow(clippy::too_many_arguments)]
	pub fn create_ecies_server(
		&self,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		supported_profiles: Vec<SecurityProfileDesc>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
		transport_config: Option<TransportOffer>,
		transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
		session_observer: Option<Arc<dyn SessionObserver>>,
	) -> Result<BoxedServerHandshake>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		P::VerifyingKey: Verifier<P::Signature> + for<'b> From<&'b PublicKey<P::Curve>>,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
		P::Signature: SignatureEncoding,
	{
		let provider = Arc::clone(&self.provider);
		let mut server = EciesHandshakeServer::<P>::new(provider, server_cert, aad_domain_tag, client_validators);
		server = server.with_supported_profiles(supported_profiles);

		if let Some(config) = transport_config {
			server = server.with_transport_config(config);
		}
		if let Some(authorizer) = transport_authorizer {
			server = server.with_transport_authorizer(authorizer);
		}
		if let Some(observer) = session_observer {
			server = server.with_session_observer(observer);
		}

		Ok(Box::new(server))
	}

	/// ECIES client orchestrator via the encapsulated key provider.
	#[cfg(feature = "transport-ecies")]
	pub fn create_ecies_client<M>(
		self: &Arc<Self>,
		_server_cert: Option<Arc<Certificate>>,
		client_cert: Option<Arc<Certificate>>,
		aad_domain_tag: Option<&'static [u8]>,
		validator: Option<Arc<dyn CertificateValidation>>,
		transport_offer: Option<TransportOffer>,
		receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	) -> Result<BoxedClientHandshake>
	where
		M: EciesMessageOps + Send + Sync + 'static,
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EciesPublicKeyOps,
		<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
		P::Signature: SignatureEncoding + Send + Sync + 'static,
		for<'b> P::Signature: TryFrom<&'b [u8]>,
		for<'b> <P::Signature as TryFrom<&'b [u8]>>::Error: Into<HandshakeError>,
		P::VerifyingKey: Verifier<P::Signature> + ExtractVerifyingKey + Send + Sync + 'static,
		P::AeadCipher: KeyInit + Send + Sync + 'static,
	{
		let identity = client_cert.map(|cert| ClientIdentity::new(cert, Arc::clone(self)));
		let mut client = EciesHandshakeClient::<P, M>::new_with_identity(aad_domain_tag, identity);
		if let Some(validator) = validator {
			client = client.with_certificate_validator(validator);
		}
		if let Some(offer) = transport_offer {
			client = client.with_transport_offer(offer);
		}
		if let Some(approver) = receipt_approver {
			client = client.with_receipt_approver(approver);
		}

		Ok(Box::new(client))
	}

	/// CMS client orchestrator via the encapsulated key provider (HSM/KMS-safe).
	#[cfg(feature = "transport-cms")]
	pub fn create_cms_client(self: &Arc<Self>, config: CmsClientConfig) -> Result<BoxedClientHandshake>
	where
		P: Default + 'static,
		P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
		<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		PublicKey<P::Curve>: EncodePublicKey,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: Send + Sync + KeyInit,
	{
		use crate::transport::handshake::client::CmsHandshakeClient;

		let provider = P::default();
		let key_provider = Arc::clone(&self.provider);
		let mut client = match config.server_identity {
			CmsServerIdentity::Certificate(cert) => CmsHandshakeClient::<P>::new(provider, key_provider, cert),
			CmsServerIdentity::Chain(chain) => CmsHandshakeClient::<P>::from_chain(provider, key_provider, chain),
		}
		.with_trust_store(config.trust_store);

		if let Some(offer) = config.security_offer {
			client = client.with_security_offer(offer);
		}
		if let Some(offer) = config.transport_offer {
			client = client.with_transport_offer(offer);
		}
		if let Some(cert) = config.client_certificate {
			let identity = ClientIdentity::new(cert, Arc::clone(self));
			client = client.with_client_identity(identity);
		}
		if let Some(approver) = config.receipt_approver {
			client = client.with_receipt_approver(approver);
		}

		Ok(Box::new(client))
	}

	/// CMS server orchestrator via the encapsulated key provider (HSM/KMS-safe).
	#[cfg(feature = "transport-cms")]
	pub fn create_cms_server(
		&self,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
		supported_profiles: Vec<SecurityProfileDesc>,
		transport_config: Option<TransportOffer>,
		transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
		session_observer: Option<Arc<dyn SessionObserver>>,
	) -> Result<BoxedServerHandshake>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
		P::Signature: 'static,
		P::Digest: Send + 'static,
		P::AeadCipher: Send + Sync + KeyInit + 'static,
	{
		let provider = Arc::clone(&self.provider);

		let mut server = CmsHandshakeServer::<P>::new(provider, client_validators);
		server = server.with_supported_profiles(supported_profiles);

		if let Some(config) = transport_config {
			server = server.with_transport_config(config);
		}
		if let Some(authorizer) = transport_authorizer {
			server = server.with_transport_authorizer(authorizer);
		}
		if let Some(observer) = session_observer {
			server = server.with_session_observer(observer);
		}

		Ok(Box::new(server))
	}
}

/// The clock a handshake deadline is measured against.
///
/// Targets without a monotonic clock carry a `u64` stand-in. The alias is
/// the one place that choice is made, so a type naming it needs no `#[cfg]`
/// of its own.
#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
pub type HandshakeClock = Instant;

/// The clock a handshake deadline is measured against.
#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
pub type HandshakeClock = u64;

/// When a handshake began, for measuring its deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeInstant(HandshakeClock);

impl HandshakeInstant {
	/// The current instant, or zero where no clock exists.
	#[must_use]
	pub fn now() -> Self {
		#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
		{
			Self(Instant::now())
		}

		#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
		{
			Self(0)
		}
	}

	/// The deadline reached by adding `allowance` to this instant.
	#[must_use]
	pub fn deadline(self, allowance: core::time::Duration) -> HandshakeClock {
		#[cfg(all(feature = "std", not(target_arch = "wasm32")))]
		{
			self.0 + allowance
		}

		#[cfg(not(all(feature = "std", not(target_arch = "wasm32"))))]
		{
			self.0.saturating_add(allowance.as_millis() as u64)
		}
	}
}

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
	// Code 6 is burned: it briefly named a settlement-rejected alert that
	// never shipped. Do not reuse. The next alert takes 7 so archived
	// captures never decode a stale meaning
}

/// A handshake message travels the wire in one of two CMS containers.
///
/// ECIES carries its own message types inside a container, so its messages
/// are decoded from one. The CMS handshake exchanges the containers
/// themselves.
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
	/// Carries an ECIES `ClientHello` or `ServerHandshake`, or a CMS Finished.
	SignedData(Box<SignedData>),
	/// Carries an ECIES `ClientKeyExchange`, or a CMS key exchange.
	EnvelopedData(Box<EnvelopedData>),
}

impl HandshakeMessage {
	/// The signed container.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds the
	///   key-transport container, which this step refuses.
	pub fn signed(self) -> CoreResult<SignedData, HandshakeError> {
		match self {
			Self::SignedData(signed) => Ok(*signed),
			Self::EnvelopedData(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// The key-transport container.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds the
	///   signed container, which this step refuses.
	pub fn enveloped(self) -> CoreResult<EnvelopedData, HandshakeError> {
		match self {
			Self::EnvelopedData(enveloped) => Ok(*enveloped),
			Self::SignedData(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// The DER form of the message, as the transport puts it on the wire.
	pub fn to_der(&self) -> CoreResult<Vec<u8>, HandshakeError> {
		match self {
			Self::SignedData(signed) => Ok(signed.to_der()?),
			Self::EnvelopedData(enveloped) => Ok(enveloped.to_der()?),
		}
	}

	/// Length of the DER form, computed without building the buffer.
	///
	/// A length beyond the target's `usize` range saturates to [`usize::MAX`],
	/// so it exceeds every ceiling and the message is refused.
	pub fn encoded_len(&self) -> CoreResult<usize, HandshakeError> {
		let len = match self {
			Self::SignedData(signed) => signed.encoded_len()?,
			Self::EnvelopedData(enveloped) => enveloped.encoded_len()?,
		};

		Ok(usize::try_from(u32::from(len)).unwrap_or(usize::MAX))
	}
}

/// What a completed handshake agreed, handed over in one value.
///
/// A handshake settles the keys and the terms that go with them at the same
/// moment, so they travel together and a transport that installs the keys
/// installs the rest with them.
#[cfg(feature = "aead")]
#[non_exhaustive]
pub struct EstablishedSession {
	/// Role-mapped directional keys. Each side sends on one key and receives
	/// on the other.
	keys: SessionKeys,
	/// Multiplexing terms when both sides negotiated them. `None` leaves the
	/// session single-flight.
	mux: Option<MuxSettings>,
	/// Dual-signed receipt from a budget-bearing handshake.
	receipt: Option<Arc<StoredReceipt>>,
	/// Peer certificate validated during mutual authentication.
	#[cfg(feature = "x509")]
	peer: Option<Arc<Certificate>>,
	/// Epoch-0 rekey materials, present exactly while a rekey could use them.
	epoch: Option<EpochMaterials>,
}

#[cfg(feature = "aead")]
impl EstablishedSession {
	/// Assemble what one handshake agreed.
	///
	/// Epoch materials serve a rekey alone, and a rekey re-signs against the
	/// session receipt and the peer identity. A session missing either can
	/// never renew, so its epoch secret is released here rather than held,
	/// unreachable, for as long as the session lives.
	pub(crate) fn new(
		keys: SessionKeys,
		mux: Option<MuxSettings>,
		receipt: Option<Arc<StoredReceipt>>,
		#[cfg(feature = "x509")] peer: Option<Arc<Certificate>>,
		epoch: Option<EpochMaterials>,
	) -> Self {
		#[cfg(feature = "x509")]
		let renewable = receipt.is_some() && peer.is_some();

		let epoch = epoch.filter(|_| renewable);

		Self {
			keys,
			mux,
			receipt,
			#[cfg(feature = "x509")]
			peer,
			epoch,
		}
	}

	/// Detach the epoch rekey materials, once.
	pub(crate) fn take_epoch(&mut self) -> Option<EpochMaterials> {
		self.epoch.take()
	}

	/// The directional keys, for a caller that consumes the session.
	pub fn into_keys(self) -> SessionKeys {
		self.keys
	}

	/// Role-mapped directional keys for this session.
	pub fn keys(&self) -> &SessionKeys {
		&self.keys
	}

	/// Multiplexing terms both sides agreed, if any.
	pub fn mux(&self) -> Option<MuxSettings> {
		self.mux
	}

	/// Dual-signed receipt from a budget-bearing handshake.
	pub fn receipt(&self) -> Option<&StoredReceipt> {
		self.receipt.as_deref()
	}

	/// Peer certificate validated during mutual authentication.
	#[cfg(feature = "x509")]
	pub fn peer(&self) -> Option<&Certificate> {
		self.peer.as_deref()
	}

	/// Shared handle to the validated peer certificate.
	#[cfg(feature = "x509")]
	pub fn peer_arc(&self) -> Option<Arc<Certificate>> {
		self.peer.as_ref().map(Arc::clone)
	}

	/// Shared handle to the dual-signed session receipt.
	pub fn receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		self.receipt.as_ref().map(Arc::clone)
	}
}

/// Client-side handshake protocol trait.
///
/// Supports multi-round handshakes where the client may need to send multiple
/// messages before completing the handshake.
///
/// `Send` is required on every target except `wasm32`, where the
/// single-threaded executor lets JS-backed signing providers participate.
pub trait ClientHandshakeProtocol: MaybeSend {
	type Error: Into<TransportError> + Send;

	/// Start the handshake, returns the first message to send to the server.
	#[allow(clippy::type_complexity)]
	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, CoreResult<HandshakeMessage, Self::Error>>;

	/// Handle a response from the server.
	///
	/// Returns `Some` when the client owes the server another message, and
	/// `None` once it has sent its last. Each step accepts one container and
	/// refuses the other.
	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, CoreResult<Option<HandshakeMessage>, Self::Error>>;

	/// Complete the handshake and take everything it agreed.
	///
	/// Call this once `is_complete()` returns true. The client sends on the
	/// client-to-server key and receives on the server-to-client key. The
	/// cipher comes from the `CryptoProvider` associated type and the OID
	/// from the negotiated security profile.
	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	fn is_complete(&self) -> bool;

	/// Negotiated algorithm OIDs after profile negotiation; `None` before accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// Server-side handshake protocol trait.
///
/// Supports multi-round handshakes where the server may need to handle
/// multiple requests from the client before completing the handshake.
///
/// `Send` is required on every target except `wasm32`, where the
/// single-threaded executor lets JS-backed signing providers participate.
pub trait ServerHandshakeProtocol: MaybeSend {
	type Error: Into<TransportError> + Send;

	/// Handle a request from the client.
	///
	/// Can be called multiple times for multi-round handshakes. Returns `Some`
	/// when the server owes a response, and `None` when the step completes the
	/// handshake. Each step accepts one container and refuses the other.
	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, CoreResult<Option<HandshakeMessage>, Self::Error>>;

	/// Complete the handshake and take everything it agreed.
	///
	/// Call this once `is_complete()` returns true. The server sends on the
	/// server-to-client key and receives on the client-to-server key. The
	/// cipher comes from the `CryptoProvider` associated type and the OID from
	/// the negotiated security profile.
	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	/// Returns true if the handshake is complete.
	fn is_complete(&self) -> bool;

	/// Negotiated algorithm OIDs after profile negotiation; `None` before accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// Boxed client handshake orchestrator.
///
/// `Send` on every target except `wasm32`, where JS-backed signing providers
/// make the orchestrator `!Send`. A `dyn` object cannot carry the non-auto
/// [`MaybeSend`] bound, so the auto-trait list is target-gated here.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send + 'static>;

/// Boxed client handshake orchestrator (`wasm32`: `Send` relaxed).
#[cfg(target_arch = "wasm32")]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + 'static>;

/// Boxed server handshake orchestrator.
///
/// `Send + Sync` on every target except `wasm32`, where JS-backed signing
/// providers make the orchestrator `!Send`. A `dyn` object cannot carry the
/// non-auto [`MaybeSend`] bound, so the auto-trait list is target-gated here.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync + 'static>;

/// Boxed server handshake orchestrator (`wasm32`: `Send + Sync` relaxed).
#[cfg(target_arch = "wasm32")]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + 'static>;

/// Specifies which handshake protocol to use (ECIES or CMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeProtocolKind {
	/// Use ECIES-based handshake (default, lighter weight)
	#[default]
	Ecies,
	/// CMS-based handshake (X.509 signed/enveloped data).
	///
	/// Key-transport handshake: the client encrypts the session key to the
	/// server's leaf certificate in its first message, so a trust store and
	/// a provisioned server certificate chain are mandatory on the client.
	/// Missing either fails closed, as does selecting this kind without the
	/// `transport-cms` feature.
	Cms,
}

/// Opening handshake message from the client, bound into the transcript.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub client_random: OctetString,
	#[asn1(optional = "true")]
	pub security_offer: Option<SecurityOffer>,
	/// Transport capability offer (multiplexing). Context-tagged so it can
	/// never be confused with the preceding optional SEQUENCE.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_offer: Option<TransportOffer>,
}

/// Server response to a [`ClientHello`], bound into the transcript.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	/// Server identity certificate the client validates against its
	/// trust store.
	#[cfg(feature = "x509")]
	pub certificate: Certificate,
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub server_random: OctetString,
	/// Server signature over the transcript so far, proving possession
	/// of the certificate's private key.
	pub signature: OctetString,
	#[asn1(optional = "true")]
	pub security_accept: Option<SecurityAccept>,
	/// Indicates if the server requires client certificate for mutual authentication.
	/// When true, client must provide certificate in ClientKeyExchange.
	pub client_cert_required: bool,
	/// Transport capability accept (multiplexing). Present only when the
	/// client offered and the server enabled multiplexing locally.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_accept: Option<TransportAccept>,
	/// Server-signed session receipt artifact for budget-bearing
	/// sessions: a CMS `SignedData`
	/// ([RFC 5652 §5](https://datatracker.ietf.org/doc/html/rfc5652#section-5))
	/// whose `eContent` is the receipt body (transcript hash, granted
	/// budgets, settlement challenge) and whose single `SignerInfo` is
	/// the server's signature over it.
	#[asn1(context_specific = "1", optional = "true")]
	pub session_receipt: Option<SignedData>,
}

/// Confidential plaintext of the ECIES key exchange.
///
/// Decrypted only by the server: carries the base session key, the
/// anti-replay client random, and the client's receipt
/// countersignature (whose signed attributes bind the bearer
/// settlement answer).
#[cfg(feature = "transport-ecies")]
#[derive(Clone, Sequence)]
pub(crate) struct EciesSessionPayload {
	/// 32-byte base session key feeding the directional AEAD derivation.
	pub base_key: OctetString,
	/// 32-byte client random echoed back for replay resistance.
	pub client_random: OctetString,
	/// Client receipt `SignerInfo` countersigning the server-issued
	/// receipt. Required exactly when the server issued one.
	#[asn1(context_specific = "0", optional = "true")]
	pub receipt_ack: Option<SignerInfo>,
}

/// Final client handshake message carrying the encrypted key material.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	/// Key-exchange payload encrypted to the server: the ECIES session
	/// payload or a CMS `EnvelopedData`, per the negotiated protocol.
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

fn encodable_to_signed_data<T: Encode>(message: &T) -> Result<SignedData> {
	let message_der = message.to_der()?;
	let octet_string = OctetString::new(message_der)?;
	// Create der::Any directly from the OctetString's DER encoding
	let econtent = Any::new(Tag::OctetString, octet_string.to_der()?)?;

	Ok(SignedData {
		version: CmsVersion::V1,
		digest_algorithms: Default::default(),
		encap_content_info: EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent) },
		certificates: None,
		crls: None,
		signer_infos: SignerInfos::try_from(Vec::new())?,
	})
}

fn signed_data_to_decodable<T: for<'a> Decode<'a>>(signed_data: &SignedData) -> Result<T> {
	let econtent_any = signed_data
		.encap_content_info
		.econtent
		.as_ref()
		.ok_or(HandshakeError::InvalidServerKeyExchange)?;

	let octet_string_der = econtent_any.value();
	let octet_string = OctetString::from_der(octet_string_der)?;
	Ok(T::from_der(octet_string.as_bytes())?)
}

/// Convert ClientHello to SignedData (opaque wrapper)
impl TryFrom<&ClientHello> for SignedData {
	type Error = HandshakeError;

	fn try_from(hello: &ClientHello) -> CoreResult<Self, Self::Error> {
		encodable_to_signed_data(hello)
	}
}

/// Extract ClientHello from SignedData
impl TryFrom<&SignedData> for ClientHello {
	type Error = HandshakeError;

	fn try_from(signed_data: &SignedData) -> CoreResult<Self, Self::Error> {
		signed_data_to_decodable(signed_data)
	}
}

/// Convert ServerHandshake to SignedData (opaque wrapper)
impl TryFrom<&ServerHandshake> for SignedData {
	type Error = HandshakeError;

	fn try_from(handshake: &ServerHandshake) -> CoreResult<Self, Self::Error> {
		encodable_to_signed_data(handshake)
	}
}

/// Extract ServerHandshake from SignedData
impl TryFrom<&SignedData> for ServerHandshake {
	type Error = HandshakeError;

	fn try_from(signed_data: &SignedData) -> CoreResult<Self, Self::Error> {
		signed_data_to_decodable(signed_data)
	}
}

#[cfg(feature = "x509")]
fn build_client_key_exchange_attrs(kex: &ClientKeyExchange) -> Result<Option<x509_cert::attr::Attributes>> {
	let mut attrs = Vec::new();

	if let Some(cert) = &kex.client_certificate {
		let cert_der = cert.to_der()?;
		let cert_octet = OctetString::new(cert_der)?;
		let cert_der_wrapped = cert_octet.to_der()?;
		let cert_any = Any::new(Tag::OctetString, cert_der_wrapped)?;
		let cert_values = SetOfVec::try_from(vec![AttributeValue::from(cert_any)])?;

		attrs.push(Attribute { oid: CLIENT_CERTIFICATE, values: cert_values });
	}

	if let Some(sig) = &kex.client_signature {
		let sig_der = sig.to_der()?;
		let sig_any = Any::new(Tag::OctetString, sig_der)?;
		let sig_values = SetOfVec::try_from(vec![AttributeValue::from(sig_any)])?;

		attrs.push(Attribute { oid: CLIENT_SIGNATURE, values: sig_values });
	}

	if attrs.is_empty() {
		Ok(None)
	} else {
		Ok(Some(Attributes::try_from(attrs)?))
	}
}

/// First value of an attribute decoded as an OCTET STRING.
#[cfg(feature = "x509")]
fn first_octet_string(attr: &Attribute) -> Result<Option<OctetString>> {
	attr.values
		.iter()
		.next()
		.map(|value| OctetString::from_der(value.value()))
		.transpose()
		.map_err(Into::into)
}

#[cfg(feature = "x509")]
fn parse_client_key_exchange_attrs(enveloped_data: &EnvelopedData) -> Result<ClientKeyExchangeAttrs> {
	let mut parsed = ClientKeyExchangeAttrs::default();
	if let Some(attrs) = &enveloped_data.unprotected_attrs {
		for attr in attrs.iter() {
			if attr.oid == CLIENT_CERTIFICATE {
				if let Some(cert_octet) = first_octet_string(attr)? {
					let cert_der = cert_octet.as_bytes();
					let cert = Certificate::from_der(cert_der)?;

					parsed.certificate = Some(cert);
				}
			} else if attr.oid == CLIENT_SIGNATURE {
				parsed.signature = first_octet_string(attr)?;
			}
		}
	}

	Ok(parsed)
}

/// Parsed unprotected attributes of a [`ClientKeyExchange`] envelope.
#[cfg(feature = "x509")]
#[derive(Default)]
struct ClientKeyExchangeAttrs {
	certificate: Option<Certificate>,
	signature: Option<OctetString>,
}

/// Convert ClientKeyExchange to EnvelopedData (opaque wrapper for ECIES ciphertext)
impl TryFrom<&ClientKeyExchange> for EnvelopedData {
	type Error = HandshakeError;

	fn try_from(kex: &ClientKeyExchange) -> CoreResult<Self, Self::Error> {
		#[cfg(feature = "x509")]
		let unprotected_attrs = build_client_key_exchange_attrs(kex)?;

		Ok(EnvelopedData {
			version: CmsVersion::V0,
			originator_info: None,
			recip_infos: RecipientInfos::try_from(Vec::new())?,
			encrypted_content: EncryptedContentInfo {
				content_type: DATA,
				content_enc_alg: aes_256_gcm_algorithm(),
				encrypted_content: Some(OctetString::new(kex.encrypted_data.as_bytes())?),
			},
			unprotected_attrs,
		})
	}
}

/// Extract ClientKeyExchange from EnvelopedData
impl TryFrom<&EnvelopedData> for ClientKeyExchange {
	type Error = HandshakeError;

	fn try_from(enveloped_data: &EnvelopedData) -> CoreResult<Self, Self::Error> {
		let encrypted_bytes = enveloped_data
			.encrypted_content
			.encrypted_content
			.as_ref()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.as_bytes();

		#[cfg(feature = "x509")]
		let attrs = parse_client_key_exchange_attrs(enveloped_data)?;

		Ok(ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate: attrs.certificate,
			#[cfg(feature = "x509")]
			client_signature: attrs.signature,
		})
	}
}

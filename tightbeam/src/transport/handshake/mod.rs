//! TightBeam handshake protocols that establish secure communication channels.
//!
//! This module implements two handshake protocols:
//!
//! - **HPKE**: the shape of the TLS 1.3 handshake (RFC 9846) in CMS
//!   containers. The server's key signs its reply, and the handshake secret
//!   derives from the two ephemerals alone.
//! - **CMS-based**: full X.509 PKI with signed and authenticated-enveloped data.
//!
//! Both protocols establish authenticated, encrypted sessions and negotiate
//! the cryptographic algorithms between client and server.
//!
//! # Protocol Capabilities
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                        TIGHTBEAM HANDSHAKE CAPABILITIES                │
//! ├────────────────────────────────────────────────────────────────────────┤
//! │  AUTHENTICATION           ENCRYPTION          NEGOTIATION              │
//! │  • Server authentication  • Session keys      • Algorithm selection    │
//! │  • Mutual authentication  • Forward secrecy   • Profile negotiation    │
//! │  • Certificate validation • AEAD ciphers      • Dealer's choice mode   │
//! │  • Transcript integrity                       • Wire-level protocol    │
//! └────────────────────────────────────────────────────────────────────────┘
//!
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                          HANDSHAKE FLOW                                │
//! ├────────────────────────────────────────────────────────────────────────┤
//! │                                                                        │
//! │ Client ─────────────────────────── Server                              │
//! │  │                           │                                         │
//! │  │── ClientHello ───────────►│  (client_rand, R, security_offer?)      │
//! │  │                           │                                         │
//! │  │◄─ ServerHandshake ────────│  (server_rand, E, accept?, ma?,         │
//! │  │                           │   signed, cert, server Finished)        │
//! │  │── Closing ───────────────►│  (seal(Finished?, tag, ack?))           │
//! │  │                           │                                         │
//! │  │ ◄═ Session Established ═► │  (AEAD keys derived)                    │
//! │  │                           │                                         │
//! │  └───────────────────────────┘                                         │
//! └────────────────────────────────────────────────────────────────────────┘
//! **Legend:**
//! - `R`, `E` = the client's and the server's per-handshake ephemeral public
//!   keys, inside the signed transcript
//! - `server Finished` = the MAC over the transcript hash and the reply's
//!   signature, which the client verifies
//! - `seal(...)` = the closing, sealed under a key of the handshake secret
//! - `Finished?` = the client Finished, which carries the client certificate, when the client presents one
//! - `tag` = the client's key-confirmation tag, which the server verifies before it settles
//! - Arrows show message direction and content
//! - Session establishment occurs after successful key exchange
//! ```
//!
//! # Forward secrecy
//!
//! Both protocols derive every traffic key from one [`HandshakeSecret`], whose
//! inputs are:
//!
//! - the ECDH output of the client's ephemeral and the server's ephemeral, and
//! - in the CMS flow, the base secret the client seals to the server's key-agreement certificate.
//!
//! The server signs its ephemeral inside the transcript, and both ephemeral
//! private keys drop at the step that consumes them. A recording plus a later
//! copy of the server's static keys recovers the CMS base secret alone, which
//! the key-agreement key opens, and no HPKE secret. These need the ECDH
//! output, which needs a private key neither side kept:
//!
//! - the traffic keys and the rekey epochs,
//! - the sealed receipt acknowledgement, and
//! - the closing, with the client identity it carries.
//!
//! # Architecture
//!
//! One type, [`Handshake`], runs both roles over both protocols:
//!
//! - The role, [`Client`] or [`Server`], fixes the step order and every negotiation and admission decision.
//! - The flow, [`Hpke`] or [`Cms`], contributes the messages of its protocol and the checks they define.
//! - The provider, a [`HandshakeProvider`], names the algorithms.
//!
//! The [`CryptoProvider`] trait is the abstraction boundary of the layer:
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────┐
//! │                          APPLICATION LAYER                             │
//! │  ┌─────────────────────────────────────────────────────────────────┐   │
//! │  │                    TCP Transport Layer                          │   │
//! │  └─────────────────────┬───────────────────────┬───────────────────┘   │
//! │                        │                       │                       │
//! │  ┌─────────────────────▼───────┐    ┌──────────▼────────┐              │
//! │  │   Handshake Orchestrator    │    │   CryptoProvider  │              │
//! │  │  ┌────────────────────────┐ │    │  ┌─────────────┐  │              │
//! │  │  │ Handshake<R, F, P>     │ │    │  │  Curve      │  │              │
//! │  │  │   R: Client | Server   │ │    │  │  Digest     │  │              │
//! │  │  │   F: Hpke | Cms        │ │    │  │  KDF        │  │              │
//! │  │  └────────────────────────┘ │    │  │  AEAD       │  │              │
//! │  │                             │    │  │  Signature  │  │              │
//! │  │         (Generic)           │    │  │  SigningKey │  │              │
//! │  └─────────────────────────────┘    │  └─────────────┘  │              │
//! │                                     │    (Associated)   │              │
//! │  ┌─────────────────────────────┐    └───────────────────┘              │
//! │  │   Authenticated Envelope    │                                       │
//! │  │       (crypto::cms)         │                                       │
//! │  │  ┌───────────────────────┐  │                                       │
//! │  │  │ AuthEnvelopedData     │  │                                       │
//! │  │  │ Recipient             │  │                                       │
//! │  │  │ Opener                │  │                                       │
//! │  │  └───────────────────────┘  │                                       │
//! │  └─────────────────────────────┘                                       │
//! └────────────────────────────────────────────────────────────────────────┘
//!
//! ## Key:
//! R = role, F = flow, P = CryptoProvider trait,
//! <P> = Compile-time generic
//! ```
//!
//! ## Cryptographic negotiation
//!
//! Both protocols negotiate through a [`SecurityOffer`] from the client and a
//! [`SecurityAccept`] from the server. The endpoints agree on these algorithms:
//!
//! - The digest algorithm, such as SHA3-256.
//! - The AEAD cipher, such as AES-256-GCM.
//! - The signature algorithm, such as ECDSA-with-SHA3-256.
//! - The key wrapping algorithm, for CMS.
//!
//! One policy, [`negotiation::ProfilePolicy`], makes both decisions in both
//! protocols:
//!
//! 1. The client sends its `SecurityOffer` in the opening, when it has one.
//! 2. The server chooses from its configured profiles: the first one the
//!    offer also names, or its own first profile when no offer came.
//! 3. The server names its choice as a `SecurityAccept` in the reply.
//! 4. The client admits the selection, which must be a member of its offer when it sent one.
//!
//! Both endpoints admit a profile only when it names the algorithms their
//! provider runs ([`negotiation::RunnableProfile`]) and meets the strength
//! floor. A server with no eligible profile refuses the opening, and a client
//! refuses a reply that selects nothing.
//!
//! | Protocol | Offer travels in | Accept travels in |
//! | --- | --- | --- |
//! | HPKE | `ClientHello` | `ServerHandshake` |
//! | CMS | Opening, authenticated attribute | Server Finished, unsigned attribute |
//!
//! ## Legs
//!
//! Both protocols run three legs, and the layer names each by its position:
//!
//! | Leg | Sender | HPKE message | CMS message |
//! | --- | --- | --- | --- |
//! | Opening | Client | `ClientHello` in an `id-data` `ContentInfo` | `AuthEnvelopedData` to the server's certificate |
//! | Reply | Server | `ServerHandshake` in a `SignedData`, with the server Finished | Server Finished, with the MAC |
//! | Closing | Client | The closing of both flows, sealed in `AuthEnvelopedData` | The same closing |
//!
//! The closing is the client Finished of a client that presents an identity,
//! or the key-confirmation attributes of an anonymous client. A server reads
//! it in one order in both protocols: it opens the closing, confirms the
//! handshake secret, admits the client, and settles the receipt.
//!
//! The client identity opens only under the handshake secret, so the
//! comparison of the client ephemeral with the client's static key waits for
//! the open. [`Handshake::finish`] states each step.
//!
//! ## State machine
//!
//! Both roles run one machine over both protocols, read through
//! [`HandshakePhase`]. A step reads the leg the peer sent, builds the leg its
//! role sends, or both, and `complete` takes the session.
//!
//! ```text
//! Client: Idle -- start --> Exchanging -- respond --> Agreed -- complete --> Completed
//! Server: Idle -- reply --> Exchanging -- finish ---> Agreed -- complete --> Completed
//! ```
//!
//! - A step outside its phase returns [`HandshakeError::InvalidState`] and leaves the phase unchanged.
//! - A step that began and failed leaves the handshake [`HandshakePhase::Spent`], which admits no step.

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::result::Result as CoreResult;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
pub(crate) use alloc::sync::Arc;
#[cfg(feature = "std")]
pub(crate) use std::sync::Arc;

mod attributes;
mod error;
mod identity;
mod peer;
mod schedule;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod flow;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod orchestrator;
#[cfg(test)]
pub(crate) mod tests;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod wire;

pub mod negotiation;
pub mod primitives;
pub mod receipt;

pub use crate::crypto::aead::DirectionalCiphers;
pub use attributes::HandshakeAttribute;
pub use error::HandshakeError;
pub use identity::ServerIdentity;
pub use peer::PeerAuthentication;
pub use schedule::EpochMaterials;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use flow::{ClientFlow, ServerFlow};
#[cfg(feature = "transport-cms")]
pub use flow::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(feature = "transport-hpke")]
pub use flow::{Hpke, HpkeClientSettings, HpkeServerSettings};
#[cfg(feature = "transport-cms")]
pub use identity::CmsIdentityPair;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use negotiation::{ProfilePolicy, SupportedProfiles};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use orchestrator::{Client, ClientConfig, Handshake, HandshakePhase, Server, ServerConfig};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use peer::AdmittedPeer;
#[cfg(feature = "transport-hpke")]
pub use peer::LearnedTrust;
#[cfg(feature = "transport-cms")]
pub use peer::ProvisionedTrust;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use schedule::HandshakeSecret;
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
pub(crate) use schedule::{CompressedPoint, EpochSecret, PeerEphemeral};
#[cfg(all(
	feature = "transport-multiplex",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
pub(crate) use wire::HandshakeOctets;

use crate::asn1::OctetString;
use crate::cms::content_info::ContentInfo;
use crate::cms::signed_data::SignedData;
use crate::crypto::aead::SessionKeys;
use crate::crypto::cms::AuthEnvelopedData;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::der::{Enumerated, Sequence};
use crate::transport::error::TransportError;
use crate::transport::handshake::negotiation::{
	MuxSettings, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::{MaybeSend, MaybeSendFuture};
use crate::x509::Certificate;
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::cms::ContentEncryption;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::profiles::CryptoProvider;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod transport {
	pub use crate::crypto::aead::KeyInit;
	pub use crate::crypto::cms::RecipientKem;
	pub use crate::crypto::common::typenum::U32;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
	pub use crate::crypto::sign::Verifier;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::spki::{EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoRef};
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use transport::*;

/// A curve both handshake protocols run on.
///
/// The field is 32 bytes wide, so a shared secret is 32 bytes and a compressed
/// point 33 bytes by type. Every curve that meets the bounds is a handshake
/// curve.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait HandshakeCurve:
	Curve<FieldBytesSize = U32>
	+ CurveArithmetic<AffinePoint: FromEncodedPoint<Self> + ToEncodedPoint<Self>>
	+ AssociatedOid
	+ Send
	+ Sync
	+ 'static
{
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C> HandshakeCurve for C where
	C: Curve<FieldBytesSize = U32>
		+ CurveArithmetic<AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>>
		+ AssociatedOid
		+ Send
		+ Sync
		+ 'static
{
}

/// A [`CryptoProvider`] the handshake layer runs on.
///
/// This is the one bound the layer states about a provider. The bounds sit on
/// the supertrait, so `P: HandshakeProvider` gives a caller every one of them:
///
/// - the curve is a [`HandshakeCurve`],
/// - a signature parses from its encoded bytes,
/// - the verifying key parses from an SPKI, converts from a point on that
///   curve, lends its point by reference, verifies a signature, and encodes as
///   an SPKI,
/// - the KEM and the backend of its private key outlive the handshake, and
/// - the AEAD cipher keys from derived bytes and seals an envelope.
///
/// Every provider that meets the bounds is a handshake provider, so a
/// provider with no HPKE suite runs both flows.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::transport::handshake::HandshakeProvider;
///
/// fn runs_a_handshake<P: HandshakeProvider>() {}
///
/// runs_a_handshake::<DefaultCryptoProvider>();
/// ```
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait HandshakeProvider:
	CryptoProvider<
		Curve: HandshakeCurve,
		Signature: for<'a> TryFrom<&'a [u8], Error: Into<HandshakeError>> + 'static,
		VerifyingKey: Verifier<Self::Signature>
		                  + for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = SpkiError>
		                  + From<PublicKey<Self::Curve>>
		                  + AsRef<AffinePoint<Self::Curve>>
		                  + EncodePublicKey
		                  + 'static,
		Digest: 'static,
		AeadCipher: KeyInit + ContentEncryption + 'static,
		Kem: RecipientKem<PrivateKey: 'static> + 'static,
	> + Send
	+ Sync
	+ 'static
{
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P> HandshakeProvider for P where
	P: CryptoProvider<
			Curve: HandshakeCurve,
			Signature: for<'a> TryFrom<&'a [u8], Error: Into<HandshakeError>> + 'static,
			VerifyingKey: Verifier<P::Signature>
			                  + for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = SpkiError>
			                  + From<PublicKey<P::Curve>>
			                  + AsRef<AffinePoint<P::Curve>>
			                  + EncodePublicKey
			                  + 'static,
			Digest: 'static,
			AeadCipher: KeyInit + ContentEncryption + 'static,
			Kem: RecipientKem<PrivateKey: 'static> + 'static,
		> + Send
		+ Sync
		+ 'static
{
}

/// One provisioned certificate of a CMS server, for a CMS client handshake:
/// a leaf, or a chain that ends at the leaf.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub enum CmsServerIdentity {
	/// A bare server certificate, evaluated directly against the trust store.
	Certificate(Arc<Certificate>),
	/// Full server chain, ordered root to leaf. Path validation runs over the
	/// chain per [RFC 5280 §6.1][rfc5280-6.1], and the leaf identifies the
	/// server.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	Chain(CmsServerChain),
}

/// A CMS server's chain, ordered root to leaf, with its leaf held apart, so
/// each admission lends the leaf without a copy.
///
/// [`Self::new`] is the one constructor, so every chain holds a leaf.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub struct CmsServerChain {
	/// The whole chain, ordered root to leaf.
	path: Arc<[Certificate]>,
	/// The last certificate of the chain.
	leaf: Arc<Certificate>,
}

#[cfg(feature = "transport-cms")]
impl CmsServerChain {
	/// The chain `path`, ordered root to leaf. Its leaf is copied once, here.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingServerCertificate`] -- `path` is empty.
	pub fn new(path: impl Into<Arc<[Certificate]>>) -> Result<Self, HandshakeError> {
		let path = path.into();
		let leaf = path.last().ok_or(HandshakeError::MissingServerCertificate)?;
		let leaf = Arc::new(leaf.clone());
		Ok(Self { path, leaf })
	}

	/// The whole chain, ordered root to leaf, which path validation reads.
	pub fn path(&self) -> &[Certificate] {
		&self.path
	}

	/// The certificate the chain starts at, the trust anchor of its path.
	pub fn root(&self) -> &Certificate {
		self.path.first().unwrap_or(&self.leaf)
	}

	/// The leaf, which identifies the server.
	pub fn leaf(&self) -> &Arc<Certificate> {
		&self.leaf
	}
}

/// The two provisioned certificates of a CMS server: the one whose key signs
/// the reply, and the one whose key the opening seals the base secret to.
///
/// The fields carry their roles by name, so the two cannot be swapped by
/// position. [`ProvisionedTrust::new`] admits the pair against a store.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub struct CmsServerCertificates {
	/// The server's signing certificate, with `digitalSignature` in its
	/// `keyUsage`.
	pub signing: CmsServerIdentity,
	/// The server's key-agreement certificate, whose `keyUsage` asserts the
	/// bit of the provider's KEM, [`RecipientKem::USAGE`]: `keyAgreement` for
	/// the house DHKEM.
	pub key_agreement: CmsServerIdentity,
}

#[cfg(feature = "transport-cms")]
impl From<Arc<Certificate>> for CmsServerIdentity {
	fn from(certificate: Arc<Certificate>) -> Self {
		Self::Certificate(certificate)
	}
}

#[cfg(feature = "transport-cms")]
impl From<CmsServerChain> for CmsServerIdentity {
	fn from(chain: CmsServerChain) -> Self {
		Self::Chain(chain)
	}
}

/// Alert code an endpoint sends to abort a handshake.
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeAlert {
	/// The server requires client authentication, and the certificate or
	/// signature is missing.
	AuthRequired = 1,
	/// The client and server protocol versions differ.
	VersionMismatch = 2,
	/// The algorithms (profile OIDs) of the two endpoints differ.
	AlgorithmMismatch = 3,
	/// Decryption failed (HPKE or AEAD).
	DecryptFail = 4,
	/// The MAC or signature over the Finished transcript hash failed
	/// verification.
	FinishedIntegrityFail = 5,
	// Code 6 is reserved for the retired settlement-rejected alert, and MUST
	// NOT be reused. The next alert takes 7, so archived captures never
	// decode a stale meaning.
}

/// A handshake message travels in one of three CMS containers (RFC 5652).
///
/// The HPKE hello is a `ContentInfo` of type `id-data`, and its reply is the
/// signer's `SignedData`. The CMS flow opens with an `AuthEnvelopedData`, and
/// its server Finished is a `SignedData`. Both flows close with an
/// `AuthEnvelopedData` under a key of the handshake secret.
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
	/// Carries the HPKE reply, or the CMS server Finished.
	SignedData(Box<WireDer<SignedData>>),
	/// Carries a CMS opening, or the closing of either flow, sealed under the
	/// closing key of the handshake secret (RFC 5083).
	AuthEnvelopedData(Box<WireDer<AuthEnvelopedData>>),
	/// Carries the HPKE hello: a `ContentInfo` of type `id-data` whose OCTET
	/// STRING is the DER of the [`ClientHello`].
	Data(Box<WireDer<ContentInfo>>),
}

impl HandshakeMessage {
	/// Returns the signed container.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds another
	///   container, which this step refuses.
	pub fn signed(self) -> CoreResult<WireDer<SignedData>, HandshakeError> {
		match self {
			Self::SignedData(signed) => Ok(*signed),
			Self::AuthEnvelopedData(_) | Self::Data(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// Returns the authenticated-enveloped container.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds another
	///   container, which this step refuses.
	pub fn auth_enveloped(self) -> CoreResult<WireDer<AuthEnvelopedData>, HandshakeError> {
		match self {
			Self::AuthEnvelopedData(enveloped) => Ok(*enveloped),
			Self::SignedData(_) | Self::Data(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// Returns the `ContentInfo` of type `id-data` that carries the HPKE
	/// hello.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds another
	///   container, which this step refuses.
	pub fn data(self) -> CoreResult<WireDer<ContentInfo>, HandshakeError> {
		match self {
			Self::Data(data) => Ok(*data),
			Self::SignedData(_) | Self::AuthEnvelopedData(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// The DER bytes of the message, exactly as sent or received.
	pub fn der(&self) -> &[u8] {
		match self {
			Self::SignedData(signed) => signed.der(),
			Self::AuthEnvelopedData(enveloped) => enveloped.der(),
			Self::Data(data) => data.der(),
		}
	}
}

/// Wraps a signed container this endpoint built, encoded once for sending.
impl TryFrom<SignedData> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(signed: SignedData) -> CoreResult<Self, Self::Error> {
		let signed = WireDer::new(signed)?;
		Ok(Self::SignedData(Box::new(signed)))
	}
}

/// Wraps an authenticated-enveloped container this endpoint built, encoded
/// once for sending.
impl TryFrom<AuthEnvelopedData> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(enveloped: AuthEnvelopedData) -> CoreResult<Self, Self::Error> {
		let enveloped = WireDer::new(enveloped)?;
		Ok(Self::AuthEnvelopedData(Box::new(enveloped)))
	}
}

/// Wraps a `ContentInfo` this endpoint built, encoded once for sending.
impl TryFrom<ContentInfo> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(content_info: ContentInfo) -> CoreResult<Self, Self::Error> {
		let content_info = WireDer::new(content_info)?;
		Ok(Self::Data(Box::new(content_info)))
	}
}

/// What a completed handshake agreed, handed over in one value.
///
/// A handshake settles the keys and the terms that go with them at the same
/// moment, so they travel together and a transport that installs the keys
/// installs the rest with them.
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
	peer: Option<Arc<Certificate>>,
	/// Epoch-0 rekey materials, present exactly while a rekey could use them.
	epoch: Option<EpochMaterials>,
}

impl EstablishedSession {
	/// Assemble what one handshake agreed.
	///
	/// Epoch materials serve a rekey alone, and a rekey re-signs against the
	/// session receipt and the peer identity. A session missing either can
	/// never renew, so this constructor releases its epoch secret instead of
	/// holding it, unreachable, for the life of the session.
	#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn new(
		keys: SessionKeys,
		mux: Option<MuxSettings>,
		receipt: Option<Arc<StoredReceipt>>,
		peer: Option<Arc<Certificate>>,
		epoch: Option<EpochMaterials>,
	) -> Self {
		let renewable = receipt.is_some() && peer.is_some();

		let epoch = epoch.filter(|_| renewable);

		Self { keys, mux, receipt, peer, epoch }
	}

	/// Detach the epoch rekey materials, once.
	pub(crate) fn take_epoch(&mut self) -> Option<EpochMaterials> {
		self.epoch.take()
	}

	/// Bound the send cipher by the encrypted-envelope ceiling the transport
	/// installs this session under ([`SessionKeys::with_envelope_ceiling`]).
	pub(crate) fn with_envelope_ceiling(mut self, encrypted_envelope: usize) -> Self {
		self.keys = self.keys.with_envelope_ceiling(encrypted_envelope);
		self
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
	pub fn peer(&self) -> Option<&Certificate> {
		self.peer.as_deref()
	}

	/// Shared handle to the validated peer certificate.
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
/// It supports multi-round handshakes, where the client sends more than one
/// message before the handshake completes.
///
/// `Send` is required on every target except `wasm32`, where the
/// single-threaded executor lets JS-backed signing providers participate.
pub trait ClientHandshakeProtocol: MaybeSend {
	/// Error the orchestrator returns, convertible into a [`TransportError`].
	type Error: Into<TransportError> + Send;

	/// Start the handshake and return the first message for the server.
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
	/// Call this after the client sends its last message. The client sends on
	/// the client-to-server key and receives on the server-to-client key. The
	/// cipher comes from the [`CryptoProvider`] associated type and the OID
	/// from the negotiated security profile.
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	/// Whether the handshake reached the terminal state that completion enters.
	fn is_complete(&self) -> bool;

	/// Negotiated algorithm OIDs after profile negotiation, or `None` before
	/// the accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// Server-side handshake protocol trait.
///
/// It supports multi-round handshakes, where the server handles more than one
/// request from the client before the handshake completes.
///
/// `Send` is required on every target except `wasm32`, where the
/// single-threaded executor lets JS-backed signing providers participate.
pub trait ServerHandshakeProtocol: MaybeSend {
	/// Error the orchestrator returns, convertible into a [`TransportError`].
	type Error: Into<TransportError> + Send;

	/// Handle a request from the client.
	///
	/// A multi-round handshake calls this once per client message. It returns
	/// `Some` when the server owes a response, and `None` when the message was
	/// the last one. Each step accepts one container and refuses the other.
	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, CoreResult<Option<HandshakeMessage>, Self::Error>>;

	/// Complete the handshake and take everything it agreed.
	///
	/// Call this after [`Self::handle_request`] returns `None`. The server
	/// sends on the server-to-client key and receives on the client-to-server
	/// key. The cipher comes from the [`CryptoProvider`] associated type and
	/// the OID from the negotiated security profile.
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	/// Whether the handshake reached the terminal state that completion enters.
	fn is_complete(&self) -> bool;

	/// Negotiated algorithm OIDs after profile negotiation, or `None` before
	/// the accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// Boxed client handshake orchestrator.
///
/// The object is `Send` on every target except `wasm32`, where JS-backed
/// signing providers make the orchestrator `!Send`. A `dyn` object cannot
/// carry the non-auto [`MaybeSend`] bound, so the auto-trait list is
/// target-gated here.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send + 'static>;

/// Boxed client handshake orchestrator for `wasm32`, which relaxes `Send`.
#[cfg(target_arch = "wasm32")]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + 'static>;

/// Boxed server handshake orchestrator.
///
/// The object is `Send + Sync` on every target except `wasm32`, where
/// JS-backed signing providers make the orchestrator `!Send`. A `dyn` object
/// cannot carry the non-auto [`MaybeSend`] bound, so the auto-trait list is
/// target-gated here.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync + 'static>;

/// Boxed server handshake orchestrator for `wasm32`, which relaxes
/// `Send + Sync`.
#[cfg(target_arch = "wasm32")]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + 'static>;

/// Specifies which handshake protocol to use (HPKE or CMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeProtocolKind {
	/// HPKE-based handshake, the default and the lighter option.
	#[default]
	Hpke,
	/// CMS-based handshake (X.509 signed and authenticated-enveloped data).
	///
	/// The client seals its first message to the server's key-agreement
	/// certificate and signs its Finished, so it MUST provision a trust store,
	/// the server's two certificates, and a client identity. A missing one
	/// fails closed, and so does this kind without the `transport-cms` feature.
	Cms,
}

/// The HPKE hello, the opening of the client, bound into the transcript.
///
/// It travels as the OCTET STRING of a `ContentInfo` of type `id-data`
/// (RFC 5652 § 4), as TLS 1.3 sends its `ClientHello` with the key share.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub client_random: OctetString,
	/// The client's agreement ephemeral `R`, as a compressed SEC1 point on the
	/// negotiated curve. Its ECDH with the server ephemeral derives the
	/// handshake secret alone (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	pub client_ephemeral: OctetString,
	/// Security profiles the client offers for negotiation.
	#[asn1(optional = "true")]
	pub security_offer: Option<SecurityOffer>,
	/// Transport capability offer for multiplexing. The context tag keeps it
	/// distinct from the preceding optional SEQUENCE.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_offer: Option<TransportOffer>,
}

/// The content of the HPKE reply, which the server signs in its `SignedData`
/// under [`HANDSHAKE_REPLY_CONTENT`](crate::oids::HANDSHAKE_REPLY_CONTENT).
///
/// The `SignedData` carries the server's certificate in `certificates`, and
/// its `SignerInfo` names it. The transcript binds this content as it was
/// sent, beside the hello and that certificate.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub server_random: OctetString,
	/// The server's per-handshake ephemeral public key, as a compressed SEC1
	/// point on the negotiated curve. The signed transcript binds it, and its
	/// ECDH with the client ephemeral derives the handshake secret (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	pub server_ephemeral: OctetString,
	/// Profile the server selected. It travels with the bytes the server
	/// encoded.
	#[asn1(optional = "true")]
	pub security_accept: Option<WireDer<SecurityAccept>>,
	/// `true` when the server requires a client certificate for mutual
	/// authentication. The client must then present its identity in the
	/// closing.
	pub client_cert_required: bool,
	/// Transport capability accept for multiplexing. Present only when the
	/// client offered and the server enabled multiplexing locally. It travels
	/// with the bytes the server encoded.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_accept: Option<WireDer<TransportAccept>>,
}

//! TightBeam handshake protocols that establish secure communication channels.
//!
//! This module implements two handshake protocols:
//!
//! - **HPKE-based**: the client seals the base secret to the server's static
//!   key (RFC 9180), and the closing travels as a [`ClientKeyExchange`].
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
//! │  │── ClientHello ───────────►│  (client_rand, security_offer?)         │
//! │  │                           │                                         │
//! │  │◄─ ServerHandshake ────────│  (server_rand, eph, cert, sig, accept?, │
//! │  │                           │   ma?)                                  │
//! │  │── ClientKeyExchange ─────►│  (hpke(base, R, tag, ack?,              │
//! │  │                           │   seal(cert, sig)?))                    │
//! │  │ ◄═ Session Established ═► │  (AEAD keys derived)                    │
//! │  │                           │                                         │
//! │  └───────────────────────────┘                                         │
//! └────────────────────────────────────────────────────────────────────────┘
//! **Legend:**
//! - `seal(cert, sig)` = the client certificate and its signature, sealed under a key of the handshake secret
//! - `eph` = the server's per-handshake ephemeral public key, inside the signed transcript
//! - `tag` = the client's key-confirmation tag, which the server verifies before it settles
//! - Arrows show message direction and content
//! - Session establishment occurs after successful key exchange
//! ```
//!
//! # Forward secrecy
//!
//! Both protocols derive every traffic key from one [`HandshakeSecret`],
//! which takes two inputs:
//!
//! - the ECDH output of the client's ephemeral and the server's ephemeral, and
//! - the base secret the client seals to the server's static key.
//!
//! The server signs its ephemeral inside the transcript, and both ephemeral
//! private keys drop at the step that consumes them. A recording plus a later
//! copy of the server's static key therefore recovers the base secret alone.
//! These need the ECDH output, which needs a private key neither side kept:
//!
//! - the traffic keys and the rekey epochs,
//! - the sealed receipt acknowledgement, and
//! - the sealed client identity.
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
//! | Opening | Client | `ClientHello` | `AuthEnvelopedData` to the server's certificate |
//! | Reply | Server | `ServerHandshake` | Server Finished |
//! | Closing | Client | `ClientKeyExchange` | Client Finished, sealed in `AuthEnvelopedData` |
//!
//! A server reads the closing in one order in both protocols: it opens the
//! closing, confirms the handshake secret, admits the client, and settles the
//! receipt. The client identity opens only under the handshake secret, so the
//! comparison of the client ephemerals with the client's static key waits for
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
pub use peer::PeerAuthentication;
pub use schedule::EpochMaterials;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use flow::{ClientFlow, ServerFlow};
#[cfg(feature = "transport-cms")]
pub use flow::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(feature = "transport-hpke")]
pub use flow::{Hpke, HpkeClientSettings, HpkeServerSettings};
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
pub(crate) use schedule::HandshakeVerifyingKey;
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
use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use crate::crypto::aead::SessionKeys;
use crate::crypto::cms::AuthEnvelopedData;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::cms::ContentEncryption;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::Signed;
use crate::der::asn1::SetOfVec;
use crate::der::{Any, Encode, Enumerated, Sequence, Tag};
use crate::oids::DATA;
use crate::transport::error::TransportError;
use crate::transport::handshake::error::Result;
use crate::transport::handshake::negotiation::{
	MuxSettings, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::receipt::StoredReceipt;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::{MaybeSend, MaybeSendFuture};
use crate::x509::attr::Attributes;
use crate::x509::Certificate;
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::profiles::CryptoProvider;
#[cfg(feature = "transport-hpke")]
use crate::der::asn1::OctetStringRef;
#[cfg(feature = "transport-hpke")]
use crate::der::Decode;
#[cfg(feature = "transport-hpke")]
use schedule::KeyConfirmation;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod transport {
	pub use crate::crypto::aead::KeyInit;
	pub use crate::crypto::common::typenum::U32;
	pub use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
	pub use crate::crypto::sign::elliptic_curve::{Curve, CurveArithmetic, PublicKey};
	pub use crate::crypto::sign::Verifier;
	pub use crate::der::oid::AssociatedOid;
	pub use crate::spki::EncodePublicKey;
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
/// - the verifying key builds from a public key on that curve, verifies a
///   signature, and encodes as an SPKI, and
/// - the AEAD cipher keys from derived bytes and seals an envelope, and
/// - the provider holds an HPKE suite when the build runs the HPKE flow.
///
/// Every provider that meets the bounds is a handshake provider.
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
		VerifyingKey: Verifier<Self::Signature> + From<PublicKey<Self::Curve>> + EncodePublicKey + 'static,
		Digest: 'static,
		AeadCipher: KeyInit + ContentEncryption + 'static,
	> + HandshakeHpke
	+ Send
	+ Sync
	+ 'static
{
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P> HandshakeProvider for P where
	P: CryptoProvider<
			Curve: HandshakeCurve,
			Signature: for<'a> TryFrom<&'a [u8], Error: Into<HandshakeError>> + 'static,
			VerifyingKey: Verifier<P::Signature> + From<PublicKey<P::Curve>> + EncodePublicKey + 'static,
			Digest: 'static,
			AeadCipher: KeyInit + ContentEncryption + 'static,
		> + HandshakeHpke
		+ Send
		+ Sync
		+ 'static
{
}

/// The HPKE role a handshake provider holds: [`HpkeProvider`] when the build
/// runs the HPKE flow.
///
/// [`HpkeProvider`]: crate::crypto::profiles::HpkeProvider
#[cfg(feature = "transport-hpke")]
pub trait HandshakeHpke: crate::crypto::profiles::HpkeProvider {}

#[cfg(feature = "transport-hpke")]
impl<P: crate::crypto::profiles::HpkeProvider> HandshakeHpke for P {}

/// The HPKE role of a build that runs the CMS flow alone, which every provider
/// holds.
#[cfg(all(feature = "transport-cms", not(feature = "transport-hpke")))]
pub trait HandshakeHpke {}

#[cfg(all(feature = "transport-cms", not(feature = "transport-hpke")))]
impl<P> HandshakeHpke for P {}

/// Provisioned server identity for a CMS client handshake.
///
/// The client encrypts the base secret to the identity's leaf certificate.
#[cfg(feature = "transport-cms")]
pub enum CmsServerIdentity {
	/// A bare server certificate, evaluated directly against the trust store.
	Certificate(Arc<Certificate>),
	/// Full server chain, ordered root to leaf. Path validation runs over the
	/// chain per [RFC 5280 §6.1][rfc5280-6.1], and the leaf becomes the
	/// encryption target.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
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

/// A handshake message travels in one of three containers, two of them CMS.
///
/// HPKE carries its hello and its reply inside a `SignedData`, and its
/// closing in a [`ClientKeyExchange`] of its own, because HPKE specifies no
/// wire format (RFC 9180 § 10). The CMS handshake exchanges the CMS
/// containers themselves.
#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeMessage {
	/// Carries an HPKE `ClientHello` or `ServerHandshake`, or a CMS server
	/// Finished.
	SignedData(Box<WireDer<SignedData>>),
	/// Carries a CMS opening, or a CMS client Finished sealed under the
	/// identity key of the handshake secret (RFC 5083).
	AuthEnvelopedData(Box<WireDer<AuthEnvelopedData>>),
	/// Carries the closing of an HPKE handshake.
	ClientKeyExchange(Box<WireDer<ClientKeyExchange>>),
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
			Self::AuthEnvelopedData(_) | Self::ClientKeyExchange(_) => Err(HandshakeError::UnexpectedContainer),
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
			Self::SignedData(_) | Self::ClientKeyExchange(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// Returns the HPKE key exchange.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the message holds another
	///   container, which this step refuses.
	pub fn key_exchange(self) -> CoreResult<WireDer<ClientKeyExchange>, HandshakeError> {
		match self {
			Self::ClientKeyExchange(key_exchange) => Ok(*key_exchange),
			Self::SignedData(_) | Self::AuthEnvelopedData(_) => Err(HandshakeError::UnexpectedContainer),
		}
	}

	/// The DER bytes of the message, exactly as sent or received.
	pub fn der(&self) -> &[u8] {
		match self {
			Self::SignedData(signed) => signed.der(),
			Self::AuthEnvelopedData(enveloped) => enveloped.der(),
			Self::ClientKeyExchange(key_exchange) => key_exchange.der(),
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

/// Wraps an HPKE key exchange this endpoint built, encoded once for sending.
impl TryFrom<ClientKeyExchange> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(key_exchange: ClientKeyExchange) -> CoreResult<Self, Self::Error> {
		let key_exchange = WireDer::new(key_exchange)?;
		Ok(Self::ClientKeyExchange(Box::new(key_exchange)))
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
	/// The client encrypts to the server certificate in its first message and
	/// signs its Finished, so it MUST provision a trust store, the server
	/// certificate chain, and a client identity. A missing one fails closed,
	/// and so does this kind without the `transport-cms` feature.
	Cms,
}

/// Opening handshake message from the client, bound into the transcript.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub client_random: OctetString,
	/// Security profiles the client offers for negotiation.
	#[asn1(optional = "true")]
	pub security_offer: Option<SecurityOffer>,
	/// Transport capability offer for multiplexing. The context tag keeps it
	/// distinct from the preceding optional SEQUENCE.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_offer: Option<TransportOffer>,
}

/// Server response to a [`ClientHello`], bound into the transcript.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	/// Server identity certificate the client validates against its
	/// trust store.
	pub certificate: Certificate,
	/// 32-byte anti-replay nonce mixed into the key derivation.
	pub server_random: OctetString,
	/// The server's per-handshake ephemeral public key, as a compressed SEC1
	/// point on the negotiated curve. The signed transcript binds it, and its
	/// ECDH with the client ephemeral feeds the handshake secret (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	pub server_ephemeral: OctetString,
	/// Server signature over the labelled digest of the transcript hash, which
	/// proves possession of the certificate's private key.
	pub signature: OctetString,
	/// Profile the server selected. It travels with the bytes the server
	/// encoded, so both endpoints bind one encoding into the transcript.
	#[asn1(optional = "true")]
	pub security_accept: Option<WireDer<SecurityAccept>>,
	/// `true` when the server requires a client certificate for mutual
	/// authentication. The client must then provide its certificate in the
	/// [`ClientKeyExchange`].
	pub client_cert_required: bool,
	/// Transport capability accept for multiplexing. Present only when the
	/// client offered and the server enabled multiplexing locally. It travels
	/// with the bytes the server encoded, so both endpoints bind one encoding
	/// into the transcript.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_accept: Option<WireDer<TransportAccept>>,
	/// Server-signed session receipt artifact for a budget-bearing session.
	///
	/// The artifact is a CMS `SignedData` ([RFC 5652 §5][rfc5652-5]). Its
	/// `eContent` is the receipt body with the transcript hash, the granted
	/// budgets, and the settlement challenge. Its single `SignerInfo` is the
	/// server's signature over that body.
	///
	/// [rfc5652-5]: https://datatracker.ietf.org/doc/html/rfc5652#section-5
	#[asn1(context_specific = "1", optional = "true")]
	pub session_receipt: Option<Signed<SignedData>>,
}

/// Confidential plaintext of the HPKE key exchange.
///
/// Only the server decrypts it. It carries the base secret, the anti-replay
/// client random, the client ephemeral, the key-confirmation tag, the sealed
/// receipt countersignature, and the sealed client identity.
#[cfg(feature = "transport-hpke")]
#[derive(Clone, Sequence)]
pub(crate) struct HpkeSessionPayload {
	/// 32-byte base secret, one of the two inputs of the handshake secret.
	pub base_key: OctetString,
	/// 32-byte client random echoed back for replay resistance.
	pub client_random: OctetString,
	/// The client's ephemeral public key, as a compressed SEC1 point, which
	/// the server pairs with its own ephemeral for the handshake secret. It
	/// serves that agreement alone, and HPKE draws the key it seals under
	/// itself (RFC 9180 § 9.2.3).
	pub client_ephemeral: OctetString,
	/// The proof that the client derived the handshake secret, which the
	/// server verifies before it settles.
	pub key_confirmation: KeyConfirmation,
	/// The DER of the envelope that seals the client receipt `SignerInfo`
	/// under the acknowledgement key. Its signed attributes bind the bearer
	/// settlement answer (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	/// It is required exactly when the server issued a receipt.
	#[asn1(context_specific = "0", optional = "true")]
	pub receipt_ack: Option<OctetString>,
	/// The DER of the `AuthEnvelopedData` that seals the client's
	/// [`HpkeIdentity`] under the identity key of the handshake secret, when
	/// the client presents an identity. The key needs the ephemeral-ephemeral
	/// agreement, so a later theft of the server's static key does not open it.
	#[asn1(context_specific = "1", optional = "true")]
	pub sealed_identity: Option<OctetString>,
}

/// The identity an HPKE client presents: its certificate and the signature
/// that proves it holds the certificate's key.
///
/// It travels only sealed, inside [`HpkeSessionPayload::sealed_identity`], so
/// the pair crosses the wire as one value or not at all.
#[cfg(feature = "transport-hpke")]
#[derive(Sequence)]
pub(crate) struct HpkeIdentity {
	/// The client certificate.
	pub certificate: Certificate,
	/// The signature of the certificate's key over the possession digest.
	pub signature: OctetString,
}

/// The closing of an HPKE handshake, in a container of its own.
///
/// HPKE specifies no wire format (RFC 9180 § 10), so the container holds the
/// HPKE message and the alert slot alone. The negotiated profile names the
/// suite, and the transcript binds the server key the message is sealed to.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	/// The HPKE message, the encapsulated key followed by the ciphertext. It
	/// seals the session payload to the server's static key, and the payload
	/// carries the client ephemeral of the handshake secret and the client
	/// identity sealed under a key of that secret.
	pub sealed_payload: OctetString,
	/// Attributes outside the seal, where a receiver refuses an abort alert.
	/// The tag is the one `EnvelopedData` and `EncryptedData` give their
	/// unprotected attributes.
	#[asn1(
		context_specific = "1",
		tag_mode = "IMPLICIT",
		constructed = "true",
		optional = "true"
	)]
	pub unprotected_attrs: Option<Attributes>,
}

fn encodable_to_signed_data<T: Encode>(message: &T) -> Result<SignedData> {
	let message_der = message.to_der()?;
	let octet_string = OctetString::new(message_der)?;
	let econtent = Any::new(Tag::OctetString, octet_string.to_der()?)?;
	let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent) };

	Ok(SignedData {
		version: CmsVersion::V1,
		digest_algorithms: Default::default(),
		encap_content_info,
		certificates: None,
		crls: None,
		signer_infos: SignerInfos::from(SetOfVec::new()),
	})
}

/// Access to the HPKE message a `SignedData` tunnels.
///
/// The step that reads the message decodes it from these bytes and binds the
/// same bytes into its transcript, so the message is parsed once and hashed as
/// it arrived.
#[cfg(feature = "transport-hpke")]
pub(crate) trait TunneledMessage {
	/// The DER of the tunneled message, as it arrived.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidServerKeyExchange`] -- the container carries no content.
	/// - [`HandshakeError::DerError`] -- the content is not an OCTET STRING.
	fn tunneled_der(&self) -> Result<&[u8]>;
}

#[cfg(feature = "transport-hpke")]
impl TunneledMessage for SignedData {
	fn tunneled_der(&self) -> Result<&[u8]> {
		let econtent = self
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::InvalidServerKeyExchange)?;

		let octets = OctetStringRef::from_der(econtent.value())?;
		Ok(octets.as_bytes())
	}
}

/// Wraps a [`ClientHello`] in an opaque `SignedData`.
impl TryFrom<&ClientHello> for SignedData {
	type Error = HandshakeError;

	fn try_from(hello: &ClientHello) -> CoreResult<Self, Self::Error> {
		encodable_to_signed_data(hello)
	}
}

/// Wraps a [`ServerHandshake`] in an opaque `SignedData`.
impl TryFrom<&ServerHandshake> for SignedData {
	type Error = HandshakeError;

	fn try_from(handshake: &ServerHandshake) -> CoreResult<Self, Self::Error> {
		encodable_to_signed_data(handshake)
	}
}

/// Reads the [`ClientHello`] that an opaque `SignedData` tunnels.
#[cfg(feature = "transport-hpke")]
impl TryFrom<&SignedData> for ClientHello {
	type Error = HandshakeError;

	fn try_from(tunnel: &SignedData) -> CoreResult<Self, Self::Error> {
		Ok(Self::from_der(tunnel.tunneled_der()?)?)
	}
}

/// Reads the [`ServerHandshake`] that an opaque `SignedData` tunnels.
#[cfg(feature = "transport-hpke")]
impl TryFrom<&SignedData> for ServerHandshake {
	type Error = HandshakeError;

	fn try_from(tunnel: &SignedData) -> CoreResult<Self, Self::Error> {
		Ok(Self::from_der(tunnel.tunneled_der()?)?)
	}
}

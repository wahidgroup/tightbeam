//! The TightBeam handshake protocols, which establish an encrypted session.
//!
//! This module implements two handshake protocols:
//!
//! - **HPKE**: the shape of the TLS 1.3 handshake (RFC 9846) in CMS
//!   containers. The server's key signs its reply, and the handshake secret
//!   derives from the two ephemerals alone.
//! - **CMS-based**: X.509 PKI on both endpoints, with signed and authenticated-enveloped data.
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
//! Both roles run one machine over both protocols, and [`HandshakePhase`]
//! names its phase. A step reads the leg the peer sent, builds the leg its
//! role sends, or both, and [`Handshake::complete`] takes the session.
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
mod session_peer;

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
pub(crate) use session_peer::SessionPeer;

#[cfg(mux_rekey)]
pub(crate) use self::{
	peer::{AgreementCertificate, ServerKeys},
	schedule::{EpochSecret, PeerEphemeral},
	wire::HandshakeOctets,
};
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
pub(crate) use peer::ValidatorChain;
#[cfg(all(test, mux_rekey))]
pub(crate) use schedule::CompressedPoint;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use schedule::HandshakeSecret;

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
/// The field is 32 bytes wide, so a shared secret is 32 bytes by type. A point
/// of the HPKE flow or of a rekey travels in its compressed SEC 1 form, at
/// the width the curve gives that form (SEC 1 v2.0 §2.3.3). Every curve that
/// meets the bounds is a handshake curve.
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

/// The certificate a CMS client pins for its server: the server's
/// key-agreement certificate, a leaf or a chain that ends at the leaf.
///
/// Its `keyUsage` asserts the bit of the provider's KEM,
/// [`RecipientKem::USAGE`]: `keyAgreement` for the house DHKEM.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub enum CmsServerIdentity {
	/// A bare server certificate, which the client evaluates directly against
	/// the trust store.
	Certificate(Arc<Certificate>),
	/// The server's chain, ordered root to leaf. Path validation runs over the
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
	/// The chain `path`, ordered root to leaf. This call copies its leaf once.
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

	/// The leaf, which identifies the server.
	pub fn leaf(&self) -> &Arc<Certificate> {
		&self.leaf
	}
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

/// The alert code an endpoint sends to abort a handshake.
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

	/// The DER bytes of the message, as the endpoint sent or received them.
	pub fn der(&self) -> &[u8] {
		match self {
			Self::SignedData(signed) => signed.der(),
			Self::AuthEnvelopedData(enveloped) => enveloped.der(),
			Self::Data(data) => data.der(),
		}
	}
}

/// Wraps a signed container this endpoint built, and encodes it once to send.
impl TryFrom<SignedData> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(signed: SignedData) -> CoreResult<Self, Self::Error> {
		let signed = WireDer::new(signed)?;
		Ok(Self::SignedData(Box::new(signed)))
	}
}

/// Wraps an authenticated-enveloped container this endpoint built, and
/// encodes it once to send.
impl TryFrom<AuthEnvelopedData> for HandshakeMessage {
	type Error = HandshakeError;

	fn try_from(enveloped: AuthEnvelopedData) -> CoreResult<Self, Self::Error> {
		let enveloped = WireDer::new(enveloped)?;
		Ok(Self::AuthEnvelopedData(Box::new(enveloped)))
	}
}

/// Wraps a `ContentInfo` this endpoint built, and encodes it once to send.
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
	/// The role-mapped directional keys. Each side sends on one key and
	/// receives on the other.
	keys: SessionKeys,
	/// The multiplexing terms, when both sides negotiated them. `None` leaves
	/// the session single-flight.
	mux: Option<MuxSettings>,
	/// The dual-signed receipt of a budget-bearing handshake.
	receipt: Option<Arc<StoredReceipt>>,
	/// The peer the handshake validated, one record that each session context
	/// of a gate shares.
	peer: Option<Arc<SessionPeer>>,
	/// The epoch-0 rekey materials, present exactly while a rekey could use
	/// them.
	/// The mux rekey reads them, so the field exists in a build with it.
	#[cfg(mux_rekey)]
	epoch: Option<EpochMaterials>,
}

impl EstablishedSession {
	/// Assemble what one handshake agreed, with no epoch materials.
	///
	/// It is private to the handshake, whose completion records only a peer
	/// that an admission built.
	#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
	fn new(
		keys: SessionKeys,
		mux: Option<MuxSettings>,
		receipt: Option<Arc<StoredReceipt>>,
		peer: Option<SessionPeer>,
	) -> Self {
		let peer = peer.map(Arc::new);

		Self {
			keys,
			mux,
			receipt,
			peer,
			#[cfg(mux_rekey)]
			epoch: None,
		}
	}

	/// This session with `epoch`, the epoch-0 rekey materials, kept exactly
	/// while a rekey could use them.
	///
	/// Epoch materials serve a rekey alone, and a rekey re-signs against the
	/// session receipt and the peer identity. A session renews only when it
	/// holds both, so this method treats the epoch secret in two ways:
	///
	/// - A session with a receipt and a peer keeps it.
	/// - Every other session releases it at once.
	#[cfg(mux_rekey)]
	fn with_epoch(self, epoch: EpochMaterials) -> Self {
		let renewable = self.receipt.is_some() && self.peer.is_some();
		let epoch = Some(epoch).filter(|_| renewable);
		Self { epoch, ..self }
	}

	/// A session of `keys`, `receipt`, and `peer`, for a test that holds the
	/// parts a handshake agrees.
	#[cfg(test)]
	pub(crate) fn forged(keys: SessionKeys, receipt: Option<Arc<StoredReceipt>>, peer: Option<SessionPeer>) -> Self {
		Self::new(keys, None, receipt, peer)
	}

	/// This session with `epoch` under the rule of [`Self::with_epoch`], for
	/// a test that holds the epoch a handshake derives.
	#[cfg(all(test, mux_rekey))]
	pub(crate) fn with_forged_epoch(self, epoch: EpochMaterials) -> Self {
		self.with_epoch(epoch)
	}

	/// The peer the handshake validated, which a rekey renews against and a
	/// session context shares.
	pub(crate) fn session_peer(&self) -> Option<&Arc<SessionPeer>> {
		self.peer.as_ref()
	}

	/// Detach the epoch rekey materials, once.
	#[cfg(mux_rekey)]
	pub(crate) fn take_epoch(&mut self) -> Option<EpochMaterials> {
		self.epoch.take()
	}

	/// The epoch rekey materials the session still holds.
	#[cfg(all(test, mux_rekey))]
	pub(crate) fn epoch(&self) -> Option<&EpochMaterials> {
		self.epoch.as_ref()
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

	/// The role-mapped directional keys of this session.
	pub fn keys(&self) -> &SessionKeys {
		&self.keys
	}

	/// The multiplexing terms both sides agreed, if any.
	pub fn mux(&self) -> Option<MuxSettings> {
		self.mux
	}

	/// The dual-signed receipt of a budget-bearing handshake, if any.
	pub fn receipt(&self) -> Option<&StoredReceipt> {
		self.receipt.as_deref()
	}

	/// The peer certificate the handshake validated. A server holds the
	/// client's under mutual authentication, and a client holds the server's
	/// signing certificate.
	pub fn peer(&self) -> Option<&Certificate> {
		let peer = self.peer.as_ref();
		peer.map(|peer| peer.certificate().as_ref())
	}

	/// A shared handle to the certificate that [`Self::peer`] returns.
	pub fn peer_arc(&self) -> Option<Arc<Certificate>> {
		let peer = self.peer.as_ref();
		peer.map(|peer| Arc::clone(peer.certificate()))
	}

	/// A shared handle to the dual-signed session receipt.
	pub fn receipt_arc(&self) -> Option<Arc<StoredReceipt>> {
		self.receipt.as_ref().map(Arc::clone)
	}
}

/// The client side of a handshake protocol.
///
/// It supports multi-round handshakes, where the client sends more than one
/// message before the handshake completes.
///
/// The [`MaybeSend`] bound requires `Send` on every target except `wasm32`,
/// where the single-threaded executor lets JS-backed signing providers
/// participate.
pub trait ClientHandshakeProtocol: MaybeSend {
	/// The error the orchestrator returns, which converts into a
	/// [`TransportError`].
	type Error: Into<TransportError> + Send;

	/// Start the handshake and return the first message for the server.
	#[allow(clippy::type_complexity)]
	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, CoreResult<HandshakeMessage, Self::Error>>;

	/// Handle a response from the server.
	///
	/// Returns `Some` when the client owes the server another message, and
	/// `None` once it has sent its last. Each step accepts one container and
	/// refuses the others.
	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, CoreResult<Option<HandshakeMessage>, Self::Error>>;

	/// Complete the handshake and take everything it agreed.
	///
	/// Call this after the client sends its last message. The client sends on
	/// the client-to-server key and receives on the server-to-client key. The
	/// cipher comes from the [`CryptoProvider`] associated type, and the OID
	/// comes from the negotiated security profile.
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	/// Whether the handshake reached the terminal state that completion enters.
	fn is_complete(&self) -> bool;

	/// The algorithm OIDs that profile negotiation selected, or `None` before
	/// the accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// The server side of a handshake protocol.
///
/// It supports multi-round handshakes, where the server handles more than one
/// request from the client before the handshake completes.
///
/// The [`MaybeSend`] bound requires `Send` on every target except `wasm32`,
/// where the single-threaded executor lets JS-backed signing providers
/// participate.
pub trait ServerHandshakeProtocol: MaybeSend {
	/// The error the orchestrator returns, which converts into a
	/// [`TransportError`].
	type Error: Into<TransportError> + Send;

	/// Handle a request from the client.
	///
	/// A multi-round handshake calls this once per client message. It returns
	/// `Some` when the server owes a response, and `None` when the message was
	/// the last one. Each step accepts one container and refuses the others.
	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, CoreResult<Option<HandshakeMessage>, Self::Error>>;

	/// Complete the handshake and take everything it agreed.
	///
	/// Call this after [`Self::handle_request`] returns `None`. The server
	/// sends on the server-to-client key and receives on the client-to-server
	/// key. The cipher comes from the [`CryptoProvider`] associated type, and
	/// the OID comes from the negotiated security profile.
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, CoreResult<EstablishedSession, Self::Error>>;

	/// Whether the handshake reached the terminal state that completion enters.
	fn is_complete(&self) -> bool;

	/// The algorithm OIDs that profile negotiation selected, or `None` before
	/// the accept.
	fn selected_profile(&self) -> Option<SecurityProfileDesc>;
}

/// A boxed client handshake orchestrator.
///
/// The object is `Send` on every target except `wasm32`, where JS-backed
/// signing providers make the orchestrator `!Send`. A `dyn` object cannot
/// carry the non-auto [`MaybeSend`] bound, so a `cfg` on the target picks
/// the auto-trait list.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + Send + 'static>;

/// A boxed client handshake orchestrator for `wasm32`, which relaxes `Send`.
#[cfg(target_arch = "wasm32")]
pub type BoxedClientHandshake = Box<dyn ClientHandshakeProtocol<Error = HandshakeError> + 'static>;

/// A boxed server handshake orchestrator.
///
/// The object is `Send + Sync` on every target except `wasm32`, where
/// JS-backed signing providers make the orchestrator `!Send`. A `dyn` object
/// cannot carry the non-auto [`MaybeSend`] bound, so a `cfg` on the target
/// picks the auto-trait list.
#[cfg(not(target_arch = "wasm32"))]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + Send + Sync + 'static>;

/// A boxed server handshake orchestrator for `wasm32`, which relaxes
/// `Send + Sync`.
#[cfg(target_arch = "wasm32")]
pub type BoxedServerHandshake = Box<dyn ServerHandshakeProtocol<Error = HandshakeError> + 'static>;

/// The handshake protocol an endpoint runs, HPKE or CMS.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeProtocolKind {
	/// The HPKE-based handshake, which is the default. Its server needs a
	/// signing certificate alone, and its client presents an identity only for
	/// mutual authentication.
	#[default]
	Hpke,
	/// The CMS-based handshake (X.509 signed and authenticated-enveloped data).
	///
	/// The client seals its first message to the server's key-agreement
	/// certificate and signs its Finished, so it MUST provision a client
	/// identity and the trust in its server, [`with_cms_server`]. A missing one
	/// fails closed, and so does this kind without the `transport-cms` feature.
	///
	/// [`with_cms_server`]: crate::transport::ClientBuilder::with_cms_server
	Cms,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeProtocolKind {
	/// The client handshake of the flow this kind names, which `provisioning`
	/// configures alone.
	///
	/// # Errors
	///
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the flow of this kind.
	/// - [`TransportError`] -- the errors of [`FlowProvisioning::client_config`] for that flow.
	pub(crate) fn client_handshake<P, E>(self, provisioning: &E) -> Result<BoxedClientHandshake, TransportError>
	where
		P: HandshakeProvider,
		E: Provisioning<P>,
	{
		let handshake: BoxedClientHandshake = match self {
			#[cfg(feature = "transport-hpke")]
			Self::Hpke => Box::new(Handshake::client(FlowProvisioning::<Hpke, P>::client_config(provisioning)?)),

			#[cfg(feature = "transport-cms")]
			Self::Cms => Box::new(Handshake::client(FlowProvisioning::<Cms, P>::client_config(provisioning)?)),

			#[cfg(not(all(feature = "transport-cms", feature = "transport-hpke")))]
			unsupported => return Err(TransportError::UnsupportedHandshakeProtocol(unsupported)),
		};

		Ok(handshake)
	}

	/// The server handshake of the flow this kind names, which `provisioning`
	/// configures alone.
	///
	/// # Errors
	///
	/// - [`TransportError::UnsupportedHandshakeProtocol`] -- this build lacks the flow of this kind.
	/// - [`TransportError`] -- the errors of [`FlowProvisioning::server_config`] for that flow.
	pub(crate) fn server_handshake<P, E>(self, provisioning: &E) -> Result<BoxedServerHandshake, TransportError>
	where
		P: HandshakeProvider,
		E: Provisioning<P>,
	{
		let handshake: BoxedServerHandshake = match self {
			#[cfg(feature = "transport-hpke")]
			Self::Hpke => Box::new(Handshake::server(FlowProvisioning::<Hpke, P>::server_config(provisioning)?)),

			#[cfg(feature = "transport-cms")]
			Self::Cms => Box::new(Handshake::server(FlowProvisioning::<Cms, P>::server_config(provisioning)?)),

			#[cfg(not(all(feature = "transport-cms", feature = "transport-hpke")))]
			unsupported => return Err(TransportError::UnsupportedHandshakeProtocol(unsupported)),
		};

		Ok(handshake)
	}
}

/// The provisioning of an endpoint, which builds both configurations of flow
/// `F` from what it holds alone.
///
/// Each flow is one implementation, which reads the trust and the identity
/// that its configurations take and refuses a provisioning that lacks a
/// required one. [`HandshakeProtocolKind`] picks the flow.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait FlowProvisioning<F: ClientFlow<P> + ServerFlow<P>, P: HandshakeProvider> {
	/// The configuration of a client handshake of flow `F`.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- this provisioning lacks the trust or the identity the client of `F` takes.
	fn client_config(&self) -> Result<ClientConfig<F, P>, TransportError>;

	/// The configuration of a server handshake of flow `F`.
	///
	/// # Errors
	///
	/// - [`TransportError`] -- this provisioning lacks the identity the server of `F` presents.
	fn server_config(&self) -> Result<ServerConfig<F, P>, TransportError>;
}

/// The provisioning of an endpoint, which builds each flow this build
/// compiles. It is the bound of the flow choice of [`HandshakeProtocolKind`].
#[cfg(all(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait Provisioning<P: HandshakeProvider>:
	FlowProvisioning<Hpke, P> + FlowProvisioning<Cms, P>
{
}

/// The provisioning of an endpoint, which builds the HPKE flow, the one flow
/// this build compiles.
#[cfg(all(feature = "transport-hpke", not(feature = "transport-cms")))]
pub(crate) trait Provisioning<P: HandshakeProvider>: FlowProvisioning<Hpke, P> {}

/// The provisioning of an endpoint, which builds the CMS flow, the one flow
/// this build compiles.
#[cfg(all(feature = "transport-cms", not(feature = "transport-hpke")))]
pub(crate) trait Provisioning<P: HandshakeProvider>: FlowProvisioning<Cms, P> {}

/// The HPKE hello, the opening of the client, bound into the transcript.
///
/// It travels as the OCTET STRING of a `ContentInfo` of type `id-data`
/// (RFC 5652 § 4), as TLS 1.3 sends its `ClientHello` with the key share.
#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	/// A 32-byte anti-replay nonce that the key derivation mixes in.
	pub client_random: OctetString,
	/// The client's agreement ephemeral `R`, as a compressed SEC 1 point on the
	/// negotiated curve. Its ECDH with the server ephemeral derives the
	/// handshake secret alone (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	pub client_ephemeral: OctetString,
	/// The security profiles the client offers for negotiation.
	#[asn1(optional = "true")]
	pub security_offer: Option<SecurityOffer>,
	/// The transport capability offer for multiplexing. The context tag keeps
	/// it distinct from the preceding optional SEQUENCE.
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
	/// A 32-byte anti-replay nonce that the key derivation mixes in.
	pub server_random: OctetString,
	/// The server's per-handshake ephemeral public key, as a compressed SEC 1
	/// point on the negotiated curve. The signed transcript binds it, and its
	/// ECDH with the client ephemeral derives the handshake secret (see
	/// [forward secrecy](crate::transport::handshake#forward-secrecy)).
	pub server_ephemeral: OctetString,
	/// The profile the server selected, which travels with the bytes the
	/// server encoded.
	#[asn1(optional = "true")]
	pub security_accept: Option<WireDer<SecurityAccept>>,
	/// `true` when the server requires a client certificate for mutual
	/// authentication. The client must then present its identity in the
	/// closing.
	pub client_cert_required: bool,
	/// The transport capability accept for multiplexing, which the server sends
	/// only when the client offered multiplexing and the server enabled it
	/// locally. It travels with the bytes the server encoded.
	#[asn1(context_specific = "0", optional = "true")]
	pub transport_accept: Option<WireDer<TransportAccept>>,
}

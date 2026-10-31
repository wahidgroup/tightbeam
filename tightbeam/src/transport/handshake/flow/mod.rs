//! The messages of one handshake protocol, and the one closing both send.
//!
//! A flow encodes and decodes the opening and the reply of one protocol,
//! binds them into the transcript, and makes the checks its messages define.
//! The orchestrator owns the step order and every negotiation and admission
//! decision, and it acts on the decoded facts alone.
//!
//! A step of the orchestrator works between three kinds of flow call:
//!
//! 1. A `read_*` or `bind_*` call returns the facts of the leg and the bytes to sign.
//! 2. The orchestrator admits, negotiates, and countersigns, and the signing identity signs each prehash.
//! 3. An `encode_*` call takes the result and builds the message.
//!
//! The [legs](crate::transport::handshake#legs) table names the message each
//! protocol sends on each leg.
//!
//! ## The closing
//!
//! Both flows derive the handshake secret at the reply, and both seal the
//! closing under its closing key as an `AuthEnvelopedData` with one
//! `KEKRecipientInfo`. [`ClosingDraft`] builds the closing and signs its
//! client Finished, and [`ClosingContent`] is the one reader of its two forms:
//!
//! - `id-signedData`: the client Finished, which carries the key-confirmation tag and the acknowledgement.
//! - `id-data`: the DER `SET OF Attribute` of an anonymous client, which holds those two attributes alone.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

use crate::asn1::admission::DerAdmission;
use crate::cms::signed_data::{CertificateSet, SignedData};
use crate::crypto::cms::AuthEnvelopedData;
use crate::crypto::kdf::KdfSalt;
use crate::crypto::sign::{
	CmsSigner, PresentedIssuers, PresentedPath, Signed, SignedContent, SignedDataExt, SignerInfoDraft, SigningIdentity,
};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::{Decode, Encode};
use crate::frame::ArrivedCertificates;
use crate::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::oids::{DATA, RECEIPT_ACK, SIGNED_DATA};
use crate::random::CryptoRngCore;
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::ephemeral::{Distinct, ExchangeSecret, OpenedShare, PeerStatics};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	RunnableProfile, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::peer::ServerTrust;
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::schedule::{
	ConfirmedSecret, FinishedRole, KeyConfirmation, Salt, Sealer, SecretSeal, Terms,
};
use crate::transport::handshake::{
	ClientShare, Exchange, HandshakeMessage, HandshakeProvider, HandshakeSecret, ServerIdentity, ServerShare,
};
use crate::transport::wire_der::WireDer;
use crate::x509::attr::{Attribute, Attributes};

#[cfg(feature = "transport-hpke")]
use crate::crypto::exchange::KeyShare;
#[cfg(feature = "transport-cms")]
use crate::crypto::exchange::ReplyAttribute;

#[cfg(feature = "transport-cms")]
mod cms;
#[cfg(feature = "transport-hpke")]
mod hpke;

#[cfg(feature = "transport-cms")]
pub use cms::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(feature = "transport-hpke")]
pub use hpke::{Hpke, HpkeClientSettings, HpkeServerSettings};

#[cfg(all(test, feature = "transport-cms"))]
pub(crate) use cms::OpeningContent;

mod sealed {
	pub trait Sealed {}
}

/// A handshake protocol, named by its marker type.
///
/// The trait is sealed, so [`Hpke`] and [`Cms`] are the only flows.
pub trait HandshakeFlow: sealed::Sealed + Sized + MaybeSend + MaybeSync + 'static {}

/// What the client configuration contributes to the opening.
pub struct OpeningParts<'a> {
	/// The security profiles the client offers.
	pub security_offer: Option<&'a SecurityOffer>,
	/// The transport capabilities the client offers.
	pub transport_offer: Option<&'a TransportOffer>,
}

/// An encoded opening, with what the client keeps for the reply.
pub struct Opened<F: ClientLegs<P>, P: HandshakeProvider> {
	/// The opening, encoded once for sending.
	pub message: HandshakeMessage,
	/// What the flow reads the reply against.
	pub opening: F::Opening,
	/// The secrets the flow holds until the agreement.
	pub pending: F::Pending,
}

/// The server's share as its reply carried it. The client parses it once the
/// reply's signature verifies, so no unauthenticated octet reaches a parse.
pub enum ReceivedShare {
	/// The OCTET STRING of the HPKE reply.
	#[cfg(feature = "transport-hpke")]
	Octets(OctetString),
	/// The reply attribute of the CMS Finished.
	#[cfg(feature = "transport-cms")]
	Attribute(ReplyAttribute),
}

impl ReceivedShare {
	/// Parses the share of the exchange of `P` from its carrier.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the carrier holds no share of the exchange.
	pub(crate) fn parse<P: HandshakeProvider>(&self) -> Result<ServerShare<P>, HandshakeError> {
		let share = match self {
			#[cfg(feature = "transport-hpke")]
			Self::Octets(octets) => <ServerShare<P> as KeyShare<Exchange<P>>>::from_octets(octets.as_bytes()),
			#[cfg(feature = "transport-cms")]
			Self::Attribute(attribute) => attribute.reply::<Exchange<P>>(),
		};
		Ok(share?)
	}
}

/// The facts of a decoded reply, bound into the sealed transcript.
pub struct ReplyIntake<F: ClientLegs<P>, P: HandshakeProvider> {
	/// What the reply names as the server, for the trust to admit.
	pub server: <F::Trust as ServerTrust<P>>::Named,
	/// The security profile the server selected.
	pub security_accept: Option<SecurityAccept>,
	/// The transport capabilities the server accepted.
	pub transport_accept: Option<TransportAccept>,
	/// The server's share in its carrier. The orchestrator parses it once the
	/// reply's signature verifies, and checks it against the static keys of the
	/// server it admits.
	pub server_ephemeral: ReceivedShare,
	/// The server-signed session receipt, when the session carries budgets.
	pub receipt: Option<Signed<SignedData>>,
	/// Whether the server demands a client identity. The HPKE reply carries
	/// the demand, and the CMS flow yields `false`, because a CMS client always
	/// holds an identity.
	pub client_cert_required: bool,
	/// The hash of the sealed transcript, which the reply signs.
	pub transcript_hash: TranscriptHash,
	/// The KDF salt of the flow.
	pub salt: Salt,
	/// The signed reply, kept for verification and for the server Finished.
	pub reply: SignedData,
}

/// The proof that the signature of a reply verified under the server the
/// client admitted.
///
/// [`ClientLegs::verify_reply`] is its one constructor, and
/// [`ServerConfirmed::confirm`] takes it, so a secret confirms only a server
/// whose reply signature verified. Its field stays private to the flows.
pub struct ReplyVerified(());

/// The handshake secret of a client that verified the reply's signature and
/// its server Finished.
///
/// [`Handshake::close`](crate::transport::handshake::Handshake) takes it, so a
/// closing exists only after [`Self::confirm`] ran. [`Self::confirm`] is its
/// one constructor, for both flows.
pub struct ServerConfirmed(HandshakeSecret);

impl ServerConfirmed {
	/// Verify the server Finished of `reply` under `secret`, for a reply whose
	/// signature `verified` proves, and confirm the server.
	///
	/// The server Finished travels once, as an unsigned attribute of the
	/// reply's `SignerInfo`, and the secret comes back only when it verifies.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the reply carries no server Finished.
	/// - [`HandshakeError::DuplicateAttribute`] -- the reply carries its server Finished twice.
	/// - [`HandshakeError::DerError`] -- the server Finished is no OCTET STRING of 32 to 64 bytes.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the reply does not have exactly one signer.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the server Finished fails to verify.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the server's `MacKey`.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
	pub(crate) fn confirm<P: HandshakeProvider>(
		reply: &SignedData,
		verified: ReplyVerified,
		secret: HandshakeSecret,
		terms: &Terms<P>,
	) -> Result<Self, HandshakeError> {
		let ReplyVerified(()) = verified;
		let finished = reply.find_unsigned_attr(KeyConfirmation::OID)?;
		let finished = finished.ok_or(HandshakeError::MissingAttribute)?;
		let received = finished.decode::<KeyConfirmation>()?;

		let secret = terms.confirm_server(secret, reply, &received)?;
		Ok(Self(secret))
	}

	/// The confirmed secret, for the closing that derives from it.
	pub(crate) fn secret(&self) -> &HandshakeSecret {
		&self.0
	}

	/// Take the secret out, for the session that derives from it.
	pub(crate) fn into_secret(self) -> HandshakeSecret {
		self.0
	}

	/// The proof over `secret`, for a unit test of a step that takes the
	/// proof as its precondition.
	#[cfg(test)]
	pub(crate) fn assumed(secret: HandshakeSecret) -> Self {
		Self(secret)
	}
}

/// What a client flow holds from its opening to the agreement: the pending
/// half of its exchange. It also holds the one decision of the flow, which
/// handshake secret it derives from the exchange. That secret is the hybrid
/// secret with the base secret in the CMS flow, or the ephemeral secret in the
/// HPKE flow.
pub trait ClientAgreement<P: HandshakeProvider>: Sized {
	/// Completes the exchange with `server_ephemeral` and derives the handshake
	/// secret under `salt`. The value drops here, so each secret it holds is
	/// wiped in place with the call.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the exchange refuses the server's share.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn agree(
		self,
		server_ephemeral: &Distinct<ServerShare<P>>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError>;
}

/// What a server flow holds from its open of the opening to the reply: the
/// client's share `R`, and the one decision of the flow, which handshake
/// secret it derives from the exchange.
///
/// [`ServerPending::settle`] is the one settlement of the server's handshake
/// secret.
pub trait ServerAgreement<P: HandshakeProvider> {
	/// Answers `R` with the server's share, drawn from `rng`, beside the
	/// secret of the exchange.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the exchange refuses `R`.
	fn respond(&self, rng: &mut dyn CryptoRngCore) -> Result<(ServerShare<P>, ExchangeSecret), HandshakeError>;

	/// Derives the handshake secret of `shared` under `salt`: the hybrid secret
	/// with the base secret in the CMS flow, or the ephemeral secret in the
	/// HPKE flow. It moves `R` out for the pending server, which holds it to
	/// the closing, and the rest of this value drops here.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn settle(
		self,
		shared: ExchangeSecret,
		salt: KdfSalt<'_>,
	) -> Result<(HandshakeSecret, OpenedShare<ClientShare<P>>), HandshakeError>;
}

/// The client side of one protocol. It is sealed, so the flow markers of this
/// crate alone implement it.
///
/// Code over either protocol names it as the bound of a client
/// [`Handshake`](crate::transport::handshake::Handshake).
pub trait ClientFlow<P: HandshakeProvider>: ClientLegs<P> {}

impl<P: HandshakeProvider, F: ClientLegs<P>> ClientFlow<P> for F {}

/// The client legs of one protocol, which the orchestrator drives.
///
/// Both flows return the same intake shapes and refuse with the same
/// [`HandshakeError`] set, so the orchestrator runs one step order over
/// either. Both flows send the one closing this module builds.
pub trait ClientLegs<P: HandshakeProvider>: HandshakeFlow {
	/// What a client of this protocol is provisioned with.
	type Settings: MaybeSend + MaybeSync + 'static;
	/// Where the client learns the server identity.
	type Trust: ServerTrust<P>;
	/// What the flow keeps from the opening to read the reply against.
	type Opening: MaybeSend + MaybeSync + 'static;
	/// The secrets the flow holds from the opening to the agreement.
	type Pending: ClientAgreement<P> + MaybeSend + MaybeSync + 'static;

	/// The identity the client presents, when it holds one.
	fn identity(settings: &Self::Settings) -> Option<&SigningIdentity>;

	/// The trust that admits the server.
	fn server_trust(settings: &Self::Settings) -> &Self::Trust;

	/// Build the opening.
	///
	/// `server` is the admitted server when its identity is provisioned, and
	/// `()` when the reply names it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError`] -- the opening fails to build or encode.
	fn open(
		settings: &Self::Settings,
		server: <Self::Trust as ServerTrust<P>>::Provisioned,
		parts: OpeningParts<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<Opened<Self, P>, HandshakeError>;

	/// Decode the reply, bind its legs, and seal the transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the reply travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the reply carries an abort alert.
	/// - [`HandshakeError::MissingServerCertificate`] -- the reply carries no certificate its signer names.
	/// - [`HandshakeError`] -- the reply fails to decode, or a leg fails to bind.
	fn read_reply(
		opening: Self::Opening,
		settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError>;

	/// Verify the signature of the reply under the key of `server`, over the
	/// content and the transcript hash this flow signs, and return the proof
	/// that [`ServerConfirmed::confirm`] takes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the reply fails to
	///   verify, names another signer than `server`, or signs another
	///   transcript.
	/// - [`HandshakeError::DerError`] -- a signed attribute fails to encode.
	fn verify_reply(
		reply: &SignedData,
		server: &PeerCertificate<Signing<P>>,
		transcript_hash: &TranscriptHash,
	) -> Result<ReplyVerified, HandshakeError>;
}

/// The facts of a decoded opening, with what the flow keeps for its open.
pub struct OpeningIntake<F: ServerLegs<P>, P: HandshakeProvider> {
	/// The security profiles the client offers.
	pub security_offer: Option<SecurityOffer>,
	/// The transport capabilities the client offers.
	pub transport_offer: Option<TransportOffer>,
	/// What the server opens of the opening: the CMS content sealed to its
	/// static key, or the HPKE hello.
	pub sealed: F::Sealed,
}

/// What the orchestrator contributes to the reply.
pub struct ReplyParts<'a, P: HandshakeProvider> {
	/// The identity the server signs its reply under.
	pub identity: &'a SigningIdentity,
	/// The security profile the server selected.
	pub profile: RunnableProfile<P>,
	/// The transport capabilities the server accepted.
	pub transport_accept: Option<&'a TransportAccept>,
	/// The server's share of the exchange, which the reply signs.
	pub server_ephemeral: &'a ServerShare<P>,
	/// Whether the server demands a client identity.
	pub client_cert_required: bool,
}

/// A reply that awaits its signature and its receipt.
pub struct ReplyBinding<F: ServerLegs<P>, P: HandshakeProvider> {
	/// The hash of the sealed transcript.
	pub transcript_hash: TranscriptHash,
	/// The KDF salt of the flow.
	pub salt: Salt,
	/// The bytes the server signs.
	pub prehash: Vec<u8>,
	/// The reply, complete except for the signature and the receipt.
	pub draft: F::Draft,
}

/// What a server holds from its reply to the closing.
///
/// Both flows derive the handshake secret at the reply. The client's
/// agreement ephemeral `R` stays for the offer, which compares it with the key
/// of the certificate the closing presents. [`Self::settle`] is its one
/// constructor, for both flows.
pub struct ServerPending<P: HandshakeProvider> {
	/// The handshake secret, derived when the reply was built.
	secret: HandshakeSecret,
	/// The client's agreement ephemeral `R`, the value the agreement read.
	client_ephemeral: OpenedShare<ClientShare<P>>,
}

impl<P: HandshakeProvider> ServerPending<P> {
	/// Settle the agreement `opened` makes from `shared`, the secret of its
	/// exchange, under the salt of `terms`, and keep `R` for the offer.
	/// `opened` and `shared` drop here, so each secret they hold is wiped with
	/// the call.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	pub(crate) fn settle(
		opened: impl ServerAgreement<P>,
		shared: ExchangeSecret,
		terms: &Terms<P>,
	) -> Result<Self, HandshakeError> {
		let (secret, client_ephemeral) = opened.settle(shared, terms.kdf_salt()?)?;
		Ok(Self { secret, client_ephemeral })
	}

	/// Attach the server Finished to `reply`: the MAC under the secret this
	/// value holds over the transcript hash of `terms` and the octets of the
	/// reply's one signature, as an unsigned attribute of its `SignerInfo`
	/// (RFC 9846 §4.5.3).
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the server's `MacKey`.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- `reply` does not have exactly one signer.
	/// - [`HandshakeError::DerError`] -- the attribute or the reply fails to encode.
	pub(crate) fn finish_reply(
		&self,
		reply: Signed<SignedData>,
		terms: &Terms<P>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let finished = terms.server_confirmation(&self.secret, &reply)?;
		let finished = Attribute::try_from(HandshakeAttribute::encode(&finished)?)?;
		let reply = reply.with_unsigned_attribute(finished)?;
		let reply = WireDer::signed(reply)?;
		Ok(HandshakeMessage::SignedData(Box::new(reply)))
	}
}

/// The server side of one protocol. It is sealed, so the flow markers of this
/// crate alone implement it.
///
/// Code over either protocol names it as the bound of a server
/// [`Handshake`](crate::transport::handshake::Handshake).
pub trait ServerFlow<P: HandshakeProvider>: ServerLegs<P> {}

impl<P: HandshakeProvider, F: ServerLegs<P>> ServerFlow<P> for F {}

/// The server legs of one protocol, which the orchestrator drives.
///
/// Both flows return the same intake shapes and refuse with the same
/// [`HandshakeError`] set, so the orchestrator runs one step order over
/// either. The open of the opening is asynchronous, so a static-key step can
/// run through the backend of the server's key-agreement identity and the
/// private key can stay behind an external boundary.
pub trait ServerLegs<P: HandshakeProvider>: HandshakeFlow {
	/// What a server of this protocol is provisioned with.
	type Settings: MaybeSend + MaybeSync + 'static;
	/// What the server signs and agrees with: one signing identity for the
	/// HPKE flow, and the signing and key-agreement pair for the CMS flow.
	type Identity: ServerIdentity;
	/// What the opening sealed to the static key.
	type Sealed: MaybeSend + 'static;
	/// What the flow holds from the static open to the reply.
	type Opened: ServerAgreement<P> + MaybeSend + 'static;
	/// The reply that awaits its signature and its receipt.
	type Draft: MaybeSend + 'static;

	/// Decode the opening, and open the transcript over it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the opening travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the CMS opening carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or the abort alert repeats.
	/// - [`HandshakeError::KeyExchange`] -- the HPKE client share is no share of the exchange.
	/// - [`HandshakeError`] -- the opening fails to decode.
	fn read_opening(
		settings: &Self::Settings,
		opening: HandshakeMessage,
	) -> Result<OpeningIntake<Self, P>, HandshakeError>;

	/// Open what the opening sealed to a static key of `identity`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::Envelope`] -- the CMS opening fails to open: its
	///   recipient, its `ukm`, its key, or its tag is refused.
	/// - [`HandshakeError::InvalidKeySize`] -- the opened base secret is not 32 bytes.
	/// - [`HandshakeError::KeyExchange`] -- the client's agreement key is no share of the exchange.
	/// - [`HandshakeError::DerError`] -- the opened content fails to decode.
	fn open_opening<'a>(
		sealed: Self::Sealed,
		identity: &'a Self::Identity,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>>;

	/// Bind the reply legs into the transcript, seal it, and name the bytes
	/// the server signs.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError`] -- a leg fails to encode or bind.
	fn bind_reply(
		opened: &mut Self::Opened,
		settings: &Self::Settings,
		parts: ReplyParts<'_, P>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<ReplyBinding<Self, P>, HandshakeError>;

	/// Encode the reply with the server signature and the receipt artifact,
	/// up to the server Finished that [`ServerPending::finish_reply`]
	/// attaches.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the reply fails to encode.
	fn encode_reply(
		draft: Self::Draft,
		signature: Vec<u8>,
		artifact: Option<&Signed<SignedData>>,
	) -> Result<Signed<SignedData>, HandshakeError>;
}

impl FinishedRole {
	/// Draft the Finished that `identity` signs for this role over
	/// `transcript_hash` and the certificate of `identity`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the certificate or a signed attribute fails to encode.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
	pub(crate) fn draft<P: HandshakeProvider>(
		self,
		identity: &SigningIdentity,
		transcript_hash: &TranscriptHash,
	) -> Result<FinishedDraft, HandshakeError> {
		let content = self.content::<P::Digest>(transcript_hash, identity.certificate())?;
		let signer = identity.draft(SignedContent::data(&content))?;
		Ok(FinishedDraft { content, signer })
	}

	/// Verify that `finished` is signed under the key of `certificate`, which
	/// its one `SignerInfo` names, and that its content is this role's over
	/// `transcript_hash` and `certificate`.
	///
	/// The `SignedData` carries the signed attributes of the CMS signer over
	/// content of type `id-data`. A Finished whose content names the other
	/// role is a reflected Finished.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the Finished
	///   carries another number of signers, fails the signer's checks, or
	///   signs another role, another transcript, or another certificate.
	/// - [`HandshakeError::DerError`] -- the certificate or a signed attribute fails to encode.
	/// - [`HandshakeError::CertificateValidationError`] -- the key identifier fails to decode.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
	pub(crate) fn verify<P: HandshakeProvider>(
		self,
		finished: &SignedData,
		certificate: &PeerCertificate<Signing<P>>,
		transcript_hash: &TranscriptHash,
	) -> Result<(), HandshakeError> {
		// The Finished covers a transcript hash, which is fresh for each
		// handshake, so its verified signature is the key of no ledger and
		// drops here.
		let content = finished.content(DATA)?;
		CmsSigner::verify_sole_signer::<P>(finished, certificate, SignedContent::data(content)).map(drop)?;

		let expected = self.content::<P::Digest>(transcript_hash, certificate.certificate())?;
		let content_matches: bool = content.ct_eq(expected.as_slice()).into();
		if !content_matches {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		Ok(())
	}
}

/// A Finished up to its signature: the content it signs, and its
/// `SignerInfo`, complete up to the signature over that content.
pub(crate) struct FinishedDraft {
	/// The role's domain label, the transcript hash, and for the client
	/// Finished the digest of its certificate.
	content: Vec<u8>,
	/// The Finished's `SignerInfo`, complete up to its signature.
	signer: SignerInfoDraft,
}

impl FinishedDraft {
	/// The bytes the signer's key signs.
	pub(crate) fn prehash(&self) -> &[u8] {
		self.signer.prehash()
	}

	/// Build the Finished: the `SignedData` over the content, with
	/// `signature` completing its `SignerInfo`, `unsigned_attrs` attached to
	/// it, and `certificates` as its certificate set.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the content, a SET, or the signature fails to encode.
	pub(crate) fn finish(
		self,
		signature: Vec<u8>,
		unsigned_attrs: Attributes,
		certificates: Option<CertificateSet>,
	) -> Result<Signed<SignedData>, HandshakeError> {
		let Self { content, signer } = self;
		let signer_info = signer.complete(signature, Some(unsigned_attrs))?;

		Ok(CmsSigner::signed_data(
			SignedContent::data(&content),
			signer_info,
			certificates,
		)?)
	}
}

/// The client Finished: the `SignedData` in which the client signs its role
/// and the transcript hash, as the proof that it holds the key of the
/// certificate it presents.
pub struct ClientFinished(SignedData);

impl ClientFinished {
	/// Verify that the one signer names `identity` and verifies under its
	/// key, and that the signed content is the client role over the sealed
	/// transcript hash of `terms`.
	///
	/// # Errors
	///
	/// - The errors of [`FinishedRole::verify`].
	pub(crate) fn verify<P: HandshakeProvider>(
		self,
		identity: &PeerCertificate<Signing<P>>,
		terms: &Terms<P>,
	) -> Result<(), HandshakeError> {
		FinishedRole::Client.verify::<P>(&self.0, identity, terms.transcript_hash())
	}
}

/// The identity a client offers, with the issuers it presents above it and
/// the client Finished that proves it holds the key, or none.
///
/// Its constructors are private to the closing, so an offer exists only where
/// a closing opened. [`Self::new`] refuses an identity whose key collapses the
/// client ephemeral, so no offer exists for that client.
pub struct Offer<P: HandshakeProvider>(Option<Offered<P>>);

/// What a client that presents an identity offers.
struct Offered<P: HandshakeProvider> {
	/// The certificate the client Finished's `sid` names.
	identity: PeerCertificate<Signing<P>>,
	/// The issuers above it that the client Finished presents, the top first.
	issuers: PresentedIssuers,
	/// The client Finished, which proves the client holds the key.
	finished: ClientFinished,
}

impl<P: HandshakeProvider> Offer<P> {
	/// The offer of a client that presents no identity.
	fn anonymous() -> Self {
		Self(None)
	}

	/// The offer of `identity` under `issuers`, proven by `finished`.
	///
	/// A server learns its client's static key only after the agreement, so
	/// the admission of `ephemeral`, the share the server agreed with, lives
	/// here: it MUST be distinct from the key of `identity`, or the agreement
	/// collapses into the static one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the ephemeral collapses into the key of `identity`.
	fn new(
		identity: PeerCertificate<Signing<P>>,
		issuers: PresentedIssuers,
		finished: ClientFinished,
		ephemeral: OpenedShare<ClientShare<P>>,
	) -> Result<Self, HandshakeError> {
		let statics = PeerStatics::<Exchange<P>>::of(identity.certificate(), None);
		statics.admit_client(ephemeral)?;

		Ok(Self(Some(Offered { identity, issuers, finished })))
	}

	/// The identity and its proof, for the admission that verifies them.
	pub(crate) fn into_identity(self) -> Option<(PeerCertificate<Signing<P>>, ClientFinished)> {
		self.0.map(|Offered { identity, finished, .. }| (identity, finished))
	}

	/// The certificate of the identity beside the issuers the client presents
	/// above it, for the policy that admits them.
	pub(crate) fn presented(&self) -> Option<(&PeerCertificate<Signing<P>>, &PresentedIssuers)> {
		self.0.as_ref().map(|Offered { identity, issuers, .. }| (identity, issuers))
	}
}

/// What the orchestrator contributes to the closing.
pub(crate) struct ClosingParts<'a, P: HandshakeProvider> {
	/// The hash of the sealed transcript.
	pub(crate) transcript_hash: &'a TranscriptHash,
	/// The DER of the `AuthEnvelopedData` that seals the receipt
	/// countersignature under the handshake secret.
	pub(crate) sealed_ack: Option<Vec<u8>>,
	/// The proof that the client derived the handshake secret.
	pub(crate) confirmation: KeyConfirmation,
	/// The single-use seal of the closing, keyed by the handshake secret.
	pub(crate) sealer: Sealer<P>,
}

/// The client Finished of a closing, up to its signature, beside the identity
/// whose key signs it and whose presented certificates it carries.
struct ClientFinishedDraft<'a> {
	/// The identity of the client.
	identity: &'a SigningIdentity,
	/// The Finished over the transcript hash and the identity's certificate.
	draft: FinishedDraft,
}

/// The closing of either flow, up to the signature of its client Finished.
///
/// The key-confirmation tag and the sealed acknowledgement travel as
/// attributes inside the seal: unsigned attributes of the client Finished,
/// or the whole content of an anonymous closing. [`Self::seal`] signs the
/// Finished the draft holds and seals either form under the closing key.
pub(crate) struct ClosingDraft<'a, P: HandshakeProvider> {
	/// The key-confirmation tag and the sealed acknowledgement.
	attributes: Attributes,
	/// The client Finished, when the client presents an identity.
	finished: Option<ClientFinishedDraft<'a>>,
	/// The single-use seal of the closing.
	sealer: Sealer<P>,
}

impl<'a, P: HandshakeProvider> ClosingDraft<'a, P> {
	/// Bind the closing of `identity`, or of an anonymous client when it is
	/// `None`, and draft its client Finished.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- an attribute or the certificate fails to encode.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the provider digest is not 32 to 64 bytes wide.
	pub(crate) fn bind(
		identity: Option<&'a SigningIdentity>,
		parts: ClosingParts<'_, P>,
	) -> Result<Self, HandshakeError> {
		let ClosingParts { transcript_hash, sealed_ack, confirmation, sealer } = parts;

		// 1. Carry the tag and the countersignature as attributes. The
		//    handshake secret binds both: it derives the tag over the
		//    transcript hash, and it seals the other.
		let mut attributes = vec![Attribute::try_from(HandshakeAttribute::encode(&confirmation)?)?];
		if let Some(sealed_ack) = sealed_ack {
			let acknowledgement = HandshakeAttribute::encode(&OctetString::new(sealed_ack)?)?;
			attributes.push(Attribute::try_from(acknowledgement)?);
		}

		let attributes = Attributes::try_from(attributes)?;

		// 2. Draft the client Finished of an identity, over the transcript
		//    hash and the identity's certificate.
		let finished = match identity {
			Some(identity) => {
				let draft = FinishedRole::Client.draft::<P>(identity, transcript_hash)?;
				Some(ClientFinishedDraft { identity, draft })
			}
			None => None,
		};

		Ok(Self { attributes, finished, sealer })
	}

	/// Sign the client Finished when the closing carries one, and seal the
	/// closing under the closing key.
	///
	/// A Finished seals as content of type `id-signedData`, and an anonymous
	/// closing as its attribute set of type `id-data`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyError`] -- the key provider failed to sign the Finished.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the key provider returned no DER signature.
	/// - [`HandshakeError::SealedClosing`] -- the envelope refused to seal the closing.
	/// - [`HandshakeError::SealedFrame`] -- the closing exceeds the frame.
	/// - [`HandshakeError::DerError`] -- the closing fails to encode.
	pub(crate) async fn seal(self) -> Result<HandshakeMessage, HandshakeError> {
		let Self { attributes, finished, sealer } = self;
		let sealed = match finished {
			Some(ClientFinishedDraft { identity, draft }) => {
				let signature = identity.sign_prehash(draft.prehash()).await?;
				let certificates = identity.presented().set();
				let finished = draft.finish(signature, attributes, Some(certificates))?;
				sealer.seal(SIGNED_DATA, finished.to_der()?)?
			}
			None => sealer.seal(DATA, attributes.to_der()?)?,
		};

		HandshakeMessage::try_from(sealed)
	}
}

/// A decoded closing of either flow, which the closing key opens.
pub(crate) struct Closing(WireDer<AuthEnvelopedData>);

impl Closing {
	/// Decode the closing, and refuse one that carries an abort alert. The
	/// seal covers every other part of the closing.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the closing travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the closing carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- the abort alert repeats.
	pub(crate) fn read(message: HandshakeMessage) -> Result<Self, HandshakeError> {
		let sealed = message.auth_enveloped()?;
		sealed.value().unauth_attrs.refuse_alert()?;
		Ok(Self(sealed))
	}

	/// Open the closing under the closing key of the secret `pending` holds,
	/// read its tag and its acknowledgement, and build the [`Offer`] of a
	/// certificate admitted for the client's key purpose, `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the closing key.
	/// - The errors of [`ClosingContent::open`].
	/// - The errors of [`ClosingContent::confirmation`].
	/// - The errors of [`ClosingContent::into_offer`].
	pub(crate) async fn open<P: HandshakeProvider>(
		self,
		pending: ServerPending<P>,
		terms: &Terms<P>,
		purpose: ObjectIdentifier,
	) -> Result<ClosingOpened<P>, HandshakeError> {
		let ServerPending { secret, client_ephemeral } = pending;

		// 1. Open the content under the closing key of the secret, in the form its content type names.
		let sealer = terms.sealer(&secret, SecretSeal::Closing)?;
		let content = ClosingContent::open(sealer, self.0).await?;

		// 2. Read the key-confirmation tag, which is mandatory, and the sealed receipt acknowledgement.
		let (confirmation, receipt_ack) = content.confirmation()?;

		// 3. Build the offer, which compares `R` with the key of the certificate the Finished names.
		let offer = content.into_offer(client_ephemeral, purpose)?;
		Ok(ClosingOpened { secret, confirmation, receipt_ack, offer })
	}
}

/// The content of an opened closing, in the form its content type names.
///
/// [`Self::open`] is its one constructor, and the one branch on the content
/// type that the closing's `authAttrs` authenticate. [`Self::confirmation`]
/// is the one reader of the key-confirmation tag and the acknowledgement of
/// either form.
pub(crate) enum ClosingContent {
	/// The client Finished of a client that presents an identity, beside the
	/// certification path its signer presents, read from the bytes the
	/// Finished arrived as.
	Finished(SignedData, Option<Box<PresentedPath>>),
	/// The attribute set of an anonymous client.
	Anonymous(Attributes),
}

impl ClosingContent {
	/// Open `closing` under `sealer`, and decode its content as the form its
	/// content type names. Any other type is refused before the closing key
	/// runs, and the tag authenticates the type that opens:
	///
	/// - `id-signedData`: the client Finished, held to the cap of a presented
	///   set, then decoded as a [`Signed`] `SignedData`.
	/// - `id-data`: the attribute set of an anonymous client, decoded once the
	///   CMS rules of the admission walk admit it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the content type is not `id-signedData` or `id-data`.
	/// - [`HandshakeError::SealedClosing`] -- the closing fails to open: its
	///   envelope, its key, its tag, or its transcript is refused.
	/// - [`HandshakeError::SealedFrame`] -- the opened frame is malformed.
	/// - [`HandshakeError::DerError`] -- the content fails to decode as its
	///   form or to pass the walk, or the Finished carries a second
	///   `certificates` field or a certificate in another encoding than its
	///   DER.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the Finished does not have exactly one signer.
	/// - [`HandshakeError::CertificateValidationError`] -- the Finished
	///   presents more than [`MAX_PRESENTED_PATH`] certificates, or the walk
	///   refuses the path.
	///
	/// [`MAX_PRESENTED_PATH`]: crate::constants::MAX_PRESENTED_PATH
	async fn open<P: HandshakeProvider>(
		sealer: Sealer<P>,
		closing: WireDer<AuthEnvelopedData>,
	) -> Result<Self, HandshakeError> {
		let content_type = closing.value().auth_encrypted_content_info.content_type;
		let decode: fn(&[u8]) -> Result<Self, HandshakeError> = match content_type {
			// The path moves out of the Finished, so the session keeps the
			// certificate past the decoded Finished without a copy.
			SIGNED_DATA => |der| {
				ArrivedCertificates::bound_presented(der)?;
				let finished = Signed::<SignedData>::from_der(der)?;
				let (finished, path) = finished.take_signer_path()?;
				Ok(Self::Finished(finished, path.map(Box::new)))
			},
			DATA => |der| Ok(Self::Anonymous(DerAdmission::Cms.decode(der)?)),
			_ => return Err(HandshakeError::UnexpectedContainer),
		};

		let content = sealer.open(closing, content_type).await?;
		content.with(|der| decode(der))
	}

	/// The key-confirmation tag and the sealed acknowledgement, read once
	/// from the attributes of either form: the unsigned attributes of the
	/// client Finished, or the attribute set of an anonymous closing.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the closing carries no tag.
	/// - [`HandshakeError::DuplicateAttribute`] -- the tag or the acknowledgement repeats.
	/// - [`HandshakeError::DerError`] -- the tag is not an OCTET STRING of 32
	///   to 64 bytes, or the acknowledgement is no OCTET STRING.
	fn confirmation(&self) -> Result<(KeyConfirmation, Option<Vec<u8>>), HandshakeError> {
		let attributes: &dyn HandshakeAttributes = match self {
			Self::Finished(finished, _) => finished,
			Self::Anonymous(attributes) => attributes,
		};

		let tag = attributes.find_unsigned_attr(KeyConfirmation::OID)?;
		let confirmation = tag.ok_or(HandshakeError::MissingAttribute)?.decode::<KeyConfirmation>()?;
		let acknowledgement = attributes.find_unsigned_attr(RECEIPT_ACK)?;
		let acknowledgement = acknowledgement.map(|attribute| attribute.decode::<OctetString>()).transpose()?;
		Ok((confirmation, acknowledgement.map(OctetString::into_bytes)))
	}

	/// The offer this closing makes: none for an anonymous closing, and for a
	/// client Finished the certificate its signer names, admitted for signing
	/// under `purpose` and compared with `client_ephemeral`, beside the
	/// issuers above it that the Finished presents.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingClientCertificate`] -- the Finished has no certificate its signer names.
	/// - [`HandshakeError::CertificateValidationError`] -- the signing use or
	///   `purpose` refuses the certificate.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- `client_ephemeral`
	///   collapses into the key of the certificate.
	fn into_offer<P: HandshakeProvider>(
		self,
		client_ephemeral: OpenedShare<ClientShare<P>>,
		purpose: ObjectIdentifier,
	) -> Result<Offer<P>, HandshakeError> {
		let Self::Finished(finished, path) = self else {
			return Ok(Offer::anonymous());
		};

		let (certificate, issuers) = path.ok_or(HandshakeError::MissingClientCertificate)?.into_parts();
		let identity = PeerCertificate::parse(certificate, purpose)?;
		Offer::new(identity, issuers, ClientFinished(finished), client_ephemeral)
	}
}

/// What the server holds once the closing is opened.
///
/// The fields stay private to the closing, and [`Self::confirm`] is the one
/// way out, so the offer reaches admission only after the key-confirmation tag
/// verified.
pub(crate) struct ClosingOpened<P: HandshakeProvider> {
	/// The handshake secret both sides derived.
	secret: HandshakeSecret,
	/// The key-confirmation tag the closing carried.
	confirmation: KeyConfirmation,
	/// The DER of the envelope that seals the receipt countersignature under
	/// the handshake secret.
	receipt_ack: Option<Vec<u8>>,
	/// The identity the client offers.
	offer: Offer<P>,
}

impl<P: HandshakeProvider> ClosingOpened<P> {
	/// Verify the key-confirmation tag against the secret, and release the
	/// offer.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the client derived
	///   another secret or confirmed another transcript.
	pub(crate) fn confirm(self, terms: &Terms<P>) -> Result<ConfirmedClosing<P>, HandshakeError> {
		let Self { secret, confirmation, receipt_ack, offer } = self;
		let secret = terms.confirm(secret, &confirmation)?;
		Ok(ConfirmedClosing { secret, receipt_ack, offer })
	}
}

/// A closing whose key-confirmation tag verified.
///
/// Its secret is a [`ConfirmedSecret`], which only the check of the tag
/// yields, so the offer it holds passed that check.
pub(crate) struct ConfirmedClosing<P: HandshakeProvider> {
	/// The handshake secret the tag confirmed.
	pub(crate) secret: ConfirmedSecret,
	/// The DER of the envelope that seals the receipt countersignature under
	/// the handshake secret.
	pub(crate) receipt_ack: Option<Vec<u8>>,
	/// The identity the client offers.
	pub(crate) offer: Offer<P>,
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::asn1::admission::fixtures::tlv;
	use crate::crypto::exchange::{EcdheShare, KeyExchangeError, KeyShare};
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::sign::PresentedPath;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::{Any, ErrorKind, Tag, TagNumber};
	use crate::oids::HANDSHAKE_ABORT_ALERT;
	use crate::testing::{Aes256Sha3_512Provider, TestCmsServer, TestResult};
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::tests::{
		acknowledgement, build_test_client_finished, create_default_test_profile, create_test_certificate,
		create_test_server, create_test_signed_data, finished_attribute, fixture_confirmation, fixture_ephemeral,
		fixture_sealer, fixture_transcript_hash, foreign_profile, foreign_transcript_hash, negated, off_curve_point,
		over_each_flow, put_off_curve_key, replied, same_key_twin, sealed_finished, two_valued_name,
		with_certificate_set, with_unsigned_attrs, without_attribute, TestFlow,
	};
	use crate::transport::handshake::{Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication};
	use crate::x509::Certificate;

	/// A client certificate admitted for signing under the house provider.
	type HouseSigner = PeerCertificate<Signing<DefaultCryptoProvider>>;

	/// The client identity of the fixed key of seed `0xb4`, beside its static
	/// key.
	fn identity() -> (HouseSigner, PublicKey<Secp256k1>) {
		let client = create_test_certificate(0xb4);
		let static_key = PublicKey::from(client.signing_key.verifying_key());
		let identity = PeerCertificate::parse(client.certificate, KeyPurposes::HOUSE.client);
		(identity.expect("the test certificate holds a point"), static_key)
	}

	/// A client Finished the offer holds for admission, which verifies it, so
	/// any signed content serves here.
	fn finished() -> ClientFinished {
		ClientFinished(create_test_signed_data(b"client finished"))
	}

	/// The offer of `identity`, which presents its certificate alone, beside
	/// `ephemeral`.
	fn offer_of(
		identity: HouseSigner,
		ephemeral: &PublicKey<Secp256k1>,
	) -> Result<Offer<DefaultCryptoProvider>, HandshakeError> {
		let leaf = Certificate::clone(identity.certificate());
		let path = PresentedPath::walk(leaf, Vec::new()).expect("a certificate alone is a path");
		let (_, issuers) = path.into_parts();
		let opened = OpenedShare::fixture(EcdheShare::from(*ephemeral));
		Offer::new(identity, issuers, finished(), opened)
	}

	/// An offer whose ephemeral differs from the key of its identity holds
	/// that identity.
	#[test]
	fn an_offer_of_a_distinct_ephemeral_holds_its_identity() -> TestResult {
		let (identity, _) = identity();
		let expected = Arc::clone(identity.certificate());
		let offer = offer_of(identity, &fixture_ephemeral(0x05).public_key())?;

		let held = offer.into_identity().map(|(identity, _)| Arc::clone(identity.certificate()));
		assert_eq!(held, Some(expected));
		Ok(())
	}

	// An offer refuses an ephemeral of the key of its identity, in each form
	// whose agreement collapses into the static one.
	crate::tb_cases! {
		fn an_offer_refuses_an_ephemeral_of_the_identity_key(form: fn(&PublicKey<Secp256k1>) -> PublicKey<Secp256k1>) {
			let (identity, static_key) = identity();
			let refused = offer_of(identity, &form(&static_key));
			assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
		}
		cases {
			itself => |key| *key,
			/// ECDH keeps the x-coordinate alone, so the negation of the
			/// identity key collapses the agreement as the key itself does.
			negation => negated,
		}
	}

	/// A client Finished of `identity` over `transcript_hash`, signed and
	/// built as the closing builds it, with its key-confirmation tag.
	async fn client_finished(identity: &SigningIdentity, transcript_hash: &TranscriptHash) -> Signed<SignedData> {
		let draft = FinishedRole::Client.draft::<DefaultCryptoProvider>(identity, transcript_hash);
		let draft = draft.expect("the Finished drafts");
		let signature = identity.sign_prehash(draft.prehash()).await.expect("the client key signs");
		let attributes = Attributes::try_from(vec![finished_attribute(&fixture_confirmation())]);
		let attributes = attributes.expect("one attribute is a SET");
		let certificates = identity.presented().set();

		let finished = draft.finish(signature, attributes, Some(certificates));
		finished.expect("the Finished assembles")
	}

	/// A client Finished verifies under the certificate it carries.
	#[tokio::test]
	async fn a_client_finished_verifies_under_the_certificate_it_carries() -> TestResult {
		let client = create_test_certificate(0xb5);
		let transcript_hash = fixture_transcript_hash();
		let finished = client_finished(&client.signing_identity(), &transcript_hash).await;
		let carried = HouseSigner::parse(client.certificate, KeyPurposes::HOUSE.client)?;

		FinishedRole::Client.verify::<DefaultCryptoProvider>(&finished, &carried, &transcript_hash)?;
		Ok(())
	}

	/// A client Finished binds the digest of the certificate it carries, so
	/// it verifies under no other certificate of its key, as a TLS 1.3
	/// signature covers the Certificate (RFC 9846 §4.5.2).
	#[tokio::test]
	async fn a_client_finished_verifies_under_no_other_certificate_of_its_key() -> TestResult {
		let client = create_test_certificate(0xb6);
		let transcript_hash = fixture_transcript_hash();
		let finished = client_finished(&client.signing_identity(), &transcript_hash).await;
		let twin = HouseSigner::parse(same_key_twin(&client), KeyPurposes::HOUSE.client)?;

		let refused = FinishedRole::Client.verify::<DefaultCryptoProvider>(&finished, &twin, &transcript_hash);
		assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// The share of `point` as the octets an OCTET STRING carrier holds.
	fn share_of(point: PublicKey<Secp256k1>) -> Vec<u8> {
		EcdheShare::from(point).to_octets()
	}

	/// The abort alert of `code`, as a peer attaches it outside a seal or a
	/// signature.
	fn abort_alert(code: u8) -> Attribute {
		let value = Any::encode_from(&code).expect("an alert code encodes");
		let alert = HandshakeAttribute::new(HANDSHAKE_ABORT_ALERT, value);
		Attribute::try_from(alert).expect("the alert is an attribute")
	}

	/// What a client of flow `F` that offered `offer` answers to the reply
	/// that the key of `server` signs by hand, which selects `accept` and
	/// carries `server_ephemeral` as the octets of the server share.
	async fn answer_to_hand_built_reply<F: TestFlow>(
		server: &TestCmsServer,
		offer: Option<SecurityOffer>,
		accept: Option<SecurityProfileDesc>,
		server_ephemeral: impl AsRef<[u8]>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let mut config = F::client(server, &create_test_certificate(0xb7));
		config.security_offer = offer;

		let mut client = Handshake::client(config);
		let opening = client.start().expect("a fresh client builds its opening");
		let reply = F::hand_built_reply(server, &opening, accept, server_ephemeral);
		client.respond(reply).await
	}

	/// The client refuses a validly signed reply that selects no profile, so
	/// no session forms without an agreed profile.
	async fn a_reply_without_a_security_accept_is_refused<F: TestFlow>() -> TestResult {
		let server = create_test_server();
		let share = share_of(fixture_ephemeral(0x31).public_key());

		let refusal = answer_to_hand_built_reply::<F>(&server, None, None, share).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	/// The client refuses a validly signed reply that selects a profile
	/// outside its offer.
	async fn a_client_refuses_a_profile_it_did_not_offer<F: TestFlow>() -> TestResult {
		let server = create_test_server();
		let offer = SecurityOffer::new(vec![foreign_profile()]);
		let share = share_of(fixture_ephemeral(0x32).public_key());
		let accept = Some(create_default_test_profile());

		let refusal = answer_to_hand_built_reply::<F>(&server, Some(offer), accept, share).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	/// The client refuses, at the parse, a validly signed server ephemeral
	/// whose x-coordinate lies off the curve, before any scalar
	/// multiplication.
	async fn an_off_curve_server_ephemeral_is_refused<F: TestFlow>() -> TestResult {
		let server = create_test_server();
		let accept = Some(create_default_test_profile());

		let refusal = answer_to_hand_built_reply::<F>(&server, None, accept, off_curve_point()).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))));
		Ok(())
	}

	/// The client refuses a validly signed server ephemeral that is the
	/// server's own static key, so the agreement cannot collapse into the
	/// static one.
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused<F: TestFlow>() -> TestResult {
		let server = create_test_server();
		let share = share_of(PublicKey::from(server.signing_key.verifying_key()));
		let accept = Some(create_default_test_profile());

		let refusal = answer_to_hand_built_reply::<F>(&server, None, accept, share).await;
		assert!(matches!(refusal, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A server ephemeral swapped for another point of the curve after the
	/// server signed its reply changes what the signature covers, so the
	/// signature fails before any agreement.
	async fn a_tampered_server_ephemeral_fails_the_reply_signature<F: TestFlow>() -> TestResult {
		let (mut client, reply) = replied::<F>(&create_test_server()).await;
		let tampered = F::with_server_ephemeral(&reply, share_of(fixture_ephemeral(0x33).public_key()));

		let refusal = client.respond(tampered).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A reply whose accept was stripped after the server signed it fails its
	/// signature. The client verifies the signature before it reads the
	/// selection, so the refusal names the signature and not the selection.
	async fn a_stripped_accept_fails_the_reply_signature<F: TestFlow>() -> TestResult {
		let (mut client, reply) = replied::<F>(&create_test_server()).await;
		let stripped = F::without_accept(&reply);

		let refusal = client.respond(stripped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// The client refuses a reply whose signer carries an abort alert among
	/// its unsigned attributes.
	async fn a_reply_with_an_abort_alert_is_refused<F: TestFlow>() -> TestResult {
		let (mut client, reply) = replied::<F>(&create_test_server()).await;
		let alerted = reply.with_unsigned(|carried| [carried, vec![abort_alert(4)]].concat());

		let refusal = client.respond(alerted).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::AbortReceived(HandshakeAlert::DecryptFail))
		));
		Ok(())
	}

	/// The client refuses a reply whose signature verifies but that carries
	/// no server Finished, before it builds any closing, and admits no
	/// further step.
	async fn a_reply_without_a_server_finished_is_refused_before_the_closing<F: TestFlow>() -> TestResult {
		let (mut client, reply) = replied::<F>(&create_test_server()).await;
		let unconfirmed = reply.with_unsigned(|carried| without_attribute(carried, KeyConfirmation::OID));

		let refusal = client.respond(unconfirmed).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// The reply carries the server's signing certificate, and its one signer
	/// names that certificate (RFC 5652 §5.1, §5.3).
	async fn the_reply_carries_the_certificate_its_signer_names<F: TestFlow>() -> TestResult {
		let server = create_test_server();
		let (_, reply) = replied::<F>(&server).await;

		let signed_data = reply.signed()?;
		let named = signed_data.value().signer_certificate()?;
		assert_eq!(named, Some(&server.signing));
		Ok(())
	}

	/// The client refuses a reply without the certificate its signer names,
	/// because it names no server to admit.
	async fn a_reply_without_its_certificate_is_refused<F: TestFlow>() -> TestResult {
		let (mut client, reply) = replied::<F>(&create_test_server()).await;
		let bare = with_certificate_set(reply.signed()?.into_value(), None);

		let refusal = client.respond(HandshakeMessage::try_from(bare)?).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
		Ok(())
	}

	/// A reply whose certificate carries its RDN values out of DER order,
	/// which would decode to the same value, is refused as it arrives under
	/// its `[3]` envelope, before the client binds a byte of it (X.690 §11.6,
	/// CWE-345).
	async fn a_reply_whose_certificate_bytes_were_reordered_is_refused<F: TestFlow>() -> TestResult {
		let (_, reply) = replied::<F>(&TestCmsServer::named(two_valued_name())).await;
		let envelope_tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		let arrived = tlv(envelope_tag, &reply.with_rdn_values_swapped());

		let refused = TransportEnvelope::from_der(&arrived).err().map(|error| error.kind());
		assert_eq!(refused, Some(ErrorKind::SetOrdering));
		Ok(())
	}

	/// A handshake under a provider whose digest is SHA3-512 seals the whole
	/// 64-byte digest as its transcript hash, and its closing confirms and
	/// opens under that hash.
	async fn a_sha3_512_profile_carries_a_64_byte_transcript_hash<F: TestFlow>() -> TestResult {
		let agreed = F::agreed_under::<Aes256Sha3_512Provider>().await;
		assert_eq!(agreed.transcript_hash.as_bytes().len(), 64);
		Ok(())
	}

	/// A handshake under the house provider of the hybrid key exchange runs to
	/// its closing under the identifier of the hybrid.
	#[cfg(feature = "preview-pqc")]
	async fn the_preview_provider_runs_the_flow<F: TestFlow>() -> TestResult {
		use crate::crypto::profiles::PreviewPqcProvider;
		use crate::oids::KEM_SECP256K1_ML_KEM_768;

		let agreed = F::agreed_under::<PreviewPqcProvider>().await;
		assert_eq!(agreed.profile.key_exchange, Some(KEM_SECP256K1_ML_KEM_768));
		Ok(())
	}

	/// A mutual server admits the hand-built identified closing and records
	/// its certificate, so each refusal of that fixture comes from the one
	/// part its test changes.
	async fn a_hand_built_identified_closing_is_admitted<F: TestFlow>() -> TestResult {
		let client = create_test_certificate(0xb8);
		let mut awaiting = F::awaiting_closing(PeerAuthentication::mutual_by_expiry(), fixture_ephemeral(0x41)).await;
		let finished = awaiting.finished_of(&client);

		awaiting.finish(&finished).await?;

		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		assert_eq!(awaiting.server.peer_certificate(), Some(&client.certificate));
		Ok(())
	}

	/// The server refuses, at the tag, a closing that opens under the right
	/// key but confirms another secret, and admits no further step. The
	/// Finished signature verifies, so the tag is what refuses it.
	async fn a_closing_that_confirms_another_secret_is_refused<F: TestFlow>() -> TestResult {
		let client = create_test_certificate(0xb9);
		let mut awaiting = F::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x42)).await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &fixture_confirmation());
		let closing = awaiting.sealed(&finished);

		let refused = awaiting.server.finish(closing.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);

		let replayed = awaiting.server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A server that demands no identity still verifies the client Finished
	/// of an offered identity, so a Finished over another transcript, as from
	/// another handshake, cannot close this one.
	async fn a_client_finished_over_another_transcript_is_refused<F: TestFlow>() -> TestResult {
		let client = create_test_certificate(0xba);
		let mut awaiting = F::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x43)).await;
		let foreign = build_test_client_finished(&client, &foreign_transcript_hash(), &awaiting.tag());

		let refusal = awaiting.finish(&foreign).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// What a server of flow `F` under `peer_authentication` answers to the
	/// closing of an identity whose opening sent its static key as its
	/// agreement ephemeral.
	async fn finish_with_a_static_ephemeral<F: TestFlow>(
		peer_authentication: PeerAuthentication,
	) -> Result<(), HandshakeError> {
		let client = create_test_certificate(0xbb);
		let ephemeral = SecretKey::from(&client.signing_key);
		let mut awaiting = F::awaiting_closing(peer_authentication, ephemeral).await;
		let finished = awaiting.finished_of(&client);

		awaiting.finish(&finished).await
	}

	/// A client that sends its static key as its ephemeral leaves the session
	/// to the secrecy of the two static keys, so a server that demands an
	/// identity refuses the closing of the one it admitted.
	async fn a_demanded_identity_that_sends_its_static_key_as_its_ephemeral_is_refused<F: TestFlow>() -> TestResult {
		let refusal = finish_with_a_static_ephemeral::<F>(PeerAuthentication::mutual_by_expiry()).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	/// A server that demands no identity still holds the key of a certificate
	/// the client offers, and refuses that key as the client ephemeral.
	async fn an_offered_identity_that_sends_its_static_key_as_its_ephemeral_is_refused<F: TestFlow>() -> TestResult {
		let refusal = finish_with_a_static_ephemeral::<F>(PeerAuthentication::Anonymous).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	/// The server refuses an offered certificate whose key is off the curve,
	/// where the opened Finished names it, before any key comparison or
	/// signature check.
	async fn an_offered_certificate_whose_key_is_off_the_curve_is_refused<F: TestFlow>() -> TestResult {
		let mut client = create_test_certificate(0xbc);
		put_off_curve_key(&mut client.certificate);

		let mut awaiting = F::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x44)).await;
		let finished = awaiting.finished_of(&client);

		let refusal = awaiting.finish(&finished).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::SpkiError(_)
			))
		));
		Ok(())
	}

	/// A server that granted no budgets issued no receipt, so it refuses a
	/// closing that acknowledges one.
	///
	/// The closing signs the sealed transcript hash and confirms the
	/// handshake secret, so confirmation and admission pass and settlement is
	/// what refuses.
	async fn an_acknowledgement_with_no_issued_receipt_is_refused<F: TestFlow>() -> TestResult {
		let client = create_test_certificate(0xbd);
		let mut awaiting = F::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x45)).await;
		let finished = awaiting.finished_of(&client);
		let ack = acknowledgement([0x41; 48]);
		let acknowledging = with_unsigned_attrs(finished, |carried| [carried, vec![ack]].concat());

		let refusal = awaiting.finish(&acknowledging).await;
		assert!(matches!(refusal, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// What a server of flow `F` answers to a closing that carries the abort
	/// alert of `code` among its unauthenticated attributes, beside a client
	/// Finished sealed under a key foreign to the server.
	async fn finish_with_an_abort_alert<F: TestFlow>(code: u8) -> Result<(), HandshakeError> {
		let client = create_test_certificate(0xbe);
		let mut awaiting = F::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x46)).await;
		let finished = awaiting.finished_of(&client);
		let sealed = sealed_finished(fixture_sealer(SecretSeal::Closing), &finished);
		let alert = Attributes::try_from(vec![abort_alert(code)]).expect("one attribute is a SET");
		let alerted = AuthEnvelopedData { unauth_attrs: Some(alert), ..sealed };
		let closing = HandshakeMessage::try_from(alerted).expect("the closing encodes");

		awaiting.server.finish(closing).await
	}

	/// A closing that carries the alert of a failed decryption is refused
	/// before the server opens it. The seal is under a key foreign to the
	/// server, and the refusal names the alert, so the server reads the alert
	/// first.
	async fn a_closing_with_a_decrypt_fail_alert_is_refused<F: TestFlow>() -> TestResult {
		let refusal = finish_with_an_abort_alert::<F>(4).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::AbortReceived(HandshakeAlert::DecryptFail))
		));
		Ok(())
	}

	/// A closing that carries the alert of a failed Finished is refused before
	/// the server opens it, and the refusal names that alert.
	async fn a_closing_with_a_finished_integrity_fail_alert_is_refused<F: TestFlow>() -> TestResult {
		let refusal = finish_with_an_abort_alert::<F>(5).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::AbortReceived(HandshakeAlert::FinishedIntegrityFail))
		));
		Ok(())
	}

	over_each_flow! {
		a_reply_without_a_security_accept_is_refused,
		a_client_refuses_a_profile_it_did_not_offer,
		an_off_curve_server_ephemeral_is_refused,
		a_server_ephemeral_equal_to_the_static_key_is_refused,
		a_tampered_server_ephemeral_fails_the_reply_signature,
		a_stripped_accept_fails_the_reply_signature,
		a_reply_with_an_abort_alert_is_refused,
		a_reply_without_a_server_finished_is_refused_before_the_closing,
		the_reply_carries_the_certificate_its_signer_names,
		a_reply_without_its_certificate_is_refused,
		a_reply_whose_certificate_bytes_were_reordered_is_refused,
		a_sha3_512_profile_carries_a_64_byte_transcript_hash,
		#[cfg(feature = "preview-pqc")]
		the_preview_provider_runs_the_flow,
		a_hand_built_identified_closing_is_admitted,
		a_closing_that_confirms_another_secret_is_refused,
		a_client_finished_over_another_transcript_is_refused,
		a_demanded_identity_that_sends_its_static_key_as_its_ephemeral_is_refused,
		an_offered_identity_that_sends_its_static_key_as_its_ephemeral_is_refused,
		an_offered_certificate_whose_key_is_off_the_curve_is_refused,
		an_acknowledgement_with_no_issued_receipt_is_refused,
		a_closing_with_a_decrypt_fail_alert_is_refused,
		a_closing_with_a_finished_integrity_fail_alert_is_refused,
	}
}

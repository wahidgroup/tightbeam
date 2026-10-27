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
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey, SecretKey};
use crate::crypto::sign::{
	CmsSigner, PresentedIssuers, PresentedPath, Signed, SignedContent, SignerInfoDraft, SigningIdentity,
};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::{Decode, Encode};
use crate::oids::{DATA, RECEIPT_ACK, SIGNED_DATA};
use crate::random::CryptoRngCore;
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	RunnableProfile, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::peer::ServerTrust;
use crate::transport::handshake::primitives::{KdfSalt, TranscriptHash};
use crate::transport::handshake::schedule::{
	Agreement, ConfirmedSecret, FinishedRole, KeyConfirmation, PeerPoint, Salt, Sealer, SecretSeal, Terms,
};
use crate::transport::handshake::{
	HandshakeCurve, HandshakeMessage, HandshakeProvider, HandshakeSecret, ServerIdentity,
};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::x509::attr::{Attribute, Attributes};

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

/// The facts of a decoded reply, bound into the sealed transcript.
pub struct ReplyIntake<F: ClientLegs<P>, P: HandshakeProvider> {
	/// What the reply names as the server, for the trust to admit.
	pub server: <F::Trust as ServerTrust<P>>::Named,
	/// The security profile the server selected.
	pub security_accept: Option<SecurityAccept>,
	/// The transport capabilities the server accepted.
	pub transport_accept: Option<TransportAccept>,
	/// The server ephemeral as SEC1 bytes. The orchestrator parses it beside
	/// the static key it must differ from.
	pub server_ephemeral: Vec<u8>,
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

/// What a client flow holds from its opening to the agreement: the private
/// half of its agreement ephemeral `R`, and the one decision of the flow,
/// which agreement it makes with the server ephemeral.
///
/// [`Self::agree`] is the one settlement of the client's handshake secret.
pub trait ClientAgreement<P: HandshakeProvider>: Sized {
	/// The agreement this value makes with the server ephemeral `peer`: the
	/// hybrid agreement with the base secret in the CMS flow, or the
	/// ephemeral agreement in the HPKE flow.
	fn agreement<'a>(&'a self, peer: &'a PeerPoint<P::Curve>) -> Agreement<'a, P>;

	/// The private half of the client's agreement ephemeral `R`.
	fn ephemeral(&self) -> &SecretKey<P::Curve>;

	/// Settle the agreement with `server_ephemeral` under `salt`. The value
	/// drops here, so each secret it holds is wiped with the call.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn agree(
		self,
		server_ephemeral: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError> {
		self.agreement(server_ephemeral).settle(self.ephemeral(), salt)
	}
}

/// What a server flow holds from its open of the opening to the reply: the
/// client's agreement ephemeral `R`, and the one decision of the flow, which
/// agreement it makes with `R`.
///
/// [`ServerPending::settle`] is the one settlement of the server's handshake
/// secret.
pub trait ServerAgreement<P: HandshakeProvider> {
	/// The client's agreement ephemeral `R`.
	fn client_ephemeral(&self) -> &PeerPoint<P::Curve>;

	/// The agreement this value makes with `R`: the hybrid agreement with the
	/// base secret in the CMS flow, or the ephemeral agreement in the HPKE
	/// flow.
	fn agreement(&self) -> Agreement<'_, P>;
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
	/// The public half of the server ephemeral, which the reply signs.
	pub server_ephemeral: PublicKey<P::Curve>,
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
pub struct ServerPending<C: CurveArithmetic> {
	/// The handshake secret, derived when the reply was built.
	secret: HandshakeSecret,
	/// The client's agreement ephemeral `R`.
	client_ephemeral: PublicKey<C>,
}

impl<C: HandshakeCurve> ServerPending<C> {
	/// Settle the agreement `opened` makes with the server `ephemeral` under
	/// the salt of `terms`, and keep `R` for the offer. `opened` and the
	/// ephemeral drop here, so each secret they hold is wiped with the call.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	pub(crate) fn settle<P: HandshakeProvider<Curve = C>>(
		opened: impl ServerAgreement<P>,
		ephemeral: Box<EphemeralSecret<C>>,
		terms: &Terms<P>,
	) -> Result<Self, HandshakeError> {
		let agreement = opened.agreement();

		let secret = agreement.settle(ephemeral.as_ref(), terms.kdf_salt())?;
		let client_ephemeral = *opened.client_ephemeral().as_public_key();
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
	pub(crate) fn finish_reply<P: HandshakeProvider<Curve = C>>(
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
/// either. The asynchronous open of the opening runs a static-key step
/// through the backend of the server's key-agreement identity, so the private
/// key can stay behind an external boundary.
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
	/// - [`HandshakeError::InvalidPublicKey`] -- the HPKE client ephemeral is not a point on the curve.
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
	/// - [`HandshakeError::InvalidPublicKey`] -- the client's agreement key is not a point on the curve.
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
		let content = CmsSigner::content(finished, DATA)?;
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
	/// the comparison lives here: `ephemeral` MUST be distinct from the key
	/// of `identity`, or the agreement collapses into the static one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the ephemeral collapses into the key of `identity`.
	fn new(
		identity: PeerCertificate<Signing<P>>,
		issuers: PresentedIssuers,
		finished: ClientFinished,
		ephemeral: &PublicKey<P::Curve>,
	) -> Result<Self, HandshakeError> {
		if !identity.distinct(ephemeral) {
			return Err(HandshakeError::ClientEphemeralIsStatic);
		}

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
		pending: ServerPending<P::Curve>,
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
		let offer = content.into_offer(&client_ephemeral, purpose)?;
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
				CmsSigner::bound_presented(der)?;
				let finished = Signed::<SignedData>::from_der(der)?;
				let (finished, path) = CmsSigner::take_signer_path(finished)?;
				Ok(Self::Finished(finished, path.map(Box::new)))
			},
			DATA => |der| {
				DerAdmission::Cms.admit(der)?;
				Ok(Self::Anonymous(Attributes::from_der(der)?))
			},
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
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- `client_ephemeral` equals the certificate key.
	fn into_offer<P: HandshakeProvider>(
		self,
		client_ephemeral: &PublicKey<P::Curve>,
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
	use std::error::Error;
	use std::sync::Arc;

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::crypto::sign::PresentedPath;
	use crate::crypto::x509::KeyPurposes;
	use crate::random::OsRng;
	use crate::transport::handshake::tests::{
		create_test_certificate, create_test_signed_data, fixture_confirmation, fixture_transcript, negated,
		same_key_twin, signing_identity,
	};
	use crate::x509::Certificate;

	/// A client certificate admitted for signing under the house provider.
	type HouseSigner = PeerCertificate<Signing<DefaultCryptoProvider>>;

	/// A fresh client identity, beside its static key.
	fn identity() -> (HouseSigner, PublicKey<Secp256k1>) {
		let client = create_test_certificate();
		let static_key = PublicKey::from(client.signing_key.verifying_key());
		let identity = PeerCertificate::parse(client.certificate, KeyPurposes::HOUSE.client);
		(identity.expect("the test certificate holds a point"), static_key)
	}

	/// A client Finished the offer holds for admission, which verifies it, so
	/// any signed content serves here.
	fn finished() -> ClientFinished {
		ClientFinished(create_test_signed_data(b"client finished"))
	}

	/// The public key of a fresh ephemeral.
	fn ephemeral() -> PublicKey<Secp256k1> {
		SecretKey::random(&mut OsRng).public_key()
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
		Offer::new(identity, issuers, finished(), ephemeral)
	}

	/// An offer whose ephemeral differs from the key of its identity holds
	/// that identity.
	#[test]
	fn an_offer_of_a_distinct_ephemeral_holds_its_identity() -> Result<(), HandshakeError> {
		let (identity, _) = identity();
		let expected = Arc::clone(identity.certificate());
		let offer = offer_of(identity, &ephemeral())?;

		let held = offer.into_identity().map(|(identity, _)| Arc::clone(identity.certificate()));
		assert_eq!(held, Some(expected));
		Ok(())
	}

	#[test]
	fn an_offer_refuses_an_ephemeral_equal_to_the_identity_key() {
		let (identity, static_key) = identity();
		let refused = offer_of(identity, &static_key);
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// ECDH keeps the x-coordinate alone, so the negation of the identity key
	/// collapses the agreement as the key itself does.
	#[test]
	fn an_offer_refuses_the_negation_of_the_identity_key() {
		let (identity, static_key) = identity();
		let negation = negated(&static_key);

		let refused = offer_of(identity, &negation);
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// A client Finished of `identity` over `transcript_hash`, signed and
	/// built as the closing builds it, with its key-confirmation tag.
	async fn client_finished(identity: &SigningIdentity, transcript_hash: &TranscriptHash) -> Signed<SignedData> {
		let draft = FinishedRole::Client.draft::<DefaultCryptoProvider>(identity, transcript_hash);
		let draft = draft.expect("the Finished drafts");
		let signature = identity.sign_prehash(draft.prehash()).await.expect("the client key signs");
		let tag = HandshakeAttribute::encode(&fixture_confirmation()).expect("a tag encodes as an attribute");
		let tag = Attribute::try_from(tag).expect("the attribute encodes");
		let attributes = Attributes::try_from(vec![tag]).expect("one attribute is a SET");
		let certificates = identity.presented().set();

		let finished = draft.finish(signature, attributes, Some(certificates));
		finished.expect("the Finished assembles")
	}

	/// A client Finished verifies under the certificate it carries.
	#[tokio::test]
	async fn a_client_finished_verifies_under_the_certificate_it_carries() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let finished = client_finished(&signing_identity(&client), &transcript_hash).await;
		let carried = HouseSigner::parse(client.certificate, KeyPurposes::HOUSE.client)?;

		let verified = FinishedRole::Client.verify::<DefaultCryptoProvider>(&finished, &carried, &transcript_hash);
		assert!(verified.is_ok());
		Ok(())
	}

	/// A client Finished binds the digest of the certificate it carries, so
	/// it verifies under no other certificate of its key, as a TLS 1.3
	/// signature covers the Certificate (RFC 9846 §4.5.2).
	#[tokio::test]
	async fn a_client_finished_verifies_under_no_other_certificate_of_its_key() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let finished = client_finished(&signing_identity(&client), &transcript_hash).await;
		let twin = HouseSigner::parse(same_key_twin(&client), KeyPurposes::HOUSE.client)?;

		let refused = FinishedRole::Client.verify::<DefaultCryptoProvider>(&finished, &twin, &transcript_hash);
		assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}
}

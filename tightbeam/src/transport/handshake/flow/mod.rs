//! The messages of one handshake protocol.
//!
//! A flow encodes and decodes the three legs of one protocol, binds them into
//! the transcript, carries the base secret, and makes the checks its messages
//! define. The orchestrator owns the step order and every negotiation and
//! admission decision, and it acts on the decoded facts alone.
//!
//! A step of the orchestrator works between three kinds of flow call:
//!
//! 1. A `read_*` or `bind_*` call returns the facts of the leg and the bytes to sign.
//! 2. The orchestrator admits, negotiates, and countersigns. `sign` signs each
//!    prehash with the provider calls of its protocol.
//! 3. An `encode_*` call takes the result and builds the message.
//!
//! The [legs](crate::transport::handshake#legs) table names the message each
//! protocol sends on each leg.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::signed_data::SignedData;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey};
use crate::random::CryptoRngCore;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	RunnableProfile, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::peer::{PeerCertificate, PossessionProof, ServerTrust};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::schedule::{
	ConfirmedSecret, KeyConfirmation, PeerEphemeral, PeerPoint, Salt, Sealer, Terms,
};
use crate::transport::handshake::{HandshakeCurve, HandshakeMessage, HandshakeProvider, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};

#[cfg(feature = "transport-cms")]
mod cms;
#[cfg(feature = "transport-hpke")]
mod hpke;

#[cfg(feature = "transport-cms")]
pub use cms::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(feature = "transport-hpke")]
pub use hpke::{Hpke, HpkeClientSettings, HpkeServerSettings};

mod sealed {
	pub trait Sealed {}
}

/// A handshake protocol, named by its marker type.
///
/// The trait is sealed, so [`Hpke`] and [`Cms`] are the only flows.
pub trait HandshakeFlow: sealed::Sealed + Sized + MaybeSend + MaybeSync + 'static {
	/// What a signed leg of this protocol carries of its signer.
	type Signed: MaybeSend;

	/// Sign `prehash` under `key`, and fetch what else of the signer the
	/// messages of this protocol carry.
	///
	/// The protocol makes the calls, so a key provider answers the ones its
	/// messages need and no other.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyError`] -- the key provider failed.
	fn sign<'a>(
		key: &'a dyn SigningKeyProvider,
		prehash: &'a [u8],
	) -> MaybeSendFuture<'a, Result<Self::Signed, HandshakeError>>;
}

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
	pub server: <F::Trust as ServerTrust<P::Curve>>::Named,
	/// The security profile the server selected.
	pub security_accept: Option<SecurityAccept>,
	/// The transport capabilities the server accepted.
	pub transport_accept: Option<TransportAccept>,
	/// The server ephemeral as SEC1 bytes. The orchestrator parses it beside
	/// the static key it must differ from.
	pub server_ephemeral: Vec<u8>,
	/// The server-signed session receipt, when the session carries budgets.
	pub receipt: Option<SignedData>,
	/// Whether the server demands a client identity. The HPKE reply carries
	/// the demand, and the CMS flow yields `false`, because a CMS client always
	/// holds an identity.
	pub client_cert_required: bool,
	/// The hash of the sealed transcript, which the reply signs.
	pub transcript_hash: [u8; 32],
	/// The KDF salt of the flow.
	pub salt: Salt,
	/// The signed reply, kept for verification and for the closing.
	pub reply: F::Reply,
}

/// What the orchestrator contributes to the closing.
pub struct ClosingParts<'a, P: HandshakeProvider> {
	/// The admitted server certificate, with its key.
	pub server: &'a PeerCertificate<P::Curve>,
	/// The hash of the sealed transcript.
	pub transcript_hash: &'a [u8; 32],
	/// The receipt countersignature, sealed under the handshake secret.
	pub sealed_ack: Option<Vec<u8>>,
	/// The proof that the client derived the handshake secret.
	pub confirmation: KeyConfirmation,
	/// The single-use AEAD the client identity is sealed under, keyed by the
	/// handshake secret.
	pub identity_sealer: Sealer<P>,
}

/// The possession proof a closing still needs: the bytes to sign, beside the
/// key that signs them.
pub struct ProofRequest<'a> {
	/// The bytes the client identity signs.
	pub prehash: Vec<u8>,
	/// The provider of the identity's signing key.
	pub signer: &'a dyn SigningKeyProvider,
}

/// A closing that awaits its possession proof.
pub struct ClosingBinding<'a, F: ClientLegs<P>, P: HandshakeProvider> {
	/// The proof to sign, when an identity presents itself in the closing.
	pub proof: Option<ProofRequest<'a>>,
	/// The closing, complete except for that proof.
	pub draft: F::Draft,
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
/// either.
pub trait ClientLegs<P: HandshakeProvider>: HandshakeFlow {
	/// What a client of this protocol is provisioned with.
	type Settings: MaybeSend + MaybeSync + 'static;
	/// Where the client learns the server identity.
	type Trust: ServerTrust<P::Curve>;
	/// What the flow keeps from the opening to read the reply against.
	type Opening: MaybeSend + MaybeSync + 'static;
	/// The secrets the flow holds from the opening to the agreement.
	type Pending: MaybeSend + MaybeSync + 'static;
	/// The decoded reply, kept for verification and for the closing.
	type Reply: MaybeSend + 'static;
	/// What the agreement hands to the closing.
	type Agreed: MaybeSend + 'static;
	/// The closing that awaits its possession proof.
	type Draft: MaybeSend + 'static;

	/// The identity the client presents, when it holds one.
	fn identity(settings: &Self::Settings) -> Option<&ClientIdentity<P>>;

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
		server: <Self::Trust as ServerTrust<P::Curve>>::Provisioned,
		parts: OpeningParts<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<Opened<Self, P>, HandshakeError>;

	/// Decode the reply, bind its legs, and seal the transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the reply travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the reply carries an abort alert.
	/// - [`HandshakeError`] -- the reply fails to decode, or a leg fails to bind.
	fn read_reply(
		opening: Self::Opening,
		settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError>;

	/// Verify the signature of the reply under `key`, over the bytes this flow
	/// derives from `transcript_hash`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureError`] -- the HPKE signature fails to parse or to verify.
	/// - [`HandshakeError::TranscriptDigestLength`] -- the HPKE digest gives fewer than 32 bytes.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the CMS Finished
	///   fails to verify, or it signs another transcript or another role.
	fn verify_reply(
		reply: &Self::Reply,
		key: P::VerifyingKey,
		transcript_hash: &[u8; 32],
	) -> Result<(), HandshakeError>;

	/// Derive the handshake secret from the client half of the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn agree(
		pending: Self::Pending,
		server_ephemeral: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(HandshakeSecret, Self::Agreed), HandshakeError>;

	/// Build the closing up to its possession proof, and name the bytes that
	/// proof signs beside the identity that signs them.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the bytes the proof signs fail to encode or to hash.
	fn bind_closing<'a>(
		agreed: Self::Agreed,
		reply: Self::Reply,
		settings: &'a Self::Settings,
		parts: ClosingParts<'_, P>,
	) -> Result<ClosingBinding<'a, Self, P>, HandshakeError>;

	/// Encode the closing with the possession proof, when the client signed
	/// one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MutualAuthRequired`] -- the protocol requires a
	///   proof and none came, or a certificate and its proof come apart.
	/// - [`HandshakeError::SealedIdentity`] -- the identity exceeds the frame,
	///   or the AEAD refused to seal it.
	/// - [`HandshakeError::HpkeError`] -- the payload fails to seal to the server's static key.
	/// - [`HandshakeError`] -- the closing fails to encode.
	fn encode_closing(draft: Self::Draft, proof: Option<Self::Signed>) -> Result<HandshakeMessage, HandshakeError>;
}

/// The facts of a decoded opening, with what it sealed to the static key.
pub struct OpeningIntake<F: ServerLegs<P>, P: HandshakeProvider> {
	/// The security profiles the client offers.
	pub security_offer: Option<SecurityOffer>,
	/// The transport capabilities the client offers.
	pub transport_offer: Option<TransportOffer>,
	/// What the opening sealed to the server's static key.
	pub sealed: F::Sealed,
}

/// What the orchestrator contributes to the reply.
pub struct ReplyParts<'a, P: HandshakeProvider> {
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
	pub transcript_hash: [u8; 32],
	/// The KDF salt of the flow.
	pub salt: Salt,
	/// The bytes the server signs.
	pub prehash: Vec<u8>,
	/// The reply, complete except for the signature and the receipt.
	pub draft: F::Draft,
}

/// The identity a client offers, with the proof that it holds the key, or
/// none.
///
/// Its constructors are private to the flows, so an offer exists only where a
/// flow opened the closing. [`Self::new`] refuses an identity whose key
/// collapses an ephemeral of the client, so no offer exists for that client.
pub struct Offer<C: CurveArithmetic, Proof>(Option<(PeerCertificate<C>, Proof)>);

impl<C: HandshakeCurve, Proof> Offer<C, Proof> {
	/// The offer of a client that presents no identity. A CMS Finished is
	/// itself a proof, so only an HPKE closing yields this offer.
	#[cfg(feature = "transport-hpke")]
	fn anonymous() -> Self {
		Self(None)
	}

	/// The offer of `identity`, proven by `proof`.
	///
	/// A server learns its client's static key only after the agreement, so
	/// the comparison lives here: each of `ephemerals` MUST have an
	/// x-coordinate other than that of the identity's key. ECDH keeps the
	/// x-coordinate alone, so a match would collapse the agreement into the
	/// static one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- an ephemeral collapses into the key of `identity`.
	fn new<'k>(
		identity: PeerCertificate<C>,
		proof: Proof,
		ephemerals: impl IntoIterator<Item = &'k PublicKey<C>>,
	) -> Result<Self, HandshakeError>
	where
		C: 'k,
	{
		let key = identity.key();
		let collapsed = ephemerals.into_iter().any(|ephemeral| key.distinct(*ephemeral).is_none());
		if collapsed {
			return Err(HandshakeError::ClientEphemeralIsStatic);
		}

		Ok(Self(Some((identity, proof))))
	}

	/// The identity and its proof, for the admission that verifies them.
	pub(crate) fn into_identity(self) -> Option<(PeerCertificate<C>, Proof)> {
		self.0
	}
}

/// What the server holds once the closing is opened.
///
/// The fields stay private to the flows, and [`Self::confirm`] is the one way
/// out, so the offer reaches admission only after the key-confirmation tag
/// verified.
pub struct ClosingOpened<F: ServerLegs<P>, P: HandshakeProvider> {
	/// The handshake secret both sides derived.
	secret: HandshakeSecret,
	/// The key-confirmation tag the closing carried.
	confirmation: KeyConfirmation,
	/// The receipt countersignature, sealed under the handshake secret.
	receipt_ack: Option<Vec<u8>>,
	/// The identity the client offers.
	offer: Offer<P::Curve, F::Proof>,
}

impl<F: ServerLegs<P>, P: HandshakeProvider> ClosingOpened<F, P> {
	/// Verify the key-confirmation tag against the secret, and release the
	/// offer.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the derivation.
	/// - [`HandshakeError::KeyConfirmationFailed`] -- the client derived
	///   another secret or confirmed another transcript.
	pub(crate) fn confirm(self, terms: &Terms<P>) -> Result<ConfirmedClosing<F, P>, HandshakeError> {
		let Self { secret, confirmation, receipt_ack, offer } = self;
		let secret = terms.confirm(secret, &confirmation)?;
		Ok(ConfirmedClosing { secret, receipt_ack, offer })
	}
}

/// A closing whose key-confirmation tag verified.
///
/// Its secret is a [`ConfirmedSecret`], which only the check of the tag
/// yields, so the offer it holds passed that check.
pub struct ConfirmedClosing<F: ServerLegs<P>, P: HandshakeProvider> {
	/// The handshake secret the tag confirmed.
	pub(crate) secret: ConfirmedSecret,
	/// The receipt countersignature, sealed under the handshake secret.
	pub(crate) receipt_ack: Option<Vec<u8>>,
	/// The identity the client offers.
	pub(crate) offer: Offer<P::Curve, F::Proof>,
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
/// either. The two asynchronous methods are the static-key operations, which
/// run through the key provider, so the private key can stay behind an
/// external boundary.
pub trait ServerLegs<P: HandshakeProvider>: HandshakeFlow {
	/// What a server of this protocol is provisioned with.
	type Settings: MaybeSend + MaybeSync + 'static;
	/// What the opening sealed to the static key.
	type Sealed: MaybeSend + 'static;
	/// What the flow holds from the static open to the reply.
	type Opened: MaybeSend + 'static;
	/// The reply that awaits its signature and its receipt.
	type Draft: MaybeSend + 'static;
	/// The secrets the flow holds from the reply to the closing.
	type Pending: MaybeSend + MaybeSync + 'static;
	/// What the closing still holds for the agreement.
	type Closing: MaybeSend + 'static;
	/// The proof that the key of the offered certificate signed the closing.
	type Proof: PossessionProof<P> + MaybeSend + 'static;

	/// Decode the opening, and open the transcript over it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the opening travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the opening carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or the abort alert repeats.
	/// - [`HandshakeError`] -- the opening fails to decode.
	fn read_opening(
		settings: &Self::Settings,
		opening: HandshakeMessage,
	) -> Result<OpeningIntake<Self, P>, HandshakeError>;

	/// Open what the opening sealed to the static key.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidClientKeyExchange`] -- the opening carries no usable key agreement.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client's key is not a point on the curve.
	/// - [`HandshakeError::KeyError`] -- the key provider failed.
	/// - [`HandshakeError`] -- the sealed content fails to open.
	fn open_opening<'a>(
		sealed: Self::Sealed,
		key: &'a dyn SigningKeyProvider,
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

	/// Encode the reply with the server signature and the receipt artifact.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the reply fails to encode.
	fn encode_reply(
		draft: Self::Draft,
		signed: Self::Signed,
		artifact: Option<&SignedData>,
	) -> Result<HandshakeMessage, HandshakeError>;

	/// Fix what the server carries from the reply to the closing.
	///
	/// The ephemeral arrives boxed, so a flow that keeps it for the closing
	/// moves a pointer, and the scalar is wiped where the box drops.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn pend(
		opened: Self::Opened,
		ephemeral: Box<EphemeralSecret<P::Curve>>,
		terms: &Terms<P>,
	) -> Result<Self::Pending, HandshakeError>;

	/// Decode the closing without opening it.
	///
	/// It takes the pending state of the reply, and the closing it returns
	/// holds what [`Self::settle`] reads of that state.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the closing travels in another container.
	/// - [`HandshakeError::AbortReceived`] -- the closing carries an abort alert.
	/// - [`HandshakeError`] -- the closing fails to decode.
	fn read_closing(
		pending: Self::Pending,
		settings: &Self::Settings,
		closing: HandshakeMessage,
	) -> Result<Self::Closing, HandshakeError>;

	/// Open the closing under the handshake secret, which HPKE derives here
	/// and CMS derived at the reply, open the client identity under it, parse
	/// the identity once, and build the [`Offer`].
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyError`] -- the key provider failed.
	/// - [`HandshakeError::HpkeError`] -- the sealed payload fails to open.
	/// - [`HandshakeError::InvalidDecryptedPayloadSize`] -- the opened payload fails to decode.
	/// - [`HandshakeError::InvalidKeySize`] -- the base secret of the payload is not 32 bytes.
	/// - [`HandshakeError::OctetStringLengthError`] -- the client random of the payload is not 32 bytes.
	/// - [`HandshakeError::ClientRandomMismatchReplay`] -- the payload echoes another client random.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client ephemeral or the
	///   key of the offered certificate is not a point on the curve.
	/// - [`HandshakeError::SealedIdentity`] -- the sealed identity fails to
	///   open, or a CMS closing names another content type or algorithm, or
	///   carries no content.
	/// - [`HandshakeError::DerError`] -- the opened identity fails to decode,
	///   or the key-confirmation tag of a CMS Finished has another width.
	/// - [`HandshakeError::MissingAttribute`] -- a CMS Finished carries no key-confirmation tag.
	/// - [`HandshakeError::DuplicateAttribute`] -- an attribute of a CMS Finished repeats.
	/// - [`HandshakeError::MissingClientCertificate`] -- a CMS Finished names no certificate.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- a client ephemeral
	///   collapses into the key of the offered certificate.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret or the identity key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the identity key.
	fn settle<'a>(
		closing: Self::Closing,
		terms: &'a Terms<P>,
		key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<ClosingOpened<Self, P>, HandshakeError>>;
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::random::OsRng;
	use crate::transport::handshake::tests::{create_test_certificate, negated};

	/// A fresh client identity, beside its static key.
	fn identity() -> (PeerCertificate<Secp256k1>, PublicKey<Secp256k1>) {
		let client = create_test_certificate();
		let static_key = PublicKey::from(client.signing_key.verifying_key());
		let identity = PeerCertificate::parse(client.certificate);
		(identity.expect("the test certificate holds a point"), static_key)
	}

	/// The public key of a fresh ephemeral.
	fn ephemeral() -> PublicKey<Secp256k1> {
		SecretKey::random(&mut OsRng).public_key()
	}

	/// An offer whose ephemerals all differ from the key of its identity holds
	/// that identity.
	#[test]
	fn an_offer_of_distinct_ephemerals_holds_its_identity() -> Result<(), HandshakeError> {
		let (identity, _) = identity();
		let expected = Arc::clone(identity.certificate());

		let offer = Offer::new(identity, (), [&ephemeral(), &ephemeral()])?;

		let held = offer.into_identity().map(|(identity, ())| Arc::clone(identity.certificate()));
		assert_eq!(held, Some(expected));
		Ok(())
	}

	#[test]
	fn an_offer_refuses_an_ephemeral_equal_to_the_identity_key() {
		let (identity, static_key) = identity();

		let refused = Offer::new(identity, (), [&static_key]);

		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// ECDH keeps the x-coordinate alone, so the negation of the identity key
	/// collapses the agreement as the key itself does.
	#[test]
	fn an_offer_refuses_the_negation_of_the_identity_key() {
		let (identity, static_key) = identity();
		let negation = negated(&static_key);

		let refused = Offer::new(identity, (), [&negation]);

		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// The offer compares every ephemeral of the client, so the identity key
	/// after a distinct ephemeral is refused as it is in the first place.
	#[test]
	fn an_offer_refuses_the_identity_key_after_a_distinct_ephemeral() {
		let (identity, static_key) = identity();

		let refused = Offer::new(identity, (), [&ephemeral(), &static_key]);

		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}
}

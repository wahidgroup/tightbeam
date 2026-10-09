//! The messages of one handshake protocol.
//!
//! A flow encodes and decodes the three legs of one protocol, binds them into
//! the transcript, carries the base secret, and makes the checks its messages
//! define. The orchestrator owns the step order and every negotiation and
//! admission decision, and it acts on the decoded facts alone.
//!
//! A step of the orchestrator works between two kinds of flow call:
//!
//! 1. A `read_*` or `bind_*` call returns the facts of the leg and the bytes to sign.
//! 2. The orchestrator admits, negotiates, signs, and countersigns.
//! 3. An `encode_*` call takes the result and builds the message.
//!
//! The [legs](crate::transport::handshake#legs) table names the message each
//! protocol sends on each leg.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::signed_data::SignedData;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::random::CryptoRngCore;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	RunnableProfile, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::peer::{PossessionProof, ServerTrust};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::schedule::{KeyConfirmation, PeerPoint, Salt, Terms};
use crate::transport::handshake::{HandshakeMessage, HandshakeProvider, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
mod cms;
#[cfg(feature = "transport-ecies")]
mod ecies;

#[cfg(feature = "transport-cms")]
pub use cms::{Cms, CmsClientSettings, CmsServerSettings};
#[cfg(feature = "transport-ecies")]
pub use ecies::{Ecies, EciesClientSettings, EciesServerSettings};

mod sealed {
	pub trait Sealed {}
}

/// A handshake protocol, named by its marker type.
///
/// The trait is sealed, so [`Ecies`] and [`Cms`] are the only flows.
pub trait HandshakeFlow: sealed::Sealed + Sized + MaybeSend + MaybeSync + 'static {}

/// A signature and the public key of its signer, from one key provider.
pub struct Signed {
	/// The signature bytes, as the provider encodes them.
	pub signature: Vec<u8>,
	/// The DER SubjectPublicKeyInfo of the key that signed.
	pub signer_spki: Vec<u8>,
}

/// What the client configuration contributes to the opening.
pub struct OpeningParts<'a> {
	/// The security profiles the client offers.
	pub security_offer: Option<&'a SecurityOffer>,
	/// The transport capabilities the client offers.
	pub transport_offer: Option<&'a TransportOffer>,
}

/// An encoded opening, with what the client keeps for the reply.
pub struct Opened<F: ClientFlow<P>, P: HandshakeProvider> {
	/// The opening, encoded once for sending.
	pub message: HandshakeMessage,
	/// What the flow reads the reply against.
	pub opening: F::Opening,
	/// The secrets the flow holds until the agreement.
	pub pending: F::Pending,
}

/// The facts of a decoded reply, bound into the sealed transcript.
pub struct ReplyIntake<F: ClientFlow<P>, P: HandshakeProvider> {
	/// What the reply names as the server, for the trust to admit.
	pub server: <F::Trust as ServerTrust>::Named,
	/// The security profile the server selected.
	pub security_accept: Option<SecurityAccept>,
	/// The transport capabilities the server accepted.
	pub transport_accept: Option<TransportAccept>,
	/// The server ephemeral as SEC1 bytes. The orchestrator parses it beside
	/// the static key it must differ from.
	pub server_ephemeral: Vec<u8>,
	/// The server-signed session receipt, when the session carries budgets.
	pub receipt: Option<SignedData>,
	/// Whether the server demands a client identity. The ECIES reply carries
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
pub struct ClosingParts<'a> {
	/// The admitted server certificate.
	pub server: &'a Certificate,
	/// The hash of the sealed transcript.
	pub transcript_hash: &'a [u8; 32],
	/// The receipt countersignature, sealed under the handshake secret.
	pub sealed_ack: Option<Vec<u8>>,
	/// The proof that the client derived the handshake secret.
	pub confirmation: KeyConfirmation,
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
pub struct ClosingBinding<'a, F: ClientFlow<P>, P: HandshakeProvider> {
	/// The proof to sign, when an identity presents itself in the closing.
	pub proof: Option<ProofRequest<'a>>,
	/// The closing, complete except for that proof.
	pub draft: F::Draft,
}

/// The client legs of one protocol.
///
/// Both flows return the same intake shapes and refuse with the same
/// [`HandshakeError`] set, so the orchestrator runs one step order over
/// either.
pub trait ClientFlow<P: HandshakeProvider>: HandshakeFlow {
	/// What a client of this protocol is provisioned with.
	type Settings: MaybeSend + MaybeSync + 'static;
	/// Where the client learns the server identity.
	type Trust: ServerTrust;
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
		server: <Self::Trust as ServerTrust>::Provisioned,
		parts: OpeningParts<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<Opened<Self, P>, HandshakeError>;

	/// Decode the reply, bind its legs, and seal the transcript.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the reply travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the reply carries an abort alert.
	/// - [`HandshakeError`] -- the reply fails to decode, or a leg fails to bind.
	fn read_reply(
		opening: Self::Opening,
		settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError>;

	/// Verify the signature of the reply over `transcript_hash` under `key`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureError`] -- the ECIES signature fails to parse or to verify.
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
	/// - [`HandshakeError`] -- the closing fails to seal or encode.
	fn bind_closing<'a>(
		agreed: Self::Agreed,
		reply: Self::Reply,
		settings: &'a Self::Settings,
		parts: ClosingParts<'_>,
	) -> Result<ClosingBinding<'a, Self, P>, HandshakeError>;

	/// Encode the closing with the possession proof, when the client signed
	/// one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MutualAuthRequired`] -- the protocol requires a proof, and none came.
	/// - [`HandshakeError`] -- the closing fails to encode.
	fn encode_closing(draft: Self::Draft, proof: Option<Signed>) -> Result<HandshakeMessage, HandshakeError>;
}

/// The facts of a decoded opening, with what it sealed to the static key.
pub struct OpeningIntake<F: ServerFlow<P>, P: HandshakeProvider> {
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
pub struct ReplyBinding<F: ServerFlow<P>, P: HandshakeProvider> {
	/// The hash of the sealed transcript.
	pub transcript_hash: [u8; 32],
	/// The KDF salt of the flow.
	pub salt: Salt,
	/// The bytes the server signs.
	pub prehash: Vec<u8>,
	/// The reply, complete except for the signature and the receipt.
	pub draft: F::Draft,
}

/// The facts of a decoded closing, with what it sealed to the static key.
pub struct ClosingIntake<F: ServerFlow<P>, P: HandshakeProvider> {
	/// The certificate the client offers as its identity.
	pub offered: Option<Certificate>,
	/// The proof that the key of the offered certificate signed the closing.
	pub proof: Option<F::Proof>,
	/// What the closing still holds for the agreement.
	pub closing: F::Closing,
}

/// What the server holds once the closing is opened.
pub struct ClosingOpened {
	/// The handshake secret both sides derived.
	pub secret: HandshakeSecret,
	/// The receipt countersignature, sealed under the handshake secret.
	pub receipt_ack: Option<Vec<u8>>,
	/// The key-confirmation tag the closing carried. The orchestrator verifies
	/// it against the handshake secret.
	pub confirmation: KeyConfirmation,
}

/// The server legs of one protocol.
///
/// Both flows return the same intake shapes and refuse with the same
/// [`HandshakeError`] set, so the orchestrator runs one step order over
/// either. The two asynchronous methods are the static-key operations, which
/// run through the key provider, so the private key can stay behind an
/// external boundary.
pub trait ServerFlow<P: HandshakeProvider>: HandshakeFlow {
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
	/// - [`HandshakeError::UnexpectedContainer`] -- the opening travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the opening carries an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or the certificate attribute repeats.
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
		signed: Signed,
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

	/// Decode the closing, and return the offered identity beside its proof.
	///
	/// # Errors
	///
	/// - [`HandshakeError::UnexpectedContainer`] -- the closing travels in the other container.
	/// - [`HandshakeError::AbortReceived`] -- the closing carries an abort alert.
	/// - [`HandshakeError::ClientCertificateMismatch`] -- the closing names
	///   another certificate than the opening bound.
	/// - [`HandshakeError::MissingAttribute`] -- the closing carries no key-confirmation tag.
	/// - [`HandshakeError`] -- the closing fails to decode.
	fn read_closing(
		pending: &Self::Pending,
		settings: &Self::Settings,
		closing: HandshakeMessage,
	) -> Result<ClosingIntake<Self, P>, HandshakeError>;

	/// Open what the closing sealed to the static key, and derive the
	/// handshake secret from the server half of the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyError`] -- the key provider failed.
	/// - [`HandshakeError::EciesError`] -- the sealed payload fails to open.
	/// - [`HandshakeError::InvalidDecryptedPayloadSize`] -- the opened payload fails to decode.
	/// - [`HandshakeError::InvalidKeySize`] -- the base secret of the payload is not 32 bytes.
	/// - [`HandshakeError::OctetStringLengthError`] -- the client random of the payload is not 32 bytes.
	/// - [`HandshakeError::ClientRandomMismatchReplay`] -- the payload echoes another client random.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	fn settle<'a>(
		pending: Self::Pending,
		closing: Self::Closing,
		terms: &'a Terms<P>,
		key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<ClosingOpened, HandshakeError>>;
}

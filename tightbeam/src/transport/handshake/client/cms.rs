//! CMS-based client handshake orchestrator.
//!
//! [`CmsHandshakeClient`] runs the client side of the TightBeam handshake
//! protocol with CMS builders and processors. The client's KARI ephemeral
//! serves two agreements: with the server's static key it wraps the base
//! secret, and with the server ephemeral on the Finished it feeds the
//! handshake secret.

#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use crate::cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EnvelopedData, KeyAgreeRecipientIdentifier, OriginatorPublicKey, UserKeyingMaterial};
use crate::cms::signed_data::{CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile, SecurityProfileDesc};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, PublicKey, SecretKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, LowSEncoding, SignatureAlgorithmIdentifier};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
use crate::crypto::x509::Certificate;
use crate::der::asn1::{OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Choice, Decode, DecodeValue, Encode};
use crate::oids::DATA;
use crate::random::{generate_nonce, CryptoRngCore, OsRng, RngWrapper};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::AttributePayload;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamKariBuilder};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfileStrengthPolicy, RunnableProfile, SecurityAccept, SecurityOffer, StrengthFloor, TransportAccept,
	TransportOffer,
};
use crate::transport::handshake::orchestrator::{
	BaseSecret, HandshakeAgreement, HandshakeVerifyingKey, KeySchedule, ServerEphemeral,
};
use crate::transport::handshake::primitives::transcript::{FinishedRole, ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::ReceiptSigner;
use crate::transport::handshake::receipt::{ReceiptApprover, ReceiptRole, SessionReceipt, StoredReceipt};
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine, Cms};
use crate::transport::handshake::{Arc, ClientHandshakeProtocol, HandshakeAlertHandler, HandshakeFinalization};
use crate::transport::handshake::{EpochMaterials, EstablishedSession, HandshakeMessage, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::zeroize::Zeroizing;

/// A server certificate path and a shared handle to the leaf it ends with.
///
/// A session records the leaf as its peer, and `Arc<[Certificate]>` cannot
/// lend out one element. Making the handle when the path is accepted keeps
/// every later read a refcount rather than a certificate copy.
struct ServerChain {
	path: Arc<[Certificate]>,
	/// `None` when the provisioned path was empty, which every read below
	/// reports as a missing server certificate.
	leaf: Option<Arc<Certificate>>,
}

impl ServerChain {
	/// The full path, ordered root to leaf, as the trust store verifies it.
	fn path(&self) -> &Arc<[Certificate]> {
		&self.path
	}

	/// The certificate the path ends with, which identifies the server.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingServerCertificate`] -- the path was empty.
	fn leaf(&self) -> Result<&Certificate, HandshakeError> {
		self.leaf.as_deref().ok_or(HandshakeError::MissingServerCertificate)
	}

	/// Shared handle to the leaf, for a session that outlives this handshake.
	fn leaf_handle(&self) -> Option<Arc<Certificate>> {
		self.leaf.as_ref().map(Arc::clone)
	}
}

impl From<Arc<[Certificate]>> for ServerChain {
	fn from(path: Arc<[Certificate]>) -> Self {
		let leaf = path.last().cloned().map(Arc::new);

		Self { path, leaf }
	}
}

/// Client-side CMS handshake orchestrator.
///
/// Generic over `P: CryptoProvider`, which defines the complete cryptographic
/// suite (curve, signature algorithm, digest, AEAD, KDF). It supports
/// cryptographic profile negotiation through the optional `security_offer`
/// field.
///
/// The client handshake runs in order:
///
/// 1. Send KeyExchange (EnvelopedData with KARI) carrying the base secret, and keep the KARI ephemeral.
/// 2. Receive and verify the server Finished (SignedData), whose transcript
///    carries the server ephemeral, then derive the handshake secret from the
///    base secret and the ephemeral-ephemeral ECDH.
/// 3. Send the client Finished (SignedData) with the receipt countersignature sealed under that secret.
pub struct CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	state: ClientStateMachine<Cms>,
	client_key_provider: Arc<dyn SigningKeyProvider>,
	/// Certificate this client presents and the key that proves it, bound as
	/// one value so both halves reach the authentication path together.
	identity: Option<ClientIdentity<P>>,
	server_cert: Option<Arc<Certificate>>,
	server_chain: Option<ServerChain>,
	transcript: Transcript,
	/// The base secret and the KARI ephemeral from the key exchange to the
	/// server Finished, which takes them, and the handshake secret from there
	/// to completion, which takes that.
	key_schedule: KeySchedule<PendingKeyExchange<P>>,
	security_offer: Option<SecurityOffer>,
	strength_floor: StrengthFloor,
	transport_offer: Option<TransportOffer>,
	mux_settings: Option<MuxSettings>,
	selected_profile: Option<RunnableProfile<P>>,
	provider: P,
	trust_store: Option<Arc<dyn CertificateTrust>>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	pending_receipt: Option<(SessionReceipt, SignedData)>,
	stored_receipt: Option<StoredReceipt>,
}

/// What the client holds between its key exchange and the server Finished.
///
/// The base secret and the ephemeral travel in one value, so one `take`
/// consumes both at the agreement.
struct PendingKeyExchange<P>
where
	P: CryptoProvider,
{
	/// The base secret the key exchange carried to the server.
	base: BaseSecret,
	/// The KARI ephemeral, kept for the agreement with the server ephemeral.
	ephemeral: SecretKey<P::Curve>,
}

/// Signer identity and algorithm identifiers for a Finished SignedData.
struct FinishedSigner {
	id: SignerIdentifier,
	digest_alg: AlgorithmIdentifierOwned,
	signature_alg: AlgorithmIdentifierOwned,
}

impl<P> CmsHandshakeClient<P>
where
	P: CryptoProvider,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::Signature: LowSEncoding + 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: KeyInit,
{
	/// Create a CMS handshake client.
	///
	/// `provider` fixes the security profile, `client_key_provider`
	/// authenticates the client, and the key agreement runs against
	/// `server_cert`.
	pub fn new(provider: P, client_key_provider: Arc<dyn SigningKeyProvider>, server_cert: Arc<Certificate>) -> Self {
		Self::with_identity(provider, client_key_provider, Some(server_cert), None)
	}

	/// Create a new CMS handshake client from a server certificate chain.
	///
	/// The encryption target is the chain leaf, which the client reads in
	/// place from the chain. Path validation runs over the whole chain during
	/// key exchange.
	pub fn from_chain(
		provider: P,
		client_key_provider: Arc<dyn SigningKeyProvider>,
		chain: Arc<[Certificate]>,
	) -> Self {
		Self::with_identity(provider, client_key_provider, None, Some(chain))
	}

	fn with_identity(
		provider: P,
		client_key_provider: Arc<dyn SigningKeyProvider>,
		server_cert: Option<Arc<Certificate>>,
		server_chain: Option<Arc<[Certificate]>>,
	) -> Self {
		let server_chain = server_chain.map(ServerChain::from);
		Self {
			state: ClientStateMachine::<Cms>::default(),
			client_key_provider,
			identity: None,
			server_cert,
			server_chain,
			transcript: Transcript::new(),
			key_schedule: KeySchedule::Idle,
			security_offer: None,
			strength_floor: StrengthFloor::default(),
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			provider,
			trust_store: None,
			receipt_approver: None,
			pending_receipt: None,
			stored_receipt: None,
		}
	}

	/// Set the trust store that validates the server certificate.
	#[must_use]
	pub fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.trust_store = Some(store);
		self
	}

	/// Provision the server certificate chain, ordered root to leaf.
	///
	/// When set, server authentication validates the full chain against the
	/// trust store ([RFC 5280 §6.1][rfc5280-6.1]), which covers every
	/// certificate in the path.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	#[must_use]
	pub fn with_server_certificate_chain(mut self, chain: Arc<[Certificate]>) -> Self {
		self.server_chain = Some(ServerChain::from(chain));
		self
	}

	/// Set the client identity used for mutual authentication.
	///
	/// The certificate is embedded in the client Finished message so the
	/// server can authenticate the client from the message itself, and the key
	/// bound beside it signs that message.
	#[must_use]
	pub fn with_client_identity(mut self, identity: ClientIdentity<P>) -> Self {
		self.identity = Some(identity);
		self
	}

	/// Configures the security offer for negotiation.
	///
	/// When configured, the client sends this offer to the server, and the
	/// server selects a mutually supported profile.
	#[must_use]
	pub fn with_security_offer(mut self, offer: SecurityOffer) -> Self {
		self.security_offer = Some(offer);
		self
	}

	/// Override the minimum-strength policy applied to the server's selection.
	///
	/// The default is [`DefaultStrengthFloor`], which requires a 256-bit AEAD
	/// key and a digest of 256 bits or more. The client applies it with or
	/// without an offer. Pass [`NoStrengthFloor`] only where weaker profiles
	/// must remain acceptable.
	///
	/// [`DefaultStrengthFloor`]: crate::transport::handshake::negotiation::DefaultStrengthFloor
	/// [`NoStrengthFloor`]: crate::transport::handshake::negotiation::NoStrengthFloor
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.strength_floor = StrengthFloor::with_policy(policy);
		self
	}

	/// Configures the transport capability offer (multiplexing).
	///
	/// When configured, the offer travels as an unprotected attribute in the
	/// key exchange. The server answers with a transport accept attribute.
	#[must_use]
	pub fn with_transport_offer(mut self, offer: TransportOffer) -> Self {
		self.transport_offer = Some(offer);
		self
	}

	/// Set the receipt approver deciding whether to countersign a
	/// session receipt and answering its settlement challenge.
	///
	/// Without one the client fails closed. It countersigns a challenge-free
	/// receipt, and a challenge-bearing receipt aborts the handshake.
	#[must_use]
	pub fn with_receipt_approver(mut self, approver: Arc<dyn ReceiptApprover>) -> Self {
		self.receipt_approver = Some(approver);
		self
	}

	/// The security profile that negotiation selected.
	///
	/// It is `None` before negotiation ends, or when no negotiation occurred.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile.map(|profile| profile.descriptor())
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
	}

	/// The server certificate that the base secret is encrypted to. It is the
	/// pinned certificate when set, and otherwise the provisioned chain's leaf.
	fn server_leaf(&self) -> Result<&Certificate, HandshakeError> {
		if let Some(cert) = &self.server_cert {
			return Ok(cert);
		}

		self.server_chain
			.as_ref()
			.ok_or(HandshakeError::MissingServerCertificate)?
			.leaf()
	}

	/// Validate state and server certificate for key exchange.
	///
	/// # Fail closed
	///
	/// A configured trust store is mandatory (CWE-295). Expiry alone
	/// authenticates nobody, so a missing store aborts the handshake.
	///
	/// # Paths
	///
	/// With a provisioned chain, the full path is validated
	/// ([RFC 5280 §6.1][rfc5280-6.1]) and the leaf must be the configured
	/// server certificate. Otherwise the bare certificate is evaluated against
	/// the store directly.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	fn validate_state_and_certificate(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::Init)?;

		let store = self.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		self.server_leaf()?.validate_expiry()?;

		match (&self.server_chain, &self.server_cert) {
			(Some(chain), pinned) => {
				store.verify_chain(chain.path())?;

				let leaf = chain.leaf()?;
				if pinned.as_ref().is_some_and(|cert| leaf != cert.as_ref()) {
					return Err(HandshakeError::PinnedCertificateMismatch);
				}
			}
			(None, Some(cert)) => store.evaluate(cert)?,
			(None, None) => return Err(HandshakeError::MissingServerCertificate),
		}

		Ok(())
	}

	/// Extract the server's public key from its certificate.
	fn extract_server_public_key(&self) -> Result<PublicKey<P::Curve>, HandshakeError> {
		Ok(PublicKey::<P::Curve>::from_sec1_bytes(
			self.server_leaf()?
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?)
	}

	/// Create an ephemeral keypair for the sender.
	fn create_ephemeral_keypair(
		&self,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let sender_ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let sender_pub_spki = SubjectPublicKeyInfoOwned::from_key(sender_ephemeral.public_key())?;

		Ok((sender_ephemeral, sender_pub_spki))
	}

	/// Build the recipient identifier from the server certificate.
	fn build_recipient_identifier(&self) -> Result<KeyAgreeRecipientIdentifier, HandshakeError> {
		let leaf = self.server_leaf()?;

		// A clone costs less here than an `Arc`.
		Ok(KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
			issuer: leaf.tbs_certificate.issuer.clone(),
			serial_number: leaf.tbs_certificate.serial_number.clone(),
		}))
	}

	/// Extract the server's verifying key from `server_cert`.
	fn extract_server_verifying_key(&self, server_cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		let server_public_key = server_cert.verifying_key::<P::Curve>()?;
		Ok(P::VerifyingKey::from(server_public_key))
	}

	/// Compute the signer identifier from the server's verifying key.
	fn compute_signer_identifier(&self, verifying_key: &P::VerifyingKey) -> Result<SignerIdentifier, HandshakeError> {
		Ok(compute_signer_identifier(verifying_key)?)
	}

	/// Verify the signature of a server Finished and return the transcript
	/// hash that it signed.
	fn verify_signature(
		&self,
		signed_data: &SignedData,
		server_verifying_key: P::VerifyingKey,
		expected_sid: SignerIdentifier,
	) -> Result<[u8; 32], HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<P::VerifyingKey, P::Signature, P::Digest>::from_verifying_key_with_sid(
			server_verifying_key,
			expected_sid,
		);

		// The signed content must match our transcript hash.
		let processor = TightBeamSignedDataProcessor::new(verifier);
		let digest_oid = P::Digest::OID;
		let verified_content = processor.process(signed_data, &digest_oid)?;
		let expected_hash = self.transcript.hash()?;
		// Content that names the other role is a reflected Finished.
		let signed_hash = FinishedRole::Server
			.transcript_hash(&verified_content)
			.ok_or(HandshakeError::SignatureVerificationFailed)?;

		let transcript_matches: bool = signed_hash.ct_eq(&expected_hash).into();
		if transcript_matches {
			Ok(signed_hash)
		} else {
			Err(HandshakeError::SignatureVerificationFailed)
		}
	}

	/// Build the KeyExchange message: EnvelopedData with a KARI that carries
	/// the base secret, encoded once so the transcript binds the bytes sent.
	///
	/// `rng` draws the base secret, the ephemeral key, the UKM, the CEK and
	/// the content nonce. `None` uses [`OsRng`]. Supply one on a `no_std`
	/// target without an OS-backed `getrandom`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the client is past `Init` and `HelloSent`.
	/// - [`HandshakeError::MissingTrustStore`] -- no trust store is set.
	/// - [`HandshakeError::MissingServerCertificate`] -- no server certificate or chain leaf is set.
	/// - [`HandshakeError::CertificateValidationError`] -- the server certificate or chain fails validation.
	/// - [`HandshakeError::PinnedCertificateMismatch`] -- the chain leaf differs from the pinned certificate.
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::MissingKeyWrapAlgorithm`] -- the profile names no key wrap.
	pub fn build_key_exchange(
		&mut self,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<WireDer<EnvelopedData>, HandshakeError> {
		// 1. Validate state and certificate
		self.validate_key_exchange_prerequisites()?;

		// 2. Resolve the RNG once, defaulting to OsRng, and reborrow it for
		//    each randomness draw in the key-exchange path.
		let mut os = OsRng;
		let rng: &mut dyn CryptoRngCore = rng.unwrap_or(&mut os);

		// 3. Draw the base secret, one of the two inputs of the handshake
		//    secret, fresh for this handshake (CWE-321).
		let base = BaseSecret::random(Some(rng))?;

		// 4. Extract cryptographic material. The ephemeral is cloned into the
		//    KARI builder and kept here for the agreement with the server
		//    ephemeral.
		let (server_public_key, sender_ephemeral, sender_pub_spki) = self.extract_key_exchange_crypto_material(rng)?;

		// 5. Create UKM and recipient identifier
		let ukm = self.create_user_keying_material(rng)?;
		let rid = self.build_recipient_identifier()?;

		// 6. Build KARI structure
		let kari_ephemeral = sender_ephemeral.clone();
		let kari_builder = self.build_kari_structure(kari_ephemeral, sender_pub_spki, server_public_key, rid, ukm)?;

		// 7. Create EnvelopedData with optional security offer
		let enveloped_data = self.build_enveloped_data(kari_builder, &base, rng)?;

		// 8. Update transcript and state. The transcript covers the encoded form, so it is built here.
		let key_exchange = WireDer::new(enveloped_data)?;
		let pending = PendingKeyExchange { base, ephemeral: sender_ephemeral };
		self.finalize_key_exchange(key_exchange.der(), pending)?;
		Ok(key_exchange)
	}

	/// Process the server Finished message, SignedData over the transcript
	/// hash, derive the handshake secret, and return the verified transcript
	/// hash.
	///
	/// # Transcript
	///
	/// The security accept, the transport accept, and the server ephemeral are
	/// part of the signed transcript, so the client appends them before it
	/// seals the transcript.
	///
	/// - A tampered attribute diverges the hashes and fails signature verification (CWE-345).
	/// - The client appends the received encoding, so a peer cannot reorder a
	///   `SET OF` into a form the decoder normalises back to the signed one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no key exchange was sent.
	/// - [`HandshakeError::DuplicateAttribute`] -- an accept or ephemeral attribute repeats.
	/// - [`HandshakeError::MissingAttribute`] -- the Finished carries no server ephemeral.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the signature or
	///   the signed transcript hash is wrong.
	/// - [`HandshakeError::InvalidPublicKey`] -- the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected a
	///   profile outside the offer, or answered no offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the receipt disagrees with the negotiated session.
	pub fn process_server_finished(&mut self, server_finished: &SignedData) -> Result<[u8; 32], HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Extract the server's SecurityAccept, TransportAccept, and
		//    ephemeral, and append their received bytes before the transcript
		//    seals. The ephemeral is mandatory, so its absence is refused here.
		let received_accept = ReceivedAttribute::<SecurityAccept>::extract(server_finished)?;
		let (accept, accept_bytes) = received_accept.map(ReceivedAttribute::into_parts).unzip();
		let received_transport_accept = ReceivedAttribute::<TransportAccept>::extract(server_finished)?;
		let (transport_accept, transport_accept_bytes) =
			received_transport_accept.map(ReceivedAttribute::into_parts).unzip();
		let received_ephemeral = ReceivedAttribute::<OriginatorPublicKey>::extract(server_finished)?;
		let received_ephemeral = received_ephemeral.ok_or(HandshakeError::MissingAttribute)?;
		let (server_ephemeral, server_ephemeral_bytes) = received_ephemeral.into_parts();

		let legs = ServerFinishedLegs {
			security_accept: accept_bytes,
			transport_accept: transport_accept_bytes,
			server_ephemeral: server_ephemeral_bytes,
		};
		self.transcript.append_server_finished(legs)?;
		self.transcript.seal::<P::Digest>()?;

		// 3. Extract cryptographic material
		let server_verifying_key = self.extract_server_verifying_key(self.server_leaf()?)?;
		let expected_signer_identifier = self.compute_signer_identifier(&server_verifying_key)?;

		// 4. Verify signature and content
		let verified_content =
			self.verify_signature(server_finished, server_verifying_key, expected_signer_identifier)?;

		// 5. Derive the handshake secret from the base secret and the agreement
		//    of the kept KARI ephemeral with the server ephemeral the signature
		//    just authenticated.
		self.derive_handshake_secret(&server_ephemeral)?;

		// 6. Validate the selections against our own offers and store them
		self.apply_security_accept(accept)?;
		self.mux_settings = MuxSettings::for_client(self.transport_offer.as_ref(), transport_accept.as_ref())?;

		// 7. Validate the session receipt. The client Finished countersigns it later.
		self.process_session_receipt(server_finished, transport_accept.as_ref())?;

		// 8. Transition state. The transcript sealed in step 2, so the server
		//    Finished itself is not part of it.
		self.state.transition(ClientHandshakeState::ServerFinishedReceived)?;

		Ok(verified_content)
	}

	/// Derive the handshake secret from the pending key exchange and the
	/// authenticated server ephemeral, parsed beside the static key it must
	/// differ from. The pending pair drops when this function returns.
	fn derive_handshake_secret(&mut self, server_ephemeral: &OriginatorPublicKey) -> Result<(), HandshakeError> {
		let static_key = self.extract_server_public_key()?;
		let server_ephemeral = static_key.server_ephemeral(server_ephemeral.public_key.raw_bytes())?;
		let PendingKeyExchange { base, ephemeral } = self.key_schedule.take_pending()?;
		let shared = ephemeral.shared_secret(&server_ephemeral)?;
		let transcript_hash = self.transcript.hash()?;
		let handshake_secret = HandshakeSecret::derive::<P>(&base, &shared, KdfSalt::new(&transcript_hash))?;
		self.key_schedule.store(handshake_secret)?;
		Ok(())
	}

	/// Validate the server's `SecurityAccept` selection and store the profile.
	///
	/// # Validation
	///
	/// - When an offer was sent, the accepted profile must be a member of it.
	/// - With or without an offer, the accepted profile must meet the strength floor.
	/// - When no attribute is present, the selection stays `None`. The
	///   trait-level `complete()` then fails closed, which holds an unknown
	///   profile out of the session.
	fn apply_security_accept(&mut self, accept: Option<SecurityAccept>) -> Result<(), HandshakeError> {
		match (accept, &self.security_offer) {
			(Some(accept), Some(offer)) => {
				if !offer.profiles.contains(&accept.profile) {
					return Err(HandshakeError::InvalidProfileSelection);
				}

				let profile = RunnableProfile::<P>::try_from(accept.profile)?;
				self.strength_floor.admit(&profile)?;
				self.selected_profile = Some(profile);
			}
			(Some(accept), None) => {
				// With no offer, the server chooses, bounded by the floor.
				let profile = RunnableProfile::<P>::try_from(accept.profile)?;
				self.strength_floor.admit(&profile)?;
				self.selected_profile = Some(profile);
			}
			(None, Some(_)) => {
				// The client offered profiles, and the server did not answer.
				return Err(HandshakeError::InvalidProfileSelection);
			}
			(None, None) => {}
		}

		Ok(())
	}

	/// Validate the server's session receipt from the Finished attributes.
	///
	/// Budget-bearing accepts demand a receipt artifact whose body
	/// matches the negotiated session and whose server `SignerInfo`
	/// verifies. Anything else fails closed. The validated body and
	/// artifact are retained for countersigning in the client Finished.
	fn process_session_receipt(
		&mut self,
		signed_data: &SignedData,
		transport_accept: Option<&TransportAccept>,
	) -> Result<(), HandshakeError> {
		let granted = transport_accept.and_then(|accept| accept.granted_budgets);
		let credit_unit = transport_accept.map(|accept| accept.credit_unit);
		let received_artifact = ReceivedAttribute::<SignedData>::extract(signed_data)?;
		let artifact = received_artifact.map(|received| received.into_parts().0);
		let transcript_digest = self.transcript.hash()?;

		let parsed_receipt = artifact.as_ref().map(ReceiptArtifact::receipt).transpose()?;
		let Some(receipt) =
			SessionReceipt::match_accept::<P::Digest>(parsed_receipt, granted, credit_unit, &transcript_digest)?
		else {
			return Ok(());
		};

		// The server SignerInfo over the receipt body makes the agreement
		// verifiable by a third party, so an unsigned receipt is no receipt.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let server_signer = artifact
			.signer_for_role(ReceiptRole::Server)?
			.ok_or(HandshakeError::ReceiptMissing)?;

		let expected_sid = self.server_leaf()?.signer_identifier::<P::Digest>()?;
		let verifying_key = self.extract_server_verifying_key(self.server_leaf()?)?;
		receipt.verify_signer::<P::Digest, P::Signature, _>(
			server_signer,
			ReceiptRole::Server,
			&expected_sid,
			&verifying_key,
		)?;

		self.pending_receipt = Some((receipt, artifact));

		Ok(())
	}

	/// Approve, answer, and countersign the pending session receipt.
	///
	/// The approver (or the fail-closed default) answers the settlement
	/// challenge, and the client `SignerInfo` binds receipt body plus
	/// answer under the client identity (non-repudiation). Returns
	/// the unsigned attributes destined for the client Finished's
	/// SignerInfo.
	///
	/// # Fail closed
	///
	/// A countersignature needs a client identity the server can verify, so a
	/// budget without mutual authentication fails with
	/// [`HandshakeError::MutualAuthRequired`]. That check runs before
	/// approval, because approval can spend an irreversible settlement answer.
	///
	/// # Confidentiality
	///
	/// The client SignerInfo, and the bearer answer bound in its signed
	/// attributes, travel sealed under the handshake secret's acknowledgement
	/// key, which keeps both off the cleartext SignedData. What that key
	/// withholds from a holder of the server's static key is stated under
	/// [forward secrecy](crate::transport::handshake#forward-secrecy).
	async fn countersign_pending_receipt(&mut self) -> Result<Option<Attributes>, HandshakeError> {
		let Some((receipt, server_artifact)) = self.pending_receipt.take() else {
			return Ok(None);
		};

		let identity = self.identity.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
		let key_provider = identity.signing_provider();

		let approver = self.receipt_approver.as_deref();
		let response = receipt.approve(approver).await?;
		let answer = response.as_ref().map(OctetString::as_bytes);
		let countersignature = receipt.countersign::<P::Digest>(answer, key_provider).await?;

		let handshake_secret = self.key_schedule.derived()?;
		let transcript_hash = self.transcript.hash()?;
		let ack_der = Zeroizing::new(countersignature.to_der()?);
		let sealed_ack = handshake_secret.seal_ack::<P>(KdfSalt::new(&transcript_hash), &transcript_hash, &ack_der)?;
		let sealed_ack = OctetString::new(sealed_ack)?;
		let ack_attr = HandshakeAttribute::encode(&sealed_ack)?;

		let values = SetOfVec::try_from(ack_attr.attr_values)?;
		let x509_attrs = vec![Attribute { oid: ack_attr.attr_type, values }];

		// Both endpoints retain the identical completed artifact.
		let completed = server_artifact.complete(countersignature)?;
		self.stored_receipt = Some(StoredReceipt::try_from(completed)?);

		Ok(Some(Attributes::try_from(x509_attrs)?))
	}

	/// Build the client Finished message, a SignedData over the transcript
	/// hash.
	///
	/// The client Finished closes the client's side of the transcript, so the
	/// transcript is already sealed when this runs.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server Finished has not been processed.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	/// - [`HandshakeError::MutualAuthRequired`] -- a pending receipt needs a
	///   client identity, and none is set.
	/// - [`HandshakeError::ApprovalRefused`] -- the receipt approver refused.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal the countersignature.
	pub async fn build_client_finished(&mut self) -> Result<SignedData, HandshakeError> {
		// 1. Validate state
		self.validate_client_finished_prerequisites()?;

		// 2. Get transcript hash and prepare digest
		let (transcript_hash, digest) = self.prepare_finished_digest()?;

		// 3. Sign the digest
		let signature_bytes = self.sign_finished_digest(&digest).await?;

		// 4. Build cryptographic components
		let signer = self.build_finished_crypto_components().await?;

		// 5. Countersign the session receipt. The signature and the settlement
		//    answer travel as SignerInfo unsigned attributes.
		let receipt_attrs = self.countersign_pending_receipt().await?;

		// 6. Build SignedData structure
		let signed_data = self.build_signed_data(transcript_hash, &signature_bytes, signer, receipt_attrs)?;

		// 7. Transition state
		self.finalize_client_finished()?;

		Ok(signed_data)
	}

	/// The current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The dual-signed session receipt.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	/// The server peer identity, which is the pinned certificate or the chain
	/// leaf used for encryption.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.server_leaf().ok()
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// This is the single home for CMS client completion. The trait
	/// implementation delegates here, so driver and test read the session
	/// terms the same way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the machine has not sent its
	///   Finished, or the negotiated profile is missing.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError>
	where
		P::AeadCipher: KeyInit + 'static,
	{
		// 1. Validate state
		if self.state.state() != ClientHandshakeState::ClientFinishedSent {
			return Err(HandshakeError::InvalidState);
		}

		// 2. Take the handshake secret. It drops when this function returns,
		//    so completion is the one derivation from it.
		let handshake_secret = self.key_schedule.take_derived()?;
		let transcript = self.transcript.hash()?;

		// 3. Derive directional session keys as P::AeadCipher
		let ciphers = self.derive_directional_aead(&handshake_secret, KdfSalt::new(&transcript))?;

		// 4. Seed epoch materials for post-handshake renewal
		let epoch_salt = KdfSalt::new(&transcript);
		let materials = EpochMaterials::derive::<P>(&handshake_secret, epoch_salt, transcript)?;

		// 5. Transition to complete
		self.state.transition(ClientHandshakeState::Completed)?;

		// 6. Role-map the directional ciphers. The orchestrator is spent, so
		//    the receipt moves out, and the session shares the leaf handle
		//    that both identity forms hold.
		#[cfg(feature = "x509")]
		let peer = match (&self.server_cert, &self.server_chain) {
			(Some(cert), _) => Some(Arc::clone(cert)),
			(None, Some(chain)) => chain.leaf_handle(),
			(None, None) => None,
		};

		let keys = SessionKeys::for_client(ciphers);
		let mux = self.mux_settings;
		let receipt = self.stored_receipt.take().map(Arc::new);
		let epoch = Some(materials);
		Ok(EstablishedSession::new(keys, mux, receipt, peer, epoch))
	}

	/// Validate state and certificate for key exchange.
	fn validate_key_exchange_prerequisites(&self) -> Result<(), HandshakeError> {
		// Accept Init for a fresh handshake, or HelloSent for a future hello
		// phase.
		if self.state.state() == ClientHandshakeState::Init {
			self.validate_state_and_certificate()?;
		} else if self.state.state() != ClientHandshakeState::HelloSent {
			return Err(HandshakeError::InvalidState);
		}

		Ok(())
	}

	/// Extract cryptographic material needed for key exchange.
	#[allow(clippy::type_complexity)]
	fn extract_key_exchange_crypto_material(
		&self,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(PublicKey<P::Curve>, SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let server_public_key = self.extract_server_public_key()?;
		let (sender_ephemeral, sender_pub_spki) = self.create_ephemeral_keypair(rng)?;
		Ok((server_public_key, sender_ephemeral, sender_pub_spki))
	}

	/// Create user keying material for the key agreement.
	fn create_user_keying_material(&self, rng: &mut dyn CryptoRngCore) -> Result<UserKeyingMaterial, HandshakeError> {
		let ukm_bytes = generate_nonce::<64>(Some(rng))?;
		UserKeyingMaterial::new(ukm_bytes.to_vec()).map_err(Into::into)
	}

	/// Build the KARI structure with all required components.
	fn build_kari_structure(
		&self,
		sender_ephemeral: SecretKey<P::Curve>,
		sender_pub_spki: SubjectPublicKeyInfoOwned,
		server_public_key: PublicKey<P::Curve>,
		rid: KeyAgreeRecipientIdentifier,
		ukm: UserKeyingMaterial,
	) -> Result<TightBeamKariBuilder<P>, HandshakeError> {
		let key_wrap_oid =
			<P::Profile as SecurityProfile>::KEY_WRAP_OID.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
		let key_enc_alg = AlgorithmIdentifierOwned { oid: key_wrap_oid, parameters: None };
		let kari_builder = TightBeamKariBuilder::new(self.provider)
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(server_public_key)
			.with_recipient_rid(rid)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		Ok(kari_builder)
	}

	/// Build the EnvelopedData over `base`, with the optional security and
	/// transport offers.
	fn build_enveloped_data(
		&self,
		kari_builder: TightBeamKariBuilder<P>,
		base: &BaseSecret,
		rng: &mut dyn CryptoRngCore,
	) -> Result<EnvelopedData, HandshakeError> {
		let mut enveloped_builder = TightBeamEnvelopedDataBuilder::new(kari_builder);

		// Each configured offer travels as an unprotected attribute.
		if let Some(ref offer) = self.security_offer {
			let offer_attr = HandshakeAttribute::encode(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}
		if let Some(ref offer) = self.transport_offer {
			let offer_attr = HandshakeAttribute::encode(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}

		if let Some(cert_attr) = self.client_certificate_attr()? {
			enveloped_builder = enveloped_builder.with_unprotected_attr(cert_attr);
		}

		enveloped_builder.build(base.as_bytes(), Some(rng))
	}

	/// The client certificate as a key-exchange unprotected attribute, when the
	/// client presents an identity.
	///
	/// The attribute enters the transcript the server signs and the client
	/// verifies, and the server requires the client Finished to embed the same
	/// certificate, which binds the session to this identity (CWE-287,
	/// CWE-345).
	fn client_certificate_attr(&self) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		self.identity
			.as_ref()
			.map(|identity| HandshakeAttribute::encode(identity.certificate()))
			.transpose()
	}

	/// Finalize the key exchange by updating the transcript and the state.
	fn finalize_key_exchange(
		&mut self,
		enveloped_data_der: impl AsRef<[u8]>,
		pending: PendingKeyExchange<P>,
	) -> Result<(), HandshakeError> {
		let enveloped_data_der = enveloped_data_der.as_ref();
		self.transcript.append(enveloped_data_der)?;

		self.key_schedule.pend(pending)?;
		// On the CMS path, KeyExchangeSent follows Init directly.
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(())
	}

	/// Validate the prerequisites for building the client Finished message.
	fn validate_client_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::ServerFinishedReceived)
	}

	/// Prepare the transcript hash and compute the digest to sign.
	fn prepare_finished_digest(&self) -> Result<([u8; 32], Vec<u8>), HandshakeError> {
		let transcript_hash = self.transcript.hash()?;
		let content = FinishedRole::Client.content(&transcript_hash);

		let mut hasher = P::Digest::new();
		hasher.update(&content);

		let digest = hasher.finalize();
		let digest_bytes = digest.to_vec();

		Ok((transcript_hash, digest_bytes))
	}

	/// The key that signs this client's Finished message.
	///
	/// A configured identity carries the key that proves its certificate, so
	/// the signature and the embedded certificate name one key. Without an
	/// identity the endpoint signs anonymously with the key it was built from.
	fn signing_provider(&self) -> &dyn SigningKeyProvider {
		match self.identity.as_ref() {
			Some(identity) => identity.signing_provider(),
			None => self.client_key_provider.as_ref(),
		}
	}

	/// Sign the finished digest with this client's signing key.
	async fn sign_finished_digest(&self, digest: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signature_bytes = self.signing_provider().sign_prehash(digest).await?;
		Ok(signature_bytes)
	}

	/// Build the signer identity and algorithm identifiers for the SignedData.
	async fn build_finished_crypto_components(&self) -> Result<FinishedSigner, HandshakeError> {
		let public_key_bytes = self.signing_provider().to_public_key_bytes().await?;

		let id = compute_signer_identifier_from_der(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };
		Ok(FinishedSigner { id, digest_alg, signature_alg })
	}

	/// Build the complete SignedData structure.
	///
	/// A configured client certificate is embedded in the `certificates`
	/// field so the server can authenticate the client from the message.
	fn build_signed_data(
		&self,
		transcript_hash: [u8; 32],
		signature_bytes: &[u8],
		signer: FinishedSigner,
		unsigned_attrs: Option<Attributes>,
	) -> Result<SignedData, HandshakeError> {
		let FinishedSigner { id, digest_alg, signature_alg } = signer;
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: id,
			// The same OID lives in SignerInfo and in the SignedData
			// digestAlgorithms SET.
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature_bytes)?,
			unsigned_attrs,
		};

		let octet_string = OctetString::new(FinishedRole::Client.content(&transcript_hash))?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = Any::from_der(&econtent_der)?;
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent_any) };

		let certificates = self
			.identity
			.as_ref()
			.map(|identity| {
				// CMS CertificateSet owns the cert. The identity keeps its Arc.
				let choice = CertificateChoices::Certificate(identity.certificate().to_owned());
				Ok::<_, HandshakeError>(CertificateSet(vec![choice].try_into()?))
			})
			.transpose()?;

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		})
	}

	/// Finalize the client Finished by transitioning the state.
	fn finalize_client_finished(&mut self) -> Result<(), HandshakeError> {
		self.state.transition(ClientHandshakeState::ClientFinishedSent)?;
		Ok(())
	}
}

/// A negotiated value and the bytes it arrived as.
///
/// The handshake acts on the value and the transcript binds the bytes, so the
/// two are taken from one attribute together and describe one encoding.
struct ReceivedAttribute<T> {
	value: T,
	transcript_bytes: Vec<u8>,
}

impl<T> ReceivedAttribute<T> {
	/// Split the attribute into the value the handshake acts on and the bytes
	/// the transcript binds.
	fn into_parts(self) -> (T, Vec<u8>) {
		(self.value, self.transcript_bytes)
	}

	/// Read the attribute `T` names from the Finished unsigned attributes,
	/// keeping its received encoding.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] -- the attribute repeats.
	/// - [`HandshakeError::DerError`] -- the attribute fails to decode as `T`.
	fn extract(signed_data: &SignedData) -> Result<Option<Self>, HandshakeError>
	where
		T: AttributePayload + for<'a> Choice<'a> + for<'a> DecodeValue<'a>,
	{
		let Some(attr) = signed_data.find_unsigned_attr(T::OID)? else {
			return Ok(None);
		};

		let transcript_bytes = attr.received_bytes()?;
		let value = attr.decode::<T>()?;
		Ok(Some(Self { value, transcript_bytes }))
	}
}

impl<P> HandshakeFinalization<P> for CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<RunnableProfile<P>> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for CmsHandshakeClient<P> where P: CryptoProvider {}

impl<P> ClientHandshakeProtocol for CmsHandshakeClient<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::Signature: LowSEncoding + 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: Send + Sync + KeyInit,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, Self::Error>> {
		Box::pin(async move {
			let key_exchange = self.build_key_exchange(None)?;
			Ok(HandshakeMessage::EnvelopedData(Box::new(key_exchange)))
		})
	}

	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			// The envelope decoded the server Finished once, and every check
			// reads that value.
			let server_finished = msg.signed()?;

			self.process_server_finished(server_finished.value())?;

			let client_finished = self.build_client_finished().await?;
			Ok(Some(HandshakeMessage::try_from(client_finished)?))
		})
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
		Box::pin(async move {
			let mut client = self;
			client.take_established()
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile.map(|profile| profile.descriptor())
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::{
		CmsHandshakeClient, EnvelopedData, FinishedRole, KeySchedule, OriginatorPublicKey, ReceivedAttribute,
		SignedData,
	};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::sign::elliptic_curve::SecretKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::der::asn1::{BitString, SetOfVec};
	use crate::der::{Decode, Encode};
	use crate::oids::{HANDSHAKE_SECURITY_ACCEPT, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::random::OsRng;
	use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
	use crate::testing::fixtures::TestCertificate;
	use crate::transport::handshake::attributes::HandshakeAttribute;
	use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	use crate::transport::handshake::error::HandshakeError;
	use crate::transport::handshake::kari::OriginatorKey;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer};
	use crate::transport::handshake::primitives::transcript::Transcript;
	use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
	use crate::transport::handshake::state::ClientHandshakeState;
	use crate::transport::handshake::tests::*;
	use crate::transport::wire_der::WireDer;
	use crate::x509::attr::{Attribute, Attributes};
	use crate::x509::Certificate;

	/// The originator key of a fresh secp256k1 ephemeral, as a server sends it.
	fn fresh_server_ephemeral() -> Result<OriginatorPublicKey, Box<dyn Error>> {
		let public_key = SecretKey::<Secp256k1>::random(&mut OsRng).public_key();
		let spki_der = public_key.to_public_key_der()?;
		Ok(SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?.originator_key()?)
	}

	/// `ephemeral` with its point bytes replaced by `point`.
	fn with_point(ephemeral: OriginatorPublicKey, point: &[u8]) -> Result<OriginatorPublicKey, Box<dyn Error>> {
		Ok(OriginatorPublicKey { algorithm: ephemeral.algorithm, public_key: BitString::from_bytes(point)? })
	}

	/// Replace the unsigned attributes of the one signer of `signed`.
	fn set_unsigned_attrs(signed: &mut SignedData, attrs: Option<Attributes>) -> Result<(), Box<dyn Error>> {
		let mut signer_infos: Vec<_> = signed.signer_infos.0.iter().cloned().collect();
		let signer = signer_infos.first_mut().ok_or("a Finished has one signer")?;
		signer.unsigned_attrs = attrs;
		signed.signer_infos = signer_infos.try_into()?;
		Ok(())
	}

	/// The attribute set that carries `ephemeral` alone.
	fn ephemeral_attrs(ephemeral: &OriginatorPublicKey) -> Result<Attributes, Box<dyn Error>> {
		let attribute = Attribute::try_from(HandshakeAttribute::encode(ephemeral)?)?;
		Ok(Attributes::try_from(vec![attribute])?)
	}

	/// A server Finished signed by `server_key` over the transcript of
	/// `key_exchange` followed by `ephemeral`, as a server that negotiated
	/// nothing sends it, with the transcript hash it signed.
	fn server_finished_over(
		server_key: &Secp256k1SigningKey,
		key_exchange: &WireDer<EnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> Result<(SignedData, [u8; 32]), Box<dyn Error>> {
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(ephemeral)?;
		let transcript_hash =
			Transcript::digest::<Sha3_256>([key_exchange.der(), ephemeral_bytes.as_slice()].concat())?;
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
		let builder =
			TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(server_key, digest_alg, signature_alg)?;

		let mut signed = builder.build(FinishedRole::Server.content(&transcript_hash))?;
		set_unsigned_attrs(&mut signed, Some(ephemeral_attrs(ephemeral)?))?;
		Ok((signed, transcript_hash))
	}

	/// A client pinned to `server_certificate` that has sent its key
	/// exchange, with that key exchange.
	fn client_after_key_exchange(
		server_certificate: &Certificate,
	) -> Result<(CmsHandshakeClient<DefaultCryptoProvider>, WireDer<EnvelopedData>), Box<dyn Error>> {
		let mut client = TestCmsClientBuilder::new()
			.with_server_cert(server_certificate.to_owned())
			.build()?;
		let key_exchange = client.build_key_exchange(None)?;
		Ok((client, key_exchange))
	}

	#[tokio::test]
	async fn test_client_state_flow() -> Result<(), Box<dyn Error>> {
		// Given: A CMS client in init state with a server certificate
		let server_test_cert = create_test_certificate();
		let server_cert = server_test_cert.certificate.to_owned();
		let mut client = TestCmsClientBuilder::new().with_server_cert(server_cert).build()?;
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: Client builds a valid key exchange
		let enveloped_data = client.build_key_exchange(None)?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		// The client keeps the base secret and its ephemeral for the Finished.
		assert!(matches!(client.key_schedule, KeySchedule::Pending(_)));

		// Then: Server should be able to decrypt the 32-byte base secret using
		// the matching private key
		let server_secret = SecretKey::from(server_test_cert.signing_key.to_owned());
		let provider = DefaultCryptoProvider::default();
		let kari_processor = TightBeamKariRecipient::new(provider, server_secret);
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(kari_processor);
		let decrypted = processor.process(enveloped_data.value())?;
		let decrypted = ToInsecure::to_insecure(decrypted);
		assert_eq!(decrypted.len(), 32);

		// When: Client processes a server Finished over the transcript, which
		// holds the key exchange and the server ephemeral because the server
		// accepted nothing
		let ephemeral = fresh_server_ephemeral()?;
		let (server_finished, transcript_hash) =
			server_finished_over(&server_test_cert.signing_key, &enveloped_data, &ephemeral)?;
		let verified = client.process_server_finished(&server_finished)?;
		assert_eq!(verified, transcript_hash);
		assert_eq!(client.state(), ClientHandshakeState::ServerFinishedReceived);
		assert!(matches!(client.key_schedule, KeySchedule::Derived(_)));

		// When: Client builds its Finished
		let _client_finished = client.build_client_finished().await?;
		assert_eq!(client.state(), ClientHandshakeState::ClientFinishedSent);

		// The terminal transition belongs to the real completion, which derives
		// the keys, so the machine rests at its last pre-terminal state.
		assert!(!client.is_complete());

		Ok(())
	}

	/// A server ephemeral swapped for another valid point after a real server
	/// signed its Finished changes the transcript, so the Finished signature
	/// fails before any agreement.
	#[tokio::test]
	async fn a_tampered_server_ephemeral_fails_the_cms_finished() -> Result<(), Box<dyn Error>> {
		let server_identity = create_test_certificate();
		let (mut server, _) = TestCmsServerBuilder::new()
			.with_key(server_identity.signing_key.to_owned())
			.build();
		let (mut client, key_exchange) = client_after_key_exchange(&server_identity.certificate)?;
		server.process_key_exchange(&key_exchange).await?;
		let mut server_finished = server.build_server_finished().await?;
		set_unsigned_attrs(&mut server_finished, Some(ephemeral_attrs(&fresh_server_ephemeral()?)?))?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A server Finished without the ephemeral attribute is refused before
	/// the transcript seals, so no session forms without the agreement.
	#[test]
	fn a_missing_server_ephemeral_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server.certificate)?;
		let (mut server_finished, _) =
			server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral()?)?;
		set_unsigned_attrs(&mut server_finished, None)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::MissingAttribute)));
		Ok(())
	}

	/// A validly signed server ephemeral that encodes the identity point is
	/// refused at the parse, before any scalar multiplication.
	#[test]
	fn an_identity_server_ephemeral_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server.certificate)?;
		let identity = with_point(fresh_server_ephemeral()?, &[0x00])?;
		let (server_finished, _) = server_finished_over(&server.signing_key, &key_exchange, &identity)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// A validly signed server ephemeral whose x-coordinate lies off the
	/// curve is refused at the parse, before any scalar multiplication.
	#[test]
	fn an_off_curve_server_ephemeral_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server.certificate)?;
		let off_curve = with_point(fresh_server_ephemeral()?, &off_curve_point())?;
		let (server_finished, _) = server_finished_over(&server.signing_key, &key_exchange, &off_curve)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[test]
	fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server.certificate)?;
		let static_key = server.signing_key.verifying_key().originator_key()?;
		let (server_finished, _) = server_finished_over(&server.signing_key, &key_exchange, &static_key)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// Completion takes the handshake secret, so the orchestrator holds no
	/// key material afterwards. The key schedule's take is the close, and
	/// this unit test reads the variant it leaves behind.
	#[tokio::test]
	async fn completion_consumes_the_handshake_secret() -> Result<(), Box<dyn Error>> {
		let server_identity = create_test_certificate();
		let (server, _) = TestCmsServerBuilder::new()
			.with_key(server_identity.signing_key.to_owned())
			.build();
		let mut server = server.with_supported_profiles(vec![create_default_test_profile()]);
		let (mut client, key_exchange) = client_after_key_exchange(&server_identity.certificate)?;
		server.process_key_exchange(&key_exchange).await?;
		let server_finished = server.build_server_finished().await?;
		client.process_server_finished(&server_finished)?;
		client.build_client_finished().await?;

		client.take_established()?;
		assert!(matches!(client.key_schedule, KeySchedule::Consumed));
		Ok(())
	}

	fn trust_store(root: Option<Certificate>) -> Result<Arc<dyn CertificateTrust>, Box<dyn Error>> {
		let mut builder = CertificateTrustBuilder::from(Secp256k1Policy);
		if let Some(root) = root {
			builder = builder.with_certificate(root)?;
		}

		Ok(Arc::new(builder.build()))
	}

	fn client_key() -> Arc<dyn crate::crypto::key::SigningKeyProvider> {
		into_provider(create_test_certificate().signing_key)
	}

	fn chain_client(
		chain: Arc<[Certificate]>,
		store_root: Option<Certificate>,
	) -> Result<CmsHandshakeClient<DefaultCryptoProvider>, Box<dyn Error>> {
		Ok(CmsHandshakeClient::<DefaultCryptoProvider>::from_chain(
			DefaultCryptoProvider::default(),
			client_key(),
			chain,
		)
		.with_trust_store(trust_store(store_root)?))
	}

	/// A client without a trust store aborts, ahead of
	/// expiry-only server authentication (CWE-295).
	#[test]
	fn test_missing_trust_store_fails_closed() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let mut client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			into_provider(server.signing_key),
			Arc::new(server.certificate),
		);

		let result = client.build_key_exchange(None);
		assert!(matches!(result, Err(HandshakeError::MissingTrustStore)));
		Ok(())
	}

	/// A chain-provisioned client path-validates the chain and encrypts to
	/// its leaf. No separate pinned certificate is needed.
	#[test]
	fn from_chain_validates_and_targets_leaf() -> Result<(), Box<dyn Error>> {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut client = chain_client(chain.to_arc(), Some(chain.root.to_owned()))?;
		client.build_key_exchange(None)?;

		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert_eq!(client.server_leaf()?, &chain.leaf);
		Ok(())
	}

	#[test]
	fn from_chain_rejects_untrusted_chain() -> Result<(), Box<dyn Error>> {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut client = chain_client(chain.to_arc(), None)?;
		let result = client.build_key_exchange(None);
		assert!(matches!(result, Err(HandshakeError::CertificateValidationError(_))));
		Ok(())
	}

	/// A pinned server certificate that differs from the provisioned chain
	/// leaf is a configuration mismatch, distinct from a re-handshake
	/// identity violation.
	#[test]
	fn pinned_certificate_mismatch_rejected() -> Result<(), Box<dyn Error>> {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let pinned = Arc::new(create_test_certificate().certificate);
		let mut client =
			CmsHandshakeClient::<DefaultCryptoProvider>::new(DefaultCryptoProvider::default(), client_key(), pinned)
				.with_server_certificate_chain(chain.to_arc())
				.with_trust_store(trust_store(Some(chain.root.to_owned()))?);

		let result = client.build_key_exchange(None);
		assert!(matches!(result, Err(HandshakeError::PinnedCertificateMismatch)));
		Ok(())
	}

	#[test]
	fn from_chain_rejects_empty_chain() -> Result<(), Box<dyn Error>> {
		let chain = TestCertificate::insecure_fixed_chain()?;
		let mut client = chain_client(Arc::from(Vec::new()), Some(chain.root))?;
		let result = client.build_key_exchange(None);
		assert!(matches!(result, Err(HandshakeError::MissingServerCertificate)));
		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
		// Given: A CMS client in init state
		let mut client = TestCmsClientBuilder::new().build()?;

		// When: Trying to process server finished before sending key exchange
		let server_finished = create_test_signed_data([]);
		let result = client.process_server_finished(&server_finished);
		assert!(result.is_err());

		// When: Trying to build client finished before processing server
		// finished
		let result = client.build_client_finished().await;
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_process_security_accept_rejects_unoffered_profile() -> Result<(), Box<dyn Error>> {
		let offered = create_default_test_profile();
		let unoffered = SecurityProfileDesc { digest: Some(crate::oids::HASH_SHA3_512), ..offered };

		let build_finished_with_accept = |profile| -> Result<Vec<u8>, Box<dyn Error>> {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
			let builder =
				TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(&signing_key, digest_alg, signature_alg)?;

			let accept_attr = HandshakeAttribute::encode(&SecurityAccept::new(profile))?;
			let x509_attr = Attribute {
				oid: HANDSHAKE_SECURITY_ACCEPT,
				values: SetOfVec::try_from(accept_attr.attr_values)?,
			};

			let mut signed_data = builder.build([7u8; 32])?;
			let attrs = Attributes::try_from(vec![x509_attr])?;
			let mut signer_infos: Vec<_> = signed_data.signer_infos.0.iter().cloned().collect();

			signer_infos[0].unsigned_attrs = Some(attrs);
			signed_data.signer_infos = signer_infos.try_into()?;

			Ok(signed_data.to_der()?)
		};

		let offer = SecurityOffer::new(vec![offered]);
		let mut client = TestCmsClientBuilder::new().build()?.with_security_offer(offer);

		let accepted = SignedData::from_der(&build_finished_with_accept(offered)?)?;
		let accept = ReceivedAttribute::<SecurityAccept>::extract(&accepted)?;
		client.apply_security_accept(accept.map(|attr| attr.value))?;
		assert_eq!(client.selected_profile(), Some(offered));

		let rejected = SignedData::from_der(&build_finished_with_accept(unoffered)?)?;
		let attrs = ReceivedAttribute::<SecurityAccept>::extract(&rejected)?;
		let result = client.apply_security_accept(attrs.map(|attr| attr.value));
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));

		Ok(())
	}

	// Without an offer the server chooses, and the client floor still bounds
	// that choice, so a selection below the floor stays out of the session.
	#[test]
	fn a_dealers_choice_client_refuses_a_profile_below_its_floor() -> Result<(), Box<dyn Error>> {
		use crate::transport::handshake::negotiation::{NegotiationError, ProfileStrength, ProfileStrengthPolicy};

		struct RefuseAll;

		impl ProfileStrengthPolicy for RefuseAll {
			fn meets_floor(&self, _strength: &ProfileStrength) -> bool {
				false
			}
		}

		let mut client = TestCmsClientBuilder::new().build()?.with_strength_policy(Arc::new(RefuseAll));
		let result = client.apply_security_accept(Some(SecurityAccept::new(create_default_test_profile())));
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::BelowStrengthFloor))
		));
		assert_eq!(client.selected_profile(), None);
		Ok(())
	}

	// A signed accept that names an algorithm the provider does not run is
	// refused, so the session never runs under a false identity.
	#[test]
	fn a_dealers_choice_client_refuses_a_profile_it_does_not_run() -> Result<(), Box<dyn Error>> {
		use crate::transport::handshake::negotiation::NegotiationError;

		let foreign = SecurityProfileDesc { aead: Some(crate::oids::AES_128_GCM), ..create_default_test_profile() };
		let mut client = TestCmsClientBuilder::new().build()?;
		let result = client.apply_security_accept(Some(SecurityAccept::new(foreign)));
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::UnrunnableProfile))
		));
		assert_eq!(client.selected_profile(), None);
		Ok(())
	}
}

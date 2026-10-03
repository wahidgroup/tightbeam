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
use crate::crypto::aead::SessionKeys;
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile, SecurityProfileDesc};
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
use crate::crypto::x509::Certificate;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Choice, Decode, DecodeValue, Encode};
use crate::oids::DATA;
use crate::random::{generate_nonce, CryptoRngCore, OsRng, RngWrapper};
use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::AttributePayload;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamKariBuilder};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfilePolicy, ProfileStrengthPolicy, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::orchestrator::{
	Agreed, Agreement, BaseSecret, HandshakeVerifyingKey, KeySchedule, Salt, ServerEphemeral, Terms,
};
use crate::transport::handshake::peer::{AdmittedServer, ProvisionedTrust};
use crate::transport::handshake::primitives::transcript::{FinishedRole, ServerFinishedLegs, Transcript};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::{PendingReceipt, ReceiptApprover, StoredReceipt};
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine, Cms};
use crate::transport::handshake::{Arc, ClientHandshakeProtocol, CmsServerIdentity, HandshakeProvider};
use crate::transport::handshake::{EstablishedSession, HandshakeMessage};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};

/// Client-side CMS handshake orchestrator.
///
/// It is generic over `P: HandshakeProvider`, which defines the cryptographic
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
	P: HandshakeProvider,
{
	state: ClientStateMachine<Cms>,
	client_key_provider: Arc<dyn SigningKeyProvider>,
	/// Certificate this client presents and the key that proves it, bound as
	/// one value so both halves reach the authentication path together.
	identity: Option<ClientIdentity<P>>,
	/// The pinned server certificate, when one is provisioned.
	server_cert: Option<Arc<Certificate>>,
	/// The server certificate path, ordered root to leaf, when one is
	/// provisioned.
	server_chain: Option<Arc<[Certificate]>>,
	trust_store: Option<Arc<dyn CertificateTrust>>,
	/// The server the key exchange encrypts to, once the trust admitted it.
	server: Option<AdmittedServer>,
	transcript: Transcript,
	/// The base secret and the KARI ephemeral from the key exchange to the
	/// server Finished, which takes them, and the handshake secret from there
	/// to completion, which takes that.
	key_schedule: KeySchedule<PendingKeyExchange<P>>,
	security_offer: Option<SecurityOffer>,
	profiles: ProfilePolicy<P>,
	transport_offer: Option<TransportOffer>,
	/// What the server Finished fixed, from there to completion.
	terms: Option<Terms<P>>,
	provider: P,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	pending_receipt: Option<PendingReceipt>,
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
	P: HandshakeProvider,
{
	/// Create a CMS handshake client.
	///
	/// `provider` fixes the security profile, `client_key_provider`
	/// authenticates the client, and the key agreement runs against
	/// `server_cert`.
	pub fn new(provider: P, client_key_provider: Arc<dyn SigningKeyProvider>, server_cert: Arc<Certificate>) -> Self {
		Self::with_identity(provider, client_key_provider, Some(server_cert), None)
	}

	/// Create a CMS handshake client from a server certificate chain.
	///
	/// The encryption target is the chain leaf. Path validation runs over the
	/// whole chain during key exchange.
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
		Self {
			state: ClientStateMachine::<Cms>::default(),
			client_key_provider,
			identity: None,
			server_cert,
			server_chain,
			trust_store: None,
			server: None,
			transcript: Transcript::new(),
			key_schedule: KeySchedule::Idle,
			security_offer: None,
			profiles: ProfilePolicy::new(),
			transport_offer: None,
			terms: None,
			provider,
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
		self.server_chain = Some(chain);
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
		self.profiles = ProfilePolicy::with_floor(policy);
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

	/// The security profile that negotiation selected, from the server
	/// Finished to completion.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.terms.as_ref().map(|terms| terms.profile().descriptor())
	}

	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
	}

	/// The server identity this client provisioned, beside the store that
	/// authenticates it.
	///
	/// # Fail closed
	///
	/// A configured trust store is mandatory (CWE-295). Expiry alone
	/// authenticates nobody, so a missing store aborts the handshake.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingTrustStore`] -- no trust store is set.
	/// - [`HandshakeError::MissingServerCertificate`] -- no server certificate or chain is set.
	/// - [`HandshakeError::PinnedCertificateMismatch`] -- the chain leaf differs from the pinned certificate.
	fn provisioned_trust(&self) -> Result<ProvisionedTrust, HandshakeError> {
		let store = self.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		let identity = match (&self.server_chain, &self.server_cert) {
			(Some(chain), Some(pinned)) => {
				if chain.last() != Some(pinned.as_ref()) {
					return Err(HandshakeError::PinnedCertificateMismatch);
				}

				CmsServerIdentity::Chain(Arc::clone(chain))
			}
			(Some(chain), None) => CmsServerIdentity::Chain(Arc::clone(chain)),
			(None, Some(certificate)) => CmsServerIdentity::Certificate(Arc::clone(certificate)),
			(None, None) => return Err(HandshakeError::MissingServerCertificate),
		};

		Ok(ProvisionedTrust { identity, store: Arc::clone(store) })
	}

	/// Draw the KARI ephemeral key and encode its public half as an SPKI.
	fn create_ephemeral_keypair(
		&self,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let sender_ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let sender_pub_spki = SubjectPublicKeyInfoOwned::from_key(sender_ephemeral.public_key())?;

		Ok((sender_ephemeral, sender_pub_spki))
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
	/// - [`HandshakeError::InvalidState`] -- the client is past `Init`.
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
		// 1. Validate the state, and admit the provisioned server before anything is encrypted to it.
		self.validate_expected_state(ClientHandshakeState::Init)?;
		let server = self.provisioned_trust()?.admit_provisioned()?;

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
		let certificate = server.certificate();
		let server_public_key = certificate.verifying_key::<P::Curve>()?;
		let (sender_ephemeral, sender_pub_spki) = self.create_ephemeral_keypair(rng)?;

		// 5. Create the UKM and the recipient identifier.
		let ukm = self.create_user_keying_material(rng)?;
		let rid = Self::recipient_identifier(certificate);

		// 6. Build the KARI structure.
		let kari_ephemeral = sender_ephemeral.clone();
		let kari_builder = self.build_kari_structure(kari_ephemeral, sender_pub_spki, server_public_key, rid, ukm)?;

		// 7. Create the EnvelopedData with the optional security and transport offers.
		let enveloped_data = self.build_enveloped_data(kari_builder, &base, rng)?;

		// 8. Update the transcript and the state. The transcript covers the
		//    encoded form, so it is built here. On the CMS path,
		//    KeyExchangeSent follows Init directly.
		let key_exchange = WireDer::new(enveloped_data)?;
		let pending = PendingKeyExchange { base, ephemeral: sender_ephemeral };
		self.transcript.append(key_exchange.der())?;
		self.key_schedule.pend(pending)?;
		self.server = Some(server);
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;
		Ok(key_exchange)
	}

	/// Process the server Finished message, a SignedData over the transcript
	/// hash, then derive the handshake secret and return the verified
	/// transcript hash.
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
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected
	///   nothing, or a profile outside the offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable, or the transport accept is invalid.
	/// - [`HandshakeError::InvalidPublicKey`] -- the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the receipt disagrees with the negotiated session.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	pub fn process_server_finished(&mut self, server_finished: &SignedData) -> Result<[u8; 32], HandshakeError> {
		// 1. Validate the state, and read the server the key exchange admitted.
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;
		let server = self.server.as_ref().ok_or(HandshakeError::InvalidState)?;

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
		let transcript_hash = self.transcript.seal::<P::Digest>()?;

		// 3. Verify the signature and the signed content under the admitted server's key.
		let static_key = server.certificate().verifying_key::<P::Curve>()?;
		let server_verifying_key = P::VerifyingKey::from(static_key);
		let expected_sid = compute_signer_identifier(&server_verifying_key)?;
		let verified_content = self.verify_signature(server_finished, server_verifying_key, expected_sid)?;

		// 4. Admit the selections against our own offers, and fix the terms.
		let profile = self.profiles.admit(self.security_offer.as_ref(), accept.as_ref())?;
		let mux = MuxSettings::for_client(self.transport_offer.as_ref(), transport_accept.as_ref())?;
		let terms = Terms::new(profile, mux, transcript_hash, Salt::TranscriptHash);

		// 5. Parse the server ephemeral the signature just authenticated,
		//    beside the static key it must differ from.
		let server_ephemeral = static_key.server_ephemeral(server_ephemeral.public_key.raw_bytes())?;

		// 6. Verify the session receipt against the accept. The client Finished countersigns it later.
		let received_artifact = ReceivedAttribute::<SignedData>::extract(server_finished)?;
		let artifact = received_artifact.map(|received| received.into_parts().0);
		let accept = transport_accept.as_ref();
		let certificate = server.certificate();
		let pending_receipt = PendingReceipt::verify::<P>(artifact, accept, &transcript_hash, certificate)?;

		// 7. Derive the handshake secret from the base secret and the agreement
		//    of the kept KARI ephemeral with the server ephemeral. The pending
		//    pair drops when this function returns.
		let PendingKeyExchange { base, ephemeral } = self.key_schedule.take_pending()?;
		let agreement = Agreement::<P>::new(&base, &server_ephemeral);
		let handshake_secret = agreement.settle(&ephemeral, terms.kdf_salt())?;
		self.key_schedule.store(handshake_secret)?;

		// 8. Keep what the Finished fixed, and transition the state. The
		//    transcript sealed in step 2, so the server Finished itself is not
		//    part of it.
		self.terms = Some(terms);
		self.pending_receipt = pending_receipt;
		self.state.transition(ClientHandshakeState::ServerFinishedReceived)?;

		Ok(verified_content)
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
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::ServerFinishedReceived)?;

		// 2. Read the transcript hash and compute the digest to sign.
		let (transcript_hash, digest) = self.prepare_finished_digest()?;

		// 3. Sign the digest.
		let signature_bytes = self.sign_finished_digest(&digest).await?;

		// 4. Build the signer identity and the algorithm identifiers.
		let signer = self.build_finished_crypto_components().await?;

		// 5. Countersign the session receipt. The countersignature travels as
		//    a SignerInfo unsigned attribute, sealed under the handshake
		//    secret.
		let receipt_attrs = match self.pending_receipt.take() {
			Some(pending) => {
				let terms = self.terms.as_ref().ok_or(HandshakeError::InvalidState)?;
				let handshake_secret = self.key_schedule.derived()?;
				let identity = self.identity.as_ref();
				let approver = self.receipt_approver.as_deref();
				let countersigning = pending.countersign(approver, identity, handshake_secret, terms);
				let (sealed_ack, stored_receipt) = countersigning.await?;

				let ack_attr = HandshakeAttribute::encode(&OctetString::new(sealed_ack)?)?;
				let x509_attrs = vec![Attribute::try_from(ack_attr)?];
				self.stored_receipt = Some(stored_receipt);
				Some(Attributes::try_from(x509_attrs)?)
			}
			None => None,
		};

		// 6. Build the SignedData.
		let signed_data = self.build_signed_data(transcript_hash, &signature_bytes, signer, receipt_attrs)?;

		// 7. Transition the state.
		self.state.transition(ClientHandshakeState::ClientFinishedSent)?;

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

	/// The server certificate the key exchange encrypted to, once the trust
	/// store admitted it: the pinned certificate, or the chain leaf.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.server.as_ref().map(|server| server.certificate().as_ref())
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// This is the single home for CMS client completion. The trait
	/// implementation delegates here, so driver and test read the session
	/// terms the same way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the machine has not sent its Finished.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused a session key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused a derived key.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::ClientFinishedSent)?;

		// 2. Take what the handshake agreed. The handshake secret moves out,
		//    so completion is the one derivation from it.
		let secret = self.key_schedule.take_derived()?;
		let terms = self.terms.take().ok_or(HandshakeError::InvalidState)?;
		let server = self.server.clone().ok_or(HandshakeError::InvalidState)?;
		let agreed = Agreed::new(terms, secret, self.stored_receipt.take(), server);

		// 3. Derive the session keys and the epoch-0 rekey materials.
		let session = agreed.complete(SessionKeys::for_client)?;

		// 4. Transition to complete.
		self.state.transition(ClientHandshakeState::Completed)?;

		Ok(session)
	}

	/// Draw 64 random bytes of user keying material for the key agreement.
	fn create_user_keying_material(&self, rng: &mut dyn CryptoRngCore) -> Result<UserKeyingMaterial, HandshakeError> {
		let ukm_bytes = generate_nonce::<64>(Some(rng))?;
		UserKeyingMaterial::new(ukm_bytes.to_vec()).map_err(Into::into)
	}

	/// The recipient identifier that names `server` in the KARI.
	fn recipient_identifier(server: &Certificate) -> KeyAgreeRecipientIdentifier {
		// A clone costs less here than an `Arc`.
		let issuer = server.tbs_certificate.issuer.clone();
		let serial_number = server.tbs_certificate.serial_number.clone();
		let named = IssuerAndSerialNumber { issuer, serial_number };
		KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(named)
	}

	/// Assemble the KARI builder, which wraps under the profile's key wrap
	/// algorithm.
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

	/// Prepare the transcript hash and compute the digest to sign.
	fn prepare_finished_digest(&self) -> Result<([u8; 32], Vec<u8>), HandshakeError> {
		let terms = self.terms.as_ref().ok_or(HandshakeError::InvalidState)?;
		let transcript_hash = *terms.transcript_hash();
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

	/// Build the client Finished SignedData.
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

impl<P> ClientHandshakeProtocol for CmsHandshakeClient<P>
where
	P: HandshakeProvider,
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
		self.selected_profile()
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::{CmsHandshakeClient, EnvelopedData, FinishedRole, KeySchedule, OriginatorPublicKey, SignedData};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::sign::elliptic_curve::SecretKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::der::asn1::BitString;
	use crate::der::Decode;
	use crate::oids::{AES_128_GCM, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
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
	/// `key_exchange` followed by the default profile's accept and
	/// `ephemeral`, as a server under dealer's choice sends it, with the
	/// transcript hash it signed.
	fn server_finished_over(
		server_key: &Secp256k1SigningKey,
		key_exchange: &WireDer<EnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> Result<(SignedData, [u8; 32]), Box<dyn Error>> {
		let accept = SecurityAccept::new(create_default_test_profile());
		let accept_bytes = HandshakeAttribute::transcript_bytes(&accept)?;
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(ephemeral)?;
		let transcript = [key_exchange.der(), accept_bytes.as_slice(), ephemeral_bytes.as_slice()].concat();
		let accept_attr = Attribute::try_from(HandshakeAttribute::encode(&accept)?)?;
		let ephemeral_attr = Attribute::try_from(HandshakeAttribute::encode(ephemeral)?)?;
		let attrs = Attributes::try_from(vec![accept_attr, ephemeral_attr])?;

		signed_server_finished(server_key, &transcript, attrs)
	}

	/// A server Finished signed by `server_key` over `transcript` that carries
	/// `attrs`, with the transcript hash it signed.
	fn signed_server_finished(
		server_key: &Secp256k1SigningKey,
		transcript: &[u8],
		attrs: Attributes,
	) -> Result<(SignedData, [u8; 32]), Box<dyn Error>> {
		let transcript_hash = Transcript::digest::<Sha3_256>(transcript)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
		let builder =
			TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(server_key, digest_alg, signature_alg)?;

		let mut signed = builder.build(FinishedRole::Server.content(&transcript_hash))?;
		set_unsigned_attrs(&mut signed, Some(attrs))?;
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

		// Then: The server decrypts the 32-byte base secret with the matching
		// private key
		let server_secret = SecretKey::from(server_test_cert.signing_key.to_owned());
		let provider = DefaultCryptoProvider::default();
		let kari_processor = TightBeamKariRecipient::new(provider, server_secret);
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(kari_processor);
		let decrypted = processor.process(enveloped_data.value())?;
		let decrypted = ToInsecure::to_insecure(decrypted);
		assert_eq!(decrypted.len(), 32);

		// When: Client processes a server Finished over the transcript, which
		// holds the key exchange, the security accept, and the server ephemeral
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

	/// A validly signed server Finished that selects no profile is refused, so
	/// no session forms without an agreed profile.
	#[test]
	fn a_server_finished_without_a_security_accept_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server.certificate)?;
		let ephemeral = fresh_server_ephemeral()?;
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(&ephemeral)?;
		let transcript = [key_exchange.der(), ephemeral_bytes.as_slice()].concat();
		let attrs = ephemeral_attrs(&ephemeral)?;
		let (server_finished, _) = signed_server_finished(&server.signing_key, &transcript, attrs)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	/// A validly signed server Finished that selects a profile outside the
	/// client's offer is refused.
	#[test]
	fn a_client_refuses_a_profile_it_did_not_offer() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() };
		let offering = TestCmsClientBuilder::new().with_server_cert(server.certificate.to_owned());
		let mut client = offering.build()?.with_security_offer(SecurityOffer::new(vec![foreign]));
		let key_exchange = client.build_key_exchange(None)?;
		let ephemeral = fresh_server_ephemeral()?;
		let (server_finished, _) = server_finished_over(&server.signing_key, &key_exchange, &ephemeral)?;

		let result = client.process_server_finished(&server_finished);
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
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
		let (mut server, _) = TestCmsServerBuilder::new()
			.with_key(server_identity.signing_key.to_owned())
			.build();
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

	/// A client without a trust store aborts instead of authenticating the
	/// server by expiry alone (CWE-295).
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
		assert_eq!(client.peer_certificate(), Some(&chain.leaf));
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
}

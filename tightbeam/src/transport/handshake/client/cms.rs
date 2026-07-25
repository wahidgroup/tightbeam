//! CMS-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam handshake protocol using
//! CMS builders and processors.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
use crate::cms::signed_data::{CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfile, SecurityProfileDesc};
use crate::crypto::secret::Secret;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, PublicKey, SecretKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier};
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::utils::{
	compute_signer_identifier, compute_signer_identifier_from_der, validate_certificate_expiry,
};
use crate::crypto::x509::Certificate;
use crate::der::asn1::{OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode};
use crate::oids::{DATA, HANDSHAKE_SECURITY_ACCEPT, HANDSHAKE_TRANSPORT_ACCEPT, SESSION_RECEIPT};
use crate::random::{generate_nonce, CryptoRngCore, OsRng, RngWrapper};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::{
	encode_receipt_ack, encode_security_offer, encode_transport_offer, extract_security_accept,
	extract_session_receipt, extract_transport_accept, find_unsigned_attr, security_accept_transcript_bytes,
	transport_accept_transcript_bytes,
};
use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamKariBuilder};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	client_mux_settings, MuxSettings, SecurityAccept, SecurityOffer, TransportAccept, TransportOffer,
};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::{
	approve_or_fail_closed, certificate_signer_identifier, complete_receipt_artifact, countersign_receipt,
	match_receipt_to_accept, receipt_from_artifact, signer_for_role, verify_receipt_signer, ReceiptApprover,
	ReceiptRole, SessionReceipt, StoredReceipt,
};
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine};
use crate::transport::handshake::utils::{compute_transcript_digest, extract_verifying_key_from_cert, validate_state};
use crate::transport::handshake::{Arc, ClientHandshakeProtocol, HandshakeAlertHandler, HandshakeFinalization};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::zeroize::Zeroizing;

/// Client-side CMS handshake orchestrator.
///
/// Generic over `P: CryptoProvider` which defines the complete cryptographic
/// suite (curve, signature algorithm, digest, AEAD, KDF). Supports
/// cryptographic profile negotiation via optional `security_offer` field.
///
/// Manages the complete client handshake flow:
/// 1. Sends KeyExchange (EnvelopedData with KARI)
/// 2. Receives and verifies server Finished (SignedData)
/// 3. Sends client Finished (SignedData)
pub struct CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	state: ClientStateMachine,
	client_key_provider: Arc<dyn SigningKeyProvider>,
	client_certificate: Option<Arc<Certificate>>,
	server_cert: Option<Arc<Certificate>>,
	server_chain: Option<Arc<[Certificate]>>,
	transcript_hash: Option<[u8; 32]>,
	transcript_buffer: Vec<u8>,
	session_key: Option<Secret<Vec<u8>>>,
	security_offer: Option<SecurityOffer>,
	transport_offer: Option<TransportOffer>,
	mux_settings: Option<MuxSettings>,
	selected_profile: Option<SecurityProfileDesc>,
	provider: P,
	trust_store: Option<Arc<dyn CertificateTrust>>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	pending_receipt: Option<(SessionReceipt, SignedData)>,
	stored_receipt: Option<StoredReceipt>,
	invariants: HandshakeInvariant,
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
	P::Signature: 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: KeyInit,
{
	/// Create a new CMS handshake client.
	///
	/// # Parameters
	/// - `provider`: The cryptographic provider defining the security profile
	/// - `client_key_provider`: The client's key provider for authentication
	/// - `server_cert`: The server's certificate (for key agreement)
	///
	/// # Transcript Hash
	/// The transcript hash is computed internally from handshake messages.
	/// If you need to provide an external transcript hash (for testing),
	/// use `with_transcript_hash()` after construction.
	pub fn new(provider: P, client_key_provider: Arc<dyn SigningKeyProvider>, server_cert: Arc<Certificate>) -> Self {
		Self::with_identity(provider, client_key_provider, Some(server_cert), None)
	}

	/// Create a new CMS handshake client from a server certificate chain.
	///
	/// The chain leaf is the encryption target, borrowed in place: no
	/// separate leaf certificate is cloned out of the chain. Path validation
	/// runs over the whole chain during key exchange.
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
			state: ClientStateMachine::default(),
			client_key_provider,
			client_certificate: None,
			server_cert,
			server_chain,
			transcript_hash: None,
			transcript_buffer: Vec::new(),
			session_key: None,
			security_offer: None,
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			provider,
			trust_store: None,
			receipt_approver: None,
			pending_receipt: None,
			stored_receipt: None,
			invariants: HandshakeInvariant::default(),
		}
	}

	/// Set an external transcript hash (for testing or custom protocols).
	///
	/// When set, the internal transcript buffer is not used.
	#[must_use]
	pub fn with_transcript_hash(mut self, hash: [u8; 32]) -> Self {
		self.transcript_hash = Some(hash);
		self
	}

	/// Set trust store for server certificate validation.
	#[must_use]
	pub fn with_trust_store(mut self, store: Arc<dyn CertificateTrust>) -> Self {
		self.trust_store = Some(store);
		self
	}

	/// Provision the server certificate chain, ordered root to leaf.
	///
	/// When set, server authentication validates the full chain against the
	/// trust store ([RFC 5280 §6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)) instead of evaluating the bare certificate.
	#[must_use]
	pub fn with_server_certificate_chain(mut self, chain: Arc<[Certificate]>) -> Self {
		self.server_chain = Some(chain);
		self
	}

	/// Set client certificate for mutual authentication.
	///
	/// The certificate is embedded in the client Finished message so the
	/// server can authenticate the client from the wire.
	#[must_use]
	pub fn with_client_certificate(mut self, certificate: impl Into<Arc<Certificate>>) -> Self {
		self.client_certificate = Some(certificate.into());
		self
	}

	/// Configures the security offer for negotiation.
	///
	/// When configured, the client will send this offer to the server,
	/// and the server will select a mutually supported profile.
	#[must_use]
	pub fn with_security_offer(mut self, offer: SecurityOffer) -> Self {
		self.security_offer = Some(offer);
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
	/// Without one the client fails closed: challenge-free receipts are
	/// countersigned, challenge-bearing receipts abort the handshake.
	#[must_use]
	pub fn with_receipt_approver(mut self, approver: Arc<dyn ReceiptApprover>) -> Self {
		self.receipt_approver = Some(approver);
		self
	}

	/// Get the selected security profile after negotiation.
	///
	/// Returns `None` if no negotiation occurred or not yet determined.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
	}

	/// The server certificate the session key is encrypted to: the pinned
	/// certificate when set, otherwise the provisioned chain's leaf.
	fn server_leaf(&self) -> Result<&Certificate, HandshakeError> {
		if let Some(cert) = &self.server_cert {
			return Ok(cert);
		}

		self.server_chain
			.as_ref()
			.and_then(|chain| chain.last())
			.ok_or(HandshakeError::MissingServerCertificate)
	}

	/// Validate state and server certificate for key exchange.
	///
	/// Fail-closed (CWE-295): a configured trust store is mandatory. Expiry
	/// alone authenticates nobody, so a missing store aborts the handshake
	/// instead of silently degrading.
	///
	/// With a provisioned chain, the full path is validated
	/// ([RFC 5280 §6.1](https://datatracker.ietf.org/doc/html/rfc5280#section-6.1))
	/// and the leaf must be the configured server certificate. Otherwise the
	/// bare certificate is evaluated against the store directly.
	fn validate_state_and_certificate(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::Init)?;

		let store = self.trust_store.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		validate_certificate_expiry(self.server_leaf()?)?;

		match (&self.server_chain, &self.server_cert) {
			(Some(chain), pinned) => {
				store.verify_chain(chain)?;

				let leaf = chain.last().ok_or(HandshakeError::MissingServerCertificate)?;
				if pinned.as_ref().is_some_and(|cert| *leaf != **cert) {
					return Err(HandshakeError::PinnedCertificateMismatch);
				}
			}
			(None, Some(cert)) => store.evaluate(cert)?,
			(None, None) => return Err(HandshakeError::MissingServerCertificate),
		}

		Ok(())
	}

	/// Extract the server's public key from certificate.
	fn extract_server_public_key(&self) -> Result<PublicKey<P::Curve>, HandshakeError> {
		Ok(PublicKey::<P::Curve>::from_sec1_bytes(
			self.server_leaf()?
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?)
	}

	/// Create ephemeral keypair for the sender.
	fn create_ephemeral_keypair(
		&self,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(SecretKey<P::Curve>, SubjectPublicKeyInfoOwned), HandshakeError> {
		let sender_ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let sender_public = sender_ephemeral.public_key();
		let sender_pub_spki = sender_public.to_public_key_der()?;
		let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes())?;

		Ok((sender_ephemeral, sender_pub_spki))
	}

	/// Build the recipient identifier from server certificate.
	fn build_recipient_identifier(&self) -> Result<KeyAgreeRecipientIdentifier, HandshakeError> {
		let leaf = self.server_leaf()?;

		// Cloning here is cheaper than Arc
		Ok(KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
			issuer: leaf.tbs_certificate.issuer.clone(),
			serial_number: leaf.tbs_certificate.serial_number.clone(),
		}))
	}

	/// Extract the server's verifying key from a certificate or similar.
	fn extract_server_verifying_key(&self, server_cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		let server_public_key = extract_verifying_key_from_cert::<P::Curve>(server_cert)?;
		Ok(P::VerifyingKey::from(server_public_key))
	}

	/// Compute the signer identifier from the server's verifying key.
	fn compute_signer_identifier(&self, verifying_key: &P::VerifyingKey) -> Result<SignerIdentifier, HandshakeError> {
		Ok(compute_signer_identifier::<P::Digest, _>(verifying_key)?)
	}

	/// Compute transcript hash from the accumulated buffer.
	///
	/// Uses the provider's digest algorithm for consistency with signatures.
	fn compute_transcript_hash(&self) -> Result<[u8; 32], HandshakeError> {
		compute_transcript_digest::<P::Digest>(&self.transcript_buffer)
	}

	/// Verify the signature and content of the SignedData.
	fn verify_signature(
		&self,
		signed_data_der: &[u8],
		server_verifying_key: P::VerifyingKey,
		expected_sid: SignerIdentifier,
	) -> Result<Vec<u8>, HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<P::VerifyingKey, P::Signature, P::Digest>::from_verifying_key_with_sid(
			server_verifying_key,
			expected_sid,
		);
		let processor = TightBeamSignedDataProcessor::new(verifier);

		// Verify content matches our transcript hash
		let digest_oid = P::Digest::OID;
		let verified_content = processor.process_der(signed_data_der, &digest_oid)?;

		let expected_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		if verified_content.len() != 32 || verified_content.as_slice() != expected_hash {
			Err(HandshakeError::SignatureVerificationFailed)
		} else {
			Ok(verified_content)
		}
	}

	/// Build KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `session_key`: The session key to wrap and send
	/// - `rng`: Optional CSPRNG for the ephemeral key, UKM, CEK, and content
	///   nonce. `None` defaults to `OsRng`. Supply one on `no_std` targets
	///   without an OS-backed `getrandom`.
	///
	/// # Returns
	/// DER-encoded EnvelopedData
	pub fn build_key_exchange(
		&mut self,
		session_key: Vec<u8>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate state and certificate
		self.validate_key_exchange_prerequisites()?;

		// 2. Resolve the RNG once (defaulting to OsRng) then reborrow it for
		//    each randomness draw in the key-exchange path.
		let mut os = OsRng;
		let rng: &mut dyn CryptoRngCore = rng.unwrap_or(&mut os);

		// 3. Extract cryptographic material
		let (server_public_key, sender_ephemeral, sender_pub_spki) = self.extract_key_exchange_crypto_material(rng)?;

		// 4. Create UKM and recipient identifier
		let ukm = self.create_user_keying_material(rng)?;
		let rid = self.build_recipient_identifier()?;

		// 5. Build KARI structure
		let kari_builder = self.build_kari_structure(sender_ephemeral, sender_pub_spki, server_public_key, rid, ukm)?;

		// 6. Create EnvelopedData with optional security offer
		let enveloped_data_der = self.build_enveloped_data(kari_builder, &session_key, rng)?;

		// 7. Update transcript and state
		self.finalize_key_exchange(&enveloped_data_der, session_key)?;

		Ok(enveloped_data_der)
	}

	/// Process server Finished message (SignedData over transcript hash).
	///
	/// # Parameters
	/// - `signed_data_der`: DER-encoded SignedData from server
	///
	/// # Returns
	/// Verified transcript hash
	pub fn process_server_finished(&mut self, signed_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Extract the server's SecurityAccept and TransportAccept before
		//    hashing: the accept bytes are part of the signed transcript, so
		//    the hash must cover them to match the server's (CWE-345). A
		//    tampered attribute diverges the hashes and fails signature
		//    verification below. The SignedData is parsed once here and
		//    shared by every attribute extraction.
		let signed_data = SignedData::from_der(signed_data_der)?;
		let accept = extract_security_accept_attr(&signed_data)?;
		let transport_accept = extract_transport_accept_attr(&signed_data)?;
		if self.transcript_hash.is_none() {
			if let Some(ref accept) = accept {
				let accept_bytes = security_accept_transcript_bytes(accept)?;
				self.transcript_buffer.extend_from_slice(&accept_bytes);
			}
			if let Some(ref accept) = transport_accept {
				let accept_bytes = transport_accept_transcript_bytes(accept)?;
				self.transcript_buffer.extend_from_slice(&accept_bytes);
			}

			self.transcript_hash = Some(self.compute_transcript_hash()?);
		}

		// 3. Extract cryptographic material
		let server_verifying_key = self.extract_server_verifying_key(self.server_leaf()?)?;
		let expected_signer_identifier = self.compute_signer_identifier(&server_verifying_key)?;

		// 4. Verify signature and content
		let verified_content =
			self.verify_signature(signed_data_der, server_verifying_key, expected_signer_identifier)?;

		// 5. Validate the selections against our own offers and store them
		self.apply_security_accept(accept)?;
		self.mux_settings = client_mux_settings(self.transport_offer.as_ref(), transport_accept.as_ref())?;

		// 6. Validate the session receipt (countersigned later, in the
		// client Finished)
		self.process_session_receipt(&signed_data, transport_accept.as_ref())?;

		// 7. Add server finished to transcript AFTER verification
		self.transcript_buffer.extend_from_slice(signed_data_der);

		// 8. Transition state & lock transcript (transcript hash verified)
		self.state.transition(ClientHandshakeState::ServerFinishedReceived)?;
		self.invariants.lock_transcript()?;

		Ok(verified_content)
	}

	/// Validate the server's `SecurityAccept` selection and store the profile.
	///
	/// # Validation
	/// - Offer sent: accepted profile must be a member of the offer
	/// - No offer (dealer's choice): any accepted profile is stored
	/// - No attribute present: selection stays `None` (trait-level `complete()`
	///   then fails closed rather than proceeding with an unknown profile)
	fn apply_security_accept(&mut self, accept: Option<SecurityAccept>) -> Result<(), HandshakeError> {
		match (accept, &self.security_offer) {
			(Some(accept), Some(offer)) => {
				if !offer.profiles.contains(&accept.profile) {
					return Err(HandshakeError::InvalidProfileSelection);
				}

				self.selected_profile = Some(accept.profile);
			}
			(Some(accept), None) => {
				// Dealer's choice: accept the server's selection
				self.selected_profile = Some(accept.profile);
			}
			(None, Some(_)) => {
				// We offered profiles but the server did not answer
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
		let artifact = extract_session_receipt_attr(signed_data)?;
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		let parsed_receipt = artifact.as_ref().map(receipt_from_artifact).transpose()?;
		let Some(receipt) =
			match_receipt_to_accept::<P::Digest>(parsed_receipt, granted, credit_unit, &transcript_digest)?
		else {
			return Ok(());
		};

		// Server SignerInfo over the receipt body: third-party verifiable
		// agreement, so an unsigned receipt is no receipt at all.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let server_signer = signer_for_role(&artifact, ReceiptRole::Server)?.ok_or(HandshakeError::ReceiptMissing)?;

		let receipt_der = receipt.to_der()?;
		let expected_sid = certificate_signer_identifier::<P::Digest>(self.server_leaf()?)?;
		let verifying_key = self.extract_server_verifying_key(self.server_leaf()?)?;
		verify_receipt_signer::<P::Digest, P::Signature, _>(
			&receipt_der,
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
	async fn countersign_pending_receipt(&mut self) -> Result<Option<Attributes>, HandshakeError> {
		let Some((receipt, server_artifact)) = self.pending_receipt.take() else {
			return Ok(None);
		};

		// Countersigning demands a client certificate the server can
		// verify against: budgets without mutual authentication fail
		// closed. Checked before approval: approving can spend an
		// irreversible settlement answer, so every local precondition
		// must already hold.
		if self.client_certificate.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		// Approve the receipt and answer its challenge.
		let approver = self.receipt_approver.as_deref();
		let response = approve_or_fail_closed(approver, &receipt).await?;
		let answer = response.as_ref().map(OctetString::as_bytes);
		let key_provider = self.client_key_provider.as_ref();
		let countersignature = countersign_receipt::<P::Digest>(&receipt, answer, key_provider).await?;

		// The acknowledgement is confidential: the client SignerInfo (and
		// the bearer answer bound in its signed attributes) travels in an
		// EnvelopedData encrypted to the server certificate, never the
		// cleartext SignedData.
		let mut os = OsRng;
		let ack_der = Zeroizing::new(countersignature.to_der()?);
		let envelope_der = self.encrypt_to_server(&ack_der, &mut os)?;
		let envelope = OctetString::new(envelope_der)?;
		let ack_attr = encode_receipt_ack(&envelope)?;

		let values = SetOfVec::try_from(ack_attr.attr_values)?;
		let x509_attrs = vec![Attribute { oid: ack_attr.attr_type, values }];

		// Both endpoints retain the identical completed artifact.
		let completed = complete_receipt_artifact(server_artifact, countersignature)?;
		self.stored_receipt = Some(StoredReceipt::try_from(completed)?);

		Ok(Some(Attributes::try_from(x509_attrs)?))
	}

	/// Build client Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub async fn build_client_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate state
		self.validate_client_finished_prerequisites()?;

		// 2. Get transcript hash and prepare digest
		let (transcript_hash, digest) = self.prepare_finished_digest()?;

		// 3. Sign the digest
		let signature_bytes = self.sign_finished_digest(&digest).await?;

		// 4. Build cryptographic components
		let signer = self.build_finished_crypto_components().await?;

		// 5. Countersign the session receipt: signature and settlement
		// answer travel as SignerInfo unsigned attributes
		let receipt_attrs = self.countersign_pending_receipt().await?;

		// 6. Build SignedData structure
		let signed_data_der = self.build_signed_data(transcript_hash, &signature_bytes, signer, receipt_attrs)?;

		// 7. Transition state
		self.finalize_client_finished()?;

		Ok(signed_data_der)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::ClientFinishedSent)?;

		// 2. Transition to complete
		self.state.transition(ClientHandshakeState::Completed)?;

		Ok(())
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// Get the session key (if available).
	///
	/// Returns a reference to the Secret-wrapped session key bytes.
	pub fn session_key(&self) -> Option<&Secret<Vec<u8>>> {
		self.session_key.as_ref()
	}

	/// Get the dual-signed session receipt.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	/// Validate state and certificate for key exchange.
	fn validate_key_exchange_prerequisites(&self) -> Result<(), HandshakeError> {
		// Accept both Init (fresh) or HelloSent (if future hello phase added)
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

	/// Build KARI structure with all required components.
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

	/// Build EnvelopedData with optional security offer.
	fn build_enveloped_data(
		&self,
		kari_builder: TightBeamKariBuilder<P>,
		session_key: &[u8],
		rng: &mut dyn CryptoRngCore,
	) -> Result<Vec<u8>, HandshakeError> {
		let mut enveloped_builder = TightBeamEnvelopedDataBuilder::new(kari_builder);

		// Add SecurityOffer as unprotected attribute if configured
		if let Some(ref offer) = self.security_offer {
			let offer_attr = encode_security_offer(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}
		// Add TransportOffer as unprotected attribute if configured
		if let Some(ref offer) = self.transport_offer {
			let offer_attr = encode_transport_offer(offer)?;
			enveloped_builder = enveloped_builder.with_unprotected_attr(offer_attr);
		}

		let enveloped_data = enveloped_builder.build(session_key, None, Some(rng))?;
		enveloped_data.to_der().map_err(Into::into)
	}

	/// Encrypt an opaque payload to the server certificate as a
	/// standalone EnvelopedData (fresh ephemeral key, UKM, and CEK).
	///
	/// Carrier for the confidential settlement answer in the client
	/// Finished. The same KARI machinery as the key exchange, without
	/// negotiation attributes.
	fn encrypt_to_server(&self, content: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, HandshakeError> {
		let (server_public_key, sender_ephemeral, sender_pub_spki) = self.extract_key_exchange_crypto_material(rng)?;
		let ukm = self.create_user_keying_material(rng)?;
		let rid = self.build_recipient_identifier()?;
		let kari_builder = self.build_kari_structure(sender_ephemeral, sender_pub_spki, server_public_key, rid, ukm)?;

		let enveloped_data = TightBeamEnvelopedDataBuilder::new(kari_builder).build(content, None, Some(rng))?;
		enveloped_data.to_der().map_err(Into::into)
	}

	/// Finalize key exchange by updating transcript and state.
	fn finalize_key_exchange(&mut self, enveloped_data_der: &[u8], session_key: Vec<u8>) -> Result<(), HandshakeError> {
		// Add to transcript if we're computing it internally
		if self.transcript_hash.is_none() {
			self.transcript_buffer.extend_from_slice(enveloped_data_der);
		}

		// Store session key and transition state
		self.session_key = Some(Secret::from(session_key));
		// Transition directly from Init -> KeyExchangeSent (CMS path) or HelloSent -> KeyExchangeSent
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(())
	}

	/// Validate prerequisites for building client finished message.
	fn validate_client_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ClientHandshakeState::ServerFinishedReceived)
	}

	/// Prepare transcript hash and compute digest for signing.
	fn prepare_finished_digest(&self) -> Result<([u8; 32], Vec<u8>), HandshakeError> {
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		let mut hasher = P::Digest::new();
		hasher.update(transcript_hash);

		let digest = hasher.finalize();
		let digest_bytes = digest.to_vec();

		Ok((transcript_hash, digest_bytes))
	}

	/// Sign the finished digest using the client key provider.
	async fn sign_finished_digest(&self, digest: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signature_bytes = self.client_key_provider.sign_prehash(digest).await?;
		Ok(signature_bytes)
	}

	/// Build cryptographic components needed for SignedData.
	async fn build_finished_crypto_components(&self) -> Result<FinishedSigner, HandshakeError> {
		let public_key_bytes = self.client_key_provider.to_public_key_bytes().await?;
		let id = compute_signer_identifier_from_der::<P::Digest>(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		Ok(FinishedSigner { id, digest_alg, signature_alg })
	}

	/// Build the complete SignedData structure.
	///
	/// A configured client certificate is embedded in the `certificates`
	/// field so the server can authenticate the client from the wire.
	fn build_signed_data(
		&self,
		transcript_hash: [u8; 32],
		signature_bytes: &[u8],
		signer: FinishedSigner,
		unsigned_attrs: Option<Attributes>,
	) -> Result<Vec<u8>, HandshakeError> {
		let FinishedSigner { id, digest_alg, signature_alg } = signer;
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: id,
			// Same OID lives in SignerInfo and the SignedData digestAlgorithms SET.
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature_bytes)?,
			unsigned_attrs,
		};

		let octet_string = OctetString::new(transcript_hash)?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = Any::from_der(&econtent_der)?;
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent_any) };

		let certificates = self
			.client_certificate
			.as_ref()
			.map(|cert| {
				// CMS CertificateSet owns the cert; orchestrator keeps Arc.
				let choice = CertificateChoices::Certificate(cert.as_ref().to_owned());
				Ok::<_, HandshakeError>(CertificateSet(vec![choice].try_into()?))
			})
			.transpose()?;

		let signed_data = SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		};

		signed_data.to_der().map_err(Into::into)
	}

	/// Finalize client finished by transitioning state and marking invariant.
	fn finalize_client_finished(&mut self) -> Result<(), HandshakeError> {
		self.state.transition(ClientHandshakeState::ClientFinishedSent)?;
		self.invariants.mark_finished_sent()?;
		Ok(())
	}
}

/// Extract the server's `SecurityAccept` from a Finished message's unsigned
/// attributes, if present.
fn extract_security_accept_attr(signed_data: &SignedData) -> Result<Option<SecurityAccept>, HandshakeError> {
	find_unsigned_attr(signed_data, HANDSHAKE_SECURITY_ACCEPT)?
		.map(|attr| extract_security_accept(&attr))
		.transpose()
}

/// Extract the server's `TransportAccept` from a Finished message's unsigned
/// attributes, if present.
fn extract_transport_accept_attr(signed_data: &SignedData) -> Result<Option<TransportAccept>, HandshakeError> {
	find_unsigned_attr(signed_data, HANDSHAKE_TRANSPORT_ACCEPT)?
		.map(|attr| extract_transport_accept(&attr))
		.transpose()
}

/// Extract the server's receipt `SignedData` artifact from a Finished message's unsigned
/// attributes, if present.
fn extract_session_receipt_attr(signed_data: &SignedData) -> Result<Option<SignedData>, HandshakeError> {
	find_unsigned_attr(signed_data, SESSION_RECEIPT)?
		.map(|attr| extract_session_receipt(&attr))
		.transpose()
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P> HandshakeFinalization<P> for CmsHandshakeClient<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for CmsHandshakeClient<P> where P: CryptoProvider {}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<P> ClientHandshakeProtocol for CmsHandshakeClient<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	<P::Curve as elliptic_curve::Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EncodePublicKey,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + signature::Verifier<P::Signature> + 'static,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::Signature: 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: Send + Sync + KeyInit,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<Vec<u8>, Self::Error>> {
		Box::pin(async move {
			// Fresh random session key per handshake: a constant key
			// would make every session trivially decryptable (CWE-321).
			let session_key = Zeroizing::new(generate_nonce::<32>(None)?);
			self.build_key_exchange(session_key.to_vec(), None)
		})
	}

	fn handle_response<'a, 'b>(&'a mut self, msg: &'b [u8]) -> MaybeSendFuture<'a, Result<Option<Vec<u8>>, Self::Error>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Process server finished
			self.process_server_finished(msg)?;

			// Build client finished
			let client_finished = self.build_client_finished().await?;
			Ok(Some(client_finished))
		})
	}

	#[cfg(feature = "aead")]
	fn complete<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<SessionKeys, Self::Error>> {
		Box::pin(async move {
			// 1. Validate state
			if self.state.state() != ClientHandshakeState::ClientFinishedSent {
				return Err(HandshakeError::InvalidState);
			}

			// 2. Get CEK (session_key) and profile
			let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;
			let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

			// 3. Derive directional session keys as P::AeadCipher
			let ciphers = cek.with(|key_bytes| self.derive_directional_aead(key_bytes, &transcript_hash))??;

			// 4. Transition to complete
			self.state.transition(ClientHandshakeState::Completed)?;

			// 5. Role-map the directional ciphers with the negotiated OID
			Ok(SessionKeys::for_client(
				ciphers.client_to_server,
				ciphers.server_to_client,
				aead_oid,
			))
		})
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.mux_settings
	}

	fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::{extract_security_accept_attr, CmsHandshakeClient, SignedData};
	use crate::cms::enveloped_data::EnvelopedData;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::policy::Secp256k1Policy;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::sign::elliptic_curve::SecretKey;
	use crate::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
	use crate::der::asn1::SetOfVec;
	use crate::der::{Decode, Encode};
	use crate::oids::{HANDSHAKE_SECURITY_ACCEPT, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::random::OsRng;
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::utils::create_test_certificate_chain;
	use crate::transport::handshake::attributes::encode_security_accept;
	use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	use crate::transport::handshake::error::HandshakeError;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer};
	use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
	use crate::transport::handshake::state::ClientHandshakeState;
	use crate::transport::handshake::tests::*;
	use crate::x509::attr::{Attribute, Attributes};
	use crate::x509::Certificate;

	#[tokio::test]
	async fn test_client_state_flow() -> Result<(), Box<dyn Error>> {
		// Given: A CMS client in init state with a server certificate
		let transcript_hash = [1u8; 32];
		let server_test_cert = create_test_certificate();
		let server_cert = server_test_cert.certificate.to_owned();
		let mut client = TestCmsClientBuilder::new()
			.with_server_cert(server_cert)
			.with_transcript_hash(transcript_hash)
			.build()?;
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: Client builds a valid key exchange
		let session_key = vec![2u8; 32];
		let key_exchange = client.build_key_exchange(session_key.to_owned(), None)?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		// Verify session key is stored
		assert!(client.session_key().is_some());

		// Then: Server should be able to decrypt it using the matching private key
		let enveloped_data = EnvelopedData::from_der(&key_exchange)?;
		let server_secret = SecretKey::from(server_test_cert.signing_key.to_owned());
		let provider = DefaultCryptoProvider::default();
		let kari_processor = TightBeamKariRecipient::new(provider, server_secret);
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(kari_processor);
		let decrypted = processor.process(&enveloped_data)?;
		let decrypted = ToInsecure::to_insecure(decrypted)?;
		assert_eq!(&decrypted[..], &session_key[..]);

		// When: Client processes server Finished
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
		let server_finished_builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(
			&server_test_cert.signing_key,
			digest_alg,
			signature_alg,
		)?;
		let server_finished = server_finished_builder.build(&transcript_hash)?;
		let server_finished = server_finished.to_der()?;

		let verified = client.process_server_finished(&server_finished)?;
		assert_eq!(verified, transcript_hash);
		assert_eq!(client.state(), ClientHandshakeState::ServerFinishedReceived);

		// Build client Finished
		let _client_finished = client.build_client_finished().await?;
		assert_eq!(client.state(), ClientHandshakeState::ClientFinishedSent);

		// Complete
		client.complete()?;
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	const TEST_SESSION_KEY: [u8; 32] = [2u8; 32];

	fn trust_store(root: Option<Certificate>) -> Result<Arc<dyn CertificateTrust>, Box<dyn Error>> {
		let mut builder = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy);
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

	/// A client without a trust store must abort instead of degrading to
	/// expiry-only server authentication (CWE-295).
	#[test]
	fn test_missing_trust_store_fails_closed() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let mut client = CmsHandshakeClient::<DefaultCryptoProvider>::new(
			DefaultCryptoProvider::default(),
			into_provider(server.signing_key),
			Arc::new(server.certificate),
		);

		let result = client.build_key_exchange(TEST_SESSION_KEY.to_vec(), None);
		assert!(matches!(result, Err(HandshakeError::MissingTrustStore)));
		Ok(())
	}

	/// A chain-provisioned client path-validates the chain and encrypts to
	/// its leaf. No separate pinned certificate is needed.
	#[test]
	fn from_chain_validates_and_targets_leaf() -> Result<(), Box<dyn Error>> {
		let chain = create_test_certificate_chain()?;
		let mut client = chain_client(chain.to_arc(), Some(chain.root.to_owned()))?;

		client.build_key_exchange(TEST_SESSION_KEY.to_vec(), None)?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert_eq!(client.server_leaf()?, &chain.leaf);
		Ok(())
	}

	#[test]
	fn from_chain_rejects_untrusted_chain() -> Result<(), Box<dyn Error>> {
		let chain = create_test_certificate_chain()?;
		let mut client = chain_client(chain.to_arc(), None)?;

		let result = client.build_key_exchange(TEST_SESSION_KEY.to_vec(), None);
		assert!(matches!(result, Err(HandshakeError::CertificateValidationError(_))));
		Ok(())
	}

	/// A pinned server certificate that differs from the provisioned chain
	/// leaf is a configuration mismatch, distinct from a re-handshake
	/// identity violation.
	#[test]
	fn pinned_certificate_mismatch_rejected() -> Result<(), Box<dyn Error>> {
		let chain = create_test_certificate_chain()?;
		let pinned = Arc::new(create_test_certificate().certificate);
		let mut client =
			CmsHandshakeClient::<DefaultCryptoProvider>::new(DefaultCryptoProvider::default(), client_key(), pinned)
				.with_server_certificate_chain(chain.to_arc())
				.with_trust_store(trust_store(Some(chain.root.to_owned()))?);

		let result = client.build_key_exchange(TEST_SESSION_KEY.to_vec(), None);
		assert!(matches!(result, Err(HandshakeError::PinnedCertificateMismatch)));
		Ok(())
	}

	#[test]
	fn from_chain_rejects_empty_chain() -> Result<(), Box<dyn Error>> {
		let chain = create_test_certificate_chain()?;
		let mut client = chain_client(Arc::from(Vec::new()), Some(chain.root))?;

		let result = client.build_key_exchange(TEST_SESSION_KEY.to_vec(), None);
		assert!(matches!(result, Err(HandshakeError::MissingServerCertificate)));
		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
		// Given: A CMS client in init state
		let mut client = TestCmsClientBuilder::new().build()?;

		// When: Trying to process server finished before sending key exchange
		let result = client.process_server_finished(&[]);
		assert!(result.is_err());

		// When: Trying to build client finished before processing server finished
		let result = client.build_client_finished().await;
		assert!(result.is_err());

		Ok(())
	}

	#[test]
	fn test_process_security_accept_rejects_unoffered_profile() -> Result<(), Box<dyn Error>> {
		let offered = create_default_test_profile();
		let mut unoffered = create_default_test_profile();
		unoffered.aead_key_size = Some(16);

		let build_finished_with_accept = |profile| -> Result<Vec<u8>, Box<dyn Error>> {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
			let builder =
				TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(&signing_key, digest_alg, signature_alg)?;
			let mut signed_data = builder.build(&[7u8; 32])?;

			let accept_attr = encode_security_accept(&SecurityAccept::new(profile))?;
			let x509_attr = Attribute {
				oid: HANDSHAKE_SECURITY_ACCEPT,
				values: SetOfVec::try_from(accept_attr.attr_values)?,
			};

			let attrs = Attributes::try_from(vec![x509_attr])?;
			let mut signer_infos: Vec<_> = signed_data.signer_infos.0.iter().cloned().collect();

			signer_infos[0].unsigned_attrs = Some(attrs);
			signed_data.signer_infos = signer_infos.try_into()?;

			Ok(signed_data.to_der()?)
		};

		let offer = SecurityOffer::new(vec![offered]);
		let mut client = TestCmsClientBuilder::new().build()?.with_security_offer(offer);

		let accepted = SignedData::from_der(&build_finished_with_accept(offered)?)?;
		client.apply_security_accept(extract_security_accept_attr(&accepted)?)?;
		assert_eq!(client.selected_profile, Some(offered));

		let rejected = SignedData::from_der(&build_finished_with_accept(unoffered)?)?;
		let attrs = extract_security_accept_attr(&rejected)?;
		let result = client.apply_security_accept(attrs);
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));

		Ok(())
	}
}

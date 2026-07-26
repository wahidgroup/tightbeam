//! ECIES-based client handshake orchestrator.
//!
//! Implements the client side of the TightBeam ECIES handshake protocol.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use core::marker::PhantomData;

use crate::utils::marker::MaybeSendFuture;

use crate::asn1::OctetString;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::ecies::EciesEphemeral;
use crate::crypto::ecies::{encrypt, EciesMessageOps, EciesPublicKeyOps};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::PrehashVerifier;
use crate::crypto::sign::SignatureEncoding;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::{extract_verifying_key_bytes, validate_certificate_expiry};
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::zeroize::{Zeroize, Zeroizing};

use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{client_mux_settings, MuxSettings, SecurityOffer, TransportOffer};
use crate::transport::handshake::receipt::{
	approve_or_fail_closed, certificate_signer_identifier, complete_receipt_artifact, countersign_receipt,
	match_receipt_to_accept, receipt_from_artifact, signer_for_role, verify_receipt_signer, ReceiptApprover,
	ReceiptRole, StoredReceipt,
};
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine};
use crate::transport::handshake::utils::{
	compute_client_auth_digest, compute_transcript_digest, octet_string_to_32_byte_array, validate_state,
};
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake,
};
use crate::transport::handshake::{DirectionalCiphers, HandshakeAlertHandler, HandshakeFinalization};
use crate::x509::Certificate;

/// Client-side ECIES handshake orchestrator.
///
/// Generic over:
/// - `P: CryptoProvider` which defines the complete cryptographic suite
/// - `M`: ECIES message type (curve-specific)
pub struct EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	state: ClientStateMachine,
	client_random: Option<[u8; 32]>,
	/// Exact DER bytes of the sent `ClientHello`, bound into the transcript so a
	/// MITM cannot rewrite the offer undetected (CWE-757).
	client_hello: Option<Vec<u8>>,
	base_session_key: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: Option<&'static [u8]>,
	security_offer: Option<SecurityOffer>,
	transport_offer: Option<TransportOffer>,
	mux_settings: Option<MuxSettings>,
	selected_profile: Option<SecurityProfileDesc>,
	certificate_validator: Option<Arc<dyn CertificateValidation>>,
	client_certificate: Option<Arc<Certificate>>,
	client_key_provider: Option<Arc<dyn SigningKeyProvider>>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	stored_receipt: Option<StoredReceipt>,
	_phantom_provider: PhantomData<P>,
	_phantom_message: PhantomData<M>,
	invariants: HandshakeInvariant,
}

/// Helper trait for extracting verifying keys from certificates.
pub trait ExtractVerifyingKey: Sized {
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError>;
}

impl<P, M> EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
	P::Signature: SignatureEncoding,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + ExtractVerifyingKey,
	P::AeadCipher: KeyInit,
	M: EciesMessageOps,
{
	/// Create a new ECIES handshake client.
	///
	/// # Parameters
	/// - `aad_domain_tag`: Optional domain tag for ECIES encryption (defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`)
	pub fn new(aad_domain_tag: Option<&'static [u8]>) -> Self {
		Self {
			state: ClientStateMachine::default(),
			client_random: None,
			client_hello: None,
			base_session_key: None,
			server_random: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.or(Some(TIGHTBEAM_AAD_DOMAIN_TAG)),
			security_offer: None, // No offer = dealer's choice mode
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			certificate_validator: None,
			client_certificate: None,
			client_key_provider: None,
			receipt_approver: None,
			stored_receipt: None,
			invariants: HandshakeInvariant::default(),
			_phantom_provider: PhantomData,
			_phantom_message: PhantomData,
		}
	}

	/// Create a new ECIES handshake client with optional client identity.
	///
	/// # Parameters
	/// - `aad_domain_tag`: Optional domain tag for ECIES encryption
	/// - `client_certificate`: Optional client certificate for mutual auth
	/// - `client_key_provider`: Optional client key provider for mutual auth
	pub fn new_with_identity(
		aad_domain_tag: Option<&'static [u8]>,
		client_certificate: Option<Arc<Certificate>>,
		client_key_provider: Option<Arc<dyn SigningKeyProvider>>,
	) -> Self {
		Self {
			state: ClientStateMachine::default(),
			client_random: None,
			client_hello: None,
			base_session_key: None,
			server_random: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.or(Some(TIGHTBEAM_AAD_DOMAIN_TAG)),
			security_offer: None, // No offer = dealer's choice mode
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			certificate_validator: None,
			client_certificate,
			client_key_provider,
			receipt_approver: None,
			stored_receipt: None,
			invariants: HandshakeInvariant::default(),
			_phantom_provider: PhantomData,
			_phantom_message: PhantomData,
		}
	}

	/// Set a certificate validator for the handshake.
	#[must_use]
	pub fn with_certificate_validator(mut self, validator: Arc<dyn CertificateValidation>) -> Self {
		self.certificate_validator = Some(validator);
		self
	}

	/// Set client identity for mutual authentication.
	///
	/// # Parameters
	/// - `certificate`: The client's X.509 certificate
	/// - `key_provider`: The client's key provider
	#[must_use]
	pub fn with_client_identity(
		mut self,
		certificate: Arc<Certificate>,
		key_provider: Arc<dyn SigningKeyProvider>,
	) -> Self {
		self.client_certificate = Some(certificate);
		self.client_key_provider = Some(key_provider);
		self
	}

	/// Set the security profile offer for negotiation.
	/// If not set, server will pick default profile (dealer's choice mode).
	#[must_use]
	pub fn with_security_offer(mut self, offer: SecurityOffer) -> Self {
		self.security_offer = Some(offer);
		self
	}

	/// Set the transport capability offer (multiplexing).
	/// If not set, the connection stays lock-step.
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

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
	}

	/// Validate server handshake and extract components.
	///
	/// Fail-closed (CWE-295): a configured certificate validator is
	/// mandatory. Expiry alone authenticates nobody, so a missing validator
	/// aborts the handshake instead of silently degrading.
	fn validate_and_extract_server_handshake(
		&self,
		server_handshake_der: &[u8],
	) -> Result<ServerHandshake, HandshakeError> {
		let server_handshake = ServerHandshake::from_der(server_handshake_der)?;
		let validator = self.certificate_validator.as_ref().ok_or(HandshakeError::MissingTrustStore)?;

		validate_certificate_expiry(&server_handshake.certificate)?;
		validator.evaluate(&server_handshake.certificate)?;

		Ok(server_handshake)
	}

	/// Extract and store server random from handshake.
	fn extract_server_random(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let server_random = octet_string_to_32_byte_array(&server_handshake.server_random)?;
		self.server_random = Some(server_random);

		Ok(())
	}

	/// Compute and store transcript hash.
	fn compute_and_store_transcript_hash(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let client_hello = self.client_hello.as_deref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.ok_or(HandshakeError::InvalidState)?;
		let spki_bytes = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// Bind the negotiated profile and transport capabilities into the
		// transcript. A tampered security_accept or transport_accept yields
		// a different hash and fails signature verification.
		let accept_der = match &server_handshake.security_accept {
			Some(accept) => accept.to_der()?,
			None => Vec::new(),
		};
		let transport_accept_der = match &server_handshake.transport_accept {
			Some(accept) => accept.to_der()?,
			None => Vec::new(),
		};

		let transcript_digest =
			self.compute_transcript_hash(client_hello, &server_random, spki_bytes, &accept_der, &transport_accept_der)?;
		self.transcript_hash = Some(transcript_digest);
		// Invariant: transcript becomes immutable after hash computed
		self.invariants.lock_transcript()?;

		Ok(())
	}

	/// Generate and store base session key.
	fn generate_base_session_key(&mut self) -> Result<(), HandshakeError> {
		let base_key = generate_nonce::<32>(None)?;
		self.base_session_key = Some(base_key);

		Ok(())
	}

	/// Build ClientHello message.
	///
	/// # Returns
	/// DER-encoded ClientHello
	pub fn build_client_hello(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::Init)?;

		// 2. Generate client random
		let client_random = generate_nonce::<32>(None)?;
		self.client_random = Some(client_random);

		// 3. Build ClientHello
		let client_hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			security_offer: self.security_offer.to_owned(),
			transport_offer: self.transport_offer.to_owned(),
		};

		// Retain the exact DER for transcript binding: the full
		// ClientHello (offer included) is hashed on both sides.
		let client_hello_der = client_hello.to_der()?;
		self.client_hello = Some(client_hello_der.to_owned());

		// Transition: mark hello sent
		self.state.transition(ClientHandshakeState::HelloSent)?;
		Ok(client_hello_der)
	}

	/// Process ServerHandshake message and build ClientKeyExchange.
	///
	/// # Parameters
	/// - `server_handshake_der`: DER-encoded ServerHandshake from server
	///
	/// # Returns
	/// DER-encoded ClientKeyExchange
	pub async fn process_server_handshake(&mut self, server_handshake_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validation: must have sent hello
		self.validate_expected_state(ClientHandshakeState::HelloSent)?;
		let _client_random_check = self.client_random.ok_or(HandshakeError::InvalidState)?;

		// 2. Transition to ServerHelloReceived
		self.state.transition(ClientHandshakeState::ServerHelloReceived)?;

		// 3. Decode and validate server handshake
		let mut server_handshake = self.validate_and_extract_server_handshake(server_handshake_der)?;

		// 4. Validate profile negotiation
		self.validate_profile_selection(&server_handshake)?;

		// 5. Validate transport capability negotiation (fails closed on an
		// accept the client never offered)
		let offer = self.transport_offer.as_ref();
		let accept = server_handshake.transport_accept.as_ref();
		self.mux_settings = client_mux_settings(offer, accept)?;

		// 6. Extract server random
		self.extract_server_random(&server_handshake)?;

		// 7. Verify server signature
		self.verify_server_handshake_signature(&server_handshake)?;

		// 8. Validate, approve, and countersign the session receipt
		// (fails closed on mismatch). Consumes the receipt artifact out
		// of the decoded message: its owner is the stored receipt.
		let pending_receipt = self.process_session_receipt(&mut server_handshake).await?;

		// 9. Generate and encrypt session key. The countersignature (and
		// the settlement answer bound inside it) folds into the ECIES
		// payload, never onto the cleartext wire. After encoding it
		// moves into the completed stored artifact (zero copy).
		let encrypted_bytes = self.generate_and_encrypt_session_key(&server_handshake, pending_receipt)?;

		// 10. Handle mutual authentication (signature commits to encrypted_bytes)
		let (client_certificate, client_signature) =
			self.prepare_client_auth(&server_handshake, &encrypted_bytes).await?;

		// 11. Build and encode ClientKeyExchange
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		};

		// 12. Advance to KeyExchangeSent (ServerHelloReceived was entered in step 2)
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(client_kex.to_der()?)
	}

	/// Validate server's profile selection against client's offer.
	///
	/// Handles both negotiation mode (client sent offer) and dealer's choice mode (no offer).
	fn validate_profile_selection(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let accept = server_handshake.security_accept.as_ref().ok_or(HandshakeError::InvalidState)?;
		match &self.security_offer {
			Some(offer) => {
				// Mode 1: Negotiation - verify server's selection is from our offer
				if !offer.profiles.contains(&accept.profile) {
					return Err(HandshakeError::InvalidProfileSelection);
				}
				self.selected_profile = Some(accept.profile);
			}
			None => {
				// Mode 2: Dealer's choice - accept whatever server picked
				self.selected_profile = Some(accept.profile);
			}
		}

		Ok(())
	}

	/// Verify server's signature over the transcript hash.
	fn verify_server_handshake_signature(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let verifying_key = self.extract_verifying_key(&server_handshake.certificate)?;
		self.compute_and_store_transcript_hash(server_handshake)?;

		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		self.verify_server_signature(&verifying_key, &transcript_digest, server_handshake.signature.as_bytes())
	}

	/// Generate base session key and ECIES-encrypt it to the server.
	///
	/// Pending receipt ack passes through encryption by value so
	/// `SignerInfo` is not cloned into the stored receipt.
	fn generate_and_encrypt_session_key(
		&mut self,
		server_handshake: &ServerHandshake,
		pending_receipt: Option<(SignedData, SignerInfo)>,
	) -> Result<Vec<u8>, HandshakeError> {
		self.generate_base_session_key()?;
		let base_key = self.base_session_key.ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;

		let (artifact, receipt_ack) = match pending_receipt {
			Some((artifact, ack)) => (Some(artifact), Some(ack)),
			None => (None, None),
		};

		let (encrypted_bytes, receipt_ack) = self.perform_ecies_encryption(
			&base_key,
			&client_random,
			receipt_ack,
			&server_handshake.certificate,
			self.aad_domain_tag,
		)?;

		if let Some(artifact) = artifact {
			let countersignature = receipt_ack.ok_or(HandshakeError::InvalidState)?;
			let completed = complete_receipt_artifact(artifact, countersignature)?;
			self.stored_receipt = Some(StoredReceipt::try_from(completed)?);
		}

		Ok(encrypted_bytes)
	}

	/// Validate, approve, and countersign the server's session receipt.
	///
	/// Budget-bearing accepts demand a receipt artifact whose body
	/// matches the negotiated session and whose server `SignerInfo`
	/// verifies. Anything else fails closed. The approver (or the
	/// fail-closed default) answers the settlement challenge, and the
	/// client `SignerInfo` binds receipt body plus answer under the
	/// client identity (non-repudiation).
	///
	/// Returns the pending artifact plus the countersignature destined
	/// for the confidential key-exchange payload. Completion is
	/// deferred until after payload encoding so the `SignerInfo` moves
	/// (never copies) into the stored artifact.
	async fn process_session_receipt(
		&mut self,
		server_handshake: &mut ServerHandshake,
	) -> Result<Option<(SignedData, SignerInfo)>, HandshakeError> {
		let granted = server_handshake
			.transport_accept
			.as_ref()
			.and_then(|accept| accept.granted_budgets);

		let credit_unit = server_handshake.transport_accept.as_ref().map(|accept| accept.credit_unit);
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		// Consume the artifact: the completed copy this function stores
		// is its only owner from here on.
		let artifact = server_handshake.session_receipt.take();
		let parsed_receipt = artifact.as_ref().map(receipt_from_artifact).transpose()?;
		let Some(receipt) =
			match_receipt_to_accept::<P::Digest>(parsed_receipt, granted, credit_unit, &transcript_digest)?
		else {
			return Ok(None);
		};

		// Server SignerInfo over the receipt body: third-party verifiable
		// agreement, so an unsigned receipt is no receipt at all.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let server_signer = signer_for_role(&artifact, ReceiptRole::Server)?.ok_or(HandshakeError::ReceiptMissing)?;

		let receipt_der = receipt.to_der()?;
		let expected_sid = certificate_signer_identifier::<P::Digest>(&server_handshake.certificate)?;
		let verifying_key = self.extract_verifying_key(&server_handshake.certificate)?;
		verify_receipt_signer::<P::Digest, P::Signature, _>(
			&receipt_der,
			server_signer,
			ReceiptRole::Server,
			&expected_sid,
			&verifying_key,
		)?;

		// Countersigning demands a full client identity (certificate for
		// the server's verification plus signing key): budgets without
		// mutual authentication fail closed. Checked before approval:
		// approving can spend an irreversible settlement answer, so every
		// local precondition must already hold.
		if self.client_certificate.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let key_provider = self.client_key_provider.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;

		// Approve the receipt and answer its challenge (fail-closed
		// without an approver).
		let response = approve_or_fail_closed(self.receipt_approver.as_deref(), &receipt).await?;
		let response_bytes = response.as_ref().map(OctetString::as_bytes);
		let countersignature =
			countersign_receipt::<P::Digest>(&receipt, response_bytes, key_provider.as_ref()).await?;

		Ok(Some((artifact, countersignature)))
	}

	/// Prepare client authentication materials if required or available.
	///
	/// The signature covers `Digest(transcript_hash || encrypted_data || cert_der)`
	/// so it cannot be spliced onto a different key exchange or identity.
	///
	/// Returns tuple of (optional certificate, optional signature).
	async fn prepare_client_auth(
		&self,
		server_handshake: &ServerHandshake,
		encrypted_data: &[u8],
	) -> Result<(Option<Certificate>, Option<OctetString>), HandshakeError> {
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		let cert = match (&self.client_certificate, server_handshake.client_cert_required) {
			(Some(cert), _) => cert,
			(None, true) => return Err(HandshakeError::MutualAuthRequired),
			(None, false) => return Ok((None, None)),
		};
		let key_provider = match (&self.client_key_provider, server_handshake.client_cert_required) {
			(Some(provider), _) => provider,
			(None, true) => return Err(HandshakeError::MutualAuthRequired),
			(None, false) => return Err(HandshakeError::InvalidState),
		};

		let cert_der = cert.to_der()?;
		let auth_digest = compute_client_auth_digest::<P::Digest>(&transcript_digest, encrypted_data, &cert_der)?;
		let signature_bytes = key_provider.sign_prehash(&auth_digest).await?;

		let cert = Certificate::clone(cert);
		let signature = OctetString::new(signature_bytes)?;
		Ok((Some(cert), Some(signature)))
	}
	/// Complete the handshake and derive the directional session keys.
	///
	/// # Returns
	/// Client-to-server and server-to-client AEAD ciphers from the provider
	pub fn complete(&mut self) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Derive final session keys
		let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

		// Concatenate client_random || server_random as salt for AEAD derivation
		let mut salt = Zeroizing::new([0u8; 64]);
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);
		let session_ciphers = self.derive_directional_aead(base_key, salt.as_slice())?;

		// Invariant: AEAD key derivation occurs exactly once after transcript locked
		self.invariants.derive_aead_once()?;

		// 3. Transition to complete
		self.state.transition(ClientHandshakeState::Completed)?;

		// 4. Clear sensitive data in place (Option impl zeroes payload, then None)
		self.base_session_key.zeroize();
		self.client_random.zeroize();
		self.server_random.zeroize();

		Ok(session_ciphers)
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// Get the transcript hash (if available).
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}

	/// Get the negotiated multiplexing settings (if any).
	pub fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.mux_settings
	}

	/// Get the dual-signed session receipt (if the completed handshake
	/// carried budgets).
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	// Helper methods

	fn extract_verifying_key(&self, cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		P::VerifyingKey::extract_from_certificate(cert)
	}

	fn compute_transcript_hash(
		&self,
		client_hello: &[u8],
		server_random: &[u8; 32],
		spki_bytes: &[u8],
		accept_der: &[u8],
		transport_accept_der: &[u8],
	) -> Result<[u8; 32], HandshakeError> {
		let mut data = Vec::with_capacity(
			client_hello.len() + 32 + spki_bytes.len() + accept_der.len() + transport_accept_der.len(),
		);
		data.extend_from_slice(client_hello);
		data.extend_from_slice(server_random);
		data.extend_from_slice(spki_bytes);
		data.extend_from_slice(accept_der);
		data.extend_from_slice(transport_accept_der);

		compute_transcript_digest::<P::Digest>(&data)
	}

	fn verify_server_signature(
		&self,
		verifying_key: &P::VerifyingKey,
		digest: &[u8; 32],
		signature_bytes: &[u8],
	) -> Result<(), HandshakeError> {
		let signature = P::Signature::try_from(signature_bytes).map_err(|e| e.into())?;

		verifying_key.verify_prehash(digest, &signature)?;

		Ok(())
	}

	/// Encrypt the session payload to the server's public key.
	///
	/// Hands the `receipt_ack` back after encoding: the caller moves it
	/// into the completed stored artifact instead of cloning it.
	fn perform_ecies_encryption(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		receipt_ack: Option<SignerInfo>,
		server_certificate: &Certificate,
		associated_data: Option<&[u8]>,
	) -> Result<(Vec<u8>, Option<SignerInfo>), HandshakeError> {
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_key.as_slice())?,
			client_random: OctetString::new(client_random.as_slice())?,
			receipt_ack,
		};

		// The DER buffer holds the base session key: wiped when dropped,
		// along with the transient OCTET STRING copy inside the payload.
		let plaintext = Zeroizing::new(payload.to_der()?);
		payload.base_key.into_bytes().zeroize();
		let receipt_ack = payload.receipt_ack;

		let recipient_pubkey = PublicKey::<P::Curve>::from_sec1_bytes(
			server_certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		// TODO decouple OsRng
		let encrypted_message = encrypt::<_, _, _, M, P::Kdf, P::AeadCipher>(
			&recipient_pubkey,
			plaintext.as_slice(),
			associated_data,
			Some(&mut rand_core::OsRng),
		)?;

		Ok((encrypted_message.to_bytes(), receipt_ack))
	}
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P, M> HandshakeFinalization<P> for EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P, M> HandshakeAlertHandler for EciesHandshakeClient<P, M> where P: CryptoProvider {}

// ============================================================================
// ClientHandshakeProtocol Implementation
// ============================================================================

impl<P, M> ClientHandshakeProtocol for EciesHandshakeClient<P, M>
where
	P: CryptoProvider + Send + Sync,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
	P::Signature: SignatureEncoding + Send + Sync,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + ExtractVerifyingKey + Send + Sync,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
	M: EciesMessageOps + Send + Sync,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<Vec<u8>, Self::Error>> {
		Box::pin(async move { self.build_client_hello() })
	}

	fn handle_response<'a, 'b>(&'a mut self, msg: &'b [u8]) -> MaybeSendFuture<'a, Result<Option<Vec<u8>>, Self::Error>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Process server handshake and build client key exchange
			let client_kex = self.process_server_handshake(msg).await?;
			Ok(Some(client_kex))
		})
	}

	#[cfg(feature = "aead")]
	fn complete<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<SessionKeys, Self::Error>> {
		Box::pin(async move {
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;
			// Delegate to the inherent method: single source of truth for state
			// validation, AEAD derivation, invariants, and cleanup.
			let ciphers = EciesHandshakeClient::complete(self)?;

			Ok(SessionKeys::for_client(
				ciphers.client_to_server,
				ciphers.server_to_client,
				aead_oid,
			))
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}

	fn negotiated_mux(&self) -> Option<MuxSettings> {
		EciesHandshakeClient::negotiated_mux(self)
	}

	fn session_receipt(&self) -> Option<&StoredReceipt> {
		EciesHandshakeClient::session_receipt(self)
	}
}

// Implement helper trait for secp256k1 verifying key
#[cfg(feature = "secp256k1")]
impl ExtractVerifyingKey for Secp256k1VerifyingKey {
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError> {
		let public_key_bytes = extract_verifying_key_bytes(cert);
		let public_key = k256::PublicKey::from_sec1_bytes(public_key_bytes)?;
		Ok(Self::from(public_key))
	}
}

#[cfg(test)]
mod tests {
	use core::error::Error;

	use super::*;
	use crate::crypto::ecies::Secp256k1EciesMessage;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::PrehashSigner;
	use crate::der::Encode;
	use crate::oids::{
		AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512,
		SIGNER_ECDSA_WITH_SHA3_512,
	};
	use crate::random::generate_nonce;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::ServerHandshake;

	#[tokio::test]
	async fn test_client_state_flow() -> Result<(), Box<dyn Error>> {
		// Given: A client in init state that trusts the test server certificate
		let test_cert = create_test_certificate();
		let mut client = TestEciesClientBuilder::new()
			.with_trusted_certificate(test_cert.certificate.to_owned())
			.build();
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: Client builds client hello
		let client_hello_der = client.build_client_hello()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent); // Hello sent
		assert!(client.client_random.is_some());

		// And: Server creates a valid server handshake response
		let server_random = generate_nonce::<32>(None)?;
		let accept_der = SecurityAccept::new(create_default_test_profile()).to_der()?;
		let transcript_hash = compute_test_transcript_hash(
			&client_hello_der,
			&server_random,
			test_cert
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
			&accept_der,
		);

		let signature_bytes: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let server_handshake_der =
			create_test_server_handshake(&test_cert.certificate, &server_random, &signature_bytes.to_bytes())?;

		// When: Client processes the server handshake
		let client_kex_der = client.process_server_handshake(&server_handshake_der).await?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert!(client.base_session_key.is_some());
		assert!(client.transcript_hash.is_some());

		// And: Client key exchange message is valid
		let _client_kex = ClientKeyExchange::from_der(&client_kex_der)?;
		// When: Client completes the handshake
		let _session_key = client.complete()?;

		// Then: Handshake is complete
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	/// A client without a certificate validator must abort instead of
	/// degrading to expiry-only server authentication (CWE-295).
	#[tokio::test]
	async fn test_missing_validator_fails_closed() -> Result<(), Box<dyn Error>> {
		let mut client = TestEciesClientBuilder::new().build();
		let client_hello_der = client.build_client_hello()?;

		let test_cert = create_test_certificate();
		let server_random = generate_nonce::<32>(None)?;
		let accept_der = SecurityAccept::new(create_default_test_profile()).to_der()?;
		let transcript_hash = compute_test_transcript_hash(
			&client_hello_der,
			&server_random,
			test_cert
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
			&accept_der,
		);
		let signature_bytes: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let server_handshake_der =
			create_test_server_handshake(&test_cert.certificate, &server_random, &signature_bytes.to_bytes())?;

		let result = client.process_server_handshake(&server_handshake_der).await;
		assert!(matches!(result, Err(HandshakeError::MissingTrustStore)));
		Ok(())
	}

	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
		// Given: A fresh client in init state
		let mut client = TestEciesClientBuilder::new().build();

		// When: Trying to process server handshake before building client hello
		let result = client.process_server_handshake(&[]).await;
		assert!(result.is_err());

		// When: Client builds client hello
		let _client_hello = client.build_client_hello()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent);

		// When: Trying to complete before processing server handshake
		let result = client.complete();
		assert!(result.is_err());

		Ok(())
	}

	/// Test client-side profile validation
	#[tokio::test]
	async fn test_client_profile_validation() -> Result<(), Box<dyn Error>> {
		let mk_profile = |id: u8| SecurityProfileDesc {
			digest: Some(match id {
				1 => HASH_SHA3_256,
				2 => HASH_SHA3_384,
				_ => HASH_SHA3_512,
			}),
			aead: Some(AES_256_GCM),
			aead_key_size: Some(32),
			signature: Some(SIGNER_ECDSA_WITH_SHA3_512),
			kdf: Some(HASH_SHA3_256), // HKDF-SHA3-256
			curve: Some(CURVE_SECP256K1),
			key_wrap: Some(AES_256_WRAP),
			kem: None,
		};

		let (p_a, p_b, p_c) = (mk_profile(1), mk_profile(2), mk_profile(3));
		let test_cert = create_test_certificate();

		// Helper to create client with security offer and build hello
		#[allow(clippy::type_complexity)]
		let setup_client = |offer: Option<SecurityOffer>| -> Result<
			(EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>, Vec<u8>),
			Box<dyn Error>,
		> {
			let mut client = TestEciesClientBuilder::new()
				.with_trusted_certificate(test_cert.certificate.to_owned())
				.build();
			if let Some(offer) = offer {
				client = client.with_security_offer(offer);
			}

			let hello = client.build_client_hello()?;
			Ok((client, hello))
		};

		// Helper to create signed server handshake
		let create_server_response = |client_hello_der: &[u8],
		                              server_random: [u8; 32],
		                              accepted_profile: &SecurityProfileDesc|
		 -> Result<Vec<u8>, Box<dyn Error>> {
			let accept_der = SecurityAccept::new(*accepted_profile).to_der()?;
			let transcript_hash = compute_test_transcript_hash(
				client_hello_der,
				&server_random,
				test_cert
					.certificate
					.tbs_certificate
					.subject_public_key_info
					.subject_public_key
					.raw_bytes(),
				&accept_der,
			);
			let signature: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
			let signature_bytes = signature.to_bytes().to_vec();

			let response = ServerHandshake {
				certificate: test_cert.certificate.to_owned(),
				server_random: OctetString::new(server_random)?,
				signature: OctetString::new(signature_bytes)?,
				security_accept: Some(SecurityAccept::new(*accepted_profile)),
				client_cert_required: false,
				transport_accept: None,
				session_receipt: None,
			};
			Ok(response.to_der()?)
		};

		// Test 1: Client offers [A, B], server accepts B -> OK
		{
			let (mut client, client_hello_der) = setup_client(Some(SecurityOffer::new(vec![p_a, p_b])))?;
			let server_response = create_server_response(&client_hello_der, [2u8; 32], &p_b)?;
			let _kex = client.process_server_handshake(&server_response).await?;
			assert_eq!(client.selected_profile, Some(p_b));
		}

		// Test 2: Client offers [A, B], server accepts C (not in offer) -> FAIL
		{
			let (mut client, client_hello_der) = setup_client(Some(SecurityOffer::new(vec![p_a, p_b])))?;
			let server_response = create_server_response(&client_hello_der, [3u8; 32], &p_c)?;
			let result = client.process_server_handshake(&server_response).await;
			assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		}

		// Test 3: No offer, server picks -> OK (dealer's choice)
		{
			let (mut client, client_hello_der) = setup_client(None)?;
			let server_response = create_server_response(&client_hello_der, [4u8; 32], &p_a)?;
			let _kex = client.process_server_handshake(&server_response).await?;
			assert_eq!(client.selected_profile, Some(p_a));
		}

		Ok(())
	}
}

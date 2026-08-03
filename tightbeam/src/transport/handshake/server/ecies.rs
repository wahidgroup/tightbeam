//! ECIES-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam ECIES handshake protocol.
//! Generic over `P: CryptoProvider` for cryptographic operations.

#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(not(feature = "std"))]
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::marker::PhantomData;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::constants::{TIGHTBEAM_AAD_DOMAIN_TAG, TIGHTBEAM_ECIES_KDF_INFO};
use crate::crypto::aead::{Aead, AeadCore, KeyInit, Nonce, Payload, SessionKeys};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::ecies::EciesError;
use crate::crypto::ecies::EciesMessageOps;
use crate::crypto::kdf::ecies_kdf;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::{PrehashVerifier, SignatureEncoding};
use crate::crypto::x509::policy::CertificateValidation;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::common::derive_epoch_materials;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	authorize_transport, server_mux_settings, DefaultStrengthFloor, MuxSettings, ProfileStrengthPolicy, SecurityAccept,
	TransportAccept, TransportAuthorizer, TransportOffer,
};
use crate::transport::handshake::receipt::{
	certificate_signer_identifier, complete_receipt_artifact, record_receipt_outcome, settle_receipt_ack, sign_receipt,
	SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict, StoredReceipt,
};
use crate::transport::handshake::state::HandshakeInvariant;
use crate::transport::handshake::state::{ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::utils::{
	clear_session_randoms, compute_client_auth_digest, compute_ecies_transcript_hash, extract_verifying_key_from_cert,
	octet_string_to_32_byte_array, validate_state,
};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake, ServerHandshakeProtocol,
};
use crate::transport::handshake::{
	DirectionalCiphers, EpochMaterials, HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation,
};
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};
use crate::ZeroizingBytes;

/// Server-side ECIES handshake orchestrator.
///
/// Manages the complete server handshake flow:
/// 1. Receives ClientHello with random nonce
/// 2. Sends ServerHandshake (certificate, random, signature over transcript)
/// 3. Receives and decrypts ClientKeyExchange with ECIES-encrypted session key
///
/// Generic over:
/// - `P: CryptoProvider` for cryptographic operations
pub struct EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	state: ServerStateMachine,
	server_key_provider: Arc<dyn SigningKeyProvider>,
	server_cert: Arc<Certificate>,
	client_random: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: Option<&'static [u8]>,
	supported_profiles: Vec<SecurityProfileDesc>,
	strength_policy: Option<Arc<dyn ProfileStrengthPolicy + Send + Sync>>,
	selected_profile: Option<SecurityProfileDesc>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	mux_settings: Option<MuxSettings>,
	client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	validated_client_cert: Option<Arc<Certificate>>,
	session_receipt: Option<SessionReceipt>,
	receipt_artifact: Option<SignedData>,
	stored_receipt: Option<StoredReceipt>,
	epoch_materials: Option<EpochMaterials>,
	_phantom: PhantomData<P>,
	invariants: HandshakeInvariant,
}

/// Parts of the decrypted ECIES key-exchange payload: session key
/// material, the anti-replay random, and the client's receipt
/// countersignature (absent for unmetered sessions).
struct SessionPayload {
	base_session_key: [u8; 32],
	client_random: [u8; 32],
	/// Client receipt `SignerInfo`. Its signed attributes bind the
	/// bearer settlement answer, so it arrives only through this
	/// confidential payload.
	receipt_ack: Option<SignerInfo>,
}

impl<P> EciesHandshakeServer<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
	P::Signature: SignatureEncoding,
{
	/// Create a new ECIES handshake server.
	///
	/// # Parameters
	/// - `server_key_provider`: The key provider for cryptographic operations
	/// - `server_cert`: The server's certificate to send to client
	/// - `aad_domain_tag`: Optional domain tag for ECIES decryption (defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`)
	/// - `client_validators`: Optional validators for client certificate authentication (mutual auth)
	pub fn new(
		server_key_provider: Arc<dyn SigningKeyProvider>,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	) -> Self {
		Self {
			state: ServerStateMachine::default(),
			server_key_provider,
			server_cert,
			client_random: None,
			server_random: None,
			base_session_key: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.or(Some(TIGHTBEAM_AAD_DOMAIN_TAG)),
			supported_profiles: Vec::new(), // Must be set via with_supported_profiles()
			strength_policy: None,          // Defaults to DefaultStrengthFloor
			selected_profile: None,
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			mux_settings: None,
			client_validators,
			validated_client_cert: None,
			session_receipt: None,
			receipt_artifact: None,
			stored_receipt: None,
			epoch_materials: None,
			invariants: HandshakeInvariant::default(),
			_phantom: PhantomData,
		}
	}

	/// Set the server's supported security profiles for negotiation.
	/// Server must have at least one supported profile configured.
	#[must_use]
	pub fn with_supported_profiles(mut self, profiles: Vec<SecurityProfileDesc>) -> Self {
		self.supported_profiles = profiles;
		self
	}

	/// Override the minimum-strength policy applied during negotiation.
	///
	/// Defaults to `DefaultStrengthFloor` (256-bit AEAD key, >= 256-bit digest).
	/// Pass `NoStrengthFloor` only where weaker profiles must remain negotiable.
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.strength_policy = Some(policy);
		self
	}

	/// Enable transport multiplexing with the given local advertisement.
	/// Multiplexing activates only when the client also offers it.
	#[must_use]
	pub fn with_transport_config(mut self, config: TransportOffer) -> Self {
		self.transport_config = Some(config);
		self
	}

	/// Override the budget-grant policy consulted between the client's
	/// transport offer and the server's accept. Without an authorizer
	/// the server grants its local configuration ceiling.
	#[must_use]
	pub fn with_transport_authorizer(mut self, authorizer: Arc<dyn TransportAuthorizer>) -> Self {
		self.transport_authorizer = Some(authorizer);
		self
	}

	/// Set the observer that records the [`SessionOutcome`] of every
	/// budget-bearing session, successful or refused.
	#[must_use]
	pub fn with_session_observer(mut self, observer: Arc<dyn SessionObserver>) -> Self {
		self.session_observer = Some(observer);
		self
	}

	/// Process ClientHello and build ServerHandshake message.
	///
	/// # Parameters
	/// - `client_hello_der`: DER-encoded ClientHello from client
	///
	/// # Returns
	/// DER-encoded ServerHandshake
	pub async fn process_client_hello(&mut self, client_hello_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// 1. Validate current state is Init
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Decode ClientHello message
		let client_hello = self.decode_client_hello(client_hello_der)?;

		// 3. Profile negotiation using trait method
		let selected = self.negotiate_profile(client_hello.security_offer.as_ref())?;
		self.selected_profile = Some(selected);

		let security_accept = SecurityAccept::new(selected);

		// 4. Transport capability negotiation: mux activates only when
		// offered AND locally enabled. The authorizer (when configured)
		// decides the budget grant and the settlement challenge before
		// the accept enters the transcript.
		let authorized = authorize_transport(
			client_hello.transport_offer.as_ref(),
			self.transport_config.as_ref(),
			self.transport_authorizer.as_deref(),
		)
		.await?;

		let transport_accept = authorized.as_ref().map(|authorized| authorized.accept);
		let settlement_challenge = authorized.and_then(|authorized| authorized.challenge);
		if let (Some(offer), Some(accept)) = (client_hello.transport_offer.as_ref(), transport_accept.as_ref()) {
			self.mux_settings = Some(server_mux_settings(offer, accept));
		}

		// 5. Extract and store client random
		let client_random = octet_string_to_32_byte_array(&client_hello.client_random)?;
		self.client_random = Some(client_random);

		// 6. Generate and store server random
		let server_random = self.generate_server_random()?;

		// 7. Compute transcript hash
		let spki_bytes = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// Bind the full ClientHello DER (offers included), the negotiated
		// profile, and the transport accept into the transcript so
		// tampering with any of them invalidates the server signature.
		let accept_der = security_accept.to_der()?;
		let transport_accept_der = match &transport_accept {
			Some(accept) => accept.to_der()?,
			None => Vec::new(),
		};
		let transcript_digest = compute_ecies_transcript_hash::<P::Digest>(
			client_hello_der,
			&server_random,
			spki_bytes,
			&accept_der,
			&transport_accept_der,
		)?;
		self.transcript_hash = Some(transcript_digest);
		self.invariants.lock_transcript()?;

		// 8. Sign transcript hash using KeyProvider
		let signature_bytes = self.sign_transcript_hash(&transcript_digest).await?;

		// 9. Issue the session receipt: the transcript hash pins it to
		// this session, the server signature makes it third-party verifiable
		self.issue_session_receipt(&transcript_digest, transport_accept.as_ref(), settlement_challenge)
			.await?;

		// 10. Build and encode ServerHandshake
		let server_handshake_der =
			self.build_server_handshake(server_random, signature_bytes, Some(security_accept), transport_accept)?;

		// 11. Transition state through ServerHelloReceived to ServerHelloSent
		self.state.transition(ServerHandshakeState::ClientHelloReceived)?;
		self.state.transition(ServerHandshakeState::ServerHelloSent)?;

		Ok(server_handshake_der)
	}

	/// Build and sign the [`SessionReceipt`] when the accept grants
	/// budgets.
	///
	/// Fail closed: budgets demand a client countersignature,
	/// so a budget-bearing accept without mutual authentication
	/// configured aborts the handshake.
	async fn issue_session_receipt(
		&mut self,
		transcript_digest: &[u8; 32],
		transport_accept: Option<&TransportAccept>,
		challenge: Option<OctetString>,
	) -> Result<(), HandshakeError> {
		let Some(accept) = transport_accept else {
			return Ok(());
		};
		let Some(granted) = accept.granted_budgets else {
			return Ok(());
		};

		if self.client_validators.is_none() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let (receipt, artifact) = sign_receipt::<P::Digest>(
			*transcript_digest,
			granted,
			accept.credit_unit,
			challenge,
			self.server_key_provider.as_ref(),
		)
		.await?;

		self.receipt_artifact = Some(artifact);
		self.session_receipt = Some(receipt);

		Ok(())
	}

	/// Process ClientKeyExchange message (decrypt ECIES-encrypted session key).
	///
	/// # Parameters
	/// - `client_kex_der`: DER-encoded ClientKeyExchange from client
	///
	/// # Returns
	/// Success (session key stored internally)
	pub async fn process_client_key_exchange(&mut self, client_kex_der: &[u8]) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// 1. Validate current state is ServerHelloSent
		self.validate_expected_state(ServerHandshakeState::ServerHelloSent)?;

		// 2. Decode ClientKeyExchange message
		let mut client_kex = self.decode_client_key_exchange(client_kex_der)?;

		// 3. Validate client certificate if mutual auth is configured
		self.validate_client_certificate(&mut client_kex)?;

		// 4. Get encrypted bytes from the message
		let encrypted_bytes = client_kex.encrypted_data.as_bytes();

		// 5. Decrypt ECIES payload (async - uses KeyProvider for ECDH)
		let decrypted_payload = self.decrypt_ecies_payload(encrypted_bytes).await?;

		// 6. Extract base session key, client random, and the confidential
		// receipt countersignature from the decrypted payload
		let SessionPayload { base_session_key, client_random, receipt_ack } =
			self.extract_session_data_from_payload(&decrypted_payload)?;

		// 7. Verify client random matches stored value (prevents replay attacks)
		self.verify_client_random(&client_random)?;

		// 8. Verify the receipt countersignature and settle, strictly
		// after decrypt and replay verification: settlement is an
		// irreversible external side effect, so it must be the last gate,
		// downstream of every cheaper rejection. The countersignature
		// arrives confidentially inside the decrypted payload.
		self.process_receipt_ack(receipt_ack).await?;

		// 9. Store base session key
		self.base_session_key = Some(base_session_key);

		// 10. Transition state to KeyExchangeReceived
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the directional session keys.
	///
	/// # Returns
	/// Client-to-server and server-to-client AEAD ciphers from the provider
	pub fn complete(&mut self) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError> {
		// 1. Validate current state is KeyExchangeReceived
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

		// 2. Get required values for key derivation
		let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		// 3. Derive final session keys using trait finalization (client_random || server_random)
		let mut salt = Zeroizing::new([0u8; 64]);
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		let salt_bytes = salt.as_slice();
		let session_ciphers = self.derive_directional_aead(base_session_key, salt_bytes)?;
		self.invariants.derive_aead_once()?;

		// 4. Derive the epoch-0 rekey materials alongside the traffic
		// keys, from the same inputs plus the transcript hash: an in-band
		// renewal later chains from this secret without touching the
		// handshake again
		if let Some(transcript_hash) = self.transcript_hash {
			let materials = derive_epoch_materials::<P>(base_session_key, salt_bytes, transcript_hash)?;
			self.epoch_materials = Some(materials);
		}

		// 5. Transition to complete state
		self.state.transition(ServerHandshakeState::Completed)?;

		// 6. Clear sensitive data
		self.clear_sensitive_data();

		Ok(session_ciphers)
	}

	/// Get the current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
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

	/// Get the dual-signed session receipt (if the completed handshake
	/// carried budgets).
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	// Helper methods

	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
	}

	fn decode_client_hello(&self, client_hello_der: &[u8]) -> Result<ClientHello, HandshakeError> {
		Ok(ClientHello::from_der(client_hello_der)?)
	}

	fn generate_server_random(&mut self) -> Result<[u8; 32], HandshakeError> {
		let server_random = generate_nonce::<32>(None)?;
		self.server_random = Some(server_random);

		Ok(server_random)
	}

	async fn sign_transcript_hash(&self, transcript_digest: &[u8; 32]) -> Result<Vec<u8>, HandshakeError> {
		// Use KeyProvider to sign - returns k256::ecdsa::Signature
		let sig = self.server_key_provider.sign_prehash(transcript_digest).await?;
		Ok(sig.to_vec())
	}

	fn build_server_handshake(
		&self,
		server_random: [u8; 32],
		signature_bytes: Vec<u8>,
		security_accept: Option<SecurityAccept>,
		transport_accept: Option<TransportAccept>,
	) -> Result<Vec<u8>, HandshakeError> {
		let server_handshake = ServerHandshake {
			certificate: Certificate::clone(&self.server_cert),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature_bytes)?,
			security_accept,
			client_cert_required: self.client_validators.is_some(),
			transport_accept,
			// Dual ownership by design: this copy is DER-encoded onto
			// the wire and dropped; the retained artifact absorbs the
			// client SignerInfo at settlement.
			session_receipt: self.receipt_artifact.clone(),
		};

		Ok(server_handshake.to_der()?)
	}

	pub fn decode_client_key_exchange(&self, der_bytes: &[u8]) -> Result<ClientKeyExchange, HandshakeError> {
		ClientKeyExchange::from_der(der_bytes).map_err(Into::into)
	}

	async fn decrypt_ecies_payload(&self, encrypted_bytes: &[u8]) -> Result<ZeroizingBytes, HandshakeError> {
		// Parse the ECIES message using the negotiated curve's wire format.
		let (ephemeral_pubkey, ciphertext_bytes) = {
			let encrypted_message = <P::EciesMessage as EciesMessageOps>::from_bytes(encrypted_bytes)?;
			(
				encrypted_message.ephemeral_pubkey().to_vec(),
				encrypted_message.ciphertext().to_vec(),
			)
		};

		// Use KeyProvider to perform ECDH. The shared secret arrives already
		// wrapped in SecretSlice.
		let shared_secret = self.server_key_provider.key_agreement(&ephemeral_pubkey).await?;
		// Derive encryption key using the negotiated KDF.
		let k_enc = ecies_kdf::<P::Kdf>(&ephemeral_pubkey, shared_secret, TIGHTBEAM_ECIES_KDF_INFO, None)?;

		// AEAD geometry comes from the negotiated cipher, not literals.
		let nonce_size = <P::AeadCipher as AeadCore>::NonceSize::USIZE;
		let tag_size = <P::AeadCipher as AeadCore>::TagSize::USIZE;
		let key_size = <P::AeadCipher as KeySizeUser>::KeySize::USIZE;

		// Extract nonce and ciphertext
		let ciphertext_bytes = ciphertext_bytes.as_slice();
		if ciphertext_bytes.len() < nonce_size + tag_size {
			return Err(HandshakeError::EciesError(EciesError::InvalidCiphertext));
		}

		let nonce = Nonce::<P::AeadCipher>::from_slice(&ciphertext_bytes[..nonce_size]);
		let ciphertext_with_tag = &ciphertext_bytes[nonce_size..];

		// Build the negotiated cipher from the derived key material.
		let key_material = &k_enc[..key_size];
		let cipher = P::AeadCipher::new_from_slice(key_material)
			.map_err(|_| HandshakeError::InvalidKeySize { expected: key_size, received: k_enc.len() })?;

		let payload = match self.aad_domain_tag {
			Some(aad) => Payload { msg: ciphertext_with_tag, aad },
			None => Payload { msg: ciphertext_with_tag, aad: b"" },
		};

		// The plaintext carries the base session key and the bearer
		// settlement answer: wiped when the buffer drops
		let plaintext = Zeroizing::new(cipher.decrypt(nonce, payload)?);
		Ok(plaintext)
	}

	/// Parse the decrypted DER [`EciesSessionPayload`] into its parts,
	/// enforcing the fixed 32-byte geometry of the key material.
	fn extract_session_data_from_payload(&self, decrypted_payload: &[u8]) -> Result<SessionPayload, HandshakeError> {
		let payload = EciesSessionPayload::from_der(decrypted_payload)
			.map_err(|_| HandshakeError::InvalidDecryptedPayloadSize)?;

		let base_key_bytes = payload.base_key.as_bytes();
		let random_bytes = payload.client_random.as_bytes();
		if base_key_bytes.len() != 32 || random_bytes.len() != 32 {
			return Err(HandshakeError::InvalidDecryptedPayloadSize);
		}

		let mut base_session_key = [0u8; 32];
		let mut client_random = [0u8; 32];
		base_session_key.copy_from_slice(base_key_bytes);
		client_random.copy_from_slice(random_bytes);

		// Wipe the transient key-material copy inside the decoded payload.
		let EciesSessionPayload { base_key, client_random: _, receipt_ack } = payload;
		base_key.into_bytes().zeroize();

		Ok(SessionPayload { base_session_key, client_random, receipt_ack })
	}

	fn verify_client_random(&self, client_random_from_payload: &[u8; 32]) -> Result<(), HandshakeError> {
		let expected_client_random = self.client_random.ok_or(HandshakeError::MissingClientRandom)?;
		let is_equal: bool = client_random_from_payload.ct_eq(&expected_client_random).into();
		if !is_equal {
			Err(HandshakeError::ClientRandomMismatchReplay)
		} else {
			Ok(())
		}
	}

	/// Validate and capture the offered client identity when mutual auth
	/// is configured.
	///
	/// When `client_validators` is set, a client certificate is required.
	/// Every validator MUST pass before the possession check, and only
	/// then is the identity stored. When validators are absent
	/// (server-auth only), the session stays anonymous: an offered
	/// certificate is discarded and never reaches
	/// [`SessionContext`](crate::policy::SessionContext).
	#[cfg(feature = "x509")]
	fn validate_client_certificate(&mut self, client_kex: &mut ClientKeyExchange) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		let (client_cert, validators) = match (client_kex.client_certificate.take(), &self.client_validators) {
			(None, Some(_)) => return Err(HandshakeError::MissingClientCertificate),
			(None, None) => return Ok(()),
			// Server-auth only: discard offered identity so authorization
			// paths cannot key off an unvalidated certificate.
			(Some(_), None) => {
				let _ = client_kex.client_signature.take();
				return Ok(());
			}
			(Some(cert), Some(validators)) => (cert, validators),
		};

		// Chain validation runs before the possession check, so a
		// certificate refused by any validator is never captured.
		for validator in validators.iter() {
			validator.evaluate(&client_cert)?;
		}

		// Verify client signature over the bound auth digest so capture
		// never records an identity the peer cannot sign for.
		let client_signature = client_kex
			.client_signature
			.as_ref()
			.ok_or(HandshakeError::SignatureVerificationFailed)?;

		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		// Recompute the digest the client signed: transcript hash bound to
		// this exact encrypted payload and this exact certificate,
		// so the signature cannot be spliced from another exchange.
		let cert_der = client_cert.to_der()?;
		let auth_digest =
			compute_client_auth_digest::<P::Digest>(&transcript_hash, client_kex.encrypted_data.as_bytes(), &cert_der)?;

		let public_key = extract_verifying_key_from_cert::<P::Curve>(&client_cert)?;
		let signature = P::Signature::try_from(client_signature.as_bytes())
			.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

		let verifying_key = P::VerifyingKey::from(&public_key);
		verifying_key.verify_prehash(&auth_digest, &signature)?;

		// Storing the certificate locks the captured identity; this is
		// the only write after construction.
		self.validated_client_cert = Some(Arc::new(client_cert));

		Ok(())
	}

	/// Verify the client's receipt countersignature and settle with the
	/// authorizer.
	///
	/// Does nothing when no receipt was issued. Otherwise fails closed:
	/// a missing or invalid countersignature aborts the handshake, and a
	/// settle refusal aborts with the application code. The completed
	/// [`StoredReceipt`] is retained only after both.
	#[cfg(feature = "x509")]
	async fn process_receipt_ack(&mut self, receipt_ack: Option<SignerInfo>) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// Taken, not cloned: the outcome owns the receipt (and its
		// unbounded ancillary challenge).
		let Some(receipt) = self.session_receipt.take() else {
			return Ok(());
		};

		// The artifact's single owner from here on: it either completes
		// into the outcome or travels server-signed as-is.
		let server_artifact = self.receipt_artifact.take().ok_or(HandshakeError::InvalidState)?;

		let (verdict, ancillary_response) = match receipt_ack.as_ref() {
			None => (SessionVerdict::CountersignatureMissing, None),
			Some(ack) => {
				let client_cert = self.validated_client_cert.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
				let expected_sid = certificate_signer_identifier::<P::Digest>(client_cert)?;
				let public_key = extract_verifying_key_from_cert::<P::Curve>(client_cert)?;
				let verifying_key = P::VerifyingKey::from(&public_key);

				settle_receipt_ack::<P::Digest, P::Signature, _>(
					&receipt,
					Some(ack),
					&expected_sid,
					&verifying_key,
					self.transport_authorizer.as_deref(),
				)
				.await?
			}
		};

		// Evidence DER before the move: the raw bytes stay in the
		// outcome even when the SignerInfo folds into the artifact.
		let countersignature = receipt_ack.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact; a failed
		// one stays out of it but its DER remains in the outcome as
		// evidence.
		let artifact = match (verdict, receipt_ack) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(ack)) => {
				complete_receipt_artifact(server_artifact, ack)?
			}
			(_, _) => server_artifact,
		};

		let outcome = SessionOutcome {
			receipt,
			artifact,
			countersignature: countersignature.map(OctetString::new).transpose()?,
			ancillary_response,
			client_certificate: self.validated_client_cert.as_ref().map(Arc::clone),
			verdict,
		};
		self.stored_receipt = Some(record_receipt_outcome(self.session_observer.as_deref(), outcome).await?);

		Ok(())
	}

	fn clear_sensitive_data(&mut self) {
		clear_session_randoms(&mut self.base_session_key, &mut self.client_random, &mut self.server_random);
	}
}

// ============================================================================
// Common Handshake Trait Implementations
// ============================================================================

impl<P> HandshakeNegotiation for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn supported_profiles(&self) -> &[SecurityProfileDesc] {
		&self.supported_profiles
	}

	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		if let Some(policy) = &self.strength_policy {
			return policy.as_ref();
		}

		&DefaultStrengthFloor
	}
}

impl<P> HandshakeFinalization<P> for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for EciesHandshakeServer<P> where P: CryptoProvider {}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl<P> ServerHandshakeProtocol for EciesHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
	P::Signature: SignatureEncoding,
{
	type Error = HandshakeError;

	fn handle_request<'a, 'b>(&'a mut self, msg: &'b [u8]) -> MaybeSendFuture<'a, Result<Option<Vec<u8>>, Self::Error>>
	where
		'b: 'a,
	{
		Box::pin(async move {
			// Determine which message type this is based on state
			match self.state() {
				ServerHandshakeState::Init => {
					// This is ClientHello - respond with ServerHandshake
					let server_handshake = self.process_client_hello(msg).await?;
					Ok(Some(server_handshake))
				}
				ServerHandshakeState::ServerHelloSent => {
					// This is ClientKeyExchange - no response needed
					self.process_client_key_exchange(msg).await?;
					Ok(None)
				}
				_ => Err(HandshakeError::InvalidState),
			}
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

	#[cfg(feature = "aead")]
	fn complete<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<SessionKeys, Self::Error>> {
		Box::pin(async move {
			let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;
			let aead_oid = profile.aead.ok_or(HandshakeError::InvalidState)?;

			// Delegate to the inherent method: single source of truth for state
			// validation, AEAD derivation, invariants, and cleanup.
			let ciphers = EciesHandshakeServer::complete(self)?;

			// Role-map the directional ciphers with the negotiated OID
			Ok(SessionKeys::for_server(
				ciphers.client_to_server,
				ciphers.server_to_client,
				aead_oid,
			))
		})
	}

	#[cfg(feature = "x509")]
	fn peer_certificate(&self) -> Option<&Certificate> {
		self.validated_client_cert.as_ref().map(|arc| arc.as_ref())
	}

	#[cfg(feature = "aead")]
	fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		self.epoch_materials.take()
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
	use crate::crypto::ecies::{encrypt, Secp256k1EciesMessage};
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::profiles::SecurityProfileDesc;
	use crate::random::{generate_nonce, OsRng};
	use crate::transport::handshake::negotiation::{select_profile, SecurityOffer};
	use crate::transport::handshake::tests::*;

	fn create_test_client_hello_with_offer(
		client_random: &[u8; 32],
		offer: Option<SecurityOffer>,
	) -> Result<Vec<u8>, Box<dyn Error>> {
		let client_hello = ClientHello {
			client_random: OctetString::new(*client_random)?,
			security_offer: offer,
			transport_offer: None,
		};
		Ok(client_hello.to_der()?)
	}

	fn create_test_client_hello_with_transport_offer(
		client_random: &[u8; 32],
		transport_offer: Option<TransportOffer>,
	) -> Result<Vec<u8>, Box<dyn Error>> {
		let client_hello = ClientHello {
			client_random: OctetString::new(*client_random)?,
			security_offer: None,
			transport_offer,
		};
		Ok(client_hello.to_der()?)
	}

	/// Test the full server state flow through a complete handshake.
	///
	/// Verifies that the server correctly transitions through all states:
	/// Init -> ServerHelloSent -> KeyExchangeReceived -> Complete
	#[tokio::test]
	async fn test_server_state_flow() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		assert_eq!(server.state(), ServerHandshakeState::Init);

		// Process ClientHello
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		let server_handshake_der = server.process_client_hello(&client_hello_der).await?;
		assert_eq!(server.state(), ServerHandshakeState::ServerHelloSent);
		assert!(server.client_random.is_some());
		assert!(server.server_random.is_some());
		assert!(server.transcript_hash.is_some());

		// Verify server handshake message is valid
		let _server_handshake = ServerHandshake::from_der(&server_handshake_der)?;

		// Process ClientKeyExchange
		let client_kex_der = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(&client_kex_der).await?;
		assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
		assert!(server.base_session_key.is_some());

		// Complete handshake
		let _session_key = server.complete()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), ServerHandshakeState::Completed);

		Ok(())
	}

	/// Test that state transitions are properly enforced.
	///
	/// Verifies that operations fail when called in the wrong state.
	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		// Cannot process client key exchange before client hello
		assert!(server.process_client_key_exchange(&[]).await.is_err());
		// Cannot complete before any handshake steps
		assert!(server.complete().is_err());

		// Process client hello to advance state
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;
		// Cannot process client hello again
		assert!(server.process_client_hello(&client_hello_der).await.is_err());
		// Cannot complete before client key exchange
		assert!(server.complete().is_err());

		// Process client key exchange to advance state
		let client_kex_der = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(&client_kex_der).await?;
		// Cannot process client key exchange again
		assert!(server.process_client_key_exchange(&client_kex_der).await.is_err());
		// Cannot process client hello after key exchange
		assert!(server.process_client_hello(&client_hello_der).await.is_err());

		Ok(())
	}

	/// Payload framing negatives: the parser fails closed on undersized
	/// key material and on garbage that is not a DER payload.
	#[test]
	fn test_payload_parse_rejects_bad_framing() -> Result<(), Box<dyn Error>> {
		let server = TestEciesServerBuilder::new().build()?;

		let garbage = vec![0u8; 68];
		assert!(matches!(
			server.extract_session_data_from_payload(&garbage),
			Err(HandshakeError::InvalidDecryptedPayloadSize)
		));

		let short_key = EciesSessionPayload {
			base_key: OctetString::new([0u8; 31])?,
			client_random: OctetString::new([0u8; 32])?,
			receipt_ack: None,
		};
		assert!(matches!(
			server.extract_session_data_from_payload(&short_key.to_der()?),
			Err(HandshakeError::InvalidDecryptedPayloadSize)
		));

		let short_random = EciesSessionPayload {
			base_key: OctetString::new([0u8; 32])?,
			client_random: OctetString::new([0u8; 16])?,
			receipt_ack: None,
		};
		assert!(matches!(
			server.extract_session_data_from_payload(&short_random.to_der()?),
			Err(HandshakeError::InvalidDecryptedPayloadSize)
		));

		Ok(())
	}

	/// An anonymous dial against a validator-less server captures no
	/// client identity.
	#[tokio::test]
	async fn test_anonymous_dial_captures_no_identity() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;

		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;

		let client_kex_der = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(&client_kex_der).await?;

		assert!(server.validated_client_cert.is_none());
		Ok(())
	}

	/// A validator-less server discards an offered client identity so the
	/// session stays anonymous (server-auth only).
	#[tokio::test]
	async fn test_validatorless_server_discards_offered_identity() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;

		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;

		let client = create_test_certificate();
		let client_kex_der = build_identified_client_key_exchange(&server, &client, None).await?;
		server.process_client_key_exchange(&client_kex_der).await?;

		assert!(server.validated_client_cert.is_none());
		Ok(())
	}

	/// A validator-less server also discards an offered identity with a
	/// forged possession signature; the handshake still completes as
	/// anonymous server-auth.
	#[tokio::test]
	async fn test_validatorless_server_discards_forged_offered_identity() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;

		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;

		let client = create_test_certificate();
		let forged_digest = [0u8; 32];

		let client_kex_der = build_identified_client_key_exchange(&server, &client, Some(forged_digest)).await?;
		server.process_client_key_exchange(&client_kex_der).await?;

		assert!(server.validated_client_cert.is_none());
		Ok(())
	}

	/// A conforming payload recovers the key material and the absent ack.
	#[test]
	fn test_payload_parse_recovers_session_data() -> Result<(), Box<dyn Error>> {
		let server = TestEciesServerBuilder::new().build()?;

		let unanswered = EciesSessionPayload {
			base_key: OctetString::new([3u8; 32])?,
			client_random: OctetString::new([5u8; 32])?,
			receipt_ack: None,
		};

		let payload = server.extract_session_data_from_payload(&unanswered.to_der()?)?;
		assert_eq!(payload.base_session_key, [3u8; 32]);
		assert_eq!(payload.client_random, [5u8; 32]);
		assert!(payload.receipt_ack.is_none());

		Ok(())
	}

	/// Test profile negotiation modes (negotiation vs dealer's choice).
	///
	/// Verifies that the server correctly handles both explicit client offers
	/// and dealer's choice mode when no offer is present.
	#[tokio::test]
	async fn test_profile_negotiation() -> Result<(), Box<dyn Error>> {
		use crate::oids::{
			AES_256_GCM, AES_256_WRAP, CURVE_SECP256K1, HASH_SHA3_256, HASH_SHA3_384, HASH_SHA3_512,
			SIGNER_ECDSA_WITH_SHA3_512,
		};

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
			// Make key_wrap consistent so profiles only differ by digest
			key_wrap: Some(AES_256_WRAP),
			kem: None,
		};

		let (p_a, p_b, p_c) = (mk_profile(1), mk_profile(2), mk_profile(3));

		// Mode 1: Negotiation - client offers [A, B], server supports [B, C] -> selects B
		{
			let offer = SecurityOffer::new(vec![p_a, p_b]);
			let selected = select_profile(&offer, &[p_b, p_c])?;
			assert_eq!(selected, p_b);

			let mut server = TestEciesServerBuilder::new().build()?.with_supported_profiles(vec![p_b, p_c]);
			let client_random = [0u8; 32];
			let offer = Some(offer.to_owned());
			let client_hello_der = create_test_client_hello_with_offer(&client_random, offer)?;
			let _response = server.process_client_hello(&client_hello_der).await?;
			assert_eq!(server.selected_profile, Some(p_b));
		}

		// Mode 2: Dealer's choice - no client offer, server picks first
		{
			let mut server = TestEciesServerBuilder::new().build()?.with_supported_profiles(vec![p_a, p_b]);
			let client_random = [1u8; 32];
			let client_hello_der = create_test_client_hello(&client_random)?;
			let _response = server.process_client_hello(&client_hello_der).await?;
			assert_eq!(server.selected_profile, Some(p_a)); // First in list
		}

		// Error case: No mutual profile
		{
			let offer = SecurityOffer::new(vec![p_a, p_b]);
			let result = select_profile(&offer, &[p_c]);
			assert!(result.is_err());
		}

		Ok(())
	}

	/// ClientHello with only a transport offer (no security offer) must
	/// round-trip: the context tag on transport_offer prevents it from being
	/// misparsed as the preceding optional SEQUENCE.
	#[test]
	fn test_client_hello_transport_offer_round_trip() -> Result<(), Box<dyn Error>> {
		let hello_der = create_test_client_hello_with_transport_offer(&[7u8; 32], Some(TransportOffer::mux(16)))?;
		let decoded = ClientHello::from_der(&hello_der)?;
		assert_eq!(decoded.security_offer, None);
		assert_eq!(decoded.transport_offer, Some(TransportOffer::mux(16)));
		Ok(())
	}

	/// Transport negotiation modes: mux activates only when offered AND
	/// locally enabled. Every other combination stays single-flight.
	#[tokio::test]
	async fn test_transport_negotiation() -> Result<(), Box<dyn Error>> {
		// Offered and locally enabled: negotiated with directional caps
		{
			let transport_offer = TransportOffer::mux(4);
			let mut server = TestEciesServerBuilder::new().build()?.with_transport_config(transport_offer);

			let transport_offer = TransportOffer::mux(8);
			let client_hello_der = create_test_client_hello_with_transport_offer(&[0u8; 32], Some(transport_offer))?;
			let response_der = server.process_client_hello(&client_hello_der).await?;

			let response = ServerHandshake::from_der(&response_der)?;
			assert!(matches!(
				response.transport_accept,
				Some(TransportAccept { mux: true, max_peer_initiated_streams: 4, .. })
			));
			assert!(matches!(
				server.mux_settings,
				Some(MuxSettings { local_initiated_cap: 8, peer_initiated_cap: 4, .. })
			));
		}

		// Offered but not locally enabled: single-flight
		{
			let transport_offer = TransportOffer::mux(8);
			let mut server = TestEciesServerBuilder::new().build()?;
			let client_hello_der = create_test_client_hello_with_transport_offer(&[1u8; 32], Some(transport_offer))?;
			let response_der = server.process_client_hello(&client_hello_der).await?;

			let response = ServerHandshake::from_der(&response_der)?;
			assert_eq!(response.transport_accept, None);
			assert_eq!(server.mux_settings, None);
		}

		// Locally enabled but not offered: single-flight
		{
			let transport_offer = TransportOffer::mux(4);
			let mut server = TestEciesServerBuilder::new().build()?.with_transport_config(transport_offer);
			let client_hello_der = create_test_client_hello_with_transport_offer(&[2u8; 32], None)?;
			let response_der = server.process_client_hello(&client_hello_der).await?;

			let response = ServerHandshake::from_der(&response_der)?;
			assert_eq!(response.transport_accept, None);
			assert_eq!(server.mux_settings, None);
		}

		Ok(())
	}

	// ========================================================================
	// Test Helper Functions
	// ========================================================================

	/// Build a test ClientKeyExchange with ECIES-encrypted session key.
	///
	/// Extracts the server's public key and stored client random, then creates
	/// a properly encrypted payload containing [session_key || client_random].
	fn build_test_client_key_exchange<P>(server: &EciesHandshakeServer<P>) -> Result<Vec<u8>, Box<dyn Error>>
	where
		P: CryptoProvider,
		P::AeadCipher: KeyInit,
	{
		// Extract server's public key from certificate
		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server
				.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		// Use the stored client_random from the server
		let stored_client_random = server.client_random.ok_or("Missing client random")?;
		let base_session_key = generate_nonce::<32>(None)?;

		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_session_key)?,
			client_random: OctetString::new(stored_client_random)?,
			receipt_ack: None,
		};
		let plaintext = payload.to_der()?;

		// Use server's AAD domain tag (or default if None)
		let aad = server.aad_domain_tag.or(Some(TIGHTBEAM_AAD_DOMAIN_TAG));
		// Encrypt with ECIES
		let encrypted_message = encrypt::<_, _, _, Secp256k1EciesMessage, P::Kdf, P::AeadCipher>(
			&server_pubkey,
			&plaintext,
			aad,
			Some(&mut OsRng),
		)?;

		// Build ClientKeyExchange message
		create_test_client_key_exchange(&encrypted_message.to_bytes())
	}

	/// Build an identified ClientKeyExchange: the encrypted payload plus
	/// the client certificate and its proof-of-possession signature.
	///
	/// `override_digest` replaces the bound auth digest so negative tests
	/// can present a signature over the wrong material.
	async fn build_identified_client_key_exchange<P>(
		server: &EciesHandshakeServer<P>,
		client: &TestCertificate,
		override_digest: Option<[u8; 32]>,
	) -> Result<Vec<u8>, Box<dyn Error>>
	where
		P: CryptoProvider,
		P::AeadCipher: KeyInit,
	{
		let server_pubkey = k256::PublicKey::from_sec1_bytes(
			server
				.server_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let stored_client_random = server.client_random.ok_or(HandshakeError::InvalidState)?;
		let base_session_key = generate_nonce::<32>(None)?;

		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_session_key)?,
			client_random: OctetString::new(stored_client_random)?,
			receipt_ack: None,
		};
		let plaintext = payload.to_der()?;

		let aad = server.aad_domain_tag.or(Some(TIGHTBEAM_AAD_DOMAIN_TAG));
		let encrypted_message = encrypt::<_, _, _, Secp256k1EciesMessage, P::Kdf, P::AeadCipher>(
			&server_pubkey,
			&plaintext,
			aad,
			Some(&mut OsRng),
		)?;
		let encrypted_bytes = encrypted_message.to_bytes();

		let transcript_hash = server.transcript_hash().ok_or(HandshakeError::InvalidState)?;
		let cert_der = client.certificate.to_der()?;
		let auth_digest = match override_digest {
			Some(digest) => digest,
			None => compute_client_auth_digest::<P::Digest>(&transcript_hash, &encrypted_bytes, &cert_der)?,
		};

		let provider = Secp256k1KeyProvider::from(client.signing_key.to_owned());
		let signature = provider.sign_prehash(&auth_digest).await?;

		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			client_certificate: Some(client.certificate.to_owned()),
			client_signature: Some(OctetString::new(signature.to_vec())?),
		};

		Ok(client_kex.to_der()?)
	}
}

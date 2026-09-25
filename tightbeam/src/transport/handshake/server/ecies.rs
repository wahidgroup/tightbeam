//! ECIES-based server handshake orchestrator.
//!
//! This module implements the server side of the TightBeam ECIES handshake
//! protocol. The orchestrator is generic over `P: CryptoProvider` for its
//! cryptographic operations.

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
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::ecies::{decrypt_with_shared_secret, EciesMessageOps};
use crate::crypto::kdf::EcdhSecret;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::{LowSEncoding, PrehashVerifier, SignatureEncoding};
use crate::crypto::subtle::ConstantTimeEq;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::common::derive_epoch_materials;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfileStrengthPolicy, RunnableProfile, SecurityAccept, StrengthFloor, TransportAccept,
	TransportAuthorizer, TransportNegotiation, TransportOffer,
};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::ReceiptSigner;
use crate::transport::handshake::receipt::{
	record_receipt_outcome, sign_receipt, SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict,
	StoredReceipt,
};
use crate::transport::handshake::state::{Ecies, ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::utils::HandshakeOctets;
use crate::transport::handshake::utils::HandshakeVerifyingKey;
use crate::transport::handshake::utils::{compute_client_auth_digest, compute_ecies_transcript_hash, validate_state};
use crate::transport::handshake::{
	AdmittedPeer, EstablishedSession, HandshakeMessage, PeerAuthentication, TunneledMessage,
};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake, ServerHandshakeProtocol,
};
use crate::transport::handshake::{
	DirectionalCiphers, EpochMaterials, HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation,
};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};
use crate::ZeroizingArray;

/// Server-side ECIES handshake orchestrator.
///
/// It is generic over `P: CryptoProvider` for its cryptographic operations.
/// The server handshake runs in order:
///
/// 1. Receive the ClientHello with its random nonce.
/// 2. Send the ServerHandshake with the certificate, the server random, and a
///    signature over the transcript.
/// 3. Receive and decrypt the ClientKeyExchange with the ECIES-encrypted session key.
pub struct EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	state: ServerStateMachine<Ecies>,
	server_key_provider: Arc<dyn SigningKeyProvider>,
	server_cert: Arc<Certificate>,
	client_random: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	base_session_key: Option<ZeroizingArray<32>>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: &'static [u8],
	supported_profiles: Vec<SecurityProfileDesc>,
	strength_floor: StrengthFloor,
	selected_profile: Option<RunnableProfile<P>>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	mux_settings: Option<MuxSettings>,
	peer_authentication: PeerAuthentication,
	admitted: Option<AdmittedPeer>,
	session_receipt: Option<SessionReceipt>,
	receipt_artifact: Option<SignedData>,
	stored_receipt: Option<StoredReceipt>,
	epoch_materials: Option<EpochMaterials>,
	_phantom: PhantomData<P>,
}

/// The parts of the decrypted ECIES key-exchange payload.
///
/// They are the session key material, the anti-replay random, and the
/// client's receipt countersignature, which an unmetered session omits.
struct SessionPayload {
	base_session_key: ZeroizingArray<32>,
	client_random: [u8; 32],
	/// The client receipt `SignerInfo`. Its signed attributes bind the bearer
	/// settlement answer, so it arrives only through this confidential
	/// payload.
	receipt_ack: Option<SignerInfo>,
}

impl<P> EciesHandshakeServer<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
	P::Signature: SignatureEncoding,
{
	/// Create an ECIES handshake server that presents `server_cert` to the
	/// client.
	///
	/// `aad_domain_tag` defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`. The client is
	/// authenticated as `peer_authentication` demands.
	pub fn new(
		server_key_provider: Arc<dyn SigningKeyProvider>,
		server_cert: Arc<Certificate>,
		aad_domain_tag: Option<&'static [u8]>,
		peer_authentication: PeerAuthentication,
	) -> Self {
		Self {
			state: ServerStateMachine::<Ecies>::default(),
			server_key_provider,
			server_cert,
			client_random: None,
			server_random: None,
			base_session_key: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.unwrap_or(TIGHTBEAM_AAD_DOMAIN_TAG),
			supported_profiles: Vec::new(), // Must be set via with_supported_profiles()
			strength_floor: StrengthFloor::default(),
			selected_profile: None,
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			mux_settings: None,
			peer_authentication,
			admitted: None,
			session_receipt: None,
			receipt_artifact: None,
			stored_receipt: None,
			epoch_materials: None,
			_phantom: PhantomData,
		}
	}

	/// Set the server's supported security profiles for negotiation.
	///
	/// The server must have at least one supported profile configured.
	#[must_use]
	pub fn with_supported_profiles(mut self, profiles: impl IntoIterator<Item = SecurityProfileDesc>) -> Self {
		let profiles: Vec<SecurityProfileDesc> = profiles.into_iter().collect();
		self.supported_profiles = profiles;
		self
	}

	/// Override the minimum-strength policy applied during negotiation.
	///
	/// The default is `DefaultStrengthFloor`, which requires a 256-bit AEAD key
	/// and a digest of 256 bits or more. Pass `NoStrengthFloor` only where
	/// weaker profiles must remain negotiable.
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.strength_floor = StrengthFloor::with_policy(policy);
		self
	}

	/// Enable transport multiplexing with the given local advertisement.
	///
	/// Multiplexing activates only when the client also offers it.
	#[must_use]
	pub fn with_transport_config(mut self, config: TransportOffer) -> Self {
		self.transport_config = Some(config);
		self
	}

	/// Override the budget-grant policy consulted between the client's
	/// transport offer and the server's accept.
	///
	/// Without an authorizer the server grants its local configuration ceiling.
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

	/// Process the ClientHello and build the ServerHandshake message.
	pub async fn process_client_hello(
		&mut self,
		client_hello_der: impl AsRef<[u8]>,
	) -> Result<ServerHandshake, HandshakeError> {
		let client_hello_der = client_hello_der.as_ref();
		// 1. Validate that the current state is Init.
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Decode the ClientHello message.
		let client_hello = self.decode_client_hello(client_hello_der)?;

		// 3. Negotiate the security profile.
		let selected = self.negotiate_profile(client_hello.security_offer.as_ref())?;
		self.selected_profile = Some(selected);

		let security_accept = WireDer::new(SecurityAccept::new(selected.descriptor()))?;

		// 4. Negotiate transport capabilities. Mux activates only when it is
		//    offered and locally enabled. A configured authorizer decides the
		//    budget grant and the settlement challenge before the accept enters
		//    the transcript.
		let offer = client_hello.transport_offer.as_ref();
		let local = self.transport_config.as_ref();
		let negotiation = TransportNegotiation { offer, local };
		let authorized = negotiation.authorize(self.transport_authorizer.as_deref()).await?;
		let authorized_accept = authorized.as_ref().map(|authorized| authorized.accept);
		let transport_accept = authorized_accept.map(WireDer::new).transpose()?;

		let settlement_challenge = authorized.and_then(|authorized| authorized.challenge);
		let accepted = transport_accept.as_ref().map(WireDer::value);
		if let (Some(offer), Some(accept)) = (client_hello.transport_offer.as_ref(), accepted) {
			self.mux_settings = Some(MuxSettings::for_server(offer, accept));
		}

		// 5. Extract and store the client random.
		let client_random = client_hello.client_random.to_32_byte_array()?;
		self.client_random = Some(client_random);

		// 6. Generate and store the server random.
		let server_random = self.generate_server_random()?;

		// 7. Compute the transcript hash.
		let spki_bytes = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// The transcript binds the full ClientHello DER with its offers, the
		// negotiated profile, and the transport accept, so tampering with any
		// of them invalidates the server signature.
		let transport_accept_der = transport_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let transcript_digest = compute_ecies_transcript_hash::<P::Digest>(
			client_hello_der,
			&server_random,
			spki_bytes,
			security_accept.der(),
			transport_accept_der,
		)?;
		self.transcript_hash = Some(transcript_digest);

		// 8. Sign the transcript hash with the key provider.
		let signature_bytes = self.sign_transcript_hash(&transcript_digest).await?;

		// 9. Issue the session receipt. The transcript hash pins it to this
		//    session, and the server signature makes it third-party verifiable.
		self.issue_session_receipt(&transcript_digest, accepted, settlement_challenge)
			.await?;

		// 10. Build the ServerHandshake.
		let security_accept = Some(security_accept);
		let server_handshake =
			self.build_server_handshake(server_random, signature_bytes, security_accept, transport_accept)?;

		// 11. Transition the state through ClientHelloReceived to ServerHelloSent.
		self.state.transition(ServerHandshakeState::ClientHelloReceived)?;
		self.state.transition(ServerHandshakeState::ServerHelloSent)?;

		Ok(server_handshake)
	}

	/// Build and sign the [`SessionReceipt`] when the accept grants
	/// budgets.
	///
	/// # Fail closed
	///
	/// Budgets demand a client countersignature, so a budget-bearing accept
	/// without configured mutual authentication aborts the handshake.
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

		if !self.peer_authentication.requires_certificate() {
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

	/// Process the ClientKeyExchange message and decrypt the ECIES-encrypted
	/// session key, which stays stored inside the server.
	pub async fn process_client_key_exchange(&mut self, mut client_kex: ClientKeyExchange) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// 1. Validate that the current state is ServerHelloSent.
		self.validate_expected_state(ServerHandshakeState::ServerHelloSent)?;

		// 2. Validate the client certificate when mutual auth is configured.
		self.validate_client_certificate(&mut client_kex)?;

		// 3. Read the encrypted bytes from the message.
		let encrypted_bytes = client_kex.encrypted_data.as_bytes();

		// 4. Decrypt the ECIES payload. The key provider runs the ECDH step.
		let decrypted_payload = self.decrypt_ecies_payload(encrypted_bytes).await?;

		// 5. Extract the base session key, the client random, and the
		//    confidential receipt countersignature from the decrypted payload.
		let SessionPayload { base_session_key, client_random, receipt_ack } =
			decrypted_payload.with(|payload| self.extract_session_data_from_payload(payload))?;

		// 6. Verify that the client random matches the stored value, which prevents replay attacks.
		self.verify_client_random(&client_random)?;

		// 7. Verify the receipt countersignature and settle, strictly after
		//    decryption and replay verification. Settlement is an irreversible
		//    external side effect, so it must be the last gate, downstream of
		//    every cheaper rejection. The countersignature arrives
		//    confidentially inside the decrypted payload.
		self.process_receipt_ack(receipt_ack).await?;

		// 8. Store the base session key.
		self.base_session_key = Some(base_session_key);

		// 9. Transition the state to KeyExchangeReceived.
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// Complete the handshake and derive the provider's client-to-server and
	/// server-to-client AEAD ciphers.
	pub fn complete(&mut self) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError> {
		// 1. Validate that the current state is KeyExchangeReceived.
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

		// 2. Read the values that key derivation requires.
		let base_session_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;

		// 3. Derive the final session keys through trait finalization, salted
		//    with `client_random || server_random`.
		let mut salt = Zeroizing::new([0u8; 64]);
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		let salt_bytes = salt.as_slice();
		let input_key_material = base_session_key.as_slice();
		let session_ciphers = self.derive_directional_aead(input_key_material, KdfSalt::new(salt_bytes))?;

		// 4. Derive the epoch-0 rekey materials alongside the traffic keys,
		//    from the same inputs plus the transcript hash. An in-band renewal
		//    later chains from this secret without touching the handshake
		//    again.
		if let Some(transcript_hash) = self.transcript_hash {
			let input_key_material = base_session_key.as_slice();
			let materials = derive_epoch_materials::<P>(input_key_material, KdfSalt::new(salt_bytes), transcript_hash)?;
			self.epoch_materials = Some(materials);
		}

		// 5. Transition to the complete state.
		self.state.transition(ServerHandshakeState::Completed)?;

		// 6. Clear the sensitive data.
		self.clear_sensitive_data();

		Ok(session_ciphers)
	}

	/// The current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The transcript hash, once the ClientHello sets it.
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}

	/// The dual-signed session receipt, when the completed handshake carried
	/// budgets.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
	}

	fn decode_client_hello(&self, client_hello_der: impl AsRef<[u8]>) -> Result<ClientHello, HandshakeError> {
		let client_hello_der = client_hello_der.as_ref();
		Ok(ClientHello::from_der(client_hello_der)?)
	}

	fn generate_server_random(&mut self) -> Result<[u8; 32], HandshakeError> {
		let server_random = generate_nonce::<32>(None)?;
		self.server_random = Some(server_random);

		Ok(server_random)
	}

	async fn sign_transcript_hash(&self, transcript_digest: &[u8; 32]) -> Result<Vec<u8>, HandshakeError> {
		let sig = self.server_key_provider.sign_prehash(transcript_digest).await?;
		Ok(sig.to_vec())
	}

	fn build_server_handshake(
		&self,
		server_random: [u8; 32],
		signature_bytes: Vec<u8>,
		security_accept: Option<WireDer<SecurityAccept>>,
		transport_accept: Option<WireDer<TransportAccept>>,
	) -> Result<ServerHandshake, HandshakeError> {
		Ok(ServerHandshake {
			certificate: Certificate::clone(&self.server_cert),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature_bytes)?,
			security_accept,
			client_cert_required: self.peer_authentication.requires_certificate(),
			transport_accept,
			// The artifact has two owners by design. This copy is
			// DER-encoded into the message and dropped, and the retained
			// artifact absorbs the client SignerInfo at settlement.
			session_receipt: self.receipt_artifact.clone(),
		})
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// The single home for ECIES server completion. The trait implementation
	/// delegates here, so driver and test read the session terms the same way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the handshake agreed no profile,
	///   so it settled on no AEAD algorithm.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError>
	where
		P::AeadCipher: KeyInit + 'static,
	{
		let ciphers = EciesHandshakeServer::complete(self)?;

		// The orchestrator is spent, so the receipt moves out instead of
		// being copied. The client certificate is already shared, so the
		// session takes a handle to it.
		#[cfg(feature = "x509")]
		let peer = self.proven_peer();

		let keys = SessionKeys::for_server(ciphers);
		let mux = self.mux_settings;
		let receipt = self.stored_receipt.take().map(Arc::new);
		let epoch = self.epoch_materials.take();
		Ok(EstablishedSession::new(keys, mux, receipt, peer, epoch))
	}

	/// Open the ECIES payload of a key exchange.
	///
	/// The ECDH step runs through the key provider, so the private key can stay
	/// behind an external boundary. Key derivation and AEAD opening are the
	/// ECIES suite's own, bound to this server's domain tag as associated data.
	/// The plaintext carries the base session key and the bearer settlement
	/// answer, so it wipes on drop.
	async fn decrypt_ecies_payload(
		&self,
		encrypted_bytes: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let message = <P::EciesMessage as EciesMessageOps>::from_bytes(encrypted_bytes.as_ref())?;
		let agreed = self.server_key_provider.key_agreement(message.ephemeral_pubkey()).await?;
		let shared_secret = EcdhSecret::try_from(agreed)?;
		let aad = Some(self.aad_domain_tag);

		let open = decrypt_with_shared_secret::<P::EciesMessage, P::Kdf, P::AeadCipher>;
		let plaintext = open(&message, shared_secret, aad)?;
		Ok(plaintext)
	}

	/// Parse the decrypted DER [`EciesSessionPayload`] into its parts, and
	/// enforce the fixed 32-byte geometry of the key material.
	fn extract_session_data_from_payload(
		&self,
		decrypted_payload: impl AsRef<[u8]>,
	) -> Result<SessionPayload, HandshakeError> {
		let decrypted_payload = decrypted_payload.as_ref();
		let payload = EciesSessionPayload::from_der(decrypted_payload)
			.map_err(|_| HandshakeError::InvalidDecryptedPayloadSize)?;

		let EciesSessionPayload { base_key, client_random, receipt_ack } = payload;

		// The key is copied straight into its wiping buffer, so no plain
		// array of key material exists on the way. The decoded copy is wiped
		// whether or not it had the right length.
		let mut base_session_key = ZeroizingArray::new([0u8; 32]);
		let copied = base_key.copy_to_32_byte_array(&mut base_session_key);
		base_key.into_bytes().zeroize();
		copied?;

		let client_random = client_random.to_32_byte_array()?;
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

	/// Admit the offered client identity and, under mutual authentication,
	/// check that the client holds its key.
	///
	/// - Under mutual authentication every validator MUST pass before the
	///   possession check, and only then is the admission kept.
	/// - Under server authentication the session stays anonymous. An offered
	///   certificate is not checked, and
	///   [`SessionContext`](crate::policy::SessionContext) reports no peer.
	#[cfg(feature = "x509")]
	fn validate_client_certificate(&mut self, client_kex: &mut ClientKeyExchange) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]> + LowSEncoding,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// Chain validation runs inside the admission, before the possession
		// check, so a certificate is kept only once every validator accepts
		// it.
		let offered = client_kex.client_certificate.take();
		let admitted = self.peer_authentication.admit(offered)?;
		let Some(client_cert) = admitted.proven() else {
			return Ok(());
		};

		// Verify the client signature over the bound auth digest, so capture
		// records an identity whose key the peer proved it holds.
		let client_signature = client_kex
			.client_signature
			.as_ref()
			.ok_or(HandshakeError::SignatureVerificationFailed)?;

		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		// Recompute the digest that the client signed. It is the transcript
		// hash bound to this exact encrypted payload and this exact
		// certificate, so the signature binds to this exchange alone.
		let cert_der = client_cert.to_der()?;
		let encrypted_data = client_kex.encrypted_data.as_bytes();
		let auth_digest = compute_client_auth_digest::<P::Digest>(&transcript_hash, encrypted_data, &cert_der)?;

		let public_key = client_cert.verifying_key::<P::Curve>()?;
		let signature = P::Signature::try_from(client_signature.as_bytes())
			.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

		let verifying_key = P::VerifyingKey::from(&public_key);
		signature.verify_prehash(&verifying_key, auth_digest)?;

		// Keeping the admission locks the captured identity. This is the
		// only write after construction.
		self.admitted = Some(admitted);

		Ok(())
	}

	/// Verify the client's receipt countersignature and settle with the
	/// authorizer.
	///
	/// A handshake that issued no receipt completes here. An issued receipt
	/// fails closed. A missing or invalid countersignature aborts the
	/// handshake, and a [`StoredReceipt`] is retained only after both checks
	/// hold.
	#[cfg(feature = "x509")]
	async fn process_receipt_ack(&mut self, receipt_ack: Option<SignerInfo>) -> Result<(), HandshakeError>
	where
		P::Curve: Curve + CurveArithmetic,
		<P::Curve as Curve>::FieldBytesSize: ModulusSize,
		AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	{
		// The receipt is taken instead of cloned, because the outcome owns it
		// and its unbounded ancillary challenge.
		let Some(receipt) = self.session_receipt.take() else {
			return Ok(());
		};

		// This is the artifact's single owner from here on. It either
		// completes into the outcome or travels server-signed as it is.
		let server_artifact = self.receipt_artifact.take().ok_or(HandshakeError::InvalidState)?;

		let (verdict, ancillary_response) = match receipt_ack.as_ref() {
			None => (SessionVerdict::CountersignatureMissing, None),
			Some(ack) => {
				let client_cert = self.proven_peer().ok_or(HandshakeError::MutualAuthRequired)?;
				let expected_sid = client_cert.signer_identifier::<P::Digest>()?;
				let public_key = client_cert.verifying_key::<P::Curve>()?;
				let verifying_key = P::VerifyingKey::from(&public_key);

				receipt
					.settle_ack::<P::Digest, P::Signature, _>(
						Some(ack),
						&expected_sid,
						&verifying_key,
						self.transport_authorizer.as_deref(),
					)
					.await?
			}
		};

		// Take the evidence DER before the move. The raw bytes stay in the
		// outcome even when the SignerInfo folds into the artifact.
		let countersignature = receipt_ack.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact. A failed one
		// stays out of it, but its DER remains in the outcome as evidence.
		let artifact = match (verdict, receipt_ack) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(ack)) => {
				server_artifact.complete(ack)?
			}
			(_, _) => server_artifact,
		};

		let outcome = SessionOutcome {
			receipt,
			artifact,
			countersignature: countersignature.map(OctetString::new).transpose()?,
			ancillary_response,
			client_certificate: self.proven_peer(),
			verdict,
		};
		self.stored_receipt = Some(record_receipt_outcome(self.session_observer.as_deref(), outcome).await?);

		Ok(())
	}

	/// The certificate this session records as its peer.
	fn proven_peer(&self) -> Option<Arc<Certificate>> {
		self.admitted.as_ref().and_then(AdmittedPeer::proven).map(Arc::clone)
	}

	/// Erase the ephemeral ECIES key material after session establishment
	/// (CWE-226).
	fn clear_sensitive_data(&mut self) {
		use crate::zeroize::Zeroize;

		self.base_session_key.zeroize();
		self.client_random.zeroize();
		self.server_random.zeroize();
	}
}

impl<P> HandshakeNegotiation<P> for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn supported_profiles(&self) -> &[SecurityProfileDesc] {
		&self.supported_profiles
	}

	fn strength_policy(&self) -> &dyn ProfileStrengthPolicy {
		self.strength_floor.policy()
	}
}

impl<P> HandshakeFinalization<P> for EciesHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<RunnableProfile<P>> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for EciesHandshakeServer<P> where P: CryptoProvider {}

impl<P> ServerHandshakeProtocol for EciesHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + for<'a> From<&'a PublicKey<P::Curve>>,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
	P::Signature: SignatureEncoding,
{
	type Error = HandshakeError;

	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			// ECIES tunnels its messages inside the containers.
			match self.state() {
				ServerHandshakeState::Init => {
					// The hello is read from the bytes it arrived as.
					let hello_container = msg.signed()?;
					let client_hello = hello_container.value().tunneled_der()?;
					let server_handshake = self.process_client_hello(client_hello).await?;

					let response = SignedData::try_from(&server_handshake)?;
					Ok(Some(HandshakeMessage::try_from(response)?))
				}
				ServerHandshakeState::ServerHelloSent => {
					let enveloped_data = msg.enveloped()?;
					let client_kex = ClientKeyExchange::try_from(enveloped_data.value())?;
					self.process_client_key_exchange(client_kex).await?;
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
		self.selected_profile.map(|profile| profile.descriptor())
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
		Box::pin(async move {
			let mut server = self;
			server.take_established()
		})
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::ecies::{encrypt, Secp256k1EciesMessage};
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::profiles::SecurityProfileDesc;
	use crate::der::asn1::ObjectIdentifier;
	use crate::oids::{HASH_SHA3_384, HASH_SHA3_512};
	use crate::random::{generate_nonce, OsRng};
	use crate::transport::handshake::negotiation::SecurityOffer;
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
	/// The server moves from Init through ServerHelloSent and
	/// KeyExchangeReceived to Complete.
	#[tokio::test]
	async fn test_server_state_flow() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		assert_eq!(server.state(), ServerHandshakeState::Init);

		// Process ClientHello
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		// The test asserts on the state the call leaves behind, not on the
		// message it returns.
		server.process_client_hello(&client_hello_der).await?;
		assert_eq!(server.state(), ServerHandshakeState::ServerHelloSent);
		assert!(server.client_random.is_some());
		assert!(server.server_random.is_some());
		assert!(server.transcript_hash.is_some());

		// Process ClientKeyExchange
		let client_kex = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(client_kex).await?;
		assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
		assert!(server.base_session_key.is_some());

		// Complete handshake
		let _session_key = server.complete()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), ServerHandshakeState::Completed);

		Ok(())
	}

	/// An operation called in the wrong state fails, so the state machine
	/// enforces its transitions.
	#[tokio::test]
	async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		// A client key exchange before the client hello fails.
		let empty_kex = create_test_client_key_exchange([])?;
		assert!(server.process_client_key_exchange(empty_kex).await.is_err());
		// Completion before any handshake step fails.
		assert!(server.complete().is_err());

		// The client hello advances the state.
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;
		// A second client hello fails.
		assert!(server.process_client_hello(&client_hello_der).await.is_err());
		// Completion before the client key exchange fails.
		assert!(server.complete().is_err());

		// The client key exchange advances the state.
		let client_kex = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(client_kex.to_owned()).await?;
		// A second client key exchange fails.
		assert!(server.process_client_key_exchange(client_kex).await.is_err());
		// A client hello after the key exchange fails.
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
			Err(HandshakeError::OctetStringLengthError(_))
		));

		let short_random = EciesSessionPayload {
			base_key: OctetString::new([0u8; 32])?,
			client_random: OctetString::new([0u8; 16])?,
			receipt_ack: None,
		};
		assert!(matches!(
			server.extract_session_data_from_payload(&short_random.to_der()?),
			Err(HandshakeError::OctetStringLengthError(_))
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

		let client_kex = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(client_kex).await?;

		assert!(server.proven_peer().is_none());
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
		let client_kex = build_identified_client_key_exchange(&server, &client, None).await?;
		server.process_client_key_exchange(client_kex).await?;

		assert!(server.proven_peer().is_none());
		Ok(())
	}

	/// A validator-less server also discards an offered identity with a
	/// forged possession signature. The handshake still completes as
	/// anonymous server-auth.
	#[tokio::test]
	async fn test_validatorless_server_discards_forged_offered_identity() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;

		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;

		let client = create_test_certificate();
		let forged_digest = [0u8; 32];

		let client_kex = build_identified_client_key_exchange(&server, &client, Some(forged_digest)).await?;
		server.process_client_key_exchange(client_kex).await?;

		assert!(server.proven_peer().is_none());
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
		assert_eq!(payload.base_session_key.as_slice(), [3u8; 32]);
		assert_eq!(payload.client_random, [5u8; 32]);
		assert!(payload.receipt_ack.is_none());

		Ok(())
	}

	/// A descriptor that names a digest the default provider does not run.
	fn foreign_profile(digest: ObjectIdentifier) -> SecurityProfileDesc {
		SecurityProfileDesc { digest: Some(digest), ..create_default_test_profile() }
	}

	#[tokio::test]
	async fn a_server_selects_the_offered_profile_it_runs() -> Result<(), Box<dyn Error>> {
		let native = create_default_test_profile();
		let offer = SecurityOffer::new(vec![foreign_profile(HASH_SHA3_384), native]);
		let supported = vec![foreign_profile(HASH_SHA3_384), native];
		let mut server = TestEciesServerBuilder::new().build()?.with_supported_profiles(supported);
		let client_hello_der = create_test_client_hello_with_offer(&[0u8; 32], Some(offer))?;

		server.process_client_hello(&client_hello_der).await?;

		assert_eq!(server.selected_profile.map(|profile| profile.descriptor()), Some(native));
		Ok(())
	}

	#[tokio::test]
	async fn a_dealers_choice_server_skips_a_profile_it_does_not_run() -> Result<(), Box<dyn Error>> {
		let native = create_default_test_profile();
		let supported = vec![foreign_profile(HASH_SHA3_512), native];
		let mut server = TestEciesServerBuilder::new().build()?.with_supported_profiles(supported);
		let client_hello_der = create_test_client_hello(&[1u8; 32])?;

		server.process_client_hello(&client_hello_der).await?;

		assert_eq!(server.selected_profile.map(|profile| profile.descriptor()), Some(native));
		Ok(())
	}

	/// A ClientHello with only a transport offer and no security offer must
	/// round-trip. The context tag on `transport_offer` keeps it from parsing
	/// as the preceding optional SEQUENCE.
	#[test]
	fn test_client_hello_transport_offer_round_trip() -> Result<(), Box<dyn Error>> {
		let hello_der = create_test_client_hello_with_transport_offer(&[7u8; 32], Some(TransportOffer::mux(16)))?;
		let decoded = ClientHello::from_der(&hello_der)?;
		assert_eq!(decoded.security_offer, None);
		assert_eq!(decoded.transport_offer, Some(TransportOffer::mux(16)));
		Ok(())
	}

	/// Mux activates only when it is offered and locally enabled. Every other
	/// combination stays single-flight.
	#[tokio::test]
	async fn test_transport_negotiation() -> Result<(), Box<dyn Error>> {
		// Offered and locally enabled, mux negotiates with directional caps.
		{
			let transport_offer = TransportOffer::mux(4);
			let mut server = TestEciesServerBuilder::new().build()?.with_transport_config(transport_offer);

			let transport_offer = TransportOffer::mux(8);
			let client_hello_der = create_test_client_hello_with_transport_offer(&[0u8; 32], Some(transport_offer))?;
			let response = server.process_client_hello(&client_hello_der).await?;
			assert!(matches!(
				response.transport_accept.as_ref().map(WireDer::value),
				Some(TransportAccept { mux: true, max_peer_initiated_streams: 4, .. })
			));
			assert!(matches!(
				server.mux_settings,
				Some(MuxSettings { local_initiated_cap: 8, peer_initiated_cap: 4, .. })
			));
		}

		// Offered but not locally enabled, the session stays single-flight.
		{
			let transport_offer = TransportOffer::mux(8);
			let mut server = TestEciesServerBuilder::new().build()?;
			let client_hello_der = create_test_client_hello_with_transport_offer(&[1u8; 32], Some(transport_offer))?;
			let response = server.process_client_hello(&client_hello_der).await?;
			assert_eq!(response.transport_accept, None);
			assert_eq!(server.mux_settings, None);
		}

		// Locally enabled but not offered, the session stays single-flight.
		{
			let transport_offer = TransportOffer::mux(4);
			let mut server = TestEciesServerBuilder::new().build()?.with_transport_config(transport_offer);
			let client_hello_der = create_test_client_hello_with_transport_offer(&[2u8; 32], None)?;
			let response = server.process_client_hello(&client_hello_der).await?;
			assert_eq!(response.transport_accept, None);
			assert_eq!(server.mux_settings, None);
		}

		Ok(())
	}

	/// Build a test ClientKeyExchange with an ECIES-encrypted session key.
	///
	/// The helper reads the server's public key and the stored client random,
	/// then encrypts a payload that holds `session_key || client_random`.
	fn build_test_client_key_exchange<P>(server: &EciesHandshakeServer<P>) -> Result<ClientKeyExchange, Box<dyn Error>>
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

		// The payload carries the client random that the server stored.
		let stored_client_random = server.client_random.ok_or("Missing client random")?;
		let base_session_key = generate_nonce::<32>(None)?;
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_session_key)?,
			client_random: OctetString::new(stored_client_random)?,
			receipt_ack: None,
		};

		let plaintext = payload.to_der()?;
		let aad = Some(server.aad_domain_tag);
		let encrypted_message = encrypt::<_, _, _, Secp256k1EciesMessage, P::Kdf, P::AeadCipher>(
			&server_pubkey,
			&plaintext,
			aad,
			Some(&mut OsRng),
		)?;

		create_test_client_key_exchange(encrypted_message.to_bytes())
	}

	/// Build an identified ClientKeyExchange, which is the encrypted payload
	/// plus the client certificate and its proof-of-possession signature.
	///
	/// `override_digest` replaces the bound auth digest so negative tests
	/// can present a signature over the wrong material.
	async fn build_identified_client_key_exchange<P>(
		server: &EciesHandshakeServer<P>,
		client: &TestCertificate,
		override_digest: Option<[u8; 32]>,
	) -> Result<ClientKeyExchange, Box<dyn Error>>
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
		let aad = Some(server.aad_domain_tag);
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

		Ok(client_kex)
	}
}

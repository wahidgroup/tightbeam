//! ECIES-based client handshake orchestrator.
//!
//! This module implements the client side of the TightBeam ECIES handshake
//! protocol.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use core::marker::PhantomData;

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::ecies::EciesEphemeral;
use crate::crypto::ecies::{encrypt, EciesMessageOps, EciesPublicKeyOps};
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::sign::ecdsa::Secp256k1VerifyingKey;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::LowSEncoding;
use crate::crypto::sign::PrehashVerifier;
use crate::crypto::sign::SignatureEncoding;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::{Decode, Encode};
use crate::random::generate_nonce;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfileStrengthPolicy, RunnableProfile, SecurityOffer, StrengthFloor, TransportOffer,
};
use crate::transport::handshake::primitives::transcript::Transcript;
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::ReceiptSigner;
use crate::transport::handshake::receipt::{ReceiptApprover, ReceiptRole, SessionReceipt, StoredReceipt};
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine, Ecies};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake,
};
use crate::transport::handshake::{DirectionalCiphers, EpochMaterials, HandshakeAlertHandler, HandshakeFinalization};
use crate::transport::handshake::{EstablishedSession, HandshakeMessage, TunneledMessage};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};
use crate::ZeroizingArray;

/// Client-side ECIES handshake orchestrator.
///
/// It is generic over two parameters:
///
/// - `P: CryptoProvider`, which defines the complete cryptographic suite.
/// - `M`, the curve-specific ECIES message type.
pub struct EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	state: ClientStateMachine<Ecies>,
	client_random: Option<[u8; 32]>,
	/// The exact DER bytes of the sent `ClientHello`. The transcript binds
	/// them, so a rewritten offer changes the transcript hash (CWE-757).
	client_hello: Option<Vec<u8>>,
	base_session_key: Option<ZeroizingArray<32>>,
	server_random: Option<[u8; 32]>,
	transcript_hash: Option<[u8; 32]>,
	aad_domain_tag: &'static [u8],
	security_offer: Option<SecurityOffer>,
	strength_floor: StrengthFloor,
	transport_offer: Option<TransportOffer>,
	mux_settings: Option<MuxSettings>,
	selected_profile: Option<RunnableProfile<P>>,
	certificate_validator: Option<Arc<dyn CertificateValidation>>,
	identity: Option<ClientIdentity<P>>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	stored_receipt: Option<StoredReceipt>,
	epoch_materials: Option<EpochMaterials>,
	server_certificate: Option<Arc<Certificate>>,
	_phantom_provider: PhantomData<P>,
	_phantom_message: PhantomData<M>,
}

/// Extraction of a verifying key from a certificate.
pub trait ExtractVerifyingKey: Sized {
	/// Extract the verifying key from `cert`.
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
	P::Signature: SignatureEncoding + LowSEncoding,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + ExtractVerifyingKey,
	P::AeadCipher: KeyInit,
	M: EciesMessageOps,
{
	/// Create an ECIES handshake client.
	///
	/// `aad_domain_tag` defaults to `TIGHTBEAM_AAD_DOMAIN_TAG`.
	pub fn new(aad_domain_tag: Option<&'static [u8]>) -> Self {
		Self {
			state: ClientStateMachine::<Ecies>::default(),
			client_random: None,
			client_hello: None,
			base_session_key: None,
			server_random: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.unwrap_or(TIGHTBEAM_AAD_DOMAIN_TAG),
			security_offer: None, // No offer = dealer's choice mode
			strength_floor: StrengthFloor::default(),
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			certificate_validator: None,
			identity: None,
			receipt_approver: None,
			stored_receipt: None,
			epoch_materials: None,
			server_certificate: None,
			_phantom_provider: PhantomData,
			_phantom_message: PhantomData,
		}
	}

	/// Create an ECIES handshake client that presents `identity`, when one is
	/// given, for mutual authentication.
	pub fn new_with_identity(aad_domain_tag: Option<&'static [u8]>, identity: Option<ClientIdentity<P>>) -> Self {
		Self {
			state: ClientStateMachine::<Ecies>::default(),
			client_random: None,
			client_hello: None,
			base_session_key: None,
			server_random: None,
			transcript_hash: None,
			aad_domain_tag: aad_domain_tag.unwrap_or(TIGHTBEAM_AAD_DOMAIN_TAG),
			security_offer: None, // No offer = dealer's choice mode
			strength_floor: StrengthFloor::default(),
			transport_offer: None,
			mux_settings: None,
			selected_profile: None,
			certificate_validator: None,
			identity,
			receipt_approver: None,
			stored_receipt: None,
			epoch_materials: None,
			server_certificate: None,
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

	/// Present `identity`, the client's certificate and the key that proves it,
	/// for mutual authentication.
	#[must_use]
	pub fn with_client_identity(mut self, identity: ClientIdentity<P>) -> Self {
		self.identity = Some(identity);
		self
	}

	/// Set the security profile offer for negotiation.
	///
	/// Without an offer, the server picks its default profile (dealer's
	/// choice).
	#[must_use]
	pub fn with_security_offer(mut self, offer: SecurityOffer) -> Self {
		self.security_offer = Some(offer);
		self
	}

	/// Override the minimum-strength policy applied to the server's selection.
	///
	/// The default is `DefaultStrengthFloor`, which requires a 256-bit AEAD key
	/// and a digest of 256 bits or more. The client applies it with or without
	/// an offer. Pass `NoStrengthFloor` only where weaker profiles must remain
	/// acceptable.
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.strength_floor = StrengthFloor::with_policy(policy);
		self
	}

	/// Set the transport capability offer for multiplexing.
	///
	/// Without an offer, the connection stays single-flight.
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

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
	}

	/// Decode and validate the server handshake.
	///
	/// # Fail closed
	///
	/// A configured certificate validator is mandatory (CWE-295). Expiry alone
	/// authenticates nobody, so a missing validator aborts the handshake.
	fn validate_and_extract_server_handshake(
		&self,
		server_handshake_der: impl AsRef<[u8]>,
	) -> Result<ServerHandshake, HandshakeError> {
		let server_handshake_der = server_handshake_der.as_ref();
		let server_handshake = ServerHandshake::from_der(server_handshake_der)?;
		let validator = self.certificate_validator.as_ref().ok_or(HandshakeError::MissingTrustStore)?;

		server_handshake.certificate.validate_expiry()?;
		validator.evaluate(&server_handshake.certificate)?;

		Ok(server_handshake)
	}

	/// Extract and store the server random from the handshake.
	fn extract_server_random(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let server_random = server_handshake.server_random.to_32_byte_array()?;
		self.server_random = Some(server_random);
		Ok(())
	}

	/// Compute and store the transcript hash.
	fn compute_and_store_transcript_hash(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let client_hello = self.client_hello.as_deref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.ok_or(HandshakeError::InvalidState)?;
		let spki_bytes = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// The transcript binds the negotiated profile and the transport
		// capabilities as the bytes that arrived. A tampered `security_accept`
		// or `transport_accept` yields a different hash and fails signature
		// verification.
		let accept_der = server_handshake.security_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let transport_accept_der = server_handshake.transport_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let mut transcript =
			Transcript::ecies_handshake(client_hello, &server_random, spki_bytes, accept_der, transport_accept_der);

		let transcript_digest = transcript.seal::<P::Digest>()?;
		self.transcript_hash = Some(transcript_digest);

		// Invariant: the transcript is immutable once its hash is computed.

		Ok(())
	}

	/// Generate and store the base session key.
	fn generate_base_session_key(&mut self) -> Result<(), HandshakeError> {
		let base_key = generate_nonce::<32>(None)?;
		self.base_session_key = Some(ZeroizingArray::new(base_key));

		Ok(())
	}

	/// Build the ClientHello message.
	pub fn build_client_hello(&mut self) -> Result<ClientHello, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::Init)?;

		// 2. Generate the client random.
		let client_random = generate_nonce::<32>(None)?;
		self.client_random = Some(client_random);

		// 3. Build the ClientHello.
		let client_hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			security_offer: self.security_offer.to_owned(),
			transport_offer: self.transport_offer.to_owned(),
		};

		// Retain the exact DER for transcript binding, because both sides
		// hash the full ClientHello with its offers.
		let client_hello_der = client_hello.to_der()?;
		self.client_hello = Some(client_hello_der.to_owned());

		// The hello is sent, so the state moves to HelloSent.
		self.state.transition(ClientHandshakeState::HelloSent)?;
		Ok(client_hello)
	}

	/// Process the ServerHandshake message and build the ClientKeyExchange to
	/// send next.
	pub async fn process_server_handshake(
		&mut self,
		server_handshake_der: impl AsRef<[u8]>,
	) -> Result<ClientKeyExchange, HandshakeError> {
		let server_handshake_der = server_handshake_der.as_ref();
		// 1. Validate that the hello was sent.
		self.validate_expected_state(ClientHandshakeState::HelloSent)?;
		let _client_random_check = self.client_random.ok_or(HandshakeError::InvalidState)?;

		// 2. Transition to ServerHelloReceived.
		self.state.transition(ClientHandshakeState::ServerHelloReceived)?;

		// 3. Decode and validate the server handshake.
		let mut server_handshake = self.validate_and_extract_server_handshake(server_handshake_der)?;

		// 4. Validate the profile negotiation.
		self.validate_profile_selection(&server_handshake)?;

		// 5. Validate the transport capability negotiation. An accept that the
		//    client never offered fails closed.
		let offer = self.transport_offer.as_ref();
		let accept = server_handshake.transport_accept.as_ref().map(WireDer::value);
		self.mux_settings = MuxSettings::for_client(offer, accept)?;

		// 6. Extract the server random.
		self.extract_server_random(&server_handshake)?;

		// 7. Verify the server signature.
		self.verify_server_handshake_signature(&server_handshake)?;

		// 8. Validate, approve, and countersign the session receipt, which
		//    fails closed on a mismatch. The step consumes the receipt artifact
		//    out of the decoded message, because the stored receipt owns it.
		let pending_receipt = self.process_session_receipt(&mut server_handshake).await?;

		// 9. Generate and encrypt the session key. The countersignature, with
		//    the settlement answer bound inside it, folds into the ECIES
		//    payload, which keeps it confidential. After encoding it moves into
		//    the completed stored artifact with zero copies.
		let encrypted_bytes = self.generate_and_encrypt_session_key(&server_handshake, pending_receipt)?;

		// 10. Handle mutual authentication. The signature commits to `encrypted_bytes`.
		let (client_certificate, client_signature) =
			self.prepare_client_auth(&server_handshake, &encrypted_bytes).await?;

		// 11. Build and encode the ClientKeyExchange.
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		};

		// 12. Retain the validated server certificate for post-handshake renewals.
		self.server_certificate = Some(Arc::new(server_handshake.certificate));

		// 13. Advance to KeyExchangeSent. Step 2 entered ServerHelloReceived.
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(client_kex)
	}

	/// Validate the server's profile selection against the client's offer and
	/// the strength floor.
	fn validate_profile_selection(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let security_accept = server_handshake.security_accept.as_ref();
		let accept = security_accept.map(WireDer::value).ok_or(HandshakeError::InvalidState)?;

		// With an offer, the server's selection must come from it. Without
		// one, the server chooses, and the floor still bounds that choice.
		if let Some(offer) = &self.security_offer {
			if !offer.profiles.contains(&accept.profile) {
				return Err(HandshakeError::InvalidProfileSelection);
			}
		}

		let profile = RunnableProfile::<P>::try_from(accept.profile)?;
		self.strength_floor.admit(&profile)?;
		self.selected_profile = Some(profile);

		Ok(())
	}

	/// Verify the server's signature over the transcript hash.
	fn verify_server_handshake_signature(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let verifying_key = self.extract_verifying_key(&server_handshake.certificate)?;
		self.compute_and_store_transcript_hash(server_handshake)?;

		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		self.verify_server_signature(&verifying_key, &transcript_digest, server_handshake.signature.as_bytes())
	}

	/// Generate the base session key and ECIES-encrypt it to the server.
	///
	/// The pending receipt ack passes through encryption by value, so its
	/// `SignerInfo` moves into the stored receipt without a clone.
	fn generate_and_encrypt_session_key(
		&mut self,
		server_handshake: &ServerHandshake,
		pending_receipt: Option<(SignedData, SignerInfo)>,
	) -> Result<Vec<u8>, HandshakeError> {
		self.generate_base_session_key()?;

		let base_key = self.base_session_key.as_deref().ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		let (artifact, receipt_ack) = match pending_receipt {
			Some((artifact, ack)) => (Some(artifact), Some(ack)),
			None => (None, None),
		};

		let (encrypted_bytes, receipt_ack) = self.perform_ecies_encryption(
			base_key,
			&client_random,
			receipt_ack,
			&server_handshake.certificate,
			Some(self.aad_domain_tag),
		)?;

		if let Some(artifact) = artifact {
			let countersignature = receipt_ack.ok_or(HandshakeError::InvalidState)?;
			let completed = artifact.complete(countersignature)?;
			self.stored_receipt = Some(StoredReceipt::try_from(completed)?);
		}

		Ok(encrypted_bytes)
	}

	/// Validate, approve, and countersign the server's session receipt.
	///
	/// Budget-bearing accepts demand a receipt artifact whose body matches the
	/// negotiated session and whose server `SignerInfo` verifies. Anything else
	/// fails closed.
	///
	/// - The approver, or the fail-closed default, answers the settlement challenge.
	/// - The client `SignerInfo` binds the receipt body plus the answer under
	///   the client identity (non-repudiation).
	///
	/// # Completion
	///
	/// It returns the pending artifact plus the countersignature destined for
	/// the confidential key-exchange payload. Completion waits until after
	/// payload encoding, so the `SignerInfo` moves into the stored artifact.
	async fn process_session_receipt(
		&mut self,
		server_handshake: &mut ServerHandshake,
	) -> Result<Option<(SignedData, SignerInfo)>, HandshakeError> {
		let accepted = server_handshake.transport_accept.as_ref().map(WireDer::value);
		let granted = accepted.and_then(|accept| accept.granted_budgets);
		let credit_unit = accepted.map(|accept| accept.credit_unit);
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;

		// Consume the artifact, because the completed copy that this function
		// stores is its only owner from here on.
		let artifact = server_handshake.session_receipt.take();
		let parsed_receipt = artifact.as_ref().map(ReceiptArtifact::receipt).transpose()?;
		let Some(receipt) =
			SessionReceipt::match_accept::<P::Digest>(parsed_receipt, granted, credit_unit, &transcript_digest)?
		else {
			return Ok(None);
		};

		// The server SignerInfo over the receipt body makes the agreement
		// verifiable by a third party, so an unsigned receipt is no receipt.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let server_signer = artifact
			.signer_for_role(ReceiptRole::Server)?
			.ok_or(HandshakeError::ReceiptMissing)?;

		let expected_sid = server_handshake.certificate.signer_identifier::<P::Digest>()?;
		let verifying_key = self.extract_verifying_key(&server_handshake.certificate)?;
		receipt.verify_signer::<P::Digest, P::Signature, _>(
			server_signer,
			ReceiptRole::Server,
			&expected_sid,
			&verifying_key,
		)?;

		// Countersigning demands a client identity, so a budget-bearing
		// session without mutual authentication fails closed. The check runs
		// before approval, because approving can spend an irreversible
		// settlement answer, so every local precondition must already hold.
		let identity = self.identity.as_ref().ok_or(HandshakeError::MutualAuthRequired)?;
		let key_provider = identity.signing_provider();

		// With no approver, approval fails closed.
		let response = receipt.approve(self.receipt_approver.as_deref()).await?;
		let answer = response.as_ref().map(OctetString::as_bytes);
		let countersignature = receipt.countersign::<P::Digest>(answer, key_provider).await?;

		Ok(Some((artifact, countersignature)))
	}

	/// Prepare the client authentication materials when the server requires
	/// them or the client holds an identity.
	///
	/// The signature covers `Digest(transcript_hash || encrypted_data ||
	/// cert_der)`, so it binds to this key exchange and this identity alone.
	/// The result is the optional certificate and the optional signature.
	async fn prepare_client_auth(
		&self,
		server_handshake: &ServerHandshake,
		encrypted_data: impl AsRef<[u8]>,
	) -> Result<(Option<Certificate>, Option<OctetString>), HandshakeError> {
		let encrypted_data = encrypted_data.as_ref();
		let transcript_digest = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		let identity = match (&self.identity, server_handshake.client_cert_required) {
			(Some(identity), _) => identity,
			(None, true) => return Err(HandshakeError::MutualAuthRequired),
			(None, false) => return Ok((None, None)),
		};

		let cert = identity.certificate();
		let cert_der = cert.to_der()?;
		let mut auth_transcript = Transcript::ecies_client_auth(&transcript_digest, encrypted_data, &cert_der);
		let auth_digest = auth_transcript.seal::<P::Digest>()?;
		let signature_bytes = identity.signing_provider().sign_prehash(&auth_digest).await?;

		let cert = Certificate::clone(cert);
		let signature = OctetString::new(signature_bytes)?;
		Ok((Some(cert), Some(signature)))
	}
	/// Complete the handshake and derive the provider's client-to-server and
	/// server-to-client AEAD ciphers.
	pub fn complete(&mut self) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Derive the final session keys.
		let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::InvalidState)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;

		// The AEAD derivation salt is `client_random || server_random`.
		let mut salt = Zeroizing::new([0u8; 64]);
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);

		let salt_bytes = salt.as_slice();
		let session_ciphers = self.derive_directional_aead(base_key.as_slice(), KdfSalt::new(salt_bytes))?;

		// Invariant: AEAD key derivation runs exactly once, after the
		// transcript locks.

		// 3. Seed the epoch materials for post-handshake renewal.
		if let Some(transcript_hash) = self.transcript_hash {
			let epoch_salt = KdfSalt::new(salt_bytes);
			let materials = EpochMaterials::derive::<P>(base_key.as_slice(), epoch_salt, transcript_hash)?;
			self.epoch_materials = Some(materials);
		}

		// 4. Transition to the complete state.
		self.state.transition(ClientHandshakeState::Completed)?;

		// 5. Clear the sensitive data in place.
		self.clear_sensitive_data();

		Ok(session_ciphers)
	}

	/// Erase the ephemeral ECIES key material after session establishment
	/// (CWE-226).
	fn clear_sensitive_data(&mut self) {
		self.base_session_key.zeroize();
		self.client_random.zeroize();
		self.server_random.zeroize();
	}

	/// The current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The transcript hash, once the server handshake sets it.
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}

	/// The negotiated multiplexing settings, if any.
	pub fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.mux_settings
	}

	/// The dual-signed session receipt, when the completed handshake carried
	/// budgets.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	/// Take the epoch materials seeded at handshake completion.
	pub fn take_epoch_materials(&mut self) -> Option<EpochMaterials> {
		self.epoch_materials.take()
	}

	/// The validated server certificate, retained for post-handshake epoch
	/// renewals.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.server_certificate.as_deref()
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// The mutual-auth path reaches this through [`ClientHandshakeProtocol`],
	/// and the client-identity-free path calls it directly, so both read the
	/// session terms the same way.
	///
	/// [`ClientHandshakeProtocol`]: crate::transport::handshake::ClientHandshakeProtocol
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the handshake has no negotiated
	///   profile, so it agreed no AEAD algorithm.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError>
	where
		P::AeadCipher: KeyInit + 'static,
	{
		// The inherent method is the one home for state validation, AEAD
		// derivation, invariants, and cleanup.
		let ciphers = self.complete()?;

		let keys = SessionKeys::for_client(ciphers);
		let mux = self.mux_settings;
		let receipt = self.stored_receipt.take().map(Arc::new);
		let epoch = self.epoch_materials.take();
		let peer = self.server_certificate.as_ref().map(Arc::clone);
		Ok(EstablishedSession::new(keys, mux, receipt, peer, epoch))
	}

	fn extract_verifying_key(&self, cert: &Certificate) -> Result<P::VerifyingKey, HandshakeError> {
		P::VerifyingKey::extract_from_certificate(cert)
	}

	fn verify_server_signature(
		&self,
		verifying_key: &P::VerifyingKey,
		digest: &[u8; 32],
		signature_bytes: &[u8],
	) -> Result<(), HandshakeError> {
		let signature = P::Signature::try_from(signature_bytes).map_err(|e| e.into())?;
		signature.verify_prehash(verifying_key, digest)?;
		Ok(())
	}

	/// Encrypt the session payload to the server's public key.
	///
	/// It hands the `receipt_ack` back after encoding, and the caller moves it
	/// into the completed stored artifact.
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

		// The DER buffer holds the base session key, so it wipes when dropped,
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

		// Ephemeral ECIES randomness comes straight from the OS CSPRNG, because
		// the provider abstraction covers the KDF and the AEAD and not entropy.
		let encrypted_message = encrypt::<_, _, _, M, P::Kdf, P::AeadCipher>(
			&recipient_pubkey,
			plaintext.as_slice(),
			associated_data,
			Some(&mut rand_core::OsRng),
		)?;

		Ok((encrypted_message.to_bytes(), receipt_ack))
	}
}

impl<P, M> HandshakeFinalization<P> for EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<RunnableProfile<P>> {
		self.selected_profile
	}
}

impl<P, M> HandshakeAlertHandler for EciesHandshakeClient<P, M> where P: CryptoProvider {}

impl<P, M> ClientHandshakeProtocol for EciesHandshakeClient<P, M>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey: EciesEphemeral<PublicKey = PublicKey<P::Curve>>,
	P::Signature: SignatureEncoding + LowSEncoding + Send + Sync,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + ExtractVerifyingKey + Send + Sync,
	P::AeadCipher: KeyInit + Send + Sync + 'static,
	M: EciesMessageOps + Send + Sync + 'static,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, Self::Error>> {
		Box::pin(async move {
			// ECIES tunnels its own messages: the hello travels signed.
			let client_hello = self.build_client_hello()?;
			let signed_data = SignedData::try_from(&client_hello)?;
			HandshakeMessage::try_from(signed_data)
		})
	}

	fn handle_response<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			// ECIES tunnels its messages inside the containers.
			// The server handshake is read from the bytes it arrived as.
			let signed_data = msg.signed()?;
			let server_handshake = signed_data.value().tunneled_der()?;

			let client_kex = self.process_server_handshake(server_handshake).await?;
			let enveloped_data = EnvelopedData::try_from(&client_kex)?;
			Ok(Some(HandshakeMessage::try_from(enveloped_data)?))
		})
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
		Box::pin(async move {
			let mut client = self;
			EciesHandshakeClient::take_established(&mut client)
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile.map(|profile| profile.descriptor())
	}
}

#[cfg(feature = "secp256k1")]
impl ExtractVerifyingKey for Secp256k1VerifyingKey {
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError> {
		let public_key_bytes = cert.verifying_key_bytes();
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
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::Encode;
	use crate::oids::{HASH_SHA3_384, HASH_SHA3_512};
	use crate::random::generate_nonce;
	use crate::transport::handshake::negotiation::{NegotiationError, ProfileStrength, SecurityAccept, SecurityOffer};
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
		let client_hello_der = client.build_client_hello()?.to_der()?;
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
			create_test_server_handshake(&test_cert.certificate, &server_random, signature_bytes.to_bytes())?;

		// When: Client processes the server handshake. The test asserts on the
		// state the call leaves behind, not on the message it returns.
		client.process_server_handshake(&server_handshake_der).await?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert!(client.base_session_key.is_some());
		assert!(client.transcript_hash.is_some());

		// When: Client completes the handshake
		let _session_key = client.complete()?;

		// Then: Handshake is complete
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);

		Ok(())
	}

	/// A client without a certificate validator aborts, ahead of
	/// degrading to expiry-only server authentication (CWE-295).
	#[tokio::test]
	async fn test_missing_validator_fails_closed() -> Result<(), Box<dyn Error>> {
		let mut client = TestEciesClientBuilder::new().build();
		let client_hello_der = client.build_client_hello()?.to_der()?;

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
			create_test_server_handshake(&test_cert.certificate, &server_random, signature_bytes.to_bytes())?;

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

	/// A descriptor that names a digest the default provider does not run.
	fn foreign_profile(digest: ObjectIdentifier) -> SecurityProfileDesc {
		SecurityProfileDesc { digest: Some(digest), ..create_default_test_profile() }
	}

	type DefaultEciesClient = EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>;

	/// A client that trusts `test_cert`, with its `ClientHello` DER.
	fn profile_test_client(
		test_cert: &TestCertificate,
		offer: Option<SecurityOffer>,
	) -> Result<(DefaultEciesClient, Vec<u8>), Box<dyn Error>> {
		let mut client = TestEciesClientBuilder::new()
			.with_trusted_certificate(test_cert.certificate.to_owned())
			.build();
		if let Some(offer) = offer {
			client = client.with_security_offer(offer);
		}

		let hello = client.build_client_hello()?.to_der()?;
		Ok((client, hello))
	}

	/// A `ServerHandshake` signed by `test_cert` that accepts `profile`.
	fn signed_server_response(
		test_cert: &TestCertificate,
		client_hello_der: &[u8],
		profile: SecurityProfileDesc,
	) -> Result<Vec<u8>, Box<dyn Error>> {
		let server_random = [2u8; 32];
		let accept_der = SecurityAccept::new(profile).to_der()?;
		let server_public_key = test_cert
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let transcript_hash =
			compute_test_transcript_hash(client_hello_der, &server_random, server_public_key, &accept_der);

		let signature: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let response = ServerHandshake {
			certificate: test_cert.certificate.to_owned(),
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature.to_bytes().to_vec())?,
			security_accept: Some(WireDer::new(SecurityAccept::new(profile))?),
			client_cert_required: false,
			transport_accept: None,
			session_receipt: None,
		};
		Ok(response.to_der()?)
	}

	#[tokio::test]
	async fn a_client_accepts_an_offered_profile_it_runs() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let native = create_default_test_profile();
		let offer = SecurityOffer::new(vec![foreign_profile(HASH_SHA3_384), native]);
		let (mut client, hello) = profile_test_client(&test_cert, Some(offer))?;
		let response = signed_server_response(&test_cert, &hello, native)?;

		client.process_server_handshake(&response).await?;

		assert_eq!(client.selected_profile.map(|profile| profile.descriptor()), Some(native));
		Ok(())
	}

	#[tokio::test]
	async fn a_client_refuses_a_profile_it_did_not_offer() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let offer = SecurityOffer::new(vec![foreign_profile(HASH_SHA3_384)]);
		let (mut client, hello) = profile_test_client(&test_cert, Some(offer))?;
		let response = signed_server_response(&test_cert, &hello, create_default_test_profile())?;

		let result = client.process_server_handshake(&response).await;

		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	#[tokio::test]
	async fn a_dealers_choice_client_accepts_a_profile_it_runs() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let native = create_default_test_profile();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let response = signed_server_response(&test_cert, &hello, native)?;

		client.process_server_handshake(&response).await?;

		assert_eq!(client.selected_profile.map(|profile| profile.descriptor()), Some(native));
		Ok(())
	}

	// A signed accept that names an algorithm the provider does not run is
	// refused, so the session never runs under a false identity.
	#[tokio::test]
	async fn a_dealers_choice_client_refuses_a_profile_it_does_not_run() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let response = signed_server_response(&test_cert, &hello, foreign_profile(HASH_SHA3_512))?;

		let result = client.process_server_handshake(&response).await;
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::UnrunnableProfile))
		));
		Ok(())
	}

	/// A policy that refuses every profile.
	struct RefuseAll;

	impl ProfileStrengthPolicy for RefuseAll {
		fn meets_floor(&self, _strength: &ProfileStrength) -> bool {
			false
		}
	}

	// Without an offer the server chooses, and the client floor still bounds
	// that choice.
	#[tokio::test]
	async fn a_dealers_choice_client_refuses_a_profile_below_its_floor() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (client, hello) = profile_test_client(&test_cert, None)?;
		let mut client = client.with_strength_policy(Arc::new(RefuseAll));

		let response = signed_server_response(&test_cert, &hello, create_default_test_profile())?;
		let result = client.process_server_handshake(&response).await;
		assert!(matches!(
			result,
			Err(HandshakeError::NegotiationError(NegotiationError::BelowStrengthFloor))
		));
		Ok(())
	}
}

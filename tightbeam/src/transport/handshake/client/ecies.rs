//! ECIES-based client handshake orchestrator.
//!
//! [`EciesHandshakeClient`] runs the client side of the TightBeam ECIES
//! handshake protocol:
//!
//! 1. Send the ClientHello with the client random and the offers.
//! 2. Verify the ServerHandshake, whose signed transcript carries the server ephemeral public key.
//! 3. Draw the ECIES ephemeral, seal the base secret to the server's static key, and derive the
//!    handshake secret from the base secret and the ephemeral-ephemeral ECDH.
//! 4. Derive the directional keys from the handshake secret at completion.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use core::marker::PhantomData;

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::constants::{EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_AAD_DOMAIN_TAG};
use crate::crypto::aead::{KeyInit, SessionKeys};
use crate::crypto::ecies::{EciesMessageOps, EciesPublicKeyOps, EciesSecretKeyOps};
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
use crate::random::{generate_nonce, OsRng};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfileStrengthPolicy, RunnableProfile, SecurityOffer, StrengthFloor, TransportOffer,
};
use crate::transport::handshake::orchestrator::{BaseSecret, HandshakeVerifyingKey, ServerEphemeral};
use crate::transport::handshake::primitives::transcript::{EciesHandshakeLegs, Transcript};
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::ReceiptSigner;
use crate::transport::handshake::receipt::{ReceiptApprover, ReceiptRole, SessionReceipt, StoredReceipt};
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine, Ecies};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake,
};
use crate::transport::handshake::{DirectionalCiphers, EpochMaterials, HandshakeAlertHandler, HandshakeFinalization};
use crate::transport::handshake::{EstablishedSession, HandshakeMessage, HandshakeSecret, TunneledMessage};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};

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
	/// The secret the session derives from, held from the key exchange to
	/// completion, which takes it.
	handshake_secret: Option<HandshakeSecret>,
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
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a valid curve point.
	fn extract_from_certificate(cert: &Certificate) -> Result<Self, HandshakeError>;
}

impl<P, M> EciesHandshakeClient<P, M>
where
	P: CryptoProvider,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	PublicKey<P::Curve>: EciesPublicKeyOps,
	P::Signature: SignatureEncoding + LowSEncoding,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	for<'a> <P::Signature as TryFrom<&'a [u8]>>::Error: Into<HandshakeError>,
	P::VerifyingKey: PrehashVerifier<P::Signature> + ExtractVerifyingKey,
	P::AeadCipher: KeyInit,
	M: EciesMessageOps,
{
	/// Create an ECIES handshake client.
	///
	/// `aad_domain_tag` defaults to [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(aad_domain_tag: Option<&'static [u8]>) -> Self {
		Self {
			state: ClientStateMachine::<Ecies>::default(),
			client_random: None,
			client_hello: None,
			handshake_secret: None,
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
			handshake_secret: None,
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
	///
	/// The server ephemeral enters at its fixed width, so a `server_ephemeral`
	/// of another length fails here, before the signature check.
	fn compute_and_store_transcript_hash(&mut self, server_handshake: &ServerHandshake) -> Result<(), HandshakeError> {
		let client_hello = self.client_hello.as_deref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.ok_or(HandshakeError::InvalidState)?;
		let server_ephemeral = server_handshake.server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let spki = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();

		// The transcript binds every leg as the bytes that arrived, so a
		// tampered leg yields another hash and fails signature verification.
		let security_accept_der = server_handshake.security_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let transport_accept_der = server_handshake.transport_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let legs = EciesHandshakeLegs {
			client_hello,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral,
			spki,
			security_accept_der,
			transport_accept_der,
		};

		let mut transcript = Transcript::ecies_handshake(legs);
		let transcript_digest = transcript.seal::<P::Digest>()?;
		self.transcript_hash = Some(transcript_digest);

		Ok(())
	}

	/// Build the ClientHello message.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the client is past `Init`.
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::DerError`] -- the ClientHello fails to encode.
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
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no ClientHello was sent, or the server sent no security accept.
	/// - [`HandshakeError::MissingTrustStore`] -- no certificate validator is set.
	/// - [`HandshakeError::CertificateValidationError`] -- the server certificate fails validation.
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected a profile outside the offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable, or the transport accept is invalid.
	/// - [`HandshakeError::OctetStringLengthError`] -- the server ephemeral is
	///   not a compressed point's width.
	/// - [`HandshakeError::SignatureError`] -- the server signature fails to verify.
	/// - [`HandshakeError::InvalidPublicKey`] -- the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::MutualAuthRequired`] -- the server or a receipt
	///   requires a client identity, and none is set.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret or the
	///   acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal the countersignature.
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

		// 8. Parse the server ephemeral the signature just authenticated,
		//    beside the static key it must differ from.
		let static_key = server_handshake.certificate.verifying_key::<P::Curve>()?;
		let server_ephemeral = static_key.server_ephemeral(server_handshake.server_ephemeral.as_bytes())?;

		// 9. Validate, approve, and countersign the session receipt, which
		//    fails closed on a mismatch. The step consumes the receipt artifact
		//    out of the decoded message, because the stored receipt owns it.
		let pending_receipt = self.process_session_receipt(&mut server_handshake).await?;

		// 10. Draw the base secret and the ECIES ephemeral, derive the handshake
		//     secret, and seal the payload with the countersignature inside it.
		let encrypted_bytes = self.seal_key_exchange_payload(&server_handshake, &server_ephemeral, pending_receipt)?;

		// 11. Handle mutual authentication. The signature commits to `encrypted_bytes`.
		let (client_certificate, client_signature) =
			self.prepare_client_auth(&server_handshake, &encrypted_bytes).await?;

		// 12. Build and encode the ClientKeyExchange.
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		};

		// 13. Retain the validated server certificate for post-handshake renewals.
		self.server_certificate = Some(Arc::new(server_handshake.certificate));

		// 14. Advance to KeyExchangeSent. Step 2 entered ServerHelloReceived.
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

	/// Draw the base secret and the ECIES ephemeral, derive the handshake
	/// secret, and ECIES-encrypt the payload to the server.
	///
	/// One ephemeral `r` serves both key agreements: `r·S` with the server's
	/// static key seals the payload, and `r·E` with `server_ephemeral` feeds
	/// the handshake secret. The ephemeral, the base secret, and the shared
	/// secret are locals, so only the handshake secret outlives this call.
	fn seal_key_exchange_payload(
		&mut self,
		server_handshake: &ServerHandshake,
		server_ephemeral: &PublicKey<P::Curve>,
		pending_receipt: Option<(SignedData, SignerInfo)>,
	) -> Result<Vec<u8>, HandshakeError> {
		let base = BaseSecret::random(None)?;
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		let transcript_hash = self.transcript_hash.ok_or(HandshakeError::InvalidState)?;
		let salt = self.randoms_salt()?;

		// Ephemeral ECIES randomness comes straight from the OS CSPRNG, because
		// the provider abstraction covers the KDF and the AEAD and not entropy.
		let ephemeral = <PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey::random(&mut OsRng);
		let shared = ephemeral.diffie_hellman(server_ephemeral);
		let handshake_secret = HandshakeSecret::derive::<P>(&base, &shared, salt.as_kdf_salt())?;

		let (artifact, receipt_ack) = match pending_receipt {
			Some((artifact, ack)) => (Some(artifact), Some(ack)),
			None => (None, None),
		};
		let sealed_ack = match receipt_ack.as_ref() {
			Some(ack) => {
				let ack_der = Zeroizing::new(ack.to_der()?);
				Some(handshake_secret.seal_ack::<P>(salt.as_kdf_salt(), &transcript_hash, &ack_der)?)
			}
			None => None,
		};

		let client_certificate = self.identity.as_ref().map(ClientIdentity::certificate);
		let aad = ClientKeyExchange::client_bound_aad(self.aad_domain_tag, client_certificate)?;
		let encrypted_bytes = self.perform_ecies_encryption(
			&ephemeral,
			&base,
			&client_random,
			sealed_ack,
			&server_handshake.certificate,
			Some(aad.as_slice()),
		)?;

		if let Some(artifact) = artifact {
			let countersignature = receipt_ack.ok_or(HandshakeError::InvalidState)?;
			let completed = artifact.complete(countersignature)?;
			self.stored_receipt = Some(StoredReceipt::try_from(completed)?);
		}

		self.handshake_secret = Some(handshake_secret);
		Ok(encrypted_bytes)
	}

	/// The KDF salt of this handshake, over the randoms both sides hold.
	fn randoms_salt(&self) -> Result<RandomsSalt, HandshakeError> {
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::InvalidState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::InvalidState)?;
		Ok(RandomsSalt::new(client_random, server_random))
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
	/// # Fail closed
	///
	/// A countersignature needs a client identity, so a budget-bearing session
	/// without mutual authentication fails with
	/// [`HandshakeError::MutualAuthRequired`]. That check runs before
	/// approval, because approval can spend an irreversible settlement answer.
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
	fn complete(&mut self) -> Result<DirectionalCiphers<P::AeadCipher>, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Take the handshake secret. It drops when this function returns,
		//    so completion is the one derivation from it.
		let handshake_secret = self.handshake_secret.take().ok_or(HandshakeError::InvalidState)?;
		let salt = self.randoms_salt()?;

		// 3. Derive the directional session keys, salted with `client_random || server_random`.
		let session_ciphers = self.derive_directional_aead(&handshake_secret, salt.as_kdf_salt())?;

		// 4. Seed the epoch materials for post-handshake renewal.
		if let Some(transcript_hash) = self.transcript_hash {
			let materials = EpochMaterials::derive::<P>(&handshake_secret, salt.as_kdf_salt(), transcript_hash)?;
			self.epoch_materials = Some(materials);
		}

		// 5. Transition to the complete state.
		self.state.transition(ClientHandshakeState::Completed)?;

		// 6. Clear the sensitive data in place.
		self.clear_sensitive_data();

		Ok(session_ciphers)
	}

	/// Erase the handshake randoms after session establishment (CWE-226).
	/// The handshake secret wipes at the take in `complete`.
	fn clear_sensitive_data(&mut self) {
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

	/// Encrypt the session payload to the server's public key under
	/// `ephemeral`, the same key the handshake secret's agreement used.
	fn perform_ecies_encryption(
		&self,
		ephemeral: &<PublicKey<P::Curve> as EciesPublicKeyOps>::SecretKey,
		base: &BaseSecret,
		client_random: &[u8; 32],
		sealed_ack: Option<Vec<u8>>,
		server_certificate: &Certificate,
		associated_data: Option<&[u8]>,
	) -> Result<Vec<u8>, HandshakeError> {
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base.as_bytes())?,
			client_random: OctetString::new(client_random.as_slice())?,
			receipt_ack: sealed_ack.map(OctetString::new).transpose()?,
		};

		// The DER buffer holds the base secret, so it wipes when dropped,
		// along with the transient OCTET STRING copy inside the payload.
		let plaintext = Zeroizing::new(payload.to_der()?);
		payload.base_key.into_bytes().zeroize();

		let recipient_pubkey = PublicKey::<P::Curve>::from_sec1_bytes(
			server_certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;

		let encrypted_message = ephemeral.encrypt_to::<M, P::Kdf, P::AeadCipher>(
			&recipient_pubkey,
			plaintext.as_slice(),
			associated_data,
			&mut OsRng,
		)?;

		Ok(encrypted_message.to_bytes())
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
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::PrehashSigner;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::Encode;
	use crate::oids::{HASH_SHA3_384, HASH_SHA3_512};
	use crate::random::generate_nonce;
	use crate::transport::handshake::negotiation::{NegotiationError, ProfileStrength, SecurityAccept, SecurityOffer};
	use crate::transport::handshake::orchestrator::CompressedPoint;
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
		let server_ephemeral = create_test_server_ephemeral();
		let accept_der = SecurityAccept::new(create_default_test_profile()).to_der()?;
		let transcript_hash = compute_test_transcript_hash(
			&client_hello_der,
			&server_random,
			&server_ephemeral,
			test_cert
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
			&accept_der,
		);

		let signature_bytes: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let server_handshake_der = create_test_server_handshake(
			&test_cert.certificate,
			&server_random,
			&server_ephemeral,
			signature_bytes.to_bytes(),
		)?;

		// When: Client processes the server handshake. The test asserts on the
		// state the call leaves behind, not on the message it returns.
		client.process_server_handshake(&server_handshake_der).await?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert!(client.handshake_secret.is_some());
		assert!(client.transcript_hash.is_some());

		// When: Client completes the handshake, which takes the secret
		let _ciphers = client.complete()?;

		// Then: Handshake is complete
		assert!(client.is_complete());
		assert_eq!(client.state(), ClientHandshakeState::Completed);
		assert!(client.handshake_secret.is_none());

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
		let server_ephemeral = create_test_server_ephemeral();
		let accept_der = SecurityAccept::new(create_default_test_profile()).to_der()?;
		let transcript_hash = compute_test_transcript_hash(
			&client_hello_der,
			&server_random,
			&server_ephemeral,
			test_cert
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
			&accept_der,
		);
		let signature_bytes: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let server_handshake_der = create_test_server_handshake(
			&test_cert.certificate,
			&server_random,
			&server_ephemeral,
			signature_bytes.to_bytes(),
		)?;

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

	/// A `ServerHandshake` signed by `test_cert` that accepts `profile` and
	/// carries a fresh server ephemeral.
	fn signed_server_response(
		test_cert: &TestCertificate,
		client_hello_der: &[u8],
		profile: SecurityProfileDesc,
	) -> Result<Vec<u8>, Box<dyn Error>> {
		signed_server_response_with_ephemeral(test_cert, client_hello_der, profile, &create_test_server_ephemeral())
	}

	/// A `ServerHandshake` signed by `test_cert` that accepts `profile` and
	/// carries `server_ephemeral` inside its signed transcript.
	fn signed_server_response_with_ephemeral(
		test_cert: &TestCertificate,
		client_hello_der: &[u8],
		profile: SecurityProfileDesc,
		server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	) -> Result<Vec<u8>, Box<dyn Error>> {
		let server_random = [2u8; 32];
		let accept_der = SecurityAccept::new(profile).to_der()?;
		let server_public_key = test_cert
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let transcript_hash = compute_test_transcript_hash(
			client_hello_der,
			&server_random,
			server_ephemeral,
			server_public_key,
			&accept_der,
		);

		let signature: Secp256k1Signature = test_cert.signing_key.sign_prehash(&transcript_hash)?;
		let response = ServerHandshake {
			certificate: test_cert.certificate.to_owned(),
			server_random: OctetString::new(server_random)?,
			server_ephemeral: OctetString::new(*server_ephemeral)?,
			signature: OctetString::new(signature.to_bytes().to_vec())?,
			security_accept: Some(WireDer::new(SecurityAccept::new(profile))?),
			client_cert_required: false,
			transport_accept: None,
			session_receipt: None,
		};
		Ok(response.to_der()?)
	}

	/// `response` with its server ephemeral replaced by `server_ephemeral`
	/// and nothing else changed, as an on-path party would rewrite it.
	fn with_swapped_ephemeral(response: &[u8], server_ephemeral: impl AsRef<[u8]>) -> Result<Vec<u8>, Box<dyn Error>> {
		let mut response = ServerHandshake::from_der(response)?;
		response.server_ephemeral = OctetString::new(server_ephemeral.as_ref())?;
		Ok(response.to_der()?)
	}

	/// A server ephemeral swapped for another valid point after a real server
	/// signed its reply changes the transcript, so the signature fails before
	/// any agreement.
	#[tokio::test]
	async fn a_tampered_server_ephemeral_fails_the_ecies_signature() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let mut server = TestEciesServerBuilder::new()
			.with_key(test_cert.signing_key.to_owned())
			.with_certificate(test_cert.certificate.to_owned())
			.build()?;
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let signed = server.process_client_hello(&hello).await?.to_der()?;
		let tampered = with_swapped_ephemeral(&signed, create_test_server_ephemeral())?;

		let result = client.process_server_handshake(&tampered).await;
		assert!(matches!(result, Err(HandshakeError::SignatureError(_))));
		Ok(())
	}

	/// A server ephemeral of another width fails the fixed-width transcript
	/// leg before the signature check.
	#[tokio::test]
	async fn a_server_ephemeral_of_another_width_is_refused() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let signed = signed_server_response(&test_cert, &hello, create_default_test_profile())?;
		let narrowed = with_swapped_ephemeral(&signed, [0x02u8; 32])?;

		let result = client.process_server_handshake(&narrowed).await;
		assert!(matches!(result, Err(HandshakeError::OctetStringLengthError(_))));
		Ok(())
	}

	/// A validly signed server ephemeral that names no point on the curve is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let signed = signed_server_response_with_ephemeral(
			&test_cert,
			&hello,
			create_default_test_profile(),
			&off_curve_point(),
		)?;

		let result = client.process_server_handshake(&signed).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
		Ok(())
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let static_key = PublicKey::<Secp256k1>::from(*test_cert.signing_key.verifying_key()).compressed_point()?;
		let signed =
			signed_server_response_with_ephemeral(&test_cert, &hello, create_default_test_profile(), &static_key)?;

		let result = client.process_server_handshake(&signed).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
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

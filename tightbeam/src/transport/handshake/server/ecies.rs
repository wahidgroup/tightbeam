//! ECIES-based server handshake orchestrator.
//!
//! [`EciesHandshakeServer`] runs the server side of the TightBeam ECIES
//! handshake protocol.

#![cfg(feature = "x509")]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::OctetString;
use crate::cms::signed_data::SignedData;
use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;
use crate::crypto::aead::SessionKeys;
use crate::crypto::ecies::{decrypt_with_shared_secret, EciesMessageOps};
use crate::crypto::kdf::EcdhSecret;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::LowSEncoding;
use crate::crypto::subtle::ConstantTimeEq;
use crate::der::{Decode, Encode};
use crate::random::{generate_nonce, OsRng};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfilePolicy, ProfileStrengthPolicy, SecurityAccept, TransportAuthorizer, TransportNegotiation,
	TransportOffer,
};
use crate::transport::handshake::orchestrator::{
	Agreed, Agreement, BaseSecret, CompressedPoint, KeySchedule, Salt, Terms,
};
use crate::transport::handshake::peer::PossessionProof;
use crate::transport::handshake::primitives::transcript::{EciesHandshakeLegs, Transcript};
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::{IssuedReceipt, SessionObserver, StoredReceipt};
use crate::transport::handshake::state::{Ecies, ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	AdmittedPeer, EstablishedSession, HandshakeMessage, HandshakeProvider, PeerAuthentication, TunneledMessage,
};
use crate::transport::handshake::{
	ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake, ServerHandshakeProtocol,
};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::Zeroize;

/// Server-side ECIES handshake orchestrator.
///
/// It is generic over `P: HandshakeProvider` for its cryptographic operations.
/// The server handshake runs in order:
///
/// 1. Receive the ClientHello with its random nonce.
/// 2. Draw a per-handshake ephemeral key and send the ServerHandshake with
///    the certificate, the server random, the ephemeral public key, and a
///    signature over the transcript that binds them all.
/// 3. Receive the ClientKeyExchange, open the ECIES payload with the static
///    key, and derive the handshake secret from the base secret and the ECDH
///    of the server ephemeral with the client's ECIES ephemeral.
pub struct EciesHandshakeServer<P>
where
	P: HandshakeProvider,
{
	state: ServerStateMachine<Ecies>,
	server_key_provider: Arc<dyn SigningKeyProvider>,
	server_cert: Arc<Certificate>,
	client_random: Option<[u8; 32]>,
	/// The per-handshake ephemeral private key from the ClientHello to the
	/// key exchange, which takes it, and the handshake secret from there to
	/// completion, which takes that. On an error before a take the value drops
	/// with the orchestrator, which wipes it.
	key_schedule: KeySchedule<EphemeralSecret<P::Curve>>,
	aad_domain_tag: &'static [u8],
	supported_profiles: Vec<SecurityProfileDesc>,
	profiles: ProfilePolicy<P>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	peer_authentication: PeerAuthentication,
	/// What the ClientHello fixed, from the ServerHandshake to completion.
	terms: Option<Terms<P>>,
	/// The receipt of a budget-bearing session, from the ServerHandshake to
	/// the key exchange, which settles it.
	issued: Option<IssuedReceipt>,
	admitted: Option<AdmittedPeer>,
	stored_receipt: Option<StoredReceipt>,
}

/// The parts of the decrypted ECIES key-exchange payload.
///
/// They are the base secret, the anti-replay random, and the client's sealed
/// receipt countersignature, which an unmetered session omits.
struct SessionPayload {
	base: BaseSecret,
	client_random: [u8; 32],
	/// The client receipt `SignerInfo`, sealed under the handshake secret.
	/// Its signed attributes bind the bearer settlement answer, so it opens
	/// only after the ephemeral-ephemeral agreement.
	receipt_ack: Option<OctetString>,
}

impl<P> EciesHandshakeServer<P>
where
	P: HandshakeProvider,
{
	/// Create an ECIES handshake server that presents `server_cert` to the
	/// client.
	///
	/// `aad_domain_tag` defaults to [`TIGHTBEAM_AAD_DOMAIN_TAG`]. The client
	/// is authenticated as `peer_authentication` demands.
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
			key_schedule: KeySchedule::Idle,
			aad_domain_tag: aad_domain_tag.unwrap_or(TIGHTBEAM_AAD_DOMAIN_TAG),
			supported_profiles: Vec::new(), // Must be set via with_supported_profiles()
			profiles: ProfilePolicy::new(),
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			peer_authentication,
			terms: None,
			issued: None,
			admitted: None,
			stored_receipt: None,
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
	/// The default is [`DefaultStrengthFloor`], which requires a 256-bit AEAD
	/// key and a digest of 256 bits or more. Pass [`NoStrengthFloor`] only
	/// where weaker profiles must remain negotiable.
	///
	/// [`DefaultStrengthFloor`]: crate::transport::handshake::negotiation::DefaultStrengthFloor
	/// [`NoStrengthFloor`]: crate::transport::handshake::negotiation::NoStrengthFloor
	#[must_use]
	pub fn with_strength_policy(mut self, policy: Arc<dyn ProfileStrengthPolicy + Send + Sync>) -> Self {
		self.profiles = ProfilePolicy::with_floor(policy);
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
	///
	/// [`SessionOutcome`]: crate::transport::handshake::receipt::SessionOutcome
	#[must_use]
	pub fn with_session_observer(mut self, observer: Arc<dyn SessionObserver>) -> Self {
		self.session_observer = Some(observer);
		self
	}

	/// Process the ClientHello and build the ServerHandshake message.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server is past `Init`.
	/// - [`HandshakeError::DerError`] -- the ClientHello fails to decode.
	/// - [`HandshakeError::NoSupportedProfiles`] -- no profile is configured.
	/// - [`HandshakeError::NegotiationError`] -- profile or transport negotiation failed.
	/// - [`HandshakeError::MutualAuthRequired`] -- the accept grants budgets,
	///   and mutual authentication is off.
	/// - [`HandshakeError::OctetStringLengthError`] -- the curve's compressed point is not the wire width.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	pub async fn process_client_hello(
		&mut self,
		client_hello_der: impl AsRef<[u8]>,
	) -> Result<ServerHandshake, HandshakeError> {
		let client_hello_der = client_hello_der.as_ref();
		// 1. Validate that the current state is Init.
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Decode the ClientHello message.
		let client_hello = ClientHello::from_der(client_hello_der)?;

		// 3. Negotiate the security profile.
		let offer = client_hello.security_offer.as_ref();
		let selected = self.profiles.choose(&self.supported_profiles, offer)?;
		let security_accept = WireDer::new(SecurityAccept::new(selected.descriptor()))?;

		// 4. Negotiate transport capabilities. A configured authorizer decides
		//    the budget grant and the settlement challenge before the accept
		//    enters the transcript.
		let offer = client_hello.transport_offer.as_ref();
		let local = self.transport_config.as_ref();
		let negotiation = TransportNegotiation { offer, local };
		let authorized = negotiation.authorize(self.transport_authorizer.as_deref()).await?;
		let authorized_accept = authorized.as_ref().map(|authorized| authorized.accept);
		let transport_accept = authorized_accept.map(WireDer::new).transpose()?;

		let challenge = authorized.and_then(|authorized| authorized.challenge);
		let accepted = transport_accept.as_ref().map(WireDer::value);
		let negotiated = offer.zip(accepted);
		let mux = negotiated.map(|(offer, accept)| MuxSettings::for_server(offer, accept));

		// 5. Extract and store the client random.
		let client_random = client_hello.client_random.to_32_byte_array()?;
		self.client_random = Some(client_random);

		// 6. Generate the server random.
		let server_random = generate_nonce::<32>(None)?;

		// 7. Draw the per-handshake ephemeral. Its public half enters the
		//    signed transcript, and its private half waits for the client's
		//    ephemeral in the key exchange.
		let ephemeral = EphemeralSecret::<P::Curve>::random(&mut OsRng);
		let server_ephemeral = ephemeral.public_key().compressed_point()?;
		self.key_schedule.pend(ephemeral)?;

		// 8. Compute the transcript hash. It binds every leg as the bytes the
		//    client receives, so tampering with one invalidates the signature.
		let spki = self
			.server_cert
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let transport_accept_der = transport_accept.as_ref().map(WireDer::der).unwrap_or_default();
		let legs = EciesHandshakeLegs {
			client_hello: client_hello_der,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral,
			spki,
			security_accept_der: security_accept.der(),
			transport_accept_der,
		};
		let mut transcript = Transcript::ecies_handshake(legs);

		let transcript_digest = transcript.seal::<P::Digest>()?;
		let salt = Salt::Randoms(RandomsSalt::new(&client_random, &server_random));
		let terms = Terms::new(selected, mux, transcript_digest, salt);

		// 9. Sign the transcript hash with the key provider.
		let signature_bytes = self.sign_transcript_hash(&transcript_digest).await?;

		// 10. Issue the session receipt. The transcript hash pins it to this
		//     session, and the server signature lets a third party verify it.
		let mutual = self.peer_authentication.requires_certificate();
		let key = self.server_key_provider.as_ref();
		let issuing = IssuedReceipt::issue::<P::Digest>(transcript_digest, accepted, challenge, mutual, key);
		let issued = issuing.await?;

		// 11. Build the ServerHandshake. The artifact has two owners by design:
		//     this copy is DER-encoded into the message and dropped, and the
		//     issued receipt absorbs the client SignerInfo at settlement.
		let session_receipt = issued.as_ref().map(|issued| issued.artifact().clone());
		let server_handshake = ServerHandshake {
			certificate: Certificate::clone(&self.server_cert),
			server_random: OctetString::new(server_random)?,
			server_ephemeral: OctetString::new(server_ephemeral)?,
			signature: OctetString::new(signature_bytes)?,
			security_accept: Some(security_accept),
			client_cert_required: mutual,
			transport_accept,
			session_receipt,
		};

		// 12. Keep what the hello fixed, and transition the state through
		//     ClientHelloReceived to ServerHelloSent.
		self.terms = Some(terms);
		self.issued = issued;
		self.state.transition(ServerHandshakeState::ClientHelloReceived)?;
		self.state.transition(ServerHandshakeState::ServerHelloSent)?;

		Ok(server_handshake)
	}

	/// Process the ClientKeyExchange message: admit the client, open the ECIES
	/// payload, run the ephemeral-ephemeral agreement, derive the handshake
	/// secret, and settle the session receipt. The handshake secret stays
	/// inside the server until completion.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no ServerHandshake was sent.
	/// - [`HandshakeError::MissingClientCertificate`] -- mutual authentication
	///   is on and no certificate came, or a signature came without one.
	/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the client certificate.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the possession signature is missing or malformed.
	/// - [`HandshakeError::SignatureError`] -- the possession signature fails to verify.
	/// - [`HandshakeError::EciesError`] -- the payload fails to decrypt, as it
	///   does under a swapped client certificate.
	/// - [`HandshakeError::InvalidDecryptedPayloadSize`] -- the plaintext is not a session payload.
	/// - [`HandshakeError::InvalidKeySize`] -- the payload's base secret is not 32 bytes.
	/// - [`HandshakeError::ClientRandomMismatchReplay`] -- the payload carries another client random.
	/// - [`HandshakeError::InvalidPublicKey`] -- the client's ephemeral public
	///   key is not a point on the curve.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret or the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the sealed countersignature fails to open.
	/// - [`HandshakeError::CountersignatureMissing`] -- an issued receipt got no countersignature.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused the settlement answer.
	pub async fn process_client_key_exchange(
		&mut self,
		mut client_kex: ClientKeyExchange,
	) -> Result<(), HandshakeError> {
		// 1. Validate that the current state is ServerHelloSent.
		self.validate_expected_state(ServerHandshakeState::ServerHelloSent)?;
		let terms = self.terms.as_ref().ok_or(HandshakeError::InvalidState)?;

		// 2. Build the associated data and the possession proof first, because
		//    admission takes the certificate. A signature with no certificate
		//    binds no certificate bytes, and admission refuses it unverified.
		let offered = client_kex.client_certificate.as_ref();
		let aad = ClientKeyExchange::client_bound_aad(self.aad_domain_tag, offered)?;
		let certificate_der = offered.map(Encode::to_der).transpose()?.unwrap_or_default();
		let encrypted_data = client_kex.encrypted_data.as_bytes();
		let signature = client_kex.client_signature.as_ref().map(OctetString::as_bytes);
		let proof = signature.map(|signature| EciesPossession { signature, encrypted_data, certificate_der });

		// 3. Admit the offered identity. Every validator runs under mutual
		//    authentication, and an offered certificate's proof is verified
		//    under either mode.
		let offered = client_kex.client_certificate.take();
		let admitted = self.peer_authentication.admit(offered, proof, terms)?;

		// 4. Parse the ECIES message, which leads with the client's ephemeral public key.
		let message = <P::EciesMessage as EciesMessageOps>::from_bytes(client_kex.encrypted_data.as_bytes())?;

		// 5. Decrypt the ECIES payload under the associated data. The key
		//    provider runs the static ECDH step, and the AEAD open
		//    authenticates the client ephemeral through the content key.
		let decrypted_payload = self.decrypt_ecies_payload(&message, &aad).await?;

		// 6. Extract the base secret, the client random, and the sealed receipt
		//    countersignature from the decrypted payload.
		let SessionPayload { base, client_random, receipt_ack } =
			decrypted_payload.with(|payload| self.extract_session_data_from_payload(payload))?;

		// 7. Verify that the client random matches the stored value, which prevents replay attacks.
		self.verify_client_random(&client_random)?;

		// 8. Run the ephemeral-ephemeral agreement and derive the handshake
		//    secret. The server ephemeral is taken, so it serves this one
		//    exchange and drops when this function returns.
		let client_ephemeral = PublicKey::<P::Curve>::from_sec1_bytes(message.ephemeral_pubkey())?;
		let server_ephemeral = self.key_schedule.take_pending()?;
		let agreement = Agreement::<P>::new(&base, &client_ephemeral);
		let handshake_secret = agreement.settle(&server_ephemeral, terms.kdf_salt())?;

		// 9. Open and verify the receipt countersignature, and settle.
		//    Settlement is irreversible, so it runs last, after decryption,
		//    replay verification, and the agreement.
		if let Some(issued) = self.issued.take() {
			let sealed_ack = receipt_ack.as_ref();
			let authorizer = self.transport_authorizer.as_deref();
			let observer = self.session_observer.as_deref();
			let settled = issued.settle(sealed_ack, &handshake_secret, terms, &admitted, authorizer, observer);
			self.stored_receipt = Some(settled.await?);
		}

		// 10. Store the handshake secret and the admission.
		self.key_schedule.store(handshake_secret)?;
		self.admitted = Some(admitted);

		// 11. Transition the state to KeyExchangeReceived.
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		Ok(())
	}

	/// The current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The security profile that negotiation selected, from the ClientHello
	/// to completion.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.terms.as_ref().map(|terms| terms.profile().descriptor())
	}

	/// The transcript hash, from the ClientHello to completion.
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.terms.as_ref().map(|terms| *terms.transcript_hash())
	}

	/// The dual-signed session receipt, when the handshake carried budgets,
	/// from the key exchange to completion.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
	}

	async fn sign_transcript_hash(&self, transcript_digest: &[u8; 32]) -> Result<Vec<u8>, HandshakeError> {
		let sig = self.server_key_provider.sign_prehash(transcript_digest).await?;
		Ok(sig.to_vec())
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// This is the single home for ECIES server completion. The trait
	/// implementation delegates here, so driver and test read the session
	/// terms the same way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no key exchange was received.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused a session key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused a derived key.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError> {
		// 1. Validate that the current state is KeyExchangeReceived.
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

		// 2. Take what the handshake agreed. The handshake secret moves out,
		//    so completion is the one derivation from it.
		let secret = self.key_schedule.take_derived()?;
		let terms = self.terms.take().ok_or(HandshakeError::InvalidState)?;
		let peer = self.admitted.take().ok_or(HandshakeError::InvalidState)?;
		let agreed = Agreed::new(terms, secret, self.stored_receipt.take(), peer);

		// 3. Derive the session keys and the epoch-0 rekey materials.
		let session = agreed.complete(SessionKeys::for_server)?;

		// 4. Transition to the complete state, and erase the client random
		//    (CWE-226). The salt wiped with the terms.
		self.state.transition(ServerHandshakeState::Completed)?;
		self.client_random.zeroize();

		Ok(session)
	}

	/// Open the ECIES payload of a key exchange.
	///
	/// The static ECDH step runs through the key provider, so the private key
	/// can stay behind an external boundary. Key derivation and AEAD opening
	/// are the ECIES suite's own, under `aad` as associated data. The plaintext
	/// carries the base secret, so it wipes on drop.
	async fn decrypt_ecies_payload(
		&self,
		message: &P::EciesMessage,
		aad: impl AsRef<[u8]>,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let agreed = self.server_key_provider.key_agreement(message.ephemeral_pubkey()).await?;
		let shared_secret = EcdhSecret::try_from(agreed)?;

		let open = decrypt_with_shared_secret::<P::EciesMessage, P::Kdf, P::AeadCipher>;
		let plaintext = open(message, shared_secret, Some(aad.as_ref()))?;
		Ok(plaintext)
	}

	/// Parse the decrypted DER [`EciesSessionPayload`] into its parts, and
	/// enforce the fixed 32-byte geometry of the base secret.
	fn extract_session_data_from_payload(
		&self,
		decrypted_payload: impl AsRef<[u8]>,
	) -> Result<SessionPayload, HandshakeError> {
		let decrypted_payload = decrypted_payload.as_ref();
		let payload = EciesSessionPayload::from_der(decrypted_payload)
			.map_err(|_| HandshakeError::InvalidDecryptedPayloadSize)?;

		let EciesSessionPayload { base_key, client_random, receipt_ack } = payload;

		// The decoded buffer moves into its wiping wrapper without a copy, and
		// the parse copies it into the fixed-width secret, so no plain array of
		// key material exists on the way (CWE-226).
		let base = BaseSecret::try_from(SecretSlice::from(base_key.into_bytes()))?;
		let client_random = client_random.to_32_byte_array()?;
		Ok(SessionPayload { base, client_random, receipt_ack })
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
}

/// The ECIES key exchange's proof that the key of the offered certificate
/// signed it.
///
/// The signed digest covers the transcript hash, the encrypted payload, and
/// the offered certificate, so the signature binds to one exchange and one
/// identity.
struct EciesPossession<'a> {
	signature: &'a [u8],
	encrypted_data: &'a [u8],
	certificate_der: Vec<u8>,
}

impl<P: HandshakeProvider> PossessionProof<P> for EciesPossession<'_> {
	fn verify(self, key: P::VerifyingKey, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let transcript_hash = terms.transcript_hash();
		let mut signed = Transcript::ecies_client_auth(transcript_hash, self.encrypted_data, &self.certificate_der);
		let digest = signed.seal::<P::Digest>()?;

		let parsed = P::Signature::try_from(self.signature);
		let signature = parsed.map_err(|_| HandshakeError::SignatureVerificationFailed)?;
		signature.verify_prehash(&key, digest)?;
		Ok(())
	}
}

impl<P> ServerHandshakeProtocol for EciesHandshakeServer<P>
where
	P: HandshakeProvider,
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
		self.selected_profile()
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
	use crate::cms::signed_data::SignerInfo;
	use crate::constants::EC_PUBKEY_COMPRESSED_SIZE;
	use crate::crypto::aead::{Aes256Gcm, DecryptContent};
	use crate::crypto::ecies::{decrypt, encrypt, Secp256k1EciesMessage};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::kdf::HkdfSha3_256;
	use crate::crypto::key::Secp256k1KeyProvider;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::SecretKey;
	use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
	use crate::der::asn1::ObjectIdentifier;
	use crate::oids::{HASH_SHA3_384, HASH_SHA3_512};
	use crate::random::{generate_nonce, OsRng};
	use crate::transport::handshake::client::EciesHandshakeClient;
	use crate::transport::handshake::negotiation::{SecurityOffer, TransportAccept};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::HandshakeKeyManager;
	use crate::transport::state::ClientIdentity;
	use crate::TightBeamError;

	type TestClient = EciesHandshakeClient<DefaultCryptoProvider, Secp256k1EciesMessage>;
	type TestServer = EciesHandshakeServer<DefaultCryptoProvider>;

	/// What crossed the wire in one ECIES handshake, plus both orchestrators
	/// after the key exchange.
	struct EciesRun {
		client_hello: Vec<u8>,
		server_handshake: Vec<u8>,
		client_kex: ClientKeyExchange,
		client: TestClient,
		server: TestServer,
	}

	impl EciesRun {
		/// Every cleartext byte the three legs put on the wire.
		fn wire_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
			let client_kex = self.client_kex.to_der()?;
			Ok([self.client_hello.as_slice(), &self.server_handshake, &client_kex].concat())
		}

		/// The salt both sides derive under, read from the recorded cleartext.
		fn recorded_salt(&self) -> Result<Vec<u8>, Box<dyn Error>> {
			let hello = ClientHello::from_der(&self.client_hello)?;
			let handshake = ServerHandshake::from_der(&self.server_handshake)?;
			Ok([hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat())
		}

		/// The transcript hash both sides sealed, recomputed from the
		/// recorded legs the way the protocol defines it.
		fn recorded_transcript_hash(&self) -> Result<[u8; 32], Box<dyn Error>> {
			let handshake = ServerHandshake::from_der(&self.server_handshake)?;
			let server_random = handshake.server_random.to_32_byte_array()?;
			let server_ephemeral = handshake.server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
			let spki = handshake
				.certificate
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes();
			let security_accept_der = handshake.security_accept.as_ref().map(WireDer::der).unwrap_or_default();
			let transport_accept_der = handshake.transport_accept.as_ref().map(WireDer::der).unwrap_or_default();
			let legs = EciesHandshakeLegs {
				client_hello: &self.client_hello,
				server_random: &server_random,
				server_ephemeral: &server_ephemeral,
				spki,
				security_accept_der,
				transport_accept_der,
			};
			Ok(Transcript::ecies_handshake(legs).seal::<Sha3_256>()?)
		}

		/// The observer of this run once it holds `server_identity`'s static
		/// key, with the payload that key opened.
		fn observer(
			&self,
			server_identity: &TestCertificate,
		) -> Result<(StaticKeyObserver, EciesSessionPayload), Box<dyn Error>> {
			let payload = observer_opens_payload(server_identity, &self.client_kex)?;
			let message = Secp256k1EciesMessage::from_bytes(self.client_kex.encrypted_data.as_bytes())?;
			let handshake = ServerHandshake::from_der(&self.server_handshake)?;
			let static_key = SecretKey::from(server_identity.signing_key.to_owned());
			let observer = StaticKeyObserver::new(
				&static_key,
				payload.base_key.as_bytes(),
				message.ephemeral_pubkey(),
				handshake.server_ephemeral.as_bytes(),
				self.recorded_salt()?,
			)?;
			Ok((observer, payload))
		}
	}

	/// Drive `client` and `server` through the three ECIES legs, recording
	/// each message as the wire carries it.
	async fn run_ecies(mut client: TestClient, mut server: TestServer) -> Result<EciesRun, Box<dyn Error>> {
		let client_hello = client.build_client_hello()?.to_der()?;
		let server_handshake = server.process_client_hello(&client_hello).await?.to_der()?;
		let client_kex = client.process_server_handshake(&server_handshake).await?;
		server.process_client_key_exchange(client_kex.to_owned()).await?;
		Ok(EciesRun { client_hello, server_handshake, client_kex, client, server })
	}

	/// An anonymous client that trusts `server_identity`.
	fn anonymous_client(server_identity: &TestCertificate) -> TestClient {
		let validator = DirectTrustValidator::default().with_trust_chain(vec![server_identity.certificate.to_owned()]);
		TestClient::new(None).with_certificate_validator(Arc::new(validator))
	}

	/// A client that trusts `server_identity` and presents `identity`.
	fn identified_client(server_identity: &TestCertificate, identity: &TestCertificate) -> TestClient {
		let provider = into_provider(identity.signing_key.to_owned());
		let manager = Arc::new(HandshakeKeyManager::<DefaultCryptoProvider>::new(provider));
		let client_identity = ClientIdentity::new(Arc::new(identity.certificate.to_owned()), manager);
		let validator = DirectTrustValidator::default().with_trust_chain(vec![server_identity.certificate.to_owned()]);
		TestClient::new_with_identity(None, Some(client_identity)).with_certificate_validator(Arc::new(validator))
	}

	/// A server under `peer_authentication` presenting `server_identity`.
	fn server_with(server_identity: &TestCertificate, peer_authentication: PeerAuthentication) -> TestServer {
		TestServer::new(
			into_provider(server_identity.signing_key.to_owned()),
			Arc::new(server_identity.certificate.to_owned()),
			None,
			peer_authentication,
		)
		.with_supported_profiles(vec![create_default_test_profile()])
	}

	/// The server identity and the two orchestrators of one handshake under
	/// `peer_authentication`. The client presents a fresh identity when the
	/// server demands one.
	struct Parties {
		server_identity: TestCertificate,
		client: TestClient,
		server: TestServer,
	}

	fn parties(peer_authentication: PeerAuthentication) -> Parties {
		let server_identity = create_test_certificate();
		let client = match peer_authentication.requires_certificate() {
			true => identified_client(&server_identity, &create_test_certificate()),
			false => anonymous_client(&server_identity),
		};
		let server = server_with(&server_identity, peer_authentication);
		Parties { server_identity, client, server }
	}

	/// A recorded handshake under `peer_authentication` with both sessions
	/// established.
	struct Established {
		server_identity: TestCertificate,
		run: EciesRun,
		client_session: EstablishedSession,
		server_session: EstablishedSession,
	}

	async fn established(peer_authentication: PeerAuthentication) -> Result<Established, Box<dyn Error>> {
		let Parties { server_identity, client, server, .. } = parties(peer_authentication);
		let mut run = run_ecies(client, server).await?;
		let client_session = run.client.take_established()?;
		let server_session = run.server.take_established()?;
		Ok(Established { server_identity, run, client_session, server_session })
	}

	/// What the observer recovers from a recorded ECIES key exchange with the
	/// server's static key: the payload, exactly as the server decrypts it.
	fn observer_opens_payload(
		server_identity: &TestCertificate,
		client_kex: &ClientKeyExchange,
	) -> Result<EciesSessionPayload, Box<dyn Error>> {
		let static_key = SecretKey::from(server_identity.signing_key.to_owned());
		let message = Secp256k1EciesMessage::from_bytes(client_kex.encrypted_data.as_bytes())?;
		let aad =
			ClientKeyExchange::client_bound_aad(TIGHTBEAM_AAD_DOMAIN_TAG, client_kex.client_certificate.as_ref())?;
		let plaintext = decrypt::<_, _, HkdfSha3_256, Aes256Gcm>(&static_key, &message, Some(&aad))?.to_insecure();
		Ok(EciesSessionPayload::from_der(&plaintext)?)
	}

	/// A passive observer who records the whole session and later obtains the
	/// server's static key still opens the key-exchange payload and reads the
	/// base secret. No traffic key the observer derives from that base and the
	/// recording opens a recorded frame.
	#[tokio::test]
	async fn a_recorded_ecies_session_does_not_open_under_the_server_static_key() -> Result<(), Box<dyn Error>> {
		let Established { server_identity, run, client_session, .. } =
			established(PeerAuthentication::Anonymous).await?;
		let frame = sealed_record(&client_session)?;

		// Positive control: the static key still opens the payload, and the
		// echoed client random proves the open is the real one.
		let (observer, payload) = run.observer(&server_identity)?;
		let hello = ClientHello::from_der(&run.client_hello)?;
		assert_eq!(payload.client_random.as_bytes(), hello.client_random.as_bytes());

		let attempts = observer.record_attempts(&frame)?;
		assert_eq!(attempts.len(), RECORD_ATTEMPTS);
		assert!(attempts
			.iter()
			.all(|attempt| matches!(attempt, Err(TightBeamError::EncryptionError(_)))));
		Ok(())
	}

	/// The same observer, on a budget-bearing session, opens the payload and
	/// finds the receipt acknowledgement sealed. It is not a plaintext
	/// `SignerInfo`, and no acknowledgement key the observer derives opens
	/// it, so the bearer settlement answer stays confidential.
	#[tokio::test]
	async fn the_settlement_answer_is_sealed_from_the_server_static_key() -> Result<(), Box<dyn Error>> {
		let Parties { server_identity, client, server, .. } = parties(mutual_with(ExpiryValidator));
		let client = client
			.with_transport_offer(budget_offer())
			.with_receipt_approver(Arc::new(PayingApprover));
		let server = server
			.with_transport_config(budget_offer())
			.with_transport_authorizer(Arc::new(ChallengingAuthorizer));
		let run = run_ecies(client, server).await?;

		// Positive control: the real server settled the real answer.
		let settled = run.server.session_receipt().and_then(StoredReceipt::ancillary_response);
		assert_eq!(settled.map(OctetString::as_bytes), Some(TEST_ANSWER));

		let (observer, payload) = run.observer(&server_identity)?;
		let sealed = payload
			.receipt_ack
			.ok_or("a budget-bearing payload carries the acknowledgement")?;
		assert!(SignerInfo::from_der(sealed.as_bytes()).is_err());

		let attempts = observer.ack_attempts(&run.recorded_transcript_hash()?, sealed.as_bytes())?;
		assert_eq!(attempts.len(), ACK_ATTEMPTS);
		assert!(attempts
			.iter()
			.all(|attempt| matches!(attempt, Err(HandshakeError::ReceiptAckCipher(_)))));
		Ok(())
	}

	/// The base secret crosses the wire only inside the sealed payload, so no
	/// cleartext leg carries its bytes (CWE-311).
	#[tokio::test]
	async fn the_base_secret_crosses_the_wire_only_sealed() -> Result<(), Box<dyn Error>> {
		let Parties { server_identity, client, server, .. } = parties(PeerAuthentication::Anonymous);
		let run = run_ecies(client, server).await?;

		let payload = observer_opens_payload(&server_identity, &run.client_kex)?;
		assert!(!contains_window(run.wire_bytes()?, payload.base_key.as_bytes()));
		Ok(())
	}

	/// Two handshakes draw two base secrets, so no session shares its key
	/// schedule input with another (CWE-321).
	#[tokio::test]
	async fn two_ecies_handshakes_draw_different_base_secrets() -> Result<(), Box<dyn Error>> {
		let first = established(PeerAuthentication::Anonymous).await?;
		let second = established(PeerAuthentication::Anonymous).await?;

		let first_payload = observer_opens_payload(&first.server_identity, &first.run.client_kex)?;
		let second_payload = observer_opens_payload(&second.server_identity, &second.run.client_kex)?;
		assert_ne!(first_payload.base_key, second_payload.base_key);
		Ok(())
	}

	/// Both sides of an anonymous ECIES handshake derive one key schedule: a
	/// frame the server seals opens on the client.
	#[tokio::test]
	async fn both_sides_derive_the_same_ecies_keys_anonymously() -> Result<(), Box<dyn Error>> {
		let Established { client_session, server_session, .. } = established(PeerAuthentication::Anonymous).await?;

		let to_client = server_session.keys().send().encrypt_next(b"server to client", None)?;
		let opened = client_session.keys().recv().decrypt_content(&to_client)?.to_insecure();
		assert_eq!(opened.as_slice(), b"server to client");
		Ok(())
	}

	/// Both sides of a mutually authenticated ECIES handshake derive one key
	/// schedule: a frame the client seals opens on the server.
	#[tokio::test]
	async fn both_sides_derive_the_same_ecies_keys_under_mutual_authentication() -> Result<(), Box<dyn Error>> {
		let Established { client_session, server_session, .. } = established(mutual_with(ExpiryValidator)).await?;

		let frame = sealed_record(&client_session)?;
		let opened = server_session.keys().recv().decrypt_content(&frame)?.to_insecure();
		assert_eq!(opened.as_slice(), RECORD_PLAINTEXT);
		Ok(())
	}

	/// The server ephemeral private key exists from the ClientHello to the
	/// key exchange, which takes it for the handshake secret. The key
	/// schedule's take is the close, and this unit test reads the variant it
	/// leaves behind.
	#[tokio::test]
	async fn the_server_ephemeral_is_consumed_at_key_exchange() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;
		assert!(matches!(server.key_schedule, KeySchedule::Pending(_)));

		let client_kex = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(client_kex).await?;
		assert!(matches!(server.key_schedule, KeySchedule::Derived(_)));
		Ok(())
	}

	/// Settlement runs between the agreement and the store, so a refused
	/// settlement leaves the key schedule `Consumed`: the agreement took the
	/// server ephemeral and the handshake secret dropped with the refusal.
	#[tokio::test]
	async fn a_refused_settlement_leaves_the_key_schedule_consumed() -> Result<(), Box<dyn Error>> {
		let Parties { client, server, .. } = parties(mutual_with(ExpiryValidator));
		let mut client = client
			.with_transport_offer(budget_offer())
			.with_receipt_approver(Arc::new(PayingApprover));
		let mut server = server
			.with_transport_config(budget_offer())
			.with_transport_authorizer(Arc::new(RefusingAuthorizer));

		let client_hello = client.build_client_hello()?.to_der()?;
		let server_handshake = server.process_client_hello(&client_hello).await?.to_der()?;
		let client_kex = client.process_server_handshake(&server_handshake).await?;
		let refused = server.process_client_key_exchange(client_kex).await;
		assert!(matches!(refused, Err(HandshakeError::SettlementRejected { .. })));
		assert!(matches!(server.key_schedule, KeySchedule::Consumed));
		Ok(())
	}

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
	/// KeyExchangeReceived to Completed.
	#[tokio::test]
	async fn test_server_state_flow() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		assert_eq!(server.state(), ServerHandshakeState::Init);

		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		// The test asserts on the state the call leaves behind, not on the
		// message it returns.
		server.process_client_hello(&client_hello_der).await?;
		assert_eq!(server.state(), ServerHandshakeState::ServerHelloSent);
		assert!(server.client_random.is_some());
		assert!(server.transcript_hash().is_some());

		let client_kex = build_test_client_key_exchange(&server)?;
		server.process_client_key_exchange(client_kex).await?;
		assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
		assert!(matches!(server.key_schedule, KeySchedule::Derived(_)));

		// Complete the handshake, which takes the handshake secret.
		server.take_established()?;
		assert!(server.is_complete());
		assert_eq!(server.state(), ServerHandshakeState::Completed);
		assert!(matches!(server.key_schedule, KeySchedule::Consumed));

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
		assert!(server.take_established().is_err());

		// The client hello advances the state.
		let client_random = generate_nonce::<32>(None)?;
		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;
		// A second client hello fails.
		assert!(server.process_client_hello(&client_hello_der).await.is_err());
		// Completion before the client key exchange fails.
		assert!(server.take_established().is_err());

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
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
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

		let session = server.take_established()?;
		assert!(session.peer().is_none());
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

		let session = server.take_established()?;
		assert!(session.peer().is_none());
		Ok(())
	}

	/// An anonymous server still verifies the possession proof of an offered
	/// identity, so a signature over other material ends the handshake.
	#[tokio::test]
	async fn an_anonymous_server_refuses_a_forged_offered_identity() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_random = generate_nonce::<32>(None)?;

		let client_hello_der = create_test_client_hello(&client_random)?;
		server.process_client_hello(&client_hello_der).await?;

		let client = create_test_certificate();
		let forged_digest = [0u8; 32];

		let client_kex = build_identified_client_key_exchange(&server, &client, Some(forged_digest)).await?;
		let refusal = server.process_client_key_exchange(client_kex).await;

		assert!(matches!(refusal, Err(HandshakeError::SignatureError(_))));
		Ok(())
	}

	/// An offered certificate with no possession signature proves no key, so
	/// the server refuses it rather than treating the client as anonymous.
	#[tokio::test]
	async fn an_offered_certificate_with_no_possession_signature_is_refused() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_hello_der = create_test_client_hello(&generate_nonce::<32>(None)?)?;
		server.process_client_hello(&client_hello_der).await?;

		let client = create_test_certificate();
		let mut client_kex = build_identified_client_key_exchange(&server, &client, None).await?;
		client_kex.client_signature = None;
		let refusal = server.process_client_key_exchange(client_kex).await;

		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A mutual server refuses a key exchange that offers no certificate.
	#[tokio::test]
	async fn a_mutual_server_refuses_a_key_exchange_with_no_certificate() -> Result<(), Box<dyn Error>> {
		let mut server = server_with(&create_test_certificate(), mutual_with(ExpiryValidator));
		let client_hello_der = create_test_client_hello(&generate_nonce::<32>(None)?)?;
		server.process_client_hello(&client_hello_der).await?;

		let client_kex = build_test_client_key_exchange(&server)?;
		let refusal = server.process_client_key_exchange(client_kex).await;

		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
		Ok(())
	}

	/// A possession signature with no certificate names no key to verify it
	/// under, so the server refuses it rather than ignoring it.
	#[tokio::test]
	async fn a_possession_signature_with_no_certificate_is_refused() -> Result<(), Box<dyn Error>> {
		let mut server = TestEciesServerBuilder::new().build()?;
		let client_hello_der = create_test_client_hello(&generate_nonce::<32>(None)?)?;
		server.process_client_hello(&client_hello_der).await?;

		let mut client_kex = build_test_client_key_exchange(&server)?;
		client_kex.client_signature = Some(OctetString::new([0x30u8; 64])?);
		let refusal = server.process_client_key_exchange(client_kex).await;

		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
		Ok(())
	}

	/// An on-path party that swaps the client certificate and re-signs the
	/// possession proof under its own key breaks the AEAD binding, so the key
	/// exchange fails to decrypt rather than misbinding the session to that
	/// certificate (CWE-287, CWE-345).
	#[tokio::test]
	async fn a_swapped_client_certificate_breaks_the_aead_binding() -> Result<(), Box<dyn Error>> {
		// The server runs mutual authentication and accepts any unexpired
		// certificate, so admission cannot be the gate that catches the swap.
		let server_identity = create_test_certificate();
		let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
			into_provider(server_identity.signing_key.to_owned()),
			Arc::new(server_identity.certificate.to_owned()),
			None,
			mutual_with(ExpiryValidator),
		)
		.with_supported_profiles(vec![create_default_test_profile()]);

		// Honest client C trusts the server and presents cert_C.
		let honest = create_test_certificate();
		let provider = into_provider(honest.signing_key.to_owned());
		let manager = Arc::new(HandshakeKeyManager::<DefaultCryptoProvider>::new(provider));
		let identity = ClientIdentity::new(Arc::new(honest.certificate.to_owned()), manager);
		let validator = DirectTrustValidator::default().with_trust_chain(vec![server_identity.certificate.to_owned()]);
		let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new_with_identity(
			None,
			Some(identity),
		)
		.with_certificate_validator(Arc::new(validator));

		// Legs one and two run honestly, and C seals the payload under its own
		// certificate.
		let client_hello = client.build_client_hello()?;
		let server_handshake = server.process_client_hello(&client_hello.to_der()?).await?;
		let mut client_kex = client.process_server_handshake(&server_handshake.to_der()?).await?;

		// The MITM swaps in cert_M and re-signs the possession proof under its
		// own key over the same transcript and encrypted payload.
		let mitm = create_test_certificate();
		let transcript_hash = server.transcript_hash().ok_or(HandshakeError::InvalidState)?;
		let encrypted = client_kex.encrypted_data.as_bytes();
		let mitm_cert_der = mitm.certificate.to_der()?;
		let auth_digest =
			Transcript::ecies_client_auth(&transcript_hash, encrypted, &mitm_cert_der).seal::<Sha3_256>()?;
		let mitm_provider = Secp256k1KeyProvider::from(mitm.signing_key.to_owned());
		let mitm_signature = mitm_provider.sign_prehash(&auth_digest).await?;

		client_kex.client_certificate = Some(mitm.certificate.to_owned());
		client_kex.client_signature = Some(OctetString::new(mitm_signature.to_vec())?);

		let result = server.process_client_key_exchange(client_kex).await;
		assert!(matches!(result, Err(HandshakeError::EciesError(_))));
		Ok(())
	}

	/// A well-formed payload parses into its base secret, its client random,
	/// and an absent acknowledgement.
	#[test]
	fn test_payload_parse_recovers_session_data() -> Result<(), Box<dyn Error>> {
		let server = TestEciesServerBuilder::new().build()?;
		let unanswered = EciesSessionPayload {
			base_key: OctetString::new([3u8; 32])?,
			client_random: OctetString::new([5u8; 32])?,
			receipt_ack: None,
		};

		let payload = server.extract_session_data_from_payload(&unanswered.to_der()?)?;
		assert_eq!(payload.base.as_bytes(), [3u8; 32]);
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

		assert_eq!(server.selected_profile(), Some(native));
		Ok(())
	}

	#[tokio::test]
	async fn a_dealers_choice_server_skips_a_profile_it_does_not_run() -> Result<(), Box<dyn Error>> {
		let native = create_default_test_profile();
		let supported = vec![foreign_profile(HASH_SHA3_512), native];
		let mut server = TestEciesServerBuilder::new().build()?.with_supported_profiles(supported);
		let client_hello_der = create_test_client_hello(&[1u8; 32])?;

		server.process_client_hello(&client_hello_der).await?;

		assert_eq!(server.selected_profile(), Some(native));
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

	/// The multiplexing terms `server` fixed at its ServerHandshake.
	fn negotiated_mux(server: &TestServer) -> Option<MuxSettings> {
		server.terms.as_ref().and_then(Terms::mux)
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
				negotiated_mux(&server),
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
			assert_eq!(negotiated_mux(&server), None);
		}

		// Locally enabled but not offered, the session stays single-flight.
		{
			let transport_offer = TransportOffer::mux(4);
			let mut server = TestEciesServerBuilder::new().build()?.with_transport_config(transport_offer);
			let client_hello_der = create_test_client_hello_with_transport_offer(&[2u8; 32], None)?;
			let response = server.process_client_hello(&client_hello_der).await?;
			assert_eq!(response.transport_accept, None);
			assert_eq!(negotiated_mux(&server), None);
		}

		Ok(())
	}

	/// Build a test ClientKeyExchange with an ECIES-encrypted payload.
	///
	/// The helper reads the server's public key and the stored client random,
	/// then encrypts an [`EciesSessionPayload`] that holds a fresh base secret
	/// and that client random.
	fn build_test_client_key_exchange<P>(server: &EciesHandshakeServer<P>) -> Result<ClientKeyExchange, Box<dyn Error>>
	where
		P: HandshakeProvider,
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
		let base_secret = generate_nonce::<32>(None)?;
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_secret)?,
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
		P: HandshakeProvider,
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
		let base_secret = generate_nonce::<32>(None)?;
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base_secret)?,
			client_random: OctetString::new(stored_client_random)?,
			receipt_ack: None,
		};

		let plaintext = payload.to_der()?;
		let cert_der = client.certificate.to_der()?;
		let aad = ClientKeyExchange::client_bound_aad(server.aad_domain_tag, Some(&client.certificate))?;
		let encrypted_message = encrypt::<_, _, _, Secp256k1EciesMessage, P::Kdf, P::AeadCipher>(
			&server_pubkey,
			&plaintext,
			Some(aad.as_slice()),
			Some(&mut OsRng),
		)?;

		let encrypted_bytes = encrypted_message.to_bytes();
		let transcript_hash = server.transcript_hash().ok_or(HandshakeError::InvalidState)?;
		let auth_digest = match override_digest {
			Some(digest) => digest,
			None => Transcript::ecies_client_auth(&transcript_hash, &encrypted_bytes, &cert_der).seal::<P::Digest>()?,
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

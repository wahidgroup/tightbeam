//! ECIES-based client handshake orchestrator.
//!
//! [`EciesHandshakeClient`] runs the client side of the TightBeam ECIES
//! handshake protocol:
//!
//! 1. Send the ClientHello with the client random and the offers.
//! 2. Verify the ServerHandshake, whose signed transcript carries the server ephemeral public key.
//! 3. Draw the ECIES ephemeral, seal the base secret to the server's static
//!    key, and derive the handshake secret from the base secret and the
//!    ephemeral-ephemeral ECDH.
//! 4. Derive the directional keys from the handshake secret at completion.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, vec::Vec};

use core::marker::PhantomData;

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignedData;
use crate::constants::{EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_AAD_DOMAIN_TAG};
use crate::crypto::aead::SessionKeys;
use crate::crypto::ecies::{EciesMessageOps, EciesSecretKeyOps};
use crate::crypto::profiles::SecurityProfileDesc;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::LowSEncoding;
use crate::crypto::x509::policy::CertificateValidation;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::{Decode, Encode};
use crate::random::{generate_nonce, OsRng};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfilePolicy, ProfileStrengthPolicy, SecurityOffer, TransportOffer,
};
use crate::transport::handshake::orchestrator::{
	Agreed, Agreement, BaseSecret, HandshakeVerifyingKey, Salt, ServerEphemeral, Terms,
};
use crate::transport::handshake::peer::{AdmittedServer, LearnedTrust};
use crate::transport::handshake::primitives::transcript::{EciesHandshakeLegs, Transcript};
use crate::transport::handshake::primitives::RandomsSalt;
use crate::transport::handshake::receipt::{PendingReceipt, ReceiptApprover, StoredReceipt};
use crate::transport::handshake::state::{ClientHandshakeState, ClientStateMachine, Ecies};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::TunneledMessage;
use crate::transport::handshake::{
	Arc, ClientHandshakeProtocol, ClientHello, ClientKeyExchange, EciesSessionPayload, ServerHandshake,
};
use crate::transport::handshake::{EstablishedSession, HandshakeMessage, HandshakeProvider, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};

/// Client-side ECIES handshake orchestrator.
///
/// It is generic over two parameters:
///
/// - `P: HandshakeProvider`, which defines the complete cryptographic suite.
/// - `M`, the curve-specific ECIES message type.
pub struct EciesHandshakeClient<P, M>
where
	P: HandshakeProvider,
{
	state: ClientStateMachine<Ecies>,
	client_random: Option<[u8; 32]>,
	/// The exact DER bytes of the sent `ClientHello`. The transcript binds
	/// them, so a rewritten offer changes the transcript hash (CWE-757).
	client_hello: Option<Vec<u8>>,
	aad_domain_tag: &'static [u8],
	security_offer: Option<SecurityOffer>,
	profiles: ProfilePolicy<P>,
	transport_offer: Option<TransportOffer>,
	trust: Option<LearnedTrust>,
	identity: Option<ClientIdentity<P>>,
	receipt_approver: Option<Arc<dyn ReceiptApprover>>,
	/// What the ServerHandshake fixed, from the key exchange to completion.
	terms: Option<Terms<P>>,
	/// The secret the session derives from, held from the key exchange to
	/// completion, which takes it.
	handshake_secret: Option<HandshakeSecret>,
	stored_receipt: Option<StoredReceipt>,
	/// The server the ServerHandshake named, once the trust admitted it.
	server: Option<AdmittedServer>,
	_phantom_message: PhantomData<M>,
}

impl<P, M> EciesHandshakeClient<P, M>
where
	P: HandshakeProvider,
	M: EciesMessageOps,
{
	/// Create an ECIES handshake client.
	///
	/// `aad_domain_tag` defaults to [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(aad_domain_tag: Option<&'static [u8]>) -> Self {
		Self::new_with_identity(aad_domain_tag, None)
	}

	/// Create an ECIES handshake client that presents `identity`, when one is
	/// given, for mutual authentication.
	pub fn new_with_identity(aad_domain_tag: Option<&'static [u8]>, identity: Option<ClientIdentity<P>>) -> Self {
		Self {
			state: ClientStateMachine::<Ecies>::default(),
			client_random: None,
			client_hello: None,
			aad_domain_tag: aad_domain_tag.unwrap_or(TIGHTBEAM_AAD_DOMAIN_TAG),
			security_offer: None, // No offer = dealer's choice mode
			profiles: ProfilePolicy::new(),
			transport_offer: None,
			trust: None,
			identity,
			receipt_approver: None,
			terms: None,
			handshake_secret: None,
			stored_receipt: None,
			server: None,
			_phantom_message: PhantomData,
		}
	}

	/// Set the validator that admits the certificate the ServerHandshake names.
	#[must_use]
	pub fn with_certificate_validator(mut self, validator: Arc<dyn CertificateValidation>) -> Self {
		self.trust = Some(LearnedTrust { validator });
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
		self.profiles = ProfilePolicy::with_floor(policy);
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

	/// Set the receipt approver that decides whether to countersign a session
	/// receipt and answers its settlement challenge.
	///
	/// Without one the client countersigns a challenge-free receipt, and a
	/// challenge-bearing receipt fails closed and aborts the handshake.
	#[must_use]
	pub fn with_receipt_approver(mut self, approver: Arc<dyn ReceiptApprover>) -> Self {
		self.receipt_approver = Some(approver);
		self
	}

	/// Refuse with [`HandshakeError::InvalidState`] unless the machine is in
	/// `expected`.
	fn validate_expected_state(&self, expected: ClientHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
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

		self.state.transition(ClientHandshakeState::HelloSent)?;
		Ok(client_hello)
	}

	/// Process the ServerHandshake message and build the ClientKeyExchange to
	/// send next.
	///
	/// # Fail closed
	///
	/// A configured certificate validator is mandatory (CWE-295). Expiry alone
	/// authenticates nobody, so a missing validator aborts the handshake.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no ClientHello was sent.
	/// - [`HandshakeError::MissingTrustStore`] -- no certificate validator is set.
	/// - [`HandshakeError::CertificateValidationError`] -- the server certificate fails validation.
	/// - [`HandshakeError::InvalidProfileSelection`] -- the server selected
	///   nothing, or a profile outside the offer.
	/// - [`HandshakeError::NegotiationError`] -- the selected profile is below
	///   the strength floor or unrunnable, or the transport accept is invalid.
	/// - [`HandshakeError::OctetStringLengthError`] -- the server ephemeral is
	///   not a compressed point's width.
	/// - [`HandshakeError::SignatureError`] -- the server signature fails to verify.
	/// - [`HandshakeError::InvalidPublicKey`] -- the signed server ephemeral is not a point on the curve.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the signed server
	///   ephemeral is the server's static key.
	/// - [`HandshakeError::ReceiptMissing`] -- a budget-bearing accept has no signed receipt.
	/// - [`HandshakeError::ReceiptMismatch`] -- the receipt disagrees with the negotiated session.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the receipt fails the server signature check.
	/// - [`HandshakeError::MutualAuthRequired`] -- the server or a receipt
	///   requires a client identity, and none is set.
	/// - [`HandshakeError::ApprovalRefused`] -- the receipt approver refused.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake
	///   secret or the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal the countersignature.
	pub async fn process_server_handshake(
		&mut self,
		server_handshake_der: impl AsRef<[u8]>,
	) -> Result<ClientKeyExchange, HandshakeError> {
		let server_handshake_der = server_handshake_der.as_ref();
		// 1. Validate that the hello was sent.
		self.validate_expected_state(ClientHandshakeState::HelloSent)?;

		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;

		// 2. Transition to ServerHelloReceived.
		self.state.transition(ClientHandshakeState::ServerHelloReceived)?;

		// 3. Decode the server handshake, and admit the certificate it names.
		let ServerHandshake {
			certificate,
			server_random,
			server_ephemeral,
			signature,
			security_accept,
			client_cert_required,
			transport_accept,
			session_receipt,
		} = ServerHandshake::from_der(server_handshake_der)?;
		let trust = self.trust.as_ref().ok_or(HandshakeError::MissingTrustStore)?;
		let server = trust.admit_named(certificate)?;

		// 4. Admit the profile selection.
		let security_accepted = security_accept.as_ref().map(WireDer::value);
		let profile = self.profiles.admit(self.security_offer.as_ref(), security_accepted)?;

		// 5. Admit the transport capability negotiation. An accept that the
		//    client never offered fails closed.
		let transport_accepted = transport_accept.as_ref().map(WireDer::value);
		let mux = MuxSettings::for_client(self.transport_offer.as_ref(), transport_accepted)?;

		// 6. Bind every leg into the transcript as the bytes that arrived, so a
		//    tampered leg changes the hash and fails the signature. The server
		//    ephemeral enters at its fixed width, so another length fails here.
		let server_random = server_random.to_32_byte_array()?;
		let client_hello = self.client_hello.as_deref().ok_or(HandshakeError::InvalidState)?;
		let legs = EciesHandshakeLegs {
			client_hello,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?,
			spki: server.certificate().verifying_key_bytes(),
			security_accept_der: security_accept.as_ref().map(WireDer::der).unwrap_or_default(),
			transport_accept_der: transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};
		let mut transcript = Transcript::ecies_handshake(legs);
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 7. Verify the server signature over the transcript hash.
		let static_key = server.certificate().verifying_key::<P::Curve>()?;
		let verifying_key = P::VerifyingKey::from(static_key);
		let signature = P::Signature::try_from(signature.as_bytes()).map_err(Into::into)?;
		signature.verify_prehash(&verifying_key, transcript_hash)?;

		let salt = Salt::Randoms(RandomsSalt::new(&client_random, &server_random));
		let terms = Terms::new(profile, mux, transcript_hash, salt);

		// 8. Parse the server ephemeral the signature just authenticated,
		//    beside the static key it must differ from.
		let server_ephemeral = static_key.server_ephemeral(server_ephemeral.as_bytes())?;

		// 9. Verify the session receipt against the accept, which fails closed on a mismatch.
		let certificate = server.certificate();
		let pending = PendingReceipt::verify::<P>(session_receipt, transport_accepted, &transcript_hash, certificate)?;

		// 10. Draw the base secret and the ECIES ephemeral, and derive the
		//     handshake secret. Both come from the OS CSPRNG, because the
		//     provider covers the KDF and the AEAD and not entropy.
		let base = BaseSecret::random(None)?;
		let ephemeral = SecretKey::<P::Curve>::random(&mut OsRng);
		let agreement = Agreement::<P>::new(&base, &server_ephemeral);
		let handshake_secret = agreement.settle(&ephemeral, terms.kdf_salt())?;

		// 11. Approve and countersign the receipt, and seal the countersignature under the handshake secret.
		let (sealed_ack, stored_receipt) = match pending {
			Some(pending) => {
				let identity = self.identity.as_ref();
				let approver = self.receipt_approver.as_deref();
				let (sealed, stored) = pending.countersign(approver, identity, &handshake_secret, &terms).await?;
				(Some(sealed), Some(stored))
			}
			None => (None, None),
		};

		// 12. Seal the payload to the server's static key.
		let encrypted_bytes = self.seal_payload(&ephemeral, &base, &client_random, sealed_ack, &static_key)?;

		// 13. Handle mutual authentication. The signature commits to `encrypted_bytes`.
		let proving = self.prepare_client_auth(client_cert_required, &transcript_hash, &encrypted_bytes);
		let (client_certificate, client_signature) = proving.await?;

		// 14. Build the ClientKeyExchange.
		let client_kex = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_bytes)?,
			#[cfg(feature = "x509")]
			client_certificate,
			#[cfg(feature = "x509")]
			client_signature,
		};

		// 15. Keep what the handshake agreed. The admitted server certificate
		//     stays for post-handshake renewals.
		self.terms = Some(terms);
		self.handshake_secret = Some(handshake_secret);
		self.stored_receipt = stored_receipt;
		self.server = Some(server);

		// 16. Advance to KeyExchangeSent. Step 2 entered ServerHelloReceived.
		self.state.transition(ClientHandshakeState::KeyExchangeSent)?;

		Ok(client_kex)
	}

	/// Prepare the client authentication materials when the server requires
	/// them or the client holds an identity.
	///
	/// The signature covers `Digest(transcript_hash || encrypted_data ||
	/// cert_der)`, so it binds to this key exchange and this identity alone.
	/// The result is the optional certificate and the optional signature.
	async fn prepare_client_auth(
		&self,
		client_cert_required: bool,
		transcript_hash: &[u8; 32],
		encrypted_data: impl AsRef<[u8]>,
	) -> Result<(Option<Certificate>, Option<OctetString>), HandshakeError> {
		let encrypted_data = encrypted_data.as_ref();
		let identity = match (&self.identity, client_cert_required) {
			(Some(identity), _) => identity,
			(None, true) => return Err(HandshakeError::MutualAuthRequired),
			(None, false) => return Ok((None, None)),
		};

		let cert = identity.certificate();
		let cert_der = cert.to_der()?;
		let mut auth_transcript = Transcript::ecies_client_auth(transcript_hash, encrypted_data, &cert_der);
		let auth_digest = auth_transcript.seal::<P::Digest>()?;
		let signature_bytes = identity.signing_provider().sign_prehash(&auth_digest).await?;

		let cert = Certificate::clone(cert);
		let signature = OctetString::new(signature_bytes)?;
		Ok((Some(cert), Some(signature)))
	}

	/// The current handshake state.
	pub fn state(&self) -> ClientHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The security profile that negotiation selected, from the server
	/// handshake to completion.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.terms.as_ref().map(|terms| terms.profile().descriptor())
	}

	/// The transcript hash, from the server handshake to completion.
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.terms.as_ref().map(|terms| *terms.transcript_hash())
	}

	/// The negotiated multiplexing settings, if any, from the server handshake
	/// to completion.
	pub fn negotiated_mux(&self) -> Option<MuxSettings> {
		self.terms.as_ref().and_then(Terms::mux)
	}

	/// The dual-signed session receipt, when the handshake carried budgets,
	/// from the server handshake to completion.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}

	/// The admitted server certificate, retained for post-handshake epoch
	/// renewals.
	pub fn peer_certificate(&self) -> Option<&Certificate> {
		self.server.as_ref().map(|server| server.certificate().as_ref())
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
	/// - [`HandshakeError::InvalidState`] -- no key exchange was sent.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused a session key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused a derived key.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ClientHandshakeState::KeyExchangeSent)?;

		// 2. Take what the handshake agreed. The handshake secret moves out,
		//    so completion is the one derivation from it.
		let secret = self.handshake_secret.take().ok_or(HandshakeError::InvalidState)?;
		let terms = self.terms.take().ok_or(HandshakeError::InvalidState)?;
		let server = self.server.clone().ok_or(HandshakeError::InvalidState)?;
		let agreed = Agreed::new(terms, secret, self.stored_receipt.take(), server);

		// 3. Derive the session keys and the epoch-0 rekey materials.
		let session = agreed.complete(SessionKeys::for_client)?;

		// 4. Transition to the Completed state, and erase the client random
		//    (CWE-226). The salt was wiped when the terms dropped.
		self.state.transition(ClientHandshakeState::Completed)?;
		self.client_random.zeroize();

		Ok(session)
	}

	/// Encrypt the session payload to the server's static key under
	/// `ephemeral`, the same key the handshake secret's agreement used.
	///
	/// That one ephemeral `r` serves both key agreements:
	///
	/// - `r·E` with the server ephemeral feeds the handshake secret.
	/// - `r·S` with the static key seals this payload.
	///
	/// The associated data binds the payload to the certificate this client
	/// presents, so it opens only under that certificate.
	fn seal_payload(
		&self,
		ephemeral: &SecretKey<P::Curve>,
		base: &BaseSecret,
		client_random: &[u8; 32],
		sealed_ack: Option<Vec<u8>>,
		static_key: &PublicKey<P::Curve>,
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

		let client_certificate = self.identity.as_ref().map(ClientIdentity::certificate);
		let aad = ClientKeyExchange::client_bound_aad(self.aad_domain_tag, client_certificate)?;
		let encrypted_message = ephemeral.encrypt_to::<M, P::Kdf, P::AeadCipher>(
			static_key,
			plaintext.as_slice(),
			Some(aad.as_slice()),
			&mut OsRng,
		)?;

		Ok(encrypted_message.to_bytes())
	}
}

impl<P, M> ClientHandshakeProtocol for EciesHandshakeClient<P, M>
where
	P: HandshakeProvider,
	M: EciesMessageOps + Send + Sync + 'static,
{
	type Error = HandshakeError;

	fn start<'a>(&'a mut self) -> MaybeSendFuture<'a, Result<HandshakeMessage, Self::Error>> {
		Box::pin(async move {
			// ECIES tunnels its own messages, so the hello travels inside an
			// opaque SignedData that carries no signer.
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
			// ECIES tunnels its messages inside the containers, and the server
			// handshake is read from the bytes it arrived as.
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
		self.selected_profile()
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
	use crate::oids::HASH_SHA3_384;
	use crate::random::generate_nonce;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer};
	use crate::transport::handshake::orchestrator::CompressedPoint;
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::ServerHandshake;

	#[tokio::test]
	async fn test_client_state_flow() -> Result<(), Box<dyn Error>> {
		// Given: a client in the Init state that trusts the test server
		// certificate.
		let test_cert = create_test_certificate();
		let mut client = TestEciesClientBuilder::new()
			.with_trusted_certificate(test_cert.certificate.to_owned())
			.build();
		assert_eq!(client.state(), ClientHandshakeState::Init);

		// When: the client builds its ClientHello.
		let client_hello_der = client.build_client_hello()?.to_der()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent); // Hello sent
		assert!(client.client_random.is_some());

		// And: the server creates a valid ServerHandshake response.
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

		// When: the client processes the server handshake. The test asserts on
		// the state the call leaves behind, not on the message it returns.
		client.process_server_handshake(&server_handshake_der).await?;
		assert_eq!(client.state(), ClientHandshakeState::KeyExchangeSent);
		assert!(client.handshake_secret.is_some());
		assert!(client.transcript_hash().is_some());

		// When: the client completes the handshake, which takes the secret.
		client.take_established()?;

		// Then: the handshake is complete.
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
		// Given: a fresh client in the Init state.
		let mut client = TestEciesClientBuilder::new().build();

		// When: the client processes a server handshake before it builds a
		// ClientHello.
		let result = client.process_server_handshake(&[]).await;
		assert!(result.is_err());

		// When: the client builds its ClientHello.
		let _client_hello = client.build_client_hello()?;
		assert_eq!(client.state(), ClientHandshakeState::HelloSent);

		// When: the client completes before it processes a server handshake.
		let result = client.take_established();
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

	/// A server handshake that selects no profile is refused, with or without
	/// an offer.
	#[tokio::test]
	async fn a_server_handshake_without_a_security_accept_is_refused() -> Result<(), Box<dyn Error>> {
		let test_cert = create_test_certificate();
		let (mut client, hello) = profile_test_client(&test_cert, None)?;
		let signed = signed_server_response(&test_cert, &hello, create_default_test_profile())?;

		let mut unanswered = ServerHandshake::from_der(&signed)?;
		unanswered.security_accept = None;

		let result = client.process_server_handshake(&unanswered.to_der()?).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
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
}

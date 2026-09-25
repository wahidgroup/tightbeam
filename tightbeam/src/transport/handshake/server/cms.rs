//! CMS-based server handshake orchestrator.
//!
//! This module implements the server side of the TightBeam handshake
//! protocol with CMS builders and processors. The orchestrator is generic over
//! `P: CryptoProvider` for its cryptographic operations.

use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::cms::cert::CertificateChoices;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, RecipientInfo};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::aead::{DecryptContent, KeyInit, SessionKeys};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, SecurityProfileDesc};
use crate::crypto::secret::{SecretSlice, ToInsecure};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, Curve, CurveArithmetic, PublicKey};
use crate::crypto::sign::{
	EcdsaSignatureVerifier, LowSEncoding, PrehashVerifier, SignatureAlgorithmIdentifier, Verifier,
};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
use crate::der::asn1::{OctetString, SetOfVec};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode};
use crate::oids::{self, DATA};
use crate::spki::AlgorithmIdentifierOwned;
use crate::spki::EncodePublicKey;
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::attributes::{self, HandshakeAttribute};
use crate::transport::handshake::common::derive_epoch_materials;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::kari::HandshakeKek;
use crate::transport::handshake::kari::{key_wrap_key_size, unwrap_and_verify_with_kek, Kek};
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfileStrengthPolicy, RunnableProfile, SecurityAccept, SecurityOffer, StrengthFloor, TransportAccept,
	TransportAuthorizer, TransportNegotiation, TransportOffer,
};
use crate::transport::handshake::primitives::transcript::{FinishedRole, Transcript};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::ReceiptArtifact;
use crate::transport::handshake::receipt::ReceiptSigner;
use crate::transport::handshake::receipt::{
	record_receipt_outcome, sign_receipt, SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict,
	StoredReceipt,
};
use crate::transport::handshake::state::{Cms, ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::utils::validate_state;
use crate::transport::handshake::utils::HandshakeVerifyingKey;
use crate::transport::handshake::ServerHandshakeProtocol;
use crate::transport::handshake::{AdmittedPeer, EstablishedSession, HandshakeMessage, PeerAuthentication};
use crate::transport::handshake::{HandshakeAlertHandler, HandshakeFinalization, HandshakeNegotiation};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::Certificate;

/// Server-side CMS handshake orchestrator.
///
/// It is generic over `P: CryptoProvider` for its cryptographic operations,
/// and it negotiates the cryptographic profile from the configured
/// `supported_profiles`. The server handshake runs in order:
///
/// 1. Receive and decrypt the KeyExchange (EnvelopedData with KARI).
/// 2. Send the server Finished (SignedData).
/// 3. Receive and verify the client Finished (SignedData).
pub struct CmsHandshakeServer<P>
where
	P: CryptoProvider,
{
	state: ServerStateMachine<Cms>,
	server_key_provider: Arc<dyn SigningKeyProvider>,
	transcript: Transcript,
	session_key: Option<SecretSlice<u8>>,
	supported_profiles: Vec<SecurityProfileDesc>,
	strength_floor: StrengthFloor,
	selected_profile: Option<RunnableProfile<P>>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	transport_accept: Option<TransportAccept>,
	settlement_challenge: Option<OctetString>,
	session_receipt: Option<SessionReceipt>,
	receipt_artifact: Option<SignedData>,
	stored_receipt: Option<StoredReceipt>,
	mux_settings: Option<MuxSettings>,
	peer_authentication: PeerAuthentication,
	admitted: Option<AdmittedPeer>,
	_phantom: PhantomData<P>,
}

impl<P> CmsHandshakeServer<P>
where
	P: CryptoProvider + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey: From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + 'static,
	P::Signature: LowSEncoding + 'static,
	P::Digest: Send + 'static + AssociatedOid,
	P::AeadCipher: KeyInit + 'static,
{
	/// Create a CMS handshake server that authenticates its client as
	/// `peer_authentication` demands.
	pub fn new(server_key_provider: Arc<dyn SigningKeyProvider>, peer_authentication: PeerAuthentication) -> Self {
		Self {
			state: ServerStateMachine::<Cms>::default(),
			server_key_provider,
			transcript: Transcript::new(),
			session_key: None,
			supported_profiles: Vec::new(),
			strength_floor: StrengthFloor::default(),
			selected_profile: None,
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			transport_accept: None,
			settlement_challenge: None,
			session_receipt: None,
			receipt_artifact: None,
			stored_receipt: None,
			mux_settings: None,
			peer_authentication,
			admitted: None,
			_phantom: PhantomData,
		}
	}

	/// Configures supported cryptographic profiles for negotiation.
	///
	/// When profiles are configured, the server selects the first mutually
	/// supported profile from the client's offer. When no profiles are
	/// configured or the client sends no offer, the server uses dealer's
	/// choice.
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

	/// The security profile that negotiation selected.
	///
	/// It is `None` when no negotiation occurred because no profiles are
	/// configured.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile.map(|profile| profile.descriptor())
	}

	/// Validate that the current state matches the expected state.
	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		validate_state(self.state.state(), expected)
	}

	/// Negotiate the security profile from the SecurityOffer in the
	/// EnvelopedData's unprotected attributes.
	///
	/// The steps apply in order:
	///
	/// 1. Convert the `x509_cert` attributes to `HandshakeAttributes`.
	/// 2. Find the SecurityOffer among them.
	/// 3. Negotiate a profile, or apply dealer's choice.
	fn process_security_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		// With no attributes and no configured profiles, negotiation is
		// skipped.
		if unprotected_attrs.is_none() && self.supported_profiles.is_empty() {
			return Ok(());
		}

		let offer = unprotected_attrs.and_then(|attrs| {
			let handshake_attrs = self.convert_to_handshake_attributes(attrs).ok()?;
			let offer_attr = attributes::find(&handshake_attrs, &oids::HANDSHAKE_SECURITY_OFFER).ok()?;

			offer_attr.decode::<SecurityOffer>().ok()
		});

		self.selected_profile = Some(self.negotiate_profile(offer.as_ref())?);

		Ok(())
	}

	/// Process the client's TransportOffer attribute, if present.
	///
	/// Multiplexing activates only when the client offered it and it is
	/// locally enabled. Otherwise the connection stays single-flight. A
	/// configured authorizer decides the budget grant.
	async fn process_transport_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		let offer = unprotected_attrs.and_then(|attrs| {
			let handshake_attrs = self.convert_to_handshake_attributes(attrs).ok()?;
			let offer_attr = attributes::find(&handshake_attrs, &oids::HANDSHAKE_TRANSPORT_OFFER).ok()?;
			offer_attr.decode::<TransportOffer>().ok()
		});

		let local = self.transport_config.as_ref();
		let authorizer = self.transport_authorizer.as_deref();
		let negotiation = TransportNegotiation { offer: offer.as_ref(), local };
		let authorized = negotiation.authorize(authorizer).await?;

		self.transport_accept = authorized.as_ref().map(|authorized| authorized.accept);
		self.settlement_challenge = authorized.and_then(|authorized| authorized.challenge);
		if let (Some(offer), Some(accept)) = (offer.as_ref(), self.transport_accept.as_ref()) {
			self.mux_settings = Some(MuxSettings::for_server(offer, accept));
		}

		Ok(())
	}

	/// Convert `Attributes` to the `HandshakeAttribute` form.
	fn convert_to_handshake_attributes(
		&self,
		attrs: &Attributes,
	) -> Result<Vec<attributes::HandshakeAttribute>, HandshakeError> {
		attrs
			.iter()
			.map(|attr| {
				// HandshakeAttribute owns its value set, and `Attributes` keeps
				// the source.
				Ok(attributes::HandshakeAttribute { attr_type: attr.oid, attr_values: attr.values.clone().into() })
			})
			.collect()
	}

	/// Extract the verifying key of the certificate that MUST verify the
	/// client Finished.
	fn extract_client_verifying_key(admitted: &AdmittedPeer) -> Result<P::VerifyingKey, HandshakeError> {
		let client_cert = admitted.verifier().ok_or(HandshakeError::MissingClientCertificate)?;
		let client_public_key = client_cert.verifying_key::<P::Curve>()?;
		Ok(P::VerifyingKey::from(client_public_key))
	}

	/// The certificate this session records as its peer.
	fn proven_peer(&self) -> Option<Arc<Certificate>> {
		self.admitted.as_ref().and_then(AdmittedPeer::proven).map(Arc::clone)
	}

	/// Compute the signer identifier from the client's verifying key.
	fn compute_client_signer_identifier(
		&self,
		client_verifying_key: &P::VerifyingKey,
	) -> Result<SignerIdentifier, HandshakeError> {
		Ok(compute_signer_identifier(client_verifying_key)?)
	}

	/// Verify the signature of a client Finished and return the transcript
	/// hash that it signed.
	fn verify_client_signature(
		&self,
		signed_data: &SignedData,
		client_verifying_key: P::VerifyingKey,
		expected_sid: SignerIdentifier,
	) -> Result<[u8; 32], HandshakeError> {
		let verifier = EcdsaSignatureVerifier::<P::VerifyingKey, P::Signature, P::Digest>::from_verifying_key_with_sid(
			client_verifying_key,
			expected_sid,
		);

		let processor = TightBeamSignedDataProcessor::new(verifier);
		let digest_oid = P::Digest::OID;
		let verified_content = processor.process(signed_data, &digest_oid)?;
		let expected_hash = self.transcript.hash()?;

		// Content that names the other role is a reflected Finished.
		let signed_hash = FinishedRole::Client
			.transcript_hash(&verified_content)
			.ok_or(HandshakeError::SignatureVerificationFailed)?;
		let transcript_matches: bool = signed_hash.ct_eq(&expected_hash).into();
		if transcript_matches {
			Ok(signed_hash)
		} else {
			Err(HandshakeError::SignatureVerificationFailed)
		}
	}

	/// Decrypt the content of a KARI EnvelopedData addressed to this server.
	///
	/// The decryption runs ECDH through the key provider, unwraps the KEK, and
	/// opens the AEAD. The key exchange and the confidential settlement answer
	/// in the client Finished share it.
	async fn decrypt_enveloped_content(
		&self,
		enveloped_data: &EnvelopedData,
	) -> Result<SecretSlice<u8>, HandshakeError> {
		let kari = enveloped_data
			.recip_infos
			.0
			.iter()
			.find_map(|ri| match ri {
				RecipientInfo::Kari(kari) => Some(kari),
				_ => None,
			})
			.ok_or_else(|| HandshakeError::InvalidClientKeyExchange)?;

		let originator_pub_bytes = match &kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(oipk) => oipk.public_key.raw_bytes(),
			_ => return Err(HandshakeError::InvalidClientKeyExchange),
		};

		// The key provider runs ECDH on the SEC1 bytes directly.
		let shared_secret = self.server_key_provider.key_agreement(originator_pub_bytes).await?;

		// The HKDF-derived KEK is sized to the negotiated key-wrap algorithm.
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let provider = P::default();

		let key_size = key_wrap_key_size::<P>()?;
		let ukm_salt = KdfSalt::new(ukm.as_bytes());
		let kari_label = KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO);
		let kek = shared_secret.derive_kek::<P>(ukm_salt, kari_label, key_size)?;

		// `recipient_enc_keys` is an unauthenticated DER SEQUENCE OF that can
		// decode empty, so index it only after a length check.
		let wrapped_key = kari
			.recipient_enc_keys
			.first()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.enc_key
			.as_bytes();
		let cek = unwrap_and_verify_with_kek(&provider, Kek::new(kek.as_slice()), wrapped_key)?;

		let cipher = cek.with(|cek| {
			P::AeadCipher::new_from_slice(cek).map_err(|_| HandshakeError::InvalidKeySize {
				expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
				received: cek.len(),
			})
		})?;
		Ok(cipher.decrypt_content(&enveloped_data.encrypted_content)?)
	}

	/// Process the KeyExchange message: EnvelopedData with a KARI that carries
	/// the session key.
	///
	/// # Security
	///
	/// The session key stays inside the server and is zeroized on drop. It is
	/// not returned, so key material is never copied out.
	pub async fn process_key_exchange(&mut self, key_exchange: &WireDer<EnvelopedData>) -> Result<(), HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Add the key exchange to the transcript as it arrived
		self.transcript.append(key_exchange.der())?;

		// 3. Transition to received state
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		// 4. Early alert detection (abort before heavy crypto or negotiation)
		let enveloped_data = key_exchange.value();
		self.check_for_alert(enveloped_data.unprotected_attrs.as_ref())?;

		// 5. Process SecurityOffer and perform profile negotiation
		self.process_security_offer(enveloped_data.unprotected_attrs.as_ref())?;

		// 6. Process TransportOffer and negotiate multiplexing
		self.process_transport_offer(enveloped_data.unprotected_attrs.as_ref()).await?;

		// 7. Decrypt and store session key
		self.session_key = Some(self.decrypt_enveloped_content(enveloped_data).await?);

		Ok(())
	}

	/// Validate the prerequisites for building the server Finished message.
	fn validate_server_finished_prerequisites(&self) -> Result<(), HandshakeError> {
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)
	}

	/// Prepare the transcript hash and compute the digest to sign.
	///
	/// The negotiated `SecurityAccept` and `TransportAccept` are appended to
	/// the transcript before hashing so the Finished signature binds both
	/// selections (CWE-345).
	fn prepare_server_finished_digest(&mut self) -> Result<Vec<u8>, HandshakeError> {
		if let Some(profile) = self.selected_profile {
			let accept_bytes = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(profile.descriptor()))?;
			self.transcript.append(accept_bytes)?;
		}
		if let Some(ref accept) = self.transport_accept {
			let accept_bytes = HandshakeAttribute::transcript_bytes(accept)?;
			self.transcript.append(accept_bytes)?;
		}

		let transcript_hash = self.transcript.seal::<P::Digest>()?;
		let content = FinishedRole::Server.content(&transcript_hash);

		// The digest covers the role-bound content that the SignedData
		// carries.
		let mut hasher = P::Digest::new();
		hasher.update(&content);

		let digest = hasher.finalize();
		Ok(digest.to_vec())
	}

	/// Sign the Finished digest with the server key provider.
	async fn sign_server_finished_digest(&self, digest: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let signature_bytes = self.server_key_provider.sign_prehash(digest).await?;
		Ok(signature_bytes)
	}

	/// Build the signer identity and algorithm identifiers for the SignedData.
	async fn build_server_finished_crypto_components(
		&self,
	) -> Result<(SignerIdentifier, AlgorithmIdentifierOwned, AlgorithmIdentifierOwned), HandshakeError> {
		let public_key_bytes = self.server_key_provider.to_public_key_bytes().await?;
		let signer_id = compute_signer_identifier_from_der(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };

		Ok((signer_id, digest_alg, signature_alg))
	}

	/// Build the SecurityAccept, TransportAccept, and session receipt
	/// unsigned attributes for the server Finished.
	///
	/// - The accepts are advisory, like TLS ServerHello extensions before
	///   Finished. The attribute itself is unauthenticated, but tampering
	///   yields a client-side transcript mismatch and the handshake fails
	///   closed.
	/// - The receipt travels as a server-signed `SignedData` artifact, which a
	///   third party can verify on its own.
	fn build_security_accept_attrs(&self) -> Result<Option<Attributes>, HandshakeError> {
		let mut x509_attrs = Vec::new();

		if let Some(profile) = self.selected_profile {
			let accept_attr = HandshakeAttribute::encode(&SecurityAccept::new(profile.descriptor()))?;
			x509_attrs
				.push(Attribute { oid: accept_attr.attr_type, values: SetOfVec::try_from(accept_attr.attr_values)? });
		}
		if let Some(ref accept) = self.transport_accept {
			let accept_attr = HandshakeAttribute::encode(accept)?;
			x509_attrs
				.push(Attribute { oid: accept_attr.attr_type, values: SetOfVec::try_from(accept_attr.attr_values)? });
		}
		if let Some(ref artifact) = self.receipt_artifact {
			let receipt_attr = HandshakeAttribute::encode(artifact)?;
			x509_attrs.push(Attribute {
				oid: receipt_attr.attr_type,
				values: SetOfVec::try_from(receipt_attr.attr_values)?,
			});
		}

		if x509_attrs.is_empty() {
			return Ok(None);
		}

		Ok(Some(Attributes::try_from(x509_attrs)?))
	}

	/// Build the complete SignedData structure.
	fn build_server_signed_data(
		&self,
		transcript_hash: [u8; 32],
		signature_bytes: &[u8],
		signer_id: SignerIdentifier,
		digest_alg: AlgorithmIdentifierOwned,
		signature_alg: AlgorithmIdentifierOwned,
	) -> Result<SignedData, HandshakeError> {
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: signer_id,
			// The same OID lives in SignerInfo and in the SignedData
			// digestAlgorithms SET.
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature_bytes)?,
			unsigned_attrs: self.build_security_accept_attrs()?,
		};

		let octet_string = OctetString::new(FinishedRole::Server.content(&transcript_hash))?;
		let econtent_der = octet_string.to_der()?;
		let econtent_any = Any::from_der(&econtent_der)?;
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent_any) };

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates: None,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		})
	}

	/// Build and sign the [`SessionReceipt`] when the accept grants
	/// budgets.
	///
	/// # Fail closed
	///
	/// Budgets demand a client countersignature, so a budget-bearing accept
	/// without configured mutual authentication aborts the handshake.
	async fn issue_session_receipt(&mut self) -> Result<(), HandshakeError> {
		let Some(accept) = self.transport_accept.as_ref() else {
			return Ok(());
		};
		let Some(granted) = accept.granted_budgets else {
			return Ok(());
		};

		if !self.peer_authentication.requires_certificate() {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let transcript_digest = self.transcript.hash()?;
		let credit_unit = accept.credit_unit;
		let challenge = self.settlement_challenge.take();
		let (receipt, artifact) = sign_receipt::<P::Digest>(
			transcript_digest,
			granted,
			credit_unit,
			challenge,
			self.server_key_provider.as_ref(),
		)
		.await?;

		self.receipt_artifact = Some(artifact);
		self.session_receipt = Some(receipt);

		Ok(())
	}

	/// Complete the handshake and take everything it agreed.
	///
	/// The single home for CMS server completion. The trait implementation
	/// delegates here, so driver and test read the session terms the same way.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the machine has not received the
	///   client Finished, or the negotiated profile is missing.
	/// - [`HandshakeError::CountersignatureMissing`] -- a budget-bearing
	///   receipt has not settled, so the session must not activate.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError>
	where
		P::AeadCipher: KeyInit + 'static,
	{
		// 1. Validate state
		if self.state.state() != ServerHandshakeState::ClientFinishedReceived {
			return Err(HandshakeError::InvalidState);
		}

		// 2. A budget-bearing session activates only after the receipt settled.
		//    This fails closed for a driver that skipped or failed
		//    `process_receipt_ack`.
		if self.receipt_unsettled() {
			return Err(HandshakeError::CountersignatureMissing);
		}

		// 3. Get the CEK (session_key)
		let cek = self.session_key.as_ref().ok_or(HandshakeError::InvalidState)?;

		let transcript = self.transcript.hash()?;
		let ciphers = cek.with(|key_bytes| self.derive_directional_aead(key_bytes, KdfSalt::new(&transcript)))?;

		// 4. Derive the epoch-0 rekey materials alongside the traffic keys,
		//    from the same inputs. An in-band renewal later chains from this
		//    secret without touching the handshake again. CMS salts key
		//    derivation with the transcript hash, so it doubles as the epoch
		//    salt here.
		let epoch_salt = KdfSalt::new(&transcript);
		let materials = cek.with(|input_key| derive_epoch_materials::<P>(input_key, epoch_salt, transcript))?;

		// 5. Transition to complete
		self.state.transition(ServerHandshakeState::Completed)?;

		// 6. Role-map the directional ciphers. The orchestrator is spent, so
		//    the receipt moves out rather than being copied. The client
		//    certificate is already shared, so the session takes a handle to
		//    it.
		#[cfg(feature = "x509")]
		let peer = self.proven_peer();

		let keys = SessionKeys::for_server(ciphers);
		let mux = self.mux_settings;
		let receipt = self.stored_receipt.take().map(Arc::new);
		let epoch = Some(materials);
		Ok(EstablishedSession::new(keys, mux, receipt, peer, epoch))
	}

	/// Build the server Finished message, SignedData over the transcript hash.
	pub async fn build_server_finished(&mut self) -> Result<SignedData, HandshakeError> {
		// 1. Validate state
		self.validate_server_finished_prerequisites()?;

		// 2. Prepare transcript hash and compute digest
		let digest = self.prepare_server_finished_digest()?;

		// 3. Issue the session receipt. The transcript hash pins it to this
		//    session, and the server signature makes it third-party verifiable.
		self.issue_session_receipt().await?;

		// 4. Sign the digest
		let signature_bytes = self.sign_server_finished_digest(&digest).await?;

		// 5. Build cryptographic components
		let (signer_id, digest_alg, signature_alg) = self.build_server_finished_crypto_components().await?;

		// 6. Build SignedData structure
		let transcript_hash = self.transcript.hash()?;
		let signed_data =
			self.build_server_signed_data(transcript_hash, &signature_bytes, signer_id, digest_alg, signature_alg)?;

		// 7. Transition state. The transcript sealed in step 2, so the server
		//    Finished itself is not part of it.
		self.state.transition(ServerHandshakeState::ServerFinishedSent)?;

		Ok(signed_data)
	}

	/// Process the client Finished message, SignedData over the transcript
	/// hash, and return the verified transcript hash.
	pub fn process_client_finished(&mut self, client_finished: &SignedData) -> Result<[u8; 32], HandshakeError> {
		// 1. Validation
		self.validate_expected_state(ServerHandshakeState::ServerFinishedSent)?;

		// 2. Admit the embedded client certificate before use. Under mutual
		//    authentication every validator runs here.
		let offered = client_finished.embedded_certificate();
		let admitted = self.peer_authentication.admit(offered)?;

		// 3. Extract cryptographic material
		let verifying_key = Self::extract_client_verifying_key(&admitted)?;
		let expected_sid = self.compute_client_signer_identifier(&verifying_key)?;

		// 4. Verify signature and content, and only then keep the admission
		let signed_hash = self.verify_client_signature(client_finished, verifying_key, expected_sid)?;
		self.admitted = Some(admitted);

		// 5. Transition state
		self.state.transition(ServerHandshakeState::ClientFinishedReceived)?;

		Ok(signed_hash)
	}

	/// Verify the client's receipt countersignature and settle with the
	/// authorizer.
	///
	/// It does nothing when no receipt was issued. Otherwise it fails closed:
	///
	/// - A missing or invalid countersignature aborts the handshake.
	/// - A settle refusal aborts with the application code.
	///
	/// The completed [`StoredReceipt`] is retained only after both checks
	/// pass.
	pub async fn process_receipt_ack(&mut self, client_finished: &SignedData) -> Result<(), HandshakeError>
	where
		for<'a> P::Signature: TryFrom<&'a [u8]>,
		P::VerifyingKey: PrehashVerifier<P::Signature>,
	{
		// The receipt is taken instead of cloned, because the outcome owns it
		// and its unbounded ancillary challenge. The fail-closed gate in
		// `complete` keys on the negotiated budgets instead of this field.
		let Some(receipt) = self.session_receipt.take() else {
			return Ok(());
		};

		// This is the artifact's single owner from here on. It either
		// completes into the outcome or travels server-signed as it is.
		let server_artifact = self.receipt_artifact.take().ok_or(HandshakeError::InvalidState)?;

		// The acknowledgement arrives as an EnvelopedData encrypted to
		// this server whose plaintext is the client's receipt
		// `SignerInfo`. Its signed attributes bind the settlement answer,
		// which is a bearer secret, so the plaintext wipes when the buffer
		// drops.
		let receipt_ack = match client_finished.receipt_ack_envelope()? {
			Some(envelope) => {
				let envelope = EnvelopedData::from_der(envelope.as_bytes())?;
				let plaintext = self.decrypt_enveloped_content(&envelope).await?.to_insecure();
				Some(SignerInfo::from_der(&plaintext)?)
			}
			None => None,
		};

		let (verdict, ancillary_response) = match receipt_ack.as_ref() {
			None => (SessionVerdict::CountersignatureMissing, None),
			Some(ack) => {
				let client_cert = self.proven_peer().ok_or(HandshakeError::MutualAuthRequired)?;
				let expected_sid = client_cert.signer_identifier::<P::Digest>()?;
				let public_key = client_cert.verifying_key::<P::Curve>()?;
				let verifying_key = P::VerifyingKey::from(public_key);

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

		let countersignature = countersignature.map(OctetString::new).transpose()?;
		let client_certificate = self.proven_peer();
		let outcome = SessionOutcome {
			receipt,
			artifact,
			countersignature,
			ancillary_response,
			client_certificate,
			verdict,
		};

		let stored_receipt = record_receipt_outcome(self.session_observer.as_deref(), outcome).await?;
		self.stored_receipt = Some(stored_receipt);

		Ok(())
	}

	/// Whether a budget-bearing accept has a receipt that never settled.
	///
	/// The check keys on the durable negotiated budgets. Settlement consumes
	/// the receipt itself, whether it succeeds or fails, so the receipt cannot
	/// carry this signal.
	fn receipt_unsettled(&self) -> bool {
		let budget_bearing = self.transport_accept.and_then(|accept| accept.granted_budgets).is_some();
		budget_bearing && self.stored_receipt.is_none()
	}

	/// The current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The secret-wrapped session key bytes, once key exchange sets them.
	pub fn session_key(&self) -> Option<&SecretSlice<u8>> {
		self.session_key.as_ref()
	}

	/// The dual-signed session receipt, when the completed handshake carried
	/// budgets.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}
}

/// What a CMS server reads from a client Finished beyond its signature.
trait ClientFinished {
	/// The enveloped receipt acknowledgement in the SignerInfo unsigned
	/// attributes, as EnvelopedData DER encrypted to this server.
	///
	/// Duplicate attributes fail closed.
	fn receipt_ack_envelope(&self) -> Result<Option<OctetString>, HandshakeError>;

	/// The first X.509 certificate embedded in the `certificates` field, if
	/// any.
	fn embedded_certificate(&self) -> Option<Certificate>;
}

impl ClientFinished for SignedData {
	fn receipt_ack_envelope(&self) -> Result<Option<OctetString>, HandshakeError> {
		let attribute = self.find_unsigned_attr(oids::RECEIPT_ACK)?;
		attribute.map(|attr| attr.decode::<OctetString>()).transpose()
	}

	fn embedded_certificate(&self) -> Option<Certificate> {
		let set = self.certificates.as_ref()?;
		set.0.iter().find_map(|choice| match choice {
			// The caller needs an owned certificate, and the parsed SignedData
			// keeps its copy.
			CertificateChoices::Certificate(cert) => Some(cert.to_owned()),
			CertificateChoices::Other(_) => None,
		})
	}
}

impl<P> HandshakeNegotiation<P> for CmsHandshakeServer<P>
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

impl<P> HandshakeFinalization<P> for CmsHandshakeServer<P>
where
	P: CryptoProvider,
{
	fn selected_profile(&self) -> Option<RunnableProfile<P>> {
		self.selected_profile
	}
}

impl<P> HandshakeAlertHandler for CmsHandshakeServer<P> where P: CryptoProvider {}

impl<P> ServerHandshakeProtocol for CmsHandshakeServer<P>
where
	P: CryptoProvider + Send + Sync + 'static,
	P::Curve: Curve + CurveArithmetic,
	<P::Curve as Curve>::FieldBytesSize: ModulusSize,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	P::VerifyingKey:
		From<PublicKey<P::Curve>> + EncodePublicKey + Verifier<P::Signature> + PrehashVerifier<P::Signature> + 'static,
	for<'a> P::Signature: TryFrom<&'a [u8]>,
	P::Signature: LowSEncoding + 'static,
	P::Digest: Send + 'static,
	P::AeadCipher: Send + Sync + KeyInit + 'static,
{
	type Error = HandshakeError;

	fn handle_request<'a>(
		&'a mut self,
		msg: HandshakeMessage,
	) -> MaybeSendFuture<'a, Result<Option<HandshakeMessage>, Self::Error>> {
		Box::pin(async move {
			// The CMS transcript covers the key exchange as it arrived, so each
			// step reads the container the envelope decoded.
			match self.state() {
				ServerHandshakeState::Init => {
					let key_exchange = msg.enveloped()?;
					self.process_key_exchange(&key_exchange).await?;
					let server_finished = self.build_server_finished().await?;
					Ok(Some(HandshakeMessage::try_from(server_finished)?))
				}
				ServerHandshakeState::ServerFinishedSent => {
					// No response is due. The receipt countersignature verifies
					// and settles before the session can activate.
					let client_finished = msg.signed()?;
					self.process_client_finished(client_finished.value())?;
					self.process_receipt_ack(client_finished.value()).await?;
					Ok(None)
				}
				_ => Err(HandshakeError::InvalidState),
			}
		})
	}

	#[cfg(feature = "aead")]
	fn complete(self: Box<Self>) -> MaybeSendFuture<'static, Result<EstablishedSession, Self::Error>> {
		Box::pin(async move {
			let mut server = self;
			server.take_established()
		})
	}

	fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		self.selected_profile.map(|profile| profile.descriptor())
	}
}

#[cfg(test)]
mod tests {
	mod server {
		use std::error::Error;

		use super::super::*;
		use crate::cms::cert::IssuerAndSerialNumber;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};
		use crate::cms::signed_data::CertificateSet;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::crypto::x509::name::Name;
		use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
		use crate::crypto::x509::serial_number::SerialNumber;
		use crate::der::asn1::ObjectIdentifier;
		use crate::der::Decode;
		use crate::oids::{AES_128_GCM, AES_128_WRAP, HASH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_256};
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
		use crate::transport::envelopes::TransportEnvelope;
		use crate::transport::handshake::builders::{
			TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
		};
		use crate::transport::handshake::tests::*;
		use crate::transport::handshake::utils::compute_transcript_digest;

		const TEST_SESSION_KEY: [u8; 32] = [2u8; 32];

		/// Drive a CMS server to where it awaits the client Finished, and build
		/// the Finished `client` signs over the transcript the server sealed.
		async fn client_finished_for(
			server: &mut CmsHandshakeServer<DefaultCryptoProvider>,
			server_public_key: &PublicKey<k256::Secp256k1>,
			client: &TestCertificate,
		) -> SignedData {
			let key_exchange = build_test_key_exchange(server_public_key, &TEST_SESSION_KEY, []);
			let key_exchange = WireDer::new(key_exchange).expect("the key exchange encodes");
			server
				.process_key_exchange(&key_exchange)
				.await
				.expect("the server accepts the key exchange");
			let server_finished = server.build_server_finished().await.expect("the server builds its Finished");
			let transcript_hash = signed_transcript(&server_finished);

			build_test_client_finished(client, &transcript_hash)
		}

		/// The transcript hash a server Finished signed, read from its content.
		fn signed_transcript(server_finished: &SignedData) -> [u8; 32] {
			let content = server_finished
				.encap_content_info
				.econtent
				.as_ref()
				.expect("a Finished carries content");
			let content = content.decode_as::<OctetString>().expect("the content is an OCTET STRING");

			FinishedRole::Server
				.transcript_hash(content.as_bytes())
				.expect("the content names the server role")
		}

		/// An unprotected attribute the server ignores, told apart by `arc`.
		fn marker_attribute(arc: u32) -> HandshakeAttribute {
			let oid = ObjectIdentifier::new_unwrap("1.2.3.4")
				.push_arc(arc)
				.expect("the arc extends the OID");
			let octets = OctetString::new(arc.to_be_bytes()).expect("four bytes fit an OCTET STRING");
			let value = Any::encode_from(&octets).expect("an OCTET STRING encodes");

			HandshakeAttribute::new_single(oid, value).expect("one value makes an attribute")
		}

		/// The DER of `key_exchange` with its trailing unprotected attributes
		/// swapped out of DER order. It decodes to the same value.
		fn misordered_der(key_exchange: &EnvelopedData) -> Vec<u8> {
			let canonical = key_exchange.to_der().expect("the key exchange encodes");
			let attrs = key_exchange
				.unprotected_attrs
				.as_ref()
				.expect("the key exchange carries attributes");
			let [first, second] = attrs.as_slice() else {
				panic!("the key exchange carries exactly two attributes");
			};

			let first = first.to_der().expect("an attribute encodes");
			let second = second.to_der().expect("an attribute encodes");
			let tail = [first.as_slice(), second.as_slice()].concat();
			let head = canonical
				.strip_suffix(tail.as_slice())
				.expect("the attributes end the encoding");

			[head, second.as_slice(), first.as_slice()].concat()
		}

		/// The key exchange a server reads from `der` sent inside a transport
		/// envelope, decoded the way the transport decodes it.
		fn received_through_envelope(der: &[u8]) -> WireDer<EnvelopedData> {
			let sent = WireDer::<EnvelopedData>::try_from(der).expect("the key exchange decodes");
			let envelope = TransportEnvelope::EnvelopedData(Box::new(sent));
			let wire = envelope.to_der().expect("the envelope encodes");
			let received = TransportEnvelope::from_der(&wire).expect("the envelope decodes");
			let message = HandshakeMessage::try_from(received).expect("the envelope carries a handshake container");

			message.enveloped().expect("the container is the key exchange")
		}

		/// The server moves from Init through KeyExchangeReceived and
		/// ServerFinishedSent to ClientFinishedReceived, and answers the
		/// transcript hash the client signed.
		#[tokio::test]
		async fn test_server_state_flow() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			assert_eq!(server.state(), ServerHandshakeState::Init);

			let key_exchange = WireDer::new(build_test_key_exchange(&server_public_key, &TEST_SESSION_KEY, []))?;
			server.process_key_exchange(&key_exchange).await?;
			assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
			assert!(server.session_key().is_some());

			let server_finished = server.build_server_finished().await?;
			assert_eq!(server.state(), ServerHandshakeState::ServerFinishedSent);

			let transcript_hash = signed_transcript(&server_finished);
			let client_finished = build_test_client_finished(&create_test_certificate(), &transcript_hash);
			let verified = server.process_client_finished(&client_finished)?;
			assert_eq!(verified, transcript_hash);
			assert_eq!(server.state(), ServerHandshakeState::ClientFinishedReceived);

			// The terminal transition belongs to the real completion, which
			// derives the keys, so the machine rests at its last pre-terminal
			// state.
			assert!(!server.is_complete());
			Ok(())
		}

		#[tokio::test]
		async fn test_invalid_state_transitions() -> Result<(), Box<dyn Error>> {
			let (mut server, _) = TestCmsServerBuilder::new().build();
			assert!(server.build_server_finished().await.is_err());
			let client_finished = create_test_signed_data([]);
			assert!(server.process_client_finished(&client_finished).is_err());
			Ok(())
		}

		/// A server that demands no client authentication verifies the Finished
		/// with the offered certificate and records no peer.
		#[cfg(feature = "aead")]
		#[tokio::test]
		async fn an_anonymous_server_records_no_peer() -> Result<(), Box<dyn Error>> {
			let (server, server_public_key) = TestCmsServerBuilder::new().build();
			let mut server = server.with_supported_profiles(vec![create_default_test_profile()]);
			let client = create_test_certificate();
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;
			server.process_client_finished(&client_finished)?;

			let session = server.take_established()?;

			assert!(session.peer().is_none());
			Ok(())
		}

		/// A mutual server records the certificate every validator accepted.
		#[cfg(feature = "aead")]
		#[tokio::test]
		async fn a_mutual_server_records_the_accepted_peer() -> Result<(), Box<dyn Error>> {
			let client = create_test_certificate();
			let pinned = DirectTrustValidator::default().with_trust_chain([client.certificate.to_owned()]);
			let (server, server_public_key) = TestCmsServerBuilder::new()
				.with_peer_authentication(mutual_with(pinned))
				.build();
			let mut server = server.with_supported_profiles(vec![create_default_test_profile()]);
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;
			server.process_client_finished(&client_finished)?;

			let session = server.take_established()?;

			assert_eq!(session.peer(), Some(&client.certificate));
			Ok(())
		}

		/// A mutual server refuses a client Finished whose certificate a
		/// validator refuses. A direct-trust validator with no anchor refuses
		/// every certificate.
		#[tokio::test]
		async fn a_mutual_server_refuses_a_refused_certificate() -> Result<(), Box<dyn Error>> {
			let refusing = DirectTrustValidator::default();
			let (mut server, server_public_key) = TestCmsServerBuilder::new()
				.with_peer_authentication(mutual_with(refusing))
				.build();
			let client = create_test_certificate();
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;

			let refusal = server.process_client_finished(&client_finished);

			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
			Ok(())
		}

		/// The server's own Finished, returned as the client's with the server
		/// certificate attached, fails because each Finished signs its role.
		/// The expiry-only validator accepts the server certificate.
		#[tokio::test]
		async fn a_reflected_server_finished_is_refused() -> Result<(), Box<dyn Error>> {
			let server_identity = create_test_certificate();
			let (mut server, server_public_key) = TestCmsServerBuilder::new()
				.with_key(server_identity.signing_key.to_owned())
				.with_peer_authentication(mutual_with(ExpiryValidator))
				.build();
			let key_exchange = WireDer::new(build_test_key_exchange(&server_public_key, &TEST_SESSION_KEY, []))?;
			server.process_key_exchange(&key_exchange).await?;
			let mut reflected = server.build_server_finished().await?;
			let server_certificate = CertificateChoices::Certificate(server_identity.certificate.to_owned());
			reflected.certificates = Some(CertificateSet(vec![server_certificate].try_into()?));

			let refusal = server.process_client_finished(&reflected);

			assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		/// A key exchange whose attribute SET OF arrives out of DER order
		/// decodes to the same value, and the server binds the bytes that
		/// arrived in the envelope rather than a sorted re-encoding.
		#[tokio::test]
		async fn the_transcript_binds_the_key_exchange_as_it_arrived() -> Result<(), Box<dyn Error>> {
			let (server, server_public_key) = TestCmsServerBuilder::new().build();
			let profile = create_default_test_profile();
			let mut server = server.with_supported_profiles(vec![profile]);
			let attrs = [marker_attribute(1), marker_attribute(2)];
			let sent = misordered_der(&build_test_key_exchange(&server_public_key, &TEST_SESSION_KEY, attrs));
			let key_exchange = received_through_envelope(&sent);
			assert_ne!(key_exchange.value().to_der()?, sent);

			server.process_key_exchange(&key_exchange).await?;
			let server_finished = server.build_server_finished().await?;

			let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(profile))?;
			let expected = compute_transcript_digest::<Sha3_256>([sent, accept].concat())?;
			assert_eq!(signed_transcript(&server_finished), expected);
			Ok(())
		}

		/// Dealer's choice: with no client SecurityOffer, the server picks from
		/// its own list.
		#[tokio::test]
		async fn test_cms_end_to_end_with_profile_negotiation() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let native = create_default_test_profile();
			let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..native };
			server = server.with_supported_profiles(vec![foreign, native]);
			let client = create_test_certificate();
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;

			server.process_client_finished(&client_finished)?;

			assert_eq!(server.selected_profile(), Some(native));
			assert!(server.session_key().is_some());
			Ok(())
		}

		/// Build a test KeyExchange (EnvelopedData) message.
		fn build_test_key_exchange(
			recipient_public_key: &PublicKey<k256::Secp256k1>,
			session_key: &[u8],
			unprotected_attrs: impl IntoIterator<Item = HandshakeAttribute>,
		) -> EnvelopedData {
			let sender_ephemeral = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
			let sender_public = sender_ephemeral.public_key();
			let spki_der = sender_public.to_public_key_der().expect("a public key encodes");
			let sender_pub_spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("the SPKI decodes");

			let ukm_bytes = generate_nonce::<64>(None).expect("the OS random source answers");
			let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec()).expect("64 bytes make a UKM");

			let serial_number = SerialNumber::new(&[0x01]).expect("one byte is a serial number");
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
				issuer: Name::default(),
				serial_number,
			});

			let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_128_WRAP, parameters: None };
			let recipient_pub = *recipient_public_key;
			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(recipient_pub)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);

			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_builder = enveloped_builder.with_unprotected_attrs(unprotected_attrs);
			enveloped_builder
				.build(session_key, None, None)
				.expect("the key exchange builds")
		}

		/// Build a client Finished signed by `client` over `transcript_hash`
		/// that embeds its certificate, as a client with an identity sends it.
		fn build_test_client_finished(client: &TestCertificate, transcript_hash: &[u8; 32]) -> SignedData {
			let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
			let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };
			let signing_key = &client.signing_key;
			let built =
				TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(signing_key, digest_alg, signature_alg);
			let builder = built.expect("the builder accepts a test key");

			let content = FinishedRole::Client.content(transcript_hash);
			let mut signed_data = builder.build(content).expect("the Finished signs");
			let embedded = CertificateChoices::Certificate(client.certificate.to_owned());
			let certificates = vec![embedded].try_into().expect("one certificate fits a set");
			signed_data.certificates = Some(CertificateSet(certificates));
			signed_data
		}
	}
}

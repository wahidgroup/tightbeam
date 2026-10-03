//! CMS-based server handshake orchestrator.
//!
//! [`CmsHandshakeServer`] runs the server side of the TightBeam handshake
//! protocol with CMS builders and processors. The server draws a
//! per-handshake ephemeral at its Finished, carries its public half in the
//! signed transcript, and derives the handshake secret from the client's base
//! secret and the ECDH of that ephemeral with the client's KARI originator.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{borrow::ToOwned, boxed::Box, sync::Arc, vec::Vec};

#[cfg(feature = "std")]
use std::sync::Arc;

use crate::cms::cert::CertificateChoices;
use crate::cms::content_info::CmsVersion;
use crate::cms::enveloped_data::{EnvelopedData, OriginatorIdentifierOrKey, OriginatorPublicKey, RecipientInfo};
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::aead::{DecryptContent, KeyInit, SessionKeys};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{CryptoProvider, DigestProvider, SecurityProfileDesc, SigningProvider};
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::PublicKey;
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Decode, Encode};
use crate::oids::{self, DATA};
use crate::random::OsRng;
use crate::spki::AlgorithmIdentifierOwned;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::kari::{HandshakeKek, Kek, OriginatorKey};
use crate::transport::handshake::negotiation::{
	MuxSettings, ProfilePolicy, ProfileStrengthPolicy, RunnableProfile, SecurityAccept, SecurityOffer, TransportAccept,
	TransportAuthorizer, TransportNegotiation, TransportOffer,
};
use crate::transport::handshake::orchestrator::{Agreed, Agreement, BaseSecret, KeySchedule, Salt, Terms};
use crate::transport::handshake::peer::PossessionProof;
use crate::transport::handshake::primitives::transcript::{FinishedRole, ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::receipt::{IssuedReceipt, SessionObserver, StoredReceipt};
use crate::transport::handshake::state::{Cms, ServerHandshakeState, ServerStateMachine};
use crate::transport::handshake::ServerHandshakeProtocol;
use crate::transport::handshake::{
	AdmittedPeer, EstablishedSession, HandshakeMessage, HandshakeProvider, PeerAuthentication,
};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::Certificate;

/// Server-side CMS handshake orchestrator.
///
/// It is generic over `P: HandshakeProvider` for its cryptographic operations,
/// and it negotiates the cryptographic profile from the configured
/// `supported_profiles`. The server handshake runs in order:
///
/// 1. Receive the KeyExchange (EnvelopedData with KARI), open the base
///    secret, and keep the client's originator key.
/// 2. Draw a per-handshake ephemeral, send the server Finished (SignedData)
///    with its public half in the signed transcript, and derive the
///    handshake secret from the base secret and the ephemeral-ephemeral ECDH.
/// 3. Receive and verify the client Finished (SignedData), and open its sealed receipt countersignature.
pub struct CmsHandshakeServer<P>
where
	P: HandshakeProvider,
{
	state: ServerStateMachine<Cms>,
	server_key_provider: Arc<dyn SigningKeyProvider>,
	transcript: Transcript,
	/// The base secret and the client's originator key from the key exchange
	/// to the server Finished, which takes them, and the handshake secret from
	/// there to completion, which takes that.
	key_schedule: KeySchedule<PendingKeyExchange<P>>,
	supported_profiles: Vec<SecurityProfileDesc>,
	profiles: ProfilePolicy<P>,
	/// The profile the key exchange selected, until the server Finished moves
	/// it into the terms.
	selected_profile: Option<RunnableProfile<P>>,
	transport_config: Option<TransportOffer>,
	transport_authorizer: Option<Arc<dyn TransportAuthorizer>>,
	session_observer: Option<Arc<dyn SessionObserver>>,
	transport_accept: Option<TransportAccept>,
	settlement_challenge: Option<OctetString>,
	/// The multiplexing terms the key exchange negotiated, until the server
	/// Finished moves them into the terms.
	mux_settings: Option<MuxSettings>,
	/// What the key exchange fixed, from the server Finished to completion.
	terms: Option<Terms<P>>,
	/// The receipt of a budget-bearing session, from the server Finished to
	/// the client Finished, which settles it.
	issued: Option<IssuedReceipt>,
	stored_receipt: Option<StoredReceipt>,
	peer_authentication: PeerAuthentication,
	admitted: Option<AdmittedPeer>,
	/// Client certificate the key exchange bound into the transcript, which the
	/// client Finished must embed unchanged.
	client_certificate: Option<Certificate>,
}

/// What the server holds between the key exchange and its Finished.
///
/// The base secret and the client's originator key travel in one value, so
/// one `take` consumes both at the agreement.
struct PendingKeyExchange<P>
where
	P: CryptoProvider,
{
	/// The base secret the key exchange carried.
	base: BaseSecret,
	/// The client's KARI originator key, parsed once at the key exchange.
	peer_ephemeral: PublicKey<P::Curve>,
}

/// Signer identity and algorithm identifiers for a Finished SignedData.
struct FinishedSigner {
	id: SignerIdentifier,
	digest_alg: AlgorithmIdentifierOwned,
	signature_alg: AlgorithmIdentifierOwned,
}

impl<P> CmsHandshakeServer<P>
where
	P: HandshakeProvider,
{
	/// Create a CMS handshake server that authenticates its client as
	/// `peer_authentication` demands.
	pub fn new(server_key_provider: Arc<dyn SigningKeyProvider>, peer_authentication: PeerAuthentication) -> Self {
		Self {
			state: ServerStateMachine::<Cms>::default(),
			server_key_provider,
			transcript: Transcript::new(),
			key_schedule: KeySchedule::Idle,
			supported_profiles: Vec::new(),
			profiles: ProfilePolicy::new(),
			selected_profile: None,
			transport_config: None,
			transport_authorizer: None,
			session_observer: None,
			transport_accept: None,
			settlement_challenge: None,
			mux_settings: None,
			terms: None,
			issued: None,
			stored_receipt: None,
			peer_authentication,
			admitted: None,
			client_certificate: None,
		}
	}

	/// Configures supported cryptographic profiles for negotiation.
	///
	/// - With a client offer, the server selects the first mutually supported profile.
	/// - Without an offer, the server uses dealer's choice over these profiles.
	/// - With no profiles configured, every key exchange fails with [`HandshakeError::NoSupportedProfiles`].
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
	/// Without an authorizer the server grants the request up to its local
	/// configuration ceiling.
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

	/// The security profile that negotiation selected, from the key exchange
	/// to completion.
	pub fn selected_profile(&self) -> Option<SecurityProfileDesc> {
		let fixed = self.terms.as_ref().map(Terms::profile);
		let selected = fixed.or(self.selected_profile);
		selected.map(|profile| profile.descriptor())
	}

	/// Refuse with [`HandshakeError::InvalidState`] unless the machine is in
	/// `expected`.
	fn validate_expected_state(&self, expected: ServerHandshakeState) -> Result<(), HandshakeError> {
		self.state.expect_state(expected)
	}

	/// Negotiate the security profile from the SecurityOffer in the
	/// EnvelopedData's unprotected attributes.
	///
	/// The steps apply in order:
	///
	/// 1. Find the SecurityOffer among the unprotected attributes.
	/// 2. Choose a profile for the offer, or by dealer's choice without one.
	fn process_security_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		// A duplicate or malformed offer attribute fails closed rather than
		// reading as no offer, which would silently fall through to dealer's
		// choice. The client fails closed the same way.
		let offer = match unprotected_attrs {
			Some(attrs) => attrs
				.find_unsigned_attr(oids::HANDSHAKE_SECURITY_OFFER)?
				.map(|attr| attr.decode::<SecurityOffer>())
				.transpose()?,
			None => None,
		};

		let selected = self.profiles.choose(&self.supported_profiles, offer.as_ref())?;
		self.selected_profile = Some(selected);

		Ok(())
	}

	/// Process the client's TransportOffer attribute, if present.
	///
	/// Multiplexing activates only when the client offered it and it is
	/// locally enabled. Otherwise the connection stays single-flight. A
	/// configured authorizer decides the budget grant.
	async fn process_transport_offer(&mut self, unprotected_attrs: Option<&Attributes>) -> Result<(), HandshakeError> {
		// A duplicate or malformed transport offer fails closed, the same as
		// the security offer above.
		let offer = match unprotected_attrs {
			Some(attrs) => attrs
				.find_unsigned_attr(oids::HANDSHAKE_TRANSPORT_OFFER)?
				.map(|attr| attr.decode::<TransportOffer>())
				.transpose()?,
			None => None,
		};

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

	/// Open the key-exchange EnvelopedData addressed to this server.
	///
	/// The static ECDH runs through the key provider, which parses the SEC1
	/// bytes behind its boundary, and the server parses the same bytes once
	/// more as the originator key it pairs with its own ephemeral. The KEK
	/// unwraps the CEK, the AEAD opens the content, and the content parses
	/// as the base secret.
	async fn open_key_exchange(&self, enveloped_data: &EnvelopedData) -> Result<PendingKeyExchange<P>, HandshakeError> {
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

		// A malformed, off-curve, or identity point is refused here, ahead of
		// the agreement.
		let peer_ephemeral = PublicKey::<P::Curve>::from_sec1_bytes(originator_pub_bytes)?;

		let shared_secret = self.server_key_provider.key_agreement(originator_pub_bytes).await?;

		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let provider = P::default();

		let ukm_salt = KdfSalt::new(ukm.as_bytes());
		let kari_label = KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO);
		let kek = shared_secret.derive_kek::<P>(ukm_salt, kari_label)?;

		// `recipient_enc_keys` is an unauthenticated DER SEQUENCE OF that can
		// decode empty, so index it only after a length check.
		let wrapped_key = kari
			.recipient_enc_keys
			.first()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.enc_key
			.as_bytes();

		let cek = Kek::new(kek.as_slice()).unwrap_verified(&provider, wrapped_key)?;
		let cipher = cek.with(|cek| {
			P::AeadCipher::new_from_slice(cek).map_err(|_| HandshakeError::InvalidKeySize {
				expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
				received: cek.len(),
			})
		})?;

		let content = cipher.decrypt_content(&enveloped_data.encrypted_content)?;
		let base = BaseSecret::try_from(content)?;
		Ok(PendingKeyExchange { base, peer_ephemeral })
	}

	/// Process the KeyExchange message: EnvelopedData with a KARI that carries
	/// the base secret.
	///
	/// # Security
	///
	/// The base secret stays inside the server, and it is zeroized on drop. It
	/// is one of the two inputs of the handshake secret.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server is past `Init`.
	/// - [`HandshakeError::AbortReceived`] -- the client sent an abort alert.
	/// - [`HandshakeError::DuplicateAttribute`] -- an offer or certificate attribute repeats.
	/// - [`HandshakeError::NoSupportedProfiles`] -- no profile is configured.
	/// - [`HandshakeError::NegotiationError`] -- profile or transport negotiation failed.
	/// - [`HandshakeError::InvalidClientKeyExchange`] -- the envelope carries no usable KARI.
	/// - [`HandshakeError::InvalidPublicKey`] -- the originator key is not a point on the curve.
	/// - [`HandshakeError::MissingUkm`] -- the KARI carries no UKM.
	/// - [`HandshakeError::AesKeyWrap`] -- the wrapped CEK fails to unwrap.
	/// - [`HandshakeError::InvalidKeySize`] -- the opened content is not a 32-byte base secret.
	pub async fn process_key_exchange(&mut self, key_exchange: &WireDer<EnvelopedData>) -> Result<(), HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ServerHandshakeState::Init)?;

		// 2. Add the key exchange to the transcript as it arrived.
		self.transcript.append(key_exchange.der())?;

		// 3. Transition to the KeyExchangeReceived state.
		self.state.transition(ServerHandshakeState::KeyExchangeReceived)?;

		// 4. Refuse an abort alert before any negotiation or key agreement runs.
		let enveloped_data = key_exchange.value();
		if let Some(attrs) = enveloped_data.unprotected_attrs.as_ref() {
			attrs.refuse_alert()?;
		}

		// 5. Read the SecurityOffer and choose the profile.
		self.process_security_offer(enveloped_data.unprotected_attrs.as_ref())?;

		// 6. Read the TransportOffer and negotiate multiplexing.
		self.process_transport_offer(enveloped_data.unprotected_attrs.as_ref()).await?;

		// 7. Keep the client certificate the key exchange carried. The
		//    transcript binds it, and the client Finished must embed the same
		//    certificate (CWE-287, CWE-345).
		self.client_certificate = Self::extract_client_certificate(enveloped_data.unprotected_attrs.as_ref())?;

		// 8. Open the base secret and keep it with the client's originator key
		//    for the agreement at the server Finished.
		let pending = self.open_key_exchange(enveloped_data).await?;
		self.key_schedule.pend(pending)?;

		Ok(())
	}

	/// The client certificate carried as an unprotected attribute of the key
	/// exchange, if the client presented one.
	fn extract_client_certificate(
		unprotected_attrs: Option<&Attributes>,
	) -> Result<Option<Certificate>, HandshakeError> {
		let Some(attrs) = unprotected_attrs else {
			return Ok(None);
		};

		attrs
			.find_unsigned_attr(oids::CLIENT_CERTIFICATE)?
			.map(|attr| attr.decode::<Certificate>())
			.transpose()
	}

	/// Prepare the transcript hash and compute the digest to sign.
	///
	/// The `SecurityAccept`, the negotiated `TransportAccept`, and the server
	/// ephemeral are appended to the transcript before hashing, so the
	/// Finished signature binds both selections and the ephemeral (CWE-345).
	fn prepare_server_finished_digest(
		&mut self,
		security_accept: &SecurityAccept,
		server_ephemeral: &OriginatorPublicKey,
	) -> Result<Vec<u8>, HandshakeError> {
		let security_accept = HandshakeAttribute::transcript_bytes(security_accept)?;
		let transport_accept = self.transport_accept.as_ref();
		let transport_accept = transport_accept.map(HandshakeAttribute::transcript_bytes).transpose()?;
		let server_ephemeral = HandshakeAttribute::transcript_bytes(server_ephemeral)?;

		let legs = ServerFinishedLegs { security_accept: Some(security_accept), transport_accept, server_ephemeral };
		self.transcript.append_server_finished(legs)?;

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
	async fn build_server_finished_crypto_components(&self) -> Result<FinishedSigner, HandshakeError> {
		let public_key_bytes = self.server_key_provider.to_public_key_bytes().await?;

		let id = compute_signer_identifier_from_der(&public_key_bytes)?;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };
		Ok(FinishedSigner { id, digest_alg, signature_alg })
	}

	/// Build the SecurityAccept, TransportAccept, server ephemeral, and
	/// session receipt unsigned attributes for the server Finished.
	///
	/// - The accepts and the ephemeral are advisory as attributes, like TLS
	///   ServerHello extensions before Finished. The attribute itself is
	///   unauthenticated, but tampering yields a client-side transcript
	///   mismatch and the handshake fails closed.
	/// - The receipt travels as a server-signed `SignedData` artifact, which
	///   a third party can verify on its own.
	fn build_server_finished_attrs(
		&self,
		security_accept: &SecurityAccept,
		server_ephemeral: &OriginatorPublicKey,
		receipt_artifact: Option<&SignedData>,
	) -> Result<Attributes, HandshakeError> {
		let mut x509_attrs = Vec::new();

		let accept_attr = HandshakeAttribute::encode(security_accept)?;
		x509_attrs.push(Attribute::try_from(accept_attr)?);
		if let Some(ref accept) = self.transport_accept {
			let accept_attr = HandshakeAttribute::encode(accept)?;
			x509_attrs.push(Attribute::try_from(accept_attr)?);
		}
		if let Some(artifact) = receipt_artifact {
			let receipt_attr = HandshakeAttribute::encode(artifact)?;
			x509_attrs.push(Attribute::try_from(receipt_attr)?);
		}

		let ephemeral_attr = HandshakeAttribute::encode(server_ephemeral)?;
		x509_attrs.push(Attribute::try_from(ephemeral_attr)?);

		Ok(Attributes::try_from(x509_attrs)?)
	}

	/// Build the Finished SignedData: one SignerInfo over the role-bound
	/// transcript hash, with `unsigned_attrs` attached to that SignerInfo.
	fn build_server_signed_data(
		&self,
		transcript_hash: [u8; 32],
		signature_bytes: &[u8],
		signer: FinishedSigner,
		unsigned_attrs: Attributes,
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
			unsigned_attrs: Some(unsigned_attrs),
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

	/// Complete the handshake and take everything it agreed.
	///
	/// This is the single home for CMS server completion. The trait
	/// implementation delegates here, so driver and test read the session
	/// terms the same way. A budget-bearing session reaches the completable
	/// state only through [`Self::process_client_finished`], which settles its
	/// receipt first.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the machine has not received the
	///   client Finished, or a refused settlement consumed the key schedule.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused a session key length.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused a derived key.
	#[cfg(feature = "aead")]
	pub fn take_established(&mut self) -> Result<EstablishedSession, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ServerHandshakeState::ClientFinishedReceived)?;

		// 2. Take what the handshake agreed. The handshake secret moves out,
		//    so completion is the one derivation from it.
		let secret = self.key_schedule.take_derived()?;
		let terms = self.terms.take().ok_or(HandshakeError::InvalidState)?;
		let peer = self.admitted.take().ok_or(HandshakeError::InvalidState)?;
		let agreed = Agreed::new(terms, secret, self.stored_receipt.take(), peer);

		// 3. Derive the session keys and the epoch-0 rekey materials.
		let session = agreed.complete(SessionKeys::for_server)?;

		// 4. Transition to the Completed state.
		self.state.transition(ServerHandshakeState::Completed)?;

		Ok(session)
	}

	/// Build the server Finished message, SignedData over the transcript hash,
	/// and derive the handshake secret.
	///
	/// The per-handshake ephemeral is a local of this function. Its public
	/// half enters the signed transcript and the Finished attributes, its
	/// agreement with the client's originator key feeds the handshake secret,
	/// and it drops when this function returns on every path.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- no key exchange was received.
	/// - [`HandshakeError::MutualAuthRequired`] -- the accept grants budgets,
	///   and mutual authentication is off.
	/// - [`HandshakeError::KeyError`] -- the signing key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the handshake secret.
	pub async fn build_server_finished(&mut self) -> Result<SignedData, HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ServerHandshakeState::KeyExchangeReceived)?;

		let profile = self.selected_profile.ok_or(HandshakeError::InvalidState)?;

		// 2. Draw the server ephemeral and carry its public half as the
		//    originator key the Finished sends, through the SPKI encoding the
		//    provider's verifying key type gives it.
		let server_ephemeral = EphemeralSecret::<P::Curve>::random(&mut OsRng);
		let server_ephemeral_public = P::VerifyingKey::from(server_ephemeral.public_key());
		let server_ephemeral_key = (&server_ephemeral_public).originator_key()?;

		// 3. Seal the transcript, compute the digest to sign, and fix the terms.
		let security_accept = SecurityAccept::new(profile.descriptor());
		let digest = self.prepare_server_finished_digest(&security_accept, &server_ephemeral_key)?;
		let transcript_hash = self.transcript.hash()?;
		let terms = Terms::new(profile, self.mux_settings, transcript_hash, Salt::TranscriptHash);

		// 4. Issue the session receipt. The transcript hash pins it to this
		//    session, and the server signature makes it third-party verifiable.
		let accept = self.transport_accept.as_ref();
		let challenge = self.settlement_challenge.take();
		let requires_certificate = self.peer_authentication.requires_certificate();
		let key = self.server_key_provider.as_ref();
		let issuing = IssuedReceipt::issue::<P::Digest>(transcript_hash, accept, challenge, requires_certificate, key);
		let issued = issuing.await?;

		// 5. Sign the digest.
		let signature_bytes = self.sign_server_finished_digest(&digest).await?;

		// 6. Build the signer identity and the algorithm identifiers.
		let signer = self.build_server_finished_crypto_components().await?;

		// 7. Build the SignedData structure.
		let receipt_artifact = issued.as_ref().map(IssuedReceipt::artifact);
		let attrs = self.build_server_finished_attrs(&security_accept, &server_ephemeral_key, receipt_artifact)?;
		let signed_data = self.build_server_signed_data(transcript_hash, &signature_bytes, signer, attrs)?;

		// 8. Derive the handshake secret from the base secret and the agreement
		//    of the server ephemeral with the client's originator key.
		let PendingKeyExchange { base, peer_ephemeral } = self.key_schedule.take_pending()?;
		let agreement = Agreement::<P>::new(&base, &peer_ephemeral);
		let handshake_secret = agreement.settle(&server_ephemeral, terms.kdf_salt())?;
		self.key_schedule.store(handshake_secret)?;

		// 9. Move what the key exchange selected into the terms, and transition
		//    the state. The transcript sealed in step 3, so the server Finished
		//    itself is not part of it.
		self.selected_profile = None;
		self.mux_settings = None;
		self.terms = Some(terms);
		self.issued = issued;
		self.state.transition(ServerHandshakeState::ServerFinishedSent)?;

		Ok(signed_data)
	}

	/// Process the client Finished message, SignedData over the transcript
	/// hash: admit the client, settle the session receipt, and return the
	/// verified transcript hash.
	///
	/// # Settlement
	///
	/// An issued receipt settles here, before the state that completion
	/// requires, so no budget-bearing session activates unsettled. The
	/// handshake secret leaves the key schedule for the settlement and returns
	/// only when it succeeds, so a refused settlement leaves nothing to
	/// complete or retry with.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidState`] -- the server Finished was not sent,
	///   or an earlier settlement was refused.
	/// - [`HandshakeError::ClientCertificateMismatch`] -- the embedded
	///   certificate differs from the key-exchange certificate.
	/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the certificate.
	/// - [`HandshakeError::MissingClientCertificate`] -- the Finished embeds no certificate to verify it.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the Finished
	///   signature, the signed transcript hash, or the countersignature is
	///   wrong.
	/// - [`HandshakeError::DuplicateAttribute`] -- the receipt acknowledgement attribute repeats.
	/// - [`HandshakeError::CountersignatureMissing`] -- an issued receipt got no countersignature.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the sealed countersignature fails to open.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused the settlement answer.
	/// - [`HandshakeError::MutualAuthRequired`] -- no client certificate was proven.
	pub async fn process_client_finished(&mut self, client_finished: &SignedData) -> Result<[u8; 32], HandshakeError> {
		// 1. Validate the state.
		self.validate_expected_state(ServerHandshakeState::ServerFinishedSent)?;
		let terms = self.terms.as_ref().ok_or(HandshakeError::InvalidState)?;

		// 2. Refuse a Finished whose signer differs from the certificate the
		//    key exchange bound into the transcript, before admission
		//    (CWE-287, CWE-345).
		let offered = client_finished.embedded_certificate();
		if offered.as_ref() != self.client_certificate.as_ref() {
			return Err(HandshakeError::ClientCertificateMismatch);
		}

		// 3. Admit the embedded client certificate, and verify the Finished
		//    under its key. Under mutual authentication every validator runs
		//    first.
		let proof = CmsFinished(client_finished);
		let admitted = self.peer_authentication.admit(offered, Some(proof), terms)?;

		// 4. Settle the session receipt. Settlement is irreversible, so it runs last.
		let handshake_secret = self.key_schedule.take_derived()?;
		if let Some(issued) = self.issued.take() {
			let sealed_ack = client_finished.sealed_receipt_ack()?;
			let authorizer = self.transport_authorizer.as_deref();
			let observer = self.session_observer.as_deref();
			let settled = issued.settle(sealed_ack, &handshake_secret, terms, &admitted, authorizer, observer);
			self.stored_receipt = Some(settled.await?);
		}

		// 5. Keep the handshake secret and the admission.
		let signed_hash = *terms.transcript_hash();
		self.key_schedule.store(handshake_secret)?;
		self.admitted = Some(admitted);

		// 6. Transition the state.
		self.state.transition(ServerHandshakeState::ClientFinishedReceived)?;

		Ok(signed_hash)
	}

	/// The current handshake state.
	pub fn state(&self) -> ServerHandshakeState {
		self.state.state()
	}

	/// Whether the handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_completed()
	}

	/// The dual-signed session receipt, when the handshake carried budgets,
	/// from the client Finished to completion.
	pub fn session_receipt(&self) -> Option<&StoredReceipt> {
		self.stored_receipt.as_ref()
	}
}

/// The CMS client Finished as the proof that the key of its embedded
/// certificate signed it.
struct CmsFinished<'a>(&'a SignedData);

/// The verifier of a Finished under provider `P`.
type FinishedVerifier<P> = EcdsaSignatureVerifier<
	<P as SigningProvider>::VerifyingKey,
	<P as SigningProvider>::Signature,
	<P as DigestProvider>::Digest,
>;

impl<P: HandshakeProvider> PossessionProof<P> for CmsFinished<'_> {
	/// The Finished verifies when its one signer is the offered key and its
	/// signed content is the client role over the sealed transcript hash.
	/// Content that names the other role is a reflected Finished.
	fn verify(self, key: P::VerifyingKey, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let expected_sid = compute_signer_identifier(&key)?;
		let verifier = FinishedVerifier::<P>::from_verifying_key_with_sid(key, expected_sid);
		let processor = TightBeamSignedDataProcessor::new(verifier);
		let digest_oid = P::Digest::OID;
		let verified_content = processor.process(self.0, &digest_oid)?;
		let signed = FinishedRole::Client.transcript_hash(&verified_content);
		let signed_hash = signed.ok_or(HandshakeError::SignatureVerificationFailed)?;

		let transcript_matches: bool = signed_hash.ct_eq(terms.transcript_hash()).into();
		if !transcript_matches {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		Ok(())
	}
}

/// What a CMS server reads from a client Finished beyond its signature.
trait ClientFinished {
	/// The sealed receipt acknowledgement in the SignerInfo unsigned
	/// attributes, as AEAD ciphertext under the handshake secret's
	/// acknowledgement key.
	///
	/// Duplicate attributes fail closed.
	fn sealed_receipt_ack(&self) -> Result<Option<OctetString>, HandshakeError>;

	/// The first X.509 certificate embedded in the `certificates` field, if
	/// any.
	fn embedded_certificate(&self) -> Option<Certificate>;
}

impl ClientFinished for SignedData {
	fn sealed_receipt_ack(&self) -> Result<Option<OctetString>, HandshakeError> {
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

impl<P> ServerHandshakeProtocol for CmsHandshakeServer<P>
where
	P: HandshakeProvider,
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
					self.process_client_finished(client_finished.value()).await?;
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
		self.selected_profile()
	}
}

#[cfg(test)]
mod tests {
	mod server {
		use std::error::Error;

		use super::super::*;
		use crate::cms::cert::IssuerAndSerialNumber;
		use crate::cms::enveloped_data::{KeyAgreeRecipientIdentifier, RecipientInfos, UserKeyingMaterial};
		use crate::cms::signed_data::CertificateSet;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::secret::ToInsecure;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::crypto::x509::name::Name;
		use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
		use crate::crypto::x509::serial_number::SerialNumber;
		use crate::der::asn1::{BitString, ObjectIdentifier};
		use crate::der::Decode;
		use crate::oids::{
			AES_128_GCM, AES_128_WRAP, HANDSHAKE_SERVER_EPHEMERAL, HASH_SHA3_256, RECEIPT_ACK,
			SIGNER_ECDSA_WITH_SHA3_256,
		};
		use crate::random::{generate_nonce, OsRng};
		use crate::spki::SubjectPublicKeyInfoOwned;
		use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
		use crate::transport::envelopes::TransportEnvelope;
		use crate::transport::handshake::builders::{
			TightBeamEnvelopedDataBuilder, TightBeamKariBuilder, TightBeamSignedDataBuilder,
		};
		use crate::transport::handshake::client::CmsHandshakeClient;
		use crate::transport::handshake::negotiation::NegotiationError;
		use crate::transport::handshake::primitives::transcript::Transcript;
		use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
		use crate::transport::handshake::receipt::StoredReceipt;
		use crate::transport::handshake::tests::*;
		use crate::transport::handshake::{HandshakeAlert, HandshakeKeyManager};
		use crate::transport::state::ClientIdentity;
		use crate::TightBeamError;

		/// The base secret a hand-built test key exchange carries.
		const TEST_BASE_SECRET: [u8; 32] = [2u8; 32];

		/// What crossed the wire in one CMS handshake, plus both orchestrators
		/// after the settled client Finished.
		struct CmsRun {
			key_exchange: WireDer<EnvelopedData>,
			server_finished: SignedData,
			client_finished: SignedData,
			client: CmsHandshakeClient<DefaultCryptoProvider>,
			server: CmsHandshakeServer<DefaultCryptoProvider>,
		}

		impl CmsRun {
			/// Every cleartext byte the three legs put on the wire.
			fn wire_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
				let server_finished = self.server_finished.to_der()?;
				let client_finished = self.client_finished.to_der()?;
				Ok([self.key_exchange.der(), &server_finished, &client_finished].concat())
			}

			/// The observer of this run once it holds `server_identity`'s
			/// static key, with the base secret that key unwrapped.
			fn observer(
				&self,
				server_identity: &TestCertificate,
			) -> Result<(StaticKeyObserver, Vec<u8>), Box<dyn Error>> {
				let base = observer_opens_base(server_identity, &self.key_exchange)?;
				let client_ephemeral = originator_point(self.key_exchange.value())?;
				let server_ephemeral = self
					.server_finished
					.find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?
					.ok_or("the server Finished carries its ephemeral")?
					.decode::<OriginatorPublicKey>()?;

				let static_key = SecretKey::from(server_identity.signing_key.to_owned());
				let observer = StaticKeyObserver::new(
					&static_key,
					&base,
					&client_ephemeral,
					server_ephemeral.public_key.raw_bytes(),
					signed_transcript(&self.server_finished),
				)?;

				Ok((observer, base))
			}
		}

		/// Drive `client` and `server` through the three CMS legs, recording
		/// each message as the wire carries it, and settle the receipt.
		async fn run_cms(
			mut client: CmsHandshakeClient<DefaultCryptoProvider>,
			mut server: CmsHandshakeServer<DefaultCryptoProvider>,
		) -> Result<CmsRun, Box<dyn Error>> {
			let key_exchange = client.build_key_exchange(None)?;
			server.process_key_exchange(&key_exchange).await?;

			let server_finished = server.build_server_finished().await?;
			client.process_server_finished(&server_finished)?;

			let client_finished = client.build_client_finished().await?;
			server.process_client_finished(&client_finished).await?;

			Ok(CmsRun { key_exchange, server_finished, client_finished, client, server })
		}

		/// A client with `identity` pinned to `server_identity`.
		fn identified_client(
			server_identity: &TestCertificate,
			identity: &TestCertificate,
		) -> Result<CmsHandshakeClient<DefaultCryptoProvider>, Box<dyn Error>> {
			let provider = into_provider(identity.signing_key.to_owned());
			let manager = HandshakeKeyManager::<DefaultCryptoProvider>::new(provider);
			let client_identity = ClientIdentity::new(Arc::new(identity.certificate.to_owned()), Arc::new(manager));
			let client = TestCmsClientBuilder::new()
				.with_client_key(identity.signing_key.to_owned())
				.with_server_cert(server_identity.certificate.to_owned())
				.build()?
				.with_client_identity(client_identity);

			Ok(client)
		}

		/// A server under `peer_authentication` holding `server_identity`.
		fn server_with(
			server_identity: &TestCertificate,
			peer_authentication: PeerAuthentication,
		) -> CmsHandshakeServer<DefaultCryptoProvider> {
			let (server, _) = TestCmsServerBuilder::new()
				.with_key(server_identity.signing_key.to_owned())
				.with_peer_authentication(peer_authentication)
				.build();
			server
		}

		/// The two identities and the two orchestrators of one handshake under
		/// `peer_authentication`. A CMS client always presents its identity.
		struct Parties {
			server_identity: TestCertificate,
			client: CmsHandshakeClient<DefaultCryptoProvider>,
			server: CmsHandshakeServer<DefaultCryptoProvider>,
		}

		fn parties(peer_authentication: PeerAuthentication) -> Result<Parties, Box<dyn Error>> {
			let server_identity = create_test_certificate();
			let client_identity = create_test_certificate();
			let client = identified_client(&server_identity, &client_identity)?;
			let server = server_with(&server_identity, peer_authentication);
			Ok(Parties { server_identity, client, server })
		}

		/// A recorded handshake under `peer_authentication` with both sessions
		/// established.
		struct Established {
			server_identity: TestCertificate,
			run: CmsRun,
			client_session: EstablishedSession,
			server_session: EstablishedSession,
		}

		async fn established(peer_authentication: PeerAuthentication) -> Result<Established, Box<dyn Error>> {
			let Parties { server_identity, client, server } = parties(peer_authentication)?;
			let mut run = run_cms(client, server).await?;
			let client_session = run.client.take_established()?;
			let server_session = run.server.take_established()?;
			Ok(Established { server_identity, run, client_session, server_session })
		}

		/// What the observer recovers from a recorded CMS key exchange with
		/// the server's static key: the base secret, through the same KARI
		/// path the server runs.
		fn observer_opens_base(
			server_identity: &TestCertificate,
			key_exchange: &WireDer<EnvelopedData>,
		) -> Result<Vec<u8>, Box<dyn Error>> {
			let static_key = SecretKey::from(server_identity.signing_key.to_owned());
			let recipient = TightBeamKariRecipient::new(DefaultCryptoProvider::default(), static_key);
			let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(recipient);
			Ok(processor.process(key_exchange.value())?.to_insecure().to_vec())
		}

		/// The client's KARI originator key of `key_exchange`, as its SEC1
		/// bytes on the wire.
		fn originator_point(key_exchange: &EnvelopedData) -> Result<Vec<u8>, Box<dyn Error>> {
			let kari = key_exchange
				.recip_infos
				.0
				.iter()
				.find_map(|info| match info {
					RecipientInfo::Kari(kari) => Some(kari),
					_ => None,
				})
				.ok_or("the key exchange carries a KARI")?;
			let OriginatorIdentifierOrKey::OriginatorKey(originator) = &kari.originator else {
				return Err("the KARI carries an originator key".into());
			};

			Ok(originator.public_key.raw_bytes().to_vec())
		}

		/// `key_exchange` with the SEC1 bytes of its KARI originator key
		/// replaced by `point`, as an on-path party would rewrite it.
		fn with_originator_point(key_exchange: EnvelopedData, point: &[u8]) -> Result<EnvelopedData, Box<dyn Error>> {
			let mut infos: Vec<RecipientInfo> = key_exchange.recip_infos.0.iter().cloned().collect();
			let RecipientInfo::Kari(kari) = infos.first_mut().ok_or("the key exchange carries a recipient")? else {
				return Err("the key exchange carries a KARI".into());
			};
			let OriginatorIdentifierOrKey::OriginatorKey(originator) = &mut kari.originator else {
				return Err("the KARI carries an originator key".into());
			};

			originator.public_key = BitString::from_bytes(point)?;
			Ok(EnvelopedData { recip_infos: RecipientInfos::try_from(infos)?, ..key_exchange })
		}

		/// A passive observer who records the whole session and later obtains
		/// the server's static key still unwraps the key exchange and reads the
		/// base secret. No traffic key the observer derives from that base and
		/// the recording opens a recorded frame.
		#[tokio::test]
		async fn a_recorded_cms_session_does_not_open_under_the_server_static_key() -> Result<(), Box<dyn Error>> {
			let Established { server_identity, run, client_session, .. } =
				established(PeerAuthentication::Anonymous).await?;
			let frame = sealed_record(&client_session)?;

			// Positive control: the static key still unwraps the base secret.
			let (observer, base) = run.observer(&server_identity)?;
			assert_eq!(base.len(), 32);

			let attempts = observer.record_attempts(&frame)?;
			assert_eq!(attempts.len(), RECORD_ATTEMPTS);
			assert!(attempts
				.iter()
				.all(|attempt| matches!(attempt, Err(TightBeamError::EncryptionError(_)))));
			Ok(())
		}

		/// The same observer, on a budget-bearing session, reads the receipt
		/// acknowledgement attribute and finds it sealed. It is no envelope to
		/// the static key, and no acknowledgement key the observer derives
		/// opens it, so the bearer settlement answer stays confidential.
		#[tokio::test]
		async fn the_settlement_answer_is_sealed_from_the_server_static_key() -> Result<(), Box<dyn Error>> {
			let Parties { server_identity, client, server } = parties(mutual_with(ExpiryValidator))?;
			let client = client
				.with_transport_offer(budget_offer())
				.with_receipt_approver(Arc::new(PayingApprover));
			let server = server
				.with_transport_config(budget_offer())
				.with_transport_authorizer(Arc::new(ChallengingAuthorizer));
			let run = run_cms(client, server).await?;

			// Positive control: the real server settled the real answer.
			let settled = run.server.session_receipt().and_then(StoredReceipt::ancillary_response);
			assert_eq!(settled.map(OctetString::as_bytes), Some(TEST_ANSWER));

			let sealed = run
				.client_finished
				.find_unsigned_attr(RECEIPT_ACK)?
				.ok_or("a budget-bearing Finished carries the acknowledgement")?
				.decode::<OctetString>()?;
			assert!(EnvelopedData::from_der(sealed.as_bytes()).is_err());

			let (observer, _base) = run.observer(&server_identity)?;
			let attempts = observer.ack_attempts(&signed_transcript(&run.server_finished), sealed.as_bytes())?;
			assert_eq!(attempts.len(), ACK_ATTEMPTS);
			assert!(attempts
				.iter()
				.all(|attempt| matches!(attempt, Err(HandshakeError::ReceiptAckCipher(_)))));
			Ok(())
		}

		/// The base secret crosses the wire only inside the KARI envelope, so
		/// no cleartext leg carries its bytes (CWE-311).
		#[tokio::test]
		async fn the_base_secret_crosses_the_wire_only_sealed() -> Result<(), Box<dyn Error>> {
			let Parties { server_identity, client, server } = parties(PeerAuthentication::Anonymous)?;
			let run = run_cms(client, server).await?;

			let base = observer_opens_base(&server_identity, &run.key_exchange)?;
			assert!(!contains_window(run.wire_bytes()?, &base));
			Ok(())
		}

		/// Two handshakes draw two base secrets, so no session shares its key
		/// schedule input with another (CWE-321).
		#[tokio::test]
		async fn two_cms_handshakes_draw_different_base_secrets() -> Result<(), Box<dyn Error>> {
			let first = established(PeerAuthentication::Anonymous).await?;
			let second = established(PeerAuthentication::Anonymous).await?;

			let first_base = observer_opens_base(&first.server_identity, &first.run.key_exchange)?;
			let second_base = observer_opens_base(&second.server_identity, &second.run.key_exchange)?;
			assert_ne!(first_base, second_base);
			Ok(())
		}

		/// Both sides of a CMS handshake against an anonymous server derive one
		/// key schedule: a frame the server seals opens on the client.
		#[tokio::test]
		async fn both_sides_derive_the_same_cms_keys_anonymously() -> Result<(), Box<dyn Error>> {
			let Established { client_session, server_session, .. } = established(PeerAuthentication::Anonymous).await?;

			let to_client = server_session.keys().send().encrypt_next(b"server to client", None)?;
			let opened = client_session.keys().recv().decrypt_content(&to_client)?.to_insecure();
			assert_eq!(opened.as_slice(), b"server to client");
			Ok(())
		}

		/// Both sides of a mutually authenticated CMS handshake derive one key
		/// schedule: a frame the client seals opens on the server.
		#[tokio::test]
		async fn both_sides_derive_the_same_cms_keys_under_mutual_authentication() -> Result<(), Box<dyn Error>> {
			let Established { client_session, server_session, .. } = established(mutual_with(ExpiryValidator)).await?;

			let frame = sealed_record(&client_session)?;
			let opened = server_session.keys().recv().decrypt_content(&frame)?.to_insecure();
			assert_eq!(opened.as_slice(), RECORD_PLAINTEXT);
			Ok(())
		}

		/// Completion takes the handshake secret, so the orchestrator holds no
		/// key material afterwards. The key schedule's take is the close, and
		/// this unit test reads the variant it leaves behind.
		#[tokio::test]
		async fn completion_consumes_the_handshake_secret() -> Result<(), Box<dyn Error>> {
			let Established { run, .. } = established(PeerAuthentication::Anonymous).await?;
			assert!(matches!(run.server.key_schedule, KeySchedule::Consumed));
			Ok(())
		}

		/// Settlement takes the handshake secret out of the key schedule and
		/// returns it only on success, so a refused settlement leaves the key
		/// schedule `Consumed` and a replayed Finished has nothing to complete
		/// with.
		#[tokio::test]
		async fn a_refused_settlement_leaves_the_key_schedule_consumed() -> Result<(), Box<dyn Error>> {
			let Parties { client, server, .. } = parties(mutual_with(ExpiryValidator))?;
			let client = client.with_transport_offer(budget_offer());
			let mut client = client.with_receipt_approver(Arc::new(PayingApprover));
			let server = server.with_transport_config(budget_offer());
			let mut server = server.with_transport_authorizer(Arc::new(RefusingAuthorizer));

			let key_exchange = client.build_key_exchange(None)?;
			server.process_key_exchange(&key_exchange).await?;

			let server_finished = server.build_server_finished().await?;
			client.process_server_finished(&server_finished)?;

			let client_finished = client.build_client_finished().await?;
			let refused = server.process_client_finished(&client_finished).await;
			assert!(matches!(refused, Err(HandshakeError::SettlementRejected { .. })));
			assert!(matches!(server.key_schedule, KeySchedule::Consumed));
			Ok(())
		}

		/// A KARI originator key whose x-coordinate lies off the curve is
		/// refused at the parse, before the static agreement runs on it.
		#[tokio::test]
		async fn an_off_curve_originator_key_is_refused() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, []);
			let key_exchange = WireDer::new(with_originator_point(key_exchange, &off_curve_point())?)?;

			let refusal = server.process_key_exchange(&key_exchange).await;
			assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
			Ok(())
		}

		/// Drive a CMS server to where it awaits the client Finished, and build
		/// the Finished `client` signs over the transcript the server sealed.
		async fn client_finished_for(
			server: &mut CmsHandshakeServer<DefaultCryptoProvider>,
			server_public_key: &PublicKey<k256::Secp256k1>,
			client: &TestCertificate,
		) -> SignedData {
			// The client binds its certificate into the key-exchange
			// transcript, so the Finished it later embeds matches.
			let cert_attr = client_certificate_attr(&client.certificate);
			let key_exchange = build_test_key_exchange(server_public_key, &TEST_BASE_SECRET, [cert_attr]);
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

		/// The client certificate as the key-exchange unprotected attribute a
		/// client with an identity sends, so a test key exchange binds the same
		/// certificate the Finished embeds.
		fn client_certificate_attr(cert: &Certificate) -> HandshakeAttribute {
			HandshakeAttribute::encode(cert).expect("a certificate encodes")
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

			let client = create_test_certificate();
			let cert_attr = client_certificate_attr(&client.certificate);
			let key_exchange =
				WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [cert_attr]))?;

			server.process_key_exchange(&key_exchange).await?;
			assert_eq!(server.state(), ServerHandshakeState::KeyExchangeReceived);
			assert!(matches!(server.key_schedule, KeySchedule::Pending(_)));

			let server_finished = server.build_server_finished().await?;
			assert_eq!(server.state(), ServerHandshakeState::ServerFinishedSent);

			let transcript_hash = signed_transcript(&server_finished);
			let client_finished = build_test_client_finished(&client, &transcript_hash);
			let verified = server.process_client_finished(&client_finished).await?;
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
			assert!(server.process_client_finished(&client_finished).await.is_err());
			Ok(())
		}

		/// A server that demands no client authentication verifies the Finished
		/// with the offered certificate and records no peer.
		#[cfg(feature = "aead")]
		#[tokio::test]
		async fn an_anonymous_server_records_no_peer() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let client = create_test_certificate();
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;

			server.process_client_finished(&client_finished).await?;

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
			let (mut server, server_public_key) = TestCmsServerBuilder::new()
				.with_peer_authentication(mutual_with(pinned))
				.build();

			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;
			server.process_client_finished(&client_finished).await?;

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

			let refusal = server.process_client_finished(&client_finished).await;
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

			// The reflected Finished embeds the server certificate, so the key
			// exchange binds the same certificate. The refusal is then the role
			// mismatch in the signature, not the certificate-binding check.
			let cert_attr = client_certificate_attr(&server_identity.certificate);
			let key_exchange =
				WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [cert_attr]))?;
			server.process_key_exchange(&key_exchange).await?;

			let mut reflected = server.build_server_finished().await?;
			let server_certificate = CertificateChoices::Certificate(server_identity.certificate.to_owned());

			reflected.certificates = Some(CertificateSet(vec![server_certificate].try_into()?));

			let refusal = server.process_client_finished(&reflected).await;
			assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		/// A mutual server and an honest client after the production key
		/// exchange, which binds the client's certificate into the transcript.
		struct MutualExchange {
			server: CmsHandshakeServer<DefaultCryptoProvider>,
			client: CmsHandshakeClient<DefaultCryptoProvider>,
			server_finished: SignedData,
		}

		/// Run an honest client's key exchange against a mutual server with an
		/// expiry-only validator, up to the server Finished.
		async fn mutual_exchange() -> Result<MutualExchange, Box<dyn Error>> {
			// The production client seals to the server certificate, so the
			// raw public key the builder also returns goes unused.
			let server_identity = create_test_certificate();
			let (mut server, _) = TestCmsServerBuilder::new()
				.with_key(server_identity.signing_key.to_owned())
				.with_peer_authentication(mutual_with(ExpiryValidator))
				.build();

			let honest = create_test_certificate();
			let provider = into_provider(honest.signing_key.to_owned());
			let manager = HandshakeKeyManager::<DefaultCryptoProvider>::new(provider);
			let identity = ClientIdentity::new(Arc::new(honest.certificate.to_owned()), Arc::new(manager));
			let mut client = TestCmsClientBuilder::new()
				.with_client_key(honest.signing_key.to_owned())
				.with_server_cert(server_identity.certificate.to_owned())
				.build()?
				.with_client_identity(identity);

			let key_exchange = client.build_key_exchange(None)?;
			server.process_key_exchange(&key_exchange).await?;

			let server_finished = server.build_server_finished().await?;

			Ok(MutualExchange { server, client, server_finished })
		}

		/// A client Finished signed under a certificate other than the one the
		/// key exchange bound into the transcript is refused, closing the
		/// mutual-authentication misbinding (CWE-287, CWE-345). An on-path
		/// party that forges a Finished over the public transcript holds no
		/// base secret, so only the key-exchange certificate may sign it.
		#[tokio::test]
		async fn a_finished_under_another_certificate_is_refused() -> Result<(), Box<dyn Error>> {
			let mut exchange = mutual_exchange().await?;
			let transcript_hash = signed_transcript(&exchange.server_finished);

			// The MITM forges a Finished over the same transcript under cert_M,
			// which an expiry-only validator would otherwise accept.
			let forger = create_test_certificate();
			let forged = build_test_client_finished(&forger, &transcript_hash);

			let refusal = exchange.server.process_client_finished(&forged).await;
			assert!(matches!(refusal, Err(HandshakeError::ClientCertificateMismatch)));
			Ok(())
		}

		/// The honest client's Finished, signed under the certificate its key
		/// exchange bound, completes the handshake.
		#[tokio::test]
		async fn a_finished_under_the_key_exchange_certificate_is_admitted() -> Result<(), Box<dyn Error>> {
			let mut exchange = mutual_exchange().await?;
			exchange.client.process_server_finished(&exchange.server_finished)?;

			let honest_finished = exchange.client.build_client_finished().await?;
			exchange.server.process_client_finished(&honest_finished).await?;
			Ok(())
		}

		/// A client Finished signed over another transcript hash is refused,
		/// so a Finished from another handshake cannot close this one.
		#[tokio::test]
		async fn a_finished_over_another_transcript_is_refused() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let client = create_test_certificate();
			client_finished_for(&mut server, &server_public_key, &client).await;
			let foreign = build_test_client_finished(&client, &[0x5au8; 32]);

			let refusal = server.process_client_finished(&foreign).await;
			assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		/// A key exchange that carries an abort alert is refused before any
		/// negotiation runs.
		#[tokio::test]
		async fn a_key_exchange_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let code = Any::encode_from(&3u8)?;
			let alert = HandshakeAttribute::new_single(oids::HANDSHAKE_ABORT_ALERT, code)?;
			let key_exchange = WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [alert]))?;

			let refusal = server.process_key_exchange(&key_exchange).await;
			let expected = HandshakeAlert::AlgorithmMismatch;
			assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
			Ok(())
		}

		/// A key exchange whose offer names no profile the server runs is
		/// refused, so the server never falls back to its own choice past an
		/// offer.
		#[tokio::test]
		async fn a_server_refuses_an_offer_that_names_no_profile_it_runs() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() };
			let offer = HandshakeAttribute::encode(&SecurityOffer::new(vec![foreign]))?;
			let key_exchange = WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [offer]))?;

			let refusal = server.process_key_exchange(&key_exchange).await;
			let expected = NegotiationError::NoMutualProfile;
			assert!(matches!(refusal, Err(HandshakeError::NegotiationError(error)) if error == expected));
			Ok(())
		}

		/// A key exchange carrying a duplicate SecurityOffer attribute fails
		/// closed rather than reading as no offer and falling through to
		/// dealer's choice, matching the client's fail-closed behaviour.
		#[tokio::test]
		async fn a_duplicate_security_offer_fails_closed() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();

			let native = create_default_test_profile();
			let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..native };
			let attr1 = HandshakeAttribute::encode(&SecurityOffer::new(vec![native]))?;
			let attr2 = HandshakeAttribute::encode(&SecurityOffer::new(vec![foreign]))?;
			let key_exchange =
				WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [attr1, attr2]))?;

			let result = server.process_key_exchange(&key_exchange).await;
			assert!(matches!(result, Err(HandshakeError::DuplicateAttribute)));
			Ok(())
		}

		/// A key exchange carrying a duplicate TransportOffer attribute fails
		/// closed the same way, rather than reading as no offer and leaving
		/// the connection single-flight.
		#[tokio::test]
		async fn a_duplicate_transport_offer_fails_closed() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();

			let attr1 = HandshakeAttribute::encode(&TransportOffer::mux(4))?;
			let attr2 = HandshakeAttribute::encode(&TransportOffer::mux(8))?;
			let key_exchange =
				WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [attr1, attr2]))?;

			let result = server.process_key_exchange(&key_exchange).await;
			assert!(matches!(result, Err(HandshakeError::DuplicateAttribute)));
			Ok(())
		}

		/// A server with no configured profile refuses the key exchange, so no
		/// handshake proceeds without an agreed profile.
		#[tokio::test]
		async fn a_profile_less_server_refuses_the_key_exchange() -> Result<(), Box<dyn Error>> {
			let (server, server_public_key) = TestCmsServerBuilder::new().build();
			let mut server = server.with_supported_profiles([]);
			let key_exchange = WireDer::new(build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, []))?;

			let refusal = server.process_key_exchange(&key_exchange).await;
			assert!(matches!(refusal, Err(HandshakeError::NoSupportedProfiles)));
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
			let sent = misordered_der(&build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, attrs));
			let key_exchange = received_through_envelope(&sent);
			assert_ne!(key_exchange.value().to_der()?, sent);

			server.process_key_exchange(&key_exchange).await?;
			let server_finished = server.build_server_finished().await?;

			let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(profile))?;
			let ephemeral = server_finished
				.find_unsigned_attr(oids::HANDSHAKE_SERVER_EPHEMERAL)?
				.ok_or("the server Finished carries its ephemeral")?
				.received_bytes()?;

			let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral].concat())?;
			assert_eq!(signed_transcript(&server_finished), expected);
			Ok(())
		}

		/// With no client SecurityOffer, the server picks from its own list by
		/// dealer's choice.
		#[tokio::test]
		async fn test_cms_end_to_end_with_profile_negotiation() -> Result<(), Box<dyn Error>> {
			let (mut server, server_public_key) = TestCmsServerBuilder::new().build();
			let native = create_default_test_profile();
			let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..native };

			server = server.with_supported_profiles(vec![foreign, native]);

			let client = create_test_certificate();
			let client_finished = client_finished_for(&mut server, &server_public_key, &client).await;

			server.process_client_finished(&client_finished).await?;

			assert_eq!(server.selected_profile(), Some(native));
			assert!(matches!(server.key_schedule, KeySchedule::Derived(_)));
			Ok(())
		}

		/// Build a test KeyExchange (EnvelopedData) message carrying `base`.
		fn build_test_key_exchange(
			recipient_public_key: &PublicKey<k256::Secp256k1>,
			base: &[u8],
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
			enveloped_builder.build(base, None).expect("the key exchange builds")
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

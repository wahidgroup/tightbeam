//! The CMS flow.
//!
//! CMS exchanges the three containers themselves. The client encrypts the base
//! secret to the server's static key on the opening, so the server identity is
//! provisioned before the handshake starts.
//!
//! The client's KARI ephemeral `c` serves two agreements:
//!
//! - `c·S` with the server's static key wraps the base secret on the opening.
//! - `c·E` with the server ephemeral feeds the handshake secret.
//!
//! ## Client identity
//!
//! The client Finished embeds the client certificate and signs under its key,
//! so the whole Finished travels sealed under a key of the handshake secret, as
//! an `EncryptedData` (RFC 5652 § 8). The server's static key unwraps the base
//! secret alone, so a recording plus that key reads no byte of the identity.
//! The server's closing runs in this order:
//!
//! 1. It opens the sealed Finished under the handshake secret of the reply.
//! 2. `Offer::new` compares the originator `C` with the key of the embedded certificate.
//! 3. The key-confirmation tag is verified, and then the validity, validator, and possession checks run.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use crate::cms::content_info::CmsVersion;
use crate::cms::encrypted_data::EncryptedData;
use crate::cms::enveloped_data::{
	EncryptedContentInfo, EnvelopedData, KeyAgreeRecipientIdentifier, KeyAgreeRecipientInfo, OriginatorIdentifierOrKey,
	OriginatorPublicKey, RecipientInfo, UserKeyingMaterial,
};
use crate::cms::signed_data::{CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo};
use crate::constants::TIGHTBEAM_KARI_KDF_INFO;
use crate::crypto::aead::{DecryptContent, KeyInit};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::hash::Digest;
use crate::crypto::kdf::EcdhSecret;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::{DigestProvider, SecurityProfile, SigningProvider};
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::{EcdsaSignatureVerifier, SignatureAlgorithmIdentifier};
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::utils::Skid;
use crate::der::asn1::{ObjectIdentifier, OctetString};
use crate::der::oid::AssociatedOid;
use crate::der::{Any, Choice, Decode, DecodeValue, Encode};
use crate::oids::{DATA, RECEIPT_ACK, SIGNED_DATA};
use crate::random::{generate_nonce, CryptoRngCore, RngWrapper};
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::builders::{TightBeamEnvelopedDataBuilder, TightBeamKariBuilder};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientLegs, ClosingBinding, ClosingOpened, ClosingParts, HandshakeFlow, Offer, Opened, OpeningIntake,
	OpeningParts, ProofRequest, ReplyBinding, ReplyIntake, ReplyParts, ServerLegs,
};
use crate::transport::handshake::kari::{Kek, OriginatorKey};
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
use crate::transport::handshake::peer::{AdmittedServer, PeerCertificate, PossessionProof, ProvisionedTrust};
use crate::transport::handshake::primitives::transcript::{FinishedRole, ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::{KdfInfo, KdfSalt};
use crate::transport::handshake::processors::TightBeamSignedDataProcessor;
use crate::transport::handshake::schedule::{
	Agreement, BaseSecret, KeyConfirmation, PeerPoint, Salt, Sealer, SecretSeal, Terms,
};
use crate::transport::handshake::{HandshakeCurve, HandshakeMessage, HandshakeProvider, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::Certificate;

/// The CMS handshake protocol.
///
/// A client is provisioned with [`CmsClientSettings`], and a server with
/// [`CmsServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cms;

impl sealed::Sealed for Cms {}

/// A signature and the public key of its signer, from one key provider. A
/// CMS Finished names its signer by the key identifier of that public key.
pub struct CmsSigned {
	/// The signature bytes, as the provider encodes them.
	signature: Vec<u8>,
	/// The DER SubjectPublicKeyInfo of the key that signed.
	signer_spki: Vec<u8>,
}

impl HandshakeFlow for Cms {
	type Signed = CmsSigned;

	fn sign<'a>(
		key: &'a dyn SigningKeyProvider,
		prehash: &'a [u8],
	) -> MaybeSendFuture<'a, Result<Self::Signed, HandshakeError>> {
		Box::pin(async move {
			let signature = key.sign_prehash(prehash).await?;
			let signer_spki = key.to_public_key_bytes().await?;
			Ok(CmsSigned { signature, signer_spki })
		})
	}
}

/// What a CMS client is provisioned with.
///
/// A CMS client signs its Finished, and the server verifies that signature
/// under the certificate the Finished embeds, so the identity is mandatory.
pub struct CmsClientSettings<P: HandshakeProvider> {
	/// The provisioned server identity, beside the store that admits it.
	pub trust: ProvisionedTrust,
	/// The identity the client presents and signs its Finished under.
	pub identity: ClientIdentity<P>,
}

/// What a CMS client keeps from its key exchange to read the reply against.
pub struct CmsOpening<C: HandshakeCurve> {
	/// The transcript, open over the key exchange as it was sent.
	transcript: Transcript,
	/// The server the key exchange encrypted to.
	server: AdmittedServer<C>,
}

/// The secrets a CMS client holds from its key exchange to the agreement.
pub struct CmsPending<C: HandshakeCurve> {
	/// The base secret the key exchange carried to the server.
	base: BaseSecret,
	/// The KARI ephemeral `c`, kept for the agreement with the server
	/// ephemeral.
	ephemeral: SecretKey<C>,
}

/// A client Finished that awaits its signature.
pub struct CmsClosingDraft<P: HandshakeProvider> {
	/// The transcript hash the Finished signs.
	transcript_hash: [u8; 32],
	/// The receipt countersignature, sealed under the handshake secret.
	sealed_ack: Option<Vec<u8>>,
	/// The proof that the client derived the handshake secret.
	confirmation: KeyConfirmation,
	/// The certificate the Finished embeds, so the server can verify it.
	certificate: Certificate,
	/// The single-use AEAD the Finished, with its certificate, is sealed
	/// under.
	identity_sealer: Sealer<P>,
}

/// The verifier of a Finished under provider `P`.
type FinishedVerifier<P> = EcdsaSignatureVerifier<
	<P as SigningProvider>::VerifyingKey,
	<P as SigningProvider>::Signature,
	<P as DigestProvider>::Digest,
>;

impl Cms {
	/// The content type of a sealed client Finished.
	const SEALED_FINISHED: ObjectIdentifier = SIGNED_DATA;

	/// `finished` sealed under `identity_sealer` as the `EncryptedData` a
	/// client sends (RFC 5652 § 8). It carries no unprotected attribute, so
	/// its version is 0.
	///
	/// # Errors
	///
	/// - The [`Sealer::seal_content`] set.
	fn seal_finished<P: HandshakeProvider>(
		identity_sealer: Sealer<P>,
		finished: &SignedData,
	) -> Result<EncryptedData, HandshakeError> {
		let finished_der = finished.to_der()?;
		let enc_content_info = identity_sealer.seal_content(Self::SEALED_FINISHED, finished_der)?;
		Ok(EncryptedData { version: CmsVersion::V0, enc_content_info, unprotected_attrs: None })
	}

	/// The payload `T` carried among `attrs`, when present.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] -- the attribute repeats.
	/// - [`HandshakeError::DerError`] -- the attribute fails to decode as `T`.
	fn carried<T>(attrs: Option<&Attributes>) -> Result<Option<T>, HandshakeError>
	where
		T: AttributePayload + for<'a> Choice<'a> + for<'a> DecodeValue<'a>,
	{
		let Some(attrs) = attrs else {
			return Ok(None);
		};

		let attribute = attrs.find_unsigned_attr(T::OID)?;
		attribute.map(|attribute| attribute.decode::<T>()).transpose()
	}

	/// The key-agreement recipient that `recipient` holds, if it is one.
	fn key_agreement_recipient(recipient: &RecipientInfo) -> Option<&KeyAgreeRecipientInfo> {
		match recipient {
			RecipientInfo::Kari(kari) => Some(kari),
			_ => None,
		}
	}

	/// The recipient identifier that names `server` in the KARI.
	fn recipient_identifier(server: &Certificate) -> KeyAgreeRecipientIdentifier {
		let issuer = server.tbs_certificate.issuer.clone();
		let serial_number = server.tbs_certificate.serial_number.clone();
		let named = IssuerAndSerialNumber { issuer, serial_number };
		KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(named)
	}

	/// Verify that `finished` is signed under `key` and that `role` signed
	/// `transcript_hash`.
	///
	/// A Finished whose content names the other role is a reflected Finished.
	fn verify_finished<P: HandshakeProvider>(
		role: FinishedRole,
		finished: &SignedData,
		key: P::VerifyingKey,
		transcript_hash: &[u8; 32],
	) -> Result<(), HandshakeError> {
		let expected_sid = SignerIdentifier::try_from(Skid::of_public_key(key.to_public_key_der()?))?;
		let verifier = FinishedVerifier::<P>::from_verifying_key_with_sid(key, expected_sid);
		let processor = TightBeamSignedDataProcessor::new(verifier);
		let digest_oid = P::Digest::OID;
		let content = processor.process(finished, &digest_oid)?;
		let signed = role.transcript_hash(&content);
		let signed_hash = signed.ok_or(HandshakeError::SignatureVerificationFailed)?;

		let transcript_matches: bool = signed_hash.ct_eq(transcript_hash).into();
		if !transcript_matches {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		Ok(())
	}

	/// The digest `role` signs for its Finished over `transcript_hash`.
	fn finished_prehash<P: HandshakeProvider>(role: FinishedRole, transcript_hash: &[u8; 32]) -> Vec<u8> {
		let content = role.content(transcript_hash);
		let mut hasher = P::Digest::new();
		hasher.update(&content);
		hasher.finalize().to_vec()
	}

	/// Build the Finished of `role`: one SignerInfo over the role-bound
	/// transcript hash, with `unsigned_attrs` attached to that SignerInfo.
	fn finished<P: HandshakeProvider>(
		role: FinishedRole,
		transcript_hash: &[u8; 32],
		signed: CmsSigned,
		unsigned_attrs: Option<Attributes>,
		certificate: Option<Certificate>,
	) -> Result<SignedData, HandshakeError> {
		let CmsSigned { signature, signer_spki } = signed;
		let digest_alg = AlgorithmIdentifierOwned { oid: P::Digest::OID, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: P::Signature::ALGORITHM_OID, parameters: None };
		let signer_info = SignerInfo {
			version: CmsVersion::V1,
			sid: SignerIdentifier::try_from(Skid::of_public_key(signer_spki))?,
			// The same OID lives in SignerInfo and in the SignedData
			// digestAlgorithms SET.
			digest_alg: digest_alg.clone(),
			signed_attrs: None,
			signature_algorithm: signature_alg,
			signature: OctetString::new(signature)?,
			unsigned_attrs,
		};

		let content = OctetString::new(role.content(transcript_hash))?;
		let econtent = Any::from_der(&content.to_der()?)?;
		let encap_content_info = EncapsulatedContentInfo { econtent_type: DATA, econtent: Some(econtent) };

		let certificates = match certificate {
			Some(certificate) => {
				let choice = CertificateChoices::Certificate(certificate);
				Some(CertificateSet(vec![choice].try_into()?))
			}
			None => None,
		};

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: vec![digest_alg].try_into()?,
			encap_content_info,
			certificates,
			crls: None,
			signer_infos: vec![signer_info].try_into()?,
		})
	}
}

/// A negotiated value and the bytes it arrived as.
///
/// The handshake acts on the value and the transcript binds the bytes, so the
/// two are taken from one attribute together and describe one encoding.
struct ReceivedAttribute<T> {
	value: T,
	transcript_bytes: Vec<u8>,
}

impl<T> ReceivedAttribute<T> {
	/// Split the attribute into the value the handshake acts on and the bytes
	/// the transcript binds.
	fn into_parts(self) -> (T, Vec<u8>) {
		(self.value, self.transcript_bytes)
	}

	/// Read the attribute `T` names from the Finished unsigned attributes,
	/// keeping its received encoding.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] -- the attribute repeats.
	/// - [`HandshakeError::DerError`] -- the attribute fails to decode as `T`.
	fn extract(signed_data: &SignedData) -> Result<Option<Self>, HandshakeError>
	where
		T: AttributePayload + for<'a> Choice<'a> + for<'a> DecodeValue<'a>,
	{
		let Some(attr) = signed_data.find_unsigned_attr(T::OID)? else {
			return Ok(None);
		};

		let transcript_bytes = attr.received_bytes()?;
		let value = attr.decode::<T>()?;
		Ok(Some(Self { value, transcript_bytes }))
	}
}

impl<P: HandshakeProvider> ClientLegs<P> for Cms {
	type Settings = CmsClientSettings<P>;
	type Trust = ProvisionedTrust;
	type Opening = CmsOpening<P::Curve>;
	type Pending = Box<CmsPending<P::Curve>>;
	type Reply = WireDer<SignedData>;
	type Agreed = ();
	type Draft = CmsClosingDraft<P>;

	fn identity(settings: &Self::Settings) -> Option<&ClientIdentity<P>> {
		Some(&settings.identity)
	}

	fn server_trust(settings: &Self::Settings) -> &Self::Trust {
		&settings.trust
	}

	fn open(
		_settings: &Self::Settings,
		server: AdmittedServer<P::Curve>,
		parts: OpeningParts<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<Opened<Self, P>, HandshakeError> {
		// 1. Draw the base secret, one of the two inputs of the handshake
		//    secret, fresh for this handshake (CWE-321).
		let base = BaseSecret::random(Some(&mut *rng))?;

		// 2. Draw the KARI ephemeral. A copy goes into the KARI builder, and
		//    this one is kept for the agreement with the server ephemeral.
		let ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(&mut *rng));
		let ephemeral_spki = SubjectPublicKeyInfoOwned::from_key(ephemeral.public_key())?;

		// 3. Build the KARI to the admitted server, under the profile's key wrap.
		let certificate = server.identity().certificate();
		let ukm_bytes = generate_nonce::<64>(Some(&mut *rng))?;
		let key_wrap = <P::Profile as SecurityProfile>::KEY_WRAP_OID;
		let key_wrap_oid = key_wrap.ok_or(HandshakeError::MissingKeyWrapAlgorithm)?;
		let recipient_key = *server.identity().key();
		let recipient = Self::recipient_identifier(certificate);
		let ukm = UserKeyingMaterial::new(ukm_bytes.to_vec())?;
		let key_enc_alg = AlgorithmIdentifierOwned { oid: key_wrap_oid, parameters: None };
		let kari = TightBeamKariBuilder::new(P::default())
			.with_sender_priv(ephemeral.clone())
			.with_sender_pub_spki(ephemeral_spki)
			.with_recipient_pub(recipient_key)
			.with_recipient_rid(recipient)
			.with_ukm(ukm)
			.with_key_enc_alg(key_enc_alg);

		// 4. Build the EnvelopedData over the base secret, with each offer as
		//    an unprotected attribute. The client certificate travels only in
		//    the sealed Finished.
		let mut envelope = TightBeamEnvelopedDataBuilder::new(kari);
		if let Some(offer) = parts.security_offer {
			envelope = envelope.with_unprotected_attr(HandshakeAttribute::encode(offer)?);
		}
		if let Some(offer) = parts.transport_offer {
			envelope = envelope.with_unprotected_attr(HandshakeAttribute::encode(offer)?);
		}

		let enveloped_data = envelope.build(base.as_bytes(), Some(rng))?;

		// 5. Encode the key exchange once, so the transcript binds the bytes sent.
		let key_exchange = WireDer::new(enveloped_data)?;
		let mut transcript = Transcript::new();
		transcript.append(key_exchange.der())?;

		let message = HandshakeMessage::EnvelopedData(Box::new(key_exchange));
		let opening = CmsOpening { transcript, server };

		// The two secrets wait in the phase for the reply, and they cross the
		// receipt approval in the orchestrator. They are boxed, so each of
		// those moves copies a pointer.
		let pending = Box::new(CmsPending { base, ephemeral });
		Ok(Opened { message, opening, pending })
	}

	fn read_reply(
		opening: Self::Opening,
		_settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError> {
		let CmsOpening { mut transcript, server } = opening;

		// 1. Take the server Finished, and refuse one that carries an abort alert.
		let reply = reply.signed()?;
		let finished = reply.value();
		finished.refuse_alert()?;

		// 2. Read the accepts, the server ephemeral, and the receipt, each
		//    with the bytes it arrived as. The ephemeral is mandatory.
		let received_accept = ReceivedAttribute::<SecurityAccept>::extract(finished)?;
		let (security_accept, security_accept_bytes) = received_accept.map(ReceivedAttribute::into_parts).unzip();
		let received_transport = ReceivedAttribute::<TransportAccept>::extract(finished)?;
		let (transport_accept, transport_accept_bytes) = received_transport.map(ReceivedAttribute::into_parts).unzip();
		let received_ephemeral = ReceivedAttribute::<OriginatorPublicKey>::extract(finished)?;
		let received_ephemeral = received_ephemeral.ok_or(HandshakeError::MissingAttribute)?;
		let (server_ephemeral, server_ephemeral_bytes) = received_ephemeral.into_parts();
		let received_artifact = ReceivedAttribute::<SignedData>::extract(finished)?;
		let receipt = received_artifact.map(|received| received.into_parts().0);

		// 3. Append the received encodings and seal the transcript. A tampered
		//    attribute diverges the hashes and fails the signature (CWE-345),
		//    and a reordered `SET OF` cannot normalise back to the signed form.
		let legs = ServerFinishedLegs {
			security_accept: security_accept_bytes,
			transport_accept: transport_accept_bytes,
			server_ephemeral: server_ephemeral_bytes,
		};
		transcript.append_server_finished(legs)?;
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 4. Return the facts of the reply.
		let server_ephemeral = server_ephemeral.public_key.raw_bytes().to_vec();
		Ok(ReplyIntake {
			server,
			security_accept,
			transport_accept,
			server_ephemeral,
			receipt,
			client_cert_required: false,
			transcript_hash,
			salt: Salt::transcript_hash(),
			reply,
		})
	}

	fn verify_reply(
		reply: &Self::Reply,
		key: P::VerifyingKey,
		transcript_hash: &[u8; 32],
	) -> Result<(), HandshakeError> {
		Self::verify_finished::<P>(FinishedRole::Server, reply.value(), key, transcript_hash)
	}

	fn agree(
		pending: Self::Pending,
		server_ephemeral: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<(HandshakeSecret, Self::Agreed), HandshakeError> {
		// The secrets are read in place, so each is wiped where the box drops.
		let CmsPending { base, ephemeral } = pending.as_ref();
		let agreement = Agreement::<P>::new(base, server_ephemeral);
		let secret = agreement.settle(ephemeral, salt)?;

		Ok((secret, ()))
	}

	fn bind_closing<'a>(
		_agreed: (),
		_reply: Self::Reply,
		settings: &'a Self::Settings,
		parts: ClosingParts<'_, P>,
	) -> Result<ClosingBinding<'a, Self, P>, HandshakeError> {
		let ClosingParts { transcript_hash, sealed_ack, confirmation, identity_sealer, .. } = parts;
		let identity = &settings.identity;
		let prehash = Self::finished_prehash::<P>(FinishedRole::Client, transcript_hash);
		let proof = ProofRequest { prehash, signer: identity.signing_provider() };
		let certificate = identity.certificate().clone();

		let transcript_hash = *transcript_hash;
		let draft = CmsClosingDraft { transcript_hash, sealed_ack, confirmation, certificate, identity_sealer };
		Ok(ClosingBinding { proof: Some(proof), draft })
	}

	fn encode_closing(draft: Self::Draft, proof: Option<CmsSigned>) -> Result<HandshakeMessage, HandshakeError> {
		let CmsClosingDraft { transcript_hash, sealed_ack, confirmation, certificate, identity_sealer } = draft;
		let signed = proof.ok_or(HandshakeError::MutualAuthRequired)?;

		// The tag and the countersignature travel as SignerInfo unsigned
		// attributes, outside the signature. The handshake secret binds both:
		// it derives the tag over the transcript hash, and it seals the other.
		let mut attributes = vec![HandshakeAttribute::encode(&confirmation)?];
		if let Some(sealed_ack) = sealed_ack {
			attributes.push(HandshakeAttribute::encode(&OctetString::new(sealed_ack)?)?);
		}

		let encoded: Result<Vec<Attribute>, HandshakeError> = attributes.into_iter().map(Attribute::try_from).collect();
		let unsigned_attrs = Attributes::try_from(encoded?)?;
		let role = FinishedRole::Client;

		let finished = Self::finished::<P>(role, &transcript_hash, signed, Some(unsigned_attrs), Some(certificate))?;

		// The Finished embeds the certificate and signs under its key, so the
		// whole Finished is sealed under the identity key of the handshake
		// secret, and both cross the wire sealed.
		let sealed = Self::seal_finished(identity_sealer, &finished)?;
		HandshakeMessage::try_from(sealed)
	}
}

/// What a CMS server is provisioned with.
///
/// The shared server configuration covers the whole protocol: its key
/// provider opens the key exchange and signs the Finished.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmsServerSettings;

/// A decoded key exchange that awaits the static open.
pub struct CmsSealed {
	/// The key exchange, whose KARI wraps the content-encryption key.
	key_exchange: WireDer<EnvelopedData>,
	/// The transcript, open over the key exchange as it arrived.
	transcript: Transcript,
}

/// What a CMS server holds from the static open to its Finished.
pub struct CmsOpened<C: HandshakeCurve> {
	/// The base secret the key exchange carried.
	base: BaseSecret,
	/// The client's KARI originator key, parsed once at the open as a point
	/// of the curve.
	originator: PeerPoint<C>,
	/// The transcript, open over the key exchange.
	transcript: Transcript,
}

/// A server Finished that awaits its signature and its receipt.
pub struct CmsReplyDraft {
	transcript_hash: [u8; 32],
	security_accept: SecurityAccept,
	transport_accept: Option<TransportAccept>,
	server_ephemeral: OriginatorPublicKey,
}

/// What a CMS server holds from its Finished to the client Finished.
pub struct CmsServerPending<C: HandshakeCurve> {
	/// The handshake secret, derived when the server Finished was built.
	secret: HandshakeSecret,
	/// The client's KARI originator key, which the offer compares with the
	/// identity's key.
	originator: PublicKey<C>,
}

/// A decoded client closing, with what the reply left for its open.
pub struct CmsClosing<C: HandshakeCurve> {
	/// The encrypted content of the client Finished, sealed under the identity
	/// key of the handshake secret.
	content: EncryptedContentInfo,
	/// The handshake secret, derived when the server Finished was built.
	secret: HandshakeSecret,
	/// The client's KARI originator key.
	originator: PublicKey<C>,
}

/// The CMS client Finished as the proof that the key of its embedded
/// certificate signed it.
pub struct CmsFinished(SignedData);

impl<P: HandshakeProvider> PossessionProof<P> for CmsFinished {
	/// The Finished verifies when its one signer is the offered key and its
	/// signed content is the client role over the sealed transcript hash.
	fn verify(self, identity: &PeerCertificate<P::Curve>, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let key = P::VerifyingKey::from(*identity.key());
		Cms::verify_finished::<P>(FinishedRole::Client, &self.0, key, terms.transcript_hash())
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

	/// The key-confirmation tag in the SignerInfo unsigned attributes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the Finished carries no tag.
	/// - [`HandshakeError::DuplicateAttribute`] -- the tag repeats.
	/// - [`HandshakeError::DerError`] -- the tag is not a 32-byte OCTET STRING.
	fn key_confirmation(&self) -> Result<KeyConfirmation, HandshakeError>;

	/// The first X.509 certificate embedded in the `certificates` field, if
	/// any. It is the offered certificate, and the Finished signature must
	/// verify under its key. The set may also carry the chain of that
	/// certificate.
	fn embedded_certificate(&self) -> Option<Certificate>;
}

impl ClientFinished for SignedData {
	fn sealed_receipt_ack(&self) -> Result<Option<OctetString>, HandshakeError> {
		let attribute = self.find_unsigned_attr(RECEIPT_ACK)?;
		attribute.map(|attr| attr.decode::<OctetString>()).transpose()
	}

	fn key_confirmation(&self) -> Result<KeyConfirmation, HandshakeError> {
		let attribute = self.find_unsigned_attr(KeyConfirmation::OID)?;
		let attribute = attribute.ok_or(HandshakeError::MissingAttribute)?;
		attribute.decode::<KeyConfirmation>()
	}

	fn embedded_certificate(&self) -> Option<Certificate> {
		let set = self.certificates.as_ref()?;
		set.0.iter().find_map(|choice| match choice {
			// The caller needs an owned certificate, and the parsed SignedData
			// keeps its copy.
			CertificateChoices::Certificate(certificate) => Some(certificate.clone()),
			CertificateChoices::Other(_) => None,
		})
	}
}

impl<P: HandshakeProvider> ServerLegs<P> for Cms {
	type Settings = CmsServerSettings;
	type Sealed = CmsSealed;
	type Opened = Box<CmsOpened<P::Curve>>;
	type Draft = CmsReplyDraft;
	type Pending = CmsServerPending<P::Curve>;
	type Closing = CmsClosing<P::Curve>;
	type Proof = CmsFinished;

	fn read_opening(
		_settings: &Self::Settings,
		opening: HandshakeMessage,
	) -> Result<OpeningIntake<Self, P>, HandshakeError> {
		// 1. Open the transcript over the key exchange as it arrived.
		let key_exchange = opening.enveloped()?;
		let mut transcript = Transcript::new();
		transcript.append(key_exchange.der())?;

		// 2. Refuse an abort alert before any negotiation or key agreement runs.
		key_exchange.value().unprotected_attrs.refuse_alert()?;
		let attrs = key_exchange.value().unprotected_attrs.as_ref();

		// 3. Read the offers. A duplicate or malformed attribute fails closed,
		//    because one read as absent would fall through to dealer's choice.
		let security_offer = Self::carried::<SecurityOffer>(attrs)?;
		let transport_offer = Self::carried::<TransportOffer>(attrs)?;

		let sealed = CmsSealed { key_exchange, transcript };
		Ok(OpeningIntake { security_offer, transport_offer, sealed })
	}

	fn open_opening<'a>(
		sealed: Self::Sealed,
		key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>> {
		Box::pin(async move {
			let CmsSealed { key_exchange, transcript } = sealed;
			let enveloped_data = key_exchange.value();

			// 1. Find the KARI and its originator key.
			let recipients = enveloped_data.recip_infos.0.iter();
			let kari = recipients.filter_map(Self::key_agreement_recipient).next();
			let kari = kari.ok_or(HandshakeError::InvalidClientKeyExchange)?;
			let originator_bytes = match &kari.originator {
				OriginatorIdentifierOrKey::OriginatorKey(originator) => originator.public_key.raw_bytes(),
				_ => return Err(HandshakeError::InvalidClientKeyExchange),
			};

			// 2. Parse the originator key. A malformed, off-curve, or identity
			//    point is refused here, ahead of the agreement. The comparison
			//    with the client's static key waits for the identity, which
			//    opens at the closing.
			let originator = PeerPoint::parse(originator_bytes)?;

			// 3. Run the static ECDH through the key provider, and derive the
			//    key-encryption key under the UKM.
			let agreed = key.key_agreement(originator_bytes).await?;
			let shared_secret = EcdhSecret::try_from(agreed)?;
			let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
			let ukm_salt = KdfSalt::new(ukm.as_bytes());
			let kek = shared_secret.derive_kek::<P>(ukm_salt, KdfInfo::new(TIGHTBEAM_KARI_KDF_INFO))?;

			// 4. Unwrap the content-encryption key. `recipient_enc_keys` is an
			//    unauthenticated DER SEQUENCE OF that can decode empty, so it
			//    is read through `first`.
			let wrapped = kari.recipient_enc_keys.first();
			let wrapped = wrapped.ok_or(HandshakeError::InvalidClientKeyExchange)?;
			let cek = Kek::new(kek.as_slice()).unwrap_verified(&P::default(), wrapped.enc_key.as_bytes())?;
			let cipher = cek.with(|cek| {
				P::AeadCipher::new_from_slice(cek).map_err(|_| HandshakeError::InvalidKeySize {
					expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
					received: cek.len(),
				})
			})?;

			// 5. Open the content, which parses as the base secret.
			let content = cipher.decrypt_content(&enveloped_data.encrypted_content)?;
			let base = BaseSecret::try_from(content)?;

			// The base secret crosses the signature and receipt awaits in the
			// orchestrator. It is boxed, so that move copies a pointer.
			Ok(Box::new(CmsOpened { base, originator, transcript }))
		})
	}

	fn bind_reply(
		opened: &mut Self::Opened,
		_settings: &Self::Settings,
		parts: ReplyParts<'_, P>,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<ReplyBinding<Self, P>, HandshakeError> {
		let ReplyParts { profile, transport_accept, server_ephemeral, .. } = parts;

		// 1. Carry the server ephemeral as the originator key the Finished
		//    sends, through the SPKI encoding of the provider's verifying key.
		let security_accept = SecurityAccept::new(profile.descriptor());
		let ephemeral_key = P::VerifyingKey::from(server_ephemeral);
		let server_ephemeral = (&ephemeral_key).originator_key()?;

		// 2. Append both selections and the ephemeral, then seal, so the
		//    Finished signature binds all three (CWE-345).
		let legs = ServerFinishedLegs {
			security_accept: Some(HandshakeAttribute::transcript_bytes(&security_accept)?),
			transport_accept: transport_accept.map(HandshakeAttribute::transcript_bytes).transpose()?,
			server_ephemeral: HandshakeAttribute::transcript_bytes(&server_ephemeral)?,
		};
		opened.transcript.append_server_finished(legs)?;

		let transcript_hash = opened.transcript.seal::<P::Digest>()?;

		// 3. Name the digest the server signs.
		let prehash = Self::finished_prehash::<P>(FinishedRole::Server, &transcript_hash);
		let transport_accept = transport_accept.copied();
		let draft = CmsReplyDraft { transcript_hash, security_accept, transport_accept, server_ephemeral };
		Ok(ReplyBinding { transcript_hash, salt: Salt::transcript_hash(), prehash, draft })
	}

	fn encode_reply(
		draft: Self::Draft,
		signed: CmsSigned,
		artifact: Option<&SignedData>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let CmsReplyDraft { transcript_hash, security_accept, transport_accept, server_ephemeral } = draft;

		// The accepts and the ephemeral are advisory as attributes, like TLS
		// ServerHello extensions before Finished. A tampered one diverges the
		// client's transcript, and the handshake fails closed.
		let mut attributes = vec![HandshakeAttribute::encode(&security_accept)?];
		if let Some(accept) = transport_accept.as_ref() {
			attributes.push(HandshakeAttribute::encode(accept)?);
		}
		if let Some(artifact) = artifact {
			attributes.push(HandshakeAttribute::encode(artifact)?);
		}

		attributes.push(HandshakeAttribute::encode(&server_ephemeral)?);

		let encoded: Result<Vec<Attribute>, HandshakeError> = attributes.into_iter().map(Attribute::try_from).collect();
		let unsigned_attrs = Attributes::try_from(encoded?)?;
		let role = FinishedRole::Server;

		let finished = Self::finished::<P>(role, &transcript_hash, signed, Some(unsigned_attrs), None)?;
		HandshakeMessage::try_from(finished)
	}

	fn pend(
		opened: Self::Opened,
		ephemeral: Box<EphemeralSecret<P::Curve>>,
		terms: &Terms<P>,
	) -> Result<Self::Pending, HandshakeError> {
		// The base secret, the ephemeral, and the transcript drop here. Both
		// secrets are read in place, so each is wiped where its box drops.
		// The server Finished itself is not part of the sealed transcript.
		let agreement = Agreement::<P>::new(&opened.base, &opened.originator);

		let secret = agreement.settle(ephemeral.as_ref(), terms.kdf_salt())?;
		let originator = *opened.originator.as_public_key();
		Ok(CmsServerPending { secret, originator })
	}

	fn read_closing(
		pending: Self::Pending,
		_settings: &Self::Settings,
		closing: HandshakeMessage,
	) -> Result<Self::Closing, HandshakeError> {
		// Take the sealed client Finished, and refuse one that carries an
		// abort alert. The seal covers every other part of the closing.
		let sealed = closing.encrypted()?;
		sealed.value().unprotected_attrs.refuse_alert()?;

		let EncryptedData { enc_content_info: content, .. } = sealed.into_value();
		let CmsServerPending { secret, originator } = pending;
		Ok(CmsClosing { content, secret, originator })
	}

	fn settle<'a>(
		closing: Self::Closing,
		terms: &'a Terms<P>,
		_key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<ClosingOpened<Self, P>, HandshakeError>> {
		// The handshake secret was derived when the server Finished was built,
		// so the open needs no await.
		let opened = closing.open(terms);
		Box::pin(async move { opened })
	}
}

impl<C: HandshakeCurve> CmsClosing<C> {
	/// Open the sealed client Finished under the identity key, read the tag,
	/// the receipt countersignature, and the certificate it carries, and build
	/// the offer.
	///
	/// The Finished is a proof, so one that names no certificate is refused,
	/// and the offer refuses an originator that collapses into the key of the
	/// certificate.
	///
	/// # Errors
	///
	/// - The [`ServerLegs::settle`] set of the CMS flow.
	fn open<P: HandshakeProvider<Curve = C>>(self, terms: &Terms<P>) -> Result<ClosingOpened<Cms, P>, HandshakeError> {
		let Self { content, secret, originator } = self;

		// 1. Open the Finished under the identity key of the secret.
		let identity_sealer = terms.sealer(&secret, SecretSeal::Identity)?;
		let finished_der = identity_sealer.open_content(&content, Cms::SEALED_FINISHED)?;
		let finished = finished_der.with(|der| SignedData::from_der(der))?;

		// 2. Read the key-confirmation tag, which is mandatory, and the sealed receipt acknowledgement.
		let confirmation = finished.key_confirmation()?;
		let sealed_ack = finished.sealed_receipt_ack()?;
		let receipt_ack = sealed_ack.map(OctetString::into_bytes);

		// 3. Parse the certificate once, and build the offer, which compares the originator with its key.
		let certificate = finished.embedded_certificate();
		let certificate = certificate.ok_or(HandshakeError::MissingClientCertificate)?;
		let identity = PeerCertificate::<C>::parse(certificate)?;
		let offer = Offer::new(identity, CmsFinished(finished), [&originator])?;
		Ok(ClosingOpened { secret, confirmation, receipt_ack, offer })
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::*;
	use crate::cms::enveloped_data::{EnvelopedData, RecipientInfos};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::{SecretSlice, ToInsecure};
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::sign::LowSEncoding;
	use crate::crypto::x509::policy::ExpiryValidator;
	use crate::der::asn1::{BitString, ObjectIdentifier};
	use crate::der::{EncodeValue, Tagged};
	use crate::oids::{
		AES_128_GCM, AES_128_WRAP, AES_256_GCM, HANDSHAKE_ABORT_ALERT, HANDSHAKE_SERVER_EPHEMERAL, HASH_SHA3_256,
		SIGNER_ECDSA_WITH_SHA3_256,
	};
	use crate::random::OsRng;
	use crate::spki::EncodePublicKey;
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
	use crate::transport::handshake::kari::OriginatorKey;
	use crate::transport::handshake::negotiation::SecurityOffer;
	use crate::transport::handshake::processors::{TightBeamEnvelopedDataProcessor, TightBeamKariRecipient};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{
		ClientKeyExchange, CmsServerIdentity, Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication,
	};

	/// The base secret a hand-built key exchange carries.
	const TEST_BASE_SECRET: [u8; 32] = [2u8; 32];

	/// The originator key of a fresh secp256k1 ephemeral, as a server sends it.
	fn fresh_server_ephemeral() -> OriginatorPublicKey {
		let public_key = SecretKey::<Secp256k1>::random(&mut OsRng).public_key();
		let spki_der = public_key.to_public_key_der().expect("a public key encodes as an SPKI");

		let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).expect("the SPKI decodes");
		spki.originator_key().expect("an SPKI names an originator key")
	}

	/// `ephemeral` with its point bytes replaced by `point`.
	fn with_point(ephemeral: OriginatorPublicKey, point: &[u8]) -> OriginatorPublicKey {
		let public_key = BitString::from_bytes(point).expect("point bytes are a BIT STRING");
		OriginatorPublicKey { algorithm: ephemeral.algorithm, public_key }
	}

	/// `signed` with the unsigned attributes of its one signer replaced by
	/// `attrs`.
	fn with_unsigned_attrs(mut signed: SignedData, attrs: Option<Attributes>) -> SignedData {
		let mut signer_infos: Vec<_> = signed.signer_infos.0.iter().cloned().collect();
		let signer = signer_infos.first_mut().expect("a Finished has one signer");
		signer.unsigned_attrs = attrs;
		signed.signer_infos = signer_infos.try_into().expect("one signer is a SET");
		signed
	}

	/// `attributes` as the unsigned attributes of a Finished.
	fn unsigned_attrs(attributes: Vec<HandshakeAttribute>) -> Attributes {
		let encoded = attributes.into_iter().map(Attribute::try_from);
		let encoded: Result<Vec<_>, _> = encoded.collect();
		Attributes::try_from(encoded.expect("each attribute encodes")).expect("the attributes are a SET")
	}

	/// The attribute that carries `payload`.
	fn attribute<T: AttributePayload + Tagged + EncodeValue>(payload: &T) -> HandshakeAttribute {
		HandshakeAttribute::encode(payload).expect("the payload encodes as an attribute")
	}

	/// A server Finished signed by `server_key` over the transcript of
	/// `key_exchange` followed by the default profile's accept and
	/// `ephemeral`, as a server under dealer's choice sends it.
	fn server_finished_over(
		server_key: &Secp256k1SigningKey,
		key_exchange: &WireDer<EnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> SignedData {
		let accept = SecurityAccept::new(create_default_test_profile());
		let accept_bytes = HandshakeAttribute::transcript_bytes(&accept).expect("an accept has transcript bytes");
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(ephemeral).expect("a key has transcript bytes");
		let transcript = [key_exchange.der(), accept_bytes.as_slice(), ephemeral_bytes.as_slice()].concat();
		let attrs = unsigned_attrs(vec![attribute(&accept), attribute(ephemeral)]);

		signed_server_finished(server_key, &transcript, attrs)
	}

	/// A server Finished signed by `server_key` over `transcript` that
	/// carries `attrs`.
	fn signed_server_finished(server_key: &Secp256k1SigningKey, transcript: &[u8], attrs: Attributes) -> SignedData {
		let transcript_hash = Transcript::digest::<Sha3_256>(transcript).expect("the transcript hashes");
		let signed = signed_finished(FinishedRole::Server, server_key, &transcript_hash);
		with_unsigned_attrs(signed, Some(attrs))
	}

	/// A Finished of `role` signed by `key` over `transcript_hash`, built by
	/// hand from the SignedData builder. It carries no attribute and no
	/// certificate.
	fn signed_finished(role: FinishedRole, key: &Secp256k1SigningKey, transcript_hash: &[u8; 32]) -> SignedData {
		let digest_alg = AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None };
		let signature_alg = AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None };

		let builder = TightBeamSignedDataBuilder::<DefaultCryptoProvider, _>::new(key, digest_alg, signature_alg);
		let builder = builder.expect("the test key builds a signer");
		builder.build(role.content(transcript_hash)).expect("the Finished signs")
	}

	/// A client pinned to `server` that has sent its key exchange under
	/// `offer`, with that key exchange.
	fn client_after_key_exchange(
		server: &TestCertificate,
		offer: Option<SecurityOffer>,
	) -> (TestClient<Cms>, WireDer<EnvelopedData>) {
		let mut config = Cms::client(&server.certificate, &create_test_certificate());
		config.security_offer = offer;

		let mut client = Handshake::client(config);
		let opening = client.start().expect("a fresh client builds its key exchange");
		let key_exchange = opening.enveloped().expect("a CMS opening travels in an EnvelopedData");
		(client, key_exchange)
	}

	/// The opening that carries `key_exchange`.
	fn opening(key_exchange: EnvelopedData) -> HandshakeMessage {
		let key_exchange = WireDer::new(key_exchange).expect("the key exchange encodes");
		HandshakeMessage::EnvelopedData(Box::new(key_exchange))
	}

	/// The reply that carries `finished`.
	fn reply(finished: SignedData) -> HandshakeMessage {
		HandshakeMessage::try_from(finished).expect("a Finished encodes")
	}

	/// The closing that carries `finished` sealed under `sealer`, as a client
	/// seals its Finished.
	fn sealed_closing(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> HandshakeMessage {
		let sealed = sealed_finished(sealer, finished);
		HandshakeMessage::try_from(sealed).expect("the closing encodes")
	}

	/// `finished` sealed under `sealer` as the `EncryptedData` a client sends.
	fn sealed_finished(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> EncryptedData {
		let sealed = Cms::seal_finished(sealer, finished);
		sealed.expect("the Finished seals")
	}

	/// `sealed` with the last byte of its encrypted content flipped, as an
	/// on-path party would alter it.
	fn with_flipped_content(mut sealed: EncryptedData) -> EncryptedData {
		let content = sealed.enc_content_info.encrypted_content.as_ref();
		let mut content = content.expect("a sealed Finished carries content").as_bytes().to_vec();
		let last = content.last_mut().expect("the content ends with a tag");
		*last ^= 0x01;

		sealed.enc_content_info.encrypted_content = Some(OctetString::new(content).expect("bytes are an OCTET STRING"));
		sealed
	}

	/// `finished` with `certificate` embedded as its one certificate.
	fn with_certificate(mut finished: SignedData, certificate: &Certificate) -> SignedData {
		let embedded = CertificateChoices::Certificate(certificate.to_owned());
		let certificates = vec![embedded].try_into().expect("one certificate fits a set");
		finished.certificates = Some(CertificateSet(certificates));
		finished
	}

	/// A client Finished signed by `client` over `transcript_hash` that embeds
	/// its certificate and carries `confirmation`, as a client with an identity
	/// builds it before the seal.
	///
	/// No client builds it, so a server that reads it is tested against the
	/// message format alone.
	fn build_test_client_finished(
		client: &TestCertificate,
		transcript_hash: &[u8; 32],
		confirmation: &KeyConfirmation,
	) -> SignedData {
		let signed = signed_finished(FinishedRole::Client, &client.signing_key, transcript_hash);
		let confirmed = with_unsigned_attrs(signed, Some(unsigned_attrs(vec![attribute(confirmation)])));
		with_certificate(confirmed, &client.certificate)
	}

	/// `finished` with its key-confirmation tag replaced by `confirmation` and
	/// every other unsigned attribute kept, as a reflecting party would build
	/// it. The signature covers no unsigned attribute, so it still verifies.
	fn with_confirmation(finished: SignedData, confirmation: &KeyConfirmation) -> SignedData {
		let signer = finished.signer_infos.0.iter().next().expect("a Finished has one signer");
		let carried = signer.unsigned_attrs.iter().flat_map(|attrs| attrs.iter());
		let kept = carried.filter(|attr| attr.oid != KeyConfirmation::OID);

		let mut attributes: Vec<HandshakeAttribute> = kept.map(HandshakeAttribute::from).collect();
		attributes.push(attribute(confirmation));

		with_unsigned_attrs(finished, Some(unsigned_attrs(attributes)))
	}

	/// A key exchange built by hand from the CMS builders, which encrypts
	/// `base` to `recipient_public_key` under a fresh originator key and
	/// carries `unprotected_attrs`.
	///
	/// No client builds it, so a server that reads it is tested against the
	/// message format alone.
	fn build_test_key_exchange(
		recipient_public_key: &PublicKey<Secp256k1>,
		base: &[u8],
		unprotected_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> EnvelopedData {
		let sender_ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		build_test_key_exchange_from(sender_ephemeral, recipient_public_key, base, unprotected_attrs)
	}

	/// The key exchange of [`build_test_key_exchange`] under the originator
	/// key `sender_ephemeral`, for a fixture that keeps that key to derive the
	/// handshake secret.
	fn build_test_key_exchange_from(
		sender_ephemeral: SecretKey<Secp256k1>,
		recipient_public_key: &PublicKey<Secp256k1>,
		base: &[u8],
		unprotected_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> EnvelopedData {
		let sender_public = sender_ephemeral.public_key();
		let sender_pub_spki = SubjectPublicKeyInfoOwned::from_key(sender_public).expect("a public key has an SPKI");

		let key_enc_alg = AlgorithmIdentifierOwned { oid: AES_128_WRAP, parameters: None };
		let kari_builder = TightBeamKariBuilder::default()
			.with_sender_priv(sender_ephemeral)
			.with_sender_pub_spki(sender_pub_spki)
			.with_recipient_pub(*recipient_public_key)
			.with_recipient_rid(create_test_recipient_id())
			.with_ukm(create_test_ukm())
			.with_key_enc_alg(key_enc_alg);

		let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
		let enveloped_builder = enveloped_builder.with_unprotected_attrs(unprotected_attrs);
		enveloped_builder.build(base, None).expect("the key exchange builds")
	}

	/// `key_exchange` with the SEC1 bytes of its KARI originator key replaced
	/// by `point`, as an on-path party would rewrite it.
	fn with_originator_point(key_exchange: EnvelopedData, point: &[u8]) -> EnvelopedData {
		let mut infos: Vec<RecipientInfo> = key_exchange.recip_infos.0.iter().cloned().collect();
		let Some(RecipientInfo::Kari(kari)) = infos.first_mut() else {
			panic!("the key exchange carries a KARI");
		};
		let OriginatorIdentifierOrKey::OriginatorKey(originator) = &mut kari.originator else {
			panic!("the KARI carries an originator key");
		};

		originator.public_key = BitString::from_bytes(point).expect("point bytes are a BIT STRING");

		let recip_infos = RecipientInfos::try_from(infos).expect("one recipient is a SET");
		EnvelopedData { recip_infos, ..key_exchange }
	}

	/// An unprotected attribute the server ignores, told apart by `arc`.
	fn marker_attribute(arc: u32) -> HandshakeAttribute {
		let parent = ObjectIdentifier::new_unwrap("1.2.3.4");
		let oid = parent.push_arc(arc).expect("the arc extends the OID");
		let octets = OctetString::new(arc.to_be_bytes()).expect("four bytes fit an OCTET STRING");
		let value = Any::encode_from(&octets).expect("an OCTET STRING encodes");
		HandshakeAttribute::new_single(oid, value).expect("one value makes an attribute")
	}

	/// The DER of `key_exchange` with its two trailing unprotected attributes
	/// swapped out of DER order. It decodes to the same value.
	fn misordered_der(key_exchange: &EnvelopedData) -> Vec<u8> {
		let canonical = key_exchange.to_der().expect("the key exchange encodes");
		let attrs = key_exchange.unprotected_attrs.as_ref();
		let attrs = attrs.expect("the key exchange carries attributes");
		let [first, second] = attrs.as_slice() else {
			panic!("the key exchange carries exactly two attributes");
		};

		let first = first.to_der().expect("an attribute encodes");
		let second = second.to_der().expect("an attribute encodes");
		let tail = [first.as_slice(), second.as_slice()].concat();
		let head = canonical.strip_suffix(tail.as_slice());
		let head = head.expect("the attributes end the encoding");

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

	/// A server that holds `identity` under `peer_authentication`, with the
	/// static public key a hand-built key exchange encrypts to.
	fn server_with(
		identity: &TestCertificate,
		peer_authentication: PeerAuthentication,
	) -> (TestServer<Cms>, PublicKey<Secp256k1>) {
		let mut config = Cms::server(identity);
		config.peer_authentication = peer_authentication;

		let static_key = PublicKey::from(*identity.signing_key.verifying_key());
		(Handshake::server(config), static_key)
	}

	/// A server that demands no client certificate, with the static public
	/// key a hand-built key exchange encrypts to.
	fn anonymous_server() -> (TestServer<Cms>, PublicKey<Secp256k1>) {
		server_with(&create_test_certificate(), PeerAuthentication::Anonymous)
	}

	/// A server that has answered a hand-built key exchange, so it awaits the
	/// client Finished, beside what the client that built the key exchange
	/// holds.
	struct AwaitingFinished {
		/// The server, with its reply sent.
		server: TestServer<Cms>,
		/// The server Finished the reply carried.
		server_finished: SignedData,
		/// The key-confirmation tag of the client that built the key exchange.
		confirmation: KeyConfirmation,
		/// What the reply confirms, as the client reads it.
		confirming: Confirming,
		/// The originator key of the key exchange.
		ephemeral: SecretKey<Secp256k1>,
	}

	impl AwaitingFinished {
		/// The transcript hash the reply sealed.
		fn transcript_hash(&self) -> &[u8; 32] {
			&self.confirming.transcript_hash
		}

		/// The closing that carries `finished`, sealed under the identity key
		/// of the client that built the key exchange, as that client seals it.
		fn sealed(&self, finished: &SignedData) -> HandshakeMessage {
			let sealed = self.sealed_finished(finished);
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// `finished` sealed as [`Self::sealed`] seals it, before it is
		/// wrapped as a closing.
		fn sealed_finished(&self, finished: &SignedData) -> EncryptedData {
			let sealer = self.confirming.identity_sealer(&test_base_secret(), &self.ephemeral);
			sealed_finished(sealer, finished)
		}
	}

	/// The identity sealer of a fixture handshake secret, foreign to the
	/// server, over `transcript_hash`.
	fn foreign_identity_sealer(transcript_hash: &[u8; 32]) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::new(transcript_hash);
		let foreign = fixture_handshake_secret(0x42);
		let sealer = foreign.sealer::<DefaultCryptoProvider>(SecretSeal::Identity, salt, transcript_hash);
		sealer.expect("a fixture secret derives an identity key")
	}

	/// The base secret of [`TEST_BASE_SECRET`].
	fn test_base_secret() -> BaseSecret {
		let base = BaseSecret::try_from(SecretSlice::from(TEST_BASE_SECRET.to_vec()));
		base.expect("32 bytes make a base secret")
	}

	/// A server that holds `identity` under `peer_authentication` and has
	/// answered a hand-built key exchange under the originator key `ephemeral`.
	async fn awaiting_finished(
		identity: &TestCertificate,
		peer_authentication: PeerAuthentication,
		ephemeral: SecretKey<Secp256k1>,
	) -> AwaitingFinished {
		let mut config = Cms::server(identity);
		config.peer_authentication = peer_authentication;
		awaiting_finished_under(identity, config, ephemeral, []).await
	}

	/// A server under `config`, which holds `identity`, that has answered a
	/// hand-built key exchange under the originator key `ephemeral` that
	/// carries `offers`.
	async fn awaiting_finished_under(
		identity: &TestCertificate,
		config: TestServerConfig<Cms>,
		ephemeral: SecretKey<Secp256k1>,
		offers: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AwaitingFinished {
		let server_public_key = PublicKey::from(*identity.signing_key.verifying_key());
		let mut server = Handshake::server(config);
		let sender = ephemeral.to_owned();
		let key_exchange = build_test_key_exchange_from(sender, &server_public_key, &TEST_BASE_SECRET, offers);

		let replying = server.reply(opening(key_exchange)).await;
		let reply = replying.expect("the server answers the key exchange");
		let server_finished = reply.signed().expect("a CMS reply is a SignedData");
		let carried = server_finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL);
		let carried = carried.expect("the ephemeral attribute is single");
		let carried = carried.expect("the server Finished carries its ephemeral");
		let originator = carried.decode::<OriginatorPublicKey>().expect("the ephemeral decodes");
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(originator.public_key.raw_bytes());

		// The CMS salt is the transcript hash.
		let transcript_hash = server.transcript_hash().expect("the reply sealed the transcript");
		let confirming = Confirming {
			server_ephemeral: server_ephemeral.expect("the server ephemeral is a point on the curve"),
			salt: transcript_hash.to_vec(),
			transcript_hash,
		};

		let confirmation = confirming.tag(&test_base_secret(), &ephemeral);
		let server_finished = server_finished.value().to_owned();
		AwaitingFinished { server, server_finished, confirmation, confirming, ephemeral }
	}

	/// A server that demands no client certificate and awaits the client
	/// Finished of a fresh originator key.
	async fn server_awaiting_finished() -> AwaitingFinished {
		let identity = create_test_certificate();
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		awaiting_finished(&identity, PeerAuthentication::Anonymous, ephemeral).await
	}

	/// The transcript hash a server Finished signed, read from its content.
	fn signed_transcript(server_finished: &SignedData) -> [u8; 32] {
		let content = server_finished.encap_content_info.econtent.as_ref();
		let content = content.expect("a Finished carries content");
		let content = content.decode_as::<OctetString>().expect("the content is an OCTET STRING");

		let signed = FinishedRole::Server.transcript_hash(content.as_bytes());
		signed.expect("the content names the server role")
	}

	/// A processor that verifies a Finished under the static key of `signer`.
	fn finished_processor(signer: &TestCertificate) -> TightBeamSignedDataProcessor {
		let key = *signer.signing_key.verifying_key();
		let key_der = key.to_public_key_der().expect("a key encodes");
		let sid = SignerIdentifier::try_from(Skid::of_public_key(key_der)).expect("a key has a signer identifier");
		let verifier = FinishedVerifier::<DefaultCryptoProvider>::from_verifying_key_with_sid(key, sid);
		TightBeamSignedDataProcessor::new(verifier)
	}

	/// The key exchange carries the 32-byte base secret, and it opens under
	/// the static key of the server the client was pinned to.
	#[test]
	fn the_key_exchange_opens_under_the_server_static_key() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (_, key_exchange) = client_after_key_exchange(&server, None);
		let server_secret = SecretKey::from(server.signing_key.to_owned());
		let recipient = TightBeamKariRecipient::new(DefaultCryptoProvider::default(), server_secret);
		let processor = TightBeamEnvelopedDataProcessor::<DefaultCryptoProvider>::new(recipient);

		let base = processor.process(key_exchange.value())?.to_insecure();
		assert_eq!(base.len(), 32);
		Ok(())
	}

	/// A client provisioned with a server its store does not hold refuses to
	/// build the opening, and the refusal spends the client.
	#[test]
	fn a_refused_provisioned_server_leaves_the_client_spent() {
		let trusted = create_test_certificate();
		let stranger = create_test_certificate();
		let mut config = Cms::client(&trusted.certificate, &create_test_certificate());
		config.flow.trust.identity = CmsServerIdentity::Certificate(Arc::new(stranger.certificate));

		let mut client = Handshake::client(config);
		let refusal = client.start();
		assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		assert_eq!(client.phase(), HandshakePhase::Spent);
		assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
	}

	/// A Finished signed over the key exchange the client sent is admitted,
	/// and the closing is the client Finished sealed as `EncryptedData`.
	#[tokio::test]
	async fn a_signed_server_finished_is_answered_with_a_sealed_client_finished() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let finished = server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral());

		let closing = client.respond(reply(finished)).await?;
		let sealed = closing.encrypted()?;
		assert_eq!(sealed.value().enc_content_info.content_type, SIGNED_DATA);
		Ok(())
	}

	/// A client seals its Finished as an `EncryptedData` of version 0 with no
	/// unprotected attribute, whose algorithm names the cipher with its zero
	/// nonce as an OCTET STRING (RFC 5652 § 8).
	#[tokio::test]
	async fn a_sealed_client_finished_names_the_cipher_and_its_zero_nonce() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let finished = server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral());
		let nonce = Any::encode_from(&OctetString::new([0u8; 12])?)?;
		let algorithm = AlgorithmIdentifierOwned { oid: AES_256_GCM, parameters: Some(nonce) };

		let closing = client.respond(reply(finished)).await?;

		let sealed = closing.encrypted()?;
		let EncryptedData { version, enc_content_info, unprotected_attrs } = sealed.value();
		assert_eq!(*version, CmsVersion::V0);
		assert_eq!(enc_content_info.content_enc_alg, algorithm);
		assert!(unprotected_attrs.is_none());
		Ok(())
	}

	/// A server ephemeral swapped for another valid point after a real server
	/// signed its Finished changes the transcript, so the Finished signature
	/// fails before any agreement.
	///
	/// The tampered Finished keeps the accept the server signed, so the
	/// ephemeral is the one leg that differs.
	#[tokio::test]
	async fn a_tampered_server_ephemeral_fails_the_cms_finished() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Cms::server(&identity));
		let mut client = Handshake::client(Cms::client(&identity.certificate, &create_test_certificate()));

		let finished = server.reply(client.start()?).await?.signed()?;
		let accept = SecurityAccept::new(create_default_test_profile());
		let swapped = unsigned_attrs(vec![attribute(&accept), attribute(&fresh_server_ephemeral())]);
		let tampered = with_unsigned_attrs(finished.value().to_owned(), Some(swapped));

		let result = client.respond(reply(tampered)).await;
		assert!(matches!(result, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A server Finished whose accept was stripped after the server signed it
	/// fails its signature. The client verifies the signature before it reads
	/// the selection, so the refusal names the signature and not the selection.
	#[tokio::test]
	async fn a_stripped_accept_fails_the_cms_finished() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Cms::server(&identity));
		let mut client = Handshake::client(Cms::client(&identity.certificate, &create_test_certificate()));

		let finished = server.reply(client.start()?).await?.signed()?;
		let ephemeral = finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?;
		let ephemeral = ephemeral.decode::<OriginatorPublicKey>()?;
		let stripped = unsigned_attrs(vec![attribute(&ephemeral)]);
		let tampered = with_unsigned_attrs(finished.value().to_owned(), Some(stripped));

		let result = client.respond(reply(tampered)).await;
		assert!(matches!(result, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A server Finished without the ephemeral attribute is refused before
	/// the transcript seals, so no session forms without the agreement.
	#[tokio::test]
	async fn a_missing_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let finished = server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral());
		let stripped = with_unsigned_attrs(finished, None);

		let result = client.respond(reply(stripped)).await;
		assert!(matches!(result, Err(HandshakeError::MissingAttribute)));
	}

	/// A server Finished that carries an abort alert is refused before any
	/// attribute is read.
	#[tokio::test]
	async fn a_server_finished_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let finished = server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral());
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, Any::encode_from(&4u8)?)?;
		let alerted = with_unsigned_attrs(finished, Some(unsigned_attrs(vec![alert])));

		let result = client.respond(reply(alerted)).await;
		let expected = HandshakeAlert::DecryptFail;
		assert!(matches!(result, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A validly signed server Finished that selects no profile is refused, so
	/// no session forms without an agreed profile.
	#[tokio::test]
	async fn a_server_finished_without_a_security_accept_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let ephemeral = fresh_server_ephemeral();
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(&ephemeral)?;
		let transcript = [key_exchange.der(), ephemeral_bytes.as_slice()].concat();
		let attrs = unsigned_attrs(vec![attribute(&ephemeral)]);
		let finished = signed_server_finished(&server.signing_key, &transcript, attrs);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	/// A validly signed server Finished that selects a profile outside the
	/// client's offer is refused.
	#[tokio::test]
	async fn a_client_refuses_a_profile_it_did_not_offer() {
		let server = create_test_certificate();
		let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() };
		let offer = SecurityOffer::new(vec![foreign]);
		let (mut client, key_exchange) = client_after_key_exchange(&server, Some(offer));
		let finished = server_finished_over(&server.signing_key, &key_exchange, &fresh_server_ephemeral());

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// A validly signed server ephemeral that encodes the identity point is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_identity_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let identity = with_point(fresh_server_ephemeral(), &[0x00]);
		let finished = server_finished_over(&server.signing_key, &key_exchange, &identity);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral whose x-coordinate lies off the
	/// curve is refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let off_curve = with_point(fresh_server_ephemeral(), &off_curve_point());
		let finished = server_finished_over(&server.signing_key, &key_exchange, &off_curve);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, key_exchange) = client_after_key_exchange(&server, None);
		let static_key = server.signing_key.verifying_key().originator_key()?;
		let finished = server_finished_over(&server.signing_key, &key_exchange, &static_key);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A server answers a hand-built key exchange with a Finished that
	/// verifies under its static key. Its content is the server role over the
	/// hash of three legs, in this order:
	///
	/// 1. the key exchange as it was sent,
	/// 2. the accept, and
	/// 3. the server ephemeral.
	///
	/// No client reads the Finished, so a server that binds another layout
	/// fails here even when a client binds the same one.
	#[tokio::test]
	async fn a_hand_built_key_exchange_is_answered_with_a_signed_server_finished() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, server_public_key) = server_with(&identity, PeerAuthentication::Anonymous);
		let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, []);
		let message = opening(key_exchange);
		let sent = message.der().to_vec();

		let finished = server.reply(message).await?.signed()?;
		let content = finished_processor(&identity).process(finished.value(), &HASH_SHA3_256)?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?;
		let ephemeral = HandshakeAttribute::transcript_bytes(&ephemeral.decode::<OriginatorPublicKey>()?)?;
		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral].concat())?;
		assert_eq!(content, FinishedRole::Server.content(&expected));
		Ok(())
	}

	/// A key exchange whose attribute SET OF arrives out of DER order decodes
	/// to the same value, and the server binds the bytes that arrived in the
	/// envelope rather than a sorted re-encoding.
	#[tokio::test]
	async fn the_transcript_binds_the_key_exchange_as_it_arrived() -> Result<(), Box<dyn Error>> {
		let (mut server, server_public_key) = anonymous_server();
		let attrs = [marker_attribute(1), marker_attribute(2)];
		let sent = misordered_der(&build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, attrs));
		let key_exchange = received_through_envelope(&sent);
		assert_ne!(key_exchange.value().to_der()?, sent);

		let opening = HandshakeMessage::EnvelopedData(Box::new(key_exchange));
		let server_finished = server.reply(opening).await?.signed()?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = server_finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?.received_bytes()?;

		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral].concat())?;
		assert_eq!(signed_transcript(server_finished.value()), expected);
		Ok(())
	}

	/// A KARI originator key whose x-coordinate lies off the curve is refused
	/// at the parse, before the static agreement runs on it.
	#[tokio::test]
	async fn an_off_curve_originator_key_is_refused() {
		let (mut server, server_public_key) = anonymous_server();
		let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, []);
		let rewritten = with_originator_point(key_exchange, &off_curve_point());

		let refusal = server.reply(opening(rewritten)).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A CMS Finished names its signer by the identifier of its public key, so
	/// a signature is the provider's signature over the prehash beside that
	/// key, fetched once.
	#[tokio::test]
	async fn a_cms_signature_fetches_the_signer_public_key_once() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let verifying_key = *identity.signing_key.verifying_key();
		let signer_spki = verifying_key.to_public_key_der()?;
		let provider = CountingProvider::new(identity.signing_key);
		let prehash = [0x42u8; 32];
		let signed = <Cms as HandshakeFlow>::sign(&provider, &prehash).await?;

		let signature = Secp256k1Signature::try_from(signed.signature.as_slice())?;
		signature.verify_prehash(&verifying_key, prehash)?;
		assert_eq!(signed.signer_spki, signer_spki.as_bytes());
		assert_eq!(provider.public_keys(), 1);
		Ok(())
	}

	/// A client that names its static key as the KARI originator leaves the
	/// session to the secrecy of that one key, so the server refuses the
	/// closing whose certificate holds that key.
	#[tokio::test]
	async fn an_originator_key_equal_to_the_client_static_key_is_refused() {
		let identity = create_test_certificate();
		let client = create_test_certificate();
		let static_key = SecretKey::<Secp256k1>::from(&client.signing_key);
		let mut awaiting = awaiting_finished(&identity, PeerAuthentication::Anonymous, static_key).await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// An offered certificate whose key is off the curve is refused where the
	/// opened Finished is parsed, before the offer compares the originator.
	#[tokio::test]
	async fn an_offered_certificate_whose_key_is_off_the_curve_is_refused() {
		let mut awaiting = server_awaiting_finished().await;
		let mut client = create_test_certificate();

		put_off_curve_key(&mut client.certificate);

		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// The container an HPKE closing travels in, as an on-path party would
	/// send it to a CMS server.
	fn hpke_key_exchange() -> HandshakeMessage {
		let sealed_payload = OctetString::new([0x41u8; 32]).expect("bytes are an OCTET STRING");
		let key_exchange = ClientKeyExchange { sealed_payload, unprotected_attrs: None };
		HandshakeMessage::try_from(key_exchange).expect("the key exchange encodes")
	}

	/// An HPKE key exchange sent to a CMS server as its opening is refused
	/// before any key is read.
	#[tokio::test]
	async fn a_cms_server_refuses_an_hpke_key_exchange_as_its_opening() {
		let (mut server, _) = anonymous_server();
		let refusal = server.reply(hpke_key_exchange()).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// An HPKE key exchange sent to a CMS server as its closing is refused
	/// before the server opens anything.
	#[tokio::test]
	async fn a_cms_server_refuses_an_hpke_key_exchange_as_its_closing() {
		let mut awaiting = server_awaiting_finished().await;
		let refusal = awaiting.server.finish(hpke_key_exchange()).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// A key exchange that carries an abort alert is refused before any
	/// negotiation runs.
	#[tokio::test]
	async fn a_key_exchange_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let (mut server, server_public_key) = anonymous_server();
		let code = Any::encode_from(&3u8)?;
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, code)?;
		let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [alert]);

		let refusal = server.reply(opening(key_exchange)).await;
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A key exchange carrying a duplicate SecurityOffer attribute fails
	/// closed rather than reading as no offer and falling through to dealer's
	/// choice, matching the client's fail-closed behaviour.
	#[tokio::test]
	async fn a_duplicate_security_offer_fails_closed() -> Result<(), Box<dyn Error>> {
		let (mut server, server_public_key) = anonymous_server();
		let native = create_default_test_profile();
		let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..native };
		let first = HandshakeAttribute::encode(&SecurityOffer::new(vec![native]))?;
		let second = HandshakeAttribute::encode(&SecurityOffer::new(vec![foreign]))?;
		let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [first, second]);

		let result = server.reply(opening(key_exchange)).await;
		assert!(matches!(result, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A key exchange carrying a duplicate TransportOffer attribute fails
	/// closed the same way, rather than reading as no offer and leaving the
	/// connection single-flight.
	#[tokio::test]
	async fn a_duplicate_transport_offer_fails_closed() -> Result<(), Box<dyn Error>> {
		let (mut server, server_public_key) = anonymous_server();
		let first = HandshakeAttribute::encode(&TransportOffer::mux(4))?;
		let second = HandshakeAttribute::encode(&TransportOffer::mux(8))?;
		let key_exchange = build_test_key_exchange(&server_public_key, &TEST_BASE_SECRET, [first, second]);

		let result = server.reply(opening(key_exchange)).await;
		assert!(matches!(result, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A hand-built client Finished over the transcript hash the server
	/// sealed, sealed as a client seals it, closes the handshake.
	#[tokio::test]
	async fn a_hand_built_client_finished_closes_the_handshake() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		awaiting.server.finish(closing).await?;
		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	/// A client Finished is a proof, so a closing that names no certificate to
	/// verify it under is refused, even by a server that demands no identity.
	#[tokio::test]
	async fn a_finished_with_no_certificate_is_refused() {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let signed = signed_finished(FinishedRole::Client, &client.signing_key, awaiting.transcript_hash());
		let tag = unsigned_attrs(vec![attribute(&awaiting.confirmation)]);
		let unidentified = with_unsigned_attrs(signed, Some(tag));
		let closing = awaiting.sealed(&unidentified);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	/// A client Finished that carries no key-confirmation tag is refused when
	/// it is opened. The tag is mandatory, so no closing reaches the agreement
	/// unconfirmed.
	#[tokio::test]
	async fn a_finished_with_no_key_confirmation_is_refused() {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let unconfirmed = with_unsigned_attrs(finished, None);
		let closing = awaiting.sealed(&unconfirmed);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
	}

	/// A key-confirmation tag of another width fails to decode, so the server
	/// refuses the Finished when it opens it and admits no further step.
	#[tokio::test]
	async fn a_finished_with_a_short_key_confirmation_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let short_tag = Any::encode_from(&OctetString::new([7u8; 31])?)?;
		let short = HandshakeAttribute::new_single(KeyConfirmation::OID, short_tag)?;
		let shortened = with_unsigned_attrs(finished, Some(unsigned_attrs(vec![short])));
		let closing = awaiting.sealed(&shortened);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::DerError(_))));
		assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// A client Finished whose tag confirms another handshake secret is
	/// refused, and the server admits no further step. The Finished signature
	/// would verify, so the tag is what refuses it.
	#[tokio::test]
	async fn a_finished_that_confirms_another_secret_is_refused() {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &fixture_confirmation());
		let closing = awaiting.sealed(&finished);

		let refused = awaiting.server.finish(closing.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);

		let replayed = awaiting.server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
	}

	/// A budget-bearing closing altered in flight fails to open, so it is
	/// refused ahead of settlement and the observer hears of no outcome. The
	/// tag and the countersignature both ride inside the sealed Finished, so
	/// an on-path party can change neither alone.
	#[tokio::test]
	async fn an_altered_sealed_finished_settles_nothing() -> Result<(), Box<dyn Error>> {
		let Parties { mut client, mut server, .. } = parties::<Cms>(mutual_with(ExpiryValidator));
		let observer = Arc::new(CountingObserver::default());
		client.transport_offer = Some(budget_offer());
		client.receipt_approver = Some(Arc::new(PayingApprover));
		server.transport = Some(budget_offer());
		server.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));
		server.session_observer = Some(observer.to_owned());

		let mut client = Handshake::client(client);
		let mut server = Handshake::server(server);

		let reply = server.reply(client.start()?).await?;
		let sealed = client.respond(reply).await?.encrypted()?;
		let altered = with_flipped_content(sealed.value().to_owned());

		let refusal = server.finish(HandshakeMessage::try_from(altered)?).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		assert_eq!(server.phase(), HandshakePhase::Spent);
		assert_eq!(observer.outcomes(), 0);
		Ok(())
	}

	/// A client Finished signed over another transcript hash is refused, so a
	/// Finished from another handshake cannot close this one.
	#[tokio::test]
	async fn a_finished_over_another_transcript_is_refused() {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let foreign = build_test_client_finished(&client, &[0x5au8; 32], &awaiting.confirmation);
		let closing = awaiting.sealed(&foreign);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// An on-path party holds the public transcript and no handshake secret,
	/// so a Finished it forges under its own certificate seals under another
	/// key and fails to open (CWE-287, CWE-345). The refusal spends the
	/// handshake, so the forger gets no second closing.
	#[tokio::test]
	async fn a_finished_sealed_without_the_handshake_secret_is_refused() -> Result<(), Box<dyn Error>> {
		let (mut client, mut server) = pair::<Cms>(mutual_with(ExpiryValidator));
		let server_finished = server.reply(client.start()?).await?.signed()?;
		let transcript_hash = signed_transcript(server_finished.value());

		// The forger signs over the real transcript, which an expiry-only
		// validator would accept, and seals under a secret it chose.
		let forger = create_test_certificate();
		let forged = build_test_client_finished(&forger, &transcript_hash, &fixture_confirmation());
		let sealer = foreign_identity_sealer(&transcript_hash);

		let refusal = server.finish(sealed_closing(sealer, &forged)).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		assert_eq!(server.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// The server's own Finished, returned as the client's with the server
	/// certificate and the client's key-confirmation tag attached, fails
	/// because each Finished signs its role. The expiry-only validator accepts
	/// the server certificate.
	#[tokio::test]
	async fn a_reflected_server_finished_is_refused() {
		let server_identity = create_test_certificate();
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		let mutual = mutual_with(ExpiryValidator);

		// The reflected Finished embeds the server certificate, which the
		// validator accepts. The tag confirms the secret the server derives,
		// so the refusal is the role mismatch in the signature.
		let mut awaiting = awaiting_finished(&server_identity, mutual, ephemeral).await;
		let reflected = with_certificate(awaiting.server_finished.to_owned(), &server_identity.certificate);
		let reflected = with_confirmation(reflected, &awaiting.confirmation);
		let closing = awaiting.sealed(&reflected);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A sealed client Finished that carries an abort alert beside it is
	/// refused before the server opens it.
	///
	/// The content is sealed under a key the server does not derive, and the
	/// refusal names the alert, so the alert is read first.
	#[tokio::test]
	async fn a_client_finished_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let sealer = foreign_identity_sealer(awaiting.transcript_hash());
		let sealed = sealed_finished(sealer, &finished);
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, Any::encode_from(&5u8)?)?;
		let attrs = unsigned_attrs(vec![alert]);
		let alerted = EncryptedData { version: CmsVersion::V2, unprotected_attrs: Some(attrs), ..sealed };

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(alerted)?).await;
		let expected = HandshakeAlert::FinishedIntegrityFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A sealed Finished that names another content type is refused before
	/// its content opens.
	#[tokio::test]
	async fn a_sealed_finished_of_another_content_type_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		sealed.enc_content_info.content_type = DATA;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		Ok(())
	}

	/// A sealed Finished that names another algorithm is refused before its
	/// content opens.
	#[tokio::test]
	async fn a_sealed_finished_under_another_algorithm_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		sealed.enc_content_info.content_enc_alg.oid = AES_128_GCM;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		Ok(())
	}

	/// A sealed Finished whose algorithm carries another nonce is refused
	/// before its content opens.
	#[tokio::test]
	async fn a_sealed_finished_under_another_nonce_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		let nonce = Any::encode_from(&OctetString::new([0x01u8; 12])?)?;

		sealed.enc_content_info.content_enc_alg.parameters = Some(nonce);

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		Ok(())
	}

	/// A sealed Finished that carries no content is refused.
	#[tokio::test]
	async fn a_sealed_finished_with_no_content_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		sealed.enc_content_info.encrypted_content = None;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity)));
		Ok(())
	}

	/// A client Finished that carries the acknowledgement twice is refused
	/// before either value is read, because every handshake attribute is
	/// single-use (CWE-694).
	#[tokio::test]
	async fn a_finished_with_a_duplicate_acknowledgement_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let confirmation = awaiting.confirmation.to_owned();
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &confirmation);
		let first = HandshakeAttribute::encode(&OctetString::new([0x41u8; 48])?)?;
		let second = HandshakeAttribute::encode(&OctetString::new([0x42u8; 48])?)?;
		let attributes = vec![attribute(&confirmation), first, second];
		let duplicated = with_unsigned_attrs(finished, Some(unsigned_attrs(attributes)));
		let closing = awaiting.sealed(&duplicated);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A server that issued a receipt refuses a client Finished that carries
	/// no countersignature, and its observer records the concluded exchange,
	/// so a withheld countersignature leaves evidence (CWE-778).
	#[tokio::test]
	async fn a_withheld_countersignature_is_refused_and_recorded() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let observer = Arc::new(CountingObserver::default());
		let mut config = Cms::server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);
		config.transport = Some(budget_offer());
		config.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));
		config.session_observer = Some(observer.to_owned());

		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		let offer = HandshakeAttribute::encode(&budget_offer())?;
		let mut awaiting = awaiting_finished_under(&identity, config, ephemeral, [offer]).await;
		let client = create_test_certificate();
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::CountersignatureMissing)));
		assert_eq!(observer.outcomes(), 1);
		Ok(())
	}

	/// A server that granted no budgets issued no receipt, so it refuses a
	/// client Finished that acknowledges one.
	///
	/// The Finished embeds the client certificate, signs the sealed transcript
	/// hash, and confirms the handshake secret, so confirmation and admission
	/// pass and settlement is what refuses.
	#[tokio::test]
	async fn an_acknowledgement_with_no_issued_receipt_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let confirmation = awaiting.confirmation.to_owned();
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &confirmation);
		let ack = HandshakeAttribute::encode(&OctetString::new([0x41u8; 48])?)?;
		let acknowledging = with_unsigned_attrs(finished, Some(unsigned_attrs(vec![attribute(&confirmation), ack])));
		let closing = awaiting.sealed(&acknowledging);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}
}

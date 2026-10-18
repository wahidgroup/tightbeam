//! The CMS flow.
//!
//! CMS exchanges the three containers themselves. The client seals the base
//! secret to the server's certificate key on the opening, so the server
//! identity is provisioned before the handshake starts.
//!
//! ## Opening
//!
//! The opening is an `AuthEnvelopedData` (RFC 5083) with one
//! `KEMRecipientInfo` (RFC 9629) to the server's certificate key. Its content
//! carries the base secret and the client's agreement ephemeral `R`, and its
//! authenticated attributes carry the offers. Each client ephemeral serves one
//! agreement:
//!
//! - The KEM draws its own, whose shared secret derives the key that wraps
//!   the content key alone (RFC 9629 §7).
//! - `R·E` with the server ephemeral feeds the handshake secret.
//!
//! ## Client identity
//!
//! The client Finished embeds the client certificate and signs under its key,
//! so the whole Finished travels sealed under a key of the handshake secret, as
//! an `AuthEnvelopedData` with a `KEKRecipientInfo` (RFC 5652 § 6.2.3). The
//! server's static key opens the base secret alone, so a recording plus that
//! key reads no byte of the identity. The server's closing runs in this order:
//!
//! 1. It opens the sealed Finished under the handshake secret of the reply.
//! 2. `Offer::new` compares `R` with the key of the embedded certificate.
//! 3. The key-confirmation tag is verified, and then the validity, validator, and possession checks run.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::cert::CertificateChoices;
use crate::cms::enveloped_data::OriginatorPublicKey;
use crate::cms::signed_data::{CertificateSet, SignedData};
use crate::constants::TIGHTBEAM_OPENING_UKM_LABEL;
use crate::crypto::cms::{AuthEnvelopedData, Opener, Recipient};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::{CmsSigner, Signed, SignedContent, SignerInfoDraft, SigningIdentity};
use crate::crypto::subtle::ConstantTimeEq;
use crate::der::asn1::{BitString, OctetString};
use crate::der::{Choice, Decode, DecodeValue, Encode, Error as DerError, Sequence};
use crate::oids::{DATA, HANDSHAKE_OPENING_CONTENT, RECEIPT_ACK};
use crate::random::{CryptoRngCore, RngWrapper};
use crate::spki::{EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientLegs, ClosingBinding, ClosingOpened, ClosingParts, HandshakeFlow, Offer, Opened, OpeningIntake,
	OpeningParts, ProofRequest, ReplyBinding, ReplyIntake, ReplyParts, ServerLegs,
};
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
use crate::transport::handshake::peer::{AdmittedServer, PeerCertificate, PossessionProof, ProvisionedTrust};
use crate::transport::handshake::primitives::transcript::{FinishedRole, ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::{KdfSalt, TranscriptHash};
use crate::transport::handshake::schedule::{
	Agreement, BaseSecret, KeyConfirmation, PeerPoint, Salt, Sealer, SecretSeal, Terms,
};
use crate::transport::handshake::{HandshakeCurve, HandshakeMessage, HandshakeProvider, HandshakeSecret};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};

/// The CMS handshake protocol.
///
/// A client is provisioned with [`CmsClientSettings`], and a server with
/// [`CmsServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cms;

impl sealed::Sealed for Cms {}

impl HandshakeFlow for Cms {
	/// The signature over the prehash of a Finished's signed attributes, in
	/// the canonical form the identity returns. The Finished's `SignerInfo`
	/// draft holds the rest.
	type Signed = Vec<u8>;

	fn sign<'a>(
		identity: &'a SigningIdentity,
		prehash: &'a [u8],
	) -> MaybeSendFuture<'a, Result<Self::Signed, HandshakeError>> {
		Box::pin(async move { Ok(identity.sign_prehash(prehash).await?) })
	}
}

/// What a CMS client is provisioned with.
///
/// A CMS client signs its Finished, and the server verifies that signature
/// under the certificate the Finished embeds, so the identity is mandatory.
pub struct CmsClientSettings {
	/// The provisioned server identity, beside the store that admits it.
	pub trust: ProvisionedTrust,
	/// The identity the client presents and signs its Finished under.
	pub identity: SigningIdentity,
}

/// What a CMS client keeps from its opening to read the reply against.
pub struct CmsOpening<C: HandshakeCurve> {
	/// The transcript, open over the opening as it was sent.
	transcript: Transcript,
	/// The server the opening sealed to.
	server: AdmittedServer<C>,
}

/// The secrets a CMS client holds from its opening to the agreement.
pub struct CmsPending<C: HandshakeCurve> {
	/// The base secret the opening carried to the server.
	base: BaseSecret,
	/// The agreement ephemeral `R`, kept for the agreement with the server
	/// ephemeral.
	ephemeral: SecretKey<C>,
}

/// A client Finished that awaits its signature.
pub struct CmsClosingDraft<P: HandshakeProvider> {
	/// The transcript hash the Finished signs.
	transcript_hash: TranscriptHash,
	/// The Finished's `SignerInfo`, complete up to its signature.
	signer: SignerInfoDraft,
	/// The DER of the envelope that seals the receipt countersignature under
	/// the handshake secret.
	sealed_ack: Option<Vec<u8>>,
	/// The proof that the client derived the handshake secret.
	confirmation: KeyConfirmation,
	/// The certificate the Finished embeds, so the server can verify it.
	certificate: Certificate,
	/// The single-use seal the Finished, with its certificate, is sealed
	/// under.
	identity_sealer: Sealer<P>,
}

/// The content of a CMS opening, under the content type
/// [`HANDSHAKE_OPENING_CONTENT`]: the base secret and the client's agreement
/// ephemeral `R`.
///
/// ```text
/// OpeningContent ::= SEQUENCE {
///   baseSecret    OCTET STRING (SIZE (32)),
///   agreementKey  OriginatorPublicKey }
/// ```
#[derive(Sequence)]
pub(crate) struct OpeningContent {
	/// The base secret, one of the two inputs of the handshake secret.
	pub(crate) base_secret: OctetString,
	/// The public half of `R`, which agrees with the server ephemeral.
	pub(crate) agreement_key: OriginatorPublicKey,
}

/// Carriage of a public key as a CMS `OriginatorPublicKey`
/// ([RFC 5652 § 6.2.2][rfc5652-6.2.2]).
///
/// The opening carries the client's agreement ephemeral this way from its
/// SPKI, and the server Finished carries the server ephemeral the same way from
/// the public key itself, so the mapping has one home.
///
/// [rfc5652-6.2.2]: https://datatracker.ietf.org/doc/html/rfc5652#section-6.2.2
trait OriginatorKey {
	/// What fails on the way from this key to its originator form.
	type Error;

	/// This key as an originator: its algorithm identifier and its public key
	/// bits.
	fn originator_key(self) -> Result<OriginatorPublicKey, Self::Error>;
}

impl OriginatorKey for SubjectPublicKeyInfoOwned {
	type Error = DerError;

	/// # Errors
	///
	/// - [`DerError`] -- the key bits fail to re-encode as a BIT STRING.
	fn originator_key(self) -> Result<OriginatorPublicKey, DerError> {
		let public_key = BitString::from_bytes(self.subject_public_key.raw_bytes())?;
		Ok(OriginatorPublicKey { algorithm: self.algorithm, public_key })
	}
}

impl<K> OriginatorKey for &K
where
	K: EncodePublicKey,
{
	type Error = SpkiError;

	/// # Errors
	///
	/// - [`SpkiError`] -- the key fails to encode as an SPKI, or its bits fail to re-encode as a BIT STRING.
	fn originator_key(self) -> Result<OriginatorPublicKey, SpkiError> {
		let spki_der = self.to_public_key_der()?;
		let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())?;
		Ok(spki.originator_key()?)
	}
}

impl Cms {
	/// `finished` sealed under `identity_sealer` as the `AuthEnvelopedData` a
	/// client sends, with one `KEKRecipientInfo` (RFC 5083, RFC 5652 § 6.2.3).
	///
	/// # Errors
	///
	/// - The [`Sealer::seal`] set.
	/// - [`HandshakeError::DerError`] -- the Finished fails to encode.
	fn seal_finished<P: HandshakeProvider>(
		identity_sealer: Sealer<P>,
		finished: &SignedData,
	) -> Result<AuthEnvelopedData, HandshakeError> {
		let finished_der = finished.to_der()?;
		identity_sealer.seal(finished_der)
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

	/// Verify that `finished` is signed by `certificate` under `key` and that
	/// `role` signed `transcript_hash`.
	///
	/// The `SignedData` carries one `SignerInfo` with the signed attributes
	/// of the CMS signer over content of type `id-data`. A Finished whose
	/// content names the other role is a reflected Finished.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the Finished
	///   carries another number of signers, fails the signer's checks, or
	///   signs another role or another transcript.
	/// - [`HandshakeError::DerError`] -- a signed attribute fails to encode.
	/// - [`HandshakeError::CertificateValidationError`] -- the key identifier fails to decode.
	fn verify_finished<P: HandshakeProvider>(
		role: FinishedRole,
		finished: &SignedData,
		certificate: &Certificate,
		key: P::VerifyingKey,
		transcript_hash: &TranscriptHash,
	) -> Result<(), HandshakeError> {
		let content = CmsSigner::content(finished, DATA)?;
		let [signer_info] = finished.signer_infos.0.as_ref() else {
			return Err(HandshakeError::SignatureVerificationFailed);
		};

		// The transcript hash a Finished signs is fresh for each handshake, so
		// its verified signature is the key of no ledger and drops here.
		let signed_content = SignedContent::data(content);
		let verifying = CmsSigner::verify_signer::<P::Signature, _>;
		verifying(signer_info, certificate, &key, signed_content).map(drop)?;

		let signed = role.transcript_hash(content);
		let signed_hash = signed.ok_or(HandshakeError::SignatureVerificationFailed)?;
		let transcript_matches: bool = signed_hash.ct_eq(transcript_hash.as_bytes()).into();
		if !transcript_matches {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		Ok(())
	}

	/// Draft the `SignerInfo` of the Finished that `identity` signs for
	/// `role` over `transcript_hash`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- a signed attribute fails to encode.
	fn finished_draft(
		identity: &SigningIdentity,
		role: FinishedRole,
		transcript_hash: &TranscriptHash,
	) -> Result<SignerInfoDraft, HandshakeError> {
		let content = role.content(transcript_hash);
		Ok(identity.draft(SignedContent::data(&content))?)
	}

	/// Build the Finished of `role`: the `SignedData` over the role-bound
	/// transcript hash, with `signature` completing `draft` and
	/// `unsigned_attrs` attached to its `SignerInfo`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the content, a SET, or the signature fails to encode.
	fn finished(
		role: FinishedRole,
		transcript_hash: &TranscriptHash,
		draft: SignerInfoDraft,
		signature: Vec<u8>,
		unsigned_attrs: Attributes,
		certificate: Option<Certificate>,
	) -> Result<Signed<SignedData>, HandshakeError> {
		let signer_info = draft.complete(signature, Some(unsigned_attrs))?;
		let certificates = match certificate {
			Some(certificate) => {
				let choice = CertificateChoices::Certificate(certificate);
				Some(CertificateSet(vec![choice].try_into()?))
			}
			None => None,
		};

		let content = role.content(transcript_hash);
		Ok(CmsSigner::signed_data(
			SignedContent::data(&content),
			signer_info,
			certificates,
		)?)
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
	type Settings = CmsClientSettings;
	type Trust = ProvisionedTrust;
	type Opening = CmsOpening<P::Curve>;
	type Pending = Box<CmsPending<P::Curve>>;
	type Reply = WireDer<SignedData>;
	type Agreed = ();
	type Draft = CmsClosingDraft<P>;

	fn identity(settings: &Self::Settings) -> Option<&SigningIdentity> {
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

		// 2. Draw the agreement ephemeral `R`, kept for the agreement with the
		//    server ephemeral. The KEM draws the key it seals under itself.
		let ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(&mut *rng));
		let ephemeral_spki = SubjectPublicKeyInfoOwned::from_key(ephemeral.public_key())?;

		// 3. Encode the content. The DER buffer holds the base secret, so it
		//    wipes when dropped, along with the transient OCTET STRING copy.
		let base_secret = OctetString::new(base.as_bytes())?;
		let content = OpeningContent { base_secret, agreement_key: ephemeral_spki.originator_key()? };
		let content_der = Zeroizing::new(content.to_der()?);
		content.base_secret.into_bytes().zeroize();

		// 4. Seal the content to the admitted server's certificate key, with
		//    each offer as an authenticated attribute. The client certificate
		//    travels only in the sealed Finished.
		let mut offers = Vec::new();
		if let Some(offer) = parts.security_offer {
			offers.push(Attribute::try_from(HandshakeAttribute::encode(offer)?)?);
		}
		if let Some(offer) = parts.transport_offer {
			offers.push(Attribute::try_from(HandshakeAttribute::encode(offer)?)?);
		}

		let certificate = server.identity().certificate();
		let recipient = Recipient::Kem { certificate, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
		let content_type = HANDSHAKE_OPENING_CONTENT;
		let sealed = AuthEnvelopedData::seal::<P>(recipient, content_type, content_der.as_slice(), offers, Some(rng))?;

		// 5. Encode the opening once, so the transcript binds the bytes sent.
		let opening = WireDer::new(sealed)?;
		let mut transcript = Transcript::new();
		transcript.append(opening.der())?;

		let message = HandshakeMessage::AuthEnvelopedData(Box::new(opening));
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
		let received_artifact = ReceivedAttribute::<Signed<SignedData>>::extract(finished)?;
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
		server: &PeerCertificate<P::Curve>,
		transcript_hash: &TranscriptHash,
	) -> Result<(), HandshakeError> {
		let key = P::VerifyingKey::from(*server.key());
		Self::verify_finished::<P>(FinishedRole::Server, reply.value(), server.certificate(), key, transcript_hash)
	}

	fn agree(
		pending: Self::Pending,
		server_ephemeral: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<(HandshakeSecret, Self::Agreed), HandshakeError> {
		// The secrets are read in place, so each is wiped where the box drops.
		let CmsPending { base, ephemeral } = pending.as_ref();
		let agreement = Agreement::<P>::new(server_ephemeral, base);
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
		let signer = Self::finished_draft(identity, FinishedRole::Client, transcript_hash)?;
		let proof = ProofRequest { prehash: signer.prehash().to_vec(), signer: identity };
		let certificate = identity.certificate().clone();

		let transcript_hash = *transcript_hash;
		let draft = CmsClosingDraft { transcript_hash, signer, sealed_ack, confirmation, certificate, identity_sealer };
		Ok(ClosingBinding { proof: Some(proof), draft })
	}

	fn encode_closing(draft: Self::Draft, proof: Option<Vec<u8>>) -> Result<HandshakeMessage, HandshakeError> {
		let CmsClosingDraft { transcript_hash, signer, sealed_ack, confirmation, certificate, identity_sealer } = draft;
		let signature = proof.ok_or(HandshakeError::MutualAuthRequired)?;

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

		let finished = Self::finished(role, &transcript_hash, signer, signature, unsigned_attrs, Some(certificate))?;

		// The Finished embeds the certificate and signs under its key, so the
		// whole Finished is sealed under the identity key of the handshake
		// secret, and both cross the wire sealed.
		let sealed = Self::seal_finished(identity_sealer, &finished)?;
		HandshakeMessage::try_from(sealed)
	}
}

/// What a CMS server is provisioned with.
///
/// The shared server configuration covers the whole protocol: its signing
/// identity signs the Finished, and the identity's key opens the opening.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmsServerSettings;

/// A decoded opening that awaits the static open.
pub struct CmsSealed {
	/// The opening, whose `KEMRecipientInfo` wraps the content key.
	opening: WireDer<AuthEnvelopedData>,
	/// The transcript, open over the opening as it arrived.
	transcript: Transcript,
}

/// What a CMS server holds from the static open to its Finished.
pub struct CmsOpened<C: HandshakeCurve> {
	/// The base secret the opening carried.
	base: BaseSecret,
	/// The client's agreement ephemeral `R`, parsed once at the open as a
	/// point of the curve.
	client_ephemeral: PeerPoint<C>,
	/// The transcript, open over the opening.
	transcript: Transcript,
}

/// A server Finished that awaits its signature and its receipt.
pub struct CmsReplyDraft {
	transcript_hash: TranscriptHash,
	/// The Finished's `SignerInfo`, complete up to its signature.
	signer: SignerInfoDraft,
	security_accept: SecurityAccept,
	transport_accept: Option<TransportAccept>,
	server_ephemeral: OriginatorPublicKey,
}

/// What a CMS server holds from its Finished to the client Finished.
pub struct CmsServerPending<C: HandshakeCurve> {
	/// The handshake secret, derived when the server Finished was built.
	secret: HandshakeSecret,
	/// The client's agreement ephemeral `R`, which the offer compares with the
	/// identity's key.
	client_ephemeral: PublicKey<C>,
}

/// A decoded client closing, with what the reply left for its open.
pub struct CmsClosing<C: HandshakeCurve> {
	/// The client Finished, sealed under the identity key of the handshake
	/// secret, as it arrived.
	sealed: WireDer<AuthEnvelopedData>,
	/// The handshake secret, derived when the server Finished was built.
	secret: HandshakeSecret,
	/// The client's agreement ephemeral `R`.
	client_ephemeral: PublicKey<C>,
}

/// The CMS client Finished as the proof that the key of its embedded
/// certificate signed it.
pub struct CmsFinished(SignedData);

impl<P: HandshakeProvider> PossessionProof<P> for CmsFinished {
	/// The Finished verifies when its one signer names the offered
	/// certificate and verifies under its key, and its signed content is the
	/// client role over the sealed transcript hash.
	fn verify(self, identity: &PeerCertificate<P::Curve>, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let key = P::VerifyingKey::from(*identity.key());
		let certificate = identity.certificate();
		Cms::verify_finished::<P>(FinishedRole::Client, &self.0, certificate, key, terms.transcript_hash())
	}
}

/// What a CMS server reads from a client Finished beyond its signature.
trait ClientFinished {
	/// The sealed receipt acknowledgement in the SignerInfo unsigned
	/// attributes, as the DER of an `AuthEnvelopedData` under the handshake
	/// secret's acknowledgement key.
	///
	/// Duplicate attributes fail closed.
	fn sealed_receipt_ack(&self) -> Result<Option<OctetString>, HandshakeError>;

	/// The key-confirmation tag in the SignerInfo unsigned attributes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the Finished carries no tag.
	/// - [`HandshakeError::DuplicateAttribute`] -- the tag repeats.
	/// - [`HandshakeError::DerError`] -- the tag is not an OCTET STRING of 32 to 64 bytes.
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
		// 1. Open the transcript over the opening as it arrived.
		let opening = opening.auth_enveloped()?;
		let mut transcript = Transcript::new();
		transcript.append(opening.der())?;

		// 2. Refuse an abort alert before any negotiation or key agreement runs.
		opening.value().unauth_attrs.refuse_alert()?;
		let attrs = opening.value().auth_attrs.as_ref();

		// 3. Read the offers. A duplicate or malformed attribute fails closed,
		//    because one read as absent would fall through to dealer's choice.
		//    The tag authenticates them when the opening opens, and the
		//    transcript binds them as they arrived.
		let security_offer = Self::carried::<SecurityOffer>(attrs)?;
		let transport_offer = Self::carried::<TransportOffer>(attrs)?;

		let sealed = CmsSealed { opening, transcript };
		Ok(OpeningIntake { security_offer, transport_offer, sealed })
	}

	fn open_opening<'a>(
		sealed: Self::Sealed,
		identity: &'a SigningIdentity,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>> {
		Box::pin(async move {
			let CmsSealed { opening, transcript } = sealed;

			// 1. Open the content under the key of the server's certificate.
			//    The opener refuses another recipient kind, another `ukm`
			//    purpose, and an algorithm outside the profile before the key
			//    provider runs, and the tag before any byte of the content is
			//    read.
			let opener = Opener::Kem { identity, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
			let (arrived, opening) = opening.into_parts();
			let content = opening.open::<P>(arrived, &opener, HANDSHAKE_OPENING_CONTENT).await?;
			let OpeningContent { base_secret, agreement_key } = content.with(|der| OpeningContent::from_der(der))?;

			// 2. Parse the base secret. The decoded buffer moves into its
			//    wiping wrapper without a copy (CWE-226).
			let base = BaseSecret::try_from(SecretSlice::from(base_secret.into_bytes()))?;

			// 3. Parse `R`. A malformed, off-curve, or identity point is
			//    refused here, ahead of the agreement. The comparison with the
			//    client's static key waits for the identity, which opens at the
			//    closing.
			let client_ephemeral = PeerPoint::parse(agreement_key.public_key.raw_bytes())?;

			// The base secret crosses the signature and receipt awaits in the
			// orchestrator. It is boxed, so that move copies a pointer.
			Ok(Box::new(CmsOpened { base, client_ephemeral, transcript }))
		})
	}

	fn bind_reply(
		opened: &mut Self::Opened,
		_settings: &Self::Settings,
		parts: ReplyParts<'_, P>,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<ReplyBinding<Self, P>, HandshakeError> {
		let ReplyParts { identity, profile, transport_accept, server_ephemeral, .. } = parts;

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

		// 3. Draft the Finished's SignerInfo, which names the digest the server signs.
		let signer = Self::finished_draft(identity, FinishedRole::Server, &transcript_hash)?;
		let prehash = signer.prehash().to_vec();
		let transport_accept = transport_accept.copied();
		let draft = CmsReplyDraft { transcript_hash, signer, security_accept, transport_accept, server_ephemeral };
		Ok(ReplyBinding { transcript_hash, salt: Salt::transcript_hash(), prehash, draft })
	}

	fn encode_reply(
		draft: Self::Draft,
		signature: Vec<u8>,
		artifact: Option<&Signed<SignedData>>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let CmsReplyDraft { transcript_hash, signer, security_accept, transport_accept, server_ephemeral } = draft;

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

		let finished = Self::finished(role, &transcript_hash, signer, signature, unsigned_attrs, None)?;
		HandshakeMessage::try_from(finished.into_inner())
	}

	fn pend(
		opened: Self::Opened,
		ephemeral: Box<EphemeralSecret<P::Curve>>,
		terms: &Terms<P>,
	) -> Result<Self::Pending, HandshakeError> {
		// The base secret, the ephemeral, and the transcript drop here. Both
		// secrets are read in place, so each is wiped where its box drops.
		// The server Finished itself is not part of the sealed transcript.
		let agreement = Agreement::<P>::new(&opened.client_ephemeral, &opened.base);

		let secret = agreement.settle(ephemeral.as_ref(), terms.kdf_salt())?;
		let client_ephemeral = *opened.client_ephemeral.as_public_key();
		Ok(CmsServerPending { secret, client_ephemeral })
	}

	fn read_closing(
		pending: Self::Pending,
		_settings: &Self::Settings,
		closing: HandshakeMessage,
	) -> Result<Self::Closing, HandshakeError> {
		// Take the sealed client Finished, and refuse one that carries an
		// abort alert. The seal covers every other part of the closing.
		let sealed = closing.auth_enveloped()?;
		sealed.value().unauth_attrs.refuse_alert()?;

		let CmsServerPending { secret, client_ephemeral } = pending;
		Ok(CmsClosing { sealed, secret, client_ephemeral })
	}

	fn settle<'a>(
		closing: Self::Closing,
		terms: &'a Terms<P>,
		_identity: &'a SigningIdentity,
	) -> MaybeSendFuture<'a, Result<ClosingOpened<Self, P>, HandshakeError>> {
		// The handshake secret was derived when the server Finished was built,
		// so the open runs under the identity key alone.
		Box::pin(closing.open(terms))
	}
}

impl<C: HandshakeCurve> CmsClosing<C> {
	/// Open the sealed client Finished under the identity key, read the tag,
	/// the receipt countersignature, and the certificate it carries, and build
	/// the offer.
	///
	/// The Finished is a proof, so one that names no certificate is refused,
	/// and the offer refuses an `R` that collapses into the key of the
	/// certificate.
	///
	/// # Errors
	///
	/// - The [`ServerLegs::settle`] set of the CMS flow.
	async fn open<P: HandshakeProvider<Curve = C>>(
		self,
		terms: &Terms<P>,
	) -> Result<ClosingOpened<Cms, P>, HandshakeError> {
		let Self { sealed, secret, client_ephemeral } = self;

		// 1. Open the Finished under the identity key of the secret.
		let identity_sealer = terms.sealer(&secret, SecretSeal::Identity)?;
		let finished_der = identity_sealer.open(sealed.der()).await?;
		let finished = finished_der.with(|der| SignedData::from_der(der))?;

		// 2. Read the key-confirmation tag, which is mandatory, and the sealed receipt acknowledgement.
		let confirmation = finished.key_confirmation()?;
		let sealed_ack = finished.sealed_receipt_ack()?;
		let receipt_ack = sealed_ack.map(OctetString::into_bytes);

		// 3. Parse the certificate once, and build the offer, which compares `R` with its key.
		let certificate = finished.embedded_certificate();
		let certificate = certificate.ok_or(HandshakeError::MissingClientCertificate)?;
		let identity = PeerCertificate::<C>::parse(certificate)?;
		let offer = Offer::new(identity, CmsFinished(finished), [&client_ephemeral])?;
		Ok(ClosingOpened { secret, confirmation, receipt_ack, offer })
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::*;
	use crate::cms::content_info::{CmsVersion, ContentInfo};
	use crate::cms::signed_data::SignerInfo;
	use crate::constants::TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN;
	use crate::crypto::cms::{EnvelopeError, GcmParameters, KemRecipientInfo};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::key::SigningKeyProvider;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::sign::{SignerError, VerifiedSignature};
	use crate::crypto::x509::policy::ExpiryValidator;
	use crate::crypto::x509::utils::CertificateExt;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::Any;
	use crate::der::{Choice, DecodeValue, EncodeValue, Tagged};
	use crate::oids::{AES_128_GCM, AUTH_ENVELOPED_DATA, HANDSHAKE_ABORT_ALERT, HANDSHAKE_SERVER_EPHEMERAL};
	use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST};
	use crate::oids::{SESSION_RECEIPT, SIGNED_DATA};
	use crate::random::OsRng;
	use crate::testing::{Aes256Sha3_512Provider, EnvelopeRecipient, TestAttributes, TestIdentity};
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::negotiation::{RunnableProfile, SecurityOffer};
	use crate::transport::handshake::schedule::TrafficSecret;
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{
		Client, ClientConfig, ClientKeyExchange, CmsServerIdentity, Handshake, HandshakeAlert, HandshakePhase,
		PeerAuthentication, Server, ServerConfig, SupportedProfiles,
	};

	/// The base secret a hand-built opening carries.
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
	/// `opening` followed by the default profile's accept and `ephemeral`, as
	/// a server under dealer's choice sends it.
	fn server_finished_over(
		server_key: &Secp256k1SigningKey,
		opening: &WireDer<AuthEnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> SignedData {
		let accept = SecurityAccept::new(create_default_test_profile());
		let accept_bytes = HandshakeAttribute::transcript_bytes(&accept).expect("an accept has transcript bytes");
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(ephemeral).expect("a key has transcript bytes");
		let transcript = [opening.der(), accept_bytes.as_slice(), ephemeral_bytes.as_slice()].concat();
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
	/// hand from the CMS signer. It carries no unsigned attribute and no
	/// certificate, and its `sid` is the key identifier of `key`, which the
	/// test certificate of `key` carries.
	fn signed_finished(role: FinishedRole, key: &Secp256k1SigningKey, transcript_hash: &TranscriptHash) -> SignedData {
		let content = role.content(transcript_hash);
		let signed = SignedContent::data(&content);
		let key = TestIdentity::certified(key.clone());
		let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&key, signed).expect("the test key signs");

		let finished = CmsSigner::signed_data(SignedContent::data(&content), signer, None);
		let finished = finished.expect("the Finished assembles");
		finished.into_inner()
	}

	/// A client pinned to `server` that has sent its opening under `offer`,
	/// with that opening.
	fn client_after_opening(
		server: &TestCertificate,
		offer: Option<SecurityOffer>,
	) -> (TestClient<Cms>, WireDer<AuthEnvelopedData>) {
		let mut config = Cms::client(&server.certificate, &create_test_certificate());
		config.security_offer = offer;

		let mut client = Handshake::client(config);
		let opening = client.start().expect("a fresh client builds its opening");
		let sealed = opening.auth_enveloped().expect("a CMS opening travels in an AuthEnvelopedData");
		(client, sealed)
	}

	/// The opening message that carries `sealed`.
	fn opening(sealed: AuthEnvelopedData) -> HandshakeMessage {
		let sealed = WireDer::new(sealed).expect("the opening encodes");
		HandshakeMessage::AuthEnvelopedData(Box::new(sealed))
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

	/// `finished` sealed under `sealer` as the `AuthEnvelopedData` a client
	/// sends.
	fn sealed_finished(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> AuthEnvelopedData {
		let sealed = Cms::seal_finished(sealer, finished);
		sealed.expect("the Finished seals")
	}

	/// `octets` with its last byte flipped, as an on-path party would alter
	/// it.
	fn flipped(octets: &OctetString) -> OctetString {
		let mut bytes = octets.as_bytes().to_vec();
		let last = bytes.last_mut().expect("the octets are not empty");
		*last ^= 0x01;
		OctetString::new(bytes).expect("bytes are an OCTET STRING")
	}

	/// `sealed` with the last byte of its encrypted content flipped.
	fn with_flipped_content(mut sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let content = sealed.auth_encrypted_content_info.encrypted_content.as_ref();
		let content = content.expect("a sealed content is present");
		sealed.auth_encrypted_content_info.encrypted_content = Some(flipped(content));
		sealed
	}

	/// `sealed` with the last byte of its tag flipped.
	fn with_flipped_mac(sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let mac = flipped(&sealed.mac);
		AuthEnvelopedData { mac, ..sealed }
	}

	/// `sealed` with a marker attribute among its authenticated attributes.
	fn with_marked_auth_attrs(mut sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let attrs = sealed.auth_attrs.as_ref().expect("an envelope authenticates its content type");
		let mut attributes: Vec<Attribute> = attrs.iter().cloned().collect();
		let marker = Attribute::try_from(marker_attribute(9)).expect("the marker is an attribute");
		attributes.push(marker);

		sealed.auth_attrs = Some(Attributes::try_from(attributes).expect("the attributes are a SET"));
		sealed
	}

	/// The parameters of `sealed` with the last byte of their nonce flipped.
	fn flipped_nonce(sealed: &AuthEnvelopedData) -> Any {
		let algorithm = &sealed.auth_encrypted_content_info.content_enc_alg;
		let parameters = algorithm.parameters.as_ref().expect("AES-GCM carries parameters");
		let parameters = parameters.decode_as::<GcmParameters>();
		let parameters = parameters.expect("the parameters are GCMParameters");
		let parameters = GcmParameters { aes_nonce: flipped(&parameters.aes_nonce), ..parameters };
		Any::encode_from(&parameters).expect("the parameters encode")
	}

	/// `sealed` with the last byte of its nonce flipped.
	fn with_flipped_nonce(mut sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let parameters = flipped_nonce(&sealed);
		sealed.auth_encrypted_content_info.content_enc_alg.parameters = Some(parameters);
		sealed
	}

	/// `sealed` with the last byte of the wrapped content key of its one
	/// `KEKRecipientInfo` flipped.
	fn with_flipped_kek_wrapped_key(sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let mut kek = sealed.kek_recipient();
		kek.encrypted_key = flipped(&kek.encrypted_key);
		sealed.with_kek_recipient(&kek)
	}

	/// `sealed` with `attributes` as its unauthenticated attributes, as a
	/// party outside the seal would attach them.
	fn with_unauth_attrs(
		sealed: AuthEnvelopedData,
		attributes: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AuthEnvelopedData {
		let unauth_attrs = Some(unsigned_attrs(attributes.into_iter().collect()));
		AuthEnvelopedData { unauth_attrs, ..sealed }
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
		transcript_hash: &TranscriptHash,
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

	/// An opening built by hand from the envelope, which seals `base` and a
	/// fresh agreement key to `server` and authenticates `auth_attrs`.
	///
	/// No client builds it, so a server that reads it is tested against the
	/// message format alone.
	fn build_test_opening(
		server: &Certificate,
		base: &[u8],
		auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AuthEnvelopedData {
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		build_test_opening_from(ephemeral, server, base, auth_attrs)
	}

	/// The opening of [`build_test_opening`] under the agreement key
	/// `ephemeral`, for a fixture that keeps that key to derive the handshake
	/// secret.
	fn build_test_opening_from(
		ephemeral: SecretKey<Secp256k1>,
		server: &Certificate,
		base: &[u8],
		auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AuthEnvelopedData {
		let spki = SubjectPublicKeyInfoOwned::from_key(ephemeral.public_key()).expect("a public key has an SPKI");
		let agreement_key = spki.originator_key().expect("an SPKI names an originator key");
		build_test_opening_of(server, base, agreement_key, auth_attrs)
	}

	/// The opening that seals `base` and `agreement_key` to `server`, as the
	/// content of the opening, and authenticates `auth_attrs`.
	fn build_test_opening_of(
		server: &Certificate,
		base: &[u8],
		agreement_key: OriginatorPublicKey,
		auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AuthEnvelopedData {
		let base_secret = OctetString::new(base).expect("bytes are an OCTET STRING");
		let content = OpeningContent { base_secret, agreement_key };
		let content = content.to_der().expect("the content encodes");
		let attributes: Result<Vec<_>, _> = auth_attrs.into_iter().map(Attribute::try_from).collect();
		let attributes = attributes.expect("each handshake attribute is an attribute");
		let recipient = Recipient::Kem { certificate: server, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };

		let sealed = AuthEnvelopedData::seal::<DefaultCryptoProvider>(
			recipient,
			HANDSHAKE_OPENING_CONTENT,
			content,
			attributes,
			None,
		);
		sealed.expect("the opening seals")
	}

	/// An unprotected attribute the server ignores, told apart by `arc`.
	fn marker_attribute(arc: u32) -> HandshakeAttribute {
		let parent = ObjectIdentifier::new_unwrap("1.2.3.4");
		let oid = parent.push_arc(arc).expect("the arc extends the OID");
		let octets = OctetString::new(arc.to_be_bytes()).expect("four bytes fit an OCTET STRING");
		let value = Any::encode_from(&octets).expect("an OCTET STRING encodes");
		HandshakeAttribute::new_single(oid, value).expect("one value makes an attribute")
	}

	/// The DER of `sealed` with its two trailing unauthenticated attributes
	/// swapped out of DER order. It decodes to the same value.
	fn misordered_der(sealed: &AuthEnvelopedData) -> Vec<u8> {
		let canonical = sealed.to_der().expect("the opening encodes");
		let attrs = sealed.unauth_attrs.as_ref();
		let attrs = attrs.expect("the opening carries unauthenticated attributes");
		let [first, second] = attrs.as_slice() else {
			panic!("the opening carries exactly two attributes");
		};

		let first = first.to_der().expect("an attribute encodes");
		let second = second.to_der().expect("an attribute encodes");
		let tail = [first.as_slice(), second.as_slice()].concat();
		let head = canonical.strip_suffix(tail.as_slice());
		let head = head.expect("the attributes end the encoding");

		[head, second.as_slice(), first.as_slice()].concat()
	}

	/// The opening a server reads from `der` sent inside a transport envelope,
	/// decoded the way the transport decodes it.
	fn received_through_envelope(der: &[u8]) -> WireDer<AuthEnvelopedData> {
		let sent = WireDer::<AuthEnvelopedData>::try_from(der).expect("the opening decodes");
		let envelope = TransportEnvelope::AuthEnvelopedData(Box::new(sent));
		let wire = envelope.to_der().expect("the envelope encodes");
		let received = TransportEnvelope::from_der(&wire).expect("the envelope decodes");

		let message = HandshakeMessage::try_from(received).expect("the envelope carries a handshake container");
		message.auth_enveloped().expect("the container is the opening")
	}

	/// A server that holds `identity` under `peer_authentication`, with the
	/// certificate a hand-built opening seals to.
	fn server_with(
		identity: &TestCertificate,
		peer_authentication: PeerAuthentication,
	) -> (TestServer<Cms>, Certificate) {
		let mut config = Cms::server(identity);
		config.peer_authentication = peer_authentication;
		(Handshake::server(config), identity.certificate.to_owned())
	}

	/// A server that demands no client certificate, with the certificate a
	/// hand-built opening seals to.
	fn anonymous_server() -> (TestServer<Cms>, Certificate) {
		server_with(&create_test_certificate(), PeerAuthentication::Anonymous)
	}

	/// A server that has answered a hand-built opening, so it awaits the
	/// client Finished, beside what the client that built the opening holds.
	struct AwaitingFinished {
		/// The server, with its reply sent.
		server: TestServer<Cms>,
		/// The server Finished the reply carried.
		server_finished: SignedData,
		/// The key-confirmation tag of the client that built the opening.
		confirmation: KeyConfirmation,
		/// What the reply confirms, as the client reads it.
		confirming: Confirming,
		/// The agreement key `R` of the opening.
		ephemeral: SecretKey<Secp256k1>,
	}

	impl AwaitingFinished {
		/// The transcript hash the reply sealed.
		fn transcript_hash(&self) -> &TranscriptHash {
			&self.confirming.transcript_hash
		}

		/// The closing that carries `finished`, sealed under the identity key
		/// of the client that built the opening, as that client seals it.
		fn sealed(&self, finished: &SignedData) -> HandshakeMessage {
			let sealed = self.sealed_finished(finished);
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// `finished` sealed as [`Self::sealed`] seals it, before it is
		/// wrapped as a closing.
		fn sealed_finished(&self, finished: &SignedData) -> AuthEnvelopedData {
			let sealer = self.confirming.identity_sealer(&test_base_secret(), &self.ephemeral);
			sealed_finished(sealer, finished)
		}
	}

	/// The identity sealer of a fixture handshake secret, foreign to the
	/// server, over `transcript_hash`.
	fn foreign_identity_sealer(transcript_hash: &TranscriptHash) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::new(transcript_hash.as_bytes());
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
	/// answered a hand-built opening under the agreement key `ephemeral`.
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
	/// hand-built opening under the agreement key `ephemeral` that carries
	/// `offers`.
	async fn awaiting_finished_under(
		identity: &TestCertificate,
		config: TestServerConfig<Cms>,
		ephemeral: SecretKey<Secp256k1>,
		offers: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AwaitingFinished {
		let mut server = Handshake::server(config);
		let sender = ephemeral.to_owned();
		let sealed = build_test_opening_from(sender, &identity.certificate, &TEST_BASE_SECRET, offers);

		let replying = server.reply(opening(sealed)).await;
		let reply = replying.expect("the server answers the opening");
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
			salt: transcript_hash.as_bytes().to_vec(),
			transcript_hash,
		};

		let confirmation = confirming.tag(&test_base_secret(), &ephemeral);
		let server_finished = server_finished.value().to_owned();
		AwaitingFinished { server, server_finished, confirmation, confirming, ephemeral }
	}

	/// A server that demands no client certificate and awaits the client
	/// Finished of a fresh agreement key.
	async fn server_awaiting_finished() -> AwaitingFinished {
		let identity = create_test_certificate();
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		awaiting_finished(&identity, PeerAuthentication::Anonymous, ephemeral).await
	}

	/// The transcript hash a server Finished signed, read from its content.
	fn signed_transcript(server_finished: &SignedData) -> TranscriptHash {
		let content = server_finished.encap_content_info.econtent.as_ref();
		let content = content.expect("a Finished carries content");
		let content = content.decode_as::<OctetString>().expect("the content is an OCTET STRING");

		let signed = FinishedRole::Server.transcript_hash(content.as_bytes());
		let signed = signed.expect("the content names the server role");
		fixture_transcript::<Sha3_256>(signed)
	}

	/// The content of `finished` once its one signer verifies under the
	/// certificate and key of `signer`.
	fn verified_content(finished: &SignedData, signer: &TestCertificate) -> Result<Vec<u8>, SignerError> {
		let content = CmsSigner::content(finished, DATA)?;
		let signer_info = finished.signer_infos.0.iter().next().ok_or(SignerError::Content)?;
		let key = signer.signing_key.verifying_key();

		let verifying = CmsSigner::verify_signer::<Secp256k1Signature, _>;
		verifying(signer_info, &signer.certificate, key, SignedContent::data(content))?;
		Ok(content.to_vec())
	}

	/// The one signer of `finished`.
	fn finished_signer(finished: &SignedData) -> SignerInfo {
		let mut signers = finished.signer_infos.0.iter();
		let signer = signers.next().expect("a Finished has one signer");
		signer.clone()
	}

	/// The opening carries the 32-byte base secret, and it opens under the
	/// key of the certificate the client was pinned to.
	#[tokio::test]
	async fn the_opening_opens_under_the_server_certificate_key() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (_, sealed) = client_after_opening(&server, None);
		let identity = signing_identity(&server);
		let opener = Opener::Kem { identity: &identity, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
		let (arrived, sealed) = sealed.into_parts();
		let opened = sealed.open::<DefaultCryptoProvider>(arrived, &opener, HANDSHAKE_OPENING_CONTENT);

		let opened = opened.await?;
		let content = opened.to_insecure();
		let content = OpeningContent::from_der(&content)?;
		assert_eq!(content.base_secret.as_bytes().len(), 32);
		Ok(())
	}

	/// The `ukm` of the opening's `KEMRecipientInfo` (RFC 9629 §3) is the
	/// opening's purpose label followed by 32 random octets the seal draws for
	/// itself.
	#[test]
	fn an_opening_ukm_is_the_opening_label_and_32_random_octets() {
		let server = create_test_certificate();
		let (_, sealed) = client_after_opening(&server, None);

		let kem = sealed.value().kem_recipient();
		let ukm = kem.ukm.as_ref().map(OctetString::as_bytes);
		assert_eq!(ukm.map(|ukm| ukm.starts_with(TIGHTBEAM_OPENING_UKM_LABEL)), Some(true));
		assert_eq!(ukm.map(<[u8]>::len), Some(TIGHTBEAM_OPENING_UKM_LABEL.len() + 32));
	}

	/// The offers travel among the authenticated attributes, which the tag
	/// covers.
	#[test]
	fn an_opening_carries_its_offers_in_the_authenticated_attributes() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let offer = SecurityOffer::new(vec![create_default_test_profile()]);
		let (_, sealed) = client_after_opening(&server, Some(offer.to_owned()));

		let carried = sealed.value().auth_attrs.find_unsigned_attr(SecurityOffer::OID)?;
		let carried = carried.ok_or("the opening carries its offer")?.decode::<SecurityOffer>()?;
		assert_eq!(carried, offer);
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

	/// A Finished signed over the opening the client sent is admitted, and
	/// the closing is the client Finished sealed as an `AuthEnvelopedData`.
	#[tokio::test]
	async fn a_signed_server_finished_is_answered_with_a_sealed_client_finished() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sealed) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sealed, &fresh_server_ephemeral());

		let closing = client.respond(reply(finished)).await?;
		let sealed = closing.auth_enveloped()?;
		assert_eq!(sealed.value().auth_encrypted_content_info.content_type, DATA);
		Ok(())
	}

	/// The sealed client Finished a client answers a signed server Finished
	/// with, beside the transcript hash that server Finished signed.
	async fn sealed_client_finished() -> (AuthEnvelopedData, TranscriptHash) {
		let server = create_test_certificate();
		let (mut client, sealed) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sealed, &fresh_server_ephemeral());
		let transcript_hash = signed_transcript(&finished);

		let closing = client.respond(reply(finished)).await.expect("the client answers the Finished");
		let closing = closing.auth_enveloped().expect("the closing is an AuthEnvelopedData");
		(closing.into_value(), transcript_hash)
	}

	/// A client seals its Finished in an `AuthEnvelopedData` of version 0.
	#[tokio::test]
	async fn a_sealed_client_finished_is_version_0() {
		let (closing, _) = sealed_client_finished().await;
		assert_eq!(closing.version, CmsVersion::V0);
	}

	/// The one recipient of a sealed client Finished is a `KEKRecipientInfo`
	/// of version 4 (RFC 5652 § 6.2.3).
	#[tokio::test]
	async fn a_sealed_client_finished_has_one_kek_recipient_of_version_4() {
		let (closing, _) = sealed_client_finished().await;
		assert_eq!(closing.kek_recipient().version, CmsVersion::V4);
	}

	/// The `kekid` of a sealed client Finished is the identity domain followed
	/// by the transcript hash.
	#[tokio::test]
	async fn a_sealed_client_finished_names_the_identity_key_of_its_transcript() {
		let (closing, transcript_hash) = sealed_client_finished().await;
		let key_identifier = [TIGHTBEAM_IDENTITY_KEY_ID_DOMAIN, transcript_hash.as_bytes()].concat();
		assert_eq!(closing.kek_recipient().kek_id.kek_identifier.as_bytes(), key_identifier);
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
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());
		let stripped = with_unsigned_attrs(finished, None);

		let result = client.respond(reply(stripped)).await;
		assert!(matches!(result, Err(HandshakeError::MissingAttribute)));
	}

	/// A server Finished that carries an abort alert is refused before any
	/// attribute is read.
	#[tokio::test]
	async fn a_server_finished_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());
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
		let (mut client, sent) = client_after_opening(&server, None);
		let ephemeral = fresh_server_ephemeral();
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(&ephemeral)?;
		let transcript = [sent.der(), ephemeral_bytes.as_slice()].concat();
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
		let (mut client, sent) = client_after_opening(&server, Some(offer));
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// A validly signed server ephemeral that encodes the identity point is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_identity_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let identity = with_point(fresh_server_ephemeral(), &[0x00]);
		let finished = server_finished_over(&server.signing_key, &sent, &identity);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral whose x-coordinate lies off the
	/// curve is refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let off_curve = with_point(fresh_server_ephemeral(), &off_curve_point());
		let finished = server_finished_over(&server.signing_key, &sent, &off_curve);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let static_key = server.signing_key.verifying_key().originator_key()?;
		let finished = server_finished_over(&server.signing_key, &sent, &static_key);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A server answers a hand-built opening with a Finished that
	/// verifies under its static key. Its content is the server role over the
	/// hash of three legs, in this order:
	///
	/// 1. the opening as it was sent,
	/// 2. the accept, and
	/// 3. the server ephemeral.
	///
	/// No client reads the Finished, so a server that binds another layout
	/// fails here even when a client binds the same one.
	#[tokio::test]
	async fn a_hand_built_opening_is_answered_with_a_signed_server_finished() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, server_certificate) = server_with(&identity, PeerAuthentication::Anonymous);
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);
		let message = opening(sealed);
		let sent = message.der().to_vec();

		let finished = server.reply(message).await?.signed()?;
		let content = verified_content(finished.value(), &identity)?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?;
		let ephemeral = HandshakeAttribute::transcript_bytes(&ephemeral.decode::<OriginatorPublicKey>()?)?;
		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral].concat())?;
		assert_eq!(content, FinishedRole::Server.content(&expected));
		Ok(())
	}

	/// An opening whose unauthenticated SET OF arrives out of DER order
	/// decodes to the same value, and the server binds the bytes that arrived
	/// in the envelope rather than a sorted re-encoding.
	#[tokio::test]
	async fn the_transcript_binds_the_opening_as_it_arrived() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let attrs = [marker_attribute(1), marker_attribute(2)];
		let sealed = with_unauth_attrs(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []), attrs);
		let sent = misordered_der(&sealed);
		let received = received_through_envelope(&sent);
		assert_ne!(received.value().to_der()?, sent);

		let message = HandshakeMessage::AuthEnvelopedData(Box::new(received));
		let server_finished = server.reply(message).await?.signed()?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = server_finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?.received_bytes()?;

		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral].concat())?;
		assert_eq!(signed_transcript(server_finished.value()), expected);
		Ok(())
	}

	/// An agreement key whose x-coordinate lies off the curve is refused at
	/// the parse, before the agreement runs on it.
	#[tokio::test]
	async fn an_off_curve_agreement_key_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let agreement_key = with_point(fresh_server_ephemeral(), &off_curve_point());
		let sealed = build_test_opening_of(&server_certificate, &TEST_BASE_SECRET, agreement_key, []);

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A base secret of another length is refused where the opened content is
	/// parsed.
	#[tokio::test]
	async fn an_opening_with_a_short_base_secret_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = build_test_opening_of(&server_certificate, &[2u8; 31], fresh_server_ephemeral(), []);

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
		));
	}

	/// An opening sealed under the `ukm` of another purpose is refused before
	/// the key provider runs.
	#[tokio::test]
	async fn an_opening_under_another_ukm_purpose_is_refused() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let content = OpeningContent {
			base_secret: OctetString::new(TEST_BASE_SECRET)?,
			agreement_key: fresh_server_ephemeral(),
		};
		let recipient = Recipient::Kem { certificate: &server_certificate, ukm_label: b"tb/handshake/other/ukm/v1" };
		let content_type = HANDSHAKE_OPENING_CONTENT;
		let sealed =
			AuthEnvelopedData::seal::<DefaultCryptoProvider>(recipient, content_type, content.to_der()?, [], None)?;

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Ukm))));
		Ok(())
	}

	/// `sealed` with its transport offer replaced by `offer`, as an on-path
	/// party would rewrite it.
	fn with_transport_offer(mut sealed: AuthEnvelopedData, offer: &TransportOffer) -> AuthEnvelopedData {
		let attrs = sealed.auth_attrs.take().expect("an opening authenticates its offers");
		let kept = attrs.into_vec().into_iter().filter(|attr| attr.oid != TransportOffer::OID);
		let offer = Attribute::try_from(attribute(offer)).expect("the offer is an attribute");
		let attributes = kept.chain([offer]).collect::<Vec<_>>();

		sealed.auth_attrs = Some(Attributes::try_from(attributes).expect("the attributes are a SET"));
		sealed
	}

	/// An opening whose transport offer changed in flight fails its tag
	/// before the server chooses a profile or asks its authorizer, so the
	/// authorizer never reads an offer the tag has not covered.
	#[tokio::test]
	async fn a_tampered_offer_never_reaches_the_authorizer() {
		let identity = create_test_certificate();
		let authorizer = Arc::new(RecordingAuthorizer::default());
		let mut config = Cms::server(&identity);
		config.transport = Some(budget_offer());
		config.transport_authorizer = Some(authorizer.to_owned());
		let mut server = Handshake::server(config);

		let sealed = build_test_opening(&identity.certificate, &TEST_BASE_SECRET, [attribute(&budget_offer())]);
		let tampered = with_transport_offer(sealed, &TransportOffer::mux(8).with_budgets(TEST_BUDGETS));
		let refusal = server.reply(opening(tampered)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
		assert!(authorizer.offers().is_empty());
	}

	/// The tag of the opening covers its content, so an opening whose `mac`
	/// changed in flight fails to open.
	#[tokio::test]
	async fn an_opening_with_an_altered_mac_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = with_flipped_mac(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []));

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
	}

	/// The authenticated attributes are the associated data of the tag, so an
	/// opening that gains an attribute in flight fails to open.
	#[tokio::test]
	async fn an_opening_with_altered_authenticated_attributes_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = with_marked_auth_attrs(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []));

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
	}

	#[tokio::test]
	async fn an_opening_with_an_altered_nonce_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = with_flipped_nonce(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []));

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
	}

	/// A KEM ciphertext swapped for another point encapsulates another shared
	/// secret, so the key-encryption key differs and the wrapped key fails its
	/// integrity check.
	#[tokio::test]
	async fn an_opening_with_an_altered_kem_ciphertext_is_refused() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);
		let stray = SecretKey::<Secp256k1>::random(&mut OsRng).public_key().to_encoded_point(false);
		let kem = KemRecipientInfo { kemct: OctetString::new(stray.as_bytes())?, ..sealed.kem_recipient() };
		let sealed = sealed.with_kem_recipient(&kem);

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::KeyUnwrap))));
		Ok(())
	}

	#[tokio::test]
	async fn an_opening_with_an_altered_wrapped_key_is_refused() {
		let (mut server, server_certificate) = anonymous_server();
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);
		let kem = sealed.kem_recipient();
		let kem = KemRecipientInfo { encrypted_key: flipped(&kem.encrypted_key), ..kem };
		let sealed = sealed.with_kem_recipient(&kem);

		let refusal = server.reply(opening(sealed)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::KeyUnwrap))));
	}

	/// A CMS Finished names its signer by the certificate of the identity, so
	/// a signature is the provider's DER signature over the prehash, and the
	/// step fetches no public key: the identity read it once when it was
	/// built.
	#[tokio::test]
	async fn a_cms_signature_fetches_no_public_key() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let verifying_key = *identity.signing_key.verifying_key();
		let provider = Arc::new(CountingProvider::new(identity.signing_key.to_owned()));
		let signing = presenting(&identity, Arc::clone(&provider) as Arc<dyn SigningKeyProvider>);
		let fetched_at_construction = provider.public_keys();
		let prehash = [0x42u8; 32];

		let signed = <Cms as HandshakeFlow>::sign(&signing, &prehash).await?;
		VerifiedSignature::verify::<Secp256k1Signature, _>(&verifying_key, prehash, &signed)?;
		assert_eq!(provider.public_keys(), fetched_at_construction);
		Ok(())
	}

	/// A server Finished carries the content type, the message digest, and
	/// the algorithm protection as signed attributes (RFC 5652 §5.3, RFC 6211).
	#[tokio::test]
	async fn a_server_finished_carries_the_three_signed_attributes() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, server_certificate) = server_with(&identity, PeerAuthentication::Anonymous);
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);

		let finished = server.reply(opening(sealed)).await?.signed()?;
		let oids = TestAttributes::oids(&finished_signer(finished.value()));
		assert_eq!(
			oids,
			vec![ATTR_CONTENT_TYPE, ATTR_CMS_ALGORITHM_PROTECTION, ATTR_MESSAGE_DIGEST]
		);
		Ok(())
	}

	/// A server Finished names its signer by the key identifier of the server
	/// certificate, so its `SignerInfo` is version 3 and its `SignedData`
	/// version 3 (RFC 5652 §5.1, §5.3).
	#[tokio::test]
	async fn a_server_finished_is_version_3_under_its_key_identifier() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, server_certificate) = server_with(&identity, PeerAuthentication::Anonymous);
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);

		let finished = server.reply(opening(sealed)).await?.signed()?;
		let signer = finished_signer(finished.value());
		assert_eq!(signer.version, CmsVersion::V3);
		assert_eq!(signer.sid, identity.certificate.signer_identifier()?);
		assert_eq!(finished.value().version, CmsVersion::V3);
		Ok(())
	}

	/// A server Finished whose signer carries no signed attributes is refused
	/// by the client (RFC 5652 §5.4).
	#[tokio::test]
	async fn a_server_finished_without_signed_attributes_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());
		let mut signer = finished_signer(&finished);
		signer.signed_attrs = None;

		let stripped = SignedData { signer_infos: vec![signer].try_into()?, ..finished };
		let refusal = client.respond(reply(stripped)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A server Finished whose `SignedData` version breaks the RFC 5652 §5.1
	/// rule is refused by the client.
	#[tokio::test]
	async fn a_server_finished_of_the_wrong_version_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());
		let downgraded = SignedData { version: CmsVersion::V1, ..finished };

		let refusal = client.respond(reply(downgraded)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A server Finished whose `sid` names another certificate is refused by
	/// the client, though its signature verifies under the server's key.
	#[tokio::test]
	async fn a_server_finished_naming_another_certificate_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing_key, &sent, &fresh_server_ephemeral());
		let mut signer = finished_signer(&finished);
		signer.sid = create_test_certificate().certificate.signer_identifier()?;

		let renamed = SignedData { signer_infos: vec![signer].try_into()?, ..finished };
		let refusal = client.respond(reply(renamed)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A client that names its static key as its agreement key `R` leaves the
	/// session to the secrecy of that one key, so the server refuses the
	/// closing whose certificate holds that key.
	#[tokio::test]
	async fn an_agreement_key_equal_to_the_client_static_key_is_refused() {
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
	/// opened Finished is parsed, before the offer compares `R`.
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

	/// An opening that carries an abort alert among its unauthenticated
	/// attributes is refused before any negotiation runs.
	#[tokio::test]
	async fn an_opening_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let code = Any::encode_from(&3u8)?;
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, code)?;
		let sealed = with_unauth_attrs(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []), [alert]);

		let refusal = server.reply(opening(sealed)).await;
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// An opening carrying a duplicate SecurityOffer attribute fails
	/// closed rather than reading as no offer and falling through to dealer's
	/// choice, matching the client's fail-closed behaviour.
	#[tokio::test]
	async fn a_duplicate_security_offer_fails_closed() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let native = create_default_test_profile();
		let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..native };
		let first = HandshakeAttribute::encode(&SecurityOffer::new(vec![native]))?;
		let second = HandshakeAttribute::encode(&SecurityOffer::new(vec![foreign]))?;
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, [first, second]);

		let result = server.reply(opening(sealed)).await;
		assert!(matches!(result, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// An opening carrying a duplicate TransportOffer attribute fails
	/// closed the same way, rather than reading as no offer and leaving the
	/// connection single-flight.
	#[tokio::test]
	async fn a_duplicate_transport_offer_fails_closed() -> Result<(), Box<dyn Error>> {
		let (mut server, server_certificate) = anonymous_server();
		let first = HandshakeAttribute::encode(&TransportOffer::mux(4))?;
		let second = HandshakeAttribute::encode(&TransportOffer::mux(8))?;
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, [first, second]);

		let result = server.reply(opening(sealed)).await;
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

	/// A key-confirmation tag narrower than any digest output fails to decode,
	/// so the server refuses the Finished when it opens it and admits no
	/// further step.
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
		let sealed = client.respond(reply).await?.auth_enveloped()?;
		let altered = with_flipped_content(sealed.value().to_owned());

		let refusal = server.finish(HandshakeMessage::try_from(altered)?).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::Authentication))
		));
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
		let foreign_transcript = fixture_transcript::<Sha3_256>([0x5au8; 32]);
		let foreign = build_test_client_finished(&client, &foreign_transcript, &awaiting.confirmation);
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
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity(EnvelopeError::KeyUnwrap))));
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
		let alerted = AuthEnvelopedData { unauth_attrs: Some(attrs), ..sealed };

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
		sealed.auth_encrypted_content_info.content_type = SIGNED_DATA;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::ContentType(_)))
		));
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
		sealed.auth_encrypted_content_info.content_enc_alg.oid = AES_128_GCM;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::ContentEncryptionAlgorithm))
		));
		Ok(())
	}

	/// A sealed Finished whose algorithm carries another nonce fails its tag.
	#[tokio::test]
	async fn a_sealed_finished_under_another_nonce_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		let parameters = flipped_nonce(&sealed);

		sealed.auth_encrypted_content_info.content_enc_alg.parameters = Some(parameters);

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::Authentication))
		));
		Ok(())
	}

	/// A sealed Finished that carries no content is refused.
	#[tokio::test]
	async fn a_sealed_finished_with_no_content_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		sealed.auth_encrypted_content_info.encrypted_content = None;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::MissingContent))
		));
		Ok(())
	}

	/// A sealed Finished whose `mac` changed in flight fails its tag.
	#[tokio::test]
	async fn a_sealed_finished_with_an_altered_mac_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let sealed = with_flipped_mac(awaiting.sealed_finished(&finished));

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(sealed)?).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::Authentication))
		));
		Ok(())
	}

	/// A sealed Finished whose authenticated attributes changed in flight
	/// fails its tag, so its transcript binding holds.
	#[tokio::test]
	async fn a_sealed_finished_with_altered_authenticated_attributes_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let sealed = with_marked_auth_attrs(awaiting.sealed_finished(&finished));

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(sealed)?).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedIdentity(EnvelopeError::Authentication))
		));
		Ok(())
	}

	/// A sealed Finished whose wrapped content key changed in flight fails
	/// the key unwrap.
	#[tokio::test]
	async fn a_sealed_finished_with_an_altered_wrapped_key_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let sealed = with_flipped_kek_wrapped_key(awaiting.sealed_finished(&finished));

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(sealed)?).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedIdentity(EnvelopeError::KeyUnwrap))));
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

	/// The compressed SEC1 point of the secp256k1 scalar of 32 `0x05` bytes.
	const KNOWN_SERVER_EPHEMERAL: [u8; 33] = [
		0x03, 0x62, 0xc0, 0xa0, 0x46, 0xda, 0xcc, 0xe8, 0x6d, 0xdd, 0x03, 0x43, 0xc6, 0xd3, 0xc7, 0xc7, 0x9c, 0x22,
		0x08, 0xba, 0x0d, 0x9c, 0x9c, 0xf2, 0x4a, 0x6d, 0x04, 0x6d, 0x21, 0xd2, 0x1f, 0x90, 0xf7,
	];

	/// The CMS client derives the handshake secret as HKDF-SHA3-256 under the
	/// salt and the session label over its agreement with the server
	/// ephemeral followed by its base secret.
	///
	/// The expected bytes come from an independent ECDH (Python's
	/// `cryptography`) and HKDF (Python's `hmac` and `hashlib`), so no code of
	/// the crate computes them.
	#[test]
	fn the_cms_handshake_secret_matches_its_known_answer() -> Result<(), Box<dyn Error>> {
		let ephemeral = SecretKey::<Secp256k1>::from_slice(&[0x03u8; 32])?;
		let pending = Box::new(CmsPending { base: test_base_secret(), ephemeral });
		let server_ephemeral = PeerPoint::<Secp256k1>::parse(KNOWN_SERVER_EPHEMERAL)?;
		let salt = KdfSalt::new(&[0x99u8; 32]);

		let agree = <Cms as ClientLegs<DefaultCryptoProvider>>::agree;
		let (secret, ()) = agree(pending, &server_ephemeral, salt, &mut OsRng)?;
		let expected = [
			0x1d, 0xdf, 0x26, 0xec, 0xa0, 0x1c, 0x5d, 0xb2, 0x3d, 0x34, 0x0c, 0x3c, 0x62, 0x94, 0xb0, 0xe2, 0x4c, 0x9c,
			0xe9, 0xea, 0xb8, 0x45, 0xd3, 0x79, 0xc8, 0x19, 0xae, 0x7c, 0x09, 0xd1, 0x52, 0xba,
		];
		assert_eq!(secret.as_bytes(), expected);
		Ok(())
	}

	/// A handshake under a provider whose digest is SHA3-512 seals the whole
	/// 64-byte digest as its transcript hash, and its closing confirms and
	/// opens under that hash.
	#[tokio::test]
	async fn a_sha3_512_profile_carries_a_64_byte_transcript_hash() -> Result<(), Box<dyn Error>> {
		let server_identity = create_test_certificate();
		let settings = Cms::client(&server_identity.certificate, &create_test_certificate()).flow;
		let profiles = SupportedProfiles::from(RunnableProfile::<Aes256Sha3_512Provider>::native().descriptor());
		let server_config = ServerConfig::new(CmsServerSettings, signing_identity(&server_identity), profiles);
		let mut client = Handshake::<Client, Cms, Aes256Sha3_512Provider>::client(ClientConfig::new(settings));
		let mut server = Handshake::<Server, Cms, Aes256Sha3_512Provider>::server(server_config);

		let opening = client.start()?;
		let reply = server.reply(opening).await?;
		let closing = client.respond(reply).await?;
		server.finish(closing).await?;

		let transcript_hash = server.transcript_hash().ok_or("the reply sealed the transcript")?;
		assert_eq!(transcript_hash.as_bytes().len(), 64);
		Ok(())
	}

	/// The directory `scripts/cms-interop.sh` reads its samples from.
	const SAMPLE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/cms-samples");

	/// The variable that asks the sample test to write its samples.
	const SAMPLE_VARIABLE: &str = "TIGHTBEAM_CMS_SAMPLES";

	/// `content` of `content_type` inside a CMS `ContentInfo` (RFC 5652 § 3),
	/// the form a CMS parser reads.
	fn content_info<T: EncodeValue + Tagged>(content_type: ObjectIdentifier, content: &T) -> Vec<u8> {
		let content = Any::encode_from(content).expect("the content encodes");
		ContentInfo { content_type, content }.to_der().expect("the ContentInfo encodes")
	}

	/// Whether `content`, inside a `ContentInfo` of `content_type`, decodes
	/// back to itself under its type.
	fn decodes_back<T>(content_type: ObjectIdentifier, content: &T) -> bool
	where
		T: EncodeValue + Tagged + for<'a> Choice<'a> + for<'a> DecodeValue<'a> + PartialEq,
	{
		let der = content_info(content_type, content);
		let info = ContentInfo::from_der(&der).expect("the ContentInfo decodes");
		let decoded = info.content.decode_as::<T>().expect("the content decodes as its type");
		info.content_type == content_type && decoded == *content
	}

	/// Write each sample of `emitted` to [`SAMPLE_DIR`] under its name, and
	/// the DER of both certificates beside them, when the environment holds
	/// [`SAMPLE_VARIABLE`].
	fn write_samples(emitted: &Emitted) -> std::io::Result<()> {
		if std::env::var_os(SAMPLE_VARIABLE).is_none() {
			return Ok(());
		}

		std::fs::create_dir_all(SAMPLE_DIR)?;
		for (name, der) in emitted.samples() {
			std::fs::write(format!("{SAMPLE_DIR}/{name}.der"), der)?;
		}

		let server = emitted.server_certificate.to_der().map_err(std::io::Error::other)?;
		let client = emitted.client_certificate.to_der().map_err(std::io::Error::other)?;
		std::fs::write(format!("{SAMPLE_DIR}/server-certificate.crt"), server)?;
		std::fs::write(format!("{SAMPLE_DIR}/client-certificate.crt"), client)
	}

	/// A frame signed by a test identity, as the `SignedData` its signature
	/// reads as: the frame's TBS encoding as `id-data` content, the frame's
	/// `SignerInfo`, and the certificate it names.
	async fn frame_signature() -> SignedData {
		use crate::builder::frame::FrameBuilder;
		use crate::builder::TypeBuilder;
		use crate::testing::TestMessage;
		use crate::Version;

		let builder = FrameBuilder::from(Version::V1).with_id("cms-sample").with_order(1696521600);
		let builder = builder.with_message(TestMessage::sample(None));
		let mut frame = builder.build().expect("the frame builds");
		let identity = TestIdentity::insecure_fixed();
		frame.sign_with_provider(&identity).await.expect("the frame signs");

		let tbs = frame.to_tbs().expect("the frame encodes its TBS");
		let signer = frame.nonrepudiation().expect("the frame carries its signature").to_owned();
		let certificate = CertificateChoices::Certificate(identity.certificate().to_owned());
		let certificates = CertificateSet(vec![certificate].try_into().expect("one certificate is a SET"));
		let signed = CmsSigner::signed_data(SignedContent::data(&tbs), signer, Some(certificates));
		signed.expect("the frame signature assembles").into_inner()
	}

	/// One of each structure the CMS flow and a signed frame emit, and the
	/// two certificates that verify the signed ones.
	struct Emitted {
		/// The opening, an `AuthEnvelopedData` with a `KEMRecipientInfo`.
		opening: AuthEnvelopedData,
		/// The server Finished, the signer's `SignedData`.
		server_finished: SignedData,
		/// The session receipt the server Finished carries, a `SignedData`.
		session_receipt: SignedData,
		/// The sealed client Finished, an `AuthEnvelopedData` with a
		/// `KEKRecipientInfo`.
		sealed_finished: AuthEnvelopedData,
		/// The acknowledgement seal, another `KEKRecipientInfo` seal.
		kek_seal: AuthEnvelopedData,
		/// A frame signature, as a `SignedData`.
		frame_signature: SignedData,
		/// The receipt the server and the client both signed, as the session
		/// observer of the server receives it.
		joined_receipt: SignedData,
		/// The certificate of the server.
		server_certificate: Certificate,
		/// The certificate of the client.
		client_certificate: Certificate,
	}

	impl Emitted {
		/// Each structure as its interop sample: its file name and the DER of
		/// its `ContentInfo`.
		fn samples(&self) -> [(&'static str, Vec<u8>); 7] {
			[
				("cms-opening", content_info(AUTH_ENVELOPED_DATA, &self.opening)),
				("server-finished", content_info(SIGNED_DATA, &self.server_finished)),
				("session-receipt", content_info(SIGNED_DATA, &self.session_receipt)),
				("sealed-finished", content_info(AUTH_ENVELOPED_DATA, &self.sealed_finished)),
				("kek-seal", content_info(AUTH_ENVELOPED_DATA, &self.kek_seal)),
				("frame-signature", content_info(SIGNED_DATA, &self.frame_signature)),
				("joined-receipt", content_info(SIGNED_DATA, &self.joined_receipt)),
			]
		}
	}

	/// Run one CMS handshake with a budget, and take one of each structure it
	/// and a signed frame emit.
	async fn emitted() -> Emitted {
		let Parties { mut client, mut server, server_identity, client_identity } =
			parties::<Cms>(mutual_with(ExpiryValidator));
		let observer = Arc::new(ArtifactObserver::default());
		client.transport_offer = Some(budget_offer());
		client.receipt_approver = Some(Arc::new(PayingApprover));
		server.transport = Some(budget_offer());
		server.transport_authorizer = Some(Arc::new(ChallengingAuthorizer));
		server.session_observer = Some(observer.to_owned());
		let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));

		let opening = client.start().expect("the client opens");
		let reply = server.reply(opening.to_owned()).await.expect("the server replies");
		let closing = client.respond(reply.to_owned()).await.expect("the client closes");
		server.finish(closing.to_owned()).await.expect("the server finishes");

		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let salt = KdfSalt::new(&[0x99u8; 32]);
		let secret = fixture_handshake_secret(0x42);
		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Ack, salt, &transcript_hash);
		let sealer = sealer.expect("the acknowledgement key derives");
		let kek_seal = sealer.seal(b"countersignature").expect("the acknowledgement seals");

		let reply = reply.signed().expect("the reply is a SignedData");
		let receipt = reply.value().find_unsigned_attr(SESSION_RECEIPT);
		let receipt = receipt.expect("the receipt attribute decodes");
		let receipt = receipt.expect("a budget-bearing Finished carries its receipt");
		let session_receipt = receipt.decode::<Signed<SignedData>>().expect("the receipt is a SignedData");
		let joined_receipt = observer.artifacts().pop().expect("the server reports its outcome");
		let opening = opening.auth_enveloped().expect("the opening is an AuthEnvelopedData");
		let closing = closing.auth_enveloped().expect("the closing is an AuthEnvelopedData");
		Emitted {
			opening: opening.value().to_owned(),
			server_finished: reply.value().to_owned(),
			session_receipt: session_receipt.into_inner(),
			sealed_finished: closing.value().to_owned(),
			kek_seal,
			frame_signature: frame_signature().await,
			joined_receipt: joined_receipt.into_inner(),
			server_certificate: server_identity.certificate,
			client_certificate: client_identity.certificate,
		}
	}

	#[tokio::test]
	async fn the_opening_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(AUTH_ENVELOPED_DATA, &emitted.opening));
	}

	#[tokio::test]
	async fn the_server_finished_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(SIGNED_DATA, &emitted.server_finished));
	}

	#[tokio::test]
	async fn the_session_receipt_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(SIGNED_DATA, &emitted.session_receipt));
	}

	#[tokio::test]
	async fn the_sealed_finished_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(AUTH_ENVELOPED_DATA, &emitted.sealed_finished));
	}

	#[tokio::test]
	async fn the_kek_seal_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(AUTH_ENVELOPED_DATA, &emitted.kek_seal));
	}

	#[tokio::test]
	async fn the_frame_signature_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(SIGNED_DATA, &emitted.frame_signature));
	}

	#[tokio::test]
	async fn the_joined_receipt_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(SIGNED_DATA, &emitted.joined_receipt));
	}

	/// Write the samples of [`Emitted`]. `scripts/cms-interop.sh` parses and
	/// verifies them with OpenSSL when the run sets `TIGHTBEAM_CMS_SAMPLES`,
	/// which `make interop` does.
	#[tokio::test]
	async fn the_emitted_structures_write_their_interop_samples() -> std::io::Result<()> {
		write_samples(&emitted().await)
	}
}

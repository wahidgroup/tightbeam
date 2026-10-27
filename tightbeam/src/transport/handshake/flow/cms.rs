//! The CMS flow.
//!
//! CMS exchanges the three containers themselves. A CMS server holds two
//! certificates of one subject: its signing certificate and its key-agreement
//! certificate.
//!
//! The client seals the base secret to the key-agreement certificate on the
//! opening, so it pins that certificate before the handshake starts. The
//! server Finished carries the signing certificate, and the client admits it
//! at each reply.
//!
//! ## Opening
//!
//! The opening is an `AuthEnvelopedData` (RFC 5083) with one
//! `KEMRecipientInfo` (RFC 9629) to the server's key-agreement certificate,
//! under the provider's KEM. Its content carries the base secret and the
//! client's agreement ephemeral `R`, and its authenticated attributes carry
//! the offers. Each client ephemeral serves one agreement:
//!
//! - The KEM draws its own, whose shared secret derives the key that wraps
//!   the content key alone (RFC 9629 §7).
//! - `R·E` with the server ephemeral feeds the handshake secret.
//!
//! ## Reply and closing
//!
//! The server Finished is the signer's `SignedData` over the server role and
//! the transcript hash:
//!
//! - It carries the signing certificate and the issuers above it that the
//!   server presents in `certificates` (RFC 5652 §5.1).
//! - The transcript binds that field as it was sent and as it arrived, as the HPKE transcript binds its own.
//! - Its `SignerInfo` carries the server Finished MAC of both flows as an
//!   unsigned attribute, which the client verifies before it closes, as the
//!   HPKE client does.
//!
//! The client closes with the closing of both flows, sealed under the closing
//! key of the handshake secret. The server's key-agreement key opens the base
//! secret alone, so the client identity stays secret from a party that holds
//! a recording and that key.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::cms::enveloped_data::OriginatorPublicKey;
use crate::cms::signed_data::{CertificateSet, SignedData};
use crate::constants::TIGHTBEAM_OPENING_UKM_LABEL;
use crate::crypto::cms::{AuthEnvelopedData, Opener, Recipient};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::SecretKey;
use crate::crypto::sign::{CmsSigner, Signed, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::{BitString, OctetString};
use crate::der::{Choice, Decode, DecodeValue, Encode, Error as DerError, Sequence};
use crate::oids::HANDSHAKE_OPENING_CONTENT;
use crate::random::{CryptoRngCore, RngWrapper};
use crate::spki::{EncodePublicKey, Error as SpkiError, SubjectPublicKeyInfoOwned};
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientAgreement, ClientLegs, FinishedDraft, HandshakeFlow, Opened, OpeningIntake, OpeningParts,
	ReplyBinding, ReplyIntake, ReplyParts, ReplyVerified, ServerAgreement, ServerLegs,
};
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
use crate::transport::handshake::peer::{
	CmsNamedServer, PinnedKeyAgreement, ProvisionedKeyAgreement, ProvisionedTrust,
};
use crate::transport::handshake::primitives::transcript::{ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::schedule::{Agreement, BaseSecret, FinishedRole, PeerPoint, Salt};
use crate::transport::handshake::{CmsIdentityPair, HandshakeCurve, HandshakeMessage, HandshakeProvider};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};
use crate::zeroize::{Zeroize, Zeroizing};

/// The CMS handshake protocol.
///
/// A client is provisioned with [`CmsClientSettings`], and a server with
/// [`CmsServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cms;

impl sealed::Sealed for Cms {}

impl HandshakeFlow for Cms {}

/// What a CMS client is provisioned with.
///
/// A CMS client signs its Finished, and the server verifies that signature
/// under the certificate the Finished embeds, so the identity is mandatory.
pub struct CmsClientSettings {
	/// The server's pinned key-agreement certificate, beside the store that
	/// admits it and the signing certificate the reply carries.
	pub trust: ProvisionedTrust,
	/// The identity the client presents and signs its Finished under.
	pub identity: SigningIdentity,
}

/// What a CMS client keeps from its opening to read the reply against.
pub struct CmsOpening<P: HandshakeProvider> {
	/// The transcript, open over the opening as it was sent.
	transcript: Transcript,
	/// The key-agreement certificate the opening sealed to.
	server: PinnedKeyAgreement<P>,
}

/// The secrets a CMS client holds from its opening to the agreement.
pub struct CmsPending<C: HandshakeCurve> {
	/// The base secret the opening carried to the server.
	base: BaseSecret,
	/// The agreement ephemeral `R`, kept for the agreement with the server
	/// ephemeral.
	ephemeral: SecretKey<C>,
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
/// ([RFC 5652 §6.2.2][rfc5652-6.2.2]).
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
	type Opening = CmsOpening<P>;
	type Pending = Box<CmsPending<P::Curve>>;

	fn identity(settings: &Self::Settings) -> Option<&SigningIdentity> {
		Some(&settings.identity)
	}

	fn server_trust(settings: &Self::Settings) -> &Self::Trust {
		&settings.trust
	}

	fn open(
		_settings: &Self::Settings,
		server: ProvisionedKeyAgreement<P>,
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
		let mut content_der = Zeroizing::new(content.to_der()?);
		content.base_secret.into_bytes().zeroize();

		// 4. Seal the content to the admitted server's key-agreement key, with
		//    each offer as an authenticated attribute. The client certificate
		//    travels only in the sealed Finished.
		let mut offers = Vec::new();
		if let Some(offer) = parts.security_offer {
			offers.push(Attribute::try_from(HandshakeAttribute::encode(offer)?)?);
		}
		if let Some(offer) = parts.transport_offer {
			offers.push(Attribute::try_from(HandshakeAttribute::encode(offer)?)?);
		}

		let (server, kem_recipient) = server.into_parts();
		let recipient = Recipient::Kem { recipient: &kem_recipient, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
		let content_type = HANDSHAKE_OPENING_CONTENT;
		let content = core::mem::take(&mut *content_der);
		let sealed = AuthEnvelopedData::seal::<P>(recipient, content_type, content, offers, Some(rng))?;

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

		// 3. Build the path the Finished's signer presents, parsed from the bytes it arrived as.
		let presented = CmsSigner::signer_path(&reply)?;
		let (signing, certificates) = presented.ok_or(HandshakeError::MissingServerCertificate)?;

		// 4. Append the received encodings and seal the transcript. A tampered
		//    attribute, a reordered `SET OF`, or a certificate swapped for one
		//    of the same key or subject diverges the hashes and fails the
		//    signature (CWE-345, RFC 9846 §4.5.2).
		let legs = ServerFinishedLegs {
			security_accept: security_accept_bytes,
			transport_accept: transport_accept_bytes,
			server_ephemeral: server_ephemeral_bytes,
			certificates,
		};

		transcript.append_server_finished(legs)?;
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 5. Return the facts of the reply.
		let server_ephemeral = server_ephemeral.public_key.raw_bytes().to_vec();
		Ok(ReplyIntake {
			server: CmsNamedServer { signing, key_agreement: server },
			security_accept,
			transport_accept,
			server_ephemeral,
			receipt,
			client_cert_required: false,
			transcript_hash,
			salt: Salt::transcript_hash(),
			reply: reply.into_value(),
		})
	}

	fn verify_reply(
		reply: &SignedData,
		server: &PeerCertificate<Signing<P>>,
		transcript_hash: &TranscriptHash,
	) -> Result<ReplyVerified, HandshakeError> {
		FinishedRole::Server.verify::<P>(reply, server, transcript_hash)?;
		Ok(ReplyVerified(()))
	}
}

/// The CMS client agrees hybrid: the ECDH output, then the base secret its
/// opening carried. The secrets are read in place, so each is wiped where the
/// box drops.
impl<P: HandshakeProvider> ClientAgreement<P> for Box<CmsPending<P::Curve>> {
	fn agreement<'a>(&'a self, peer: &'a PeerPoint<P::Curve>) -> Agreement<'a, P> {
		Agreement::hybrid(peer, &self.base)
	}

	fn ephemeral(&self) -> &SecretKey<P::Curve> {
		&self.ephemeral
	}
}

/// What a CMS server is provisioned with.
///
/// The shared server configuration covers the whole protocol: its
/// [`CmsIdentityPair`] signs the Finished with one key, and opens the opening
/// with the other.
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
	/// The server Finished, complete up to its signature.
	finished: FinishedDraft,
	security_accept: SecurityAccept,
	transport_accept: Option<TransportAccept>,
	server_ephemeral: OriginatorPublicKey,
	/// The certificates the Finished carries: the signing certificate its
	/// `SignerInfo` names, and the issuers above it that the server presents.
	certificates: CertificateSet,
}

impl<P: HandshakeProvider> ServerLegs<P> for Cms {
	type Settings = CmsServerSettings;
	type Identity = CmsIdentityPair<P::Kem>;
	type Sealed = CmsSealed;
	type Opened = Box<CmsOpened<P::Curve>>;
	type Draft = CmsReplyDraft;

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
		identity: &'a CmsIdentityPair<P::Kem>,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>> {
		Box::pin(async move {
			let CmsSealed { opening, transcript } = sealed;

			// 1. Open the content under the server's key-agreement key. The
			//    opener refuses another recipient kind, `ukm` purpose, or an
			//    algorithm outside the profile before the backend runs, and
			//    checks the tag before it reads a byte of the content.
			let opener = Opener::Kem { identity: identity.key_agreement(), ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
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

		// 2. Append both selections, the ephemeral, and the `certificates`
		//    field the Finished carries, as the DER its identity encoded once.
		//    Then seal, so the Finished signature binds all four (CWE-345), as
		//    TLS 1.3 signs over its Certificate.
		let presented = identity.presented();
		let legs = ServerFinishedLegs {
			security_accept: Some(HandshakeAttribute::transcript_bytes(&security_accept)?),
			transport_accept: transport_accept.map(HandshakeAttribute::transcript_bytes).transpose()?,
			server_ephemeral: HandshakeAttribute::transcript_bytes(&server_ephemeral)?,
			certificates: presented.field(),
		};
		opened.transcript.append_server_finished(legs)?;

		let transcript_hash = opened.transcript.seal::<P::Digest>()?;

		// 3. Draft the Finished's SignerInfo, which names the digest the server
		//    signs. The Finished carries its own copy of the certificates,
		//    since a `CertificateSet` owns each certificate it holds.
		let finished = FinishedRole::Server.draft::<P>(identity, &transcript_hash)?;
		let prehash = finished.prehash().to_vec();
		let transport_accept = transport_accept.copied();
		let certificates = presented.set();
		let draft = CmsReplyDraft { finished, security_accept, transport_accept, server_ephemeral, certificates };
		Ok(ReplyBinding { transcript_hash, salt: Salt::transcript_hash(), prehash, draft })
	}

	fn encode_reply(
		draft: Self::Draft,
		signature: Vec<u8>,
		artifact: Option<&Signed<SignedData>>,
	) -> Result<Signed<SignedData>, HandshakeError> {
		let CmsReplyDraft { finished, security_accept, transport_accept, server_ephemeral, certificates } = draft;

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

		finished.finish(signature, unsigned_attrs, Some(certificates))
	}
}

/// The CMS server agrees hybrid with `R`: the ECDH output, then the base
/// secret the opening carried. The base secret and the transcript drop with
/// the value, and the secrets are read in place, so each is wiped where its
/// box drops.
impl<P: HandshakeProvider> ServerAgreement<P> for Box<CmsOpened<P::Curve>> {
	fn client_ephemeral(&self) -> &PeerPoint<P::Curve> {
		&self.client_ephemeral
	}

	fn agreement(&self) -> Agreement<'_, P> {
		Agreement::hybrid(&self.client_ephemeral, &self.base)
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::str::FromStr;
	use std::sync::Arc;

	use super::*;
	use crate::asn1::admission::fixtures::tlv;
	use crate::cms::content_info::{CmsVersion, ContentInfo};
	use crate::cms::signed_data::SignerInfo;
	use crate::constants::{TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, TIGHTBEAM_SERVER_FINISHED_DOMAIN};
	use crate::crypto::cms::{EnvelopeError, GcmParameters, KemRecipient, KemRecipientInfo};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::hpke::DhKemSecp256k1;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Signature};
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::sign::{CmsSigner, SignedContent, SignerError};
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use crate::crypto::x509::utils::CertificateExt;
	use crate::crypto::x509::KeyAgreement;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::Any;
	use crate::der::{Choice, DecodeValue, EncodeValue, ErrorKind, Tag, TagNumber, Tagged};
	use crate::oids::{AES_128_GCM, AUTH_ENVELOPED_DATA, HANDSHAKE_ABORT_ALERT, HANDSHAKE_SERVER_EPHEMERAL};
	use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST};
	use crate::oids::{DATA, SESSION_RECEIPT, SIGNED_DATA};
	use crate::random::OsRng;
	use crate::testing::{Aes256Sha3_512Provider, EnvelopeRecipient, TestAttributes, TestIdentity};
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::negotiation::{RunnableProfile, SecurityOffer};
	use crate::transport::handshake::primitives::KdfSalt;
	use crate::transport::handshake::schedule::{KeyConfirmation, Sealer, SecretSeal, TrafficSecret};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{
		Client, ClientConfig, Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication, Server, ServerConfig,
		SupportedProfiles,
	};
	use crate::x509::ext::pkix::{KeyUsage, KeyUsages};
	use crate::x509::name::RdnSequence;
	use crate::x509::Certificate;

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

	/// A server Finished signed by `server` over the transcript of `opening`
	/// followed by the default profile's accept, `ephemeral`, and the
	/// `certificates` field of `server`, as a server under dealer's choice
	/// sends it.
	fn server_finished_over(
		server: &TestCertificate,
		opening: &WireDer<AuthEnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> SignedData {
		let accept = SecurityAccept::new(create_default_test_profile());
		let accept_bytes = HandshakeAttribute::transcript_bytes(&accept).expect("an accept has transcript bytes");
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(ephemeral).expect("a key has transcript bytes");
		let certificates = certificates_field([server.certificate.to_owned()]);
		let transcript = [opening.der(), &accept_bytes, &ephemeral_bytes, &certificates].concat();
		let attrs = unsigned_attrs(vec![attribute(&accept), attribute(ephemeral)]);

		signed_server_finished(server, &transcript, attrs)
	}

	/// A server Finished signed by `server` over `transcript` that carries
	/// `attrs` and the certificate of `server`.
	fn signed_server_finished(server: &TestCertificate, transcript: &[u8], attrs: Attributes) -> SignedData {
		let transcript_hash = Transcript::digest::<Sha3_256>(transcript).expect("the transcript hashes");
		let signed = signed_finished(FinishedRole::Server, &server.signing_key, &transcript_hash, &server.certificate);
		let signed = with_unsigned_attrs(signed, Some(attrs));
		with_certificate(signed, &server.certificate)
	}

	/// A Finished of `role` signed by `key` over `transcript_hash` and
	/// `certificate`, built by hand from the CMS signer. It carries no
	/// unsigned attribute and no certificate, and its `sid` is the key
	/// identifier of `key`, which the test certificate of `key` carries.
	fn signed_finished(
		role: FinishedRole,
		key: &Secp256k1SigningKey,
		transcript_hash: &TranscriptHash,
		certificate: &Certificate,
	) -> SignedData {
		let content = role.content::<Sha3_256>(transcript_hash, certificate);
		let content = content.expect("the Finished content builds");
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
		server: &TestServerIdentity,
		offer: Option<SecurityOffer>,
	) -> (TestClient<Cms>, WireDer<AuthEnvelopedData>) {
		let mut config = Cms::client(server, &create_test_certificate());
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
	/// sends: content of type `id-signedData` under the closing key.
	fn sealed_finished(sealer: Sealer<DefaultCryptoProvider>, finished: &SignedData) -> AuthEnvelopedData {
		let finished_der = finished.to_der().expect("the Finished encodes");
		let sealed = sealer.seal(SIGNED_DATA, finished_der);
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
		finished.certificates = Some(CertificateFixtures::set_of([certificate.to_owned()]));
		finished
	}

	/// `finished` with its `certificates` set to `certificates`, which DER
	/// sorts.
	fn with_certificates(mut finished: SignedData, certificates: impl IntoIterator<Item = Certificate>) -> SignedData {
		finished.certificates = Some(CertificateFixtures::set_of(certificates));
		finished
	}

	/// A client Finished signed by `client` over `transcript_hash` that embeds
	/// its certificate and carries `confirmation`, as a client with an identity
	/// builds it before the seal.
	///
	/// The fixture builds it outside the client flow, so a server that reads it
	/// is tested against the message format alone.
	fn build_test_client_finished(
		client: &TestCertificate,
		transcript_hash: &TranscriptHash,
		confirmation: &KeyConfirmation,
	) -> SignedData {
		let signed = signed_finished(FinishedRole::Client, &client.signing_key, transcript_hash, &client.certificate);
		let confirmed = with_unsigned_attrs(signed, Some(unsigned_attrs(vec![attribute(confirmation)])));
		with_certificate(confirmed, &client.certificate)
	}

	/// `finished` with its key-confirmation tag replaced by `confirmation` and
	/// every other unsigned attribute kept, as a reflecting party would build
	/// it. The unsigned attributes sit outside the signature, so it still
	/// verifies.
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
	/// The fixture builds it outside the client flow, so a server that reads it
	/// is tested against the message format alone.
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
		let recipient = recipient_of(server);
		let recipient = Recipient::Kem { recipient: &recipient, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };

		let sealed = AuthEnvelopedData::seal::<DefaultCryptoProvider>(
			recipient,
			HANDSHAKE_OPENING_CONTENT,
			content,
			attributes,
			None,
		);
		sealed.expect("the opening seals")
	}

	/// The KEM recipient of `certificate`, admitted for key agreement under
	/// the house KEM.
	fn recipient_of(certificate: &Certificate) -> KemRecipient<DhKemSecp256k1> {
		let purpose = KeyPurposes::HOUSE.server;
		let admitted = PeerCertificate::<KeyAgreement<DhKemSecp256k1>>::parse(certificate.to_owned(), purpose);
		let admitted = admitted.expect("the test certificate is admitted for key agreement");
		KemRecipient::from_certificate(admitted).expect("the test certificate names its recipient")
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

	/// A server that holds `identity` under `peer_authentication`, with the
	/// key-agreement certificate a hand-built opening seals to.
	fn server_with(
		identity: &TestServerIdentity,
		peer_authentication: PeerAuthentication,
	) -> (TestServer<Cms>, Certificate) {
		let mut config = Cms::server(identity);
		config.peer_authentication = peer_authentication;
		(Handshake::server(config), identity.key_agreement.certificate.to_owned())
	}

	/// A server that demands no client certificate, with the certificate a
	/// hand-built opening seals to.
	fn anonymous_server() -> (TestServer<Cms>, Certificate) {
		server_with(&create_test_server(), PeerAuthentication::Anonymous)
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

		/// The closing that carries `finished`, sealed under the closing key of
		/// the client that built the opening, as that client seals it.
		fn sealed(&self, finished: &SignedData) -> HandshakeMessage {
			let sealed = self.sealed_finished(finished);
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// `finished` sealed as [`Self::sealed`] seals it, before it is
		/// wrapped as a closing.
		fn sealed_finished(&self, finished: &SignedData) -> AuthEnvelopedData {
			let sealer = self.confirming.closing_sealer(Some(&test_base_secret()), &self.ephemeral);
			sealed_finished(sealer, finished)
		}
	}

	/// The closing sealer of a fixture handshake secret, foreign to the
	/// server, over `transcript_hash`.
	fn foreign_closing_sealer(transcript_hash: &TranscriptHash) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::new(transcript_hash.as_bytes());
		let foreign = fixture_handshake_secret(0x42);
		let sealer = foreign.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, transcript_hash);
		sealer.expect("a fixture secret derives a closing key")
	}

	/// The base secret of [`TEST_BASE_SECRET`].
	fn test_base_secret() -> BaseSecret {
		let base = BaseSecret::try_from(SecretSlice::from(TEST_BASE_SECRET.to_vec()));
		base.expect("32 bytes make a base secret")
	}

	/// A server that holds `identity` under `peer_authentication` and has
	/// answered a hand-built opening under the agreement key `ephemeral`.
	async fn awaiting_finished(
		identity: &TestServerIdentity,
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
		identity: &TestServerIdentity,
		config: TestServerConfig<Cms>,
		ephemeral: SecretKey<Secp256k1>,
		offers: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AwaitingFinished {
		let mut server = Handshake::server(config);
		let sender = ephemeral.to_owned();
		let sealed = build_test_opening_from(sender, &identity.key_agreement.certificate, &TEST_BASE_SECRET, offers);

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

		let confirmation = confirming.tag(Some(&test_base_secret()), &ephemeral);
		let server_finished = server_finished.value().to_owned();
		AwaitingFinished { server, server_finished, confirmation, confirming, ephemeral }
	}

	/// A server that demands no client certificate and awaits the client
	/// Finished of a fresh agreement key.
	async fn server_awaiting_finished() -> AwaitingFinished {
		let identity = create_test_server();
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		awaiting_finished(&identity, PeerAuthentication::Anonymous, ephemeral).await
	}

	/// The transcript hash a server Finished signed, read from its content.
	fn signed_transcript(server_finished: &SignedData) -> TranscriptHash {
		let content = server_finished.encap_content_info.econtent.as_ref();
		let content = content.expect("a Finished carries content");
		let content = content.decode_as::<OctetString>().expect("the content is an OCTET STRING");

		let signed = content.as_bytes().strip_prefix(TIGHTBEAM_SERVER_FINISHED_DOMAIN);
		let signed = signed.expect("the content names the server role");
		fixture_transcript::<Sha3_256>(signed)
	}

	/// The content of `finished` once its one signer verifies under the
	/// certificate of `signer`, admitted for signing.
	fn verified_content(finished: &SignedData, signer: &TestCertificate) -> Result<Vec<u8>, SignerError> {
		let content = CmsSigner::content(finished, DATA)?;
		let signer_info = finished.signer_infos.0.iter().next().ok_or(SignerError::Content)?;
		let presented = signer.certificate.to_owned();
		let purpose = KeyPurposes::HOUSE.server;
		let certificate = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(presented, purpose)?;

		CmsSigner::verify_signer::<DefaultCryptoProvider>(signer_info, &certificate, SignedContent::data(content))?;
		Ok(content.to_vec())
	}

	/// The one signer of `finished`.
	fn finished_signer(finished: &SignedData) -> SignerInfo {
		let mut signers = finished.signer_infos.0.iter();
		let signer = signers.next().expect("a Finished has one signer");
		signer.clone()
	}

	/// The opening carries the 32-byte base secret, and it opens under the
	/// key of the server's key-agreement certificate.
	#[tokio::test]
	async fn the_opening_opens_under_the_server_key_agreement_key() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (_, sealed) = client_after_opening(&server, None);
		let identity = server.key_agreement_identity();
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
		let server = create_test_server();
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
		let server = create_test_server();
		let offer = SecurityOffer::new(vec![create_default_test_profile()]);
		let (_, sealed) = client_after_opening(&server, Some(offer.to_owned()));

		let carried = sealed.value().auth_attrs.find_unsigned_attr(SecurityOffer::OID)?;
		let carried = carried.ok_or("the opening carries its offer")?.decode::<SecurityOffer>()?;
		assert_eq!(carried, offer);
		Ok(())
	}

	/// A client whose store refuses its pinned certificate after the trust
	/// was built refuses to build the opening, and the refusal spends the
	/// client.
	#[test]
	fn a_refused_provisioned_server_leaves_the_client_spent() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let pinned = server.key_agreement.certificate.to_owned();
		let revocation = LaterRevocation::of(pinned.to_owned());
		let trust = ProvisionedTrust::new(Arc::new(pinned), Arc::new(server.store_with(revocation.clone())))?;

		revocation.revoke();

		let identity = client_identity(&create_test_certificate());
		let config = TestClientConfig::<Cms>::new(CmsClientSettings { trust, identity }, KeyPurposes::HOUSE)?;

		let mut client = Handshake::client(config);
		let refusal = client.start();
		assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		assert_eq!(client.phase(), HandshakePhase::Spent);
		assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A client of a server of `identity`, beside the reply the server sent
	/// to the client's opening.
	async fn replied(identity: &TestServerIdentity) -> (TestClient<Cms>, HandshakeMessage) {
		let (mut server, _) = server_with(identity, PeerAuthentication::Anonymous);
		let (client, sealed) = client_after_opening(identity, None);
		let reply = server.reply(opening(sealed.into_value())).await;
		let reply = reply.expect("the server admits the opening");
		(client, reply)
	}

	/// `reply` with the `s` of its signature flipped to `n - s`. ECDSA verifies
	/// both (SEC 1 v2.0 §4.1.4), so the signature still verifies, and the
	/// server Finished MACs the octets of the other one.
	fn with_signature_flipped(reply: &HandshakeMessage) -> HandshakeMessage {
		let mut signed_data = reply_signed_data(reply);
		let signers = core::mem::take(&mut signed_data.signer_infos.0).into_vec();
		let [signer] = <[SignerInfo; 1]>::try_from(signers).expect("a reply has one signer");
		let low = Signature::<Secp256k1>::from_der(signer.signature.as_bytes()).expect("the signature is DER");
		let (r, s) = low.split_scalars();
		let high = Signature::<Secp256k1>::from_scalars(r, -s).expect("n - s is a scalar");
		let signature = OctetString::new(high.to_der().as_bytes()).expect("a signature is an OCTET STRING");

		let signer = SignerInfo { signature, ..signer };
		signed_data.signer_infos = vec![signer].try_into().expect("one signer is a SET");
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// A client answers a reply with its client Finished sealed as an
	/// `AuthEnvelopedData` of content type `id-signedData`.
	#[tokio::test]
	async fn a_reply_is_answered_with_a_sealed_client_finished() -> Result<(), Box<dyn Error>> {
		let (mut client, reply) = replied(&create_test_server()).await;

		let closing = client.respond(reply).await?;
		let sealed = closing.auth_enveloped()?;
		assert_eq!(sealed.value().auth_encrypted_content_info.content_type, SIGNED_DATA);
		Ok(())
	}

	/// A server Finished whose signature verifies but that carries no server
	/// Finished MAC is refused before the client builds any closing, and the
	/// client admits no further step.
	#[tokio::test]
	async fn a_reply_without_a_server_finished_mac_is_refused_before_the_closing() {
		let server = create_test_server();
		let (mut client, sealed) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sealed, &fresh_server_ephemeral());

		let refusal = client.respond(reply(finished)).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// A reply whose server Finished MAC covers another signature than the one
	/// it carries is refused before the client builds any closing, though that
	/// signature verifies.
	#[tokio::test]
	async fn a_reply_whose_server_finished_covers_another_signature_is_refused() {
		let (mut client, reply) = replied(&create_test_server()).await;
		let flipped = with_signature_flipped(&reply);

		let refusal = client.respond(flipped).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// The sealed client Finished a client answers a reply with, beside the
	/// transcript hash the reply's server Finished signed.
	async fn sealed_client_finished() -> (AuthEnvelopedData, TranscriptHash) {
		let (mut client, reply) = replied(&create_test_server()).await;
		let transcript_hash = signed_transcript(&reply_signed_data(&reply));

		let closing = client.respond(reply).await.expect("the client answers the reply");
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
	/// of version 4 (RFC 5652 §6.2.3).
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
		let key_identifier = [TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, transcript_hash.as_bytes()].concat();
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
		let identity = create_test_server();
		let mut server = Handshake::server(Cms::server(&identity));
		let mut client = Handshake::client(Cms::client(&identity, &create_test_certificate()));

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
		let identity = create_test_server();
		let mut server = Handshake::server(Cms::server(&identity));
		let mut client = Handshake::client(Cms::client(&identity, &create_test_certificate()));

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
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());
		let stripped = with_unsigned_attrs(finished, None);

		let result = client.respond(reply(stripped)).await;
		assert!(matches!(result, Err(HandshakeError::MissingAttribute)));
	}

	/// A server Finished that carries an abort alert is refused before any
	/// attribute is read.
	#[tokio::test]
	async fn a_server_finished_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());
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
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let ephemeral = fresh_server_ephemeral();
		let ephemeral_bytes = HandshakeAttribute::transcript_bytes(&ephemeral)?;
		let certificates = certificates_field([server.signing.certificate.to_owned()]);
		let transcript = [sent.der(), &ephemeral_bytes, &certificates].concat();
		let attrs = unsigned_attrs(vec![attribute(&ephemeral)]);
		let finished = signed_server_finished(&server.signing, &transcript, attrs);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
		Ok(())
	}

	/// A validly signed server Finished that selects a profile outside the
	/// client's offer is refused.
	#[tokio::test]
	async fn a_client_refuses_a_profile_it_did_not_offer() {
		let server = create_test_server();
		let foreign = SecurityProfileDesc { aead: Some(AES_128_GCM), ..create_default_test_profile() };
		let offer = SecurityOffer::new(vec![foreign]);
		let (mut client, sent) = client_after_opening(&server, Some(offer));
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// A validly signed server ephemeral that encodes the identity point is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_identity_server_ephemeral_is_refused() {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let identity = with_point(fresh_server_ephemeral(), &[0x00]);
		let finished = server_finished_over(&server.signing, &sent, &identity);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral whose x-coordinate lies off the
	/// curve is refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let off_curve = with_point(fresh_server_ephemeral(), &off_curve_point());
		let finished = server_finished_over(&server.signing, &sent, &off_curve);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let static_key = server.signing.signing_key.verifying_key().originator_key()?;
		let finished = server_finished_over(&server.signing, &sent, &static_key);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A validly signed server ephemeral that is the key of the server's
	/// key-agreement certificate is refused, so the agreement cannot collapse
	/// into the key the opening sealed to.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_key_agreement_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let static_key = server.key_agreement.signing_key.verifying_key().originator_key()?;
		let finished = server_finished_over(&server.signing, &sent, &static_key);

		let result = client.respond(reply(finished)).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A server answers a hand-built opening with a Finished that verifies
	/// under its static key. Its content is the server role over the hash of
	/// four legs, in this order:
	///
	/// 1. the opening as it was sent,
	/// 2. the accept,
	/// 3. the server ephemeral, and
	/// 4. the `certificates` field the Finished carries.
	///
	/// The test computes the expected hash by hand, so a server that binds
	/// another layout fails here even when a client binds the same one.
	#[tokio::test]
	async fn a_hand_built_opening_is_answered_with_a_signed_server_finished() -> Result<(), Box<dyn Error>> {
		let identity = create_test_server();
		let (mut server, server_certificate) = server_with(&identity, PeerAuthentication::Anonymous);
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);
		let message = opening(sealed);
		let sent = message.der().to_vec();

		let finished = server.reply(message).await?.signed()?;
		let content = verified_content(finished.value(), &identity.signing)?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?;
		let ephemeral = HandshakeAttribute::transcript_bytes(&ephemeral.decode::<OriginatorPublicKey>()?)?;
		let certificates = certificates_field([identity.signing.certificate.to_owned()]);
		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral, certificates].concat())?;
		let server_content = FinishedRole::Server.content::<Sha3_256>(&expected, &identity.signing.certificate)?;
		assert_eq!(content, server_content);
		Ok(())
	}

	/// An opening whose unauthenticated SET OF arrives out of DER order is not
	/// the DER of the value it decodes to, so the decode refuses it before a
	/// server reads it (X.690 § 11.6).
	#[test]
	fn an_opening_whose_attributes_arrive_out_of_der_order_is_refused() {
		let (_, server_certificate) = anonymous_server();
		let attrs = [marker_attribute(1), marker_attribute(2)];
		let sealed = with_unauth_attrs(build_test_opening(&server_certificate, &TEST_BASE_SECRET, []), attrs);
		let sent = misordered_der(&sealed);

		let refused = WireDer::<AuthEnvelopedData>::try_from(sent.as_slice());
		let noncanonical = ErrorKind::Noncanonical { tag: Tag::Sequence };
		assert_eq!(refused.map_err(|error| error.kind()), Err(noncanonical));
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

		let recipient = recipient_of(&server_certificate);
		let recipient = Recipient::Kem { recipient: &recipient, ukm_label: b"tb/handshake/other/ukm/v1" };
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
		let identity = create_test_server();
		let authorizer = Arc::new(RecordingAuthorizer::default());
		let mut config = Cms::server(&identity);
		config.transport = Some(budget_offer());
		config.transport_authorizer = Some(authorizer.to_owned());

		let mut server = Handshake::server(config);

		let sealed = build_test_opening(
			&identity.key_agreement.certificate,
			&TEST_BASE_SECRET,
			[attribute(&budget_offer())],
		);
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

	/// A server Finished carries the content type, the message digest, and
	/// the algorithm protection as signed attributes (RFC 5652 §5.3, RFC 6211).
	#[tokio::test]
	async fn a_server_finished_carries_the_three_signed_attributes() -> Result<(), Box<dyn Error>> {
		let identity = create_test_server();
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
		let identity = create_test_server();
		let (mut server, server_certificate) = server_with(&identity, PeerAuthentication::Anonymous);
		let sealed = build_test_opening(&server_certificate, &TEST_BASE_SECRET, []);

		let finished = server.reply(opening(sealed)).await?.signed()?;
		let signer = finished_signer(finished.value());
		assert_eq!(signer.version, CmsVersion::V3);
		assert_eq!(signer.sid, identity.signing.certificate.signer_identifier()?);
		assert_eq!(finished.value().version, CmsVersion::V3);
		Ok(())
	}

	/// The client refuses a server Finished whose signer carries no signed
	/// attributes (RFC 5652 §5.4).
	#[tokio::test]
	async fn a_server_finished_without_signed_attributes_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());
		let mut signer = finished_signer(&finished);
		signer.signed_attrs = None;

		let stripped = SignedData { signer_infos: vec![signer].try_into()?, ..finished };
		let refusal = client.respond(reply(stripped)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// The client refuses a server Finished whose `SignedData` version breaks
	/// the RFC 5652 §5.1 rule.
	#[tokio::test]
	async fn a_server_finished_of_the_wrong_version_is_refused() {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());
		let downgraded = SignedData { version: CmsVersion::V1, ..finished };

		let refusal = client.respond(reply(downgraded)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A server Finished whose `sid` names a certificate it does not carry
	/// names no server to admit, though its signature verifies under the
	/// server's key.
	#[tokio::test]
	async fn a_server_finished_naming_another_certificate_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = server_finished_over(&server.signing, &sent, &fresh_server_ephemeral());
		let mut signer = finished_signer(&finished);
		signer.sid = create_test_certificate().certificate.signer_identifier()?;

		let renamed = SignedData { signer_infos: vec![signer].try_into()?, ..finished };
		let refusal = client.respond(reply(renamed)).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
		Ok(())
	}

	/// The server Finished carries the server's signing certificate in
	/// `certificates`, and its one signer names that certificate
	/// (RFC 5652 §5.1, §5.3).
	#[tokio::test]
	async fn a_server_finished_carries_the_certificate_its_signer_names() -> Result<(), Box<dyn Error>> {
		let identity = create_test_server();
		let (_, reply) = replied(&identity).await;

		let finished = reply_signed_data(&reply);
		let named = CmsSigner::signer_certificate(&finished)?;
		assert_eq!(named, Some(&identity.signing.certificate));
		Ok(())
	}

	/// A server Finished without the certificate its signer names is refused,
	/// because it names no server to admit.
	#[tokio::test]
	async fn a_server_finished_without_its_certificate_is_refused() {
		let (mut client, sent) = replied(&create_test_server()).await;
		let mut finished = reply_signed_data(&sent);
		finished.certificates = None;

		let refusal = client.respond(reply(finished)).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
	}

	/// The transcript binds the certificate the server Finished carries as it
	/// arrived, so one swapped for another the authority issued for the same
	/// key, of the same subject and the same key identifier, fails the
	/// signature (RFC 9846 §4.5.2).
	#[tokio::test]
	async fn a_reply_whose_certificate_was_swapped_for_one_of_the_same_key_is_refused() {
		let identity = create_test_server();
		let (mut client, sent) = replied(&identity).await;
		let twin = identity.fixture().signing_twin(9);
		let swapped = with_certificate(reply_signed_data(&sent), &twin);

		let refusal = client.respond(reply(swapped)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A control of the swap above: the twin itself is admitted as the
	/// server's signing certificate, so the refusal is the transcript's.
	#[test]
	fn a_signing_twin_names_the_signer_of_the_reply() -> Result<(), Box<dyn Error>> {
		let identity = create_test_server();
		let twin = identity.fixture().signing_twin(9);
		let store = identity.store();
		store.evaluate(&twin)?;

		let named = twin.is_named_by(&identity.signing.certificate.signer_identifier()?)?;
		assert!(named);
		Ok(())
	}

	/// A reply whose certificate carries its RDN values in another order than
	/// DER, which would decode to the same value, is refused as it arrives
	/// under its `[3]` envelope, before the client binds a byte of it
	/// (X.690 §11.6, CWE-345).
	#[tokio::test]
	async fn a_reply_whose_certificate_bytes_were_reordered_is_refused() {
		let identity = create_named_test_server(two_valued_name());
		let (_client, sent) = replied(&identity).await;
		let envelope_tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		let arrived = tlv(envelope_tag, &with_rdn_values_swapped(&sent));

		let refused = TransportEnvelope::from_der(&arrived).err().map(|error| error.kind());
		assert_eq!(refused, Some(ErrorKind::SetOrdering));
	}

	/// A client that names its static key as its agreement key `R` leaves the
	/// session to the secrecy of that one key, so the server refuses the
	/// closing whose certificate holds that key.
	#[tokio::test]
	async fn an_agreement_key_equal_to_the_client_static_key_is_refused() {
		let identity = create_test_server();
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
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::SpkiError(_)
			))
		));
	}

	/// An offered certificate whose `keyUsage` lacks `digitalSignature` is
	/// refused where the opened Finished is parsed, as the signing use reads
	/// it.
	#[tokio::test]
	async fn an_offered_certificate_without_digital_signature_is_refused() {
		let mut awaiting = server_awaiting_finished().await;
		let mut client = create_test_certificate();
		let usage = KeyUsage(KeyUsages::KeyAgreement.into());
		client.certificate = crate::testing::fixtures::TestCertificate::with_key_usage(client.certificate, usage);

		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)
			))
		));
	}

	/// An offered certificate that names the server's purpose alone is
	/// refused for the client role (RFC 5280 §4.2.1.12).
	#[tokio::test]
	async fn an_offered_server_certificate_is_refused_as_the_client() {
		let mut awaiting = server_awaiting_finished().await;
		let mut client = create_test_certificate();
		client.certificate = of_purpose(client.certificate, KeyPurposes::HOUSE.server);

		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::ExcludedKeyPurpose
			))
		));
	}

	/// A server whose own certificate names the client's purpose alone holds
	/// no certificate of its role, so its configuration is refused.
	#[test]
	fn a_server_configuration_of_a_client_certificate_is_refused() {
		let mut identity = create_test_server();
		identity.signing.certificate = of_purpose(identity.signing.certificate, KeyPurposes::HOUSE.client);
		let profiles = SupportedProfiles::from(create_default_test_profile());

		let refusal = TestServerConfig::<Cms>::new(CmsServerSettings, identity.pair(), profiles, KeyPurposes::HOUSE);
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::ExcludedKeyPurpose
			))
		));
	}

	/// A server configured with an implementor's own server purpose reads its
	/// signing certificate of that purpose as its role's, so it replies.
	#[tokio::test]
	async fn a_server_of_its_own_purpose_replies() -> Result<(), Box<dyn Error>> {
		let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.10");
		let mut identity = create_test_server();
		identity.signing.certificate = of_purpose(identity.signing.certificate, own);
		let sealed = build_test_opening(&identity.key_agreement.certificate, &TEST_BASE_SECRET, []);
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let purposes = KeyPurposes { server: own, ..KeyPurposes::HOUSE };
		let config = TestServerConfig::<Cms>::new(CmsServerSettings, identity.pair(), profiles, purposes)?;
		let mut server = Handshake::server(config);

		let reply = server.reply(opening(sealed)).await;
		assert!(reply.is_ok());
		Ok(())
	}

	/// A client whose own certificate names the server's purpose alone holds
	/// no certificate of its role, so its configuration is refused.
	#[test]
	fn a_client_configuration_of_a_server_certificate_is_refused() {
		let server = create_test_server();
		let client = create_test_certificate();
		let certificate = of_purpose(client.certificate, KeyPurposes::HOUSE.server);
		let identity = TestIdentity::presenting(certificate, &client.signing_key);
		let settings = CmsClientSettings { trust: server.trust(), identity };

		let refusal = TestClientConfig::<Cms>::new(settings, KeyPurposes::HOUSE);
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::ExcludedKeyPurpose
			))
		));
	}

	/// `certificate` with an `extendedKeyUsage` that names `purpose` alone.
	fn of_purpose(certificate: Certificate, purpose: ObjectIdentifier) -> Certificate {
		crate::testing::fixtures::TestCertificate::with_key_purposes(certificate, [purpose])
	}

	/// The container an HPKE hello travels in, a `ContentInfo` of type
	/// `id-data`, as an on-path party would send it to a CMS server.
	fn hpke_hello() -> HandshakeMessage {
		let octets = OctetString::new([0x41u8; 32]).expect("bytes are an OCTET STRING");
		let content = Any::encode_from(&octets).expect("an OCTET STRING encodes");
		let hello = ContentInfo { content_type: DATA, content };
		HandshakeMessage::try_from(hello).expect("the ContentInfo encodes")
	}

	/// An HPKE hello sent to a CMS server as its opening is refused before
	/// any key is read.
	#[tokio::test]
	async fn a_cms_server_refuses_an_hpke_hello_as_its_opening() {
		let (mut server, _) = anonymous_server();
		let refusal = server.reply(hpke_hello()).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// An HPKE hello sent to a CMS server as its closing is refused before
	/// the server opens anything.
	#[tokio::test]
	async fn a_cms_server_refuses_an_hpke_hello_as_its_closing() {
		let mut awaiting = server_awaiting_finished().await;
		let refusal = awaiting.server.finish(hpke_hello()).await;
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

	/// An opening that carries a duplicate SecurityOffer attribute fails
	/// closed, as the client does. Read as no offer, it would fall through to
	/// dealer's choice.
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

	/// An opening that carries a duplicate TransportOffer attribute fails
	/// closed the same way. Read as no offer, it would leave the connection
	/// single-flight.
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

	/// The server takes the certificate the client Finished's `sid` names, so
	/// a Finished that carries its chain closes the handshake. The fixed
	/// chain's leaf sorts second of the three in the DER SET.
	#[tokio::test]
	async fn a_finished_carrying_its_chain_closes_under_its_leaf() -> Result<(), Box<dyn Error>> {
		let chain = crate::testing::fixtures::TestCertificate::insecure_fixed_chain()?;
		let mut awaiting = server_awaiting_finished().await;
		let signed = signed_finished(FinishedRole::Client, &chain.leaf_key, awaiting.transcript_hash(), &chain.leaf);
		let confirmed = with_unsigned_attrs(signed, Some(unsigned_attrs(vec![attribute(&awaiting.confirmation)])));
		let finished = with_certificates(confirmed, [chain.leaf, chain.intermediate, chain.root]);
		let closing = awaiting.sealed(&finished);

		awaiting.server.finish(closing).await?;
		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	/// A client Finished whose `certificates` hold no certificate its `sid`
	/// names is refused, though the set carries the signer's chain.
	#[tokio::test]
	async fn a_finished_whose_certificates_omit_its_signer_is_refused() -> Result<(), Box<dyn Error>> {
		let chain = crate::testing::fixtures::TestCertificate::insecure_fixed_chain()?;
		let mut awaiting = server_awaiting_finished().await;
		let signed = signed_finished(FinishedRole::Client, &chain.leaf_key, awaiting.transcript_hash(), &chain.leaf);
		let confirmed = with_unsigned_attrs(signed, Some(unsigned_attrs(vec![attribute(&awaiting.confirmation)])));
		let finished = with_certificates(confirmed, [chain.intermediate, chain.root]);
		let closing = awaiting.sealed(&finished);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
		Ok(())
	}

	/// A client Finished is a proof, so a closing that names no certificate to
	/// verify it under is refused, even by a server that demands no identity.
	#[tokio::test]
	async fn a_finished_with_no_certificate_is_refused() {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let transcript_hash = awaiting.transcript_hash();
		let signed = signed_finished(FinishedRole::Client, &client.signing_key, transcript_hash, &client.certificate);
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
	/// tag and the countersignature both travel inside the sealed Finished, so
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
			Err(HandshakeError::SealedClosing(EnvelopeError::Authentication))
		));
		assert_eq!(server.phase(), HandshakePhase::Spent);
		assert_eq!(observer.outcomes(), 0);
		Ok(())
	}

	/// An honest budget-bearing closing settles, and the observer hears of one
	/// outcome, so this test is the control for the count of zero after an
	/// altered closing.
	#[tokio::test]
	async fn an_honest_budget_bearing_closing_reports_one_outcome() -> Result<(), Box<dyn Error>> {
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
		let closing = client.respond(reply).await?;
		server.finish(closing).await?;
		assert_eq!(observer.outcomes(), 1);
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
		let sealer = foreign_closing_sealer(&transcript_hash);

		let refusal = server.finish(sealed_closing(sealer, &forged)).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(EnvelopeError::KeyUnwrap))));
		assert_eq!(server.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// The server's own Finished, returned as the client's with the server
	/// certificate and the client's key-confirmation tag attached, fails
	/// because each Finished signs its role. The expiry-only validator accepts
	/// the server certificate.
	#[tokio::test]
	async fn a_reflected_server_finished_is_refused() {
		let server_identity = create_test_server();
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		let mutual = mutual_with(ExpiryValidator);

		// The reflected Finished embeds the server certificate, which the
		// validator accepts. The tag confirms the secret the server derives,
		// so the refusal is the role mismatch in the signature.
		let mut awaiting = awaiting_finished(&server_identity, mutual, ephemeral).await;
		let reflected = with_certificate(awaiting.server_finished.to_owned(), &server_identity.signing.certificate);
		let reflected = with_confirmation(reflected, &awaiting.confirmation);
		let closing = awaiting.sealed(&reflected);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A sealed client Finished that carries an abort alert beside it is
	/// refused before the server opens it.
	///
	/// The content is sealed under a foreign key, and the refusal names the
	/// alert, so the alert is read first.
	#[tokio::test]
	async fn a_client_finished_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let sealer = foreign_closing_sealer(awaiting.transcript_hash());
		let sealed = sealed_finished(sealer, &finished);
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, Any::encode_from(&5u8)?)?;
		let attrs = unsigned_attrs(vec![alert]);
		let alerted = AuthEnvelopedData { unauth_attrs: Some(attrs), ..sealed };

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(alerted)?).await;
		let expected = HandshakeAlert::FinishedIntegrityFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A sealed Finished whose encrypted content names the anonymous form
	/// while its authenticated content type names the Finished is refused
	/// before its content opens.
	#[tokio::test]
	async fn a_sealed_finished_of_another_content_type_is_refused() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = server_awaiting_finished().await;
		let finished = build_test_client_finished(&client, awaiting.transcript_hash(), &awaiting.confirmation);
		let mut sealed = awaiting.sealed_finished(&finished);
		sealed.auth_encrypted_content_info.content_type = DATA;

		let closing = HandshakeMessage::try_from(sealed)?;
		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedClosing(EnvelopeError::ContentType(_)))
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
			Err(HandshakeError::SealedClosing(EnvelopeError::ContentEncryptionAlgorithm))
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
			Err(HandshakeError::SealedClosing(EnvelopeError::Authentication))
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
			Err(HandshakeError::SealedClosing(EnvelopeError::MissingContent))
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
			Err(HandshakeError::SealedClosing(EnvelopeError::Authentication))
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
			Err(HandshakeError::SealedClosing(EnvelopeError::Authentication))
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
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(EnvelopeError::KeyUnwrap))));
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
		let identity = create_test_server();
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
	/// `cryptography`) and HKDF (Python's `hmac` and `hashlib`), so they are
	/// independent of the crate's code.
	#[test]
	fn the_cms_handshake_secret_matches_its_known_answer() -> Result<(), Box<dyn Error>> {
		let ephemeral = SecretKey::<Secp256k1>::from_slice(&[0x03u8; 32])?;
		let pending = Box::new(CmsPending { base: test_base_secret(), ephemeral });
		let server_ephemeral = PeerPoint::<Secp256k1>::parse(KNOWN_SERVER_EPHEMERAL)?;
		let salt = KdfSalt::new(&[0x99u8; 32]);

		let agree = <Box<CmsPending<Secp256k1>> as ClientAgreement<DefaultCryptoProvider>>::agree;
		let secret = agree(pending, &server_ephemeral, salt)?;
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
		let server_identity = create_test_server();
		let identity = client_identity(&create_test_certificate());
		let settings = CmsClientSettings { trust: server_identity.trust(), identity };
		let profiles = SupportedProfiles::from(RunnableProfile::<Aes256Sha3_512Provider>::native().descriptor());
		let pair = server_identity.pair();
		let server_config = ServerConfig::new(CmsServerSettings, pair, profiles, KeyPurposes::HOUSE)?;
		let client_config = ClientConfig::new(settings, KeyPurposes::HOUSE)?;
		let mut client = Handshake::<Client, Cms, Aes256Sha3_512Provider>::client(client_config);
		let mut server = Handshake::<Server, Cms, Aes256Sha3_512Provider>::server(server_config);

		let opening = client.start()?;
		let reply = server.reply(opening).await?;
		let closing = client.respond(reply).await?;
		server.finish(closing).await?;

		let transcript_hash = server.transcript_hash().ok_or("the reply sealed the transcript")?;
		assert_eq!(transcript_hash.as_bytes().len(), 64);
		Ok(())
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

	/// Write each sample of `emitted` under its name, what opens each
	/// `KEKRecipientInfo` sample, and the DER of the five certificates, when
	/// the environment asks for interop samples.
	fn write_samples(emitted: &Emitted) -> std::io::Result<()> {
		let certificates = [
			("server-certificate", &emitted.server_certificate),
			("server-key-agreement-certificate", &emitted.server_key_agreement_certificate),
			("client-certificate", &emitted.client_certificate),
			("test-root", &emitted.test_root),
			("chain-root", &emitted.chain_root),
		];
		write_interop_samples(&emitted.samples(), &emitted.kek_openings(), &certificates)
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
		let certificates = CertificateFixtures::set_of([identity.certificate().to_owned()]);
		let signed = CmsSigner::signed_data(SignedContent::data(&tbs), signer, Some(certificates));
		signed.expect("the frame signature assembles").into_inner()
	}

	/// One of each structure the CMS flow and a signed frame emit, the two
	/// certificates that verify the signed ones, the certificate the opening
	/// seals to, and the authority that issued the three.
	struct Emitted {
		/// The opening, an `AuthEnvelopedData` with a `KEMRecipientInfo`.
		opening: AuthEnvelopedData,
		/// The server Finished, the signer's `SignedData`.
		server_finished: SignedData,
		/// The server Finished of a server whose signing certificate sits
		/// under an intermediate, which the Finished carries beside it.
		chained_finished: SignedData,
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
		/// The signing certificate of the server.
		server_certificate: Certificate,
		/// The key-agreement certificate of the server, which the opening
		/// names as its recipient.
		server_key_agreement_certificate: Certificate,
		/// The certificate of the client.
		client_certificate: Certificate,
		/// The authority that issued the server's two certificates and the
		/// client's, the one root OpenSSL verifies the signed samples under.
		test_root: Certificate,
		/// The root of the chained server, the one certificate OpenSSL holds
		/// when it verifies [`Self::chained_finished`].
		chain_root: Certificate,
		/// What OpenSSL opens [`Self::sealed_finished`] with.
		sealed_finished_opening: KekOpening,
		/// What OpenSSL opens [`Self::kek_seal`] with.
		kek_seal_opening: KekOpening,
	}

	impl Emitted {
		/// Each structure as its interop sample: its file name and the DER of
		/// its `ContentInfo`.
		fn samples(&self) -> [(&'static str, Vec<u8>); 8] {
			[
				("cms-opening", content_info(AUTH_ENVELOPED_DATA, &self.opening)),
				("server-finished", content_info(SIGNED_DATA, &self.server_finished)),
				("server-finished-chained", content_info(SIGNED_DATA, &self.chained_finished)),
				("session-receipt", content_info(SIGNED_DATA, &self.session_receipt)),
				("sealed-finished", content_info(AUTH_ENVELOPED_DATA, &self.sealed_finished)),
				("kek-seal", content_info(AUTH_ENVELOPED_DATA, &self.kek_seal)),
				("frame-signature", content_info(SIGNED_DATA, &self.frame_signature)),
				("joined-receipt", content_info(SIGNED_DATA, &self.joined_receipt)),
			]
		}

		/// Each `KEKRecipientInfo` sample's file name beside what opens it.
		fn kek_openings(&self) -> [(&'static str, &KekOpening); 2] {
			let sealed_finished = ("sealed-finished", &self.sealed_finished_opening);
			[sealed_finished, ("kek-seal", &self.kek_seal_opening)]
		}
	}

	/// A client identity the authority of `server` issued, so the signed
	/// samples verify under one root.
	fn issued_client(server: &TestServerIdentity) -> TestCertificate {
		let signing_key = Secp256k1SigningKey::random(&mut OsRng);
		let subject = RdnSequence::from_str("CN=tightbeam interop client").expect("the name parses");
		let certificate = server.fixture().issue_signing(&signing_key, subject, 5);
		TestCertificate { signing_key, certificate }
	}

	/// The server Finished of a server whose signing certificate sits under an
	/// intermediate, as a client whose store holds the root alone admits it.
	async fn chained_finished() -> (SignedData, Certificate) {
		let chained = ChainedTestServer::fixed();
		let client = Cms::client(&chained.identity, &create_test_certificate());
		let server = Cms::server_presenting(&chained.identity, chained.signing_identity());

		let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));
		let opening = client.start().expect("the client of the chained server opens");
		let reply = server.reply(opening).await.expect("the chained server replies");
		let admitted = client.respond(reply.to_owned()).await;
		admitted.expect("a client of the root alone admits the reply");

		let finished = reply.signed().expect("the reply is a SignedData");
		(finished.into_value(), chained.identity.authority)
	}

	/// Run one CMS handshake with a budget, and take one of each structure it
	/// and a signed frame emit.
	async fn emitted() -> Emitted {
		let server_identity = create_test_server();
		let client_identity = issued_client(&server_identity);
		let mut client = Cms::client(&server_identity, &client_identity);
		let mut server = Cms::server(&server_identity);
		server.peer_authentication = mutual_with(ExpiryValidator);

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

		server.finish(closing).await.expect("the server finishes");

		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let salt = KdfSalt::new(&[0x99u8; 32]);
		let secret = fixture_handshake_secret(0x42);
		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Ack, salt, &transcript_hash);
		let sealer = sealer.expect("the acknowledgement key derives");
		let kek_seal_opening = KekOpening::of(&sealer, SecretSeal::Ack, b"countersignature");
		let kek_seal = sealer.seal(DATA, b"countersignature").expect("the acknowledgement seals");

		// The client Finished seals under the closing key of the same fixed
		// secret, so a reader holds its key.
		let finished = build_test_client_finished(&client_identity, &transcript_hash, &fixture_confirmation());
		let finished_der = finished.to_der().expect("the Finished encodes");
		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, &transcript_hash);
		let sealer = sealer.expect("the closing key derives");
		let sealed_finished_opening = KekOpening::of(&sealer, SecretSeal::Closing, &finished_der);
		let sealed_finished = sealer.seal(SIGNED_DATA, finished_der).expect("the Finished seals");

		let reply = reply.signed().expect("the reply is a SignedData");
		let receipt = reply.value().find_unsigned_attr(SESSION_RECEIPT);
		let receipt = receipt.expect("the receipt attribute decodes");
		let receipt = receipt.expect("a budget-bearing Finished carries its receipt");
		let session_receipt = receipt.decode::<Signed<SignedData>>().expect("the receipt is a SignedData");
		let joined_receipt = observer.artifacts().pop().expect("the server reports its outcome");
		let opening = opening.auth_enveloped().expect("the opening is an AuthEnvelopedData");
		let (chained_finished, chain_root) = chained_finished().await;

		Emitted {
			opening: opening.value().to_owned(),
			server_finished: reply.value().to_owned(),
			chained_finished,
			session_receipt: session_receipt.into_inner(),
			sealed_finished,
			kek_seal,
			frame_signature: frame_signature().await,
			joined_receipt: joined_receipt.into_inner(),
			server_certificate: server_identity.signing.certificate,
			server_key_agreement_certificate: server_identity.key_agreement.certificate,
			client_certificate: client_identity.certificate,
			test_root: server_identity.authority,
			chain_root,
			sealed_finished_opening,
			kek_seal_opening,
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
	async fn the_chained_server_finished_decodes_back_from_its_content_info() {
		let emitted = emitted().await;
		assert!(decodes_back(SIGNED_DATA, &emitted.chained_finished));
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

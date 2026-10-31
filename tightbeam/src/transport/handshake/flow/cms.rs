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
use crate::crypto::exchange::{KemCiphertext, KeyExchange, KeyShare, ReplyAttribute};
use crate::crypto::kdf::KdfSalt;
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::{Signed, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::OctetString;
use crate::der::{Choice, Decode, DecodeValue, Encode, Sequence};
use crate::marker::MaybeSendFuture;
use crate::oids::HANDSHAKE_OPENING_CONTENT;
use crate::random::CryptoRngCore;
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::ephemeral::{Distinct, ExchangeSecret, OpenedShare};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientAgreement, ClientLegs, FinishedDraft, HandshakeFlow, Opened, OpeningIntake, OpeningParts,
	ReceivedShare, ReplyBinding, ReplyIntake, ReplyParts, ReplyVerified, ServerAgreement, ServerLegs,
};
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
use crate::transport::handshake::peer::{
	CmsNamedServer, PinnedKeyAgreement, ProvisionedKeyAgreement, ProvisionedTrust,
};
use crate::transport::handshake::primitives::transcript::{ServerFinishedLegs, Transcript};
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::schedule::{BaseSecret, FinishedRole, Salt};
use crate::transport::handshake::{
	ClientShare, CmsIdentityPair, Exchange, HandshakeMessage, HandshakeProvider, HandshakeSecret, ServerShare,
};
use crate::transport::wire_der::WireDer;
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
pub struct CmsOpening {
	/// The transcript, open over the opening as it was sent.
	transcript: Transcript,
	/// The key-agreement certificate the opening sealed to.
	server: PinnedKeyAgreement,
}

/// The secrets a CMS client holds from its opening to the agreement.
pub struct CmsPending<P: HandshakeProvider> {
	/// The base secret the opening carried to the server.
	base: BaseSecret,
	/// The pending half of the exchange of `R`, kept for its completion with
	/// the server's share.
	ephemeral: <Exchange<P> as KeyExchange>::Pending,
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

/// The server's share as the server Finished carries it: an unsigned
/// attribute under the OID of its carrier, whose value the transcript binds.
///
/// A DH reply travels as an `OriginatorPublicKey` (RFC 5652 §6.2.2), and a KEM
/// reply as a [`KemCiphertext`] (RFC 9629 §3), so each field means what its
/// standard says.
impl ReplyAttribute {
	/// Reads the one reply attribute that `finished` carries, beside the bytes
	/// of its value as they arrived.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- `finished` carries no reply attribute.
	/// - [`HandshakeError::DuplicateAttribute`] -- a carrier repeats, or `finished` carries both carriers.
	/// - [`HandshakeError::DerError`] -- a carrier fails to decode.
	fn extract(finished: &SignedData) -> Result<(Self, Vec<u8>), HandshakeError> {
		let key = ReceivedAttribute::<OriginatorPublicKey>::extract(finished)?;
		let ciphertext = ReceivedAttribute::<KemCiphertext>::extract(finished)?;
		match (key, ciphertext) {
			(Some(key), None) => {
				let (key, bytes) = key.into_parts();
				Ok((Self::OriginatorKey(key), bytes))
			}
			(None, Some(ciphertext)) => {
				let (ciphertext, bytes) = ciphertext.into_parts();
				Ok((Self::KemCiphertext(ciphertext), bytes))
			}
			(None, None) => Err(HandshakeError::MissingAttribute),
			(Some(_), Some(_)) => Err(HandshakeError::DuplicateAttribute),
		}
	}

	/// The bytes of the attribute value, as the transcript binds them.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the value fails to encode.
	fn transcript_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
		match self {
			Self::OriginatorKey(key) => HandshakeAttribute::transcript_bytes(key),
			Self::KemCiphertext(ciphertext) => HandshakeAttribute::transcript_bytes(ciphertext),
		}
	}

	/// The attribute under the OID of its carrier.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the value fails to encode.
	fn attribute(&self) -> Result<HandshakeAttribute, HandshakeError> {
		match self {
			Self::OriginatorKey(key) => HandshakeAttribute::encode(key),
			Self::KemCiphertext(ciphertext) => HandshakeAttribute::encode(ciphertext),
		}
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
	type Opening = CmsOpening;
	type Pending = Box<CmsPending<P>>;

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

		// 2. Draw the offer `R` of the exchange, and keep its pending half for
		//    the completion with the server's share. The KEM draws the key it
		//    seals under itself.
		let (ephemeral, offer) = Exchange::<P>::offer(&mut *rng);
		let agreement_key = offer.to_originator_key()?;

		// 3. Encode the content. The DER buffer holds the base secret, so it
		//    wipes when dropped, along with the transient OCTET STRING copy.
		let base_secret = OctetString::new(base.as_bytes())?;
		let content = OpeningContent { base_secret, agreement_key };
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

		// 2. Read the accepts, the server's share, and the receipt, each with
		//    the bytes it arrived as. The share is mandatory.
		let received_accept = ReceivedAttribute::<SecurityAccept>::extract(finished)?;
		let (security_accept, security_accept_bytes) = received_accept.map(ReceivedAttribute::into_parts).unzip();
		let received_transport = ReceivedAttribute::<TransportAccept>::extract(finished)?;
		let (transport_accept, transport_accept_bytes) = received_transport.map(ReceivedAttribute::into_parts).unzip();
		let (server_ephemeral, server_ephemeral_bytes) = ReplyAttribute::extract(finished)?;
		let received_artifact = ReceivedAttribute::<Signed<SignedData>>::extract(finished)?;
		let receipt = received_artifact.map(|received| received.into_parts().0);

		// 3. Build the path the Finished's signer presents, parsed from the bytes it arrived as.
		let presented = reply.signer_path()?;
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

		// 5. Return the facts of the reply, with the share in its carrier until the signature verifies.
		Ok(ReplyIntake {
			server: CmsNamedServer { signing, key_agreement: server },
			security_accept,
			transport_accept,
			server_ephemeral: ReceivedShare::Attribute(server_ephemeral),
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

/// The CMS client derives the hybrid secret: the secret of the exchange, then
/// the base secret its opening carried. The secrets are read in place, so
/// each is wiped where the box drops.
impl<P: HandshakeProvider> ClientAgreement<P> for Box<CmsPending<P>> {
	fn agree(
		self,
		server_ephemeral: &Distinct<ServerShare<P>>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError> {
		let shared = server_ephemeral.complete::<Exchange<P>>(&self.ephemeral)?;
		HandshakeSecret::hybrid::<P>(shared.as_ref(), &self.base, salt)
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
pub struct CmsOpened<P: HandshakeProvider> {
	/// The base secret the opening carried.
	base: BaseSecret,
	/// The client's share `R`, parsed once at the open.
	client_ephemeral: OpenedShare<ClientShare<P>>,
	/// The transcript, open over the opening.
	transcript: Transcript,
}

/// A server Finished that awaits its signature and its receipt.
pub struct CmsReplyDraft {
	/// The server Finished, complete up to its signature.
	finished: FinishedDraft,
	security_accept: SecurityAccept,
	transport_accept: Option<TransportAccept>,
	/// The server's share, in the carrier of its kind of reply.
	server_ephemeral: ReplyAttribute,
	/// The certificates the Finished carries: the signing certificate its
	/// `SignerInfo` names, and the issuers above it that the server presents.
	certificates: CertificateSet,
}

impl<P: HandshakeProvider> ServerLegs<P> for Cms {
	type Settings = CmsServerSettings;
	type Identity = CmsIdentityPair<P::Kem>;
	type Sealed = CmsSealed;
	type Opened = Box<CmsOpened<P>>;
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

			// 3. Parse `R`. A share that fails its parse is refused here, ahead
			//    of the agreement. The comparison with the client's static key
			//    waits for the identity, which opens at the closing.
			let client_ephemeral = OpenedShare::from_originator_key::<Exchange<P>>(&agreement_key)?;

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

		// 1. Carry the server's share in the reply attribute of its kind of
		//    exchange, which the Finished sends.
		let security_accept = SecurityAccept::new(profile.descriptor());
		let server_ephemeral = ReplyAttribute::of::<Exchange<P>>(server_ephemeral)?;

		// 2. Append both selections, the ephemeral, and the `certificates`
		//    field the Finished carries, as the DER its identity encoded once.
		//    Then seal, so the Finished signature binds all four (CWE-345), as
		//    TLS 1.3 signs over its Certificate.
		let presented = identity.presented();
		let legs = ServerFinishedLegs {
			security_accept: Some(HandshakeAttribute::transcript_bytes(&security_accept)?),
			transport_accept: transport_accept.map(HandshakeAttribute::transcript_bytes).transpose()?,
			server_ephemeral: server_ephemeral.transcript_bytes()?,
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

		attributes.push(server_ephemeral.attribute()?);

		let encoded: Result<Vec<Attribute>, HandshakeError> = attributes.into_iter().map(Attribute::try_from).collect();
		let unsigned_attrs = Attributes::try_from(encoded?)?;

		finished.finish(signature, unsigned_attrs, Some(certificates))
	}
}

/// The CMS server derives the hybrid secret with `R`: the secret of the
/// exchange, then the base secret the opening carried. The base secret is read
/// in place, and it drops with the transcript, so it is wiped where its box
/// drops.
impl<P: HandshakeProvider> ServerAgreement<P> for Box<CmsOpened<P>> {
	fn respond(&self, rng: &mut dyn CryptoRngCore) -> Result<(ServerShare<P>, ExchangeSecret), HandshakeError> {
		self.client_ephemeral.respond::<Exchange<P>>(rng)
	}

	fn settle(
		self,
		shared: ExchangeSecret,
		salt: KdfSalt<'_>,
	) -> Result<(HandshakeSecret, OpenedShare<ClientShare<P>>), HandshakeError> {
		let secret = HandshakeSecret::hybrid::<P>(&shared, &self.base, salt)?;
		let CmsOpened { client_ephemeral, .. } = *self;
		Ok((secret, client_ephemeral))
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use std::sync::Arc;

	use p256::NistP256;

	use super::*;
	use crate::cms::content_info::{CmsVersion, ContentInfo};
	use crate::cms::signed_data::SignerInfo;
	use crate::constants::{TIGHTBEAM_CLOSING_KEY_ID_DOMAIN, TIGHTBEAM_SERVER_FINISHED_DOMAIN};
	use crate::crypto::cms::{EnvelopeError, GcmParameters, KemRecipientInfo};
	use crate::crypto::exchange::{Ecdhe, EcdheShare, KeyExchangeError};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::secret::ToInsecure;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Signature;
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
	use crate::crypto::sign::{CmsSigner, SignedContent, SignedDataExt, SignedDataSigners, SignerError};
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::CertificateValidation;
	use crate::crypto::x509::utils::CertificateExt;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::Any;
	use crate::der::{Choice, DecodeValue, EncodeValue, ErrorKind, Tag, Tagged};
	use crate::oids::{AES_128_GCM, AUTH_ENVELOPED_DATA, HANDSHAKE_ABORT_ALERT, HANDSHAKE_SERVER_EPHEMERAL};
	use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST};
	use crate::oids::{CURVE_SECP256K1, DATA, SESSION_RECEIPT, SIGNED_DATA};
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::fixtures::{flip_last, write_interop_samples, KekOpening, TestEnvelope};
	use crate::testing::TestResult;
	use crate::testing::{
		unhex, EnvelopeRecipient, SeededStream, TestAttributes, TestCmsServer, TestFrame, TestIdentity, TestKey,
	};
	use crate::transport::handshake::ephemeral::PeerStatics;
	use crate::transport::handshake::negotiation::{RunnableProfile, SecurityOffer};
	use crate::transport::handshake::peer::{ServerAdmission, ServerTrust};
	use crate::transport::handshake::receipt::SessionObserver;
	use crate::transport::handshake::schedule::{KeyConfirmation, Sealer, SecretSeal, TrafficSecret};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{
		Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication, SupportedProfiles,
	};
	use crate::x509::ext::pkix::{KeyUsage, KeyUsages};
	use crate::x509::name::RdnSequence;
	use crate::x509::Certificate;

	/// An alteration of a seal in flight, as an on-path party would make it.
	type Alteration = fn(AuthEnvelopedData) -> AuthEnvelopedData;

	/// An edit of a server Finished after its server signed it.
	type FinishedEdit = fn(SignedData) -> SignedData;

	/// A build of the client Finished that a closing carries to the server
	/// that awaits it.
	type ClosingFinished = fn(&AwaitingClosing<Cms>) -> SignedData;

	/// The originator key of the fixture ephemeral of `seed`, as a party sends
	/// its share.
	fn seeded_originator(seed: u8) -> OriginatorPublicKey {
		originator_of(fixture_ephemeral(seed).public_key())
	}

	/// A server Finished signed by `server` over the transcript of `opening`
	/// followed by the default profile's accept, `ephemeral`, and the
	/// `certificates` field of `server`, as a server under dealer's choice
	/// sends it.
	fn server_finished_over(
		server: &HandshakeCertificate,
		opening: &WireDer<AuthEnvelopedData>,
		ephemeral: &OriginatorPublicKey,
	) -> SignedData {
		let reply = ReplyAttribute::OriginatorKey(ephemeral.to_owned());
		server_finished_carrying(server, opening, &[reply])
	}

	/// A server Finished as [`server_finished_over`] builds it, whose reply
	/// attributes are `replies`, each bound into the transcript in order.
	fn server_finished_carrying(
		server: &HandshakeCertificate,
		opening: &WireDer<AuthEnvelopedData>,
		replies: &[ReplyAttribute],
	) -> SignedData {
		let accept = SecurityAccept::new(create_default_test_profile());
		let encoded = |reply: &ReplyAttribute| reply.attribute().expect("a reply encodes as an attribute");
		server_finished_selecting(server, opening.der(), Some(accept), replies.iter().map(encoded))
	}

	/// The server Finished of [`server_finished_over`] that the signing key of
	/// `server` signs over `opening`, with the share of the fixture ephemeral
	/// of `0x51`. Each edit of a validly signed Finished starts from it.
	fn server_finished_of(server: &TestCmsServer, opening: &WireDer<AuthEnvelopedData>) -> SignedData {
		let signer = HandshakeCertificate::signing_of(server);
		server_finished_over(&signer, opening, &seeded_originator(0x51))
	}

	/// The compressed point of the fixture ephemeral of `0x52` as a KEM
	/// ciphertext under the OID of the curve, the carrier of another kind of
	/// reply.
	fn kem_carried_point() -> ReplyAttribute {
		let point = fixture_ephemeral(0x52).public_key().to_encoded_point(true);
		let kem = AlgorithmIdentifierOwned { oid: CURVE_SECP256K1, parameters: None };
		let kemct = OctetString::new(point.as_bytes()).expect("a point is an OCTET STRING");
		ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct })
	}

	/// A client pinned to `server` that has sent its opening under `offer`,
	/// with that opening.
	fn client_after_opening(
		server: &TestCmsServer,
		offer: Option<SecurityOffer>,
	) -> (TestClient<Cms>, WireDer<AuthEnvelopedData>) {
		let mut config = Cms::client(server, &create_test_certificate(0xc0));
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

	/// What a client of a fresh test server answers, once it has sent its
	/// opening, to the server Finished that `forge` signs over that opening.
	async fn respond_to_finished(
		forge: impl FnOnce(&TestCmsServer, &WireDer<AuthEnvelopedData>) -> SignedData,
	) -> Result<HandshakeMessage, HandshakeError> {
		let server = create_test_server();
		let (mut client, sent) = client_after_opening(&server, None);
		let finished = forge(&server, &sent);
		client.respond(reply(finished)).await
	}

	/// `octets` with its last byte flipped, as an on-path party would alter
	/// it.
	fn flipped(octets: &OctetString) -> OctetString {
		OctetString::new(flip_last(octets.as_bytes())).expect("bytes are an OCTET STRING")
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

	/// `sealed` with the last byte of the wrapped content key of its one
	/// `KEMRecipientInfo` flipped.
	fn with_flipped_kem_wrapped_key(sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let kem = sealed.kem_recipient();
		let kem = KemRecipientInfo { encrypted_key: flipped(&kem.encrypted_key), ..kem };
		sealed.with_kem_recipient(&kem)
	}

	/// `sealed` with the KEM ciphertext of its one `KEMRecipientInfo` swapped
	/// for the uncompressed point of the fixture ephemeral of `0x24`, which
	/// encapsulates another shared secret.
	fn with_stray_kem_ciphertext(sealed: AuthEnvelopedData) -> AuthEnvelopedData {
		let stray = fixture_ephemeral(0x24).public_key().to_encoded_point(false);
		let kemct = OctetString::new(stray.as_bytes()).expect("a point is an OCTET STRING");
		let kem = KemRecipientInfo { kemct, ..sealed.kem_recipient() };
		sealed.with_kem_recipient(&kem)
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

	/// An opening built by hand from the envelope, which seals a base secret
	/// of `0x02` octets and the agreement key of the fixture ephemeral of
	/// `0x21` to `server` and authenticates `auth_attrs`.
	///
	/// The fixture builds it outside the client flow, so a server that reads it
	/// is tested against the message format alone.
	fn build_test_opening(
		server: &Certificate,
		auth_attrs: impl IntoIterator<Item = HandshakeAttribute>,
	) -> AuthEnvelopedData {
		let base = fixture_base_secret(0x02);
		build_test_opening_from(fixture_ephemeral(0x21), server, base.as_bytes(), auth_attrs)
	}

	/// What a fresh test server that demands no client certificate answers to
	/// the opening that `build` seals to its key-agreement certificate.
	async fn reply_to_opening(
		build: impl FnOnce(&Certificate) -> AuthEnvelopedData,
	) -> Result<HandshakeMessage, HandshakeError> {
		let identity = create_test_server();
		let sealed = build(&identity.key_agreement);
		let mut server = Handshake::server(Cms::server(&identity));
		server.reply(opening(sealed)).await
	}

	/// An unprotected attribute the server ignores, told apart by `arc`.
	fn marker_attribute(arc: u32) -> HandshakeAttribute {
		let parent = ObjectIdentifier::new_unwrap("1.2.3.4");
		let oid = parent.push_arc(arc).expect("the arc extends the OID");
		let octets = OctetString::new(arc.to_be_bytes()).expect("four bytes fit an OCTET STRING");
		let value = Any::encode_from(&octets).expect("an OCTET STRING encodes");
		HandshakeAttribute::new(oid, value)
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

	/// The closing sealer of a fixture handshake secret, foreign to the
	/// server, over `transcript_hash`.
	fn foreign_closing_sealer(transcript_hash: &TranscriptHash) -> Sealer<DefaultCryptoProvider> {
		let salt = KdfSalt::try_from(transcript_hash.as_bytes()).expect("a transcript hash meets the salt floor");
		let foreign = fixture_handshake_secret(0x42);
		let sealer = foreign.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, transcript_hash);
		sealer.expect("a fixture secret derives a closing key")
	}

	/// What a server that demands no client certificate answers to the
	/// sealed client Finished of the test certificate of seed `0xc1` once
	/// `alter` changed the seal in flight.
	async fn sealed_closing_refusal(
		alter: impl FnOnce(AuthEnvelopedData) -> AuthEnvelopedData,
	) -> Result<(), HandshakeError> {
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x62)).await;
		let finished = awaiting.finished_of(&create_test_certificate(0xc1));
		let altered = alter(awaiting.sealed_finished(&finished));
		let closing = HandshakeMessage::try_from(altered).expect("the closing encodes");
		awaiting.server.finish(closing).await
	}

	/// A client Finished of the leaf of the fixed test chain over the
	/// transcript the reply of `awaiting` sealed, with the tag of the client
	/// that built the opening, whose `certificates` hold what `presented`
	/// takes of the chain.
	fn chain_finished(
		awaiting: &AwaitingClosing<Cms>,
		presented: impl FnOnce(TestCertificateChain) -> Vec<Certificate>,
	) -> SignedData {
		let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
		let leaf = HandshakeCertificate { signing_key: chain.leaf_key.to_owned(), certificate: chain.leaf.to_owned() };
		let finished = awaiting.finished_of(&leaf);
		with_certificate_set(finished, Some(TestCertificate::set_of(presented(chain))))
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

	/// The content of `finished` once its one signer verifies under `signer`,
	/// admitted for signing.
	fn verified_content(finished: &SignedData, signer: &Certificate) -> Result<Vec<u8>, SignerError> {
		let content = finished.content(DATA)?;
		let signer_info = finished.sole_signer()?;
		let presented = signer.to_owned();
		let purpose = KeyPurposes::HOUSE.server;
		let certificate = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(presented, purpose)?;

		CmsSigner::verify_signer::<DefaultCryptoProvider>(signer_info, &certificate, SignedContent::data(content))?;
		Ok(content.to_vec())
	}

	/// The opening carries the 32-byte base secret, and it opens under the
	/// key of the server's key-agreement certificate.
	#[tokio::test]
	async fn the_opening_opens_under_the_server_key_agreement_key() -> TestResult {
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
	fn an_opening_carries_its_offers_in_the_authenticated_attributes() -> TestResult {
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
	fn a_refused_provisioned_server_leaves_the_client_spent() -> TestResult {
		let server = create_test_server();
		let pinned = server.key_agreement.to_owned();
		let revocation = LaterRevocation::of(pinned.to_owned());
		let trust = ProvisionedTrust::new(Arc::new(pinned), Arc::new(server.store_with(revocation.clone())))?;

		revocation.revoke();

		let identity = create_test_certificate(0xc2).signing_identity();
		let config = TestClientConfig::<Cms>::new(CmsClientSettings { trust, identity }, KeyPurposes::HOUSE)?;

		let mut client = Handshake::client(config);
		let refusal = client.start();
		assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		assert_eq!(client.phase(), HandshakePhase::Spent);
		assert!(matches!(client.start(), Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// `reply` with the `s` of its signature flipped to `n - s`. ECDSA verifies
	/// both (SEC 1 v2.0 §4.1.4), so the signature still verifies, and the
	/// server Finished MACs the octets of the other one.
	fn with_signature_flipped(reply: &HandshakeMessage) -> HandshakeMessage {
		let signed_data = reply.to_owned().signed().expect("a CMS reply is a SignedData");
		let flipped = with_signer(signed_data.into_value(), |signer| {
			let low = Signature::<Secp256k1>::from_der(signer.signature.as_bytes()).expect("the signature is DER");
			let high = TestKey::high_s_twin(low).to_der();
			let signature = OctetString::new(high.as_bytes()).expect("a signature is an OCTET STRING");
			SignerInfo { signature, ..signer }
		});

		HandshakeMessage::try_from(flipped).expect("the reply encodes")
	}

	/// A client answers a reply with its client Finished sealed as an
	/// `AuthEnvelopedData` of content type `id-signedData`.
	#[tokio::test]
	async fn a_reply_is_answered_with_a_sealed_client_finished() -> TestResult {
		let (mut client, reply) = replied::<Cms>(&create_test_server()).await;

		let closing = client.respond(reply).await?;
		let sealed = closing.auth_enveloped()?;
		assert_eq!(sealed.value().auth_encrypted_content_info.content_type, SIGNED_DATA);
		Ok(())
	}

	/// A reply whose server Finished MAC covers another signature than the one
	/// it carries is refused before the client builds any closing, though that
	/// signature verifies.
	#[tokio::test]
	async fn a_reply_whose_server_finished_covers_another_signature_is_refused() {
		let (mut client, reply) = replied::<Cms>(&create_test_server()).await;
		let flipped = with_signature_flipped(&reply);

		let refusal = client.respond(flipped).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// The sealed client Finished a client answers a reply with, beside the
	/// transcript hash the reply's server Finished signed.
	async fn sealed_client_finished() -> (AuthEnvelopedData, TranscriptHash) {
		let (mut client, reply) = replied::<Cms>(&create_test_server()).await;
		let server_finished = reply.to_owned().signed().expect("a CMS reply is a SignedData");
		let transcript_hash = signed_transcript(server_finished.value());

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

	/// A server Finished without the ephemeral attribute is refused before
	/// the transcript seals, so no session forms without the agreement.
	#[tokio::test]
	async fn a_missing_server_ephemeral_is_refused() {
		let refusal = respond_to_finished(|server, sent| {
			let finished = server_finished_of(server, sent);
			with_unsigned_attrs(finished, |carried| without_attribute(carried, HANDSHAKE_SERVER_EPHEMERAL))
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
	}

	/// A server Finished that carries its share as a KEM ciphertext, the
	/// carrier of another kind of reply, is refused at the parse of the share.
	#[tokio::test]
	async fn a_server_share_in_the_kem_carrier_is_refused() {
		let refusal = respond_to_finished(|server, sent| {
			let signer = HandshakeCertificate::signing_of(server);
			let replies = [kem_carried_point()];
			server_finished_carrying(&signer, sent, &replies)
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(KeyExchangeError::Algorithm))));
	}

	/// A server Finished that carries both reply carriers carries two replies,
	/// so it is refused before the transcript seals.
	#[tokio::test]
	async fn a_server_finished_with_both_reply_carriers_is_refused() {
		let refusal = respond_to_finished(|server, sent| {
			let signer = HandshakeCertificate::signing_of(server);
			let key = ReplyAttribute::OriginatorKey(seeded_originator(0x51));
			server_finished_carrying(&signer, sent, &[key, kem_carried_point()])
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
	}

	/// A validly signed server ephemeral that encodes the identity point is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_identity_server_ephemeral_is_refused() {
		let refusal = respond_to_finished(|server, sent| {
			let signer = HandshakeCertificate::signing_of(server);
			server_finished_over(&signer, sent, &originator_holding([0x00]))
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))));
	}

	/// A validly signed server ephemeral that is the key of the server's
	/// key-agreement certificate is refused, so the agreement cannot collapse
	/// into the key the opening sealed to.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_key_agreement_key_is_refused() {
		let refusal = respond_to_finished(|server, sent| {
			let signer = HandshakeCertificate::signing_of(server);
			let static_key = originator_of(PublicKey::from(server.key_agreement_key.verifying_key()));
			server_finished_over(&signer, sent, &static_key)
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::ServerEphemeralIsStatic)));
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
	async fn a_hand_built_opening_is_answered_with_a_signed_server_finished() -> TestResult {
		let identity = create_test_server();
		let mut server = Handshake::server(Cms::server(&identity));
		let sealed = build_test_opening(&identity.key_agreement, []);
		let message = opening(sealed);
		let sent = message.der().to_vec();

		let finished = server.reply(message).await?.signed()?;
		let content = verified_content(finished.value(), &identity.signing)?;

		let accept = HandshakeAttribute::transcript_bytes(&SecurityAccept::new(create_default_test_profile()))?;
		let ephemeral = finished.value().find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let ephemeral = ephemeral.ok_or("the server Finished carries its ephemeral")?;
		let ephemeral = HandshakeAttribute::transcript_bytes(&ephemeral.decode::<OriginatorPublicKey>()?)?;
		let certificates = certificates_field([identity.signing.to_owned()]);
		let expected = Transcript::digest::<Sha3_256>([sent, accept, ephemeral, certificates].concat())?;
		let server_content = FinishedRole::Server.content::<Sha3_256>(&expected, &identity.signing)?;
		assert_eq!(content, server_content);
		Ok(())
	}

	/// An opening whose unauthenticated SET OF arrives out of DER order is not
	/// the DER of the value it decodes to, so the decode refuses it before a
	/// server reads it (X.690 § 11.6).
	#[test]
	fn an_opening_whose_attributes_arrive_out_of_der_order_is_refused() {
		let server = create_test_server();
		let attrs = [marker_attribute(1), marker_attribute(2)];
		let sealed = with_unauth_attrs(build_test_opening(&server.key_agreement, []), attrs);
		let sent = misordered_der(&sealed);

		let refused = WireDer::<AuthEnvelopedData>::try_from(sent.as_slice());
		let noncanonical = ErrorKind::Noncanonical { tag: Tag::Sequence };
		assert_eq!(refused.map_err(|error| error.kind()), Err(noncanonical));
	}

	/// An agreement key whose x-coordinate lies off the curve is refused at
	/// the parse, before the agreement runs on it.
	#[tokio::test]
	async fn an_off_curve_agreement_key_is_refused() {
		let agreement_key = originator_holding(off_curve_point());
		let refusal = reply_to_opening(|server| {
			build_test_opening_of(server, fixture_base_secret(0x02).as_bytes(), agreement_key, [])
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(KeyExchangeError::Malformed))));
	}

	/// An agreement key on another curve names another algorithm, so the
	/// server refuses the opening before it answers.
	#[tokio::test]
	async fn an_agreement_key_of_another_curve_is_refused() -> TestResult {
		let point = p256::SecretKey::from_slice(&[0x25; 32])?.public_key();
		let agreement_key = EcdheShare::<NistP256>::from(point).to_originator_key()?;

		let refusal = reply_to_opening(|server| {
			build_test_opening_of(server, fixture_base_secret(0x02).as_bytes(), agreement_key, [])
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(KeyExchangeError::Algorithm))));
		Ok(())
	}

	/// A base secret of another length is refused where the opened content is
	/// parsed.
	#[tokio::test]
	async fn an_opening_with_a_short_base_secret_is_refused() {
		let agreement_key = seeded_originator(0x22);
		let refusal = reply_to_opening(|server| build_test_opening_of(server, &[0x02; 31], agreement_key, [])).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 })
		));
	}

	/// An opening sealed under the `ukm` of another purpose is refused before
	/// the key provider runs.
	#[tokio::test]
	async fn an_opening_under_another_ukm_purpose_is_refused() -> TestResult {
		let identity = create_test_server();
		let mut server = Handshake::server(Cms::server(&identity));
		let content = OpeningContent {
			base_secret: OctetString::new(fixture_base_secret(0x02).as_bytes())?,
			agreement_key: seeded_originator(0x23),
		};

		let recipient = recipient_of(&identity.key_agreement);
		let recipient = Recipient::Kem { recipient: &recipient, ukm_label: b"tb/handshake/other/ukm/v1" };
		let content_type = HANDSHAKE_OPENING_CONTENT;
		let content = content.to_der()?;
		let sealed = AuthEnvelopedData::seal::<DefaultCryptoProvider>(recipient, content_type, content, [], None)?;

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

		let sealed = build_test_opening(&identity.key_agreement, [attribute(&budget_offer())]);
		let tampered = with_transport_offer(sealed, &TransportOffer::mux(8).with_budgets(TEST_BUDGETS));
		let refusal = server.reply(opening(tampered)).await;
		assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
		assert_eq!(authorizer.offers(), []);
	}

	// The tag of the opening covers its content, and its authenticated
	// attributes are the associated data of the tag, so an opening whose
	// `mac`, nonce, or authenticated attributes changed in flight fails to
	// open.
	crate::tb_cases! {
		async fn an_opening_altered_in_flight_fails_its_tag(alter: Alteration) {
			let refusal = reply_to_opening(|server| alter(build_test_opening(server, []))).await;
			assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::Authentication))));
		}
		cases {
			mac => with_flipped_mac,
			/// The opening gains an attribute among its authenticated
			/// attributes.
			authenticated_attributes => with_marked_auth_attrs,
			nonce => with_flipped_nonce,
		}
	}

	// The wrapped content key of the opening fails its integrity check when
	// its KEM ciphertext or the wrapped key itself changed in flight.
	crate::tb_cases! {
		async fn an_opening_altered_in_flight_fails_its_key_unwrap(alter: Alteration) {
			let refusal = reply_to_opening(|server| alter(build_test_opening(server, []))).await;
			assert!(matches!(refusal, Err(HandshakeError::Envelope(EnvelopeError::KeyUnwrap))));
		}
		cases {
			/// A KEM ciphertext swapped for another point encapsulates another
			/// shared secret, so the key-encryption key differs.
			kem_ciphertext => with_stray_kem_ciphertext,
			wrapped_key => with_flipped_kem_wrapped_key,
		}
	}

	/// A server Finished carries the content type, the message digest, and
	/// the algorithm protection as signed attributes (RFC 5652 §5.3, RFC 6211).
	#[tokio::test]
	async fn a_server_finished_carries_the_three_signed_attributes() -> TestResult {
		let finished = reply_to_opening(|server| build_test_opening(server, [])).await?.signed()?;
		let oids = TestAttributes::oids(finished.value().sole_signer()?);
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
	async fn a_server_finished_is_version_3_under_its_key_identifier() -> TestResult {
		let identity = create_test_server();
		let mut server = Handshake::server(Cms::server(&identity));
		let sealed = build_test_opening(&identity.key_agreement, []);

		let finished = server.reply(opening(sealed)).await?.signed()?;
		let signer = finished.value().sole_signer()?;
		assert_eq!(signer.version, CmsVersion::V3);
		assert_eq!(signer.sid, identity.signing.signer_identifier()?);
		assert_eq!(finished.value().version, CmsVersion::V3);
		Ok(())
	}

	// The client refuses a validly signed server Finished that an on-path
	// party edited after the server signed it.
	crate::tb_cases! {
		async fn an_altered_server_finished_fails_its_signature(edit: FinishedEdit) {
			let refusal = respond_to_finished(|server, sent| edit(server_finished_of(server, sent))).await;
			assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		}
		cases {
			/// The signer carries no signed attributes (RFC 5652 §5.4).
			no_signed_attributes => |finished| {
				with_signer(finished, |signer| SignerInfo { signed_attrs: None, ..signer })
			},
			/// The `SignedData` version breaks the RFC 5652 §5.1 rule.
			wrong_version => |finished| SignedData { version: CmsVersion::V1, ..finished },
		}
	}

	/// A server Finished whose `sid` names a certificate it does not carry
	/// names no server to admit, though its signature verifies under the
	/// server's key.
	#[tokio::test]
	async fn a_server_finished_naming_another_certificate_is_refused() -> TestResult {
		let sid = create_test_certificate(0xc3).certificate.signer_identifier()?;
		let refusal = respond_to_finished(|server, sent| {
			with_signer(server_finished_of(server, sent), |signer| SignerInfo { sid, ..signer })
		})
		.await;

		assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
		Ok(())
	}

	/// The transcript binds the certificate the server Finished carries as it
	/// arrived, so one swapped for another the authority issued for the same
	/// key, of the same subject and the same key identifier, fails the
	/// signature (RFC 9846 §4.5.2).
	#[tokio::test]
	async fn a_reply_whose_certificate_was_swapped_for_one_of_the_same_key_is_refused() -> TestResult {
		let identity = create_test_server();
		let (mut client, sent) = replied::<Cms>(&identity).await;
		let twin = identity.signing_twin(9);
		let swapped = with_certificate_set(sent.signed()?.into_value(), Some(TestCertificate::set_of([twin])));

		let refusal = client.respond(reply(swapped)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A control of the swap above: the twin itself is admitted as the
	/// server's signing certificate, so the refusal is the transcript's.
	#[test]
	fn a_signing_twin_names_the_signer_of_the_reply() -> TestResult {
		let identity = create_test_server();
		let twin = identity.signing_twin(9);
		let store = identity.store();
		store.evaluate(&twin)?;

		let sid = identity.signing.signer_identifier()?;
		assert!(twin.is_named_by(&sid)?);
		Ok(())
	}

	/// An offered certificate whose `keyUsage` lacks `digitalSignature` is
	/// refused where the opened Finished is parsed, as the signing use reads
	/// it.
	#[tokio::test]
	async fn an_offered_certificate_without_digital_signature_is_refused() {
		let mut client = create_test_certificate(0xc4);
		let usage = KeyUsage(KeyUsages::KeyAgreement.into());
		client.certificate = TestCertificate::with_key_usage(client.certificate, usage);

		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x61)).await;
		let finished = awaiting.finished_of(&client);

		let refusal = awaiting.finish(&finished).await;
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
		let mut client = create_test_certificate(0xc5);
		client.certificate = TestCertificate::with_key_purposes(client.certificate, [KeyPurposes::HOUSE.server]);

		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x63)).await;
		let finished = awaiting.finished_of(&client);

		let refusal = awaiting.finish(&finished).await;
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
		let certificate = identity.signing;
		identity.signing = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.client]);

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
	async fn a_server_of_its_own_purpose_replies() -> TestResult {
		let own = ObjectIdentifier::new("1.3.6.1.4.1.99999.3.10")?;
		let mut identity = create_test_server();
		identity.signing = TestCertificate::with_key_purposes(identity.signing, [own]);

		let sealed = build_test_opening(&identity.key_agreement, []);
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let purposes = KeyPurposes { server: own, ..KeyPurposes::HOUSE };
		let config = TestServerConfig::<Cms>::new(CmsServerSettings, identity.pair(), profiles, purposes)?;

		let mut server = Handshake::server(config);
		server.reply(opening(sealed)).await?;
		Ok(())
	}

	/// A client whose own certificate names the server's purpose alone holds
	/// no certificate of its role, so its configuration is refused.
	#[test]
	fn a_client_configuration_of_a_server_certificate_is_refused() {
		let server = create_test_server();
		let client = create_test_certificate(0xc6);
		let certificate = TestCertificate::with_key_purposes(client.certificate, [KeyPurposes::HOUSE.server]);
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
		let mut server = Handshake::server(Cms::server(&create_test_server()));
		let refusal = server.reply(hpke_hello()).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// An HPKE hello sent to a CMS server as its closing is refused before
	/// the server opens anything.
	#[tokio::test]
	async fn a_cms_server_refuses_an_hpke_hello_as_its_closing() {
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x64)).await;
		let refusal = awaiting.server.finish(hpke_hello()).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// An opening that carries an abort alert among its unauthenticated
	/// attributes is refused before any negotiation runs.
	#[tokio::test]
	async fn an_opening_with_an_abort_alert_is_refused() -> TestResult {
		let alert = HandshakeAttribute::new(HANDSHAKE_ABORT_ALERT, Any::encode_from(&3u8)?);
		let refusal = reply_to_opening(|server| with_unauth_attrs(build_test_opening(server, []), [alert])).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::AbortReceived(HandshakeAlert::AlgorithmMismatch))
		));
		Ok(())
	}

	// An opening that carries an offer twice fails closed, as the client
	// does. Read as no offer, a second security offer would fall through to
	// dealer's choice, and a second transport offer would leave the
	// connection single-flight.
	crate::tb_cases! {
		async fn an_opening_with_a_duplicate_offer_fails_closed(offers: [HandshakeAttribute; 2]) {
			let refusal = reply_to_opening(|server| build_test_opening(server, offers)).await;
			assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
		}
		cases {
			security_offer => [
				attribute(&SecurityOffer::new(vec![create_default_test_profile()])),
				attribute(&SecurityOffer::new(vec![foreign_profile()])),
			],
			transport_offer => [attribute(&TransportOffer::mux(4)), attribute(&TransportOffer::mux(8))],
		}
	}

	/// The server takes the certificate the client Finished's `sid` names, so
	/// a Finished that carries its chain closes the handshake. The fixed
	/// chain's leaf sorts second of the three in the DER SET.
	#[tokio::test]
	async fn a_finished_carrying_its_chain_closes_under_its_leaf() -> TestResult {
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x65)).await;
		let finished = chain_finished(&awaiting, |chain| vec![chain.leaf, chain.intermediate, chain.root]);

		awaiting.finish(&finished).await?;

		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	// A client Finished is a proof, so a closing whose `certificates` hold no
	// certificate its `sid` names is refused, even by a server that demands
	// no identity.
	crate::tb_cases! {
		async fn a_finished_without_its_signer_certificate_is_refused(finished_for: ClosingFinished) {
			let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x66)).await;
			let finished = finished_for(&awaiting);

			let refusal = awaiting.finish(&finished).await;
			assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
		}
		cases {
			/// The set carries the chain of the signer above its leaf.
			omits_signer => |awaiting| chain_finished(awaiting, |chain| vec![chain.intermediate, chain.root]),
			/// The Finished carries no `certificates` set.
			no_certificate => |awaiting| {
				let finished = awaiting.finished_of(&create_test_certificate(0xc7));
				with_certificate_set(finished, None)
			},
		}
	}

	/// A client Finished that carries no key-confirmation tag is refused when
	/// it is opened. The tag is mandatory, so no closing reaches the agreement
	/// unconfirmed.
	#[tokio::test]
	async fn a_finished_with_no_key_confirmation_is_refused() {
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x67)).await;
		let finished = awaiting.finished_of(&create_test_certificate(0xc8));
		let unconfirmed = with_signer(finished, |signer| SignerInfo { unsigned_attrs: None, ..signer });

		let refusal = awaiting.finish(&unconfirmed).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
	}

	/// A key-confirmation tag narrower than any digest output fails to decode,
	/// so the server refuses the Finished when it opens it and admits no
	/// further step.
	#[tokio::test]
	async fn a_finished_with_a_short_key_confirmation_is_refused() -> TestResult {
		let short_tag = Any::encode_from(&OctetString::new([7u8; 31])?)?;
		let short = Attribute::try_from(HandshakeAttribute::new(KeyConfirmation::OID, short_tag))?;
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x68)).await;
		let finished = awaiting.finished_of(&create_test_certificate(0xc9));
		let shortened = with_unsigned_attrs(finished, |_| vec![short]);

		let refusal = awaiting.finish(&shortened).await;
		assert!(matches!(refusal, Err(HandshakeError::DerError(_))));
		assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// Two budget-bearing endpoints of the CMS flow, where
	/// [`ChallengingAuthorizer`] grants the budgets and `observer` hears each
	/// outcome the server reports.
	fn observed_budget_bearing(observer: Arc<dyn SessionObserver>) -> Parties<Cms> {
		let mut parties = budget_bearing::<Cms>(ChallengingAuthorizer);
		parties.server.session_observer = Some(observer);
		parties
	}

	/// A budget-bearing closing altered in flight fails to open, so it is
	/// refused ahead of settlement and the observer hears of no outcome. The
	/// tag and the countersignature both travel inside the sealed Finished, so
	/// an on-path party can change neither alone.
	#[tokio::test]
	async fn an_altered_sealed_finished_settles_nothing() -> TestResult {
		let observer = Arc::new(CountingObserver::default());
		let Parties { client, server, .. } = observed_budget_bearing(observer.to_owned());
		let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));
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
	async fn an_honest_budget_bearing_closing_reports_one_outcome() -> TestResult {
		let observer = Arc::new(CountingObserver::default());
		let Parties { client, server, .. } = observed_budget_bearing(observer.to_owned());
		let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));
		let reply = server.reply(client.start()?).await?;
		let closing = client.respond(reply).await?;
		server.finish(closing).await?;
		assert_eq!(observer.outcomes(), 1);
		Ok(())
	}

	/// An on-path party holds the public transcript and no handshake secret,
	/// so a Finished it forges under its own certificate seals under another
	/// key and fails to open (CWE-287, CWE-345). The refusal spends the
	/// handshake, so the forger gets no second closing.
	#[tokio::test]
	async fn a_finished_sealed_without_the_handshake_secret_is_refused() -> TestResult {
		let (mut client, mut server) = pair::<Cms>(PeerAuthentication::mutual_by_expiry());
		let server_finished = server.reply(client.start()?).await?.signed()?;
		let transcript_hash = signed_transcript(server_finished.value());

		// The forger signs over the real transcript, which an expiry-only
		// validator would accept, and seals under a secret it chose.
		let forger = create_test_certificate(0xca);
		let forged = build_test_client_finished(&forger, &transcript_hash, &fixture_confirmation());
		let sealer = foreign_closing_sealer(&transcript_hash);

		let refusal = server.finish(sealed_closing(sealer, &forged)).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(EnvelopeError::KeyUnwrap))));
		assert_eq!(server.phase(), HandshakePhase::Spent);
		Ok(())
	}

	/// The server's own Finished, returned as the client's with the client's
	/// key-confirmation tag in place of its own, fails because each Finished
	/// signs its role. The expiry-only validator accepts the server
	/// certificate.
	#[tokio::test]
	async fn a_reflected_server_finished_is_refused() -> TestResult {
		// The reflected Finished carries the server certificate, which the
		// validator accepts. The tag confirms the secret the server derives,
		// so the refusal is the role mismatch in the signature.
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::mutual_by_expiry(), fixture_ephemeral(0x6b)).await;
		let tag = finished_attribute(&awaiting.tag());
		let server_finished = awaiting.reply.to_owned().signed()?.into_value();
		let reflected = with_unsigned_attrs(server_finished, |carried| {
			[without_attribute(carried, KeyConfirmation::OID), vec![tag]].concat()
		});

		let refusal = awaiting.finish(&reflected).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A sealed Finished whose encrypted content names the anonymous form
	/// while its authenticated content type names the Finished is refused
	/// before its content opens.
	#[tokio::test]
	async fn a_sealed_finished_of_another_content_type_is_refused() {
		let refusal = sealed_closing_refusal(|mut sealed| {
			sealed.auth_encrypted_content_info.content_type = DATA;
			sealed
		})
		.await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedClosing(EnvelopeError::ContentType(_)))
		));
	}

	/// A sealed Finished that names another algorithm is refused before its
	/// content opens.
	#[tokio::test]
	async fn a_sealed_finished_under_another_algorithm_is_refused() {
		let refusal = sealed_closing_refusal(|mut sealed| {
			sealed.auth_encrypted_content_info.content_enc_alg.oid = AES_128_GCM;
			sealed
		})
		.await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedClosing(EnvelopeError::ContentEncryptionAlgorithm))
		));
	}

	/// A sealed Finished that carries no content is refused.
	#[tokio::test]
	async fn a_sealed_finished_with_no_content_is_refused() {
		let refusal = sealed_closing_refusal(|mut sealed| {
			sealed.auth_encrypted_content_info.encrypted_content = None;
			sealed
		})
		.await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::SealedClosing(EnvelopeError::MissingContent))
		));
	}

	// A sealed Finished whose nonce, `mac`, or authenticated attributes
	// changed in flight fails its tag, so its transcript binding holds.
	crate::tb_cases! {
		async fn a_sealed_finished_altered_in_flight_fails_its_tag(alter: Alteration) {
			let refusal = sealed_closing_refusal(alter).await;
			assert!(matches!(
				refusal,
				Err(HandshakeError::SealedClosing(EnvelopeError::Authentication))
			));
		}
		cases {
			nonce => with_flipped_nonce,
			mac => with_flipped_mac,
			authenticated_attributes => with_marked_auth_attrs,
		}
	}

	/// A sealed Finished whose wrapped content key changed in flight fails
	/// the key unwrap.
	#[tokio::test]
	async fn a_sealed_finished_with_an_altered_wrapped_key_is_refused() {
		let refusal = sealed_closing_refusal(with_flipped_kek_wrapped_key).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(EnvelopeError::KeyUnwrap))));
	}

	/// A client Finished that carries the acknowledgement twice is refused
	/// before either value is read, because every handshake attribute is
	/// single-use (CWE-694).
	#[tokio::test]
	async fn a_finished_with_a_duplicate_acknowledgement_is_refused() {
		let acknowledgements = vec![acknowledgement([0x41; 48]), acknowledgement([0x42; 48])];
		let mut awaiting = Cms::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x69)).await;
		let finished = awaiting.finished_of(&create_test_certificate(0xcb));
		let duplicated = with_unsigned_attrs(finished, |carried| [carried, acknowledgements].concat());

		let refusal = awaiting.finish(&duplicated).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
	}

	/// A server that issued a receipt refuses a client Finished that carries
	/// no countersignature, and its observer records the concluded exchange,
	/// so a withheld countersignature leaves evidence (CWE-778).
	#[tokio::test]
	async fn a_withheld_countersignature_is_refused_and_recorded() {
		let observer = Arc::new(CountingObserver::default());
		let Parties { server_identity, server, .. } = observed_budget_bearing(observer.to_owned());
		let offers = [attribute(&budget_offer())];
		let mut awaiting = AwaitingClosing::under(&server_identity, server, fixture_ephemeral(0x6a), offers).await;
		let finished = awaiting.finished_of(&create_test_certificate(0xcc));

		let refusal = awaiting.finish(&finished).await;
		assert!(matches!(refusal, Err(HandshakeError::CountersignatureMissing)));
		assert_eq!(observer.outcomes(), 1);
	}

	/// The compressed SEC1 point of the secp256k1 scalar of 32 `0x05` bytes.
	const KNOWN_SERVER_EPHEMERAL: &str = "0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7";

	/// The CMS client derives the handshake secret as HKDF-SHA3-256 under the
	/// salt and the session label over its agreement with the server
	/// ephemeral followed by its base secret.
	///
	/// The expected bytes come from Python's `cryptography` for the ECDH and
	/// its `hmac` and `hashlib` for the HKDF, so they are independent of the
	/// crate's code.
	#[test]
	fn the_cms_handshake_secret_matches_its_known_answer() -> TestResult {
		let ephemeral = SecretKey::<Secp256k1>::from_slice(&[0x03u8; 32])?;
		let pending = Box::new(CmsPending::<DefaultCryptoProvider> { base: fixture_base_secret(0x02), ephemeral });
		let server_share = EcdheShare::from(PublicKey::<Secp256k1>::from_sec1_bytes(&unhex(KNOWN_SERVER_EPHEMERAL))?);
		let server_ephemeral = PeerStatics::<Ecdhe<Secp256k1>>::none().server_ephemeral(server_share)?;

		let agree = <Box<CmsPending<DefaultCryptoProvider>> as ClientAgreement<DefaultCryptoProvider>>::agree;
		let secret = agree(pending, &server_ephemeral, fixture_salt())?;
		let expected = unhex("1ddf26eca01c5db23d340c3c6294b0e24c9ce9eab845d379c819ae7c09d152ba");
		assert_eq!(secret.as_bytes(), expected.as_slice());
		Ok(())
	}

	/// The DER of the `OriginatorPublicKey` of the point of
	/// [`KNOWN_SERVER_EPHEMERAL`]: `id-ecPublicKey` on secp256k1 and the
	/// uncompressed point (RFC 5480 §2.2).
	const KNOWN_ORIGINATOR_KEY: &str = "3056301006072a8648ce3d020106052b8104000a03420004\
		62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7\
		6d83f6a6ff2df8664ec7b804ab1362cc95403e4374d1819e0840bd8a8817800d";

	/// The DER of the server-ephemeral attribute that carries
	/// [`KNOWN_ORIGINATOR_KEY`].
	const KNOWN_SERVER_EPHEMERAL_ATTRIBUTE: &str = "3066060a2b0601040183f84a01173158\
		3056301006072a8648ce3d020106052b8104000a03420004\
		62c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7\
		6d83f6a6ff2df8664ec7b804ab1362cc95403e4374d1819e0840bd8a8817800d";

	/// The opening carries its agreement ephemeral `R` as
	/// [`KNOWN_ORIGINATOR_KEY`] when the seeded draw makes `R` the point of
	/// [`KNOWN_SERVER_EPHEMERAL`]: the base secret takes the draw of `0x04`
	/// bytes, and `R` the scalar of `0x05` bytes.
	#[tokio::test]
	async fn the_opening_carries_its_agreement_key_as_its_known_der() -> TestResult {
		let server = create_test_server();
		let config = Cms::client(&server, &create_test_certificate(0xcd));
		let provisioned = config.flow().trust.admit_provisioned(ServerAdmission::of(&config))?;
		let parts = OpeningParts { security_offer: None, transport_offer: None };
		let open = <Cms as ClientLegs<DefaultCryptoProvider>>::open;
		let opened = open(config.flow(), provisioned, parts, &mut SeededStream(3))?;

		let identity = server.key_agreement_identity();
		let opener = Opener::Kem { identity: &identity, ukm_label: TIGHTBEAM_OPENING_UKM_LABEL };
		let (arrived, sealed) = opened.message.auth_enveloped()?.into_parts();
		let opening = sealed.open::<DefaultCryptoProvider>(arrived, &opener, HANDSHAKE_OPENING_CONTENT);
		let content = opening.await?;
		let content = OpeningContent::from_der(&content.to_insecure())?;
		let der = content.agreement_key.to_der()?;
		assert_eq!(der, unhex(KNOWN_ORIGINATOR_KEY));
		Ok(())
	}

	/// The server Finished carries the server ephemeral of
	/// [`KNOWN_SERVER_EPHEMERAL`] as [`KNOWN_SERVER_EPHEMERAL_ATTRIBUTE`].
	#[tokio::test]
	async fn the_server_finished_carries_its_ephemeral_as_its_known_der() -> TestResult {
		let server = create_test_server();
		let identity = server.signing_identity();
		let known = EcdheShare::from(PublicKey::<Secp256k1>::from_sec1_bytes(&unhex(KNOWN_SERVER_EPHEMERAL))?);
		let client_ephemeral = OpenedShare::fixture(known);
		let opened = CmsOpened { base: fixture_base_secret(0x02), client_ephemeral, transcript: Transcript::new() };
		let mut opened = Box::new(opened);
		let server_ephemeral = &known;
		let profile = RunnableProfile::<DefaultCryptoProvider>::native();
		let parts = ReplyParts {
			identity: &identity,
			profile,
			transport_accept: None,
			server_ephemeral,
			client_cert_required: false,
		};

		let bind = <Cms as ServerLegs<DefaultCryptoProvider>>::bind_reply;
		let bound = bind(&mut opened, &CmsServerSettings, parts, &mut SeededStream(5))?;
		let signature = identity.sign_prehash(&bound.prehash).await?;
		let encode = <Cms as ServerLegs<DefaultCryptoProvider>>::encode_reply;
		let finished = encode(bound.draft, signature, None)?;

		let carried = finished.find_unsigned_attr(HANDSHAKE_SERVER_EPHEMERAL)?;
		let carried = carried.ok_or("the server Finished carries its ephemeral")?;
		assert_eq!(carried.to_der()?, unhex(KNOWN_SERVER_EPHEMERAL_ATTRIBUTE));
		Ok(())
	}

	/// `content` inside a `ContentInfo` of `content_type`, decoded back: the
	/// content type the `ContentInfo` names, beside the content as its own
	/// type.
	fn decodes_back<T>(content_type: ObjectIdentifier, content: &T) -> (ObjectIdentifier, T)
	where
		T: EncodeValue + Tagged + for<'a> Choice<'a> + for<'a> DecodeValue<'a>,
	{
		let der = TestEnvelope::content_info(content_type, content);
		let info = ContentInfo::from_der(&der).expect("the ContentInfo decodes");
		let decoded = info.content.decode_as::<T>().expect("the content decodes as its type");
		(info.content_type, decoded)
	}

	/// Write each sample of `emitted` under its name, what opens each
	/// `KEKRecipientInfo` sample, and the DER of the five certificates, when
	/// the environment asks for interop samples.
	fn write_samples(emitted: &Emitted) {
		let certificates = [
			("server-certificate", &emitted.server_certificate),
			("server-key-agreement-certificate", &emitted.server_key_agreement_certificate),
			("client-certificate", &emitted.client_certificate),
			("test-root", &emitted.test_root),
			("chain-root", &emitted.chain_root),
		];
		write_interop_samples(&emitted.samples(), &emitted.kek_openings(), &certificates);
	}

	/// A frame signed by a test identity, as the `SignedData` its signature
	/// reads as: the frame's TBS encoding as `id-data` content, the frame's
	/// `SignerInfo`, and the certificate it names.
	fn frame_signature() -> SignedData {
		let identity = TestIdentity::insecure_fixed();
		let frame = TestFrame::signed_by(TestFrame::v1(None, Some("cms-sample")), &identity);

		let tbs = frame.to_tbs().expect("the frame encodes its TBS");
		let signer = frame.nonrepudiation().expect("the frame carries its signature").to_owned();
		let certificates = TestCertificate::set_of([identity.certificate().to_owned()]);
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
			let enveloped = |content: &AuthEnvelopedData| TestEnvelope::content_info(AUTH_ENVELOPED_DATA, content);
			let signed = |content: &SignedData| TestEnvelope::content_info(SIGNED_DATA, content);
			[
				("cms-opening", enveloped(&self.opening)),
				("server-finished", signed(&self.server_finished)),
				("server-finished-chained", signed(&self.chained_finished)),
				("session-receipt", signed(&self.session_receipt)),
				("sealed-finished", enveloped(&self.sealed_finished)),
				("kek-seal", enveloped(&self.kek_seal)),
				("frame-signature", signed(&self.frame_signature)),
				("joined-receipt", signed(&self.joined_receipt)),
			]
		}

		/// Each `KEKRecipientInfo` sample's file name beside what opens it.
		fn kek_openings(&self) -> [(&'static str, &KekOpening); 2] {
			let sealed_finished = ("sealed-finished", &self.sealed_finished_opening);
			[sealed_finished, ("kek-seal", &self.kek_seal_opening)]
		}
	}

	/// A client identity of the fixed key of `0x71` that the authority of
	/// `server` issued, so the signed samples verify under one root.
	fn issued_client(server: &TestCmsServer) -> HandshakeCertificate {
		let signing_key = TestKey::fixed(0x71);
		let subject = RdnSequence::from_str("CN=tightbeam interop client").expect("the name parses");
		let certificate = server.issue_signing(&signing_key, subject, 5);
		HandshakeCertificate { signing_key, certificate }
	}

	/// The server Finished of a server whose signing certificate sits under an
	/// intermediate, as a client whose store holds the root alone admits it.
	async fn chained_finished() -> (SignedData, Certificate) {
		let chained = ChainedTestServer::fixed();
		let client = Cms::client(&chained.identity, &create_test_certificate(0xce));
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
		let mut parties = parties::<Cms>(PeerAuthentication::mutual_by_expiry());
		parties.client_identity = issued_client(&parties.server_identity);
		parties.client = Cms::client(&parties.server_identity, &parties.client_identity);

		let observer = Arc::new(ArtifactObserver::default());
		let parties = parties.budget_bearing(Arc::new(PayingApprover), Arc::new(ChallengingAuthorizer));
		let Parties { server_identity, client_identity, client, mut server } = parties;
		server.session_observer = Some(observer.to_owned());

		let (mut client, mut server) = (Handshake::client(client), Handshake::server(server));
		let opening = client.start().expect("the client opens");
		let reply = server.reply(opening.to_owned()).await.expect("the server replies");
		let closing = client.respond(reply.to_owned()).await.expect("the client closes");

		server.finish(closing).await.expect("the server finishes");

		let sealer = fixture_sealer(SecretSeal::Ack);
		let kek_seal_opening = sealer.kek_opening(b"countersignature");
		let kek_seal = sealer.seal(DATA, b"countersignature").expect("the acknowledgement seals");

		// The client Finished seals under the closing key of the same fixed
		// secret, so a reader holds its key.
		let transcript_hash = fixture_transcript_hash();
		let finished = build_test_client_finished(&client_identity, &transcript_hash, &fixture_confirmation());
		let finished_der = finished.to_der().expect("the Finished encodes");
		let sealer = fixture_sealer(SecretSeal::Closing);
		let sealed_finished_opening = sealer.kek_opening(&finished_der);
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
			frame_signature: frame_signature(),
			joined_receipt: joined_receipt.into_inner(),
			server_certificate: server_identity.signing,
			server_key_agreement_certificate: server_identity.key_agreement,
			client_certificate: client_identity.certificate,
			test_root: server_identity.authority,
			chain_root,
			sealed_finished_opening,
			kek_seal_opening,
		}
	}

	// Each enveloped structure the flow emits decodes back from its
	// `ContentInfo` to itself, under the content type that names it.
	crate::tb_cases! {
		async fn an_enveloped_structure_decodes_back_from_its_content_info(take: fn(Emitted) -> AuthEnvelopedData) {
			let content = take(emitted().await);
			let decoded = decodes_back(AUTH_ENVELOPED_DATA, &content);
			assert_eq!(decoded, (AUTH_ENVELOPED_DATA, content));
		}
		cases {
			opening => |emitted| emitted.opening,
			sealed_finished => |emitted| emitted.sealed_finished,
			kek_seal => |emitted| emitted.kek_seal,
		}
	}

	// Each signed structure the flow and a signed frame emit decodes back
	// from its `ContentInfo` to itself, under the content type that names it.
	crate::tb_cases! {
		async fn a_signed_structure_decodes_back_from_its_content_info(take: fn(Emitted) -> SignedData) {
			let content = take(emitted().await);
			let decoded = decodes_back(SIGNED_DATA, &content);
			assert_eq!(decoded, (SIGNED_DATA, content));
		}
		cases {
			server_finished => |emitted| emitted.server_finished,
			chained_server_finished => |emitted| emitted.chained_finished,
			session_receipt => |emitted| emitted.session_receipt,
			frame_signature => |emitted| emitted.frame_signature,
			joined_receipt => |emitted| emitted.joined_receipt,
		}
	}

	/// Write the samples of [`Emitted`]. `scripts/cms-interop.sh` parses and
	/// verifies them with OpenSSL when the run sets `TIGHTBEAM_CMS_SAMPLES`,
	/// which `make interop` does.
	#[tokio::test]
	async fn the_emitted_structures_write_their_interop_samples() {
		write_samples(&emitted().await);
	}
}

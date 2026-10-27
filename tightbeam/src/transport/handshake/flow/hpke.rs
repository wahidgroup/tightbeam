//! The HPKE flow, in the shape of the TLS 1.3 handshake (RFC 9846).
//!
//! The client learns the server from the reply. The handshake secret derives
//! from the ephemeral-ephemeral agreement alone, so the hello travels
//! unsealed, and the server's certificate key only signs.
//!
//! ## Messages
//!
//! - The hello is an `id-data` `ContentInfo` over the [`ClientHello`], which holds the client ephemeral `R`.
//! - The reply is the signer's `SignedData` over the [`ServerHandshake`], with the server ephemeral `E`.
//! - The closing is the closing of both flows, under the closing key of the handshake secret.
//!
//! The reply's signed attributes carry the transcript hash, which covers the
//! hello, the reply content, and the reply's `certificates` field. The field
//! holds the signing certificate the `sid` names and each issuer above it
//! that the server presents, so a swapped certificate of the same key or the
//! same subject fails the signature (RFC 9846 §4.5.2).
//!
//! ## Key confirmation
//!
//! The server derives the handshake secret before it encodes the reply, so
//! the reply carries the server Finished as an unsigned attribute of its
//! `SignerInfo`: a MAC over the transcript hash and the octets of the reply's
//! signature (RFC 9846 §4.5.3). The CMS reply carries the same MAC, so both
//! clients confirm the server alike.
//!
//! The client verifies the server Finished before it seals its closing, and
//! the server verifies the client's tag before it admits the client.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec, vec::Vec};

use crate::asn1::OctetString;
use crate::cms::content_info::ContentInfo;
use crate::cms::signed_data::{CertificateSet, SignedData};
use crate::crypto::sign::elliptic_curve::SecretKey;
use crate::crypto::sign::{CmsSigner, Signed, SignedContent, SignerInfoDraft, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::OctetStringRef;
use crate::der::{Any, Decode, Encode, Tag};
use crate::oids::{DATA, HANDSHAKE_REPLY_CONTENT};
use crate::random::{generate_nonce, CryptoRngCore, RngWrapper};
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientAgreement, ClientLegs, HandshakeFlow, Opened, OpeningIntake, OpeningParts, ReplyBinding, ReplyIntake,
	ReplyParts, ReplyVerified, ServerAgreement, ServerLegs,
};
use crate::transport::handshake::negotiation::SecurityAccept;
use crate::transport::handshake::peer::LearnedTrust;
use crate::transport::handshake::primitives::transcript::Transcript;
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::schedule::{Agreement, CompressedPoint, PeerPoint, Salt};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{ClientHello, HandshakeCurve, HandshakeMessage, HandshakeProvider, ServerHandshake};
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::attr::{Attribute, Attributes};

/// The HPKE handshake protocol.
///
/// A client takes [`HpkeClientSettings`], and a server takes
/// [`HpkeServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hpke;

impl sealed::Sealed for Hpke {}

impl HandshakeFlow for Hpke {}

/// The provisioning of an HPKE client.
pub struct HpkeClientSettings {
	/// The trust that admits the server the reply names.
	pub trust: LearnedTrust,
	/// The identity the client presents for mutual authentication.
	pub identity: Option<SigningIdentity>,
}

impl HpkeClientSettings {
	/// Settings for an anonymous client.
	pub fn new(trust: LearnedTrust) -> Self {
		Self { trust, identity: None }
	}
}

/// What an HPKE client keeps from its hello to read the reply against.
pub struct HpkeOpening {
	/// The transcript, open over the hello as it was sent. A rewritten offer
	/// changes the transcript hash (CWE-757).
	transcript: Transcript,
	/// The client random the hello carried.
	client_random: [u8; 32],
}

impl<P: HandshakeProvider> ClientLegs<P> for Hpke {
	type Settings = HpkeClientSettings;
	type Trust = LearnedTrust;
	type Opening = HpkeOpening;
	/// The agreement ephemeral `R`. It is boxed, so a move to the agreement
	/// copies a pointer, and `SecretKey` wipes the scalar where the box drops.
	type Pending = Box<SecretKey<P::Curve>>;

	fn identity(settings: &Self::Settings) -> Option<&SigningIdentity> {
		settings.identity.as_ref()
	}

	fn server_trust(settings: &Self::Settings) -> &Self::Trust {
		&settings.trust
	}

	fn open(
		_settings: &Self::Settings,
		_server: (),
		parts: OpeningParts<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<Opened<Self, P>, HandshakeError> {
		// 1. Draw the client random and the agreement ephemeral `R`, whose
		//    agreement with the server ephemeral derives the handshake secret
		//    alone.
		let client_random = generate_nonce::<32>(Some(&mut *rng))?;
		let ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let client_ephemeral = ephemeral.public_key().compressed_point()?;

		// 2. Carry the hello as the OCTET STRING of a `ContentInfo` of type `id-data`, and encode it once.
		let hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			client_ephemeral: OctetString::new(client_ephemeral.as_slice())?,
			security_offer: parts.security_offer.cloned(),
			transport_offer: parts.transport_offer.cloned(),
		};
		let content = Any::new(Tag::OctetString, hello.to_der()?)?;
		let message = HandshakeMessage::try_from(ContentInfo { content_type: DATA, content })?;

		// 3. Open the transcript over the hello as it was sent.
		let mut transcript = Transcript::new();
		transcript.append(message.der())?;

		let opening = HpkeOpening { transcript, client_random };
		Ok(Opened { message, opening, pending: Box::new(ephemeral) })
	}

	fn read_reply(
		opening: Self::Opening,
		_settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError> {
		let HpkeOpening { mut transcript, client_random } = opening;

		// 1. Take the reply, refuse one that carries an abort alert, and decode
		//    the content its signer signs. The transcript binds the content as
		//    it arrived.
		let reply = reply.signed()?;
		reply.value().refuse_alert()?;

		let content = CmsSigner::content(reply.value(), HANDSHAKE_REPLY_CONTENT)?;
		let handshake = ServerHandshake::from_der(content)?;
		transcript.append(content)?;

		// 2. Build the path the reply's signer presents, parsed from the bytes
		//    it arrived as, for the trust to admit, and bind the `certificates`
		//    field as it arrived after the content, then seal.
		let presented = CmsSigner::signer_path(&reply)?;
		let (server, certificates) = presented.ok_or(HandshakeError::MissingServerCertificate)?;
		transcript.append(certificates)?;
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 3. Keep the decoded reply, for its signature and its attributes.
		let reply = reply.into_value();

		// 4. Return the facts of the reply, with the session receipt its signer
		//    attached, and its ephemeral at the compressed width of the curve.
		let receipt = reply.find_unsigned_attr(<Signed<SignedData> as AttributePayload>::OID)?;
		let receipt = receipt.map(|attribute| attribute.decode::<Signed<SignedData>>()).transpose()?;
		let server_random = handshake.server_random.to_32_byte_array()?;
		let server_point = handshake.server_ephemeral.to_compressed_point::<P::Curve>()?;
		Ok(ReplyIntake {
			server,
			security_accept: handshake.security_accept.map(WireDer::into_value),
			transport_accept: handshake.transport_accept.map(WireDer::into_value),
			server_ephemeral: server_point.to_vec(),
			receipt,
			client_cert_required: handshake.client_cert_required,
			transcript_hash,
			salt: Salt::randoms(&client_random, &server_random),
			reply,
		})
	}

	fn verify_reply(
		reply: &SignedData,
		server: &PeerCertificate<Signing<P>>,
		transcript_hash: &TranscriptHash,
	) -> Result<ReplyVerified, HandshakeError> {
		// The transcript hash is a signed attribute, so a signer that saw
		// another transcript fails. The hash is fresh for each handshake, so
		// the verified signature keys no ledger and drops here.
		let content = CmsSigner::content(reply, HANDSHAKE_REPLY_CONTENT)?;
		let signed = SignedContent::new(HANDSHAKE_REPLY_CONTENT, content).with_attribute(transcript_hash.attribute()?);
		CmsSigner::verify_sole_signer::<P>(reply, server, signed).map(drop)?;
		Ok(ReplyVerified(()))
	}
}

/// The HPKE client agrees over the ephemerals alone. The agreement reads the
/// ephemeral in place, so `SecretKey` wipes it where the box drops.
impl<P: HandshakeProvider> ClientAgreement<P> for Box<SecretKey<P::Curve>> {
	fn agreement<'a>(&'a self, peer: &'a PeerPoint<P::Curve>) -> Agreement<'a, P> {
		Agreement::ephemeral(peer)
	}

	fn ephemeral(&self) -> &SecretKey<P::Curve> {
		self
	}
}

/// The provisioning of an HPKE server.
///
/// The server presents the certificate of its signing identity, which
/// [`ServerConfig`](crate::transport::handshake::ServerConfig) holds.
#[derive(Debug, Clone, Copy, Default)]
pub struct HpkeServerSettings;

impl HpkeServerSettings {
	/// The settings of an HPKE server.
	pub fn new() -> Self {
		Self
	}
}

/// What an HPKE server keeps of the hello to bind the reply over and to
/// agree with.
pub struct HpkeHello<C: HandshakeCurve> {
	/// The transcript, open over the hello as it arrived.
	transcript: Transcript,
	/// The client random the hello carried.
	client_random: [u8; 32],
	/// The client's agreement ephemeral `R`, parsed once as a point of the
	/// curve.
	client_ephemeral: PeerPoint<C>,
}

/// A reply that awaits its signature and its receipt.
pub struct HpkeReplyDraft {
	/// The DER of the `ServerHandshake`, which the reply signs as its content.
	content: Vec<u8>,
	/// The reply's `SignerInfo`, complete up to its signature.
	signer: SignerInfoDraft,
	/// The certificates the reply carries: the signing certificate its
	/// `SignerInfo` names, and the issuers above it that the server presents.
	certificates: CertificateSet,
}

impl<P: HandshakeProvider> ServerLegs<P> for Hpke {
	type Settings = HpkeServerSettings;
	type Identity = SigningIdentity;
	type Sealed = HpkeHello<P::Curve>;
	type Opened = HpkeHello<P::Curve>;
	type Draft = HpkeReplyDraft;

	fn read_opening(
		_settings: &Self::Settings,
		opening: HandshakeMessage,
	) -> Result<OpeningIntake<Self, P>, HandshakeError> {
		// 1. Take the hello, and open the transcript over it as it arrived.
		let hello = opening.data()?;
		let mut transcript = Transcript::new();
		transcript.append(hello.der())?;

		// 2. Decode the `ClientHello` from the OCTET STRING of a `ContentInfo` of type `id-data`.
		let content_info = hello.value();
		if content_info.content_type != DATA {
			return Err(HandshakeError::UnexpectedContainer);
		}

		let octets = content_info.content.decode_as::<OctetStringRef<'_>>()?;
		let ClientHello { client_random, client_ephemeral, security_offer, transport_offer } =
			ClientHello::from_der(octets.as_bytes())?;

		// 3. Parse `R` at the compressed width, so a point of another width or
		//    form, malformed, off-curve, or the identity fails before any
		//    negotiation. The static-key check waits for the closing identity.
		let client_random = client_random.to_32_byte_array()?;
		let client_point = client_ephemeral.to_compressed_point::<P::Curve>()?;
		let client_ephemeral = PeerPoint::parse(client_point)?;
		let sealed = HpkeHello { transcript, client_random, client_ephemeral };
		Ok(OpeningIntake { security_offer, transport_offer, sealed })
	}

	fn open_opening<'a>(
		sealed: Self::Sealed,
		_identity: &'a SigningIdentity,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>> {
		// The server's key only signs, so the hello opens as it arrived.
		Box::pin(async move { Ok(sealed) })
	}

	fn bind_reply(
		opened: &mut Self::Opened,
		_settings: &Self::Settings,
		parts: ReplyParts<'_, P>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<ReplyBinding<Self, P>, HandshakeError> {
		let ReplyParts { identity, profile, transport_accept, server_ephemeral, client_cert_required } = parts;

		// 1. Encode the reply content once, so the transcript binds the bytes the reply signs.
		let server_random = generate_nonce::<32>(Some(rng))?;
		let server_point = server_ephemeral.compressed_point()?;
		let handshake = ServerHandshake {
			server_random: OctetString::new(server_random)?,
			server_ephemeral: OctetString::new(server_point.as_slice())?,
			security_accept: Some(WireDer::new(SecurityAccept::new(profile.descriptor()))?),
			client_cert_required,
			transport_accept: transport_accept.copied().map(WireDer::new).transpose()?,
		};
		let content = handshake.to_der()?;

		// 2. Bind the content and the `certificates` field after the hello, and
		//    seal, as TLS 1.3 signs over its Certificate. The field is the DER
		//    the identity encoded once.
		let presented = identity.presented();
		opened.transcript.append(&content)?;
		opened.transcript.append(presented.field())?;
		let transcript_hash = opened.transcript.seal::<P::Digest>()?;

		// 3. Draft the reply's `SignerInfo`, whose signed attributes carry the transcript hash.
		let signed = SignedContent::new(HANDSHAKE_REPLY_CONTENT, &content).with_attribute(transcript_hash.attribute()?);
		let signer = identity.draft(signed)?;
		let prehash = signer.prehash().to_vec();
		let salt = Salt::randoms(&opened.client_random, &server_random);
		let draft = HpkeReplyDraft { content, signer, certificates: presented.set() };
		Ok(ReplyBinding { transcript_hash, salt, prehash, draft })
	}

	fn encode_reply(
		draft: Self::Draft,
		signature: Vec<u8>,
		artifact: Option<&Signed<SignedData>>,
	) -> Result<Signed<SignedData>, HandshakeError> {
		let HpkeReplyDraft { content, signer, certificates } = draft;

		// 1. Complete the `SignerInfo`, with the session receipt as an unsigned
		//    attribute. The artifact has two owners: the message holds one
		//    copy, and the issued receipt absorbs the client SignerInfo at
		//    settlement.
		let receipt = artifact.map(HandshakeAttribute::encode).transpose()?;
		let receipt = receipt.map(Attribute::try_from).transpose()?;
		let unsigned_attrs = receipt.map(|receipt| Attributes::try_from(vec![receipt])).transpose()?;
		let signer_info = signer.complete(signature, unsigned_attrs)?;

		// 2. Assemble the reply, which carries the signing certificate and the issuers above it.
		let signed = SignedContent::new(HANDSHAKE_REPLY_CONTENT, &content);
		Ok(CmsSigner::signed_data(signed, signer_info, Some(certificates))?)
	}
}

/// The HPKE server agrees with `R` over the ephemerals alone. The server
/// ephemeral serves this one agreement, and the transcript of the hello drops
/// with the value.
impl<P: HandshakeProvider> ServerAgreement<P> for HpkeHello<P::Curve> {
	fn client_ephemeral(&self) -> &PeerPoint<P::Curve> {
		&self.client_ephemeral
	}

	fn agreement(&self) -> Agreement<'_, P> {
		Agreement::ephemeral(&self.client_ephemeral)
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;
	use std::sync::Arc;

	use super::*;
	use crate::asn1::admission::fixtures::{descending_attribute, tlv};
	use crate::cms::signed_data::{SignerInfo, SignerInfos};
	use crate::crypto::cms::AuthEnvelopedData;
	use crate::crypto::common::typenum::Unsigned;
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::key::SigningKeyProvider;
	use crate::crypto::profiles::{DefaultCryptoProvider, SecurityProfileDesc};
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::elliptic_curve::sec1::{CompressedPointSize, ToEncodedPoint};
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
	use crate::crypto::x509::KeyPurposes;
	use crate::der::asn1::{ObjectIdentifier, SetOfVec};
	use crate::der::{ErrorKind, Tag, TagNumber};
	use crate::oids::{
		AUTH_ENVELOPED_DATA, HANDSHAKE_ABORT_ALERT, HANDSHAKE_TRANSCRIPT_HASH, HASH_SHA3_384, RECEIPT_ACK, SIGNED_DATA,
	};
	use crate::random::OsRng;
	use crate::testing::{Aes256Sha3_512Provider, TestIdentity};
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::flow::{ClosingDraft, ClosingParts};
	use crate::transport::handshake::negotiation::{RunnableProfile, SecurityOffer, TransportOffer};
	use crate::transport::handshake::primitives::KdfSalt;
	use crate::transport::handshake::schedule::{FinishedRole, KeyConfirmation, SecretSeal};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{
		Client, ClientConfig, Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication, Server, ServerConfig,
		SupportedProfiles,
	};
	use crate::x509::Certificate;

	/// The client random each hand-built hello of this module carries.
	const CLIENT_RANDOM: [u8; 32] = [7u8; 32];

	/// The configuration of an anonymous client that trusts `server`.
	fn anonymous_client(server: &TestCertificate) -> TestClientConfig<Hpke> {
		hpke_client(&server.certificate, None)
	}

	/// An anonymous client that trusts `server` and has sent its hello under
	/// `offer`, with that hello.
	fn client_after_hello(
		server: &TestCertificate,
		offer: Option<SecurityOffer>,
	) -> (TestClient<Hpke>, HandshakeMessage) {
		let mut config = anonymous_client(server);
		config.security_offer = offer;

		let mut client = Handshake::client(config);
		let opening = client.start().expect("a fresh client builds its hello");
		(client, opening)
	}

	/// A hello that carries [`CLIENT_RANDOM`] and the public half of
	/// `ephemeral`, as a client that keeps `ephemeral` builds it.
	fn hello_of(ephemeral: &SecretKey<Secp256k1>) -> ClientHello {
		let client_ephemeral = ephemeral.public_key().compressed_point().expect("a point compresses");
		hello_carrying(client_ephemeral)
	}

	/// A hello that carries [`CLIENT_RANDOM`] and `client_ephemeral` as its
	/// agreement ephemeral.
	fn hello_carrying(client_ephemeral: impl AsRef<[u8]>) -> ClientHello {
		ClientHello {
			client_random: OctetString::new(CLIENT_RANDOM).expect("a random is an OCTET STRING"),
			client_ephemeral: OctetString::new(client_ephemeral.as_ref()).expect("a point is an OCTET STRING"),
			security_offer: None,
			transport_offer: None,
		}
	}

	/// A real server of `identity` and a real anonymous client that trusts
	/// it, with the reply the server sent to the client's hello.
	async fn replied(identity: &TestCertificate) -> (TestClient<Hpke>, HandshakeMessage) {
		let mut server = Handshake::server(hpke_server(identity));
		let mut client = Handshake::client(anonymous_client(identity));
		let opening = client.start().expect("a fresh client builds its hello");
		let reply = server.reply(opening).await.expect("the server admits the hello");
		(client, reply)
	}

	/// `reply` with only its content rewritten by `edit`, as an on-path party
	/// would rewrite it. The signature still covers the content the server
	/// signed.
	fn with_content(reply: &HandshakeMessage, edit: impl FnOnce(&mut ServerHandshake)) -> HandshakeMessage {
		let mut signed_data = reply_signed_data(reply);
		let mut handshake = signed_handshake(reply);
		edit(&mut handshake);

		let content = handshake.to_der().expect("the content encodes");
		let econtent = Any::new(Tag::OctetString, content).expect("the content is an OCTET STRING");
		signed_data.encap_content_info.econtent = Some(econtent);
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// `reply` with the unsigned attributes of its one signer rewritten by
	/// `edit`. The unsigned attributes sit outside the signature.
	fn with_unsigned(
		reply: &HandshakeMessage,
		edit: impl FnOnce(Vec<Attribute>) -> Vec<Attribute>,
	) -> HandshakeMessage {
		let mut signed_data = reply_signed_data(reply);
		let signers = core::mem::take(&mut signed_data.signer_infos.0).into_vec();
		let [signer] = <[SignerInfo; 1]>::try_from(signers).expect("a reply has one signer");
		let carried = signer.unsigned_attrs.clone().map(SetOfVec::into_vec).unwrap_or_default();
		let unsigned = Attributes::try_from(edit(carried)).expect("the attributes are a SET");

		let signer = SignerInfo { unsigned_attrs: Some(unsigned), ..signer };
		signed_data.signer_infos = SignerInfos(SetOfVec::try_from(vec![signer]).expect("one signer is a SET"));
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// `reply` with the certificates it carries replaced by `certificates`.
	fn with_certificates(reply: &HandshakeMessage, certificates: Option<CertificateSet>) -> HandshakeMessage {
		let mut signed_data = reply_signed_data(reply);
		signed_data.certificates = certificates;
		HandshakeMessage::try_from(signed_data).expect("the reply encodes")
	}

	/// An attribute of `oid` whose one value is `value`.
	fn attribute_of(oid: ObjectIdentifier, value: &(impl crate::der::EncodeValue + crate::der::Tagged)) -> Attribute {
		let value = Any::encode_from(value).expect("the value encodes");
		let values = SetOfVec::try_from(vec![value]).expect("one value is a SET");
		Attribute { oid, values }
	}

	/// The key-confirmation attribute that carries `tag`.
	fn finished_attribute(tag: &KeyConfirmation) -> Attribute {
		let attribute = HandshakeAttribute::encode(tag).expect("a tag encodes as an attribute");
		Attribute::try_from(attribute).expect("the attribute encodes")
	}

	/// A reply that `server` signs over `handshake` under `content_type`,
	/// with its signing certificate and a transcript-hash attribute over
	/// `transcript_hash`. It carries no server Finished, so a client that
	/// reads it refuses it at the latest where it reads the server Finished.
	fn signed_reply_over(
		server: &TestCertificate,
		handshake: &ServerHandshake,
		transcript_hash: &TranscriptHash,
		content_type: ObjectIdentifier,
	) -> HandshakeMessage {
		let content = handshake.to_der().expect("the content encodes");
		let attribute = transcript_hash.attribute().expect("the transcript hash is an attribute");
		let signed = SignedContent::new(content_type, &content).with_attribute(attribute);
		let key = TestIdentity::certified(server.signing_key.to_owned());
		let signer = CmsSigner::sign_with::<Secp256k1Signature, _>(&key, signed).expect("the test key signs");

		let certificates = CertificateFixtures::set_of([server.certificate.to_owned()]);
		let content = SignedContent::new(content_type, &content);
		let reply = CmsSigner::signed_data(content, signer, Some(certificates)).expect("the reply assembles");
		HandshakeMessage::try_from(reply.into_inner()).expect("the reply encodes")
	}

	/// The reply `server` signs over `handshake` in answer to `opening`, over
	/// the transcript a client of that opening seals: the hello, the content,
	/// and the `certificates` field that holds the signing certificate.
	fn signed_reply(
		server: &TestCertificate,
		opening: &HandshakeMessage,
		handshake: &ServerHandshake,
	) -> HandshakeMessage {
		signed_reply_under(server, opening, handshake, HANDSHAKE_REPLY_CONTENT)
	}

	/// The reply of [`signed_reply`], signed under `content_type`.
	fn signed_reply_under(
		server: &TestCertificate,
		opening: &HandshakeMessage,
		handshake: &ServerHandshake,
		content_type: ObjectIdentifier,
	) -> HandshakeMessage {
		let content = handshake.to_der().expect("the content encodes");
		let certificates = certificates_field([server.certificate.to_owned()]);
		let transcript = [opening.der(), content.as_slice(), certificates.as_slice()].concat();
		let transcript_hash = Transcript::digest::<Sha3_256>(transcript).expect("the transcript hashes");
		signed_reply_over(server, handshake, &transcript_hash, content_type)
	}

	/// The content of a reply that accepts `profile`, when one is given, and
	/// carries `server_ephemeral`.
	fn reply_content(profile: Option<SecurityProfileDesc>, server_ephemeral: impl AsRef<[u8]>) -> ServerHandshake {
		let accept = profile.map(|profile| WireDer::new(SecurityAccept::new(profile)).expect("an accept encodes"));
		ServerHandshake {
			server_random: OctetString::new([2u8; 32]).expect("a random is an OCTET STRING"),
			server_ephemeral: OctetString::new(server_ephemeral.as_ref()).expect("a point is an OCTET STRING"),
			security_accept: accept,
			client_cert_required: false,
			transport_accept: None,
		}
	}

	/// A server that holds `identity` under `peer_authentication` and awaits
	/// the closing of a hand-built hello, beside what the client that built
	/// the hello holds.
	struct AwaitingClosing {
		/// The server, with its reply sent.
		server: TestServer<Hpke>,
		/// What the reply confirms, as the client reads it.
		confirming: Confirming,
		/// The agreement ephemeral `R` of the hello.
		ephemeral: SecretKey<Secp256k1>,
	}

	impl AwaitingClosing {
		/// A server of a fresh identity under `peer_authentication`, after a
		/// hand-built hello of a fresh ephemeral.
		async fn new(peer_authentication: PeerAuthentication) -> Self {
			let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
			Self::with_ephemeral(peer_authentication, ephemeral).await
		}

		/// A server of a fresh identity under `peer_authentication`, after a
		/// hand-built hello of the agreement ephemeral `ephemeral`.
		async fn with_ephemeral(peer_authentication: PeerAuthentication, ephemeral: SecretKey<Secp256k1>) -> Self {
			let mut config = hpke_server(&create_test_certificate());
			config.peer_authentication = peer_authentication;

			let mut server = Handshake::server(config);
			let reply = server.reply(hello_opening(&hello_of(&ephemeral))).await;
			let reply = reply.expect("the server admits the hello");
			let handshake = signed_handshake(&reply);
			let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(handshake.server_ephemeral.as_bytes());
			let confirming = Confirming {
				server_ephemeral: server_ephemeral.expect("the reply carries a point on the curve"),
				salt: [CLIENT_RANDOM.as_slice(), handshake.server_random.as_bytes()].concat(),
				transcript_hash: server.transcript_hash().expect("the reply sealed the transcript"),
			};
			Self { server, confirming, ephemeral }
		}

		/// The key-confirmation tag of the client that built the hello.
		fn tag(&self) -> KeyConfirmation {
			self.confirming.tag(None, &self.ephemeral)
		}

		/// The closing that carries `content`, of `content_type`, as its
		/// content, sealed as the client that built the hello seals it.
		fn sealed_as(&self, content_type: ObjectIdentifier, content: Vec<u8>) -> HandshakeMessage {
			let sealer = self.confirming.closing_sealer(None, &self.ephemeral);
			let sealed = sealer.seal(content_type, content).expect("the closing seals");
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// The closing that carries `attributes` as the attribute set of an
		/// anonymous client, sealed under `sealing`'s closing key.
		fn anonymous_under(&self, sealing: &Confirming, attributes: Vec<Attribute>) -> HandshakeMessage {
			let attributes = Attributes::try_from(attributes).expect("distinct attributes are a SET");
			let attributes = attributes.to_der().expect("the attribute set encodes");
			let sealer = sealing.closing_sealer(None, &self.ephemeral);
			let sealed = sealer.seal(DATA, attributes).expect("the closing seals");
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// The anonymous closing that carries `attributes`, as the client that
		/// built the hello seals it.
		fn anonymous(&self, attributes: Vec<Attribute>) -> HandshakeMessage {
			self.anonymous_under(&self.confirming, attributes)
		}

		/// The closing in which `client` signs its client Finished over
		/// `transcript_hash` and carries `certificate`, sealed as the client
		/// that built the hello seals it, with its honest key-confirmation
		/// tag.
		async fn identified_over(
			&self,
			client: &TestCertificate,
			transcript_hash: &TranscriptHash,
			certificate: Certificate,
		) -> HandshakeMessage {
			let identity = client_identity(client);
			let role = FinishedRole::Client;
			let draft = role.draft::<DefaultCryptoProvider>(&identity, transcript_hash);
			let draft = draft.expect("the Finished drafts");
			let signature = identity.sign_prehash(draft.prehash()).await.expect("the client key signs");
			let attributes = Attributes::try_from(vec![finished_attribute(&self.tag())]);
			let attributes = attributes.expect("one attribute is a SET");
			let certificates = CertificateFixtures::set_of([certificate]);
			let finished = draft.finish(signature, attributes, Some(certificates));
			let finished = finished.expect("the Finished assembles");
			let finished = finished.to_der().expect("the Finished encodes");

			let sealer = self.confirming.closing_sealer(None, &self.ephemeral);
			let sealed = sealer.seal(SIGNED_DATA, finished).expect("the closing seals");
			HandshakeMessage::try_from(sealed).expect("the closing encodes")
		}

		/// The closing in which `client` signs its client Finished, as an
		/// honest client of the hello builds it.
		async fn identified(&self, client: &TestCertificate) -> HandshakeMessage {
			let transcript_hash = self.confirming.transcript_hash;
			let certificate = client.certificate.to_owned();
			self.identified_over(client, &transcript_hash, certificate).await
		}
	}

	/// The hello is a `ContentInfo` of type `id-data` (RFC 5652 §4).
	#[test]
	fn the_hello_is_a_content_info_of_type_data() -> Result<(), Box<dyn Error>> {
		let (_, opening) = client_after_hello(&create_test_certificate(), None);

		let hello = opening.data()?;
		assert_eq!(hello.value().content_type, ObjectIdentifier::new("1.2.840.113549.1.7.1")?);
		Ok(())
	}

	/// The hello carries the client ephemeral `R` as a compressed point of the
	/// curve, as a TLS 1.3 hello carries its key share.
	#[test]
	fn the_hello_carries_the_client_ephemeral() {
		let (_, opening) = client_after_hello(&create_test_certificate(), None);

		let hello = carried_hello(&opening);
		let point = PublicKey::<Secp256k1>::from_sec1_bytes(hello.client_ephemeral.as_bytes());
		assert_eq!(hello.client_ephemeral.as_bytes().len(), CompressedPointSize::<Secp256k1>::USIZE);
		assert!(point.is_ok());
	}

	/// The hello travels under context tag 8 of the transport envelope.
	#[test]
	fn an_hpke_hello_travels_under_tag_8() -> Result<(), Box<dyn Error>> {
		let (_, opening) = client_after_hello(&create_test_certificate(), None);

		let encoded = TransportEnvelope::from(opening).to_der()?;
		assert_eq!(encoded.first(), Some(&0xA8));
		Ok(())
	}

	/// The reply is a `SignedData` whose content is the `ServerHandshake`
	/// under the reply content type.
	#[tokio::test]
	async fn the_reply_signs_the_server_handshake_under_its_content_type() -> Result<(), Box<dyn Error>> {
		let (_, reply) = replied(&create_test_certificate()).await;

		let signed_data = reply_signed_data(&reply);
		let content_type = signed_data.encap_content_info.econtent_type;
		assert_eq!(content_type, ObjectIdentifier::new("1.3.6.1.4.1.64586.1.26")?);
		Ok(())
	}

	/// The reply carries the server's certificate, and its one signer names
	/// that certificate.
	#[tokio::test]
	async fn the_reply_carries_the_certificate_its_signer_names() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (_, reply) = replied(&identity).await;

		let signed_data = reply_signed_data(&reply);
		let named = CmsSigner::signer_certificate(&signed_data)?;
		assert_eq!(named, Some(&identity.certificate));
		Ok(())
	}

	/// The reply signs the transcript hash as a signed attribute: SHA3-256 of
	/// the hello as it was sent, the reply content, and the `certificates`
	/// field, in that order (RFC 9846 §4.5.2 signs over the Certificate).
	///
	/// The expected digest comes from the `sha3` crate over those bytes, so
	/// the check is independent of the crate's transcript code.
	#[tokio::test]
	async fn the_reply_signs_the_hash_of_the_hello_the_content_and_the_certificates() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(hpke_server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let opening = client.start()?;
		let reply = server.reply(opening.to_owned()).await?;
		let signed_data = reply_signed_data(&reply);
		let content = CmsSigner::content(&signed_data, HANDSHAKE_REPLY_CONTENT)?;
		let certificates = certificates_field([identity.certificate.to_owned()]);
		let expected = Sha3_256::new().chain_update(opening.der()).chain_update(content);
		let expected = expected.chain_update(certificates).finalize();

		let signer = signed_data.signer_infos.0.iter().next().ok_or("the reply has a signer")?;
		let signed_attrs = signer.signed_attrs.as_ref().ok_or("the reply carries signed attributes")?;
		let carried = signed_attrs.iter().find(|attribute| attribute.oid == HANDSHAKE_TRANSCRIPT_HASH);
		let carried = carried.ok_or("the reply signs its transcript hash")?;
		let value = carried.values.iter().next().ok_or("the attribute has a value")?;
		let hash = value.decode_as::<OctetString>()?;
		assert_eq!(hash.as_bytes(), expected.as_slice());
		Ok(())
	}

	/// The reply carries its server Finished once, as an unsigned attribute
	/// of its signer.
	#[tokio::test]
	async fn the_reply_carries_the_server_finished() -> Result<(), Box<dyn Error>> {
		let (_, reply) = replied(&create_test_certificate()).await;

		let signed_data = reply_signed_data(&reply);
		let finished = signed_data.find_unsigned_attr(KeyConfirmation::OID)?;
		let tag = finished.map(|finished| finished.decode::<KeyConfirmation>()).transpose()?;
		assert!(tag.is_some());
		Ok(())
	}

	/// The reply signature is a DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3).
	#[tokio::test]
	async fn the_reply_signature_is_der() -> Result<(), Box<dyn Error>> {
		let (_, reply) = replied(&create_test_certificate()).await;

		let signed_data = reply_signed_data(&reply);
		let signer = signed_data.signer_infos.0.iter().next().ok_or("the reply has a signer")?;
		let parsed = Secp256k1Signature::from_der(signer.signature.as_bytes());
		assert!(parsed.is_ok());
		Ok(())
	}

	/// A server reply names its signer by the certificate it carries, so the
	/// whole step costs the key provider its signature alone.
	#[tokio::test]
	async fn an_hpke_reply_fetches_no_public_key() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let provider = Arc::new(CountingProvider::new(identity.signing_key.to_owned()));
		let identity = presenting(&identity, Arc::clone(&provider) as Arc<dyn SigningKeyProvider>);
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let config = TestServerConfig::<Hpke>::new(HpkeServerSettings::new(), identity, profiles, KeyPurposes::HOUSE)?;

		let fetched_at_construction = provider.public_keys();
		let mut server = Handshake::server(config);
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);

		server.reply(hello_opening(&hello_of(&ephemeral))).await?;

		assert_eq!(provider.public_keys(), fetched_at_construction);
		Ok(())
	}

	/// A server ephemeral rewritten after the server signed its reply changes
	/// the signed content, so the signature fails before any agreement.
	#[tokio::test]
	async fn a_tampered_server_ephemeral_fails_the_reply_signature() -> Result<(), Box<dyn Error>> {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let swapped = OctetString::new(create_test_server_ephemeral().as_slice())?;
		let tampered = with_content(&reply, |handshake| handshake.server_ephemeral = swapped);

		let refusal = client.respond(tampered).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A reply whose accept was stripped after the server signed it fails its
	/// signature. The client verifies the signature before it reads the
	/// selection, so the refusal names the signature and not the selection.
	#[tokio::test]
	async fn a_stripped_accept_fails_the_reply_signature() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let stripped = with_content(&reply, |handshake| handshake.security_accept = None);

		let refusal = client.respond(stripped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A certificate demand flipped after the server signed its reply changes
	/// the signed content, so the signature fails. An on-path party cannot talk
	/// an anonymous client past a server that demands an identity.
	#[tokio::test]
	async fn a_flipped_certificate_demand_fails_the_reply_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = hpke_server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);

		let mut server = Handshake::server(config);
		let mut client = Handshake::client(anonymous_client(&identity));
		let reply = server.reply(client.start()?).await?;
		let flipped = with_content(&reply, |handshake| handshake.client_cert_required = false);

		let refusal = client.respond(flipped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A reply whose signer saw another transcript fails its signed
	/// attributes, though the server's key signed it.
	#[tokio::test]
	async fn a_reply_signed_over_another_transcript_is_refused() {
		let server = create_test_certificate();
		let (mut client, _) = client_after_hello(&server, None);
		let handshake = reply_content(Some(create_default_test_profile()), create_test_server_ephemeral());
		let foreign = fixture_transcript::<Sha3_256>([0x5au8; 32]);
		let reply = signed_reply_over(&server, &handshake, &foreign, HANDSHAKE_REPLY_CONTENT);

		let refusal = client.respond(reply).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// The transcript covers the certificate the reply's signer names, so a
	/// reply whose certificate was swapped for another the client trusts, of
	/// the same key, fails its signed transcript hash.
	#[tokio::test]
	async fn a_reply_whose_certificate_was_swapped_for_one_of_the_same_key_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let twin = same_key_twin(&identity);
		let anchors = [identity.certificate.to_owned(), twin.to_owned()];
		let trusted = DirectTrustValidator::default().with_trust_chain(anchors);
		let settings = HpkeClientSettings::new(LearnedTrust::new(trusted));
		let mut client = Handshake::client(TestClientConfig::<Hpke>::new(settings, KeyPurposes::HOUSE)?);
		let mut server = Handshake::server(hpke_server(&identity));
		let reply = server.reply(client.start()?).await?;
		let swapped = with_certificates(&reply, Some(CertificateFixtures::set_of([twin])));

		let refusal = client.respond(swapped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// The client refuses a reply whose certificate carries its RDN values out
	/// of DER order, which would decode to the same value. The refusal comes at
	/// the `[3]` envelope, before the client binds a byte of it (X.690 §11.6,
	/// CWE-345).
	#[tokio::test]
	async fn a_reply_whose_certificate_bytes_were_reordered_is_refused() {
		let mut server = create_test_certificate();
		server.certificate.tbs_certificate.subject = two_valued_name();
		let (_client, reply) = replied(&server).await;
		let envelope_tag = Tag::ContextSpecific { constructed: true, number: TagNumber::N3 };
		let arrived = tlv(envelope_tag, &with_rdn_values_swapped(&reply));

		let refused = TransportEnvelope::from_der(&arrived).err().map(|error| error.kind());
		assert_eq!(refused, Some(ErrorKind::SetOrdering));
	}

	/// The client refuses a reply without the certificate its signer names,
	/// because it names no server to admit.
	#[tokio::test]
	async fn a_reply_without_its_certificate_is_refused() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let bare = with_certificates(&reply, None);

		let refusal = client.respond(bare).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
	}

	/// The client refuses, at the parse, a validly signed server ephemeral that
	/// names no point on the curve, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, opening) = client_after_hello(&server, None);
		let handshake = reply_content(Some(create_default_test_profile()), off_curve_point());

		let refusal = client.respond(signed_reply(&server, &opening, &handshake)).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// The reply signs under a content type of its own, so the same content
	/// that the server's key signed under `id-data`, over the right transcript,
	/// verifies as no reply.
	#[tokio::test]
	async fn a_reply_under_another_content_type_is_refused() {
		let server = create_test_certificate();
		let (mut client, opening) = client_after_hello(&server, None);
		let handshake = reply_content(Some(create_default_test_profile()), create_test_server_ephemeral());
		let reply = signed_reply_under(&server, &opening, &handshake, DATA);

		let refusal = client.respond(reply).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A validly signed server ephemeral in the uncompressed form names a
	/// point of the curve, and the client refuses it at the width, because the
	/// HPKE reply carries the compressed form alone.
	#[tokio::test]
	async fn an_uncompressed_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, opening) = client_after_hello(&server, None);
		let key = SecretKey::<Secp256k1>::random(&mut OsRng).public_key();
		let handshake = reply_content(Some(create_default_test_profile()), key.to_encoded_point(false));

		let refusal = client.respond(signed_reply(&server, &opening, &handshake)).await;
		assert!(matches!(refusal, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// The client refuses a validly signed server ephemeral that is the
	/// server's own static key, so the agreement cannot collapse into the
	/// static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, opening) = client_after_hello(&server, None);
		let static_key = PublicKey::<Secp256k1>::from(*server.signing_key.verifying_key()).compressed_point()?;
		let handshake = reply_content(Some(create_default_test_profile()), static_key);

		let refusal = client.respond(signed_reply(&server, &opening, &handshake)).await;
		assert!(matches!(refusal, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// The client refuses a validly signed reply that selects no profile.
	#[tokio::test]
	async fn a_reply_without_a_security_accept_is_refused() {
		let server = create_test_certificate();
		let (mut client, opening) = client_after_hello(&server, None);
		let handshake = reply_content(None, create_test_server_ephemeral());

		let refusal = client.respond(signed_reply(&server, &opening, &handshake)).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// The client refuses a validly signed reply that selects a profile outside
	/// its offer.
	#[tokio::test]
	async fn a_client_refuses_a_profile_it_did_not_offer() {
		let server = create_test_certificate();
		let foreign = SecurityProfileDesc { digest: Some(HASH_SHA3_384), ..create_default_test_profile() };
		let (mut client, opening) = client_after_hello(&server, Some(SecurityOffer::new(vec![foreign])));
		let handshake = reply_content(Some(create_default_test_profile()), create_test_server_ephemeral());

		let refusal = client.respond(signed_reply(&server, &opening, &handshake)).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// The client refuses a reply whose signer carries an abort alert among its
	/// unsigned attributes.
	#[tokio::test]
	async fn a_reply_with_an_abort_alert_is_refused() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let alert = attribute_of(HANDSHAKE_ABORT_ALERT, &4u8);
		let alerted = with_unsigned(&reply, |carried| [carried, vec![alert]].concat());

		let refusal = client.respond(alerted).await;
		let expected = HandshakeAlert::DecryptFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
	}

	/// The client refuses a reply that carries no server Finished, before it
	/// builds any closing, and admits no further step.
	#[tokio::test]
	async fn a_reply_without_a_server_finished_is_refused_before_the_closing() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let unconfirmed = with_unsigned(&reply, |_| Vec::new());

		let refusal = client.respond(unconfirmed).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// The client refuses a reply whose server Finished fails, though its
	/// signature verifies, before it builds any closing.
	#[tokio::test]
	async fn a_reply_whose_server_finished_fails_is_refused_before_the_closing() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let forged = with_unsigned(&reply, |_| vec![finished_attribute(&fixture_confirmation())]);

		let refusal = client.respond(forged).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// The client refuses a reply that carries its server Finished twice.
	#[tokio::test]
	async fn a_reply_with_two_server_finished_is_refused() {
		let (mut client, reply) = replied(&create_test_certificate()).await;
		let second = finished_attribute(&fixture_confirmation());
		let doubled = with_unsigned(&reply, |carried| [carried, vec![second]].concat());

		let refusal = client.respond(doubled).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
	}

	#[tokio::test]
	async fn an_anonymous_client_refuses_a_server_that_demands_an_identity() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = hpke_server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);

		let mut server = Handshake::server(config);
		let mut client = Handshake::client(anonymous_client(&identity));

		let reply = server.reply(client.start()?).await?;
		let refused = client.respond(reply).await;
		assert!(matches!(refused, Err(HandshakeError::MutualAuthRequired)));
		Ok(())
	}

	/// A closing step that began and failed leaves the client spent, so it
	/// admits no further step and completes nothing.
	///
	/// The server here demands a client identity, and the client holds none,
	/// so the step refuses before it derives the handshake secret.
	#[tokio::test]
	async fn a_failed_hpke_closing_leaves_the_client_spent() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = hpke_server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);
		config.transport = Some(budget_offer());

		let mut server = Handshake::server(config);
		let mut config = anonymous_client(&identity);
		config.transport_offer = Some(budget_offer());

		let mut client = Handshake::client(config);

		let reply = server.reply(client.start()?).await?;
		let refused = client.respond(reply.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::MutualAuthRequired)));
		assert_eq!(client.phase(), HandshakePhase::Spent);

		let replayed = client.respond(reply).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// The server refuses a hello whose agreement ephemeral names no point on
	/// the curve as it reads the hello, before any negotiation.
	#[tokio::test]
	async fn an_off_curve_client_ephemeral_is_refused() {
		let mut server = Handshake::server(hpke_server(&create_test_certificate()));

		let refusal = server.reply(hello_opening(&hello_carrying(off_curve_point()))).await;
		assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// The server refuses, at the width, a hello whose agreement ephemeral is a
	/// point of the curve in the uncompressed form, because the HPKE hello
	/// carries the compressed form alone.
	#[tokio::test]
	async fn an_uncompressed_client_ephemeral_is_refused() {
		let mut server = Handshake::server(hpke_server(&create_test_certificate()));
		let key = SecretKey::<Secp256k1>::random(&mut OsRng).public_key();

		let refusal = server.reply(hello_opening(&hello_carrying(key.to_encoded_point(false)))).await;
		assert!(matches!(refusal, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// The server refuses a hello in a `ContentInfo` of another content type,
	/// before it reads the content.
	#[tokio::test]
	async fn a_hello_of_another_content_type_is_refused() -> Result<(), Box<dyn Error>> {
		let mut server = Handshake::server(hpke_server(&create_test_certificate()));
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		let hello = hello_of(&ephemeral).to_der()?;
		let content = Any::new(Tag::OctetString, hello)?;
		let opening = HandshakeMessage::try_from(ContentInfo { content_type: SIGNED_DATA, content })?;

		let refusal = server.reply(opening).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
		Ok(())
	}

	/// The server refuses a hello that arrives as a `SignedData`, before it
	/// reads the content.
	#[tokio::test]
	async fn an_hpke_server_refuses_a_signed_data_as_its_hello() -> Result<(), Box<dyn Error>> {
		let mut server = Handshake::server(hpke_server(&create_test_certificate()));
		let signed = HandshakeMessage::try_from(create_test_signed_data(b"hello"))?;

		let refusal = server.reply(signed).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
		Ok(())
	}

	/// An anonymous closing carries the attribute set as content of type
	/// `id-data`.
	#[tokio::test]
	async fn an_anonymous_closing_seals_its_attributes_as_data() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let run = run(anonymous_client(&identity), hpke_server(&identity)).await;

		let closing = run.closing.auth_enveloped()?;
		let content_type = closing.value().auth_encrypted_content_info.content_type;
		assert_eq!(content_type, ObjectIdentifier::new("1.2.840.113549.1.7.1")?);
		Ok(())
	}

	/// A closing of an identity carries its client Finished as content of
	/// type `id-signedData`.
	#[tokio::test]
	async fn an_identified_closing_seals_its_client_finished_as_signed_data() -> Result<(), Box<dyn Error>> {
		let Parties { client, server, .. } = parties::<Hpke>(mutual_with(ExpiryValidator));
		let run = run(client, server).await;

		let closing = run.closing.auth_enveloped()?;
		let content_type = closing.value().auth_encrypted_content_info.content_type;
		assert_eq!(content_type, ObjectIdentifier::new("1.2.840.113549.1.7.2")?);
		Ok(())
	}

	/// An anonymous closing opens under the shared closing, and the server
	/// records no peer.
	#[tokio::test]
	async fn an_anonymous_closing_opens_and_records_no_peer() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut run = run(anonymous_client(&identity), hpke_server(&identity)).await;

		let session = run.server.complete()?;
		assert!(session.peer().is_none());
		Ok(())
	}

	/// An identified closing opens under the shared closing, and a mutual
	/// server records the client's certificate.
	#[tokio::test]
	async fn an_identified_closing_opens_and_records_its_certificate() -> Result<(), Box<dyn Error>> {
		let Parties { client_identity, client, server, .. } = parties::<Hpke>(mutual_with(ExpiryValidator));
		let mut run = run(client, server).await;

		let session = run.server.complete()?;
		assert_eq!(session.peer(), Some(&client_identity.certificate));
		Ok(())
	}

	/// The server admits the hand-built anonymous closing, so each refusal of
	/// that fixture comes from the one part its test changes.
	#[tokio::test]
	async fn a_hand_built_anonymous_closing_is_admitted() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag())]);

		awaiting.server.finish(closing).await?;
		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	/// A mutual server admits the hand-built identified closing and records
	/// its certificate, so each refusal of that fixture comes from the one
	/// part its test changes.
	#[tokio::test]
	async fn a_hand_built_identified_closing_is_admitted() -> Result<(), Box<dyn Error>> {
		let client = create_test_certificate();
		let mut awaiting = AwaitingClosing::new(mutual_with(ExpiryValidator)).await;
		let closing = awaiting.identified(&client).await;

		awaiting.server.finish(closing).await?;
		assert_eq!(awaiting.server.peer_certificate(), Some(&client.certificate));
		Ok(())
	}

	/// A closing whose client agreed with another server ephemeral seals
	/// under another handshake secret, so it fails to open, and the server
	/// admits no further step.
	#[tokio::test]
	async fn a_closing_under_another_handshake_secret_is_refused() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let stray = PublicKey::<Secp256k1>::from_sec1_bytes(&create_test_server_ephemeral())?;
		let diverged = Confirming { server_ephemeral: stray, ..awaiting.confirming.to_owned() };
		let closing = awaiting.anonymous_under(&diverged, vec![finished_attribute(&awaiting.tag())]);

		let refusal = awaiting.server.finish(closing.to_owned()).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(_))));
		assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);

		let replayed = awaiting.server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// The server refuses, at the tag, a closing that opens under the right key
	/// but carries the tag of another secret.
	#[tokio::test]
	async fn a_closing_that_confirms_another_secret_is_refused() {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let closing = awaiting.anonymous(vec![finished_attribute(&fixture_confirmation())]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
	}

	/// The closing seal binds its transcript, so a closing sealed under the
	/// closing key of another transcript fails to open.
	#[tokio::test]
	async fn a_closing_sealed_under_another_transcript_is_refused() {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let transcript_hash = fixture_transcript::<Sha3_256>([0x5au8; 32]);
		let foreign = Confirming { transcript_hash, ..awaiting.confirming.to_owned() };
		let closing = awaiting.anonymous_under(&foreign, vec![finished_attribute(&awaiting.tag())]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SealedClosing(_))));
	}

	/// The attribute set of an anonymous closing passes the admission walk
	/// before its decode sorts a set in it (X.690 §11.6).
	#[tokio::test]
	async fn an_anonymous_closing_of_a_descending_set_is_refused() {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let closing = awaiting.sealed_as(DATA, tlv(Tag::Set, &descending_attribute()));

		let refusal = awaiting.server.finish(closing).await;
		assert_eq!(der_refusal(refusal), Some(ErrorKind::SetOrdering));
	}

	/// The kind of the DER error that refused a closing, or `None` for
	/// another outcome.
	fn der_refusal<T>(outcome: Result<T, HandshakeError>) -> Option<ErrorKind> {
		match outcome {
			Err(HandshakeError::DerError(error)) => Some(error.kind()),
			_ => None,
		}
	}

	/// A client Finished passes the admission walk, as a `Signed` structure,
	/// before its decode sorts a set in it (X.690 §11.6).
	#[tokio::test]
	async fn a_client_finished_of_a_descending_set_is_refused() {
		let mut awaiting = AwaitingClosing::new(mutual_with(ExpiryValidator)).await;
		let closing = awaiting.sealed_as(SIGNED_DATA, tlv(Tag::Sequence, &descending_attribute()));

		let refusal = awaiting.server.finish(closing).await;
		assert_eq!(der_refusal(refusal), Some(ErrorKind::SetOrdering));
	}

	/// The key-confirmation tag is mandatory in either form of the closing.
	#[tokio::test]
	async fn an_anonymous_closing_with_no_tag_is_refused() {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let closing = awaiting.anonymous(Vec::new());

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
	}

	/// The server refuses an anonymous closing that carries its tag twice, so
	/// the one reader takes each attribute once.
	#[tokio::test]
	async fn an_anonymous_closing_with_two_tags_is_refused() {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let second = finished_attribute(&fixture_confirmation());
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag()), second]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
	}

	/// The server refuses an anonymous closing that carries the acknowledgement
	/// twice.
	#[tokio::test]
	async fn an_anonymous_closing_with_two_acknowledgements_is_refused() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let first = attribute_of(RECEIPT_ACK, &OctetString::new(*b"first")?);
		let second = attribute_of(RECEIPT_ACK, &OctetString::new(*b"second")?);
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag()), first, second]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A server that granted no budgets issued no receipt, so it refuses a
	/// closing that acknowledges one.
	#[tokio::test]
	async fn an_acknowledgement_with_no_issued_receipt_is_refused() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let stray = OctetString::new(*b"an acknowledgement of no receipt")?;
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag()), attribute_of(RECEIPT_ACK, &stray)]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::ReceiptMismatch)));
		Ok(())
	}

	/// The server refuses a closing whose content type is neither a client
	/// Finished nor an attribute set, before the closing key runs.
	#[tokio::test]
	async fn a_closing_of_another_content_type_is_refused() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let sealer = awaiting.confirming.closing_sealer(None, &awaiting.ephemeral);
		let sealed = sealer.seal(AUTH_ENVELOPED_DATA, b"another container".to_vec())?;

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(sealed)?).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
		Ok(())
	}

	/// The server refuses a closing that carries an abort alert among its
	/// unauthenticated attributes, before the closing opens.
	#[tokio::test]
	async fn a_closing_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag())]);
		let mut sealed = closing.auth_enveloped()?.into_value();
		let alert = attribute_of(HANDSHAKE_ABORT_ALERT, &4u8);
		sealed.unauth_attrs = Some(Attributes::try_from(vec![alert])?);

		let refusal = awaiting.server.finish(HandshakeMessage::try_from(sealed)?).await;
		let expected = HandshakeAlert::DecryptFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A mutual server refuses an anonymous closing, which offers no
	/// certificate.
	#[tokio::test]
	async fn a_mutual_server_refuses_an_anonymous_closing() {
		let mut awaiting = AwaitingClosing::new(mutual_with(ExpiryValidator)).await;
		let closing = awaiting.anonymous(vec![finished_attribute(&awaiting.tag())]);

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	/// An anonymous server still verifies the client Finished of an offered
	/// identity, so a Finished over another transcript ends the handshake.
	#[tokio::test]
	async fn an_anonymous_server_refuses_a_client_finished_over_another_transcript() {
		let client = create_test_certificate();
		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let foreign = fixture_transcript::<Sha3_256>([0x5au8; 32]);
		let closing = awaiting.identified_over(&client, &foreign, client.certificate.to_owned()).await;

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// What a server under `peer_authentication` answers to the closing of an
	/// identity whose hello sent its static key as its agreement ephemeral.
	async fn finish_with_a_static_ephemeral(peer_authentication: PeerAuthentication) -> Result<(), HandshakeError> {
		let client = create_test_certificate();
		let ephemeral = SecretKey::<Secp256k1>::from(&client.signing_key);
		let mut awaiting = AwaitingClosing::with_ephemeral(peer_authentication, ephemeral).await;
		let closing = awaiting.identified(&client).await;

		awaiting.server.finish(closing).await
	}

	/// A client that sends its static key as its ephemeral leaves the session
	/// to the secrecy of the two static keys, so a server that demands an
	/// identity refuses the closing of the one it admitted.
	#[tokio::test]
	async fn a_demanded_identity_that_sends_its_static_key_as_its_ephemeral_is_refused() {
		let refusal = finish_with_a_static_ephemeral(mutual_with(ExpiryValidator)).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// A server that demands no identity still holds the key of a certificate
	/// the client offers, and refuses that key as the client ephemeral.
	#[tokio::test]
	async fn an_offered_identity_that_sends_its_static_key_as_its_ephemeral_is_refused() {
		let refusal = finish_with_a_static_ephemeral(PeerAuthentication::Anonymous).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	/// The server refuses an offered certificate whose key is off the curve,
	/// where the opened Finished names it, before any key comparison or
	/// signature check.
	#[tokio::test]
	async fn an_offered_certificate_whose_key_is_off_the_curve_is_refused() {
		let client = create_test_certificate();
		let mut off_curve = client.certificate.to_owned();
		put_off_curve_key(&mut off_curve);

		let mut awaiting = AwaitingClosing::new(PeerAuthentication::Anonymous).await;
		let transcript_hash = awaiting.confirming.transcript_hash;
		let closing = awaiting.identified_over(&client, &transcript_hash, off_curve).await;

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(
			refusal,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::SpkiError(_)
			))
		));
	}

	/// A handshake under a provider whose digest is SHA3-512 seals the whole
	/// 64-byte digest as its transcript hash, and its closing confirms and
	/// opens under that hash.
	#[tokio::test]
	async fn a_sha3_512_profile_carries_a_64_byte_transcript_hash() -> Result<(), Box<dyn Error>> {
		let server_identity = create_test_certificate();
		let identity = Some(client_identity(&create_test_certificate()));
		let settings = hpke_client_settings(&server_identity.certificate, identity);
		let profiles = SupportedProfiles::from(RunnableProfile::<Aes256Sha3_512Provider>::native().descriptor());
		let signing = signing_identity(&server_identity);
		let server_config = ServerConfig::new(HpkeServerSettings::new(), signing, profiles, KeyPurposes::HOUSE)?;
		let client_config = ClientConfig::new(settings, KeyPurposes::HOUSE)?;
		let mut client = Handshake::<Client, Hpke, Aes256Sha3_512Provider>::client(client_config);
		let mut server = Handshake::<Server, Hpke, Aes256Sha3_512Provider>::server(server_config);

		let opening = client.start()?;
		let reply = server.reply(opening).await?;
		let closing = client.respond(reply).await?;
		server.finish(closing).await?;

		let transcript_hash = server.transcript_hash().ok_or("the reply sealed the transcript")?;
		assert_eq!(transcript_hash.as_bytes().len(), 64);
		Ok(())
	}

	/// A hello with only a transport offer and no security offer round-trips.
	/// The context tag on `transport_offer` keeps a decoder from reading it as
	/// the preceding optional SEQUENCE.
	#[test]
	fn a_hello_with_only_a_transport_offer_round_trips() -> Result<(), Box<dyn Error>> {
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		let hello = ClientHello { transport_offer: Some(TransportOffer::mux(16)), ..hello_of(&ephemeral) };

		let decoded = ClientHello::from_der(&hello.to_der()?)?;
		assert_eq!(decoded.security_offer, None);
		assert_eq!(decoded.transport_offer, Some(TransportOffer::mux(16)));
		Ok(())
	}

	/// The hello, the reply, and the closing of one HPKE handshake, as their
	/// interop samples.
	struct Emitted {
		/// The hello, a `ContentInfo` of type `id-data`, as it was sent.
		hello: HandshakeMessage,
		/// The reply, the signer's `SignedData`, which the client admitted.
		reply: SignedData,
		/// An anonymous closing under the closing key of a fixed secret, an
		/// `AuthEnvelopedData` with a `KEKRecipientInfo`.
		closing: AuthEnvelopedData,
		/// What OpenSSL opens [`Self::closing`] with.
		closing_opening: KekOpening,
	}

	/// Run one HPKE handshake up to the closing, and take its hello and its
	/// reply, beside an anonymous closing sealed under the closing key of a
	/// fixed secret, so a reader holds its key.
	async fn emitted() -> Emitted {
		let identity = create_test_certificate();
		let mut server = Handshake::server(hpke_server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let hello = client.start().expect("a fresh client builds its hello");
		let reply = server.reply(hello.to_owned()).await.expect("the server admits the hello");

		client.respond(reply.to_owned()).await.expect("the client admits the reply");

		let transcript_hash = fixture_transcript::<Sha3_256>([0x07u8; 32]);
		let salt = KdfSalt::new(&[0x99u8; 32]);
		let secret = fixture_handshake_secret(0x42);
		let sealer = secret.sealer::<DefaultCryptoProvider>(SecretSeal::Closing, salt, &transcript_hash);
		let sealer = sealer.expect("the closing key derives");
		let attributes = Attributes::try_from(vec![finished_attribute(&fixture_confirmation())]);
		let attributes = attributes.expect("one attribute is a SET");
		let attributes = attributes.to_der().expect("the attribute set encodes");
		let closing_opening = KekOpening::of(&sealer, SecretSeal::Closing, &attributes);
		let confirmation = fixture_confirmation();
		let parts = ClosingParts { transcript_hash: &transcript_hash, sealed_ack: None, confirmation, sealer };
		let draft = ClosingDraft::bind(None, parts).expect("an anonymous closing binds");
		let closing = draft.seal().await.expect("the closing seals");
		let closing = closing.auth_enveloped().expect("a closing is an AuthEnvelopedData");
		let closing = closing.into_value();

		Emitted { hello, reply: reply_signed_data(&reply), closing, closing_opening }
	}

	/// Write the samples of [`Emitted`]. `scripts/cms-interop.sh` parses the
	/// hello, verifies the reply, and decrypts the closing with OpenSSL when
	/// the run sets `TIGHTBEAM_CMS_SAMPLES`, which `make interop` does.
	#[tokio::test]
	async fn the_emitted_structures_write_their_interop_samples() -> std::io::Result<()> {
		let emitted = emitted().await;
		let samples = [
			("hpke-hello", emitted.hello.der().to_vec()),
			("hpke-reply", content_info(SIGNED_DATA, &emitted.reply)),
			("hpke-closing", content_info(AUTH_ENVELOPED_DATA, &emitted.closing)),
		];

		write_interop_samples(&samples, &[("hpke-closing", &emitted.closing_opening)], &[])
	}
}

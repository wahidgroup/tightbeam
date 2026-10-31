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
use crate::crypto::exchange::{KeyExchange, KeyShare};
use crate::crypto::kdf::KdfSalt;
use crate::crypto::sign::{CmsSigner, Signed, SignedContent, SignedDataExt, SignerInfoDraft, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::OctetStringRef;
use crate::der::{Any, Decode, Encode, Tag};
use crate::marker::MaybeSendFuture;
use crate::oids::{DATA, HANDSHAKE_REPLY_CONTENT};
use crate::random::{generate_nonce, CryptoRngCore};
use crate::transport::handshake::attributes::{AttributePayload, HandshakeAttribute, HandshakeAttributes};
use crate::transport::handshake::ephemeral::{Distinct, ExchangeSecret, OpenedShare};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientAgreement, ClientLegs, HandshakeFlow, Opened, OpeningIntake, OpeningParts, ReceivedShare,
	ReplyBinding, ReplyIntake, ReplyParts, ReplyVerified, ServerAgreement, ServerLegs,
};
use crate::transport::handshake::negotiation::SecurityAccept;
use crate::transport::handshake::peer::LearnedTrust;
use crate::transport::handshake::primitives::transcript::Transcript;
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::schedule::Salt;
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	ClientHello, ClientShare, Exchange, HandshakeMessage, HandshakeProvider, HandshakeSecret, ServerHandshake,
	ServerShare,
};
use crate::transport::wire_der::WireDer;
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

/// What an HPKE client holds from its hello to the agreement: the pending
/// half of its exchange, which the agreement reads in place.
pub struct HpkePending<P: HandshakeProvider>(<Exchange<P> as KeyExchange>::Pending);

impl<P: HandshakeProvider> ClientLegs<P> for Hpke {
	type Settings = HpkeClientSettings;
	type Trust = LearnedTrust;
	type Opening = HpkeOpening;
	/// The pending half of the exchange. It is boxed, so a move to the
	/// agreement copies a pointer, and it wipes in place where the box drops.
	type Pending = Box<HpkePending<P>>;

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
		// 1. Draw the client random and the offer `R` of the exchange, whose
		//    completion with the server's share derives the handshake secret
		//    alone.
		let client_random = generate_nonce::<32>(Some(&mut *rng))?;
		let (pending, client_ephemeral) = Exchange::<P>::offer(rng);

		// 2. Carry the hello as the OCTET STRING of a `ContentInfo` of type `id-data`, and encode it once.
		let hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			client_ephemeral: OctetString::new(client_ephemeral.to_octets())?,
			security_offer: parts.security_offer.cloned(),
			transport_offer: parts.transport_offer.cloned(),
		};
		let content = Any::new(Tag::OctetString, hello.to_der()?)?;
		let message = HandshakeMessage::try_from(ContentInfo { content_type: DATA, content })?;

		// 3. Open the transcript over the hello as it was sent.
		let mut transcript = Transcript::new();
		transcript.append(message.der())?;

		let opening = HpkeOpening { transcript, client_random };
		Ok(Opened { message, opening, pending: Box::new(HpkePending(pending)) })
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

		let content = reply.value().content(HANDSHAKE_REPLY_CONTENT)?;
		let handshake = ServerHandshake::from_der(content)?;
		transcript.append(content)?;

		// 2. Build the path the reply's signer presents, parsed from the bytes
		//    it arrived as, for the trust to admit, and bind the `certificates`
		//    field as it arrived after the content, then seal.
		let presented = reply.signer_path()?;
		let (server, certificates) = presented.ok_or(HandshakeError::MissingServerCertificate)?;
		transcript.append(certificates)?;
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 3. Keep the decoded reply, for its signature and its attributes.
		let reply = reply.into_value();

		// 4. Return the facts of the reply, with the session receipt its signer
		//    attached, and its share in its OCTET STRING until the signature
		//    verifies.
		let receipt = reply.find_unsigned_attr(<Signed<SignedData> as AttributePayload>::OID)?;
		let receipt = receipt.map(|attribute| attribute.decode::<Signed<SignedData>>()).transpose()?;
		let server_random = handshake.server_random.to_32_byte_array()?;
		Ok(ReplyIntake {
			server,
			security_accept: handshake.security_accept.map(WireDer::into_value),
			transport_accept: handshake.transport_accept.map(WireDer::into_value),
			server_ephemeral: ReceivedShare::Octets(handshake.server_ephemeral),
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
		let content = reply.content(HANDSHAKE_REPLY_CONTENT)?;
		let signed = SignedContent::new(HANDSHAKE_REPLY_CONTENT, content).with_attribute(transcript_hash.attribute()?);
		CmsSigner::verify_sole_signer::<P>(reply, server, signed).map(drop)?;
		Ok(ReplyVerified(()))
	}
}

/// The HPKE client derives the ephemeral secret from the exchange alone. The
/// completion reads the pending half in place, so it wipes where the box
/// drops.
impl<P: HandshakeProvider> ClientAgreement<P> for Box<HpkePending<P>> {
	fn agree(
		self,
		server_ephemeral: &Distinct<ServerShare<P>>,
		salt: KdfSalt<'_>,
	) -> Result<HandshakeSecret, HandshakeError> {
		let shared = server_ephemeral.complete::<Exchange<P>>(&self.0)?;
		HandshakeSecret::ephemeral::<P>(shared.as_ref(), salt)
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
pub struct HpkeHello<P: HandshakeProvider> {
	/// The transcript, open over the hello as it arrived.
	transcript: Transcript,
	/// The client random the hello carried.
	client_random: [u8; 32],
	/// The client's share `R`, parsed once from the hello.
	client_ephemeral: OpenedShare<ClientShare<P>>,
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
	type Sealed = HpkeHello<P>;
	type Opened = HpkeHello<P>;
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

		// 3. Parse `R` as a share of the exchange, so a share of another width
		//    or form, or no share at all, fails before any negotiation. The
		//    static-key check waits for the closing identity.
		let client_random = client_random.to_32_byte_array()?;
		let client_ephemeral = OpenedShare::from_octets::<Exchange<P>>(client_ephemeral.as_bytes())?;
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
		let handshake = ServerHandshake {
			server_random: OctetString::new(server_random)?,
			server_ephemeral: OctetString::new(server_ephemeral.to_octets())?,
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

/// The HPKE server derives the ephemeral secret from the exchange with `R`
/// alone. The server's share serves this one exchange, and the transcript of
/// the hello drops with the value.
impl<P: HandshakeProvider> ServerAgreement<P> for HpkeHello<P> {
	fn respond(&self, rng: &mut dyn CryptoRngCore) -> Result<(ServerShare<P>, ExchangeSecret), HandshakeError> {
		self.client_ephemeral.respond::<Exchange<P>>(rng)
	}

	fn settle(
		self,
		shared: ExchangeSecret,
		salt: KdfSalt<'_>,
	) -> Result<(HandshakeSecret, OpenedShare<ClientShare<P>>), HandshakeError> {
		let secret = HandshakeSecret::ephemeral::<P>(&shared, salt)?;
		Ok((secret, self.client_ephemeral))
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::asn1::admission::fixtures::{descending_attribute, tlv};
	use crate::crypto::cms::AuthEnvelopedData;
	use crate::crypto::common::typenum::Unsigned;
	use crate::crypto::exchange::{EcdheShare, KeyExchangeError};
	use crate::crypto::hash::{Digest, Sha3_256};
	use crate::crypto::key::SigningKeyProvider;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::Secp256k1Signature;
	use crate::crypto::sign::elliptic_curve::sec1::{CompressedPointSize, ToEncodedPoint};
	use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
	use crate::crypto::sign::SignedDataSigners;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::policy::DirectTrustValidator;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::asn1::ObjectIdentifier;
	use crate::der::{ErrorKind, Tag};
	use crate::oids::{AUTH_ENVELOPED_DATA, HANDSHAKE_TRANSCRIPT_HASH, SIGNED_DATA};
	use crate::testing::fixtures::{der_round_trip, write_interop_samples, KekOpening, TestEnvelope};
	use crate::testing::{unhex, SeededStream, TestResult};
	use crate::transport::envelopes::TransportEnvelope;
	use crate::transport::handshake::flow::{ClosingDraft, ClosingParts};
	use crate::transport::handshake::negotiation::{RunnableProfile, TransportOffer};
	use crate::transport::handshake::schedule::{KeyConfirmation, SecretSeal};
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{Handshake, HandshakePhase, PeerAuthentication, SupportedProfiles};

	/// The configuration of an anonymous client that trusts `server`.
	fn anonymous_client(server: &HandshakeCertificate) -> TestClientConfig<Hpke> {
		hpke_client(&server.certificate, None)
	}

	/// An anonymous client that trusts `server` and has sent its hello, with
	/// that hello.
	fn client_after_hello(server: &HandshakeCertificate) -> (TestClient<Hpke>, HandshakeMessage) {
		let mut client = Handshake::client(anonymous_client(server));
		let opening = client.start().expect("a fresh client builds its hello");
		(client, opening)
	}

	/// A client that admits a fresh server, beside what it answers to the
	/// reply of that server once `edit` rewrote it.
	async fn respond_to_edited(
		edit: impl FnOnce(&HandshakeMessage) -> HandshakeMessage,
	) -> (TestClient<Hpke>, Result<HandshakeMessage, HandshakeError>) {
		let (mut client, reply) = replied::<Hpke>(&create_test_server()).await;
		let answer = client.respond(edit(&reply)).await;
		(client, answer)
	}

	/// What an anonymous client answers to the reply that `sign` builds with
	/// the key of the server the client trusts, in answer to the client's
	/// hello, over a content that accepts the default profile and carries
	/// `server_ephemeral`.
	async fn respond_to_content(
		server_ephemeral: impl AsRef<[u8]>,
		sign: impl FnOnce(&HandshakeCertificate, &HandshakeMessage, &ServerHandshake) -> HandshakeMessage,
	) -> Result<HandshakeMessage, HandshakeError> {
		let server = create_test_certificate(0xd0);
		let (mut client, opening) = client_after_hello(&server);
		let handshake = reply_content(Some(create_default_test_profile()), server_ephemeral);
		client.respond(sign(&server, &opening, &handshake)).await
	}

	/// An anonymous client that trusts a server which demands an identity,
	/// beside the reply that server sent to the client's hello. Both sides
	/// carry `transport_offer`.
	async fn replied_by_a_mutual_server(
		transport_offer: Option<TransportOffer>,
	) -> (TestClient<Hpke>, HandshakeMessage) {
		let identity = create_test_certificate(0xd1);
		let mut server = hpke_server(&identity);
		let mut client = anonymous_client(&identity);
		server.peer_authentication = PeerAuthentication::mutual_by_expiry();
		server.transport = transport_offer.to_owned();
		client.transport_offer = transport_offer;

		let mut client = Handshake::client(client);
		let mut replying = Handshake::server(server);
		let opening = client.start().expect("a fresh client builds its hello");
		let reply = replying.reply(opening).await.expect("the server admits the hello");
		(client, reply)
	}

	/// What a server that demands no identity answers to `opening` as the
	/// hello of an HPKE handshake.
	async fn hpke_reply_to(opening: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		let mut server = Handshake::server(hpke_server(&create_test_certificate(0xd2)));
		server.reply(opening).await
	}

	/// A handshake of an anonymous client, run through its closing.
	async fn anonymous_run() -> Run<Hpke> {
		let identity = create_test_certificate(0xd3);
		run(anonymous_client(&identity), hpke_server(&identity)).await
	}

	/// A handshake of a client that presents the identity of [`parties`] to a
	/// server that demands one, run through its closing, beside that identity.
	async fn identified_run() -> (HandshakeCertificate, Run<Hpke>) {
		let Parties { client_identity, client, server, .. } = parties::<Hpke>(PeerAuthentication::mutual_by_expiry());
		(client_identity, run(client, server).await)
	}

	/// The hello is a `ContentInfo` of type `id-data` (RFC 5652 §4).
	#[test]
	fn the_hello_is_a_content_info_of_type_data() -> TestResult {
		let (_, opening) = client_after_hello(&create_test_certificate(0xd4));
		let hello = opening.data()?;
		assert_eq!(hello.value().content_type, ObjectIdentifier::new("1.2.840.113549.1.7.1")?);
		Ok(())
	}

	/// The hello carries the client ephemeral `R` as a compressed point of the
	/// curve, as a TLS 1.3 hello carries its key share.
	#[test]
	fn the_hello_carries_the_client_ephemeral() -> TestResult {
		let (_, opening) = client_after_hello(&create_test_certificate(0xd5));
		let hello = opening.carried_hello();
		PublicKey::<Secp256k1>::from_sec1_bytes(hello.client_ephemeral.as_bytes())?;
		assert_eq!(hello.client_ephemeral.as_bytes().len(), CompressedPointSize::<Secp256k1>::USIZE);
		Ok(())
	}

	/// The hello travels under context tag 8 of the transport envelope.
	#[test]
	fn an_hpke_hello_travels_under_tag_8() -> TestResult {
		let (_, opening) = client_after_hello(&create_test_certificate(0xd6));
		let encoded = TransportEnvelope::from(opening).to_der()?;
		assert_eq!(encoded.first(), Some(&0xA8));
		Ok(())
	}

	/// The reply is a `SignedData` whose content is the `ServerHandshake`
	/// under the reply content type.
	#[tokio::test]
	async fn the_reply_signs_the_server_handshake_under_its_content_type() -> TestResult {
		let (_, reply) = replied::<Hpke>(&create_test_server()).await;

		let signed_data = reply.signed_data();
		let content_type = signed_data.encap_content_info.econtent_type;
		assert_eq!(content_type, ObjectIdentifier::new("1.3.6.1.4.1.64586.1.26")?);
		Ok(())
	}

	/// The reply signs the transcript hash as a signed attribute: SHA3-256 of
	/// the hello as it was sent, the reply content, and the `certificates`
	/// field, in that order (RFC 9846 §4.5.2 signs over the Certificate).
	///
	/// The expected digest comes from the `sha3` crate over those bytes, so
	/// the check is independent of the crate's transcript code.
	#[tokio::test]
	async fn the_reply_signs_the_hash_of_the_hello_the_content_and_the_certificates() -> TestResult {
		let identity = create_test_certificate(0xd7);
		let mut server = Handshake::server(hpke_server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let opening = client.start()?;
		let reply = server.reply(opening.to_owned()).await?;
		let signed_data = reply.signed_data();
		let content = signed_data.content(HANDSHAKE_REPLY_CONTENT)?;
		let certificates = certificates_field([identity.certificate.to_owned()]);
		let expected = Sha3_256::new().chain_update(opening.der()).chain_update(content);
		let expected = expected.chain_update(certificates).finalize();

		let signer = signed_data.sole_signer()?;
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
	async fn the_reply_carries_the_server_finished() -> TestResult {
		let (_, reply) = replied::<Hpke>(&create_test_server()).await;

		let signed_data = reply.signed_data();
		let finished = signed_data.find_unsigned_attr(KeyConfirmation::OID)?;
		let finished = finished.ok_or("the reply carries its server Finished")?;
		finished.decode::<KeyConfirmation>()?;
		Ok(())
	}

	/// The reply signature is a DER `ECDSA-Sig-Value` (RFC 3279 §2.2.3).
	#[tokio::test]
	async fn the_reply_signature_is_der() -> TestResult {
		let (_, reply) = replied::<Hpke>(&create_test_server()).await;

		let signed_data = reply.signed_data();
		let signer = signed_data.sole_signer()?;
		Secp256k1Signature::from_der(signer.signature.as_bytes())?;
		Ok(())
	}

	/// A server reply names its signer by the certificate it carries, so the
	/// whole step costs the key provider its signature alone.
	#[tokio::test]
	async fn an_hpke_reply_fetches_no_public_key() -> TestResult {
		let identity = create_test_certificate(0xd8);
		let provider = Arc::new(CountingProvider::new(identity.signing_key.to_owned()));
		let identity = presenting(&identity, Arc::clone(&provider) as Arc<dyn SigningKeyProvider>);
		let profiles = SupportedProfiles::from(create_default_test_profile());
		let config = TestServerConfig::<Hpke>::new(HpkeServerSettings::new(), identity, profiles, KeyPurposes::HOUSE)?;

		let fetched_at_construction = provider.public_keys();
		let mut server = Handshake::server(config);
		let ephemeral = fixture_ephemeral(0x51);

		server.reply(hello_opening(&hello_of(&ephemeral))).await?;

		assert_eq!(provider.public_keys(), fetched_at_construction);
		Ok(())
	}

	/// A server share that is rewritten into octets that encode no share,
	/// after the server signed its reply, fails the signature. The client
	/// checks the signature before it parses the share, so no unauthenticated
	/// octet reaches the parse.
	#[tokio::test]
	async fn a_tampered_malformed_share_fails_the_signature_before_its_parse() {
		let (_, refusal) = respond_to_edited(|reply| Hpke::with_server_ephemeral(reply, off_curve_point())).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A certificate demand flipped after the server signed its reply changes
	/// the signed content, so the signature fails. An on-path party cannot talk
	/// an anonymous client past a server that demands an identity.
	#[tokio::test]
	async fn a_flipped_certificate_demand_fails_the_reply_signature() {
		let (mut client, reply) = replied_by_a_mutual_server(None).await;
		let flipped = reply.with_content(|handshake| handshake.client_cert_required = false);

		let refusal = client.respond(flipped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	// A client refuses a reply that the server's key signed over the right
	// content under another binding, so a signature over another transcript
	// or under another content type verifies as no reply.
	crate::tb_cases! {
		async fn a_client_refuses_a_reply_signed_under_another(
			sign: fn(&HandshakeCertificate, &HandshakeMessage, &ServerHandshake) -> HandshakeMessage
		) {
			let share = fixture_ephemeral(0x52).public_key().to_encoded_point(true);
			let refusal = respond_to_content(share, sign).await;
			assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		}
		cases {
			/// A reply whose signer saw another transcript fails its signed
			/// attributes, though the server's key signed it.
			transcript => |server, _, handshake| {
				signed_reply_over(server, handshake, &foreign_transcript_hash(), HANDSHAKE_REPLY_CONTENT)
			},
			/// The reply signs under a content type of its own, so the same
			/// content that the server's key signed under `id-data`, over
			/// the right transcript, verifies as no reply.
			content_type => |server, opening, handshake| signed_reply_under(server, opening, handshake, DATA),
		}
	}

	/// The transcript covers the certificate the reply's signer names, so a
	/// reply whose certificate was swapped for another the client trusts, of
	/// the same key, fails its signed transcript hash.
	#[tokio::test]
	async fn a_reply_whose_certificate_was_swapped_for_one_of_the_same_key_is_refused() -> TestResult {
		let identity = create_test_certificate(0xd9);
		let twin = same_key_twin(&identity);
		let anchors = [identity.certificate.to_owned(), twin.to_owned()];
		let trusted = DirectTrustValidator::default().with_trust_chain(anchors)?;
		let settings = HpkeClientSettings::new(LearnedTrust::new(trusted));
		let mut client = Handshake::client(TestClientConfig::<Hpke>::new(settings, KeyPurposes::HOUSE)?);
		let mut server = Handshake::server(hpke_server(&identity));
		let reply = server.reply(client.start()?).await?;
		let swapped = reply.with_presented([twin]);

		let refusal = client.respond(swapped).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
		Ok(())
	}

	/// A validly signed server ephemeral in the uncompressed form names a
	/// point of the curve, and the client refuses it at the width, because the
	/// HPKE reply carries the compressed form alone.
	#[tokio::test]
	async fn an_uncompressed_server_ephemeral_is_refused() {
		let uncompressed = fixture_ephemeral(0x53).public_key().to_encoded_point(false);

		let refusal = respond_to_content(uncompressed, signed_reply).await;
		let width = KeyExchangeError::Width { expected: 33, actual: 65 };
		assert!(matches!(refusal, Err(HandshakeError::KeyExchange(error)) if error == width));
	}

	/// The client refuses a reply whose server Finished fails, though its
	/// signature verifies, before it builds any closing.
	#[tokio::test]
	async fn a_reply_whose_server_finished_fails_is_refused_before_the_closing() {
		let forged = vec![finished_attribute(&fixture_confirmation())];
		let (client, refusal) = respond_to_edited(|reply| reply.with_unsigned(|_| forged)).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(client.phase(), HandshakePhase::Spent);
	}

	/// The client refuses a reply that carries its server Finished twice.
	#[tokio::test]
	async fn a_reply_with_two_server_finished_is_refused() {
		let second = finished_attribute(&fixture_confirmation());
		let doubled = |reply: &HandshakeMessage| reply.with_unsigned(|carried| [carried, vec![second]].concat());

		let (_, refusal) = respond_to_edited(doubled).await;
		assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
	}

	/// A client reads the validity period of the certificate a reply names on
	/// its own clock, so a clock past the end of the period refuses a server
	/// that the host clock reads as current.
	#[tokio::test]
	async fn a_client_reads_the_validity_of_the_reply_signer_on_its_own_clock() -> TestResult {
		let identity = create_windowed_test_certificate(0xdd);
		let config = anonymous_client(&identity).with_clock(TestCertificate::clock_past_validity());

		let mut server = Handshake::server(hpke_server(&identity));
		let mut client = Handshake::client(config);

		let reply = server.reply(client.start()?).await?;
		let refused = client.respond(reply).await;
		assert!(matches!(
			refused,
			Err(HandshakeError::CertificateValidationError(CertificateValidationError::Expired))
		));
		Ok(())
	}

	/// An anonymous client refuses the reply of a server that demands a client
	/// identity.
	#[tokio::test]
	async fn an_anonymous_client_refuses_a_server_that_demands_an_identity() {
		let (mut client, reply) = replied_by_a_mutual_server(None).await;
		let refused = client.respond(reply).await;
		assert!(matches!(refused, Err(HandshakeError::MutualAuthRequired)));
	}

	/// A closing step that began and failed leaves the client spent, so it
	/// admits no further step and completes nothing.
	///
	/// The server here demands a client identity, and the client holds none,
	/// so the step refuses before it derives the handshake secret.
	#[tokio::test]
	async fn a_failed_hpke_closing_leaves_the_client_spent() {
		let (mut client, reply) = replied_by_a_mutual_server(Some(budget_offer())).await;

		let refused = client.respond(reply.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::MutualAuthRequired)));
		assert_eq!(client.phase(), HandshakePhase::Spent);

		let replayed = client.respond(reply).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		assert!(matches!(client.complete(), Err(HandshakeError::InvalidState)));
	}

	// The server reads the agreement ephemeral of a hello before any
	// negotiation, and refuses one that is no compressed point of the curve.
	crate::tb_cases! {
		async fn the_server_refuses_a_client_ephemeral((ephemeral, refusal): (Vec<u8>, KeyExchangeError)) {
			let answer = hpke_reply_to(hello_opening(&hello_carrying(ephemeral))).await;
			assert!(matches!(answer, Err(HandshakeError::KeyExchange(error)) if error == refusal));
		}
		cases {
			/// An ephemeral that names no point on the curve is refused as
			/// the server reads the hello.
			off_the_curve => (off_curve_point().to_vec(), KeyExchangeError::Malformed),
			/// A point of the curve in the uncompressed form is refused at
			/// the width, because the HPKE hello carries the compressed form
			/// alone.
			in_the_uncompressed_form => (
				fixture_ephemeral(0x54).public_key().to_encoded_point(false).as_bytes().to_vec(),
				KeyExchangeError::Width { expected: 33, actual: 65 },
			),
		}
	}

	// The server refuses a hello in any container but a `ContentInfo` of type
	// `id-data`, before it reads the content.
	crate::tb_cases! {
		async fn the_server_refuses_a_hello(opening: HandshakeMessage) -> TestResult {
			let refusal = hpke_reply_to(opening).await;
			assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
			Ok(())
		}
		cases {
			/// The hello travels in a `ContentInfo` of type `id-signedData`.
			of_another_content_type => {
				let hello = Any::new(Tag::OctetString, hello_of(&fixture_ephemeral(0x55)).to_der()?)?;
				HandshakeMessage::try_from(ContentInfo { content_type: SIGNED_DATA, content: hello })?
			},
			/// The hello is a `SignedData`, the container of a reply.
			in_a_signed_data => HandshakeMessage::try_from(create_test_signed_data(b"hello"))?,
		}
	}

	// A closing seals its content under the type that names it: the attribute
	// set of an anonymous client as data, and the client Finished of an
	// identity as signed data.
	crate::tb_cases! {
		async fn a_closing_seals_its_content_as((run, content_type): (Run<Hpke>, ObjectIdentifier)) -> TestResult {
			let closing = run.closing.auth_enveloped()?;
			assert_eq!(closing.value().auth_encrypted_content_info.content_type, content_type);
			Ok(())
		}
		cases {
			/// An anonymous closing carries the attribute set as content of
			/// type `id-data`.
			data_when_anonymous => (anonymous_run().await, ObjectIdentifier::new("1.2.840.113549.1.7.1")?),
			/// A closing of an identity carries its client Finished as
			/// content of type `id-signedData`.
			signed_data_when_identified => (identified_run().await.1, ObjectIdentifier::new("1.2.840.113549.1.7.2")?),
		}
	}

	/// An anonymous closing opens under the shared closing, and the server
	/// records no peer.
	#[tokio::test]
	async fn an_anonymous_closing_opens_and_records_no_peer() -> TestResult {
		let mut run = anonymous_run().await;

		let session = run.server.complete()?;
		assert_eq!(session.peer(), None);
		Ok(())
	}

	/// An identified closing opens under the shared closing, and a mutual
	/// server records the client's certificate.
	#[tokio::test]
	async fn an_identified_closing_opens_and_records_its_certificate() -> TestResult {
		let (client_identity, mut run) = identified_run().await;
		let session = run.server.complete()?;
		assert_eq!(session.peer(), Some(&client_identity.certificate));
		Ok(())
	}

	/// The server admits the hand-built anonymous closing, so each refusal of
	/// that fixture comes from the one part its test changes.
	#[tokio::test]
	async fn a_hand_built_anonymous_closing_is_admitted() -> TestResult {
		let mut awaiting = Hpke::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x56)).await;
		let tag = finished_attribute(&awaiting.tag());

		awaiting.finish_anonymous(vec![tag]).await?;
		assert_eq!(awaiting.server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	// The closing seal binds the handshake secret and the transcript, so a
	// closing sealed under the closing key of another of either fails to open,
	// and the server admits no further step.
	crate::tb_cases! {
		async fn the_server_refuses_a_closing_sealed_under_another(diverged: fn(&Confirming) -> Confirming) {
			let mut awaiting = Hpke::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x57)).await;
			let tag = finished_attribute(&awaiting.tag());
			let closing = awaiting.anonymous_under(&diverged(&awaiting.confirming), vec![tag]);

			let refusal = awaiting.server.finish(closing.to_owned()).await;
			assert!(matches!(refusal, Err(HandshakeError::SealedClosing(_))));
			assert_eq!(awaiting.server.phase(), HandshakePhase::Spent);

			let replayed = awaiting.server.finish(closing).await;
			assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		}
		cases {
			/// A client that agreed with another server ephemeral seals under
			/// another handshake secret.
			handshake_secret => |confirming| Confirming {
				server_ephemeral: fixture_ephemeral(0x58).public_key(),
				..confirming.to_owned()
			},
			/// A closing key of another transcript seals the closing.
			transcript => |confirming| Confirming {
				transcript_hash: foreign_transcript_hash(),
				..confirming.to_owned()
			},
		}
	}

	// A closing passes the admission walk before its decode sorts a set in
	// it, so the server refuses a set out of DER order (X.690 §11.6).
	crate::tb_cases! {
		async fn a_descending_set_is_refused_in(
			(peer_authentication, content_type, tag): (PeerAuthentication, ObjectIdentifier, Tag)
		) {
			let mut awaiting = Hpke::awaiting_closing(peer_authentication, fixture_ephemeral(0x59)).await;
			let closing = awaiting.sealed_as(content_type, tlv(tag, &descending_attribute()));

			let refusal = awaiting.server.finish(closing).await;
			assert!(matches!(refusal, Err(HandshakeError::DerError(error)) if error.kind() == ErrorKind::SetOrdering));
		}
		cases {
			/// The attribute set of an anonymous closing carries the set.
			an_anonymous_attribute_set => (PeerAuthentication::Anonymous, DATA, Tag::Set),
			/// A client Finished carries the set, and the walk reads it as a
			/// `Signed` structure.
			a_client_finished => (PeerAuthentication::mutual_by_expiry(), SIGNED_DATA, Tag::Sequence),
		}
	}

	/// The key-confirmation tag is mandatory in either form of the closing.
	#[tokio::test]
	async fn an_anonymous_closing_with_no_tag_is_refused() {
		let mut awaiting = Hpke::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x5a)).await;
		let refusal = awaiting.finish_anonymous(Vec::new()).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingAttribute)));
	}

	// The server refuses an anonymous closing that carries an attribute twice
	// beside its tag, so the one reader takes each attribute once.
	crate::tb_cases! {
		async fn an_anonymous_closing_is_refused_with(beside_the_tag: Vec<Attribute>) {
			let mut awaiting = Hpke::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x5b)).await;
			let attributes = [vec![finished_attribute(&awaiting.tag())], beside_the_tag].concat();

			let refusal = awaiting.finish_anonymous(attributes).await;
			assert!(matches!(refusal, Err(HandshakeError::DuplicateAttribute)));
		}
		cases {
			/// The closing carries a second tag, of a fixture secret.
			two_tags => vec![finished_attribute(&fixture_confirmation())],
			/// The closing carries two receipt acknowledgements.
			two_acknowledgements => vec![acknowledgement(b"first"), acknowledgement(b"second")],
		}
	}

	/// The server refuses a closing whose content type is neither a client
	/// Finished nor an attribute set, before the closing key runs.
	#[tokio::test]
	async fn a_closing_of_another_content_type_is_refused() {
		let mut awaiting = Hpke::awaiting_closing(PeerAuthentication::Anonymous, fixture_ephemeral(0x5c)).await;
		let closing = awaiting.sealed_as(AUTH_ENVELOPED_DATA, b"another container".to_vec());

		let refusal = awaiting.server.finish(closing).await;
		assert!(matches!(refusal, Err(HandshakeError::UnexpectedContainer)));
	}

	/// A mutual server refuses an anonymous closing, which offers no
	/// certificate.
	#[tokio::test]
	async fn a_mutual_server_refuses_an_anonymous_closing() {
		let mutual = PeerAuthentication::mutual_by_expiry();
		let mut awaiting = Hpke::awaiting_closing(mutual, fixture_ephemeral(0x5d)).await;
		let tag = finished_attribute(&awaiting.tag());

		let refusal = awaiting.finish_anonymous(vec![tag]).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	/// A hello with only a transport offer and no security offer round-trips.
	/// The context tag on `transport_offer` keeps a decoder from reading it as
	/// the preceding optional SEQUENCE.
	#[test]
	fn a_hello_with_only_a_transport_offer_round_trips() {
		let ephemeral = fixture_ephemeral(0x5e);
		let hello = ClientHello { transport_offer: Some(TransportOffer::mux(16)), ..hello_of(&ephemeral) };

		let decoded = der_round_trip(&hello);
		assert_eq!(decoded, hello);
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
		let identity = create_test_certificate(0xda);
		let mut server = Handshake::server(hpke_server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let hello = client.start().expect("a fresh client builds its hello");
		let reply = server.reply(hello.to_owned()).await.expect("the server admits the hello");

		client.respond(reply.to_owned()).await.expect("the client admits the reply");

		let transcript_hash = fixture_transcript_hash();
		let sealer = fixture_sealer(SecretSeal::Closing);
		let attributes = Attributes::try_from(vec![finished_attribute(&fixture_confirmation())]);
		let attributes = attributes.expect("one attribute is a SET");
		let attributes = attributes.to_der().expect("the attribute set encodes");
		let closing_opening = sealer.kek_opening(&attributes);
		let confirmation = fixture_confirmation();
		let parts = ClosingParts { transcript_hash: &transcript_hash, sealed_ack: None, confirmation, sealer };
		let draft = ClosingDraft::bind(None, parts).expect("an anonymous closing binds");
		let closing = draft.seal().await.expect("the closing seals");
		let closing = closing.auth_enveloped().expect("a closing is an AuthEnvelopedData");
		let closing = closing.into_value();

		Emitted { hello, reply: reply.signed_data(), closing, closing_opening }
	}

	/// Write the samples of [`Emitted`]. `scripts/cms-interop.sh` parses the
	/// hello, verifies the reply, and decrypts the closing with OpenSSL when
	/// the run sets `TIGHTBEAM_CMS_SAMPLES`, which `make interop` does.
	#[tokio::test]
	async fn the_emitted_structures_write_their_interop_samples() {
		let emitted = emitted().await;
		let closing = TestEnvelope::content_info(AUTH_ENVELOPED_DATA, &emitted.closing);
		let samples = [
			("hpke-hello", emitted.hello.der().to_vec()),
			("hpke-reply", TestEnvelope::content_info(SIGNED_DATA, &emitted.reply)),
			("hpke-closing", closing),
		];

		write_interop_samples(&samples, &[("hpke-closing", &emitted.closing_opening)], &[]);
	}

	/// The point of the secp256k1 scalar of 32 `0x05` bytes, the agreement
	/// ephemeral that `SeededStream(3)` draws after a random of `0x04` bytes.
	fn seeded_point() -> PublicKey<Secp256k1> {
		let scalar = SecretKey::<Secp256k1>::from_slice(&[0x05; 32]);
		scalar.expect("32 bytes of 0x05 are a scalar").public_key()
	}

	/// The DER of the `ClientHello` a client sends under `SeededStream(3)`.
	const KNOWN_HELLO: &str = "304504200404040404040404040404040404040404040404040404040404040404040404\
		04210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7";

	/// The DER of the `ServerHandshake` a server binds under `SeededStream(9)`,
	/// with [`seeded_point`] as its ephemeral.
	const KNOWN_SERVER_HANDSHAKE: &str = "30819804200a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a\
		04210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7\
		304e304ca00b0609608648016503040208a10b060960864801650304012ea20b060960864801650304030a\
		a30d060b2a864886f70d0109100321a40706052b8104000aa50b060960864801650304012d010100";

	/// The hello carries its agreement ephemeral `R` as the compressed point
	/// the seeded draw makes, and encodes as [`KNOWN_HELLO`].
	#[test]
	fn the_hello_carries_its_share_as_its_known_octets() -> TestResult {
		let server = create_test_certificate(0xdb);
		let config = anonymous_client(&server);
		let parts = OpeningParts { security_offer: None, transport_offer: None };
		let open = <Hpke as ClientLegs<DefaultCryptoProvider>>::open;
		let opened = open(config.flow(), (), parts, &mut SeededStream(3))?;

		let hello = opened.message.data()?;
		let octets = hello.value().content.decode_as::<OctetStringRef<'_>>()?;
		let decoded = ClientHello::from_der(octets.as_bytes())?;
		let expected = seeded_point().to_encoded_point(true);
		assert_eq!(decoded.client_ephemeral.as_bytes(), expected.as_bytes());
		assert_eq!(octets.as_bytes(), unhex(KNOWN_HELLO));
		Ok(())
	}

	/// The reply carries the server ephemeral as the compressed point, and its
	/// content encodes as [`KNOWN_SERVER_HANDSHAKE`].
	#[test]
	fn the_reply_carries_its_share_as_its_known_octets() -> TestResult {
		let server = create_test_certificate(0xdc);
		let identity = server.signing_identity();
		let server_share = EcdheShare::from(seeded_point());
		let client_ephemeral = OpenedShare::fixture(EcdheShare::from(seeded_point()));
		let mut opened = HpkeHello { transcript: Transcript::new(), client_random: CLIENT_RANDOM, client_ephemeral };
		let profile = RunnableProfile::<DefaultCryptoProvider>::native();
		let parts = ReplyParts {
			identity: &identity,
			profile,
			transport_accept: None,
			server_ephemeral: &server_share,
			client_cert_required: false,
		};

		let bind = <Hpke as ServerLegs<DefaultCryptoProvider>>::bind_reply;
		let bound = bind(&mut opened, &HpkeServerSettings, parts, &mut SeededStream(9))?;
		let handshake = ServerHandshake::from_der(&bound.draft.content)?;
		let expected = seeded_point().to_encoded_point(true);
		assert_eq!(handshake.server_ephemeral.as_bytes(), expected.as_bytes());
		assert_eq!(bound.draft.content, unhex(KNOWN_SERVER_HANDSHAKE));
		Ok(())
	}
}

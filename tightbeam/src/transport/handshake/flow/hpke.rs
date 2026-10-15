//! The HPKE flow.
//!
//! HPKE tunnels its own messages inside the two containers. The client
//! learns the server from the reply, and it seals the base secret to the
//! server's static key on the closing.
//!
//! The client holds two ephemeral keys, and each serves one agreement
//! (RFC 9180 § 9.2.3):
//!
//! - `r` agrees with the server ephemeral `E`, and `r·E` feeds the handshake
//!   secret. Its public half travels inside the sealed payload.
//! - HPKE draws its own ephemeral to seal the closing payload to the server's static key.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignedData;
use crate::constants::{EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_AAD_DOMAIN_TAG, TIGHTBEAM_HPKE_HANDSHAKE_INFO};
use crate::crypto::hpke::{HpkeMessage, HpkePublicKeyOps, HpkeSuite};
use crate::crypto::kdf::EcdhSecret;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::LowSEncoding;
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::{Decode, Encode};
use crate::random::{generate_nonce, CryptoRngCore, RngWrapper};
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientFlow, ClosingBinding, ClosingIntake, ClosingOpened, ClosingParts, HandshakeFlow, Opened,
	OpeningIntake, OpeningParts, ProofRequest, ReplyBinding, ReplyIntake, ReplyParts, ServerFlow,
};
use crate::transport::handshake::negotiation::{SecurityAccept, TransportAccept};
use crate::transport::handshake::peer::{LearnedTrust, PeerCertificate, PossessionProof};
use crate::transport::handshake::primitives::transcript::{HpkeHandshakeLegs, Transcript};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::schedule::{
	Agreement, BaseSecret, ClientStatic, CompressedPoint, HandshakeVerifyingKey, KeyConfirmation, PeerEphemeral,
	PeerPoint, Salt, Terms,
};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	Arc, ClientHello, ClientKeyExchange, HandshakeCurve, HandshakeMessage, HandshakeProvider, HandshakeSecret,
	HpkeSessionPayload, ServerHandshake, TunneledMessage,
};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};

/// The HPKE handshake protocol.
///
/// A client is provisioned with [`HpkeClientSettings`], and a server with
/// [`HpkeServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hpke;

impl sealed::Sealed for Hpke {}

impl HandshakeFlow for Hpke {
	/// The signature bytes, as the provider encodes them. An HPKE message
	/// names its signer by the certificate beside it.
	type Signed = Vec<u8>;

	fn sign<'a>(
		key: &'a dyn SigningKeyProvider,
		prehash: &'a [u8],
	) -> MaybeSendFuture<'a, Result<Self::Signed, HandshakeError>> {
		Box::pin(async move {
			let signature = key.sign_prehash(prehash).await?;
			Ok(signature)
		})
	}
}

/// What an HPKE client is provisioned with.
pub struct HpkeClientSettings<P: HandshakeProvider> {
	/// The trust that admits the certificate the reply names.
	pub trust: LearnedTrust,
	/// The domain tag the closing payload is sealed under. Both endpoints
	/// MUST hold the same tag for a session to complete.
	pub aad_domain_tag: &'static [u8],
	/// The identity the client presents for mutual authentication.
	pub identity: Option<ClientIdentity<P>>,
}

impl<P: HandshakeProvider> HpkeClientSettings<P> {
	/// Settings for an anonymous client under [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(trust: LearnedTrust) -> Self {
		Self { trust, aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG, identity: None }
	}
}

/// What an HPKE client keeps from its hello to read the reply against.
pub struct HpkeOpening {
	/// The DER of the sent `ClientHello`. The transcript binds these bytes, so
	/// a rewritten offer changes the transcript hash (CWE-757).
	hello_der: Vec<u8>,
	/// The client random the hello carried.
	client_random: [u8; 32],
}

/// A decoded `ServerHandshake`, kept for verification and for the closing.
pub struct HpkeReply {
	/// The server signature over the transcript hash.
	signature: OctetString,
	/// The client random, which the closing payload echoes.
	client_random: [u8; 32],
}

/// The client half of an HPKE agreement, kept to seal the closing.
pub struct HpkeAgreed {
	/// The base secret the closing carries to the server.
	base: BaseSecret,
	/// The public half of the client ephemeral `r`, which the closing carries
	/// to the server. The private half is wiped at the agreement.
	client_ephemeral: [u8; EC_PUBKEY_COMPRESSED_SIZE],
}

/// A `ClientKeyExchange` that awaits its possession signature.
pub struct HpkeClosingDraft {
	/// The payload, sealed to the server's static key.
	encrypted_data: Vec<u8>,
	/// The certificate the client presents, when it holds an identity.
	certificate: Option<Certificate>,
}

impl<P: HandshakeProvider> ClientFlow<P> for Hpke {
	type Settings = HpkeClientSettings<P>;
	type Trust = LearnedTrust;
	type Opening = HpkeOpening;
	type Pending = ();
	type Reply = HpkeReply;
	type Agreed = Box<HpkeAgreed>;
	type Draft = HpkeClosingDraft;

	fn identity(settings: &Self::Settings) -> Option<&ClientIdentity<P>> {
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
		let client_random = generate_nonce::<32>(Some(rng))?;
		let hello = ClientHello {
			client_random: OctetString::new(client_random)?,
			security_offer: parts.security_offer.cloned(),
			transport_offer: parts.transport_offer.cloned(),
		};

		// The hello travels inside an opaque SignedData that carries no
		// signer, and the transcript binds the DER that container holds.
		let tunnel = SignedData::try_from(&hello)?;
		let hello_der = tunnel.tunneled_der()?.to_vec();

		let message = HandshakeMessage::try_from(tunnel)?;
		let opening = HpkeOpening { hello_der, client_random };
		Ok(Opened { message, opening, pending: () })
	}

	fn read_reply(
		opening: Self::Opening,
		_settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError> {
		let HpkeOpening { hello_der, client_random } = opening;

		// 1. Take the tunnel, refuse one that carries an abort alert, and
		//    decode the ServerHandshake from the bytes it arrived as.
		let tunnel = reply.signed()?;
		tunnel.value().refuse_alert()?;

		let ServerHandshake {
			certificate,
			server_random,
			server_ephemeral,
			signature,
			security_accept,
			client_cert_required,
			transport_accept,
			session_receipt,
		} = ServerHandshake::try_from(tunnel.value())?;

		// 2. Bind every leg into the transcript as the bytes that arrived, so a
		//    tampered leg changes the hash and fails the signature. The server
		//    ephemeral enters at its fixed width, so another length fails here.
		let server_random = server_random.to_32_byte_array()?;
		let legs = HpkeHandshakeLegs {
			client_hello: &hello_der,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?,
			server_public_key: certificate.verifying_key_bytes(),
			security_accept_der: security_accept.as_ref().map(WireDer::der).unwrap_or_default(),
			client_cert_required,
			transport_accept_der: transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};
		let mut transcript = Transcript::hpke_handshake(legs);
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 3. Return the facts of the reply.
		let salt = Salt::randoms(&client_random, &server_random);
		let security_accept = security_accept.as_ref().map(WireDer::value).cloned();
		let transport_accept = transport_accept.as_ref().map(WireDer::value).cloned();
		let server_ephemeral = server_ephemeral.into_bytes();
		let reply = HpkeReply { signature, client_random };
		Ok(ReplyIntake {
			server: certificate,
			security_accept,
			transport_accept,
			server_ephemeral,
			receipt: session_receipt,
			client_cert_required,
			transcript_hash,
			salt,
			reply,
		})
	}

	fn verify_reply(
		reply: &Self::Reply,
		key: P::VerifyingKey,
		transcript_hash: &[u8; 32],
	) -> Result<(), HandshakeError> {
		let signature = P::Signature::try_from(reply.signature.as_bytes()).map_err(Into::into)?;
		signature.verify_prehash(&key, transcript_hash)?;
		Ok(())
	}

	fn agree(
		_pending: (),
		server_ephemeral: &PeerPoint<P::Curve>,
		salt: KdfSalt<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(HandshakeSecret, Self::Agreed), HandshakeError> {
		let base = BaseSecret::random(Some(&mut *rng))?;
		let ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let agreement = Agreement::<P>::new(&base, server_ephemeral);
		let secret = agreement.settle(&ephemeral, salt)?;
		let client_ephemeral = ephemeral.public_key().compressed_point()?;

		// The ephemeral served its one agreement, so it is wiped where this
		// function returns. The base secret is boxed, so the move into the
		// closing copies a pointer and it is wiped where the box drops.
		Ok((secret, Box::new(HpkeAgreed { base, client_ephemeral })))
	}

	fn bind_closing<'a>(
		agreed: Self::Agreed,
		reply: Self::Reply,
		settings: &'a Self::Settings,
		parts: ClosingParts<'_, P::Curve>,
	) -> Result<ClosingBinding<'a, Self, P>, HandshakeError> {
		// The base secret is read in place, so it is wiped where the box drops.
		let HpkeAgreed { base, client_ephemeral } = agreed.as_ref();
		let ClosingParts { server, transcript_hash, sealed_ack, confirmation } = parts;

		// 1. Encode the payload. The DER buffer holds the base secret, so it
		//    wipes when dropped, along with the transient OCTET STRING copy.
		let payload = HpkeSessionPayload {
			base_key: OctetString::new(base.as_bytes())?,
			client_random: OctetString::new(reply.client_random.as_slice())?,
			client_ephemeral: OctetString::new(client_ephemeral.as_slice())?,
			key_confirmation: confirmation,
			receipt_ack: sealed_ack.map(OctetString::new).transpose()?,
		};
		let plaintext = Zeroizing::new(payload.to_der()?);
		payload.base_key.into_bytes().zeroize();

		// 2. Seal the payload to the server's static key. The associated data
		//    binds it to the certificate this client presents, so it opens
		//    only under that certificate.
		let identity = settings.identity.as_ref();
		let certificate = identity.map(ClientIdentity::certificate);
		let aad = ClientKeyExchange::client_bound_aad(settings.aad_domain_tag, certificate)?;
		let static_key = server.key();
		let sealed = static_key.seal::<P::HpkeSuite>(TIGHTBEAM_HPKE_HANDSHAKE_INFO, &aad, &plaintext, None)?;
		let encrypted_data = sealed.to_bytes();

		// 3. Name the bytes the identity signs. The digest covers the
		//    transcript hash, the sealed payload, and the certificate, so the
		//    signature binds to this key exchange and this identity alone.
		let proof = match identity {
			Some(identity) => {
				let certificate_der = identity.certificate().to_der()?;
				let mut signed = Transcript::hpke_client_auth(transcript_hash, &encrypted_data, &certificate_der);
				let prehash = signed.seal::<P::Digest>()?.to_vec();
				Some(ProofRequest { prehash, signer: identity.signing_provider() })
			}
			None => None,
		};
		let draft = HpkeClosingDraft { encrypted_data, certificate: certificate.cloned() };
		Ok(ClosingBinding { proof, draft })
	}

	fn encode_closing(draft: Self::Draft, proof: Option<Vec<u8>>) -> Result<HandshakeMessage, HandshakeError> {
		let HpkeClosingDraft { encrypted_data, certificate } = draft;
		let signature = proof.map(OctetString::new).transpose()?;
		let key_exchange = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_data)?,
			client_certificate: certificate,
			client_signature: signature,
		};

		let carrier = EnvelopedData::try_from(&key_exchange)?;
		HandshakeMessage::try_from(carrier)
	}
}

/// What an HPKE server is provisioned with.
pub struct HpkeServerSettings {
	/// The certificate the server presents in its reply.
	pub certificate: Arc<Certificate>,
	/// The domain tag the closing payload is sealed under. Both endpoints
	/// MUST hold the same tag for a session to complete.
	pub aad_domain_tag: &'static [u8],
}

impl HpkeServerSettings {
	/// Settings for a server that presents `certificate` under
	/// [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(certificate: impl Into<Arc<Certificate>>) -> Self {
		Self { certificate: certificate.into(), aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG }
	}
}

/// What an HPKE server keeps of the hello to bind the reply over.
pub struct HpkeHello {
	/// The DER of the received `ClientHello`, as the transcript binds it.
	hello_der: Vec<u8>,
	/// The client random the hello carried.
	client_random: [u8; 32],
}

/// A `ServerHandshake` that awaits its signature and its receipt.
pub struct HpkeReplyDraft {
	server_random: [u8; 32],
	server_ephemeral: [u8; EC_PUBKEY_COMPRESSED_SIZE],
	security_accept: WireDer<SecurityAccept>,
	transport_accept: Option<WireDer<TransportAccept>>,
	certificate: Certificate,
	client_cert_required: bool,
}

/// What an HPKE server holds from its reply to the key exchange.
pub struct HpkeServerPending<C: HandshakeCurve> {
	/// The server ephemeral `e`, which serves one agreement. It is boxed, so
	/// a move of the pending state copies a pointer.
	ephemeral: Box<EphemeralSecret<C>>,
	/// The client random the key exchange must echo.
	client_random: [u8; 32],
}

/// A decoded key exchange that awaits the static open.
pub struct HpkeClosing<S: HpkeSuite> {
	/// The HPKE message, whose encapsulated key the parse validated.
	message: HpkeMessage<S>,
	/// The server's static key, which the message was sealed to.
	recipient: PublicKey<S::Curve>,
	/// The associated data the payload was sealed under.
	aad: Vec<u8>,
	/// The static key of the certificate the client offers, which the client
	/// ephemeral must differ from.
	client_static: ClientStatic<S::Curve>,
}

/// The proof of an HPKE key exchange that the key of the offered
/// certificate signed it.
///
/// The signed digest covers the transcript hash, the encrypted payload, and
/// the offered certificate, so the signature binds to one exchange and one
/// identity.
pub struct HpkePossession {
	signature: Vec<u8>,
	encrypted_data: Vec<u8>,
	certificate_der: Vec<u8>,
}

impl<P: HandshakeProvider> PossessionProof<P> for HpkePossession {
	fn verify(self, key: P::VerifyingKey, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let transcript_hash = terms.transcript_hash();
		let mut signed = Transcript::hpke_client_auth(transcript_hash, &self.encrypted_data, &self.certificate_der);
		let digest = signed.seal::<P::Digest>()?;

		let parsed = P::Signature::try_from(self.signature.as_slice());
		let signature = parsed.map_err(|_| HandshakeError::SignatureVerificationFailed)?;
		signature.verify_prehash(&key, digest)?;
		Ok(())
	}
}

/// The parts of the decrypted key-exchange payload.
struct SessionPayload<C: HandshakeCurve> {
	/// The base secret the client drew.
	base: BaseSecret,
	/// The client random the payload echoes against replay.
	client_random: [u8; 32],
	/// The client ephemeral, admitted as a point of the curve that differs
	/// from the client's static key.
	client_ephemeral: PeerPoint<C>,
	/// The key-confirmation tag of the client.
	confirmation: KeyConfirmation,
	/// The client receipt `SignerInfo`, sealed under the handshake secret.
	/// Its signed attributes bind the bearer settlement answer, so it opens
	/// only after the ephemeral-ephemeral agreement.
	receipt_ack: Option<OctetString>,
}

impl<C: HandshakeCurve> SessionPayload<C> {
	/// Parse the decrypted DER [`HpkeSessionPayload`], and enforce the fixed
	/// 32-byte geometry of the base secret. A payload with no key-confirmation
	/// tag, or with one of another width, fails to decode.
	///
	/// The client ephemeral is admitted through [`PeerEphemeral`] as a point of
	/// the curve that differs from `client_static`.
	fn parse(decrypted: &[u8], client_static: &ClientStatic<C>) -> Result<Self, HandshakeError> {
		let payload = HpkeSessionPayload::from_der(decrypted);
		let payload = payload.map_err(|_| HandshakeError::InvalidDecryptedPayloadSize)?;
		let HpkeSessionPayload { base_key, client_random, client_ephemeral, key_confirmation, receipt_ack } = payload;

		// The decoded buffer moves into its wiping wrapper without a copy, and
		// the parse copies it into the fixed-width secret, so no plain array of
		// key material exists on the way (CWE-226).
		let base = BaseSecret::try_from(SecretSlice::from(base_key.into_bytes()))?;
		let client_random = client_random.to_32_byte_array()?;
		let point = client_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let client_ephemeral = client_static.client_ephemeral(&point)?;
		Ok(Self {
			base,
			client_random,
			client_ephemeral,
			confirmation: key_confirmation,
			receipt_ack,
		})
	}
}

impl<P: HandshakeProvider> ServerFlow<P> for Hpke {
	type Settings = HpkeServerSettings;
	type Sealed = HpkeHello;
	type Opened = HpkeHello;
	type Draft = HpkeReplyDraft;
	type Pending = HpkeServerPending<P::Curve>;
	type Closing = HpkeClosing<P::HpkeSuite>;
	type Proof = HpkePossession;

	fn read_opening(
		_settings: &Self::Settings,
		opening: HandshakeMessage,
	) -> Result<OpeningIntake<Self, P>, HandshakeError> {
		// A tunnel that carries an abort alert is refused. The hello is read
		// from the bytes it arrived as, and the transcript binds those bytes.
		let tunnel = opening.signed()?;
		tunnel.value().refuse_alert()?;

		let hello_der = tunnel.value().tunneled_der()?.to_vec();
		let ClientHello { client_random, security_offer, transport_offer } = ClientHello::try_from(tunnel.value())?;
		let client_random = client_random.to_32_byte_array()?;
		let sealed = HpkeHello { hello_der, client_random };

		Ok(OpeningIntake { security_offer, transport_offer, sealed })
	}

	fn open_opening<'a>(
		sealed: Self::Sealed,
		_key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<Self::Opened, HandshakeError>> {
		// The hello seals nothing: the base secret arrives on the closing.
		Box::pin(async move { Ok(sealed) })
	}

	fn bind_reply(
		opened: &mut Self::Opened,
		settings: &Self::Settings,
		parts: ReplyParts<'_, P>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<ReplyBinding<Self, P>, HandshakeError> {
		let ReplyParts { profile, transport_accept, server_ephemeral, client_cert_required } = parts;
		let server_random = generate_nonce::<32>(Some(rng))?;
		let server_ephemeral = server_ephemeral.compressed_point()?;
		let security_accept = WireDer::new(SecurityAccept::new(profile.descriptor()))?;
		let transport_accept = transport_accept.copied().map(WireDer::new).transpose()?;

		// The transcript binds every leg as the bytes the client receives, so
		// tampering with one invalidates the signature.
		let legs = HpkeHandshakeLegs {
			client_hello: &opened.hello_der,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral,
			server_public_key: settings.certificate.verifying_key_bytes(),
			security_accept_der: security_accept.der(),
			client_cert_required,
			transport_accept_der: transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};

		let mut transcript = Transcript::hpke_handshake(legs);
		let transcript_hash = transcript.seal::<P::Digest>()?;

		let salt = Salt::randoms(&opened.client_random, &server_random);
		let draft = HpkeReplyDraft {
			server_random,
			server_ephemeral,
			security_accept,
			transport_accept,
			certificate: Certificate::clone(&settings.certificate),
			client_cert_required,
		};
		Ok(ReplyBinding { transcript_hash, salt, prehash: transcript_hash.to_vec(), draft })
	}

	fn encode_reply(
		draft: Self::Draft,
		signature: Vec<u8>,
		artifact: Option<&SignedData>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let HpkeReplyDraft {
			server_random,
			server_ephemeral,
			security_accept,
			transport_accept,
			certificate,
			client_cert_required,
		} = draft;

		// The artifact has two owners by design: this copy is encoded into
		// the message, and the issued receipt absorbs the client SignerInfo
		// at settlement.
		let handshake = ServerHandshake {
			certificate,
			server_random: OctetString::new(server_random)?,
			server_ephemeral: OctetString::new(server_ephemeral)?,
			signature: OctetString::new(signature)?,
			security_accept: Some(security_accept),
			client_cert_required,
			transport_accept,
			session_receipt: artifact.cloned(),
		};

		let tunnel = SignedData::try_from(&handshake)?;
		HandshakeMessage::try_from(tunnel)
	}

	fn pend(
		opened: Self::Opened,
		ephemeral: Box<EphemeralSecret<P::Curve>>,
		_terms: &Terms<P>,
	) -> Result<Self::Pending, HandshakeError> {
		Ok(HpkeServerPending { ephemeral, client_random: opened.client_random })
	}

	fn read_closing(
		_pending: &Self::Pending,
		settings: &Self::Settings,
		closing: HandshakeMessage,
	) -> Result<ClosingIntake<Self, P>, HandshakeError> {
		// 1. Take the carrier, and refuse one that carries an abort alert.
		let carrier = closing.enveloped()?;
		if let Some(attrs) = carrier.value().unprotected_attrs.as_ref() {
			attrs.refuse_alert()?;
		}

		// 2. Decode the key exchange. The parse validates the encapsulated key
		//    and the ciphertext length, so the static ECDH runs on a point of
		//    the curve and on a message that carries a tag.
		let key_exchange = ClientKeyExchange::try_from(carrier.value())?;
		let ClientKeyExchange { encrypted_data, client_certificate, client_signature } = key_exchange;
		let message = HpkeMessage::<P::HpkeSuite>::from_bytes(encrypted_data.as_bytes())?;
		let recipient = settings.certificate.verifying_key::<P::Curve>()?;

		// 3. Parse the offered identity once, and refuse an encapsulated key
		//    that collapses into its static key. The encapsulated key is a
		//    client ephemeral as well: a client that seals under its static key
		//    leaves the payload to the secrecy of that key.
		let parsed = client_certificate.map(PeerCertificate::<P::Curve>::parse);
		let identity = parsed.transpose()?;
		let client_static = ClientStatic::of(identity.as_ref());
		client_static.client_ephemeral_point(*message.encapsulated_key())?;

		// 4. Build the associated data and the possession proof over the
		//    offered certificate. A signature with no certificate binds no
		//    certificate bytes, and admission refuses it unverified.
		let offered = identity.as_ref().map(|identity| identity.certificate().as_ref());
		let aad = ClientKeyExchange::client_bound_aad(settings.aad_domain_tag, offered)?;
		let certificate_der = offered.map(Encode::to_der).transpose()?.unwrap_or_default();
		let proof = client_signature.map(|signature| HpkePossession {
			signature: signature.into_bytes(),
			encrypted_data: encrypted_data.into_bytes(),
			certificate_der,
		});

		let closing = HpkeClosing { message, recipient, aad, client_static };
		Ok(ClosingIntake { offered: identity, proof, closing })
	}

	fn settle<'a>(
		pending: Self::Pending,
		closing: Self::Closing,
		terms: &'a Terms<P>,
		key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<ClosingOpened, HandshakeError>> {
		Box::pin(async move {
			let HpkeServerPending { ephemeral, client_random } = pending;
			let HpkeClosing { message, recipient, aad, client_static } = closing;

			// 1. Open the payload under the associated data. The key provider
			//    runs the static ECDH step on the encapsulated key the parse
			//    validated.
			let enc = message.encapsulated_key().to_encoded_point(false);
			let agreed = key.key_agreement(enc.as_bytes()).await?;
			let shared_secret = EcdhSecret::try_from(agreed)?;
			let plaintext = shared_secret.open(&recipient, &message, TIGHTBEAM_HPKE_HANDSHAKE_INFO, &aad)?;
			let payload = plaintext.with(|payload| SessionPayload::<P::Curve>::parse(payload, &client_static))?;
			let SessionPayload { base, client_random: echoed, client_ephemeral, confirmation, receipt_ack } = payload;

			// 2. Verify that the payload echoes the client random of the hello, which prevents replay.
			let is_echo: bool = echoed.ct_eq(&client_random).into();
			if !is_echo {
				return Err(HandshakeError::ClientRandomMismatchReplay);
			}

			// 3. Run the ephemeral-ephemeral agreement with the client
			//    ephemeral the payload carried, and derive the handshake
			//    secret. The server ephemeral serves this one exchange and
			//    drops when this step returns.
			let agreement = Agreement::<P>::new(&base, &client_ephemeral);
			let secret = agreement.settle(ephemeral.as_ref(), terms.kdf_salt())?;

			let receipt_ack = receipt_ack.map(OctetString::into_bytes);
			Ok(ClosingOpened { secret, receipt_ack, confirmation })
		})
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::{SignerIdentifier, SignerInfo, SignerInfos};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::hpke::HpkeError::DecryptionFailed;
	use crate::crypto::hpke::HpkeSecp256k1Sha3Aes256Gcm;
	use crate::crypto::profiles::SecurityProfileDesc;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
	use crate::crypto::sign::PrehashSigner;
	use crate::crypto::x509::policy::ExpiryValidator;
	use crate::crypto::x509::utils::Skid;
	use crate::der::{Any, Sequence};
	use crate::oids::{HANDSHAKE_ABORT_ALERT, HASH_SHA3_256, HASH_SHA3_384, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::random::OsRng;
	use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
	use crate::transport::handshake::attributes::HandshakeAttribute;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportOffer};
	use crate::transport::handshake::schedule::CompressedPoint;
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication};
	use crate::x509::attr::{Attribute, Attributes};

	/// The configuration of an anonymous client that trusts `server`.
	fn anonymous_client(server: &TestCertificate) -> TestClientConfig<Hpke> {
		let mut config = Hpke::client(&server.certificate, &create_test_certificate());
		config.flow.identity = None;
		config
	}

	/// An anonymous client that trusts `server` and has sent its hello under
	/// `offer`, with the DER of that hello.
	fn client_after_hello(server: &TestCertificate, offer: Option<SecurityOffer>) -> (TestClient<Hpke>, Vec<u8>) {
		let mut config = anonymous_client(server);
		config.security_offer = offer;

		let mut client = Handshake::client(config);
		let opening = client.start().expect("a fresh client builds its hello");
		(client, tunneled_hello(&opening))
	}

	/// A `ServerHandshake` signed by `server` over the transcript of
	/// `client_hello`, that accepts `profile` and carries a fresh server
	/// ephemeral.
	fn signed_server_response(
		server: &TestCertificate,
		client_hello: &[u8],
		profile: SecurityProfileDesc,
	) -> ServerHandshake {
		signed_server_response_with_ephemeral(server, client_hello, Some(profile), &create_test_server_ephemeral())
	}

	/// A `ServerHandshake` signed by `server` over the transcript of
	/// `client_hello`, that carries `server_ephemeral` inside its signed
	/// transcript and accepts `profile`, when one is given.
	fn signed_server_response_with_ephemeral(
		server: &TestCertificate,
		client_hello: &[u8],
		profile: Option<SecurityProfileDesc>,
		server_ephemeral: &[u8; EC_PUBKEY_COMPRESSED_SIZE],
	) -> ServerHandshake {
		let server_random = [2u8; 32];
		let accept = profile.map(|profile| WireDer::new(SecurityAccept::new(profile)).expect("an accept encodes"));
		let accept_der = accept.as_ref().map(WireDer::der).unwrap_or_default();
		let legs = HpkeHandshakeLegs {
			client_hello,
			server_random: &server_random,
			server_ephemeral,
			server_public_key: server.certificate.verifying_key_bytes(),
			security_accept_der: accept_der,
			client_cert_required: false,
			transport_accept_der: &[],
		};

		let mut transcript = Transcript::hpke_handshake(legs);
		let transcript_hash = transcript.seal::<Sha3_256>().expect("the transcript seals");
		let signed = server.signing_key.sign_prehash(&transcript_hash);
		let signature: Secp256k1Signature = signed.expect("the test key signs");

		ServerHandshake {
			certificate: server.certificate.to_owned(),
			server_random: OctetString::new(server_random).expect("a random is an OCTET STRING"),
			server_ephemeral: OctetString::new(*server_ephemeral).expect("a point is an OCTET STRING"),
			signature: OctetString::new(signature.to_bytes().to_vec()).expect("a signature is an OCTET STRING"),
			security_accept: accept,
			client_cert_required: false,
			transport_accept: None,
			session_receipt: None,
		}
	}

	/// `response` with its server ephemeral replaced by `server_ephemeral`
	/// and nothing else changed, as an on-path party would rewrite it.
	fn with_swapped_ephemeral(mut response: ServerHandshake, server_ephemeral: impl AsRef<[u8]>) -> ServerHandshake {
		let swapped = OctetString::new(server_ephemeral.as_ref()).expect("a point is an OCTET STRING");
		response.server_ephemeral = swapped;
		response
	}

	/// `tunnel` with one signer added, whose unsigned attribute is an abort
	/// alert of `code`.
	///
	/// An HPKE tunnel is sent with no signer. A `SignedData` still has room
	/// for one, and that is where a peer that aborts would put its alert.
	fn with_abort_alert(tunnel: HandshakeMessage, code: u8) -> HandshakeMessage {
		let tunnel = tunnel.signed().expect("an HPKE tunnel is a SignedData");
		let code = Any::encode_from(&code).expect("an alert code encodes");
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, code).expect("one value is an attribute");
		let alert = Attribute::try_from(alert).expect("the alert encodes");

		let signer = create_test_certificate();
		let signer_der = signer.signing_key.verifying_key().to_public_key_der().expect("a key encodes");
		let sid = SignerIdentifier::try_from(Skid::of_public_key(signer_der)).expect("a key has an identifier");
		let aborting = SignerInfo {
			version: CmsVersion::V1,
			sid,
			digest_alg: AlgorithmIdentifierOwned { oid: HASH_SHA3_256, parameters: None },
			signed_attrs: None,
			signature_algorithm: AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_256, parameters: None },
			signature: OctetString::new([0x30u8; 64]).expect("a signature is an OCTET STRING"),
			unsigned_attrs: Some(Attributes::try_from(vec![alert]).expect("one attribute is a SET")),
		};

		let mut alerted = tunnel.value().to_owned();
		alerted.signer_infos = SignerInfos::try_from(vec![aborting]).expect("one signer is a SET");
		HandshakeMessage::try_from(alerted).expect("the tunnel encodes")
	}

	/// The client random that each hand-built hello of this module carries.
	const CLIENT_RANDOM: [u8; 32] = [7u8; 32];

	/// A server that holds `identity` under `peer_authentication` and has
	/// replied to a hand-built hello that carries [`CLIENT_RANDOM`], with what
	/// a key exchange for it confirms.
	async fn server_after_hello(
		identity: &TestCertificate,
		peer_authentication: PeerAuthentication,
	) -> (TestServer<Hpke>, Confirming) {
		let mut config = Hpke::server(identity);
		config.peer_authentication = peer_authentication;

		let mut server = Handshake::server(config);
		let hello_der = create_test_client_hello(&CLIENT_RANDOM).expect("a hello encodes");
		let hello = ClientHello::from_der(&hello_der).expect("the hello decodes");
		let opening = tunneled_opening(&hello);

		let reply = server.reply(opening).await.expect("the server admits the hello");
		let reply = tunneled_handshake(&reply);
		let server_ephemeral = PublicKey::<Secp256k1>::from_sec1_bytes(reply.server_ephemeral.as_bytes());
		let confirming = Confirming {
			server_ephemeral: server_ephemeral.expect("the reply carries a point on the curve"),
			salt: [CLIENT_RANDOM.as_slice(), reply.server_random.as_bytes()].concat(),
			transcript_hash: server.transcript_hash().expect("the reply sealed the transcript"),
		};
		(server, confirming)
	}

	/// A client that offers no certificate, as the payload parse takes it.
	fn anonymous() -> ClientStatic<Secp256k1> {
		ClientStatic::of(None)
	}

	/// The DER of an `HpkeSessionPayload` that carries `base_key`,
	/// `client_random`, `client_ephemeral`, and `receipt_ack` at the widths
	/// they come in, beside `confirmation`.
	fn session_payload_der(
		base_key: impl AsRef<[u8]>,
		client_random: impl AsRef<[u8]>,
		client_ephemeral: impl AsRef<[u8]>,
		confirmation: &KeyConfirmation,
		receipt_ack: Option<&[u8]>,
	) -> Vec<u8> {
		let octets = |bytes: &[u8]| OctetString::new(bytes).expect("bytes are an OCTET STRING");
		let payload = HpkeSessionPayload {
			base_key: octets(base_key.as_ref()),
			client_random: octets(client_random.as_ref()),
			client_ephemeral: octets(client_ephemeral.as_ref()),
			key_confirmation: confirmation.to_owned(),
			receipt_ack: receipt_ack.map(octets),
		};
		payload.to_der().expect("the payload encodes")
	}

	/// The payload as an encoder with no rule for the key-confirmation tag
	/// writes it: the tag is absent, or it has any width.
	#[derive(Sequence)]
	struct LoosePayload {
		base_key: OctetString,
		client_random: OctetString,
		client_ephemeral: OctetString,
		#[asn1(optional = "true")]
		key_confirmation: Option<OctetString>,
	}

	/// The DER of a payload that carries a well-formed base secret, client
	/// random, and client ephemeral beside `key_confirmation`.
	fn loose_payload_der(key_confirmation: Option<&[u8]>) -> Vec<u8> {
		let octets = |bytes: &[u8]| OctetString::new(bytes).expect("bytes are an OCTET STRING");
		let payload = LoosePayload {
			base_key: octets(&[3u8; 32]),
			client_random: octets(&[5u8; 32]),
			client_ephemeral: octets(&create_test_server_ephemeral()),
			key_confirmation: key_confirmation.map(octets),
		};
		payload.to_der().expect("the payload encodes")
	}

	/// The bytes of an HPKE message that seals a payload to the static key of
	/// `server` under the associated data `aad`, as an honest client builds it.
	///
	/// The payload carries a fresh base secret, `client_random`, a fresh
	/// client ephemeral, and `receipt_ack`. Its key-confirmation tag is the
	/// one `confirming` yields for that base secret and that ephemeral.
	fn sealed_payload(
		server: &TestCertificate,
		confirming: &Confirming,
		client_random: &[u8; 32],
		receipt_ack: Option<&[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Vec<u8> {
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		sealed_payload_from(&ephemeral, server, confirming, client_random, receipt_ack, aad)
	}

	/// The payload of [`sealed_payload`] under the client ephemeral
	/// `ephemeral`, for a fixture that chooses that key.
	fn sealed_payload_from(
		ephemeral: &SecretKey<Secp256k1>,
		server: &TestCertificate,
		confirming: &Confirming,
		client_random: &[u8; 32],
		receipt_ack: Option<&[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Vec<u8> {
		let static_key = PublicKey::<Secp256k1>::from_sec1_bytes(server.certificate.verifying_key_bytes());
		let static_key = static_key.expect("the test certificate carries a point on the curve");
		let base = BaseSecret::random(None).expect("the random source draws a base secret");
		let confirmation = confirming.tag(&base, ephemeral);
		let client_ephemeral = ephemeral.public_key().compressed_point().expect("a point compresses");
		let base_key = base.as_bytes();
		let plaintext = session_payload_der(base_key, client_random, client_ephemeral, &confirmation, receipt_ack);

		let sealed = static_key.seal::<HpkeSecp256k1Sha3Aes256Gcm>(TIGHTBEAM_HPKE_HANDSHAKE_INFO, aad, plaintext, None);
		sealed.expect("the payload seals").to_bytes()
	}

	/// A `ClientKeyExchange` that carries `encrypted_data` and offers no
	/// identity.
	fn anonymous_key_exchange(encrypted_data: impl AsRef<[u8]>) -> ClientKeyExchange {
		let encrypted_data = OctetString::new(encrypted_data.as_ref()).expect("sealed bytes are an OCTET STRING");
		ClientKeyExchange { encrypted_data, client_certificate: None, client_signature: None }
	}

	/// A hand-built `ClientKeyExchange` that offers no identity, for the
	/// server that holds `server` and sent what `confirming` holds.
	///
	/// The payload echoes `client_random` and carries `receipt_ack`, and it is
	/// sealed under [`TIGHTBEAM_AAD_DOMAIN_TAG`] alone.
	fn build_test_client_key_exchange(
		server: &TestCertificate,
		confirming: &Confirming,
		client_random: &[u8; 32],
		receipt_ack: Option<&[u8]>,
	) -> ClientKeyExchange {
		let sealed = sealed_payload(server, confirming, client_random, receipt_ack, TIGHTBEAM_AAD_DOMAIN_TAG);
		anonymous_key_exchange(sealed)
	}

	/// The digest the identity behind `certificate` signs as its possession
	/// proof over `encrypted_data` in the handshake of `transcript_hash`.
	fn possession_digest(
		transcript_hash: &[u8; 32],
		encrypted_data: impl AsRef<[u8]>,
		certificate: &Certificate,
	) -> [u8; 32] {
		let certificate_der = certificate.to_der().expect("the test certificate encodes");
		let mut signed = Transcript::hpke_client_auth(transcript_hash, encrypted_data, certificate_der);
		signed.seal::<Sha3_256>().expect("the possession transcript seals")
	}

	/// The signature of `signer` over `digest`, as a key exchange carries a
	/// possession proof.
	fn possession_signature(signer: &TestCertificate, digest: &[u8; 32]) -> OctetString {
		let signature: Secp256k1Signature = signer.signing_key.sign_prehash(digest).expect("the test key signs");
		OctetString::new(signature.to_bytes().to_vec()).expect("a signature is an OCTET STRING")
	}

	/// A hand-built `ClientKeyExchange` that offers the identity of `client`,
	/// for the server that holds `server` and sent what `confirming` holds.
	///
	/// The payload echoes `client_random`, it is sealed under the associated
	/// data that binds the certificate of `client`, and `client` signs the
	/// [`possession_digest`] of the sealed payload.
	fn build_identified_client_key_exchange(
		server: &TestCertificate,
		confirming: &Confirming,
		client_random: &[u8; 32],
		client: &TestCertificate,
	) -> ClientKeyExchange {
		let ephemeral = SecretKey::<Secp256k1>::random(&mut OsRng);
		build_identified_client_key_exchange_from(&ephemeral, server, confirming, client_random, client)
	}

	/// The key exchange of [`build_identified_client_key_exchange`] under the
	/// client ephemeral `ephemeral`.
	fn build_identified_client_key_exchange_from(
		ephemeral: &SecretKey<Secp256k1>,
		server: &TestCertificate,
		confirming: &Confirming,
		client_random: &[u8; 32],
		client: &TestCertificate,
	) -> ClientKeyExchange {
		let aad = ClientKeyExchange::client_bound_aad(TIGHTBEAM_AAD_DOMAIN_TAG, Some(&client.certificate));
		let aad = aad.expect("the test certificate encodes");
		let sealed = sealed_payload_from(ephemeral, server, confirming, client_random, None, aad);
		let digest = possession_digest(&confirming.transcript_hash, &sealed, &client.certificate);

		ClientKeyExchange {
			encrypted_data: OctetString::new(sealed).expect("a sealed payload is an OCTET STRING"),
			client_certificate: Some(client.certificate.to_owned()),
			client_signature: Some(possession_signature(client, &digest)),
		}
	}

	/// A server that has replied to a hand-built hello, with a hand-built key
	/// exchange that offers an identity to it.
	struct Identified {
		/// The server, with its reply sent.
		server: TestServer<Hpke>,
		/// The identity the key exchange offers.
		client: TestCertificate,
		/// The key exchange, with the possession proof of `client`.
		key_exchange: ClientKeyExchange,
	}

	/// A server under `peer_authentication` that has replied to a hand-built
	/// hello, with the key exchange of a fresh identity for it.
	async fn identified(peer_authentication: PeerAuthentication) -> Identified {
		let identity = create_test_certificate();
		let (server, confirming) = server_after_hello(&identity, peer_authentication).await;
		let client = create_test_certificate();
		let key_exchange = build_identified_client_key_exchange(&identity, &confirming, &CLIENT_RANDOM, &client);

		Identified { server, client, key_exchange }
	}

	/// A reply signed over the hello the client sent is admitted, and the
	/// closing carries the payload sealed to the server.
	#[tokio::test]
	async fn a_signed_server_handshake_is_answered_with_a_key_exchange() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, hello) = client_after_hello(&server, None);
		let signed = signed_server_response(&server, &hello, create_default_test_profile());
		let closing = client.respond(tunneled_reply(&signed)).await?;

		let key_exchange = carried_key_exchange(&closing);
		assert!(!key_exchange.encrypted_data.as_bytes().is_empty());
		assert!(key_exchange.client_certificate.is_none());
		assert!(key_exchange.client_signature.is_none());
		Ok(())
	}

	/// A server ephemeral swapped for another valid point after a real server
	/// signed its reply changes the transcript, so the signature fails before
	/// any agreement.
	#[tokio::test]
	async fn a_tampered_server_ephemeral_fails_the_hpke_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Hpke::server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));

		let signed = server.reply(client.start()?).await?;
		let tampered = with_swapped_ephemeral(tunneled_handshake(&signed), create_test_server_ephemeral());

		let result = client.respond(tunneled_reply(&tampered)).await;
		assert!(matches!(result, Err(HandshakeError::SignatureError(_))));
		Ok(())
	}

	/// A reply whose accept was stripped after the server signed it fails its
	/// signature. The client verifies the signature before it reads the
	/// selection, so the refusal names the signature and not the selection.
	#[tokio::test]
	async fn a_stripped_accept_fails_the_hpke_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Hpke::server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));

		let signed = server.reply(client.start()?).await?;
		let mut stripped = tunneled_handshake(&signed);
		stripped.security_accept = None;

		let result = client.respond(tunneled_reply(&stripped)).await;
		assert!(matches!(result, Err(HandshakeError::SignatureError(_))));
		Ok(())
	}

	/// A certificate demand flipped after the server signed its reply changes
	/// the transcript, so the signature fails. An on-path party therefore
	/// cannot talk an anonymous client past a server that demands an identity.
	#[tokio::test]
	async fn a_flipped_certificate_demand_fails_the_hpke_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = Hpke::server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);

		let mut server = Handshake::server(config);
		let mut client = Handshake::client(anonymous_client(&identity));

		let signed = server.reply(client.start()?).await?;
		let mut flipped = tunneled_handshake(&signed);
		flipped.client_cert_required = false;

		let result = client.respond(tunneled_reply(&flipped)).await;
		assert!(matches!(result, Err(HandshakeError::SignatureError(_))));
		Ok(())
	}

	/// A server ephemeral of another width fails the fixed-width transcript
	/// leg before the signature check.
	#[tokio::test]
	async fn a_server_ephemeral_of_another_width_is_refused() {
		let server = create_test_certificate();
		let (mut client, hello) = client_after_hello(&server, None);
		let signed = signed_server_response(&server, &hello, create_default_test_profile());
		let narrowed = with_swapped_ephemeral(signed, [0x02u8; 32]);

		let result = client.respond(tunneled_reply(&narrowed)).await;
		assert!(matches!(result, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// A validly signed server ephemeral that names no point on the curve is
	/// refused at the parse, before any scalar multiplication.
	#[tokio::test]
	async fn an_off_curve_server_ephemeral_is_refused() {
		let server = create_test_certificate();
		let (mut client, hello) = client_after_hello(&server, None);
		let profile = Some(create_default_test_profile());
		let signed = signed_server_response_with_ephemeral(&server, &hello, profile, &off_curve_point());

		let result = client.respond(tunneled_reply(&signed)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidPublicKey(_))));
	}

	/// A validly signed server ephemeral that is the server's own static key
	/// is refused, so the agreement cannot collapse into the static one.
	#[tokio::test]
	async fn a_server_ephemeral_equal_to_the_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let (mut client, hello) = client_after_hello(&server, None);
		let static_key = PublicKey::<Secp256k1>::from(*server.signing_key.verifying_key()).compressed_point()?;
		let profile = Some(create_default_test_profile());
		let signed = signed_server_response_with_ephemeral(&server, &hello, profile, &static_key);

		let result = client.respond(tunneled_reply(&signed)).await;
		assert!(matches!(result, Err(HandshakeError::ServerEphemeralIsStatic)));
		Ok(())
	}

	/// A validly signed server handshake that selects no profile is refused.
	#[tokio::test]
	async fn a_server_handshake_without_a_security_accept_is_refused() {
		let server = create_test_certificate();
		let (mut client, hello) = client_after_hello(&server, None);
		let ephemeral = create_test_server_ephemeral();
		let unanswered = signed_server_response_with_ephemeral(&server, &hello, None, &ephemeral);

		let result = client.respond(tunneled_reply(&unanswered)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
	}

	/// A validly signed server handshake that selects a profile outside the
	/// client's offer is refused.
	#[tokio::test]
	async fn a_client_refuses_a_profile_it_did_not_offer() {
		let server = create_test_certificate();
		let foreign = SecurityProfileDesc { digest: Some(HASH_SHA3_384), ..create_default_test_profile() };
		let offer = SecurityOffer::new(vec![foreign]);
		let (mut client, hello) = client_after_hello(&server, Some(offer));
		let signed = signed_server_response(&server, &hello, create_default_test_profile());

		let result = client.respond(tunneled_reply(&signed)).await;
		assert!(matches!(result, Err(HandshakeError::InvalidProfileSelection)));
	}

	#[tokio::test]
	async fn an_anonymous_client_refuses_a_server_that_demands_an_identity() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = Hpke::server(&identity);
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
	/// so the step refuses before it draws a secret.
	#[tokio::test]
	async fn a_failed_hpke_closing_leaves_the_client_spent() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = Hpke::server(&identity);
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

	/// An anonymous dial against a server that demands no certificate captures
	/// no client identity.
	#[tokio::test]
	async fn an_anonymous_dial_captures_no_identity() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut run = run(anonymous_client(&identity), Hpke::server(&identity)).await;

		let session = run.server.complete()?;
		assert!(session.peer().is_none());
		Ok(())
	}

	/// The reply to a hand-built hello is signed under the server's static key
	/// over the transcript of that hello and the legs the reply carries. No
	/// client reads the reply, so the test holds the reply encoder to the
	/// message format alone.
	#[tokio::test]
	async fn a_hand_built_hello_is_answered_with_a_signed_server_handshake() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Hpke::server(&identity));
		let hello_der = create_test_client_hello(&CLIENT_RANDOM)?;
		let hello = ClientHello::from_der(&hello_der)?;

		let reply = server.reply(tunneled_opening(&hello)).await?;
		let handshake = tunneled_handshake(&reply);
		let random = handshake.server_random.to_32_byte_array()?;
		let ephemeral = handshake.server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let server_public_key = identity.certificate.verifying_key_bytes();
		let legs = HpkeHandshakeLegs {
			client_hello: &hello_der,
			server_random: &random,
			server_ephemeral: &ephemeral,
			server_public_key,
			security_accept_der: handshake.security_accept.as_ref().map(WireDer::der).unwrap_or_default(),
			client_cert_required: handshake.client_cert_required,
			transport_accept_der: handshake.transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};

		let transcript_hash = Transcript::hpke_handshake(legs).seal::<Sha3_256>()?;
		let static_key = Secp256k1VerifyingKey::from_sec1_bytes(server_public_key)?;
		let signature = Secp256k1Signature::try_from(handshake.signature.as_bytes())?;

		let verified = signature.verify_prehash(&static_key, transcript_hash);
		assert!(verified.is_ok());
		Ok(())
	}

	/// The server admits the hand-built key exchange that offers no identity.
	/// Each refusal of that fixture in this module therefore comes from the
	/// one part its test changes.
	#[tokio::test]
	async fn a_hand_built_key_exchange_is_admitted() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let key_exchange = build_test_client_key_exchange(&identity, &confirming, &CLIENT_RANDOM, None);

		server.finish(carried_closing(&key_exchange)).await?;
		assert_eq!(server.phase(), HandshakePhase::Agreed);
		Ok(())
	}

	/// A key exchange whose client agreed with another server ephemeral
	/// confirms another handshake secret. The server refuses it at the closing,
	/// and it admits no further step.
	#[tokio::test]
	async fn a_key_exchange_that_confirms_another_secret_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let stray = PublicKey::<Secp256k1>::from_sec1_bytes(&create_test_server_ephemeral())?;
		let diverged = Confirming { server_ephemeral: stray, ..confirming };
		let closing = carried_closing(&build_test_client_key_exchange(&identity, &diverged, &CLIENT_RANDOM, None));

		let refused = server.finish(closing.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::KeyConfirmationFailed)));
		assert_eq!(server.phase(), HandshakePhase::Spent);

		let replayed = server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A tag over another transcript hash confirms another handshake, so the
	/// server refuses it although the handshake secret is the one it derived.
	#[tokio::test]
	async fn a_key_exchange_that_confirms_another_transcript_is_refused() {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let foreign = Confirming { transcript_hash: [0x5au8; 32], ..confirming };
		let key_exchange = build_test_client_key_exchange(&identity, &foreign, &CLIENT_RANDOM, None);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::KeyConfirmationFailed)));
	}

	/// A mutual server admits the hand-built key exchange that offers an
	/// identity, and it records that certificate. Each refusal of that
	/// fixture in this module therefore comes from the one part its test
	/// changes.
	#[tokio::test]
	async fn a_hand_built_identified_key_exchange_is_admitted() -> Result<(), Box<dyn Error>> {
		let Identified { mut server, client, key_exchange } = identified(mutual_with(ExpiryValidator)).await;

		server.finish(carried_closing(&key_exchange)).await?;
		assert_eq!(server.peer_certificate(), Some(&client.certificate));
		Ok(())
	}

	/// What a server under `peer_authentication` answers to the key exchange
	/// of an identity that sends its static key as its ephemeral.
	async fn finish_with_a_static_ephemeral(peer_authentication: PeerAuthentication) -> Result<(), HandshakeError> {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, peer_authentication).await;
		let client = create_test_certificate();
		let reused = SecretKey::<Secp256k1>::from(&client.signing_key);
		let sent = build_identified_client_key_exchange_from(&reused, &identity, &confirming, &CLIENT_RANDOM, &client);

		server.finish(carried_closing(&sent)).await
	}

	/// An HPKE message names its signer by the certificate beside it, so a
	/// signature is the provider's signature over the prehash and costs it
	/// that one call.
	#[tokio::test]
	async fn an_hpke_signature_fetches_no_public_key() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let verifying_key = *identity.signing_key.verifying_key();
		let provider = CountingProvider::new(identity.signing_key);
		let prehash = [0x42u8; 32];

		let signed = <Hpke as HandshakeFlow>::sign(&provider, &prehash).await?;

		let signature = Secp256k1Signature::try_from(signed.as_slice())?;
		signature.verify_prehash(&verifying_key, prehash)?;
		assert_eq!(provider.public_keys(), 0);
		Ok(())
	}

	/// A server reply names its signer by the certificate it carries, so the
	/// whole step costs the key provider its signature alone.
	#[tokio::test]
	async fn an_hpke_reply_fetches_no_public_key() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let provider = Arc::new(CountingProvider::new(identity.signing_key.to_owned()));
		let shared = Arc::clone(&provider);
		let mut config = Hpke::server(&identity);
		config.key = shared;
		let mut server = Handshake::server(config);
		let hello_der = create_test_client_hello(&CLIENT_RANDOM)?;
		let hello = ClientHello::from_der(&hello_der)?;

		server.reply(tunneled_opening(&hello)).await?;

		assert_eq!(provider.public_keys(), 0);
		Ok(())
	}

	/// A client that sends its static key as its ephemeral leaves the session
	/// to the secrecy of the two static keys, so a server that demands an
	/// identity refuses the key exchange of the one it admitted.
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

	/// The encapsulated key is a client ephemeral as well, so an identity that
	/// seals under its static key is refused where the closing is read.
	#[tokio::test]
	async fn an_encapsulated_key_equal_to_the_client_static_key_is_refused() -> Result<(), Box<dyn Error>> {
		let Identified { mut server, client, mut key_exchange } = identified(PeerAuthentication::Anonymous).await;
		let static_key = client.certificate.verifying_key::<Secp256k1>()?;
		let encapsulated_key = static_key.to_encoded_point(false);
		let sealed_under_static = [encapsulated_key.as_bytes(), &[0u8; 16]].concat();
		key_exchange.encrypted_data = OctetString::new(sealed_under_static)?;

		let refusal = server.finish(carried_closing(&key_exchange)).await;

		assert!(matches!(refusal, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	/// An anonymous server still verifies the possession proof of an offered
	/// identity, so a signature over other material ends the handshake.
	#[tokio::test]
	async fn an_anonymous_server_refuses_a_forged_offered_identity() {
		let Identified { mut server, client, mut key_exchange } = identified(PeerAuthentication::Anonymous).await;
		let forged_digest = [0u8; 32];

		key_exchange.client_signature = Some(possession_signature(&client, &forged_digest));

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureError(_))));
	}

	/// An offered certificate with no possession signature proves no key, so
	/// the server refuses it rather than treating the client as anonymous.
	#[tokio::test]
	async fn an_offered_certificate_with_no_possession_signature_is_refused() {
		let Identified { mut server, mut key_exchange, .. } = identified(PeerAuthentication::Anonymous).await;
		key_exchange.client_signature = None;

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	#[tokio::test]
	async fn a_mutual_server_refuses_a_key_exchange_with_no_certificate() {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, mutual_with(ExpiryValidator)).await;
		let key_exchange = build_test_client_key_exchange(&identity, &confirming, &CLIENT_RANDOM, None);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	/// A possession signature with no certificate names no key to verify it
	/// under, so the server refuses it rather than ignoring it.
	#[tokio::test]
	async fn a_possession_signature_with_no_certificate_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let mut key_exchange = build_test_client_key_exchange(&identity, &confirming, &CLIENT_RANDOM, None);
		key_exchange.client_signature = Some(OctetString::new([0x30u8; 64])?);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
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
		// certificate, so admission passes the swapped certificate and the
		// AEAD open is the gate that catches the swap.
		let (mut client, mut server) = pair::<Hpke>(mutual_with(ExpiryValidator));

		// The honest client presents its own certificate and seals the payload
		// under it.
		let reply = server.reply(client.start()?).await?;
		let closing = client.respond(reply).await?;
		let mut key_exchange = carried_key_exchange(&closing);

		// The on-path party swaps in its certificate and signs the possession
		// proof under its own key, over the same transcript and sealed payload.
		let mitm = create_test_certificate();
		let transcript_hash = server.transcript_hash().ok_or("the reply sealed the transcript")?;
		let digest = possession_digest(&transcript_hash, key_exchange.encrypted_data.as_bytes(), &mitm.certificate);

		key_exchange.client_certificate = Some(mitm.certificate.to_owned());
		key_exchange.client_signature = Some(possession_signature(&mitm, &digest));

		let result = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(result, Err(HandshakeError::HpkeError(DecryptionFailed(_)))));
		Ok(())
	}

	/// The server ephemeral leaves the phase when the closing step starts, and
	/// the step holds it as a local. A key exchange that fails the AEAD open
	/// drops the ephemeral with the step, and the server admits no further
	/// step.
	///
	/// The payload here is sealed under another domain tag, so the open fails
	/// on the associated data.
	#[tokio::test]
	async fn a_failed_hpke_open_leaves_the_server_spent() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let foreign = sealed_payload(&identity, &confirming, &CLIENT_RANDOM, None, b"another domain tag");
		let closing = carried_closing(&anonymous_key_exchange(foreign));

		let refused = server.finish(closing.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::HpkeError(DecryptionFailed(_)))));
		assert_eq!(server.phase(), HandshakePhase::Spent);

		let replayed = server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A hello whose tunnel carries an abort alert is refused.
	#[tokio::test]
	async fn a_hello_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Hpke::server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let alerted = with_abort_alert(client.start()?, 3);

		let refusal = server.reply(alerted).await;
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A server handshake whose tunnel carries an abort alert is refused.
	#[tokio::test]
	async fn a_server_handshake_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Hpke::server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));
		let reply = server.reply(client.start()?).await?;
		let alerted = with_abort_alert(reply, 4);

		let refusal = client.respond(alerted).await;
		let expected = HandshakeAlert::DecryptFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A key exchange whose envelope carries an abort alert is refused before
	/// the key exchange is read.
	///
	/// The sealed bytes here are too short for an HPKE message, so a server
	/// that decoded the key exchange first would refuse with another error.
	#[tokio::test]
	async fn a_key_exchange_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let (mut server, _) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let key_exchange = anonymous_key_exchange([0x41u8; 32]);
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, Any::encode_from(&4u8)?)?;

		let mut alerted = EnvelopedData::try_from(&key_exchange)?;
		alerted.unprotected_attrs = Some(Attributes::try_from(vec![Attribute::try_from(alert)?])?);

		let refusal = server.finish(HandshakeMessage::try_from(alerted)?).await;
		let expected = HandshakeAlert::DecryptFail;
		assert!(matches!(refusal, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// The payload echoes the client random of the hello, so a key exchange
	/// recorded from one handshake fails on another. A payload that echoes
	/// another random is refused as a replay.
	#[tokio::test]
	async fn a_key_exchange_that_echoes_another_client_random_is_refused() {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let other_random = [8u8; 32];
		let replayed = build_test_client_key_exchange(&identity, &confirming, &other_random, None);

		let refusal = server.finish(carried_closing(&replayed)).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientRandomMismatchReplay)));
	}

	/// A server that granted no budgets issued no receipt, so it refuses a key
	/// exchange whose payload acknowledges one.
	#[tokio::test]
	async fn an_acknowledgement_with_no_issued_receipt_is_refused() {
		let identity = create_test_certificate();
		let (mut server, confirming) = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let stray_ack = Some(b"an acknowledgement of no receipt".as_slice());
		let key_exchange = build_test_client_key_exchange(&identity, &confirming, &CLIENT_RANDOM, stray_ack);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::ReceiptMismatch)));
	}

	#[test]
	fn a_payload_that_is_not_der_is_refused() {
		let garbage = [0u8; 68];
		let parsed = SessionPayload::<Secp256k1>::parse(&garbage, &anonymous());
		assert!(matches!(parsed, Err(HandshakeError::InvalidDecryptedPayloadSize)));
	}

	#[test]
	fn a_payload_with_a_short_base_secret_is_refused() {
		let client_ephemeral = create_test_server_ephemeral();
		let short_key = session_payload_der([0u8; 31], [0u8; 32], client_ephemeral, &fixture_confirmation(), None);
		let parsed = SessionPayload::<Secp256k1>::parse(&short_key, &anonymous());
		let refused = matches!(parsed, Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 }));
		assert!(refused);
	}

	/// The parser fails closed on a client random of another width.
	#[test]
	fn a_payload_with_a_short_client_random_is_refused() {
		let client_ephemeral = create_test_server_ephemeral();
		let short_random = session_payload_der([0u8; 32], [0u8; 16], client_ephemeral, &fixture_confirmation(), None);
		let parsed = SessionPayload::<Secp256k1>::parse(&short_random, &anonymous());
		assert!(matches!(parsed, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// The parser admits a client ephemeral that is a compressed point of the
	/// curve and no other, so the ephemeral-ephemeral agreement runs on a
	/// validated key.
	#[test]
	fn a_payload_with_a_client_ephemeral_that_is_no_point_is_refused() {
		let confirmation = fixture_confirmation();
		let uncompressed = [0x04u8; 65];
		let off_curve = session_payload_der([0u8; 32], [0u8; 32], off_curve_point(), &confirmation, None);
		let another_width = session_payload_der([0u8; 32], [0u8; 32], uncompressed, &confirmation, None);

		let off_curve = SessionPayload::<Secp256k1>::parse(&off_curve, &anonymous());
		let another_width = SessionPayload::<Secp256k1>::parse(&another_width, &anonymous());
		assert!(matches!(off_curve, Err(HandshakeError::InvalidPublicKey(_))));
		assert!(matches!(another_width, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// The key-confirmation tag is mandatory, so a payload that carries none
	/// fails to decode and no closing reaches the agreement unconfirmed.
	#[test]
	fn a_payload_with_no_key_confirmation_is_refused() {
		let unconfirmed = loose_payload_der(None);
		let parsed = SessionPayload::<Secp256k1>::parse(&unconfirmed, &anonymous());
		assert!(matches!(parsed, Err(HandshakeError::InvalidDecryptedPayloadSize)));
	}

	/// A key-confirmation tag of another width fails to decode.
	#[test]
	fn a_payload_with_a_short_key_confirmation_is_refused() {
		let short_tag = loose_payload_der(Some(&[7u8; 31]));
		let parsed = SessionPayload::<Secp256k1>::parse(&short_tag, &anonymous());
		assert!(matches!(parsed, Err(HandshakeError::InvalidDecryptedPayloadSize)));
	}

	/// The loose encoding of a 32-byte tag is the payload the parser admits, so
	/// each refusal above comes from the tag alone.
	#[test]
	fn a_payload_with_a_key_confirmation_of_the_one_width_parses() {
		let confirmed = loose_payload_der(Some(&[7u8; 32]));
		let parsed = SessionPayload::<Secp256k1>::parse(&confirmed, &anonymous());
		assert!(parsed.is_ok());
	}

	/// A well-formed payload parses into its base secret, its client random,
	/// its client ephemeral, and an absent acknowledgement.
	#[test]
	fn a_well_formed_payload_parses_into_its_session_data() -> Result<(), Box<dyn Error>> {
		let client_ephemeral = create_test_server_ephemeral();
		let unanswered = session_payload_der([3u8; 32], [5u8; 32], client_ephemeral, &fixture_confirmation(), None);
		let payload = SessionPayload::<Secp256k1>::parse(&unanswered, &anonymous())?;
		assert_eq!(payload.base.as_bytes(), [3u8; 32]);
		assert_eq!(payload.client_random, [5u8; 32]);
		assert_eq!(payload.client_ephemeral.as_public_key().compressed_point()?, client_ephemeral);
		assert!(payload.receipt_ack.is_none());
		Ok(())
	}

	/// A ClientHello with only a transport offer and no security offer must
	/// round-trip. The context tag on `transport_offer` keeps it from parsing
	/// as the preceding optional SEQUENCE.
	#[test]
	fn a_hello_with_only_a_transport_offer_round_trips() -> Result<(), Box<dyn Error>> {
		let hello = ClientHello {
			client_random: OctetString::new([7u8; 32])?,
			security_offer: None,
			transport_offer: Some(TransportOffer::mux(16)),
		};

		let decoded = ClientHello::from_der(&hello.to_der()?)?;
		assert_eq!(decoded.security_offer, None);
		assert_eq!(decoded.transport_offer, Some(TransportOffer::mux(16)));
		Ok(())
	}
}

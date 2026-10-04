//! The ECIES flow.
//!
//! ECIES tunnels its own messages inside the two containers. The client
//! learns the server from the reply, and it seals the base secret to the
//! server's static key on the closing.
//!
//! One client ephemeral `r` serves both key agreements:
//!
//! - `r·E` with the server ephemeral feeds the handshake secret.
//! - `r·S` with the server's static key seals the closing payload.

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::cms::signed_data::SignedData;
use crate::constants::{EC_PUBKEY_COMPRESSED_SIZE, TIGHTBEAM_AAD_DOMAIN_TAG};
use crate::crypto::ecies::{decrypt_with_shared_secret, EciesMessageOps, EciesSecretKeyOps};
use crate::crypto::kdf::EcdhSecret;
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::ecdh::EphemeralSecret;
use crate::crypto::sign::elliptic_curve::{PublicKey, SecretKey};
use crate::crypto::sign::LowSEncoding;
use crate::crypto::subtle::ConstantTimeEq;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::{Decode, Encode};
use crate::random::{generate_nonce, CryptoRngCore, OsRng, RngWrapper};
use crate::transport::handshake::attributes::HandshakeAttributes;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::{
	sealed, ClientFlow, ClosingBinding, ClosingIntake, ClosingOpened, ClosingParts, HandshakeFlow, Opened,
	OpeningIntake, OpeningParts, ProofRequest, ReplyBinding, ReplyIntake, ReplyParts, ServerFlow, Signed,
};
use crate::transport::handshake::negotiation::{SecurityAccept, TransportAccept};
use crate::transport::handshake::peer::{LearnedTrust, PossessionProof};
use crate::transport::handshake::primitives::transcript::{EciesHandshakeLegs, Transcript};
use crate::transport::handshake::primitives::KdfSalt;
use crate::transport::handshake::schedule::{
	Agreement, BaseSecret, CompressedPoint, HandshakeVerifyingKey, Salt, Terms,
};
use crate::transport::handshake::wire::HandshakeOctets;
use crate::transport::handshake::{
	Arc, ClientHello, ClientKeyExchange, EciesSessionPayload, HandshakeCurve, HandshakeMessage, HandshakeProvider,
	HandshakeSecret, ServerHandshake, TunneledMessage,
};
use crate::transport::state::ClientIdentity;
use crate::transport::wire_der::WireDer;
use crate::utils::marker::MaybeSendFuture;
use crate::x509::Certificate;
use crate::zeroize::{Zeroize, Zeroizing};

/// The ECIES handshake protocol.
///
/// A client is provisioned with [`EciesClientSettings`], and a server with
/// [`EciesServerSettings`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ecies;

impl sealed::Sealed for Ecies {}

impl HandshakeFlow for Ecies {}

/// What an ECIES client is provisioned with.
pub struct EciesClientSettings<P: HandshakeProvider> {
	/// The trust that admits the certificate the reply names.
	pub trust: LearnedTrust,
	/// The domain tag the closing payload is sealed under. Both endpoints
	/// MUST hold the same tag for a session to complete.
	pub aad_domain_tag: &'static [u8],
	/// The identity the client presents for mutual authentication.
	pub identity: Option<ClientIdentity<P>>,
}

impl<P: HandshakeProvider> EciesClientSettings<P> {
	/// Settings for an anonymous client under [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(trust: LearnedTrust) -> Self {
		Self { trust, aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG, identity: None }
	}
}

/// What an ECIES client keeps from its hello to read the reply against.
pub struct EciesOpening {
	/// The DER of the sent `ClientHello`. The transcript binds these bytes, so
	/// a rewritten offer changes the transcript hash (CWE-757).
	hello_der: Vec<u8>,
	/// The client random the hello carried.
	client_random: [u8; 32],
}

/// A decoded `ServerHandshake`, kept for verification and for the closing.
pub struct EciesReply {
	/// The server signature over the transcript hash.
	signature: OctetString,
	/// The client random, which the closing payload echoes.
	client_random: [u8; 32],
}

/// The client half of an ECIES agreement, kept to seal the closing.
pub struct EciesAgreed<C: HandshakeCurve> {
	/// The base secret the closing carries to the server.
	base: BaseSecret,
	/// The client ephemeral `r`.
	ephemeral: SecretKey<C>,
}

/// A `ClientKeyExchange` that awaits its possession signature.
pub struct EciesClosingDraft {
	/// The payload, sealed to the server's static key.
	encrypted_data: Vec<u8>,
	/// The certificate the client presents, when it holds an identity.
	certificate: Option<Certificate>,
}

impl<P: HandshakeProvider> ClientFlow<P> for Ecies {
	type Settings = EciesClientSettings<P>;
	type Trust = LearnedTrust;
	type Opening = EciesOpening;
	type Pending = ();
	type Reply = EciesReply;
	type Agreed = Box<EciesAgreed<P::Curve>>;
	type Draft = EciesClosingDraft;

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
		let opening = EciesOpening { hello_der, client_random };
		Ok(Opened { message, opening, pending: () })
	}

	fn read_reply(
		opening: Self::Opening,
		_settings: &Self::Settings,
		reply: HandshakeMessage,
	) -> Result<ReplyIntake<Self, P>, HandshakeError> {
		let EciesOpening { hello_der, client_random } = opening;

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
		let legs = EciesHandshakeLegs {
			client_hello: &hello_der,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?,
			spki: certificate.verifying_key_bytes(),
			security_accept_der: security_accept.as_ref().map(WireDer::der).unwrap_or_default(),
			transport_accept_der: transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};
		let mut transcript = Transcript::ecies_handshake(legs);
		let transcript_hash = transcript.seal::<P::Digest>()?;

		// 3. Return the facts of the reply.
		let salt = Salt::randoms(&client_random, &server_random);
		let security_accept = security_accept.as_ref().map(WireDer::value).cloned();
		let transport_accept = transport_accept.as_ref().map(WireDer::value).cloned();
		let server_ephemeral = server_ephemeral.into_bytes();
		let reply = EciesReply { signature, client_random };
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
		server_ephemeral: &PublicKey<P::Curve>,
		salt: KdfSalt<'_>,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(HandshakeSecret, Self::Agreed), HandshakeError> {
		let base = BaseSecret::random(Some(&mut *rng))?;
		let ephemeral = SecretKey::<P::Curve>::random(&mut RngWrapper(rng));
		let agreement = Agreement::<P>::new(&base, server_ephemeral);
		let secret = agreement.settle(&ephemeral, salt)?;

		// The two secrets cross the countersignature await in the orchestrator.
		// They are boxed, so that move copies a pointer.
		Ok((secret, Box::new(EciesAgreed { base, ephemeral })))
	}

	fn bind_closing<'a>(
		agreed: Self::Agreed,
		reply: Self::Reply,
		settings: &'a Self::Settings,
		parts: ClosingParts<'_>,
	) -> Result<ClosingBinding<'a, Self, P>, HandshakeError> {
		// The secrets are read in place, so each is wiped where the box drops.
		let EciesAgreed { base, ephemeral } = agreed.as_ref();
		let ClosingParts { server, transcript_hash, sealed_ack } = parts;

		// 1. Encode the payload. The DER buffer holds the base secret, so it
		//    wipes when dropped, along with the transient OCTET STRING copy.
		let payload = EciesSessionPayload {
			base_key: OctetString::new(base.as_bytes())?,
			client_random: OctetString::new(reply.client_random.as_slice())?,
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
		let static_key = server.verifying_key::<P::Curve>()?;
		let seal = SecretKey::<P::Curve>::encrypt_to::<P::EciesMessage, P::Kdf, P::AeadCipher>;
		let sealed = seal(ephemeral, &static_key, plaintext.as_slice(), Some(aad.as_slice()), &mut OsRng)?;
		let encrypted_data = sealed.to_bytes();

		// 3. Name the bytes the identity signs. The digest covers the
		//    transcript hash, the sealed payload, and the certificate, so the
		//    signature binds to this key exchange and this identity alone.
		let proof = match identity {
			Some(identity) => {
				let certificate_der = identity.certificate().to_der()?;
				let mut signed = Transcript::ecies_client_auth(transcript_hash, &encrypted_data, &certificate_der);
				let prehash = signed.seal::<P::Digest>()?.to_vec();
				Some(ProofRequest { prehash, signer: identity.signing_provider() })
			}
			None => None,
		};
		let draft = EciesClosingDraft { encrypted_data, certificate: certificate.cloned() };
		Ok(ClosingBinding { proof, draft })
	}

	fn encode_closing(draft: Self::Draft, proof: Option<Signed>) -> Result<HandshakeMessage, HandshakeError> {
		let EciesClosingDraft { encrypted_data, certificate } = draft;
		let signature = proof.map(|signed| OctetString::new(signed.signature)).transpose()?;
		let key_exchange = ClientKeyExchange {
			encrypted_data: OctetString::new(encrypted_data)?,
			client_certificate: certificate,
			client_signature: signature,
		};

		let carrier = EnvelopedData::try_from(&key_exchange)?;
		HandshakeMessage::try_from(carrier)
	}
}

/// What an ECIES server is provisioned with.
pub struct EciesServerSettings {
	/// The certificate the server presents in its reply.
	pub certificate: Arc<Certificate>,
	/// The domain tag the closing payload is sealed under. Both endpoints
	/// MUST hold the same tag for a session to complete.
	pub aad_domain_tag: &'static [u8],
}

impl EciesServerSettings {
	/// Settings for a server that presents `certificate` under
	/// [`TIGHTBEAM_AAD_DOMAIN_TAG`].
	pub fn new(certificate: impl Into<Arc<Certificate>>) -> Self {
		Self { certificate: certificate.into(), aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG }
	}
}

/// What an ECIES server keeps of the hello to bind the reply over.
pub struct EciesHello {
	/// The DER of the received `ClientHello`, as the transcript binds it.
	hello_der: Vec<u8>,
	/// The client random the hello carried.
	client_random: [u8; 32],
}

/// A `ServerHandshake` that awaits its signature and its receipt.
pub struct EciesReplyDraft {
	server_random: [u8; 32],
	server_ephemeral: [u8; EC_PUBKEY_COMPRESSED_SIZE],
	security_accept: WireDer<SecurityAccept>,
	transport_accept: Option<WireDer<TransportAccept>>,
	certificate: Certificate,
	client_cert_required: bool,
}

/// What an ECIES server holds from its reply to the key exchange.
pub struct EciesServerPending<C: HandshakeCurve> {
	/// The server ephemeral `e`, which serves one agreement. It is boxed, so
	/// a move of the pending state copies a pointer.
	ephemeral: Box<EphemeralSecret<C>>,
	/// The client random the key exchange must echo.
	client_random: [u8; 32],
}

/// A decoded key exchange that awaits the static open.
pub struct EciesClosing<M> {
	/// The ECIES message, which leads with the client ephemeral.
	message: M,
	/// The associated data the payload was sealed under.
	aad: Vec<u8>,
}

/// The proof of an ECIES key exchange that the key of the offered
/// certificate signed it.
///
/// The signed digest covers the transcript hash, the encrypted payload, and
/// the offered certificate, so the signature binds to one exchange and one
/// identity.
pub struct EciesPossession {
	signature: Vec<u8>,
	encrypted_data: Vec<u8>,
	certificate_der: Vec<u8>,
}

impl<P: HandshakeProvider> PossessionProof<P> for EciesPossession {
	fn verify(self, key: P::VerifyingKey, terms: &Terms<P>) -> Result<(), HandshakeError> {
		let transcript_hash = terms.transcript_hash();
		let mut signed = Transcript::ecies_client_auth(transcript_hash, &self.encrypted_data, &self.certificate_der);
		let digest = signed.seal::<P::Digest>()?;

		let parsed = P::Signature::try_from(self.signature.as_slice());
		let signature = parsed.map_err(|_| HandshakeError::SignatureVerificationFailed)?;
		signature.verify_prehash(&key, digest)?;
		Ok(())
	}
}

/// The parts of the decrypted key-exchange payload.
struct SessionPayload {
	/// The base secret the client drew.
	base: BaseSecret,
	/// The client random the payload echoes against replay.
	client_random: [u8; 32],
	/// The client receipt `SignerInfo`, sealed under the handshake secret.
	/// Its signed attributes bind the bearer settlement answer, so it opens
	/// only after the ephemeral-ephemeral agreement.
	receipt_ack: Option<OctetString>,
}

impl SessionPayload {
	/// Parse the decrypted DER [`EciesSessionPayload`], and enforce the fixed
	/// 32-byte geometry of the base secret.
	fn parse(decrypted: &[u8]) -> Result<Self, HandshakeError> {
		let payload = EciesSessionPayload::from_der(decrypted);
		let payload = payload.map_err(|_| HandshakeError::InvalidDecryptedPayloadSize)?;
		let EciesSessionPayload { base_key, client_random, receipt_ack } = payload;

		// The decoded buffer moves into its wiping wrapper without a copy, and
		// the parse copies it into the fixed-width secret, so no plain array of
		// key material exists on the way (CWE-226).
		let base = BaseSecret::try_from(SecretSlice::from(base_key.into_bytes()))?;
		let client_random = client_random.to_32_byte_array()?;
		Ok(Self { base, client_random, receipt_ack })
	}
}

impl<P: HandshakeProvider> ServerFlow<P> for Ecies {
	type Settings = EciesServerSettings;
	type Sealed = EciesHello;
	type Opened = EciesHello;
	type Draft = EciesReplyDraft;
	type Pending = EciesServerPending<P::Curve>;
	type Closing = EciesClosing<P::EciesMessage>;
	type Proof = EciesPossession;

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
		let sealed = EciesHello { hello_der, client_random };

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
		let legs = EciesHandshakeLegs {
			client_hello: &opened.hello_der,
			server_random: &server_random,
			server_ephemeral: &server_ephemeral,
			spki: settings.certificate.verifying_key_bytes(),
			security_accept_der: security_accept.der(),
			transport_accept_der: transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};

		let mut transcript = Transcript::ecies_handshake(legs);
		let transcript_hash = transcript.seal::<P::Digest>()?;

		let salt = Salt::randoms(&opened.client_random, &server_random);
		let draft = EciesReplyDraft {
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
		signed: Signed,
		artifact: Option<&SignedData>,
	) -> Result<HandshakeMessage, HandshakeError> {
		let EciesReplyDraft {
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
			signature: OctetString::new(signed.signature)?,
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
		Ok(EciesServerPending { ephemeral, client_random: opened.client_random })
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

		// 2. Decode the key exchange. The ECIES message leads with the client ephemeral public key.
		let key_exchange = ClientKeyExchange::try_from(carrier.value())?;
		let ClientKeyExchange { encrypted_data, client_certificate, client_signature } = key_exchange;
		let message = <P::EciesMessage as EciesMessageOps>::from_bytes(encrypted_data.as_bytes())?;

		// 3. Build the associated data and the possession proof over the
		//    offered certificate. A signature with no certificate binds no
		//    certificate bytes, and admission refuses it unverified.
		let offered = client_certificate.as_ref();
		let aad = ClientKeyExchange::client_bound_aad(settings.aad_domain_tag, offered)?;
		let certificate_der = offered.map(Encode::to_der).transpose()?.unwrap_or_default();
		let proof = client_signature.map(|signature| EciesPossession {
			signature: signature.into_bytes(),
			encrypted_data: encrypted_data.into_bytes(),
			certificate_der,
		});

		let closing = EciesClosing { message, aad };
		Ok(ClosingIntake { offered: client_certificate, proof, closing })
	}

	fn settle<'a>(
		pending: Self::Pending,
		closing: Self::Closing,
		terms: &'a Terms<P>,
		key: &'a dyn SigningKeyProvider,
	) -> MaybeSendFuture<'a, Result<ClosingOpened, HandshakeError>> {
		Box::pin(async move {
			let EciesServerPending { ephemeral, client_random } = pending;
			let EciesClosing { message, aad } = closing;

			// 1. Open the payload under the associated data. The key provider
			//    runs the static ECDH step, so the private key can stay behind
			//    an external boundary, and the AEAD open authenticates the
			//    client ephemeral through the content key.
			let agreed = key.key_agreement(message.ephemeral_pubkey()).await?;
			let shared_secret = EcdhSecret::try_from(agreed)?;
			let open = decrypt_with_shared_secret::<P::EciesMessage, P::Kdf, P::AeadCipher>;
			let plaintext = open(&message, shared_secret, Some(aad.as_slice()))?;
			let payload = plaintext.with(|payload| SessionPayload::parse(payload))?;
			let SessionPayload { base, client_random: echoed, receipt_ack } = payload;

			// 2. Verify that the payload echoes the client random of the hello, which prevents replay.
			let is_echo: bool = echoed.ct_eq(&client_random).into();
			if !is_echo {
				return Err(HandshakeError::ClientRandomMismatchReplay);
			}

			// 3. Run the ephemeral-ephemeral agreement and derive the
			//    handshake secret. The server ephemeral serves this one
			//    exchange and drops when this step returns.
			let client_ephemeral = PublicKey::<P::Curve>::from_sec1_bytes(message.ephemeral_pubkey())?;
			let agreement = Agreement::<P>::new(&base, &client_ephemeral);
			let secret = agreement.settle(ephemeral.as_ref(), terms.kdf_salt())?;

			let receipt_ack = receipt_ack.map(OctetString::into_bytes);
			Ok(ClosingOpened { secret, receipt_ack })
		})
	}
}

#[cfg(test)]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::{SignerInfo, SignerInfos};
	use crate::crypto::aead::Aes256Gcm;
	use crate::crypto::ecies::EciesError::DecryptionFailed;
	use crate::crypto::ecies::{encrypt, Secp256k1EciesMessage};
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::kdf::HkdfSha3_256;
	use crate::crypto::profiles::SecurityProfileDesc;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
	use crate::crypto::sign::PrehashSigner;
	use crate::crypto::x509::policy::ExpiryValidator;
	use crate::crypto::x509::utils::compute_signer_identifier;
	use crate::der::Any;
	use crate::oids::{HANDSHAKE_ABORT_ALERT, HASH_SHA3_256, HASH_SHA3_384, SIGNER_ECDSA_WITH_SHA3_256};
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::transport::handshake::attributes::HandshakeAttribute;
	use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportOffer};
	use crate::transport::handshake::schedule::CompressedPoint;
	use crate::transport::handshake::tests::*;
	use crate::transport::handshake::{Handshake, HandshakeAlert, HandshakePhase, PeerAuthentication};
	use crate::x509::attr::{Attribute, Attributes};

	/// The configuration of an anonymous client that trusts `server`.
	fn anonymous_client(server: &TestCertificate) -> TestClientConfig<Ecies> {
		let mut config = Ecies::client(&server.certificate, &create_test_certificate());
		config.flow.identity = None;
		config
	}

	/// An anonymous client that trusts `server` and has sent its hello under
	/// `offer`, with the DER of that hello.
	fn client_after_hello(server: &TestCertificate, offer: Option<SecurityOffer>) -> (TestClient<Ecies>, Vec<u8>) {
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
		let legs = EciesHandshakeLegs {
			client_hello,
			server_random: &server_random,
			server_ephemeral,
			spki: server.certificate.verifying_key_bytes(),
			security_accept_der: accept_der,
			transport_accept_der: &[],
		};

		let mut transcript = Transcript::ecies_handshake(legs);
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
	/// An ECIES tunnel is sent with no signer. A `SignedData` still has room
	/// for one, and that is where a peer that aborts would put its alert.
	fn with_abort_alert(tunnel: HandshakeMessage, code: u8) -> HandshakeMessage {
		let tunnel = tunnel.signed().expect("an ECIES tunnel is a SignedData");
		let code = Any::encode_from(&code).expect("an alert code encodes");
		let alert = HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, code).expect("one value is an attribute");
		let alert = Attribute::try_from(alert).expect("the alert encodes");

		let signer = create_test_certificate();
		let sid = compute_signer_identifier(signer.signing_key.verifying_key()).expect("a key has an identifier");
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
	/// replied to a hand-built hello that carries [`CLIENT_RANDOM`].
	async fn server_after_hello(
		identity: &TestCertificate,
		peer_authentication: PeerAuthentication,
	) -> TestServer<Ecies> {
		let mut config = Ecies::server(identity);
		config.peer_authentication = peer_authentication;

		let mut server = Handshake::server(config);
		let hello_der = create_test_client_hello(&CLIENT_RANDOM).expect("a hello encodes");
		let hello = ClientHello::from_der(&hello_der).expect("the hello decodes");
		let opening = tunneled_opening(&hello);

		server.reply(opening).await.expect("the server admits the hello");
		server
	}

	/// The DER of an `EciesSessionPayload` that carries `base_key`,
	/// `client_random`, and `receipt_ack` at the widths they come in.
	fn session_payload_der(
		base_key: impl AsRef<[u8]>,
		client_random: impl AsRef<[u8]>,
		receipt_ack: Option<&[u8]>,
	) -> Vec<u8> {
		let octets = |bytes: &[u8]| OctetString::new(bytes).expect("bytes are an OCTET STRING");
		let payload = EciesSessionPayload {
			base_key: octets(base_key.as_ref()),
			client_random: octets(client_random.as_ref()),
			receipt_ack: receipt_ack.map(octets),
		};
		payload.to_der().expect("the payload encodes")
	}

	/// The bytes of an ECIES message that seals a payload to the static key of
	/// `server` under the associated data `aad`. The payload carries a fresh
	/// base secret, `client_random`, and `receipt_ack`.
	fn sealed_payload(
		server: &TestCertificate,
		client_random: &[u8; 32],
		receipt_ack: Option<&[u8]>,
		aad: impl AsRef<[u8]>,
	) -> Vec<u8> {
		let static_key = PublicKey::<Secp256k1>::from_sec1_bytes(server.certificate.verifying_key_bytes());
		let static_key = static_key.expect("the test certificate carries a point on the curve");
		let base_secret = generate_nonce::<32>(None).expect("the random source draws a base secret");
		let plaintext = session_payload_der(base_secret, client_random, receipt_ack);

		let seal = encrypt::<_, _, _, Secp256k1EciesMessage, HkdfSha3_256, Aes256Gcm>;
		let sealed = seal(&static_key, plaintext, Some(aad.as_ref()), Some(&mut OsRng));
		sealed.expect("the payload seals").to_bytes()
	}

	/// A `ClientKeyExchange` that carries `encrypted_data` and offers no
	/// identity.
	fn anonymous_key_exchange(encrypted_data: impl AsRef<[u8]>) -> ClientKeyExchange {
		let encrypted_data = OctetString::new(encrypted_data.as_ref()).expect("sealed bytes are an OCTET STRING");
		ClientKeyExchange { encrypted_data, client_certificate: None, client_signature: None }
	}

	/// A hand-built `ClientKeyExchange` that offers no identity, for the
	/// server that holds `server`.
	///
	/// The payload echoes `client_random` and carries `receipt_ack`, and it is
	/// sealed under [`TIGHTBEAM_AAD_DOMAIN_TAG`] alone.
	fn build_test_client_key_exchange(
		server: &TestCertificate,
		client_random: &[u8; 32],
		receipt_ack: Option<&[u8]>,
	) -> ClientKeyExchange {
		let sealed = sealed_payload(server, client_random, receipt_ack, TIGHTBEAM_AAD_DOMAIN_TAG);
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
		let mut signed = Transcript::ecies_client_auth(transcript_hash, encrypted_data, certificate_der);
		signed.seal::<Sha3_256>().expect("the possession transcript seals")
	}

	/// The signature of `signer` over `digest`, as a key exchange carries a
	/// possession proof.
	fn possession_signature(signer: &TestCertificate, digest: &[u8; 32]) -> OctetString {
		let signature: Secp256k1Signature = signer.signing_key.sign_prehash(digest).expect("the test key signs");
		OctetString::new(signature.to_bytes().to_vec()).expect("a signature is an OCTET STRING")
	}

	/// A hand-built `ClientKeyExchange` that offers the identity of `client`,
	/// for the server that holds `server` and sealed `transcript_hash`.
	///
	/// The payload echoes `client_random`, it is sealed under the associated
	/// data that binds the certificate of `client`, and `client` signs the
	/// [`possession_digest`] of the sealed payload.
	fn build_identified_client_key_exchange(
		server: &TestCertificate,
		client_random: &[u8; 32],
		transcript_hash: &[u8; 32],
		client: &TestCertificate,
	) -> ClientKeyExchange {
		let aad = ClientKeyExchange::client_bound_aad(TIGHTBEAM_AAD_DOMAIN_TAG, Some(&client.certificate));
		let aad = aad.expect("the test certificate encodes");
		let sealed = sealed_payload(server, client_random, None, aad);
		let digest = possession_digest(transcript_hash, &sealed, &client.certificate);

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
		server: TestServer<Ecies>,
		/// The identity the key exchange offers.
		client: TestCertificate,
		/// The key exchange, with the possession proof of `client`.
		key_exchange: ClientKeyExchange,
	}

	/// A server under `peer_authentication` that has replied to a hand-built
	/// hello, with the key exchange of a fresh identity for it.
	async fn identified(peer_authentication: PeerAuthentication) -> Identified {
		let identity = create_test_certificate();
		let server = server_after_hello(&identity, peer_authentication).await;
		let transcript_hash = server.transcript_hash().expect("the reply sealed the transcript");
		let client = create_test_certificate();
		let key_exchange = build_identified_client_key_exchange(&identity, &CLIENT_RANDOM, &transcript_hash, &client);

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
	async fn a_tampered_server_ephemeral_fails_the_ecies_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Ecies::server(&identity));
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
	async fn a_stripped_accept_fails_the_ecies_signature() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Ecies::server(&identity));
		let mut client = Handshake::client(anonymous_client(&identity));

		let signed = server.reply(client.start()?).await?;
		let mut stripped = tunneled_handshake(&signed);
		stripped.security_accept = None;

		let result = client.respond(tunneled_reply(&stripped)).await;
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
		let mut config = Ecies::server(&identity);
		config.peer_authentication = mutual_with(ExpiryValidator);

		let mut server = Handshake::server(config);
		let mut client = Handshake::client(anonymous_client(&identity));

		let reply = server.reply(client.start()?).await?;
		let refused = client.respond(reply).await;
		assert!(matches!(refused, Err(HandshakeError::MutualAuthRequired)));
		Ok(())
	}

	/// The handshake secret is a local of the closing step until the step
	/// stores what it agreed. A closing that fails after the agreement drops
	/// the secret with the step, and the client admits no further step.
	///
	/// The reply here carries a receipt, which demands a client identity, and
	/// the client holds none, so the step fails at the countersignature.
	#[tokio::test]
	async fn a_failed_ecies_closing_leaves_the_client_spent() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut config = Ecies::server(&identity);
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
		let mut run = run(anonymous_client(&identity), Ecies::server(&identity)).await;

		let session = run.server.complete()?;
		assert!(session.peer().is_none());
		Ok(())
	}

	/// The reply to a hand-built hello is signed under the server's static key
	/// over the transcript of that hello and the legs the reply carries. No
	/// client reads the reply, so the test holds the reply encoder to the wire
	/// types alone.
	#[tokio::test]
	async fn a_hand_built_hello_is_answered_with_a_signed_server_handshake() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Ecies::server(&identity));
		let hello_der = create_test_client_hello(&CLIENT_RANDOM)?;
		let hello = ClientHello::from_der(&hello_der)?;

		let reply = server.reply(tunneled_opening(&hello)).await?;
		let handshake = tunneled_handshake(&reply);
		let random = handshake.server_random.to_32_byte_array()?;
		let ephemeral = handshake.server_ephemeral.to_byte_array::<EC_PUBKEY_COMPRESSED_SIZE>()?;
		let spki = identity.certificate.verifying_key_bytes();
		let legs = EciesHandshakeLegs {
			client_hello: &hello_der,
			server_random: &random,
			server_ephemeral: &ephemeral,
			spki,
			security_accept_der: handshake.security_accept.as_ref().map(WireDer::der).unwrap_or_default(),
			transport_accept_der: handshake.transport_accept.as_ref().map(WireDer::der).unwrap_or_default(),
		};

		let transcript_hash = Transcript::ecies_handshake(legs).seal::<Sha3_256>()?;
		let static_key = Secp256k1VerifyingKey::from_sec1_bytes(spki)?;
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
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let key_exchange = build_test_client_key_exchange(&identity, &CLIENT_RANDOM, None);

		server.finish(carried_closing(&key_exchange)).await?;
		assert_eq!(server.phase(), HandshakePhase::Agreed);
		Ok(())
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
		let mut server = server_after_hello(&identity, mutual_with(ExpiryValidator)).await;
		let key_exchange = build_test_client_key_exchange(&identity, &CLIENT_RANDOM, None);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	/// A possession signature with no certificate names no key to verify it
	/// under, so the server refuses it rather than ignoring it.
	#[tokio::test]
	async fn a_possession_signature_with_no_certificate_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let mut key_exchange = build_test_client_key_exchange(&identity, &CLIENT_RANDOM, None);
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
		let (mut client, mut server) = pair::<Ecies>(mutual_with(ExpiryValidator));

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
		assert!(matches!(result, Err(HandshakeError::EciesError(DecryptionFailed(_)))));
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
	async fn a_failed_ecies_open_leaves_the_server_spent() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let foreign = sealed_payload(&identity, &CLIENT_RANDOM, None, b"another domain tag");
		let closing = carried_closing(&anonymous_key_exchange(foreign));

		let refused = server.finish(closing.to_owned()).await;
		assert!(matches!(refused, Err(HandshakeError::EciesError(DecryptionFailed(_)))));
		assert_eq!(server.phase(), HandshakePhase::Spent);

		let replayed = server.finish(closing).await;
		assert!(matches!(replayed, Err(HandshakeError::InvalidState)));
		Ok(())
	}

	/// A hello whose tunnel carries an abort alert is refused.
	#[tokio::test]
	async fn a_hello_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = Handshake::server(Ecies::server(&identity));
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
		let mut server = Handshake::server(Ecies::server(&identity));
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
	/// The sealed bytes here are too short for an ECIES message, so a server
	/// that decoded the key exchange first would refuse with another error.
	#[tokio::test]
	async fn a_key_exchange_with_an_abort_alert_is_refused() -> Result<(), Box<dyn Error>> {
		let identity = create_test_certificate();
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
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
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let other_random = [8u8; 32];
		let replayed = build_test_client_key_exchange(&identity, &other_random, None);

		let refusal = server.finish(carried_closing(&replayed)).await;
		assert!(matches!(refusal, Err(HandshakeError::ClientRandomMismatchReplay)));
	}

	/// A server that granted no budgets issued no receipt, so it refuses a key
	/// exchange whose payload acknowledges one.
	#[tokio::test]
	async fn an_acknowledgement_with_no_issued_receipt_is_refused() {
		let identity = create_test_certificate();
		let mut server = server_after_hello(&identity, PeerAuthentication::Anonymous).await;
		let stray_ack = Some(b"an acknowledgement of no receipt".as_slice());
		let key_exchange = build_test_client_key_exchange(&identity, &CLIENT_RANDOM, stray_ack);

		let refusal = server.finish(carried_closing(&key_exchange)).await;
		assert!(matches!(refusal, Err(HandshakeError::ReceiptMismatch)));
	}

	#[test]
	fn a_payload_that_is_not_der_is_refused() {
		let garbage = [0u8; 68];
		let parsed = SessionPayload::parse(&garbage);
		assert!(matches!(parsed, Err(HandshakeError::InvalidDecryptedPayloadSize)));
	}

	#[test]
	fn a_payload_with_a_short_base_secret_is_refused() {
		let short_key = session_payload_der([0u8; 31], [0u8; 32], None);
		let parsed = SessionPayload::parse(&short_key);
		let refused = matches!(parsed, Err(HandshakeError::InvalidKeySize { expected: 32, received: 31 }));
		assert!(refused);
	}

	/// The parser fails closed on a client random of another width.
	#[test]
	fn a_payload_with_a_short_client_random_is_refused() {
		let short_random = session_payload_der([0u8; 32], [0u8; 16], None);
		let parsed = SessionPayload::parse(&short_random);
		assert!(matches!(parsed, Err(HandshakeError::OctetStringLengthError(_))));
	}

	/// A well-formed payload parses into its base secret, its client random,
	/// and an absent acknowledgement.
	#[test]
	fn a_well_formed_payload_parses_into_its_session_data() -> Result<(), Box<dyn Error>> {
		let unanswered = session_payload_der([3u8; 32], [5u8; 32], None);
		let payload = SessionPayload::parse(&unanswered)?;
		assert_eq!(payload.base.as_bytes(), [3u8; 32]);
		assert_eq!(payload.client_random, [5u8; 32]);
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

//! The helpers and fixtures that the security threat integration tests share.
//!
//! It gives one protocol-agnostic interface over the handshake backends (HPKE,
//! CMS), so each threat test runs against every backend from one body.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::{
	asn1::GcmParameters,
	cms::content_info::ContentInfo,
	cms::enveloped_data::RecipientInfo,
	cms::signed_data::SignedData,
	constants::{TIGHTBEAM_CLOSING_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO},
	crypto::{
		aead::{Aes128Gcm, Aes128GcmOid, Aes256Gcm, Aes256GcmOid},
		cms::{AuthEnvelopedData, EnvelopeError, Opener},
		exchange::{Ecdhe, KeyExchange, KeyExchangeError, KeyShare, ReplyKind},
		hash::Sha3_256,
		kdf::{Hkdf, HkdfSha3_256},
		profiles::{
			AeadProvider, Aes128Wrap, Aes256Wrap, CryptoProvider, DefaultCryptoProvider, DigestProvider, KdfProvider,
			Kek, KeyExchangeProvider, KeyWrapProvider, NoStrengthFloor, ProfileStrengthPolicy, SecurityProfile,
			SecurityProfileDesc, SecurityStrength, SigningProvider,
		},
		secret::SecretSlice,
		sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey},
		sign::SigningIdentity,
		x509::error::CertificateValidationError,
		x509::policy::CertificateValidation,
		x509::Certificate,
	},
	der::{
		asn1::ObjectIdentifier, asn1::OctetString, asn1::OctetStringRef, oid::AssociatedOid, Any, Decode, Encode, Tag,
	},
	random::CryptoRngCore,
	spki::SubjectPublicKeyInfoRef,
	testing::{error::TestingError, SeededStream},
	trace::TraceCollector,
	transport::handshake::{
		negotiation::{ProfilePolicy, SecurityOffer},
		Client, ClientFlow, ClientHandshakeProtocol, ClientHello, Handshake, HandshakeError, HandshakeMessage,
		HandshakeProtocolKind, HandshakeProvider, Hpke, Server, ServerFlow, ServerHandshake, ServerHandshakeProtocol,
	},
	transport::tcp::r#async::TokioListener,
	transport::wire_der::WireDer,
	transport::{Arrived, ClientBuilder, ConnectionBuilder, TransportEncryptionConfig, WireEnvelope},
	urn::Urn,
	TightBeamError,
};

use crate::common::security::{
	combined_trust, default_security_profile, expectation_failure, hpke_client_config, pinning_validator,
	weak_security_profile, ClientMaterials, ServerMaterials,
};
use crate::common::transport::bind_on_loopback;
use crate::security::live::{AttackStep, FrameEdit, FrameSlot, LiveHandshake, REPLY_FRAME};

#[cfg(feature = "transport-cms")]
use crate::common::transport::TestCmsServerExt;
#[cfg(feature = "transport-cms")]
use tightbeam::crypto::hpke::DhKemSecp256k1;
#[cfg(feature = "transport-cms")]
use tightbeam::oids::{AES_128_GCM, AES_256_GCM};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::Cms;

/// A security profile on AES-128-GCM, which is weaker than the default
/// AES-256-GCM.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<k256::Secp256k1>;

	type KeyWrapOid = Aes128Wrap;
}

/// A crypto provider on AES-128-GCM, for a downgrade attack test. Its AEAD
/// key is 128 bits, below the default floor, so it names [`NoStrengthFloor`]
/// as its floor.
#[derive(Debug, Default, Clone, Copy)]
pub struct Aes128CryptoProvider {
	profile: Aes128Profile,
}

impl DigestProvider for Aes128CryptoProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for Aes128CryptoProvider {
	type AeadCipher = Aes128Gcm;
}

impl SigningProvider for Aes128CryptoProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for Aes128CryptoProvider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for Aes128CryptoProvider {
	type KeyExchange = Ecdhe<k256::Secp256k1>;
}

impl KeyWrapProvider for Aes128CryptoProvider {
	type KeyWrap = Aes128Wrap;
}

impl CryptoProvider for Aes128CryptoProvider {
	type Profile = Aes128Profile;
	type Kem = tightbeam::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}

	fn strength_floor() -> &'static (dyn ProfileStrengthPolicy + Send + Sync) {
		&NoStrengthFloor
	}
}

/// The exchange that [`KnownExchange`] runs through.
type HouseExchange = Ecdhe<k256::Secp256k1>;

/// ECDH over secp256k1 whose two scalars are fixed, so a test holds the secret
/// of each handshake under it. The OS source of a handshake fills every draw
/// of [`HouseExchange`], so this exchange draws from a seeded stream.
#[derive(Debug, Default, Clone, Copy)]
pub struct KnownExchange;

impl AssociatedOid for KnownExchange {
	const OID: ObjectIdentifier = HouseExchange::OID;
}

/// One share of [`KnownExchange`].
pub struct KnownShare(<HouseExchange as KeyExchange>::Offer);

impl KeyShare<KnownExchange> for KnownShare {
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		KeyShare::<HouseExchange>::from_octets(octets).map(Self)
	}

	fn to_octets(&self) -> Vec<u8> {
		KeyShare::<HouseExchange>::to_octets(&self.0)
	}

	fn collapses_into(&self, key: &<HouseExchange as KeyExchange>::StaticKey) -> bool {
		KeyShare::<HouseExchange>::collapses_into(&self.0, key)
	}
}

impl KeyExchange for KnownExchange {
	type Offer = KnownShare;
	type Reply = KnownShare;
	type Pending = <HouseExchange as KeyExchange>::Pending;
	type StaticKey = <HouseExchange as KeyExchange>::StaticKey;

	const REPLY: ReplyKind = <HouseExchange as KeyExchange>::REPLY;

	fn strength() -> SecurityStrength {
		HouseExchange::strength()
	}

	fn offer(_rng: &mut dyn CryptoRngCore) -> (Self::Pending, KnownShare) {
		let (pending, offer) = HouseExchange::offer(&mut SeededStream(1));
		(pending, KnownShare(offer))
	}

	fn respond(
		offer: &KnownShare,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<(KnownShare, SecretSlice<u8>), KeyExchangeError> {
		let (reply, shared) = HouseExchange::respond(&offer.0, &mut SeededStream(2))?;
		Ok((KnownShare(reply), shared))
	}

	fn complete(pending: &Self::Pending, reply: &KnownShare) -> Result<SecretSlice<u8>, KeyExchangeError> {
		HouseExchange::complete(pending, &reply.0)
	}

	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self::StaticKey> {
		HouseExchange::static_key(spki)
	}
}

impl KnownExchange {
	/// The secret of the exchange of every handshake under [`KnownExchange`].
	pub fn secret() -> Result<Vec<u8>, TightBeamError> {
		let (_, offer) = Self::offer(&mut SeededStream(1));
		let (_, shared) = Self::respond(&offer, &mut SeededStream(2)).map_err(|_| expectation_failure("no share"))?;
		Ok(shared.with(|secret| secret.to_vec()))
	}
}

/// The default profile, over [`KnownExchange`].
#[derive(Debug, Default, Clone, Copy)]
pub struct KnownExchangeProfile;

impl SecurityProfile for KnownExchangeProfile {
	type Digest = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = KnownExchange;

	type KeyWrapOid = Aes256Wrap;
}

/// The default provider, over [`KnownExchange`].
#[derive(Debug, Default, Clone, Copy)]
pub struct KnownExchangeProvider {
	profile: KnownExchangeProfile,
}

impl DigestProvider for KnownExchangeProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for KnownExchangeProvider {
	type AeadCipher = Aes256Gcm;
}

impl SigningProvider for KnownExchangeProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for KnownExchangeProvider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for KnownExchangeProvider {
	type KeyExchange = KnownExchange;
}

impl KeyWrapProvider for KnownExchangeProvider {
	type KeyWrap = Aes256Wrap;
}

impl CryptoProvider for KnownExchangeProvider {
	type Profile = KnownExchangeProfile;
	type Kem = tightbeam::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The direction a handshake message travels in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
	/// The client sends the message to the server.
	ClientToServer,
	/// The server sends the message to the client.
	ServerToClient,
}

/// A single handshake message captured during the flow.
#[derive(Debug, Clone)]
pub struct CapturedMessage {
	/// The step number the protocol assigns this message, which is its
	/// [`FlowStep::index`].
	pub step: usize,
	/// The endpoint that sent the message.
	pub direction: Direction,
	/// The DER bytes of the message, as its sender encoded them.
	pub payload: Vec<u8>,
}

/// The record of one complete handshake, as
/// [`HandshakeProtocol::capture_full`] returns it.
#[derive(Debug, Clone)]
pub struct CapturedHandshake {
	/// Every message that the flow produces, in send order.
	pub messages: Vec<CapturedMessage>,
	/// The handshake backend that produces the capture.
	pub kind: HandshakeBackendKind,
}

impl CapturedHandshake {
	/// The last client-to-server message, the common replay target.
	pub fn final_client_message(&self) -> Option<&CapturedMessage> {
		self.messages.iter().rev().find(|m| m.direction == Direction::ClientToServer)
	}

	/// The reply, the one server-to-client message, which the server
	/// signs over the transcript of its client's opening.
	pub fn server_reply(&self) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.direction == Direction::ServerToClient)
	}

	/// The message captured at `step`.
	pub fn message_at(&self, step: usize) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.step == step)
	}
}

/// The boxed future a flow step returns, which borrows the session it runs on.
type FlowFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, TightBeamError>> + Send + 'a>>;

/// The container a handshake message travels in.
#[derive(Debug, Clone, Copy)]
pub enum Container {
	/// A `SignedData`.
	Signed,
	/// An `AuthEnvelopedData`.
	AuthEnveloped,
	/// A `ContentInfo` of type `id-data`, the HPKE hello.
	Data,
}

impl Container {
	/// Reads `der` as a message in this container, and keeps the bytes it
	/// arrived as.
	fn message(self, der: &[u8]) -> Result<HandshakeMessage, TightBeamError> {
		let message = match self {
			Self::Signed => HandshakeMessage::SignedData(Box::new(WireDer::try_from(der)?)),
			Self::AuthEnveloped => HandshakeMessage::AuthEnvelopedData(Box::new(WireDer::try_from(der)?)),
			Self::Data => HandshakeMessage::Data(Box::new(WireDer::try_from(der)?)),
		};

		Ok(message)
	}
}

/// One message in a handshake flow.
#[derive(Debug, Clone, Copy)]
pub struct FlowStep {
	/// The step number the protocol assigns this message.
	pub index: usize,
	/// The endpoint that sends it.
	pub direction: Direction,
	/// The container the message travels in.
	pub container: Container,
}

/// A handshake flow described as its ordered steps.
///
/// A backend states its step table and how one step advances to the next.
/// [`HandshakeProtocol`] walks that table to capture a handshake, and
/// [`HandshakeBackendKind::slot_of`] reads it to place an injection on the
/// wire, so the two name the same sequence.
pub trait HandshakeFlow: Send {
	/// The backend this flow belongs to.
	fn backend(&self) -> HandshakeBackendKind;

	/// The ordered steps this protocol exchanges.
	fn steps(&self) -> &'static [FlowStep];

	/// Builds the opening message, which the first step delivers.
	fn open(&mut self) -> FlowFuture<'_, Vec<u8>>;

	/// Hands `msg` to the endpoint that receives step `index`, and returns its
	/// answer, which is `None` when that endpoint ends the flow.
	fn advance<'a>(
		&'a mut self,
		index: usize,
		msg: &'a (impl AsRef<[u8]> + ?Sized + Sync),
	) -> FlowFuture<'a, Option<Vec<u8>>>;
}

/// The protocol-agnostic handshake operations that a threat test drives.
///
/// Every [`HandshakeFlow`] implements this trait from its step table, so a
/// backend states its sequence once and gets its capture from it.
pub trait HandshakeProtocol: Send {
	/// Runs a complete handshake, and captures every message that it exchanges.
	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake>;
}

impl<F: HandshakeFlow> HandshakeProtocol for F {
	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake> {
		Box::pin(async move {
			let steps = self.steps();
			let backend = HandshakeFlow::backend(self);
			let mut messages = Vec::with_capacity(steps.len());
			let mut pending = Some(self.open().await?);

			for step in steps {
				let Some(payload) = pending else {
					break;
				};

				pending = self.advance(step.index, &payload).await?;
				messages.push(CapturedMessage { step: step.index, direction: step.direction, payload });
			}

			Ok(CapturedHandshake { messages, kind: backend })
		})
	}
}

/// The handshake backends the harness can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandshakeBackendKind {
	/// The HPKE handshake.
	Hpke,
	/// The CMS handshake.
	#[cfg(feature = "transport-cms")]
	Cms,
}

impl HandshakeBackendKind {
	/// The ordered steps of this backend's flow.
	fn steps(self) -> &'static [FlowStep] {
		match self {
			Self::Hpke => HPKE_FLOW,
			#[cfg(feature = "transport-cms")]
			Self::Cms => CMS_FLOW,
		}
	}

	/// The step of this backend's flow at `index`.
	fn step(self, index: usize) -> Result<&'static FlowStep, TightBeamError> {
		let step = self.steps().iter().find(|step| step.index == index);
		step.ok_or_else(|| invalid_step_error(index))
	}

	/// The handshake protocol that a transport of this backend runs.
	pub fn protocol(self) -> HandshakeProtocolKind {
		match self {
			Self::Hpke => HandshakeProtocolKind::Hpke,
			#[cfg(feature = "transport-cms")]
			Self::Cms => HandshakeProtocolKind::Cms,
		}
	}

	/// The encryption configuration of a server of this backend over
	/// `materials`, under the default transport limits.
	pub fn server_config(self, materials: &ServerMaterials) -> TransportEncryptionConfig<DefaultCryptoProvider> {
		match self {
			Self::Hpke => TransportEncryptionConfig::new(materials.identity()),
			#[cfg(feature = "transport-cms")]
			Self::Cms => materials.cms.encryption_config(),
		}
	}

	/// Binds a listener on a free local port that serves this backend under
	/// the default transport limits, beside its address.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the socket fails to bind.
	pub async fn bind_listener(
		self,
		materials: &ServerMaterials,
	) -> Result<(TokioListener, SocketAddr), TightBeamError> {
		bind_on_loopback(self.server_config(materials)).await
	}

	/// A client builder of this backend that trusts the server of
	/// `materials` alone.
	///
	/// - An HPKE client pins the server certificate, and presents `identity` when it holds one.
	/// - A CMS client seals its opening to the key-agreement certificate of
	///   the server and signs its Finished, so it presents `identity`, or a
	///   fresh identity in its place.
	pub fn client_builder(
		self,
		materials: &ServerMaterials,
		identity: Option<SigningIdentity>,
	) -> ClientBuilder<TokioListener> {
		let builder = ClientBuilder::<TokioListener>::builder().with_handshake_protocol(self.protocol());
		let (builder, identity) = match self {
			Self::Hpke => {
				let store = combined_trust(&[&materials.certificate]);
				(builder.with_trust_store(store), identity)
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let identity = identity.unwrap_or_else(|| ClientMaterials::generate().identity());
				(builder.with_cms_server(materials.cms.trust()), Some(identity))
			}
		};

		match identity {
			Some(identity) => builder.with_client_identity(identity),
			None => builder,
		}
	}

	/// The frame that carries the message at step `index` of this backend's
	/// flow.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the flow holds no step at `index`.
	pub fn slot_of(self, index: usize) -> Result<FrameSlot, TightBeamError> {
		let step = self.step(index)?;
		let earlier = self.steps().iter().take_while(|earlier| earlier.index <= index);
		let ordinal = earlier.filter(|earlier| earlier.direction == step.direction).count();
		Ok(FrameSlot { direction: step.direction, ordinal })
	}

	/// The attack step that hands its endpoint `payload`, the DER of a
	/// message captured at step `index`, in place of the message at that
	/// step.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the flow holds no step at `index`, or `payload`
	///   is no message in the container of that step.
	pub fn replacement(self, index: usize, payload: impl AsRef<[u8]>) -> Result<AttackStep, TightBeamError> {
		let slot = self.slot_of(index)?;
		let message = self.step(index)?.container.message(payload.as_ref())?;
		Ok(AttackStep::replace(slot, message))
	}

	/// The attack step that tampers the reply of a live session in transit,
	/// as [`Self::tamper_server_message`] does. The reply stays the reply of
	/// the client that reads it, so only the check of the tamper can refuse
	/// it.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the flow of this backend holds no reply.
	pub fn tamper_reply(self) -> Result<AttackStep, TightBeamError> {
		let mut steps = self.steps().iter();
		let reply = steps.find(|step| step.direction == Direction::ServerToClient);
		let reply = reply.ok_or_else(|| expectation_failure("the flow holds no reply"))?;
		let tamper = move |message: HandshakeMessage| {
			let tampered = self.tamper_server_message(message.der())?;
			reply.container.message(&tampered)
		};

		Ok(AttackStep::new(REPLY_FRAME, FrameEdit::Rewrite(Box::new(tamper))))
	}

	/// Flips one byte of the signed content in this backend's server message.
	///
	/// It models a MITM attacker that changes the message in transit. It edits
	/// the decoded message and re-encodes it, so the result is well-formed DER
	/// that only a transcript or signature check can refuse.
	///
	/// - HPKE tampers the server random of the `ServerHandshake` the reply signs.
	/// - CMS tampers the first byte of the content the `ServerFinished` signs,
	///   which sits in the domain label ahead of the transcript hash.
	pub fn tamper_server_message(self, payload: impl AsRef<[u8]>) -> Result<Vec<u8>, TightBeamError> {
		let payload = payload.as_ref();
		match self {
			Self::Hpke => {
				let reply = Container::Signed.message(payload)?;
				let mut message = signed_handshake(reply.to_owned());
				let server_random = flip_first_byte(message.server_random.as_bytes())?;
				message.server_random = OctetString::new(server_random)?;
				Ok(rewritten_reply(reply, &message).der().to_vec())
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let mut signed_data = SignedData::from_der(payload)?;
				let carried = signed_data
					.encap_content_info
					.econtent
					.as_ref()
					.ok_or_else(|| expectation_failure("ServerFinished carries no content"))?;

				let content: OctetString = carried.decode_as()?;
				let tampered = OctetString::new(flip_first_byte(content.as_bytes())?)?;
				signed_data.encap_content_info.econtent = Some(Any::encode_from(&tampered)?);
				Ok(signed_data.to_der()?)
			}
		}
	}

	/// The reply of this backend as a MITM that decodes it and encodes it
	/// unchanged sends it on. It is the control of the tampers above: a
	/// handshake that completes through it shows that the re-encoding of a
	/// decoded reply alone refuses nothing.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the reply fails to decode or to encode.
	pub fn re_encoded_reply(self, reply: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
		match self {
			Self::Hpke => {
				let handshake = signed_handshake(reply.to_owned());
				Ok(rewritten_reply(reply, &handshake))
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let der = SignedData::from_der(reply.der())?.to_der()?;
				Container::Signed.message(&der)
			}
		}
	}
}

/// Copies `bytes`, and inverts the first byte of the copy.
fn flip_first_byte(bytes: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let mut flipped = bytes.to_vec();
	let first = flipped
		.first_mut()
		.ok_or_else(|| expectation_failure("tamper target is empty"))?;

	*first ^= 0xFF;

	Ok(flipped)
}

/// A validator that refuses every certificate with `CertificateDenied`, for a
/// scenario whose endpoint policy refuses the genuine peer.
#[derive(Debug, Clone, Copy)]
pub struct RejectAllValidator;

impl CertificateValidation for RejectAllValidator {
	fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
		Err(CertificateValidationError::CertificateDenied)
	}
}

/// A harness that spawns handshake sessions across every enabled backend.
///
/// When the harness holds a [`TraceCollector`], each spawn records the
/// observable events of its path, so a process spec orders the harness steps
/// beside the attack events.
#[derive(Clone)]
pub struct SecurityThreatHarness {
	materials: ServerMaterials,
	trace: Option<Arc<TraceCollector>>,
}

impl Default for SecurityThreatHarness {
	fn default() -> Self {
		Self { materials: ServerMaterials::fixed(), trace: None }
	}
}

impl SecurityThreatHarness {
	/// Observable CSP event: the harness is about to build a handshake session.
	pub const HARNESS_SPAWN_SESSION: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-session");
	/// Observable CSP event: the harness selects the HPKE backend for the
	/// session.
	pub const HARNESS_SPAWN_HPKE: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-hpke");
	/// Observable CSP event: the harness selects the CMS backend for the
	/// session.
	pub const HARNESS_SPAWN_CMS: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-cms");

	/// A harness that records its spawn events into `trace`.
	pub fn with_trace(trace: Arc<TraceCollector>) -> Self {
		Self { materials: ServerMaterials::fixed(), trace: Some(trace) }
	}

	/// The server materials of the harness, for test verification.
	pub fn materials(&self) -> &ServerMaterials {
		&self.materials
	}

	/// Emits a spawn event when the harness holds a trace collector.
	fn emit(&self, event: Urn<'static>) -> Result<(), TightBeamError> {
		if let Some(ref trace) = self.trace {
			trace.event(event)?;
		}

		Ok(())
	}

	/// Spawns a protocol session of `kind`, where both endpoints run the
	/// default security profile.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace collector refuses a spawn event, as in
	///   [`Self::spawn_with_profiles`].
	pub fn spawn(&self, kind: HandshakeBackendKind) -> Result<Box<dyn HandshakeProtocol>, TightBeamError> {
		let client_profiles = vec![default_security_profile()];
		let server_profiles = vec![default_security_profile()];
		self.spawn_with_profiles(kind, client_profiles, server_profiles)
	}

	/// Spawns a protocol session of `kind` with separate client and server
	/// profiles.
	///
	/// - The client offers `client_profiles`.
	/// - The server accepts `server_profiles`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace collector refuses a spawn event, as
	///   an injected fault of a `testing-fault` run does.
	pub fn spawn_with_profiles(
		&self,
		kind: HandshakeBackendKind,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> Result<Box<dyn HandshakeProtocol>, TightBeamError> {
		let client_profiles: Vec<SecurityProfileDesc> = client_profiles.into_iter().collect();
		let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();

		self.emit(Self::HARNESS_SPAWN_SESSION)?;
		self.emit(Self::spawn_event(kind))?;

		match kind {
			HandshakeBackendKind::Hpke => Ok(Box::new(Session::<Hpke, DefaultCryptoProvider>::with_profiles(
				&self.materials,
				client_profiles,
				server_profiles,
			))),
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => Ok(Box::new(Session::<Cms, DefaultCryptoProvider>::with_profiles(
				&self.materials,
				client_profiles,
				server_profiles,
			))),
		}
	}

	/// Spawns an HPKE session under [`KnownExchange`], whose secret a test
	/// holds.
	pub fn spawn_known_exchange(&self) -> Box<dyn HandshakeProtocol> {
		let profiles = [default_security_profile()];
		let session =
			Session::<Hpke, KnownExchangeProvider>::with_profiles(&self.materials, profiles.to_owned(), profiles);

		Box::new(session)
	}

	/// Starts a live handshake of `kind` over the server materials of this
	/// harness, for the attack of a threat scenario. It records the spawn
	/// events that [`Self::spawn`] records for `kind`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace collector refuses a spawn event, as
	///   an injected fault of a `testing-fault` run does.
	pub fn live(&self, kind: HandshakeBackendKind) -> Result<LiveHandshake, TightBeamError> {
		self.emit(Self::HARNESS_SPAWN_SESSION)?;
		self.emit(Self::spawn_event(kind))?;

		Ok(LiveHandshake::new(kind, self.materials.to_owned()))
	}

	/// The spawn event that names the backend `kind` of a session.
	fn spawn_event(kind: HandshakeBackendKind) -> Urn<'static> {
		match kind {
			HandshakeBackendKind::Hpke => Self::HARNESS_SPAWN_HPKE,
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => Self::HARNESS_SPAWN_CMS,
		}
	}
}

/// The error for an injection step at `index` that the handshake flow lacks.
fn invalid_step_error(index: usize) -> TightBeamError {
	TightBeamError::TestingError(TestingError::UnknownFlowStep(index))
}

/// The `AuthEnvelopedData` of `frame`, a record that the relay kept as it
/// travelled sealed on an established session.
///
/// # Errors
///
/// - [`TightBeamError`] -- `frame` is no wire envelope, or its record fails to decode.
/// - An expectation failure -- `frame` travels in the clear.
pub fn sealed_record(mut frame: Vec<u8>) -> Result<AuthEnvelopedData, TightBeamError> {
	let Arrived::Encrypted(record) = WireEnvelope::arrive(&mut frame)? else {
		return Err(expectation_failure("a record of an established session travels sealed"));
	};

	Ok(AuthEnvelopedData::from_der(record)?)
}

/// The wrapped content key and the GCM nonce of `envelope`, the two values
/// that each seal draws afresh.
///
/// # Errors
///
/// - [`TightBeamError`] -- the parameters of the content cipher are no `GCMParameters`.
/// - An expectation failure -- the envelope names no single `KEKRecipientInfo`, or no parameters.
pub fn fresh_values(envelope: &AuthEnvelopedData) -> Result<(Vec<u8>, Vec<u8>), TightBeamError> {
	let [RecipientInfo::Kekri(recipient)] = envelope.recipient_infos.0.as_slice() else {
		return Err(expectation_failure("the envelope carries one KEKRecipientInfo"));
	};

	let parameters = envelope.auth_encrypted_content_info.content_enc_alg.parameters.as_ref();
	let parameters = parameters.ok_or_else(|| expectation_failure("the content cipher carries its parameters"))?;
	let nonce = parameters.decode_as::<GcmParameters>()?.aes_nonce.into_bytes();
	Ok((recipient.encrypted_key.as_bytes().to_vec(), nonce))
}

/// The `ClientHello` that a captured HPKE hello carries, decoded from its DER.
fn captured_hello(hello: &[u8]) -> Result<ClientHello, TightBeamError> {
	let content_info = WireDer::<ContentInfo>::try_from(hello)?;
	let octets = content_info.value().content.decode_as::<OctetStringRef<'_>>()?;
	Ok(ClientHello::from_der(octets.as_bytes())?)
}

/// The `ServerHandshake` that a captured HPKE reply signs.
fn captured_handshake(reply: &[u8]) -> Result<ServerHandshake, TightBeamError> {
	let signed = SignedData::from_der(reply)?;
	let econtent = signed.encap_content_info.econtent;
	let econtent = econtent.ok_or_else(|| expectation_failure("the reply carries no content"))?;
	Ok(ServerHandshake::from_der(econtent.value())?)
}

/// The `client_random` of a captured HPKE hello.
pub fn captured_client_random(hello: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	Ok(captured_hello(hello)?.client_random.into_bytes())
}

/// The two ephemerals a captured HPKE handshake carries in the clear: the
/// client ephemeral `R` of the hello and the server ephemeral `E` of the
/// reply, each as its compressed SEC 1 bytes.
pub fn captured_ephemerals(hello: &[u8], reply: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TightBeamError> {
	let client_ephemeral = captured_hello(hello)?.client_ephemeral.into_bytes();
	let server_ephemeral = captured_handshake(reply)?.server_ephemeral.into_bytes();
	Ok((client_ephemeral, server_ephemeral))
}

/// The x-coordinate of the SEC 1 point `sec1`, which an ECDH output on it
/// shares with its negation.
pub fn x_coordinate(sec1: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let point = k256::PublicKey::from_sec1_bytes(sec1).map_err(|_| expectation_failure("no point of secp256k1"))?;
	let encoded = k256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&point, false);

	let x = encoded.x();
	let x = x.ok_or_else(|| expectation_failure("the identity point has no x-coordinate"))?;
	Ok(x.to_vec())
}

/// A passive observer of one captured HPKE handshake who later obtained the
/// server's static key.
///
/// Each candidate stands in for the ephemeral-ephemeral secret `ee` and runs
/// through the key schedule of the HPKE flow:
///
/// ```text
/// S       = client_random || server_random
/// hs      = HKDF-SHA3-256(ee, salt = S, info = "tb/session/kdf/v1")
/// closing = HKDF-SHA3-256(hs, salt = S, info = "tb/session/kdf/closing/v1")
/// ```
///
/// The candidates are:
///
/// - the all-zero secret,
/// - the static key's agreement with the client ephemeral `R` of the hello,
/// - the static key's agreement with the server ephemeral `E` of the reply, and
/// - the x-coordinate of `R` and of `E`.
pub struct StaticKeyObserver {
	closing: Vec<u8>,
	keks: Vec<Vec<u8>>,
}

/// The number of candidate closing keys a [`StaticKeyObserver`] derives.
pub const STATIC_KEY_CANDIDATES: usize = 5;

impl StaticKeyObserver {
	/// The observer of the captured `hello`, `reply`, and `closing` who holds
	/// `static_key`.
	pub fn new(
		hello: &[u8],
		reply: &[u8],
		closing: &[u8],
		static_key: &k256::SecretKey,
	) -> Result<Self, TightBeamError> {
		let hello = captured_hello(hello)?;
		let handshake = captured_handshake(reply)?;
		let salt = closing_salt(&hello, &handshake);
		let client_ephemeral = hello.client_ephemeral.as_bytes();
		let server_ephemeral = handshake.server_ephemeral.as_bytes();

		let candidates = [
			vec![0u8; 32],
			static_agreement(static_key, client_ephemeral)?,
			static_agreement(static_key, server_ephemeral)?,
			x_coordinate(client_ephemeral)?,
			x_coordinate(server_ephemeral)?,
		];

		let keks = candidates.iter().map(|ee| closing_key(ee, &salt)).collect::<Result<_, _>>()?;
		Ok(Self { closing: closing.to_vec(), keks })
	}

	/// The observer of the captured `hello`, `reply`, and `closing` who holds
	/// `ee`, the secret of the exchange, as its one candidate.
	pub fn holding(hello: &[u8], reply: &[u8], closing: &[u8], ee: &[u8]) -> Result<Self, TightBeamError> {
		let salt = closing_salt(&captured_hello(hello)?, &captured_handshake(reply)?);
		Ok(Self { closing: closing.to_vec(), keks: vec![closing_key(ee, &salt)?] })
	}

	/// Opens the closing under each candidate closing key, with the key
	/// identifier the closing names, and reports each outcome.
	pub async fn closing_attempts(&self) -> Result<Vec<Result<SecretSlice<u8>, EnvelopeError>>, TightBeamError> {
		let mut attempts = Vec::with_capacity(self.keks.len());
		for kek in &self.keks {
			let envelope = AuthEnvelopedData::from_der(&self.closing)?;
			let content_type = envelope.auth_encrypted_content_info.content_type;
			let key_identifier = kek_identifier(&envelope)?;
			let kek = Kek::try_from(kek.as_slice())?;
			let opener = Opener::Kek { kek, key_identifier: &key_identifier };
			let attempt = envelope.open::<DefaultCryptoProvider>(&self.closing, &opener, content_type);
			attempts.push(attempt.await);
		}

		Ok(attempts)
	}
}

/// The salt of the key schedule of a captured handshake: the client random
/// and the server random.
fn closing_salt(hello: &ClientHello, handshake: &ServerHandshake) -> Vec<u8> {
	[hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat()
}

/// The ECDH output of `static_key` with the SEC 1 point `peer`.
fn static_agreement(static_key: &k256::SecretKey, peer: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let peer = k256::PublicKey::from_sec1_bytes(peer).map_err(|_| expectation_failure("no point of secp256k1"))?;
	let shared = k256::ecdh::diffie_hellman(static_key.to_nonzero_scalar(), peer.as_affine());
	Ok(shared.raw_secret_bytes().to_vec())
}

/// The closing key of the HPKE key schedule over the candidate `ee` under
/// `salt`, through an HKDF-SHA3-256 of its own.
pub fn closing_key(ee: &[u8], salt: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let mut handshake_secret = [0u8; 32];
	let mut kek = vec![0u8; 32];
	let failed = |_| expectation_failure("HKDF refused a 32-byte output");
	let session = Hkdf::<Sha3_256>::new(Some(salt), ee);
	let expanded = session.expand(TIGHTBEAM_SESSION_KDF_INFO, &mut handshake_secret);
	expanded.map_err(failed)?;

	let closing = Hkdf::<Sha3_256>::new(Some(salt), &handshake_secret);
	let expanded = closing.expand(TIGHTBEAM_CLOSING_KDF_INFO, &mut kek);
	expanded.map_err(failed)?;
	Ok(kek)
}

/// The `kekid.keyIdentifier` of the one `KEKRecipientInfo` of `envelope`.
fn kek_identifier(envelope: &AuthEnvelopedData) -> Result<Vec<u8>, TightBeamError> {
	let [RecipientInfo::Kekri(recipient)] = envelope.recipient_infos.0.as_slice() else {
		return Err(expectation_failure("the closing carries one KEKRecipientInfo"));
	};

	Ok(recipient.kek_id.kek_identifier.as_bytes().to_vec())
}

/// The three messages an HPKE handshake exchanges.
const HPKE_FLOW: &[FlowStep] = &[
	FlowStep { index: 0, direction: Direction::ClientToServer, container: Container::Data },
	FlowStep { index: 1, direction: Direction::ServerToClient, container: Container::Signed },
	FlowStep {
		index: 2,
		direction: Direction::ClientToServer,
		container: Container::AuthEnveloped,
	},
];

/// The three messages a CMS handshake exchanges. The odd steps between them
/// are the receiving half of each message, so the table lists only the even
/// steps.
#[cfg(feature = "transport-cms")]
const CMS_FLOW: &[FlowStep] = &[
	FlowStep {
		index: 0,
		direction: Direction::ClientToServer,
		container: Container::AuthEnveloped,
	},
	FlowStep { index: 2, direction: Direction::ServerToClient, container: Container::Signed },
	FlowStep {
		index: 4,
		direction: Direction::ClientToServer,
		container: Container::AuthEnveloped,
	},
];

/// A handshake protocol the harness runs sessions of, under provider `P`.
///
/// The library's flow markers implement it, and [`Session`] drives the client
/// and the server handshake that the flow builds.
pub trait SessionFlow<P: HandshakeProvider>: ClientFlow<P> + ServerFlow<P> {
	/// The backend this flow belongs to.
	const BACKEND: HandshakeBackendKind;

	/// A client that admits the server of `materials`, sends `offer`, and
	/// admits the selection under `policy`.
	fn client(
		materials: &ServerMaterials,
		offer: SecurityOffer,
		policy: ProfilePolicy<P>,
	) -> Handshake<Client, Self, P>;

	/// An anonymous-client server over `materials` that runs `profiles` and
	/// chooses among them under `policy`.
	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Handshake<Server, Self, P>;
}

impl<P: HandshakeProvider> SessionFlow<P> for Hpke {
	const BACKEND: HandshakeBackendKind = HandshakeBackendKind::Hpke;

	fn client(
		materials: &ServerMaterials,
		offer: SecurityOffer,
		policy: ProfilePolicy<P>,
	) -> Handshake<Client, Self, P> {
		let mut config = hpke_client_config(pinning_validator(&materials.certificate));
		config.security_offer = Some(offer);
		config.profiles = policy;
		Handshake::client(config)
	}

	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Handshake<Server, Self, P> {
		let mut config = materials.hpke_server_config(profiles);
		config.policy = policy;
		Handshake::server(config)
	}
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider<Kem = DhKemSecp256k1>> SessionFlow<P> for Cms {
	const BACKEND: HandshakeBackendKind = HandshakeBackendKind::Cms;

	/// The client pins the server's key-agreement certificate and presents a
	/// fresh identity.
	fn client(
		materials: &ServerMaterials,
		offer: SecurityOffer,
		policy: ProfilePolicy<P>,
	) -> Handshake<Client, Self, P> {
		let client_materials = ClientMaterials::generate();
		let identity = client_materials.identity();

		let mut config = materials.cms_client_config(identity);
		config.security_offer = Some(offer);
		config.profiles = policy;
		Handshake::client(config)
	}

	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Handshake<Server, Self, P> {
		let mut config = materials.cms_server_config(profiles);
		config.policy = policy;
		Handshake::server(config)
	}
}

/// One handshake of flow `F` under provider `P`, with both of its endpoints.
pub struct Session<F: SessionFlow<P>, P: HandshakeProvider> {
	client: Handshake<Client, F, P>,
	server: Handshake<Server, F, P>,
}

impl<F: SessionFlow<P>, P: HandshakeProvider> Session<F, P> {
	/// A session where the client offers `client_profiles` and the
	/// server runs `server_profiles`, each endpoint under the floor of `P`.
	fn with_profiles(
		materials: &ServerMaterials,
		client_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
		server_profiles: impl IntoIterator<Item = SecurityProfileDesc>,
	) -> Self {
		let offer = SecurityOffer::new(client_profiles);
		let server_profiles: Vec<SecurityProfileDesc> = server_profiles.into_iter().collect();
		let policy = ProfilePolicy::new();

		Self {
			client: F::client(materials, offer, policy.clone()),
			server: F::server(materials, server_profiles, policy),
		}
	}
}

impl<F: SessionFlow<P>, P: HandshakeProvider> HandshakeFlow for Session<F, P> {
	fn backend(&self) -> HandshakeBackendKind {
		F::BACKEND
	}

	fn steps(&self) -> &'static [FlowStep] {
		F::BACKEND.steps()
	}

	fn open(&mut self) -> FlowFuture<'_, Vec<u8>> {
		Box::pin(async move {
			let opening = ClientHandshakeProtocol::start(&mut self.client).await?;
			Ok(opening.der().to_vec())
		})
	}

	fn advance<'a>(
		&'a mut self,
		index: usize,
		msg: &'a (impl AsRef<[u8]> + ?Sized + Sync),
	) -> FlowFuture<'a, Option<Vec<u8>>> {
		let msg = msg.as_ref();
		Box::pin(async move {
			let step = F::BACKEND.step(index)?;

			// The server answers the opening with its reply and ends the flow
			// at the closing. The client answers the reply with its closing.
			let message = step.container.message(msg)?;
			let answer = match step.direction {
				Direction::ClientToServer => self.server.handle_request(message).await?,
				Direction::ServerToClient => self.client.handle_response(message).await?,
			};

			Ok(answer.map(|answer| answer.der().to_vec()))
		})
	}
}

/// A downgrade of one handshake of flow `F`: a victim that offers the strong
/// profile ahead of the weak one, a server of the victim on the strong profile,
/// and a client and a server of the MITM on the weak profile alone. The two
/// sides share their server materials, so a reply of the weak server names the
/// server that the victim trusts.
pub struct DowngradeAttack<F>
where
	F: SessionFlow<DefaultCryptoProvider> + SessionFlow<Aes128CryptoProvider>,
{
	victim: Session<F, DefaultCryptoProvider>,
	weak: Session<F, Aes128CryptoProvider>,
}

impl<F> DowngradeAttack<F>
where
	F: SessionFlow<DefaultCryptoProvider> + SessionFlow<Aes128CryptoProvider>,
{
	/// The attack on one handshake with the server of `materials`.
	pub fn new(materials: &ServerMaterials) -> Self {
		let strong = strong_security_profile();
		let weak = weak_security_profile();
		Self {
			victim: Session::with_profiles(materials, [strong.to_owned(), weak.to_owned()], [strong]),
			weak: Session::with_profiles(materials, [weak.to_owned()], [weak]),
		}
	}

	/// The opening of the victim.
	pub fn victim_opening(&mut self) -> Result<HandshakeMessage, HandshakeError> {
		self.victim.client.start()
	}

	/// An opening that the MITM seals itself, which offers the weak profile
	/// alone.
	pub fn mitm_opening(&mut self) -> Result<HandshakeMessage, HandshakeError> {
		self.weak.client.start()
	}

	/// The answer of the server of the victim to `opening`.
	pub async fn strong_reply(&mut self, opening: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		self.victim.server.reply(opening).await
	}

	/// The answer of the server on the weak profile to `opening`.
	pub async fn weak_reply(&mut self, opening: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		self.weak.server.reply(opening).await
	}

	/// The verdict of the victim on `reply`: its closing, or its refusal.
	pub async fn victim_reads(&mut self, reply: HandshakeMessage) -> Result<HandshakeMessage, HandshakeError> {
		self.victim.client.respond(reply).await
	}
}

/// `opening` with the weak entry of its sealed offer forged in place, by a MITM
/// that holds no key of the seal.
///
/// The seal runs AES-256-GCM, so AES-128-GCM appears in the offer alone. A
/// server selects the strong entry, so the tag of the seal is the check that
/// meets the forged entry. The two OIDs have one length, so the DER stays well
/// formed.
#[cfg(feature = "transport-cms")]
pub fn forge_sealed_offer(opening: &HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let mut der = opening.der().to_vec();
	let weak = AES_128_GCM.as_bytes();
	let at = der.windows(weak.len()).position(|window| window == weak);
	let at = at.ok_or_else(|| expectation_failure("the opening names no AES-128-GCM"))?;

	// The forged bytes travel as they are, so the seal meets the forged entry
	// and no re-encoding.
	der[at..at + weak.len()].copy_from_slice(AES_256_GCM.as_bytes());
	Container::AuthEnveloped.message(&der)
}

/// The sealed closing with the middle byte of its encrypted content flipped.
/// A flipped content byte is the one change on the wire that a MITM can make
/// to what the closing seals: the client Finished or the anonymous
/// attributes, and the acknowledgement inside either.
pub fn flip_sealed_content(sealed_closing: &AuthEnvelopedData) -> Result<AuthEnvelopedData, TightBeamError> {
	let mut tampered = sealed_closing.to_owned();
	let content = tampered.auth_encrypted_content_info.encrypted_content.as_ref();
	let content = content.ok_or_else(|| expectation_failure("a sealed closing carries content"))?;
	let mut forged = content.as_bytes().to_vec();
	let middle = forged.len() / 2;

	forged[middle] ^= 0xFF;
	tampered.auth_encrypted_content_info.encrypted_content = Some(OctetString::new(forged)?);
	Ok(tampered)
}

/// The strong profile (AES-256-GCM) of a downgrade test: the profile of the
/// default provider.
pub fn strong_security_profile() -> SecurityProfileDesc {
	default_security_profile()
}

/// Whether `needle` appears as a contiguous window inside `haystack`.
#[cfg(feature = "transport-multiplex")]
pub fn contains_window(haystack: impl AsRef<[u8]>, needle: impl AsRef<[u8]>) -> bool {
	let haystack = haystack.as_ref();
	let needle = needle.as_ref();
	haystack.windows(needle.len()).any(|window| window == needle)
}

/// The `ServerHandshake` that `reply` signs as its content.
pub fn signed_handshake(reply: HandshakeMessage) -> ServerHandshake {
	let signed = reply.signed().expect("an HPKE reply is a SignedData").into_value();
	let econtent = signed.encap_content_info.econtent.expect("the reply carries its content");
	ServerHandshake::from_der(econtent.value()).expect("the reply signs a ServerHandshake")
}

/// `reply` with `handshake` in place of the content it signs, as a MITM forges
/// it. The signature and every attribute stay as the server made them.
pub fn rewritten_reply(reply: HandshakeMessage, handshake: &ServerHandshake) -> HandshakeMessage {
	let mut signed = reply.signed().expect("an HPKE reply is a SignedData").into_value();
	let der = handshake.to_der().expect("a ServerHandshake encodes");
	let content = Any::new(Tag::OctetString, der).expect("the content fits an OCTET STRING");
	signed.encap_content_info.econtent = Some(content);

	HandshakeMessage::try_from(signed).expect("the rewritten reply encodes")
}

/// A client and server pair of either backend that a receipt scenario drives
/// by hand.
#[cfg(feature = "transport-multiplex")]
mod budget_fixtures {
	use std::sync::Arc;

	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
	use tightbeam::transport::handshake::{
		ClientConfig, ClientFlow, ClientHandshakeProtocol, Handshake, PeerAuthentication, ServerConfig, ServerFlow,
		ServerHandshakeProtocol,
	};

	#[cfg(feature = "transport-cms")]
	use tightbeam::transport::handshake::Cms;

	use super::{default_security_profile, HandshakeBackendKind, ServerMaterials};
	use crate::common::security::{hpke_client_config_presenting, pinning_validator, ClientMaterials};
	use crate::security::live::ReceiptHooks;

	/// A mutually authenticated client and server with a budget-bearing
	/// transport offer, ready to drive by hand through the protocol traits.
	pub struct BudgetPair {
		/// The client, before its opening.
		pub client: Box<dyn ClientHandshakeProtocol>,
		/// The server, before the opening arrives.
		pub server: Box<dyn ServerHandshakeProtocol>,
	}

	impl ServerMaterials {
		/// Builds a [`BudgetPair`] of `kind`. The client presents the fixed
		/// identity, pins the server of these materials, and requests the
		/// `request` budgets. The server demands a client certificate within
		/// its validity period.
		pub fn budget_pair(&self, kind: HandshakeBackendKind, request: MuxBudgets, hooks: ReceiptHooks) -> BudgetPair {
			let offer = TransportOffer::mux(4).with_budgets(request);
			match kind {
				HandshakeBackendKind::Hpke => {
					let identity = ClientMaterials::fixed().identity();
					let client = hpke_client_config_presenting(pinning_validator(&self.certificate), identity);
					let server = self.hpke_server_config(vec![default_security_profile()]);
					Self::budget_pair_of(client, server, offer, hooks)
				}
				#[cfg(feature = "transport-cms")]
				HandshakeBackendKind::Cms => {
					let profile = default_security_profile();
					let pair = self.cms_pair(vec![profile], vec![profile], PeerAuthentication::Anonymous);
					Self::budget_pair_of::<Cms>(pair.client, pair.server, offer, hooks)
				}
			}
		}

		/// The pair of `client` and `server` once both offer `offer` and hold
		/// the `hooks`, and the server demands a client certificate.
		fn budget_pair_of<F>(
			mut client: ClientConfig<F, DefaultCryptoProvider>,
			mut server: ServerConfig<F, DefaultCryptoProvider>,
			offer: TransportOffer,
			hooks: ReceiptHooks,
		) -> BudgetPair
		where
			F: ClientFlow<DefaultCryptoProvider> + ServerFlow<DefaultCryptoProvider> + 'static,
		{
			let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator::default());
			client.transport_offer = Some(offer.to_owned());
			client.receipt_approver = hooks.approver;

			server.transport = Some(offer);
			server.transport_authorizer = hooks.authorizer;
			server.session_observer = hooks.observer;
			server.peer_authentication = PeerAuthentication::Anonymous.and(validator);

			BudgetPair {
				client: Box::new(Handshake::client(client)),
				server: Box::new(Handshake::server(server)),
			}
		}
	}
}

#[cfg(feature = "transport-multiplex")]
pub use budget_fixtures::*;

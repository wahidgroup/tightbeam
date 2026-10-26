//! This module holds the helpers and fixtures that the integration tests for
//! security threats share.
//!
//! The module gives one protocol-agnostic interface over the handshake
//! backends (HPKE, CMS), so each threat test runs against every backend from
//! one body.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tightbeam::{
	cms::content_info::ContentInfo,
	cms::enveloped_data::RecipientInfo,
	cms::signed_data::SignedData,
	constants::{TIGHTBEAM_CLOSING_KDF_INFO, TIGHTBEAM_SESSION_KDF_INFO},
	crypto::{
		aead::{Aes128Gcm, Aes128GcmOid},
		cms::{AuthEnvelopedData, EnvelopeError, Opener},
		hash::Sha3_256,
		kdf::{Hkdf, HkdfSha3_256},
		profiles::{
			AeadProvider, Aes128Wrap, CryptoProvider, CurveProvider, DefaultCryptoProvider, DigestProvider,
			KdfProvider, Kek, KeyWrapProvider, NoStrengthFloor, ProfileStrengthPolicy, SecurityProfile,
			SecurityProfileDesc, SigningProvider,
		},
		secret::SecretSlice,
		sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey},
		sign::SigningIdentity,
	},
	der::{asn1::OctetString, asn1::OctetStringRef, Any, Decode, Encode},
	prelude::TightBeamSocketAddr,
	testing::error::{FdrConfigError, TestingError},
	transport::handshake::{
		negotiation::{ProfilePolicy, SecurityOffer},
		Client, ClientFlow, ClientHandshakeProtocol, ClientHello, Handshake, HandshakeMessage, HandshakeProtocolKind,
		HandshakeProvider, Hpke, Server, ServerFlow, ServerHandshake, ServerHandshakeProtocol,
	},
	transport::tcp::r#async::TokioListener,
	transport::wire_der::WireDer,
	transport::{ClientBuilder, ConnectionBuilder, EncryptedProtocol, TransportEncryptionConfig},
	TightBeamError,
};

use crate::common::security::pinning_trust_store;
use crate::security::live::{AttackStep, FrameSlot, LiveHandshake};

// The shared fixtures live in the crate-wide `common` module, so each threat
// suite depends only on that module.
pub use crate::common::security::{
	default_security_profile, expectation_failure, hpke_client_config, hpke_server_config, pinning_validator,
	rewritten_reply, signed_handshake, weak_security_profile, ServerMaterials,
};

#[cfg(feature = "transport-cms")]
use crate::common::security::{cms_client_config, cms_server_config, ClientMaterials};
#[cfg(feature = "transport-cms")]
use tightbeam::crypto::hpke::DhKemSecp256k1;
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
	type Curve = k256::Secp256k1;

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

impl CurveProvider for Aes128CryptoProvider {
	type Curve = k256::Secp256k1;
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
	/// Return the last client-to-server message, the common replay target.
	pub fn final_client_message(&self) -> Option<&CapturedMessage> {
		self.messages.iter().rev().find(|m| m.direction == Direction::ClientToServer)
	}

	/// Return every client-to-server message.
	pub fn client_messages(&self) -> impl Iterator<Item = &CapturedMessage> {
		self.messages.iter().filter(|m| m.direction == Direction::ClientToServer)
	}

	/// Return the reply, the one server-to-client message, which the server
	/// signs over the transcript of its client's opening.
	pub fn server_reply(&self) -> Option<&CapturedMessage> {
		self.messages.iter().find(|m| m.direction == Direction::ServerToClient)
	}

	/// Return the message captured at `step`.
	#[allow(dead_code)]
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
	/// Read `der` as a message in this container, and keep the bytes it
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

	/// Build the opening message, which the first step delivers.
	fn open(&mut self) -> FlowFuture<'_, Vec<u8>>;

	/// Hand `msg` to the endpoint that receives step `index`, and return that
	/// endpoint's answer, which is `None` when that endpoint ends the flow.
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
#[allow(dead_code)]
pub trait HandshakeProtocol: Send {
	/// Return the backend kind for this session.
	fn kind(&self) -> HandshakeBackendKind;

	/// Run a complete handshake, and capture every message it exchanges.
	fn capture_full(&mut self) -> FlowFuture<'_, CapturedHandshake>;
}

impl<F: HandshakeFlow> HandshakeProtocol for F {
	fn kind(&self) -> HandshakeBackendKind {
		HandshakeFlow::backend(self)
	}

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
	/// The human-readable backend label, for logs and trace events.
	#[allow(dead_code)]
	pub fn label(self) -> &'static str {
		match self {
			Self::Hpke => "hpke",
			#[cfg(feature = "transport-cms")]
			Self::Cms => "cms",
		}
	}

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
		step.ok_or_else(|| invalid_step_error("step is not part of this handshake flow"))
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
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the CMS pair refuses its key-agreement identity.
	pub fn server_config(
		self,
		materials: &ServerMaterials,
	) -> Result<TransportEncryptionConfig<DefaultCryptoProvider>, TightBeamError> {
		let config = match self {
			Self::Hpke => TransportEncryptionConfig::new(materials.identity()),
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let config = TransportEncryptionConfig::new(materials.cms.signing_identity());
				config.with_key_agreement(materials.cms.key_agreement_identity())?
			}
		};

		Ok(config)
	}

	/// Bind a listener on a free local port that serves this backend under
	/// the default transport limits, beside its address.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the CMS pair refuses its key-agreement identity, or the socket fails to bind.
	pub async fn bind_listener(
		self,
		materials: &ServerMaterials,
	) -> Result<(TokioListener, SocketAddr), TightBeamError> {
		let config = self.server_config(materials)?;
		bind_on_loopback(config).await
	}

	/// A client builder of this backend that trusts the server of
	/// `materials` alone.
	///
	/// - An HPKE client pins the server certificate, and presents `identity` when it holds one.
	/// - A CMS client seals its opening to the key-agreement certificate of
	///   the server and signs its Finished, so it presents `identity`, or a
	///   fresh identity in its place.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trust store refuses the server certificate.
	pub fn client_builder(
		self,
		materials: &ServerMaterials,
		identity: Option<SigningIdentity>,
	) -> Result<ClientBuilder<TokioListener>, TightBeamError> {
		let builder = ClientBuilder::<TokioListener>::builder().with_handshake_protocol(self.protocol());
		let (builder, identity) = match self {
			Self::Hpke => {
				let store = pinning_trust_store(&materials.certificate)?;
				(builder.with_trust_store(store), identity)
			}
			#[cfg(feature = "transport-cms")]
			Self::Cms => {
				let identity = identity.unwrap_or_else(|| ClientMaterials::generate().identity());
				(builder.with_cms_server(materials.cms.trust()), Some(identity))
			}
		};

		let builder = match identity {
			Some(identity) => builder.with_client_identity(identity),
			None => builder,
		};

		Ok(builder)
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

	/// Flip one byte of the signed content in this backend's server message.
	///
	/// The edit models a MITM attacker that changes the message in transit. It
	/// goes through the decoded message and re-encodes it, so the result is
	/// well-formed DER that only a transcript or signature check can refuse.
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
				let content = signed_data
					.encap_content_info
					.econtent
					.as_ref()
					.ok_or_else(|| expectation_failure("ServerFinished carries no content"))?;

				let transcript_hash: OctetString = content.decode_as()?;
				let tampered_hash = OctetString::new(flip_first_byte(transcript_hash.as_bytes())?)?;
				signed_data.encap_content_info.econtent = Some(Any::encode_from(&tampered_hash)?);
				Ok(signed_data.to_der()?)
			}
		}
	}
}

/// Copy `bytes` with the first byte inverted.
fn flip_first_byte(bytes: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let mut flipped = bytes.to_vec();
	let first = flipped
		.first_mut()
		.ok_or_else(|| expectation_failure("tamper target is empty"))?;

	*first ^= 0xFF;

	Ok(flipped)
}

/// Bind a listener under `config` on a free loopback port, beside its
/// address.
///
/// # Errors
///
/// - [`TightBeamError`] -- the socket fails to bind.
pub async fn bind_on_loopback(
	config: TransportEncryptionConfig<DefaultCryptoProvider>,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, bound) = TokioListener::bind_with(addr, config).await?;
	Ok((listener, *bound))
}

use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;

/// A harness that spawns handshake sessions across every enabled backend.
///
/// The harness can hold a [`TraceCollector`]. When it does, each spawn records
/// the observable events of the path it takes, so a process spec orders the
/// steps of the harness beside the events of the attack.
#[derive(Clone)]
pub struct SecurityThreatHarness {
	materials: ServerMaterials,
	trace: Option<Arc<TraceCollector>>,
}

impl Default for SecurityThreatHarness {
	fn default() -> Self {
		Self { materials: ServerMaterials::generate(), trace: None }
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
	/// Observable CSP event: the harness enters the weak-cipher spawn path.
	pub const HARNESS_SPAWN_WEAK: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-weak");
	/// Observable CSP event: the harness selects the weak HPKE backend.
	pub const HARNESS_SPAWN_HPKE_WEAK: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-hpke-weak");
	/// Observable CSP event: the harness selects the weak CMS backend.
	pub const HARNESS_SPAWN_CMS_WEAK: Urn<'static> = tightbeam::urn!("test", "event:security-harness/spawn-cms-weak");

	/// Create a harness that records its spawn events into `trace`.
	pub fn with_trace(trace: Arc<TraceCollector>) -> Self {
		Self { materials: ServerMaterials::generate(), trace: Some(trace) }
	}

	/// Return the server materials for test verification.
	pub fn materials(&self) -> &ServerMaterials {
		&self.materials
	}

	/// Emit a spawn event when the harness holds a trace collector.
	fn emit(&self, event: Urn<'static>) -> Result<(), TightBeamError> {
		if let Some(ref trace) = self.trace {
			trace.event(event)?;
		}
		Ok(())
	}

	/// Spawn a protocol session of `kind`, where both endpoints run the default
	/// security profile.
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

	/// Spawn a protocol session of `kind` with separate client and server
	/// profiles, which a cross-session downgrade test needs.
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

	/// Start a live handshake of `kind` over the server materials of this
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

	/// Spawn a session of `kind` on the weak AES-128-GCM cipher, for a
	/// downgrade test.
	///
	/// - [`Aes128CryptoProvider`] runs AES-128 at the cipher level, and also
	///   names it in the profile descriptor OIDs.
	/// - The session is deliberately weak. Its provider names
	///   [`NoStrengthFloor`] as its floor, so the downgrade harness can capture
	///   the messages of an AES-128 session.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace collector refuses a spawn event, as
	///   an injected fault of a `testing-fault` run does.
	pub fn spawn_weak(&self, kind: HandshakeBackendKind) -> Result<Box<dyn HandshakeProtocol>, TightBeamError> {
		self.emit(Self::HARNESS_SPAWN_WEAK)?;
		match kind {
			HandshakeBackendKind::Hpke => {
				self.emit(Self::HARNESS_SPAWN_HPKE_WEAK)?;
				Ok(Box::new(Session::<Hpke, Aes128CryptoProvider>::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
				)))
			}
			#[cfg(feature = "transport-cms")]
			HandshakeBackendKind::Cms => {
				self.emit(Self::HARNESS_SPAWN_CMS_WEAK)?;
				Ok(Box::new(Session::<Cms, Aes128CryptoProvider>::with_profiles(
					&self.materials,
					vec![weak_security_profile()],
					vec![weak_security_profile()],
				)))
			}
		}
	}
}

/// Create the error for an invalid injection step.
fn invalid_step_error(msg: &'static str) -> TightBeamError {
	TightBeamError::TestingError(TestingError::InvalidFdrConfig(FdrConfigError {
		field: "inject_at_step",
		reason: msg,
	}))
}

/// Return `payload` with `extra` appended, as a MITM attacker that adds data
/// to a message sends it.
#[allow(dead_code)]
pub fn tamper_payload_append(payload: impl AsRef<[u8]>, extra: impl AsRef<[u8]>) -> Vec<u8> {
	let payload = payload.as_ref();
	let extra = extra.as_ref();

	let mut tampered = payload.to_vec();
	tampered.extend_from_slice(extra);
	tampered
}

/// Return the first `keep_bytes` bytes of `payload`, as a MITM attacker that
/// truncates a message sends it.
#[allow(dead_code)]
pub fn tamper_payload_truncate(payload: impl AsRef<[u8]>, keep_bytes: usize) -> Vec<u8> {
	let payload = payload.as_ref();
	payload.iter().take(keep_bytes).copied().collect()
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
		let salt = [hello.client_random.as_bytes(), handshake.server_random.as_bytes()].concat();
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

	/// Open the closing under each candidate closing key, with the key
	/// identifier the closing names, and report each outcome.
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
		let mut config = hpke_server_config(materials, profiles);
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

		let mut config = cms_client_config(materials, identity);
		config.security_offer = Some(offer);
		config.profiles = policy;
		Handshake::client(config)
	}

	fn server(
		materials: &ServerMaterials,
		profiles: Vec<SecurityProfileDesc>,
		policy: ProfilePolicy<P>,
	) -> Handshake<Server, Self, P> {
		let mut config = cms_server_config(materials, profiles);
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
	/// Create a session where the client offers `client_profiles` and the
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

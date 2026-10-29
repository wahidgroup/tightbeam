//! Live handshakes for the threat scenarios.
//!
//! A live handshake runs the two endpoints of one backend as `TcpTransport`s
//! on loopback, and the attacker's step in a frame relay between them. The
//! endpoint whose verdict a scenario reads holds the scenario trace, so the
//! production audit event of a refused attack reaches the spec of the
//! scenario.

use core::time::Duration;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::net::{TcpListener, TcpStream};

use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::der::Encode;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::HandshakeMessage;
use tightbeam::transport::protocols::{AsyncReadStream, AsyncWriteStream, SplittableStream};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioReadHalf, TokioStream, TokioWriteHalf};
use tightbeam::transport::{Arrived, EncryptedMessageIO, TransportLimits, WireEnvelope};
use tightbeam::TightBeamError;

#[cfg(feature = "transport-multiplex")]
use tightbeam::crypto::x509::policy::ExpiryValidator;
#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportAuthorizer, TransportOffer};
#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};

use crate::common::security::flip_sealed_content;
use crate::security::common::{
	bind_on_loopback, expectation_failure, Direction, HandshakeBackendKind, ServerMaterials,
};
use crate::transport::support::serve_one_handshake_message;

/// The transport that each endpoint of a live handshake runs.
pub type LiveTransport = TcpTransport<TokioStream>;

/// A change to the transport of one endpoint before its first handshake
/// message, such as its multiplexing offer or its receipt hooks.
type Configure = Box<dyn FnOnce(LiveTransport) -> LiveTransport + Send>;

/// A rewrite of the handshake message that one frame carries.
pub type MessageRewrite = Box<dyn FnOnce(HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> + Send>;

/// How long a server of a live handshake may take to end its handshake once
/// the client ended its own.
const LIVE_DEADLINE: Duration = Duration::from_secs(10);

/// The stream cap that each endpoint of a budget-bearing handshake offers.
#[cfg(feature = "transport-multiplex")]
const MUX_STREAMS: u32 = 4;

/// The opening of either backend, the first frame that the client sends.
pub const OPENING_FRAME: FrameSlot = FrameSlot { direction: Direction::ClientToServer, ordinal: 1 };

/// The reply of either backend, the first frame that the server sends.
pub const REPLY_FRAME: FrameSlot = FrameSlot { direction: Direction::ServerToClient, ordinal: 1 };

/// The closing of either backend, the second frame that the client sends.
pub const CLOSING_FRAME: FrameSlot = FrameSlot { direction: Direction::ClientToServer, ordinal: 2 };

/// One frame of a link: the direction it travels in and its position among
/// the frames of that direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameSlot {
	/// The direction the frame travels in.
	pub direction: Direction,
	/// The position of the frame among the frames of its direction, from 1.
	pub ordinal: usize,
}

impl FrameSlot {
	/// Whether the frame at this slot is a message of the handshake of either
	/// backend: the opening or the closing of the client, or the reply of the
	/// server.
	fn in_handshake(&self) -> bool {
		let last = match self.direction {
			Direction::ClientToServer => CLOSING_FRAME,
			Direction::ServerToClient => REPLY_FRAME,
		};

		self.ordinal <= last.ordinal
	}
}

/// What the attacker does to one frame in transit.
pub enum FrameEdit {
	/// Remove the frame from the link.
	Drop,
	/// Send the frame twice.
	Duplicate,
	/// Send the frame with its handshake message rewritten.
	Rewrite(MessageRewrite),
	/// Send the frame with its last octet flipped. The last octet of a record
	/// lies in its tag, so the edit forges a record that no key opens.
	FlipLastOctet,
}

impl FrameEdit {
	/// The edit that flips the middle byte of the sealed content of a
	/// closing, the one part of what the closing seals that a MITM can edit.
	pub fn flip_sealed_content() -> Self {
		Self::Rewrite(Box::new(|closing| {
			let sealed = closing.auth_enveloped()?;
			let flipped = flip_sealed_content(sealed.value())?;
			Ok(HandshakeMessage::try_from(flipped)?)
		}))
	}

	/// The frames that leave the relay in place of `frame`.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a rewrite fails to read the handshake message
	///   of `frame`, refuses it, or fails to encode its result.
	/// - An expectation failure -- `frame` holds no octet to flip.
	fn apply(self, frame: Vec<u8>) -> Result<Vec<Vec<u8>>, TightBeamError> {
		match self {
			Self::Drop => Ok(Vec::new()),
			Self::Duplicate => Ok(vec![frame.to_owned(), frame]),
			Self::Rewrite(rewrite) => {
				let carried = carried_message(frame)?;
				let message = rewrite(carried)?;
				let rewritten = WireEnvelope::Cleartext(message.into()).to_der()?;
				Ok(vec![rewritten])
			}
			Self::FlipLastOctet => {
				let mut forged = frame;
				let last = forged
					.last_mut()
					.ok_or_else(|| expectation_failure("the frame holds no octet"))?;
				*last ^= 0x01;
				Ok(vec![forged])
			}
		}
	}
}

/// The handshake message that `frame` carries in the clear.
fn carried_message(mut frame: Vec<u8>) -> Result<HandshakeMessage, TightBeamError> {
	let Arrived::Cleartext(envelope) = WireEnvelope::arrive(&mut frame)? else {
		return Err(expectation_failure("a handshake message travels in the clear"));
	};

	Ok(HandshakeMessage::try_from(envelope)?)
}

/// The attacker's step in a relay: one edit of the frame at one slot.
pub struct AttackStep {
	slot: FrameSlot,
	edit: FrameEdit,
}

impl AttackStep {
	/// The step that applies `edit` to the frame at `slot`.
	pub fn new(slot: FrameSlot, edit: FrameEdit) -> Self {
		Self { slot, edit }
	}

	/// The step that hands its endpoint `message` in place of the handshake
	/// message at `slot`.
	pub fn replace(slot: FrameSlot, message: HandshakeMessage) -> Self {
		Self::new(slot, FrameEdit::Rewrite(Box::new(move |_| Ok(message))))
	}
}

/// What a relay saw: each frame as it arrived, the fault that ended the
/// relay early, and the slot of the attacker's step while it waits for its
/// frame.
#[derive(Default)]
struct RelayRecord {
	frames: Vec<(FrameSlot, Vec<u8>)>,
	fault: Option<TightBeamError>,
	pending_step: Option<FrameSlot>,
}

/// The record of a relay, which its two directions and the scenario share.
#[derive(Default)]
struct RelayLog(Mutex<RelayRecord>);

impl RelayLog {
	/// Keep `frame`, as it arrived at `slot`.
	fn push(&self, slot: FrameSlot, frame: &[u8]) {
		let mut record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.frames.push((slot, frame.to_vec()));
	}

	/// Keep `fault`, which ended the relay early.
	fn fail(&self, fault: TightBeamError) {
		let mut record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.fault = Some(fault);
	}

	/// Take the fault that ended the relay early.
	fn take_fault(&self) -> Option<TightBeamError> {
		let mut record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.fault.take()
	}

	/// Mark that the attacker's step waits for its frame at `slot`.
	fn arm_step(&self, slot: FrameSlot) {
		let mut record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.pending_step = Some(slot);
	}

	/// Mark that the attacker's step reached its frame.
	fn apply_step(&self) {
		let mut record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.pending_step = None;
	}

	/// The slot of the attacker's step while it waits for its frame.
	fn pending_step(&self) -> Option<FrameSlot> {
		let record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		record.pending_step
	}

	/// The frame that arrived at `slot`.
	fn frame(&self, slot: FrameSlot) -> Option<Vec<u8>> {
		let record = self.0.lock().unwrap_or_else(PoisonError::into_inner);
		let frame = record.frames.iter().find(|(arrived, _)| *arrived == slot);
		frame.map(|(_, frame)| frame.to_owned())
	}
}

/// A frame-aware TCP relay in front of one server, which applies the
/// attacker's step and keeps each frame as it arrived.
///
/// The relay works on whole frames, so each edit is an act of an active
/// attacker on a well-formed envelope, which only a check of an endpoint can
/// refuse.
pub struct FrameRelay {
	addr: SocketAddr,
	log: Arc<RelayLog>,
}

impl FrameRelay {
	/// Bind a relay in front of `upstream` that applies `step` to the first
	/// connection it accepts.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the socket of the relay fails to bind.
	pub async fn spawn(upstream: SocketAddr, step: Option<AttackStep>) -> Result<Self, TightBeamError> {
		let listener = TcpListener::bind("127.0.0.1:0").await?;
		let addr = listener.local_addr()?;
		let log = Arc::new(RelayLog::default());
		if let Some(step) = &step {
			log.arm_step(step.slot);
		}

		let shared = Arc::clone(&log);

		tokio::spawn(async move {
			match Self::link(listener, upstream).await {
				Ok((inbound, outbound)) => Self::relay(inbound, outbound, step, &shared).await,
				Err(fault) => shared.fail(fault),
			}
		});

		Ok(Self { addr, log })
	}

	/// The address that the relay accepts its one client on.
	pub fn addr(&self) -> SocketAddr {
		self.addr
	}

	/// The frame that arrived at `slot`, as the endpoint sent it.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the fault that ended the relay early.
	/// - An expectation failure -- no frame arrived at `slot`.
	pub fn frame(&self, slot: FrameSlot) -> Result<Vec<u8>, TightBeamError> {
		self.check()?;

		let frame = self.log.frame(slot);
		frame.ok_or_else(|| expectation_failure("no frame arrived at the slot"))
	}

	/// Fail with the fault that ended the relay early, or when the attacker's
	/// step aims at a message of the handshake that it never reached. A
	/// handshake whose attack never ran therefore passes no check.
	///
	/// A step that aims at a frame past the handshake waits for traffic that
	/// the scenario sends later, which the refusal of the scenario asserts.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the step failed, or the relay failed to link its client to its server.
	/// - An expectation failure -- the step aims at a message of the handshake, which it never reached.
	pub fn check(&self) -> Result<(), TightBeamError> {
		if let Some(fault) = self.log.take_fault() {
			return Err(fault);
		}

		let unreached = self.log.pending_step().filter(FrameSlot::in_handshake);
		unreached.map_or(Ok(()), |_| Err(expectation_failure("the attack step never reached its frame")))
	}

	/// Accept the client on `listener`, and connect it to `upstream`.
	async fn link(listener: TcpListener, upstream: SocketAddr) -> Result<(TcpStream, TcpStream), TightBeamError> {
		let (inbound, _) = listener.accept().await?;
		let outbound = TcpStream::connect(upstream).await?;
		Ok((inbound, outbound))
	}

	/// Forward each frame between `inbound` and `outbound` until both
	/// directions end, and apply `step` in its direction.
	async fn relay(inbound: TcpStream, outbound: TcpStream, step: Option<AttackStep>, log: &RelayLog) {
		let (client_read, client_write) = TokioStream::from(inbound).into_split();
		let (server_read, server_write) = TokioStream::from(outbound).into_split();
		let (upward, downward) = match step {
			Some(step) if step.slot.direction == Direction::ClientToServer => (Some(step), None),
			downward => (None, downward),
		};

		tokio::join!(
			Self::forward(client_read, server_write, Direction::ClientToServer, upward, log),
			Self::forward(server_read, client_write, Direction::ServerToClient, downward, log),
		);
	}

	/// Forward each frame from `reader` to `writer`, and apply `step` to the
	/// frame at its slot.
	async fn forward(
		mut reader: TokioReadHalf,
		mut writer: TokioWriteHalf,
		direction: Direction,
		mut step: Option<AttackStep>,
		log: &RelayLog,
	) {
		let cap = TransportLimits::default().max_envelope();
		let mut ordinal = 0usize;

		// A read fails once the sender closes its link, and that close ends
		// this direction.
		while let Ok(frame) = reader.read_frame(cap).await {
			ordinal += 1;
			let slot = FrameSlot { direction, ordinal };
			log.push(slot, &frame);

			let edit = step.take_if(|step| step.slot == slot);
			let sent = match edit {
				Some(step) => {
					log.apply_step();
					step.edit.apply(frame)
				}
				None => Ok(vec![frame]),
			};

			let frames = match sent {
				Ok(frames) => frames,
				Err(fault) => return log.fail(fault),
			};

			for frame in frames {
				// A write fails once the receiver closes its link, and that
				// close ends this direction.
				if writer.write_frame(&frame).await.is_err() {
					return;
				}
			}
		}
	}
}

/// The setup of one endpoint of a live handshake.
#[derive(Default)]
struct EndpointSetup {
	/// The change to the transport of the endpoint, when it needs one.
	configure: Option<Configure>,
	/// The scenario trace, when the endpoint files its audit events there.
	trace: Option<TraceCollector>,
}

impl EndpointSetup {
	/// Returns `transport` with this setup applied.
	fn prepare(self, transport: LiveTransport) -> LiveTransport {
		let transport = match self.configure {
			Some(configure) => configure(transport),
			None => transport,
		};

		match self.trace {
			Some(trace) => transport.with_trace(trace),
			None => transport,
		}
	}
}

/// One handshake of a backend between two live endpoints, through a frame
/// relay that applies the attacker's step.
pub struct LiveHandshake {
	kind: HandshakeBackendKind,
	materials: ServerMaterials,
	client_validators: Vec<Arc<dyn CertificateValidation>>,
	client_identity: Option<SigningIdentity>,
	server_policy: Vec<Arc<dyn CertificateValidation>>,
	server: EndpointSetup,
	client: EndpointSetup,
	step: Option<AttackStep>,
}

impl LiveHandshake {
	/// A handshake of `kind` between a server that presents `materials` and
	/// a client that trusts that server alone. The relay forwards each frame
	/// unchanged until [`Self::with_step`] names the attacker's step.
	pub fn new(kind: HandshakeBackendKind, materials: ServerMaterials) -> Self {
		Self {
			kind,
			materials,
			client_validators: Vec::new(),
			client_identity: None,
			server_policy: Vec::new(),
			server: EndpointSetup::default(),
			client: EndpointSetup::default(),
			step: None,
		}
	}

	/// The server demands a client certificate, which each validator of
	/// `validators` runs on.
	pub fn with_client_validators(
		mut self,
		validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>,
	) -> Self {
		self.client_validators = validators.into_iter().collect();
		self
	}

	/// The client presents `identity`.
	pub fn with_client_identity(mut self, identity: SigningIdentity) -> Self {
		self.client_identity = Some(identity);
		self
	}

	/// The client runs each validator of `validators` on the certificate of
	/// its server.
	pub fn with_server_policy(mut self, validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		self.server_policy = validators.into_iter().collect();
		self
	}

	/// The client files its audit events in `trace`.
	pub fn audit_client(mut self, trace: &TraceCollector) -> Self {
		self.client.trace = Some(trace.share());
		self
	}

	/// The server files its audit events in `trace`.
	pub fn audit_server(mut self, trace: &TraceCollector) -> Self {
		self.server.trace = Some(trace.share());
		self
	}

	/// The relay applies `step`.
	pub fn with_step(mut self, step: AttackStep) -> Self {
		self.step = Some(step);
		self
	}

	/// Run the handshake, and return the verdict of each endpoint beside the
	/// relay.
	///
	/// The client runs on the caller's task and the server on a task of its
	/// own. A client that refused drops its link, so the server ends its
	/// handshake too.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- a socket fails to bind or to connect, the client
	///   builder refuses its trust, the server task panics or ends no
	///   handshake within its deadline, or the relay fails.
	pub async fn run(self) -> Result<LiveOutcome, TightBeamError> {
		let Self {
			kind,
			materials,
			client_validators,
			client_identity,
			server_policy,
			server,
			client,
			step,
		} = self;

		// 1. Bind the server, and the relay in front of it.
		let config = kind.server_config(&materials)?.with_client_validators(client_validators);
		let (listener, server_addr) = bind_on_loopback(config).await?;
		let relay = FrameRelay::spawn(server_addr, step).await?;

		// 2. Serve the handshake on a task of its own.
		let server_task = tokio::spawn(async move {
			let (transport, _) = listener.accept().await?;
			let transport = transport.with_handshake_protocol(kind.protocol());
			let mut transport = server.prepare(transport);
			let verdict = Self::serve(&mut transport).await;
			Ok::<_, TightBeamError>((transport, verdict))
		});

		// 3. Run the client handshake through the relay.
		let builder = kind.client_builder(&materials, client_identity)?;
		let builder = builder.with_server_policy(server_policy);
		let stream = TcpStream::connect(relay.addr()).await?;
		let adopted = builder.adopt(TokioStream::from(stream))?;
		let mut transport = client.prepare(adopted.into_transport());
		let verdict = transport.perform_client_handshake().await;
		let client = verdict.map(|()| transport).map_err(TightBeamError::from);

		// 4. Join the server, and surface a fault of the relay ahead of the verdicts it caused.
		let joined = tokio::time::timeout(LIVE_DEADLINE, server_task).await;
		relay.check()?;

		let joined = joined.map_err(|_| expectation_failure("the server ended no handshake within the deadline"))?;
		let (transport, verdict) = joined.map_err(|_| expectation_failure("the server task panicked"))??;
		let server = verdict.map(|()| transport);

		Ok(LiveOutcome { client, server, relay })
	}

	/// Serve the two client messages of a handshake, the opening and the
	/// closing, and stop at the first refusal.
	async fn serve(transport: &mut LiveTransport) -> Result<(), TightBeamError> {
		serve_one_handshake_message(transport).await?;
		serve_one_handshake_message(transport).await
	}
}

/// The hooks of a budget-bearing live handshake.
#[cfg(feature = "transport-multiplex")]
#[derive(Default)]
pub struct ReceiptHooks {
	/// The policy on the server that grants the budgets and settles the
	/// receipt.
	pub authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// The approver that the client consults before it countersigns.
	pub approver: Option<Arc<dyn ReceiptApprover>>,
	/// The observer that the server reports each receipt outcome to.
	pub observer: Option<Arc<dyn SessionObserver>>,
}

#[cfg(feature = "transport-multiplex")]
impl LiveHandshake {
	/// A mutually authenticated handshake of `kind` over `materials`, whose
	/// client presents `identity` and requests `budgets`.
	///
	/// - The server demands a client certificate within its validity period.
	/// - Each endpoint offers multiplexing under the same budgets.
	/// - The server grants through the authorizer of `hooks` and reports to its observer.
	/// - The client countersigns the receipt through the approver of `hooks`.
	pub fn budget_bearing(
		kind: HandshakeBackendKind,
		materials: ServerMaterials,
		identity: SigningIdentity,
		budgets: MuxBudgets,
		hooks: ReceiptHooks,
	) -> Self {
		let ReceiptHooks { authorizer, approver, observer } = hooks;
		let offer = TransportOffer::mux(MUX_STREAMS).with_budgets(budgets);
		let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator::default());

		let client_offer = offer.to_owned();
		let client: Configure = Box::new(move |transport| {
			let transport = transport.with_mux_offer(Some(client_offer));
			match approver {
				Some(approver) => transport.with_receipt_approver(approver),
				None => transport,
			}
		});

		let server: Configure = Box::new(move |transport| {
			let mut transport = transport.with_mux_offer(Some(offer));
			if let Some(authorizer) = authorizer {
				transport = transport.with_transport_authorizer(authorizer);
			}
			if let Some(observer) = observer {
				transport = transport.with_session_observer(observer);
			}
			transport
		});

		let handshake = Self::new(kind, materials).with_client_validators([validator]);
		let mut handshake = handshake.with_client_identity(identity);
		handshake.client.configure = Some(client);
		handshake.server.configure = Some(server);
		handshake
	}
}

/// The verdict of each endpoint of a live handshake, beside its relay.
pub struct LiveOutcome {
	/// The client transport after its handshake, or the error that ended it.
	pub client: Result<LiveTransport, TightBeamError>,
	/// The server transport after its handshake, or the error that ended it.
	pub server: Result<LiveTransport, TightBeamError>,
	/// The relay, which holds each frame it saw.
	pub relay: FrameRelay,
}

impl LiveOutcome {
	/// The two transports, client first, once both endpoints completed the
	/// handshake.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the error that ended the handshake of the client or of the server.
	pub fn established(self) -> Result<(LiveTransport, LiveTransport), TightBeamError> {
		Ok((self.client?, self.server?))
	}

	/// Fail with `accepted` when the client completed the handshake.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the expectation failure `accepted`, when the client completed.
	pub fn refused_by_client(&self, accepted: &'static str) -> Result<(), TightBeamError> {
		if self.client.is_ok() {
			return Err(expectation_failure(accepted));
		}

		Ok(())
	}

	/// Fail with `accepted` when the server completed the handshake.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the expectation failure `accepted`, when the server completed.
	pub fn refused_by_server(&self, accepted: &'static str) -> Result<(), TightBeamError> {
		if self.server.is_ok() {
			return Err(expectation_failure(accepted));
		}

		Ok(())
	}
}

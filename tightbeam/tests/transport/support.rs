//! Shared functions for the transport integration tests.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use core::time::Duration;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{KeyCurves, KeyPurposes};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::TestFrame;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
use tightbeam::transport::handshake::HandshakeMessage;
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::state::SessionPhase;
use tightbeam::transport::tcp::r#async::{SplitTransport, TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	Arrived, ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol, MessageCollector, MessageIO,
	TransportEncryptionConfig, TransportError, TransportLimits, WireEnvelope,
};
use tightbeam::x509::Certificate;
use tightbeam::Frame;
use tightbeam::TightBeamError;

#[cfg(feature = "transport-multiplex")]
use core::future::IntoFuture;
#[cfg(feature = "transport-multiplex")]
use tightbeam::crypto::policy::Secp256k1Policy;
#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::receipt::StoredReceipt;
#[cfg(feature = "transport-multiplex")]
use tokio::sync::Notify;

#[cfg(feature = "transport-multiplex")]
use crate::common::poll::poll_until;
use crate::common::security::{expectation_failure, pinning_validator, ClientMaterials, ServerMaterials};

/// The number of reads a transport wait takes, one every 5 ms for 2 s.
#[cfg(feature = "transport-multiplex")]
const TRANSPORT_WAIT_ATTEMPTS: u32 = 400;

/// The interval between the reads of a transport wait.
#[cfg(feature = "transport-multiplex")]
const TRANSPORT_WAIT_INTERVAL: Duration = Duration::from_millis(5);

/// How long a scenario waits on its tokio clock for work on another task: a
/// signal that a handler or a server task raises, or a task that it joins.
#[cfg(feature = "transport-multiplex")]
const SCENARIO_WAIT_DEADLINE: Duration = Duration::from_secs(5);

/// Polls `ready` on the transport cadence and returns whether it held.
#[cfg(feature = "transport-multiplex")]
pub async fn await_transport(ready: impl FnMut() -> bool) -> bool {
	poll_until(TRANSPORT_WAIT_ATTEMPTS, TRANSPORT_WAIT_INTERVAL, ready).await
}

/// The output of `work` within [`SCENARIO_WAIT_DEADLINE`], or `None` once the
/// deadline passes first.
#[cfg(feature = "transport-multiplex")]
async fn within_deadline<F: IntoFuture>(work: F) -> Option<F::Output> {
	tokio::time::timeout(SCENARIO_WAIT_DEADLINE, work).await.ok()
}

/// Awaits `work` within [`SCENARIO_WAIT_DEADLINE`], and fails with
/// `expectation` when the deadline passes first, so a stalled server ends its
/// scenario at the deadline.
#[cfg(feature = "transport-multiplex")]
pub async fn await_within_deadline<F: IntoFuture>(
	work: F,
	expectation: &'static str,
) -> Result<F::Output, TightBeamError> {
	let finished = within_deadline(work).await;
	finished.ok_or_else(|| expectation_failure(expectation))
}

/// A signal that a handler or a server task raises, which a scenario awaits
/// only within [`SCENARIO_WAIT_DEADLINE`].
#[cfg(feature = "transport-multiplex")]
#[derive(Default)]
pub struct HandlerSignal(Notify);

#[cfg(feature = "transport-multiplex")]
impl HandlerSignal {
	/// Raises the signal for one wait. A raise before the wait stores a
	/// permit, so the wait that follows returns at once.
	pub fn raise(&self) {
		self.0.notify_one();
	}

	/// Awaits the raise, and fails with `expectation` when the deadline
	/// passes first.
	pub async fn wait(&self, expectation: &'static str) -> Result<(), TightBeamError> {
		await_within_deadline(self.0.notified(), expectation).await
	}

	/// Whether a task raises the signal before the deadline passes.
	pub async fn raised(&self) -> bool {
		within_deadline(self.0.notified()).await.is_some()
	}
}

/// Polls until the epoch receipt differs from `previous`, and returns the new
/// one, or `None` when the wait runs out.
#[cfg(feature = "transport-multiplex")]
pub async fn await_receipt_rotation<F>(current: F, previous: Option<&StoredReceipt>) -> Option<Arc<StoredReceipt>>
where
	F: Fn() -> Option<Arc<StoredReceipt>>,
{
	let mut rotated = None;
	let settled = await_transport(|| {
		rotated = current().filter(|receipt| Some(receipt.as_ref()) != previous);
		rotated.is_some()
	})
	.await;

	settled.then_some(rotated).flatten()
}

/// Serves one single-flight request. The reply carries the gate's status, and
/// the accepted frame back when that status is `Ok`.
pub async fn respond_echo<T: MessageCollector + Send>(mut transport: T) -> Result<(), TransportError> {
	let (request, status) = transport.collect_message().await?;
	let message = match status {
		TransitStatus::Ok => Some(Arc::try_unwrap(request).unwrap_or_else(|shared| (*shared).clone())),
		_ => None,
	};

	transport.send_response(status, message).await
}

/// A small labeled frame for multiplexed exchanges.
pub fn mux_frame(label: impl AsRef<str>) -> Frame {
	let label = label.as_ref();
	TestFrame::v0(Some(label), None)
}

/// A multiplexing offer that advertises `cap` peer-initiated streams.
pub fn mux_offer(cap: u32) -> TransportOffer {
	TransportOffer::mux(cap)
}

pub async fn await_ok<T, E>(task: JoinHandle<Result<T, E>>, panic_msg: &'static str) -> Result<T, TightBeamError>
where
	E: Into<TightBeamError>,
{
	let joined = task.await.map_err(|_| expectation_failure(panic_msg))?;
	let value = joined.map_err(Into::into)?;
	Ok(value)
}

pub async fn join_task<T>(task: JoinHandle<T>, panic_msg: &'static str) -> Result<T, TightBeamError> {
	let value = task.await.map_err(|_| expectation_failure(panic_msg))?;
	Ok(value)
}

pub async fn bind_encrypted_listener(
	materials: &ServerMaterials,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let config = TransportEncryptionConfig::new(materials.identity());
	bind_with_config(config).await
}

pub async fn bind_encrypted_listener_with_timeout(
	materials: &ServerMaterials,
	handshake_timeout: Duration,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let limits = TransportLimits { handshake_timeout, ..TransportLimits::default() };
	let config = TransportEncryptionConfig::new(materials.identity()).with_limits(limits);
	bind_with_config(config).await
}

async fn bind_with_config(
	config: TransportEncryptionConfig<DefaultCryptoProvider>,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, bound_addr) = TokioListener::bind_with(addr, config).await?;
	Ok((listener, *bound_addr))
}

pub async fn bind_mutual_listener(
	materials: &ServerMaterials,
	client_certificate: &Certificate,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	bind_mutual_listener_under(materials, client_certificate, KeyPurposes::HOUSE).await
}

/// Binds a listener that presents `materials`, pins `client_certificate` as
/// its one client, and admits each role under `key_purposes`.
pub async fn bind_mutual_listener_under(
	materials: &ServerMaterials,
	client_certificate: &Certificate,
	key_purposes: KeyPurposes,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let validators = vec![pinning_validator(client_certificate)];
	let config = TransportEncryptionConfig::new(materials.identity()).with_client_validators(validators);
	bind_with_config(config.with_key_purposes(key_purposes)).await
}

/// Binds a listener that presents the CMS server of `materials`, its signing
/// identity paired with its key-agreement identity, and pins
/// `client_certificate` as its one client.
#[cfg(feature = "transport-cms")]
pub async fn bind_cms_mutual_listener(
	materials: &ServerMaterials,
	client_certificate: &Certificate,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let validators = vec![pinning_validator(client_certificate)];
	let config = TransportEncryptionConfig::new(materials.cms.signing_identity());
	let config = config.with_key_agreement(materials.cms.key_agreement_identity())?;
	bind_with_config(config.with_client_validators(validators)).await
}

pub async fn connect_mutual_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
	client: &ClientMaterials,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	connect_mutual_client_under(addr, server_certificate, client, KeyPurposes::HOUSE).await
}

/// Connects a client that presents `client`, pins `server_certificate`, and
/// admits each role under `key_purposes`.
pub async fn connect_mutual_client_under(
	addr: SocketAddr,
	server_certificate: &Certificate,
	client: &ClientMaterials,
	key_purposes: KeyPurposes,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let builder = pinned_client(server_certificate)?.with_client_identity(client.identity());
	let builder = builder.with_key_purposes(key_purposes);
	let stream = TcpStream::connect(addr).await?;

	let adopted = builder.adopt(TokioStream::from(stream))?;
	Ok(adopted.into_transport())
}

/// The optional per-session hooks for mutual-auth handshakes.
#[derive(Default)]
pub struct MutualSessionHooks {
	/// The transport authorizer that the server installs, when set.
	pub authorizer: Option<Arc<dyn TransportAuthorizer>>,
	/// The receipt approver that the client installs, when set.
	pub approver: Option<Arc<dyn ReceiptApprover>>,
	/// The session observer that the server notifies, when set.
	pub observer: Option<Arc<dyn SessionObserver>>,
	/// The trace collector attached to both endpoints, whose production
	/// instrumentation emits session labels for spec assertions.
	pub trace: Option<TraceCollector>,
}

/// The established mutual-auth transports, with the peer identities that
/// receipt verification needs.
pub struct MutualTransports {
	/// The client transport, with its handshake complete.
	pub client: TcpTransport<TokioStream>,
	/// The server transport, with its handshake complete.
	pub server: TcpTransport<TokioStream>,
	/// The certificate that the server presents.
	pub server_certificate: Arc<Certificate>,
	/// The certificate that the client presents.
	pub client_certificate: Arc<Certificate>,
}

/// Establishes a mutual-auth client and server transport pair.
///
/// A budget-bearing session requires a client countersignature over the
/// session receipt.
pub async fn establish_mutual_transports(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	hooks: MutualSessionHooks,
) -> Result<MutualTransports, TightBeamError> {
	let materials = ServerMaterials::generate();
	let client_materials = ClientMaterials::generate();
	let key_purposes = KeyPurposes::HOUSE;
	establish_mutual_transports_of(client_offer, server_offer, hooks, &materials, &client_materials, key_purposes).await
}

/// Establishes a mutual-auth pair in which the server presents `materials`,
/// the client presents `client_materials`, and both endpoints admit each
/// role under `key_purposes`.
pub async fn establish_mutual_transports_of(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	hooks: MutualSessionHooks,
	materials: &ServerMaterials,
	client_materials: &ClientMaterials,
	key_purposes: KeyPurposes,
) -> Result<MutualTransports, TightBeamError> {
	let (listener, addr) = bind_mutual_listener_under(materials, &client_materials.certificate, key_purposes).await?;

	#[cfg(feature = "instrument")]
	let server_trace = hooks.trace.as_ref().map(TraceCollector::share);
	let server_task = tokio::spawn(async move {
		let (transport, _) = listener.accept().await?;
		let mut transport = transport.with_mux_offer(Some(server_offer));
		if let Some(authorizer) = hooks.authorizer {
			transport = transport.with_transport_authorizer(authorizer);
		}
		if let Some(observer) = hooks.observer {
			transport = transport.with_session_observer(observer);
		}

		#[cfg(feature = "instrument")]
		if let Some(trace) = server_trace {
			transport = transport.with_trace(trace);
		}

		// An HPKE handshake takes two client messages: the hello and the
		// closing.
		serve_one_handshake_message(&mut transport).await?;
		serve_one_handshake_message(&mut transport).await?;
		Ok::<_, TightBeamError>(transport)
	});

	let mut client = connect_mutual_client_under(addr, &materials.certificate, client_materials, key_purposes).await?;
	client = client.with_mux_offer(Some(client_offer));

	if let Some(approver) = hooks.approver {
		client = client.with_receipt_approver(approver);
	}

	#[cfg(feature = "instrument")]
	if let Some(trace) = hooks.trace {
		client = client.with_trace(trace);
	}

	client.perform_client_handshake().await?;

	let server = await_ok(server_task, "server handshake task must not panic").await?;
	Ok(MutualTransports {
		client,
		server,
		server_certificate: Arc::clone(&materials.certificate),
		client_certificate: Arc::clone(&client_materials.certificate),
	})
}

pub async fn serve_one_handshake_message(transport: &mut TcpTransport<TokioStream>) -> Result<(), TightBeamError> {
	let mut wire_bytes = transport.read_envelope_bytes().await?;
	let wire_envelope = WireEnvelope::arrive(&mut wire_bytes)?;
	let envelope = match wire_envelope {
		Arrived::Cleartext(envelope) => envelope,
		Arrived::Encrypted(_) => return Err(expectation_failure("handshake containers must be cleartext")),
	};

	let request = HandshakeMessage::try_from(envelope)?;
	transport.perform_server_handshake(request).await?;
	Ok(())
}

pub async fn accept_handshaken_split(listener: TokioListener) -> Result<SplitTransport<TokioStream>, TightBeamError> {
	let (mut transport, _) = listener.accept().await?;

	// An HPKE handshake takes two client messages: the hello and the closing.
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;

	assert!(
		matches!(transport.session_state().phase(), SessionPhase::Encrypted(_)),
		"server handshake must complete after the closing"
	);

	let halves = transport.into_split()?;
	Ok(halves)
}

pub async fn connect_handshaken_split(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<SplitTransport<TokioStream>, TightBeamError> {
	let mut client = connect_pinned_client(addr, server_certificate).await?;
	client.perform_client_handshake().await?;
	assert!(
		matches!(client.session_state().phase(), SessionPhase::Encrypted(_)),
		"client handshake must complete before splitting"
	);

	let halves = client.into_split()?;
	Ok(halves)
}

pub async fn connect_pinned_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let builder = pinned_client(server_certificate)?;
	let stream = TcpStream::connect(addr).await?;

	let adopted = builder.adopt(TokioStream::from(stream))?;
	Ok(adopted.into_transport())
}

/// A client builder that trusts `server_certificate` alone.
fn pinned_client(server_certificate: &Certificate) -> Result<ClientBuilder<TokioListener>, TightBeamError> {
	let trust_store: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
			.with_certificate(server_certificate.to_owned())?
			.build(),
	);

	Ok(ClientBuilder::<TokioListener>::builder().with_trust_store(trust_store))
}

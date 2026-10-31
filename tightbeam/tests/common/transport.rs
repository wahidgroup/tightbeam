//! The transport fixtures that the transport, security, colony, and seams
//! suites share: loopback listeners and clients, handshake drivers, and the
//! encryption config of a CMS test server.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::TcpStream;

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
use tightbeam::transport::state::CollectStep;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, ConnectionBuilder, EncryptedMessageIO, EncryptedProtocol, MessageCollector,
	TransportEncryptionConfig, TransportError,
};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

#[cfg(feature = "transport-multiplex")]
use core::time::Duration;
#[cfg(feature = "transport-cms")]
use tightbeam::testing::TestCmsServer;
#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::receipt::StoredReceipt;

use crate::common::poll::joined;
use crate::common::security::{
	combined_trust, expectation_failure, pinning_validator, ClientMaterials, ServerMaterials,
};

#[cfg(feature = "transport-multiplex")]
use crate::common::poll::poll_until;

/// The number of reads a transport wait takes, one every 5 ms for 2 s.
#[cfg(feature = "transport-multiplex")]
const TRANSPORT_WAIT_ATTEMPTS: u32 = 400;

/// The interval between the reads of a transport wait.
#[cfg(feature = "transport-multiplex")]
const TRANSPORT_WAIT_INTERVAL: Duration = Duration::from_millis(5);

/// Polls `ready` on the transport cadence and returns whether it held.
#[cfg(feature = "transport-multiplex")]
pub async fn await_transport(ready: impl FnMut() -> bool) -> bool {
	poll_until(TRANSPORT_WAIT_ATTEMPTS, TRANSPORT_WAIT_INTERVAL, ready).await
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

/// Binds a listener under `config` on a free loopback port, beside its
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

/// The transport encryption config that a CMS test server serves under.
///
/// The public `testing` API defines [`TestCmsServer`], so the config is a
/// trait method that a test calls on the server itself.
#[cfg(feature = "transport-cms")]
pub trait TestCmsServerExt {
	/// The config of a listener that presents this server: its signing
	/// identity, paired with its key-agreement identity.
	fn encryption_config(&self) -> TransportEncryptionConfig<DefaultCryptoProvider>;
}

#[cfg(feature = "transport-cms")]
impl TestCmsServerExt for TestCmsServer {
	fn encryption_config(&self) -> TransportEncryptionConfig<DefaultCryptoProvider> {
		let config = TransportEncryptionConfig::new(self.signing_identity());
		let config = config.with_key_agreement(self.key_agreement_identity());
		config.expect("the two certificates of a test server name one subject")
	}
}

/// Binds a listener that presents `materials`, pins `client_certificate` as
/// its one client, and admits each role under the house purposes.
pub async fn bind_mutual_listener(
	materials: &ServerMaterials,
	client_certificate: &Certificate,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	materials
		.bind_mutual_listener_under(client_certificate, KeyPurposes::HOUSE)
		.await
}

impl ServerMaterials {
	/// Binds a listener that presents these materials, pins
	/// `client_certificate` as its one client, and admits each role under
	/// `key_purposes`.
	pub async fn bind_mutual_listener_under(
		&self,
		client_certificate: &Certificate,
		key_purposes: KeyPurposes,
	) -> Result<(TokioListener, SocketAddr), TightBeamError> {
		let validators = vec![pinning_validator(client_certificate)];
		let config = TransportEncryptionConfig::new(self.identity()).with_client_validators(validators);
		bind_on_loopback(config.with_key_purposes(key_purposes)).await
	}
}

/// Connects a client that presents `client`, pins `server_certificate`, and
/// admits each role under `key_purposes`.
pub async fn connect_mutual_client_under(
	addr: SocketAddr,
	server_certificate: &Certificate,
	client: &ClientMaterials,
	key_purposes: KeyPurposes,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let builder = pinned_client(server_certificate).with_client_identity(client.identity());
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
	let materials = ServerMaterials::fixed();
	let client_materials = ClientMaterials::fixed();
	let key_purposes = KeyPurposes::HOUSE;
	establish_mutual_transports_of(client_offer, server_offer, hooks, &materials, &client_materials, key_purposes).await
}

/// Establishes a mutual-auth pair in which the server presents `materials`,
/// the client presents `client_materials`, and both endpoints admit each
/// role under `key_purposes`.
///
/// The join of the server task panics when the task panics or outlasts
/// [`HANG_GUARD`].
///
/// [`HANG_GUARD`]: crate::common::poll::HANG_GUARD
pub async fn establish_mutual_transports_of(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	hooks: MutualSessionHooks,
	materials: &ServerMaterials,
	client_materials: &ClientMaterials,
	key_purposes: KeyPurposes,
) -> Result<MutualTransports, TightBeamError> {
	let bound = materials.bind_mutual_listener_under(&client_materials.certificate, key_purposes);
	let (listener, addr) = bound.await?;

	#[cfg(feature = "instrument")]
	let server_trace = hooks.trace.as_ref().map(TraceCollector::share);
	let server_task = tokio::spawn(accept_handshaken(listener, move |transport| {
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

		transport
	}));

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

	let server = joined(server_task).await?;
	Ok(MutualTransports {
		client,
		server,
		server_certificate: Arc::clone(&materials.certificate),
		client_certificate: Arc::clone(&client_materials.certificate),
	})
}

/// Reads one handshake message from `transport` through the read step of the
/// session, which admits the arrival by its mode, and serves it as the server.
/// An application envelope in its place fails as an expectation failure.
pub async fn serve_one_handshake_message(transport: &mut TcpTransport<TokioStream>) -> Result<(), TightBeamError> {
	let request = match transport.collect_step().await? {
		CollectStep::Handshake(request) => request,
		CollectStep::Envelope(_) => return Err(expectation_failure("a handshake round is a handshake container")),
	};

	transport.perform_server_handshake(request).await?;
	Ok(())
}

/// Serves the two client messages of a handshake on `transport`, the opening
/// and the closing, and stops at the first refusal.
///
/// # Errors
///
/// - [`TightBeamError`] -- the read failure or the refusal of either message.
pub async fn serve_handshake(transport: &mut TcpTransport<TokioStream>) -> Result<(), TightBeamError> {
	serve_one_handshake_message(transport).await?;
	serve_one_handshake_message(transport).await
}

/// Accepts one connection on `listener`, sets it up with `configure`, and
/// serves its handshake.
///
/// # Errors
///
/// - [`TightBeamError`] -- the accept failure, or the errors of [`serve_handshake`].
pub async fn accept_handshaken(
	listener: TokioListener,
	configure: impl FnOnce(TcpTransport<TokioStream>) -> TcpTransport<TokioStream>,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let (transport, _) = listener.accept().await?;
	let mut transport = configure(transport);
	serve_handshake(&mut transport).await?;
	Ok(transport)
}

/// A client builder that trusts `server_certificate` alone.
pub fn pinned_client(server_certificate: &Certificate) -> ClientBuilder<TokioListener> {
	let trust_store = combined_trust(&[server_certificate]);
	ClientBuilder::<TokioListener>::builder().with_trust_store(trust_store)
}

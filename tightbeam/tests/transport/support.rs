//! Transport integration test plumbing.

#![cfg(all(
	feature = "transport-ecies",
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

#[cfg(feature = "transport-multiplex")]
use tokio::time::{sleep, timeout};

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::policy::TransitStatus;
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
use tightbeam::transport::handshake::{HandshakeKeyManager, TcpHandshakeState};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::tcp::r#async::{SplitTransport, TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageCollector, MessageIO, TransportEncryptionConfig, TransportError,
	WireEnvelope, X509ClientConfig,
};
use tightbeam::utils::urn::Urn;
use tightbeam::x509::Certificate;
use tightbeam::Frame;
use tightbeam::TightBeamError;

#[cfg(feature = "transport-multiplex")]
use tightbeam::transport::handshake::receipt::StoredReceipt;

use crate::common::security::{expectation_failure, pinning_validator, ClientMaterials, ServerMaterials};

/// Poll until epoch receipt differs from `previous` (timeout-bounded).
#[cfg(feature = "transport-multiplex")]
pub async fn await_receipt_rotation<F>(current: F, previous: Option<&StoredReceipt>) -> Option<Arc<StoredReceipt>>
where
	F: Fn() -> Option<Arc<StoredReceipt>>,
{
	let rotated = timeout(Duration::from_secs(2), async {
		loop {
			match current() {
				Some(receipt) if Some(receipt.as_ref()) != previous => return receipt,
				_ => sleep(Duration::from_millis(5)).await,
			}
		}
	})
	.await;

	rotated.ok()
}

/// Serve one single-flight request by echoing the accepted frame back,
/// answering with the gate's status.
pub async fn respond_echo<T: MessageCollector + Send>(mut transport: T) -> Result<(), TransportError> {
	let (request, status) = transport.collect_message().await?;
	let message = match status {
		TransitStatus::Ok => Some(Arc::try_unwrap(request).unwrap_or_else(|shared| (*shared).clone())),
		_ => None,
	};

	transport.send_response(status, message).await
}

/// A small labeled frame for multiplexed exchanges.
pub fn mux_frame(label: &str) -> Frame {
	create_v0_tightbeam(Some(label), None)
}

/// A multiplexing offer advertising `cap` peer-initiated streams.
pub fn mux_offer(cap: u32) -> TransportOffer {
	TransportOffer::mux(cap)
}

/// Record an event outcome from a spawned task, where no `Result`
/// return exists for `?`. A recording failure panics the task; the
/// spec then surfaces it as the missing event.
pub fn record_spawned_event(trace: &TraceCollector, urn: Urn<'static>, value: bool) {
	trace.event_with(urn, &[], value).expect("spawned task must record its event");
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
	let certificate = Certificate::clone(&materials.certificate);
	let key_manager = HandshakeKeyManager::new(Arc::clone(&materials.key_provider));

	let config = TransportEncryptionConfig::new(certificate, key_manager);
	bind_with_config(config).await
}

pub async fn bind_encrypted_listener_with_timeout(
	materials: &ServerMaterials,
	handshake_timeout: Duration,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let certificate = Certificate::clone(&materials.certificate);
	let key_manager = HandshakeKeyManager::new(Arc::clone(&materials.key_provider));

	let mut config = TransportEncryptionConfig::new(certificate, key_manager);
	config.handshake_timeout = handshake_timeout;
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
	let certificate = Certificate::clone(&materials.certificate);
	let key_manager = HandshakeKeyManager::new(Arc::clone(&materials.key_provider));
	let validators = vec![pinning_validator(client_certificate)];

	let config = TransportEncryptionConfig::new(certificate, key_manager).with_client_validators(validators);
	bind_with_config(config).await
}

pub async fn connect_mutual_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
	client: &ClientMaterials,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let transport = connect_pinned_client(addr, server_certificate).await?;
	Ok(transport.with_client_identity(Arc::clone(&client.certificate), Arc::clone(&client.key_manager)))
}

/// Optional per-session hooks for mutual-auth handshakes.
#[derive(Default)]
pub struct MutualSessionHooks {
	pub authorizer: Option<Arc<dyn TransportAuthorizer>>,
	pub approver: Option<Arc<dyn ReceiptApprover>>,
	pub observer: Option<Arc<dyn SessionObserver>>,
	/// Attached to both endpoints: production instrumentation emits
	/// session labels for spec assertions.
	pub trace: Option<TraceCollector>,
}

/// Established mutual-auth transports plus peer identities for receipt verification.
pub struct MutualTransports {
	pub client: TcpTransport<TokioStream>,
	pub server: TcpTransport<TokioStream>,
	pub server_certificate: Arc<Certificate>,
	pub client_certificate: Arc<Certificate>,
}

/// Budget-bearing sessions require client countersignature over session receipt.
pub async fn establish_mutual_transports(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	hooks: MutualSessionHooks,
) -> Result<MutualTransports, TightBeamError> {
	let materials = ServerMaterials::generate();
	let client_materials = ClientMaterials::generate();
	let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

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

		// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
		serve_one_handshake_message(&mut transport).await?;
		serve_one_handshake_message(&mut transport).await?;
		Ok::<_, TightBeamError>(transport)
	});

	let mut client = connect_mutual_client(addr, &materials.certificate, &client_materials).await?;
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
	let wire_bytes = transport.read_envelope_bytes().await?;
	let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
	let envelope = match wire_envelope {
		WireEnvelope::Cleartext(envelope) => envelope,
		WireEnvelope::Encrypted(_) => return Err(expectation_failure("handshake containers must be cleartext")),
	};

	let handshake_bytes = envelope.to_der()?;
	transport.perform_server_handshake(&handshake_bytes).await?;
	Ok(())
}

pub async fn accept_handshaken_split(listener: TokioListener) -> Result<SplitTransport<TokioStream>, TightBeamError> {
	let (mut transport, _) = listener.accept().await?;

	// ECIES is exactly two client messages: ClientHello, ClientKeyExchange.
	serve_one_handshake_message(&mut transport).await?;
	serve_one_handshake_message(&mut transport).await?;
	assert_eq!(
		transport.to_handshake_state(),
		TcpHandshakeState::Complete,
		"server handshake must complete after ClientKeyExchange"
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
	assert_eq!(
		client.to_handshake_state(),
		TcpHandshakeState::Complete,
		"client handshake must complete before splitting"
	);

	let halves = client.into_split()?;
	Ok(halves)
}

pub async fn connect_pinned_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let trust_store: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(server_certificate.to_owned())?
			.build(),
	);

	let stream = TcpStream::connect(addr).await?;
	let client_stream = TokioStream::from(stream);
	let transport = TcpTransport::from(client_stream).with_trust_store(trust_store);
	Ok(transport)
}

//! Shared plumbing for transport integration tests: encrypted listener
//! setup, manual server-side handshake, and pinned clients.

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::der::{Decode, Encode};
use tightbeam::prelude::TightBeamSocketAddr;
use tightbeam::transport::handshake::negotiation::{TransportAuthorizer, TransportOffer};
use tightbeam::transport::handshake::receipt::{ReceiptApprover, SessionObserver};
use tightbeam::transport::handshake::{HandshakeKeyManager, TcpHandshakeState};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::tcp::r#async::{SplitTransport, TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageIO, TransportEncryptionConfig, WireEnvelope, X509ClientConfig,
};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::common::security::{expectation_failure, pinning_validator, ClientMaterials, ServerMaterials};

/// Await a spawned `Result` task. Join panics become expectation failures.
pub async fn await_ok<T, E>(task: JoinHandle<Result<T, E>>, panic_msg: &'static str) -> Result<T, TightBeamError>
where
	E: Into<TightBeamError>,
{
	let joined = task.await.map_err(|_| expectation_failure(panic_msg))?;
	let value = joined.map_err(Into::into)?;
	Ok(value)
}

/// Await a spawned task and surface join panics as expectation failures.
pub async fn join_task<T>(task: JoinHandle<T>, panic_msg: &'static str) -> Result<T, TightBeamError> {
	let value = task.await.map_err(|_| expectation_failure(panic_msg))?;
	Ok(value)
}

/// Bind an encrypted listener backed by the given server materials.
pub async fn bind_encrypted_listener(
	materials: &ServerMaterials,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let certificate = Certificate::clone(&materials.certificate);
	let key_manager = HandshakeKeyManager::new(Arc::clone(&materials.key_provider));

	let config = TransportEncryptionConfig::new(certificate, key_manager);
	let addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, bound_addr) = TokioListener::bind_with(addr, config).await?;
	Ok((listener, *bound_addr))
}

/// Bind an encrypted listener that additionally validates client
/// certificates (mutual auth), pinned to the given client certificate.
pub async fn bind_mutual_listener(
	materials: &ServerMaterials,
	client_certificate: &Certificate,
) -> Result<(TokioListener, SocketAddr), TightBeamError> {
	let certificate = Certificate::clone(&materials.certificate);
	let key_manager = HandshakeKeyManager::new(Arc::clone(&materials.key_provider));
	let validators = vec![pinning_validator(client_certificate)];
	let config = TransportEncryptionConfig::new(certificate, key_manager).with_client_validators(validators);

	let addr = "127.0.0.1:0".parse::<TightBeamSocketAddr>()?;
	let (listener, bound_addr) = TokioListener::bind_with(addr, config).await?;
	Ok((listener, *bound_addr))
}

/// Connect a pinned client carrying its own identity for mutual auth.
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
}

/// Established mutual-auth transports plus the peer identities, for
/// scenarios that verify session artifacts against the certificates.
pub struct MutualTransports {
	pub client: TcpTransport<TokioStream>,
	pub server: TcpTransport<TokioStream>,
	pub server_certificate: Arc<Certificate>,
	pub client_certificate: Arc<Certificate>,
}

/// Full ECIES handshake with mutual authentication: budget-bearing
/// sessions demand a client countersignature over the session receipt,
/// so both endpoints carry identities.
pub async fn establish_mutual_transports(
	client_offer: TransportOffer,
	server_offer: TransportOffer,
	hooks: MutualSessionHooks,
) -> Result<MutualTransports, TightBeamError> {
	let materials = ServerMaterials::generate();
	let client_materials = ClientMaterials::generate();
	let (listener, addr) = bind_mutual_listener(&materials, &client_materials.certificate).await?;

	let server_task = tokio::spawn(async move {
		let (transport, _) = listener.accept().await?;
		let mut transport = transport.with_mux_offer(Some(server_offer));
		if let Some(authorizer) = hooks.authorizer {
			transport = transport.with_transport_authorizer(authorizer);
		}
		if let Some(observer) = hooks.observer {
			transport = transport.with_session_observer(observer);
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

	client.perform_client_handshake().await?;

	let server = await_ok(server_task, "server handshake task must not panic").await?;
	Ok(MutualTransports {
		client,
		server,
		server_certificate: Arc::clone(&materials.certificate),
		client_certificate: Arc::clone(&client_materials.certificate),
	})
}

/// Read one cleartext handshake container and feed it to the server dispatcher.
pub async fn serve_one_handshake_message(transport: &mut TcpTransport<TokioStream>) -> Result<(), TightBeamError> {
	let wire_bytes = transport.read_envelope().await?;
	let wire_envelope = WireEnvelope::from_der(&wire_bytes)?;
	let envelope = match wire_envelope {
		WireEnvelope::Cleartext(envelope) => envelope,
		WireEnvelope::Encrypted(_) => return Err(expectation_failure("handshake containers must be cleartext")),
	};

	let handshake_bytes = envelope.to_der()?;
	transport.perform_server_handshake(&handshake_bytes).await?;
	Ok(())
}

/// Accept one connection, drive the server-side ECIES handshake to
/// completion, and split into exclusive read/write halves.
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

/// Connect a pinned client, drive its handshake to completion, and split
/// into exclusive read/write halves.
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

/// Connect a client pinned to the server certificate.
pub async fn connect_pinned_client(
	addr: SocketAddr,
	server_certificate: &Certificate,
) -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let trust_store: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(server_certificate.clone())?
			.build(),
	);

	let stream = TcpStream::connect(addr).await?;
	let transport = TcpTransport::from(TokioStream::from(stream)).with_trust_store(trust_store);
	Ok(transport)
}

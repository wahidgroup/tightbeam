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
use tightbeam::transport::handshake::{HandshakeKeyManager, TcpHandshakeState};
use tightbeam::transport::state::EncryptedProtocolState;
use tightbeam::transport::tcp::r#async::{SplitTransport, TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	EncryptedMessageIO, EncryptedProtocol, MessageIO, TransportEncryptionConfig, TransportError, WireEnvelope,
	X509ClientConfig,
};
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::common::security::{expectation_failure, ServerMaterials};

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
	let (mut transport, _) = listener.accept().await.map_err(TransportError::from)?;

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

	let stream = TcpStream::connect(addr).await.map_err(TransportError::from)?;
	let transport = TcpTransport::from(TokioStream::from(stream)).with_trust_store(trust_store);
	Ok(transport)
}

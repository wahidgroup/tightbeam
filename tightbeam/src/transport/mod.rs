//! Transport layer for TightBeam protocol

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(all(feature = "x509", feature = "std"))]
use core::time::Duration;

// Module declarations
pub mod builders;
pub mod envelopes;
pub mod error;
pub mod handshake;
pub mod io;
pub mod messaging;
pub mod protocols;
pub mod state;

#[cfg(feature = "transport-multiplex")]
pub mod multiplex;
#[cfg(feature = "transport-policy")]
pub mod policy;
#[cfg(feature = "std")]
pub mod pool;
#[cfg(feature = "tcp")]
pub mod tcp;

// Re-exports from submodules
pub use builders::{EnvelopeBuilder, EnvelopeLimits};
pub use envelopes::{RequestPackage, ResponsePackage, TransportEnvelope, WireEnvelope, WireMode};
pub use error::{TransportError, TransportFailure};
pub use io::{EncryptedMessageIO, MessageIO, Pingable};
pub use messaging::{MessageCollector, MessageEmitter, ResponseHandler, Transport};
pub use protocols::{
	AsyncListenerTrait, EncryptedProtocol, Mycelial, PersistentConnection, Protocol, ProtocolStream, TightBeamAddress,
	X509ClientConfig,
};

#[cfg(feature = "std")]
pub use pool::{Client, ConnectionPool, PoolConfig, PooledClient};

/// Transport-agnostic result type
pub type TransportResult<T> = Result<T, TransportError>;

#[cfg(feature = "x509")]
use crate::crypto::x509::policy::CertificateValidation;
#[cfg(feature = "x509")]
use crate::transport::handshake::HandshakeKeyManager;
#[cfg(feature = "x509")]
use crate::x509::Certificate;

use crate::constants::TIGHTBEAM_AAD_DOMAIN_TAG;

/// Composite validator that runs multiple validators in sequence
#[cfg(feature = "x509")]
pub(crate) struct CompositeValidator {
	pub(crate) validators: Arc<Vec<Arc<dyn CertificateValidation>>>,
}

#[cfg(feature = "x509")]
impl CertificateValidation for CompositeValidator {
	fn evaluate(
		&self,
		cert: &Certificate,
	) -> core::result::Result<(), crate::crypto::x509::error::CertificateValidationError> {
		for validator in self.validators.iter() {
			validator.evaluate(cert)?;
		}
		Ok(())
	}
}

#[cfg(all(feature = "x509", feature = "std"))]
#[derive(Clone)]
pub struct TransportEncryptionConfig {
	pub certificate: Certificate,
	pub key_manager: Arc<HandshakeKeyManager>,
	pub client_validators: Option<Arc<Vec<Arc<dyn CertificateValidation>>>>,
	pub aad_domain_tag: &'static [u8],
	pub max_cleartext_envelope: usize,
	pub max_encrypted_envelope: usize,
	pub handshake_timeout: Duration,
}

#[cfg(all(feature = "x509", feature = "std"))]
impl TransportEncryptionConfig {
	pub fn new(certificate: Certificate, key_manager: HandshakeKeyManager) -> Self {
		Self {
			certificate,
			key_manager: Arc::new(key_manager),
			client_validators: None,
			aad_domain_tag: TIGHTBEAM_AAD_DOMAIN_TAG,
			max_cleartext_envelope: 128 * 1024,
			max_encrypted_envelope: 256 * 1024,
			handshake_timeout: Duration::from_secs(10),
		}
	}

	pub fn with_client_validators(mut self, validators: Vec<Arc<dyn CertificateValidation>>) -> Self {
		self.client_validators = Some(Arc::new(validators));
		self
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::asn1::Frame;
	use crate::testing::create_v0_tightbeam;
	use crate::transport::error::TransportFailure;
	use crate::transport::policy::PolicyConf;

	#[cfg(feature = "tokio")]
	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn test_server_and_client_macros() -> TransportResult<()> {
		use std::sync::{mpsc, Arc};

		use crate::transport::policy::RestartLinearBackoff;
		use crate::transport::tcp::r#async::TokioListener;
		use crate::transport::tcp::TightBeamSocketAddr;

		let listener = TokioListener::bind("127.0.0.1:0").await?;
		let addr = TightBeamSocketAddr(listener.local_addr()?);

		let (tx, rx) = mpsc::channel();
		let tx = Arc::new(tx);

		// Spawn server using server! macro
		let server_handle = crate::server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = Arc::clone(&tx);
				async move {
					// Quantum tunnel testing channel -- TUNNEL
					let _ = tx.send(message);
					Ok(None)
				}
			}
		};

		// Create client using client! macro
		let mut client = crate::client! {
			connect TokioListener: addr,
			policies: {
				restart_policy: RestartLinearBackoff::default(),
			}
		};

		let message = create_v0_tightbeam(None, None);
		let result = client.emit(message.clone(), None).await;
		result?;

		// Verify server received the message -- TUNNEL
		let received = rx
			.recv_timeout(Duration::from_secs(1))
			.map_err(|_| TransportError::OperationFailed(error::TransportFailure::Timeout))?;
		assert_eq!(message, received);

		server_handle.abort();

		Ok(())
	}

	#[cfg(feature = "aes-gcm")]
	#[test]
	fn test_envelope_builder_encrypted_limit_returns_message() -> Result<(), Box<dyn std::error::Error>> {
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid, KeyInit, RuntimeAead};
		use crate::der::oid::AssociatedOid;

		let frame = create_v0_tightbeam(None, None);
		let cipher = Aes256Gcm::new_from_slice(&[0u8; 32]).map_err(|_| "Invalid key")?;
		let encryptor = RuntimeAead::new(cipher, Aes256GcmOid::OID);

		let err = builders::EnvelopeBuilder::request(frame.clone())
			.with_wire_mode(WireMode::Encrypted)
			.with_encryptor(&encryptor)
			.with_max_encrypted_envelope(1)
			.finish()
			.expect_err("encrypted size limit should fail");

		match err {
			TransportError::MessageNotSent(returned, TransportFailure::SizeExceeded) => {
				assert_eq!(*returned, frame);
			}
			other => panic!("unexpected error variant: {other:?}"),
		}

		Ok(())
	}

	#[test]
	fn test_envelope_builder_cleartext_limit_returns_message() {
		let frame = create_v0_tightbeam(None, None);
		let err = builders::EnvelopeBuilder::request(frame.clone())
			.with_max_cleartext_envelope(1)
			.finish()
			.expect_err("cleartext size limit should fail");

		match err {
			TransportError::MessageNotSent(returned, TransportFailure::SizeExceeded) => {
				assert_eq!(*returned, frame);
			}
			other => panic!("unexpected error variant: {other:?}"),
		}
	}
}

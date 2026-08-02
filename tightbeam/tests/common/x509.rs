//! X.509 certificate test helpers.
//!
//! These fixtures mint gateway identities and multi-anchor trust stores for
//! colony transport and federation tests, including split-plane export
//! scenarios that need distinct organizations and mutual TLS.

#![allow(dead_code)]

use core::time::Duration;
use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::{
	cert,
	crypto::{
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::{
			ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey},
			Sha3Signer,
		},
		x509::{
			policy::CertificateValidation,
			store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder},
		},
	},
	error::Result,
	prelude::{collect::TokioListener, *},
	server,
	spki::SubjectPublicKeyInfoOwned,
	testing::{create_test_certificate_with_uri_sans, create_test_signing_key},
	transport::{handshake::HandshakeKeyManager, EncryptedProtocol, TransportEncryptionConfig},
	utils::urn::Urn,
	x509::Certificate,
	Frame, TightBeamError,
};

/// Create a test certificate with signing key for a given subject and validity period
pub fn create_test_cert_with_key(subject: &str, validity_days: u64) -> Result<(Certificate, Secp256k1SigningKey)> {
	let signing_key = create_test_signing_key();
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let sha3_signer = Sha3Signer::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
	let validity_duration = Duration::from_secs(validity_days * 24 * 60 * 60);

	let cert = cert! {
		profile: Root,
		subject: subject,
		serial: 1u32,
		duration: validity_duration,
		signer: &sha3_signer,
		subject_public_key: spki
	}?;

	Ok((cert, signing_key))
}

/// Create server encryption config with certificate, key, and validators
pub fn create_server_config(
	cert: Certificate,
	key_provider: impl Into<HandshakeKeyManager<DefaultCryptoProvider>>,
	validators: Vec<Arc<dyn CertificateValidation>>,
) -> TransportEncryptionConfig<DefaultCryptoProvider> {
	let key_manager = key_provider.into();
	TransportEncryptionConfig::new(cert, key_manager).with_client_validators(validators)
}

/// Self-signed gateway materials shared by colony transport tests.
///
/// One certificate serves as identity and trust anchor for cluster, hive,
/// and servlet endpoints alike.
pub struct GatewayCerts {
	pub cert: Certificate,
	pub key: Secp256k1SigningKey,
	pub trust: Arc<dyn CertificateTrust>,
}

impl GatewayCerts {
	/// Generate a fresh self-signed gateway identity for `subject`.
	pub fn generate(subject: &str) -> Self {
		let (cert, key) = create_test_cert_with_key(subject, 365).expect("Failed to create gateway cert");
		let trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
				.with_chain(vec![cert.to_owned()])
				.expect("Failed to build trust")
				.build(),
		);
		Self { cert, key, trust }
	}

	/// Generate a colony-member gateway identity.
	///
	/// The certificate carries `colony_urn` as a URI Subject Alternative Name
	/// (RFC 5280 section 4.2.1.6) with an empty subject, so membership
	/// provably binds to the SAN alone. Colony membership gates gossip and
	/// peer federation.
	pub fn generate_colony(colony_urn: &Urn<'_>) -> Self {
		let raw = create_test_signing_key();
		let cert = create_test_certificate_with_uri_sans(&raw, &[&colony_urn.to_string()]);
		let key = Secp256k1SigningKey::from(raw);
		let trust = combined_trust(&[&cert]);
		Self { cert, key, trust }
	}
}

/// Trust builder anchoring several independent identities at once.
fn combined_trust_builder(certs: &[&Certificate]) -> CertificateTrustBuilder<Sha3_256> {
	let mut builder = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy);
	for cert in certs {
		builder = builder
			.with_certificate((*cert).to_owned())
			.expect("Failed to anchor combined trust");
	}

	builder
}

/// Trust store anchoring several independent identities at once.
///
/// Used by multi-peer federation and split-plane export tests.
pub fn combined_trust(certs: &[&Certificate]) -> Arc<dyn CertificateTrust> {
	Arc::new(combined_trust_builder(certs).build())
}

/// Client-certificate validator anchoring several identities at once.
///
/// Used on the inbound mutual-TLS accept plane
/// (`ClusterTlsConfig::client_validators`). Export scenarios turn this on so
/// the gateway can recognize first-party origin sessions.
pub fn combined_validator(certs: &[&Certificate]) -> Arc<dyn CertificateValidation> {
	Arc::new(combined_trust_builder(certs).build())
}

/// Extract Common Name (CN) from certificate subject
///
/// Returns the first CN found in the certificate subject RDN sequence.
pub fn extract_cn(cert: &Certificate) -> Option<String> {
	use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};

	// OID for Common Name (CN) is 2.5.4.3
	const CN_OID: &str = "2.5.4.3";

	// Iterate through RDN sequence to find CN
	for rdn in cert.tbs_certificate.subject.0.iter() {
		for attr in rdn.0.iter() {
			if attr.oid.to_string() == CN_OID {
				// The value is an Any type which can be various string types
				// Try UTF8String first
				if let Ok(utf8_str) = attr.value.decode_as::<Utf8StringRef>() {
					return Some(utf8_str.to_string());
				}
				// Try PrintableString
				if let Ok(printable) = attr.value.decode_as::<PrintableStringRef>() {
					return Some(printable.to_string());
				}
				// Try IA5String
				if let Ok(ia5) = attr.value.decode_as::<Ia5StringRef>() {
					return Some(ia5.to_string());
				}
			}
		}
	}
	None
}

/// Test fixture for a server with mutual authentication
///
/// Provides a managed server instance with message reception channel
/// for integration testing.
pub struct MutualAuthServer {
	pub handle: tokio::task::JoinHandle<()>,
	pub addr: TightBeamSocketAddr,
	pub rx: tokio::sync::mpsc::Receiver<Frame>,
}

impl MutualAuthServer {
	/// Create a new mutual auth server with specified certificate and validators
	pub async fn new(
		server_cert: Certificate,
		server_key: Secp256k1SigningKey,
		client_validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self> {
		use tightbeam::{compose, decode};

		#[derive(Clone, Debug, PartialEq, tightbeam::Beamable, tightbeam::Sequence)]
		struct PingMessage {
			data: String,
		}

		#[derive(Clone, Debug, PartialEq, tightbeam::Beamable, tightbeam::Sequence)]
		struct PongMessage {
			echo: String,
		}

		let server_config = create_server_config(server_cert, server_key, client_validators);
		let socket_addr = "127.0.0.1:0"
			.parse()
			.map_err(|e| TightBeamError::IoError(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;
		let bind_addr = TightBeamSocketAddr(socket_addr);
		let (listener, addr) = TokioListener::bind_with(bind_addr, server_config).await?;
		let (tx, rx) = tokio::sync::mpsc::channel(8);

		let handle = server! {
			protocol TokioListener: listener,
			handle: move |message: Frame| {
				let tx = tx.to_owned();
				async move {
					tx.send(message.to_owned()).await.map_err(|_| TightBeamError::InvalidBody)?;

					let ping: PingMessage = decode(&message.message)?;
					let pong = PongMessage { echo: ping.data };

					Ok(Some(compose! {
						V0: id: &message.metadata.id,
						message: pong
					}?))
				}
			}
		};

		Ok(Self { handle, addr, rx })
	}

	/// Expect to receive a message within the given timeout
	pub async fn expect_message(&mut self, timeout: Duration) -> Frame {
		tokio::time::timeout(timeout, self.rx.recv())
			.await
			.expect("Server should receive message within timeout")
			.expect("Message should not be None")
	}

	/// Abort the server task
	pub fn abort(self) {
		self.handle.abort();
	}
}

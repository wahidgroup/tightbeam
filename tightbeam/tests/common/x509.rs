//! X.509 certificate test helpers.
//!
//! These fixtures create gateway identities and multi-anchor trust stores for
//! the colony transport and federation tests, including split-plane export
//! scenarios that need distinct organizations and mutual TLS.

#![allow(dead_code)]

use core::time::Duration;
use std::sync::Arc;

use tightbeam::{
	cert,
	crypto::{
		key::Secp256k1KeyProvider,
		policy::Secp256k1Policy,
		profiles::DefaultCryptoProvider,
		sign::{
			ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey},
			Sha3Signer, SigningIdentity,
		},
		x509::{
			policy::CertificateValidation,
			store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder},
			KeyCurves,
		},
	},
	error::Result,
	prelude::{collect::TokioListener, *},
	random::OsRng,
	server,
	spki::SubjectPublicKeyInfoOwned,
	testing::TestCertificate,
	transport::{EncryptedProtocol, TransportEncryptionConfig},
	urn::Urn,
	x509::Certificate,
	Frame, TightBeamError,
};

/// Creates a self-issued end-entity test certificate for `subject`, valid for
/// `validity_days`, with its signing key. Its `keyUsage` asserts
/// `digitalSignature`, so a handshake admits it for signing.
///
/// Each call draws its own key, so a scenario that holds the identity trusts
/// it alone, and a dial that a released port carries to the listener of
/// another scenario fails its handshake.
pub fn create_test_cert_with_key(
	subject: impl AsRef<str>,
	validity_days: u64,
) -> Result<(Certificate, Secp256k1SigningKey)> {
	let subject = subject.as_ref();
	let signing_key = Secp256k1SigningKey::from(k256::ecdsa::SigningKey::random(&mut OsRng));
	let verifying_key = Secp256k1VerifyingKey::from(&signing_key);
	let sha3_signer = Sha3Signer::from(&signing_key);
	let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;
	let validity_duration = Duration::from_secs(validity_days * 24 * 60 * 60);

	let cert = cert! {
		profile: Leaf,
		subject: subject,
		issuer: subject,
		serial: 1u32,
		duration: validity_duration,
		subject_public_key: spki,
		signer: &sha3_signer
	}?;

	Ok((cert, signing_key))
}

/// The server encryption config of `cert` and `key`, which validates clients
/// with `validators`.
pub fn create_server_config(
	cert: Certificate,
	key: Secp256k1SigningKey,
	validators: Vec<Arc<dyn CertificateValidation>>,
) -> TransportEncryptionConfig<DefaultCryptoProvider> {
	let identity = signing_identity(cert, key);
	TransportEncryptionConfig::new(identity).with_client_validators(validators)
}

/// The signing identity of `cert`, whose private key is `key`.
pub fn signing_identity(cert: impl Into<Arc<Certificate>>, key: Secp256k1SigningKey) -> SigningIdentity {
	let provider = Arc::new(Secp256k1KeyProvider::from(key));
	SigningIdentity::new(cert, provider).expect("the key must match its certificate")
}

/// The self-signed gateway materials that the colony transport tests share.
///
/// One certificate serves as the identity and the trust anchor of cluster,
/// hive, and servlet endpoints alike.
pub struct GatewayCerts {
	/// The self-signed certificate of the gateway.
	pub cert: Certificate,
	/// The signing key of `cert`.
	pub key: Secp256k1SigningKey,
	/// The trust store that anchors `cert`.
	pub trust: Arc<dyn CertificateTrust>,
}

impl GatewayCerts {
	/// Generate a fresh self-signed gateway identity for `subject`.
	pub fn generate(subject: impl AsRef<str>) -> Self {
		let subject = subject.as_ref();
		let (cert, key) = create_test_cert_with_key(subject, 365).expect("Failed to create gateway cert");
		let trust: Arc<dyn CertificateTrust> = Arc::new(
			CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
				.with_chain(vec![cert.to_owned()])
				.expect("Failed to build trust")
				.build(),
		);
		Self { cert, key, trust }
	}

	/// Generate a colony-member gateway identity on a fresh key.
	///
	/// The certificate carries `colony_urn` as a URI Subject Alternative Name
	/// (RFC 5280 section 4.2.1.6) with an empty subject, so membership binds
	/// to the SAN alone. Colony membership gates gossip and peer federation.
	pub fn generate_colony(colony_urn: &Urn<'_>) -> Self {
		let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
		let cert = TestCertificate::with_uri_sans(&raw, &[&colony_urn.to_string()]);
		let key = Secp256k1SigningKey::from(raw);
		let trust = combined_trust(&[&cert]);
		Self { cert, key, trust }
	}
}

/// A trust builder that anchors every certificate of `certs`.
fn combined_trust_builder(certs: &[&Certificate]) -> CertificateTrustBuilder {
	let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	for cert in certs {
		builder = builder
			.with_certificate((*cert).to_owned())
			.expect("Failed to anchor combined trust");
	}

	builder
}

/// A trust store that anchors every certificate of `certs`, for the multi-peer
/// federation and split-plane export tests.
pub fn combined_trust(certs: &[&Certificate]) -> Arc<dyn CertificateTrust> {
	Arc::new(combined_trust_builder(certs).build())
}

/// A client-certificate validator that anchors every certificate of `certs`.
///
/// It serves the inbound mutual-TLS accept plane
/// (`ClusterTlsConfig::client_authentication`). Export scenarios turn it on
/// so the gateway can recognize first-party origin sessions.
pub fn combined_validator(certs: &[&Certificate]) -> Arc<dyn CertificateValidation> {
	Arc::new(combined_trust_builder(certs).build())
}

/// Extracts the Common Name (CN) from the subject of `cert`.
///
/// It returns the first CN in the subject RDN sequence that decodes as a
/// UTF8String, a PrintableString, or an IA5String, tried in that order.
pub fn extract_cn(cert: &Certificate) -> Option<String> {
	use der::asn1::{Ia5StringRef, PrintableStringRef, Utf8StringRef};

	const CN_OID: &str = "2.5.4.3";

	for rdn in cert.tbs_certificate.subject.0.iter() {
		for attr in rdn.0.iter() {
			if attr.oid.to_string() == CN_OID {
				// The value is an `Any`, which holds one of the directory
				// string types.
				if let Ok(utf8_str) = attr.value.decode_as::<Utf8StringRef>() {
					return Some(utf8_str.to_string());
				}
				if let Ok(printable) = attr.value.decode_as::<PrintableStringRef>() {
					return Some(printable.to_string());
				}
				if let Ok(ia5) = attr.value.decode_as::<Ia5StringRef>() {
					return Some(ia5.to_string());
				}
			}
		}
	}
	None
}

/// A test server that requires mutual authentication.
///
/// It answers each ping with a pong and hands every frame it receives to
/// `rx`, for integration tests.
pub struct MutualAuthServer {
	/// The task that runs the server.
	pub handle: tokio::task::JoinHandle<()>,
	/// The address the server listens on.
	pub addr: TightBeamSocketAddr,
	/// The frames the server receives, in arrival order.
	pub rx: tokio::sync::mpsc::Receiver<Frame>,
}

impl MutualAuthServer {
	/// Starts a mutual-authentication server on a local port with
	/// `server_cert` and `server_key`, which validates clients with
	/// `client_validators`.
	pub async fn new(
		server_cert: Certificate,
		server_key: Secp256k1SigningKey,
		client_validators: Vec<Arc<dyn CertificateValidation>>,
	) -> Result<Self> {
		use tightbeam::compose;

		#[derive(Clone, Debug, PartialEq, tightbeam::Beamable, tightbeam::der::Sequence)]
		struct PingMessage {
			data: String,
		}

		#[derive(Clone, Debug, PartialEq, tightbeam::Beamable, tightbeam::der::Sequence)]
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

					let ping: PingMessage = message.decode_message()?;
					let pong = PongMessage { echo: ping.data };

					Ok(Some(compose! {
						V0: id: message.metadata().id(),
						message: pong
					}?))
				}
			}
		};

		Ok(Self { handle, addr, rx })
	}

	/// Waits up to `timeout` for the next frame the server receives, and
	/// panics when none arrives in time.
	pub async fn expect_message(&mut self, timeout: Duration) -> Frame {
		tokio::time::timeout(timeout, self.rx.recv())
			.await
			.expect("Server should receive message within timeout")
			.expect("Message should not be None")
	}

	/// Aborts the server task.
	pub fn abort(self) {
		self.handle.abort();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Each call draws its own key, so the store of one identity holds no key
	/// of another.
	#[test]
	fn a_gateway_identity_trusts_no_key_of_another_call() {
		let scenario = GatewayCerts::generate("CN=Scenario Gateway");
		let other = GatewayCerts::generate("CN=Scenario Gateway");

		let other_key = &other.cert.tbs_certificate.subject_public_key_info;
		assert!(scenario.trust.find_by_public_key(other_key).is_none());
	}
}

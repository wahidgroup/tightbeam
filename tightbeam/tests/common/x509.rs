//! X.509 certificate test helpers.
//!
//! These fixtures create the gateway identities of the colony transport and
//! federation tests, including split-plane export scenarios that need distinct
//! organizations and mutual TLS. Their trust stores come from
//! [`combined_trust`].

use core::time::Duration;
use std::sync::Arc;

use tightbeam::{
	cert,
	cms::signed_data::SignerIdentifier,
	crypto::{
		profiles::DefaultCryptoProvider,
		sign::{
			ecdsa::{Secp256k1SigningKey, Secp256k1VerifyingKey},
			Sha3Signer, SigningIdentity,
		},
		x509::{policy::CertificateValidation, store::CertificateTrust, utils::CertificateExt},
	},
	error::Result,
	spki::SubjectPublicKeyInfoOwned,
	testing::TestIdentity,
	transport::TransportEncryptionConfig,
	x509::Certificate,
};

#[cfg(feature = "colony")]
use tightbeam::{colony::cluster::ClusterTlsConfig, crypto::x509::KeyPurposes};

use crate::common::security::{combined_trust, random_signing_key};

/// Creates a self-issued end-entity test certificate for `subject`, valid for
/// `validity_days`, with its signing key. Its `keyUsage` asserts
/// `digitalSignature`, so a handshake admits it for signing. Its key is a
/// fresh [`random_signing_key`].
pub fn create_test_cert_with_key(
	subject: impl AsRef<str>,
	validity_days: u64,
) -> Result<(Certificate, Secp256k1SigningKey)> {
	let subject = subject.as_ref();
	let signing_key = random_signing_key();
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
#[allow(dead_code)]
pub fn create_server_config(
	cert: Certificate,
	key: Secp256k1SigningKey,
	validators: Vec<Arc<dyn CertificateValidation>>,
) -> TransportEncryptionConfig<DefaultCryptoProvider> {
	let identity = signing_identity(cert, key);
	TransportEncryptionConfig::new(identity).with_client_validators(validators)
}

/// The signing identity of `cert`, whose private key is `key`, through the
/// public [`TestIdentity::presenting`].
pub fn signing_identity(cert: impl Into<Arc<Certificate>>, key: Secp256k1SigningKey) -> SigningIdentity {
	TestIdentity::presenting(cert, &key)
}

/// The signer that names `certificate` (RFC 5652 §5.3).
pub fn signer_of(certificate: &Certificate) -> SignerIdentifier {
	certificate.signer_identifier().expect("a fixture certificate names its key")
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
		let trust = combined_trust(&[&cert]);
		Self { cert, key, trust }
	}

	/// The signing identity of this gateway: its certificate over its key,
	/// through the public [`TestIdentity::presenting`].
	pub fn identity(&self) -> SigningIdentity {
		TestIdentity::presenting(self.cert.to_owned(), &self.key)
	}

	/// The colony-plane TLS of this gateway under the house key purposes,
	/// whose hive plane trusts the store of this gateway.
	#[cfg(feature = "colony")]
	pub fn cluster_tls(&self) -> ClusterTlsConfig {
		let tls = ClusterTlsConfig::from_identity(self.identity(), KeyPurposes::HOUSE);
		let tls = tls.expect("a fixture certificate admits the house signer purpose");
		tls.with_hive_trust(Some(Arc::clone(&self.trust)))
	}
}

mod tests {
	use super::*;

	/// Each call draws its own key, so the store of one identity finds its own
	/// certificate and holds no key of another.
	#[test]
	fn a_gateway_identity_trusts_no_key_of_another_call() {
		let scenario = GatewayCerts::generate("CN=Scenario Gateway");
		let other = GatewayCerts::generate("CN=Scenario Gateway");

		let own_key = &scenario.cert.tbs_certificate.subject_public_key_info;
		let other_key = &other.cert.tbs_certificate.subject_public_key_info;
		let found = (
			scenario.trust.find_by_public_key(own_key),
			scenario.trust.find_by_public_key(other_key),
		);
		assert_eq!(found, (Some(&scenario.cert), None));
	}
}

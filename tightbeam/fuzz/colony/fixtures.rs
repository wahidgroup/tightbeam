//! Deterministic cert and TLS fixtures for the colony AFL harness.
//!
//! Fuzz bins cannot import `tests/`, so the multi-org identity helpers
//! live here beside the harness. Identities MUST be deterministic so
//! AFL sees stable coverage across identical inputs.

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::colony::cluster::ClusterTlsConfig;
use tightbeam::colony::common::ColonyNamespace;
use tightbeam::colony::hive::{HiveConfig, HiveTlsConfig};
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, CertificateSpec};
use tightbeam::der::Encode;
use tightbeam::testing::utils::{create_test_certificate_with_cn_and_uri_sans, create_test_signing_key};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::utils::urn::Urn;

/// Gateway identity bundle used by the colony fuzz topology.
///
/// The SPKI DER is encoded once at construction and shared as
/// `Arc<[u8]>`, so the shadow oracle borrows it per attempt instead of
/// re-encoding DER on every prediction.
pub(crate) struct GatewayCerts {
	/// Gateway leaf certificate shared across dials and trust anchors.
	pub cert: Arc<Certificate>,
	/// Signing key for control frames and mutual-auth dials.
	pub key: Secp256k1SigningKey,
	/// Trust store that anchors this gateway identity alone.
	pub trust: Arc<dyn CertificateTrust>,
	/// DER-encoded SubjectPublicKeyInfo shared for shadow and ACL lookups.
	pub spki: Arc<[u8]>,
}

impl GatewayCerts {
	/// Build a bundle from a certificate and key, encoding the SPKI DER
	/// once. Falls back to an empty SPKI when the certificate cannot
	/// encode, which the shadow treats as an unmatched identity.
	pub fn new(cert: Arc<Certificate>, key: Secp256k1SigningKey, trust: Arc<dyn CertificateTrust>) -> Self {
		let spki = spki_der(cert.as_ref());
		Self { cert, key, trust, spki }
	}

	#[allow(dead_code)]
	pub fn generate_colony(colony_urn: &Urn<'_>) -> Self {
		let raw = create_test_signing_key();
		let data = create_test_certificate_with_cn_and_uri_sans(&raw, "Colony Gateway", &[&colony_urn.to_string()]);

		let cert = Arc::new(data);
		let key = Secp256k1SigningKey::from(raw);
		let trust = combined_trust(&[cert.as_ref()]);
		Self::new(cert, key, trust)
	}
}

/// DER-encode a certificate's `SubjectPublicKeyInfo` once for shared,
/// borrow-only reuse by the shadow oracle.
fn spki_der(cert: &Certificate) -> Arc<[u8]> {
	match cert.tbs_certificate.subject_public_key_info.to_der() {
		Ok(der) => Arc::from(der),
		Err(_) => Arc::from(Vec::new()),
	}
}

pub(crate) type ClusterTestCerts = GatewayCerts;

pub(crate) fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

pub(crate) fn colony_urn(name: &str) -> Urn<'static> {
	colony_ns().colony(name).expect("static colony name")
}

pub(crate) fn servlet_urn(name: &str) -> Urn<'static> {
	colony_ns().servlet(name).expect("static servlet name")
}

/// Build a fixed secp256k1 key from a non-zero seed byte.
///
/// Distinct orgs MUST use distinct seeds so SPKIs and trust anchors stay
/// unique while remaining identical across AFL executions.
pub(crate) fn fixed_signing_key(seed: u8) -> k256::ecdsa::SigningKey {
	let secret = [seed.max(1); 32];
	k256::ecdsa::SigningKey::from_bytes(&secret.into()).expect("non-zero seed is a valid secp256k1 key")
}

/// Deterministic gateway identity for AFL (seeded key, fixed CN/SAN).
pub(crate) fn colony_identity(cn: &str, colony: &Urn<'_>, key_seed: u8) -> (Certificate, Secp256k1SigningKey) {
	let raw = fixed_signing_key(key_seed);
	let cert = create_test_certificate_with_cn_and_uri_sans(&raw, cn, &[&colony.to_string()]);
	(cert, Secp256k1SigningKey::from(raw))
}

fn combined_trust_builder(certs: &[&Certificate]) -> CertificateTrustBuilder<Sha3_256> {
	let mut builder = CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy);
	for cert in certs {
		builder = builder
			.with_certificate((*cert).to_owned())
			.expect("Failed to anchor combined trust");
	}

	builder
}

pub(crate) fn combined_trust(certs: &[&Certificate]) -> Arc<dyn CertificateTrust> {
	Arc::new(combined_trust_builder(certs).build())
}

pub(crate) fn cluster_tls_config(certs: &ClusterTestCerts) -> ClusterTlsConfig {
	let certificate = CertificateSpec::Built(Box::new(certs.cert.as_ref().clone()));
	let key = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));

	ClusterTlsConfig {
		certificate,
		key,
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.trust)),
		peer_trust: None,
	}
}

pub(crate) fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConfig {
	let certificate = CertificateSpec::Built(Box::new(certs.cert.as_ref().clone()));
	let key = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));
	let hive_tls = Arc::new(HiveTlsConfig { certificate, key, validators: vec![] });
	let offer = Arc::new(TransportOffer::mux(8));

	let mut conf = HiveConfig {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.trust)),
		..HiveConfig::default()
	};
	conf.pool.mux_offer = Some(offer);
	conf
}

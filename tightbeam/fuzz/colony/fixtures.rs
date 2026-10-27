//! Deterministic certificate and TLS fixtures for the colony AFL harness.
//!
//! A fuzz binary builds apart from `tests/`, so the multi-org identity
//! helpers live here beside the harness. Identities MUST be deterministic so
//! AFL sees stable coverage across identical inputs.

use std::sync::Arc;

use tightbeam::colony::cluster::ClusterTlsConfig;
use tightbeam::colony::hive::{HiveConfig, HiveTlsConfig};
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{CanonicalKey, Certificate, CertificateSpec, KeyCurves};
use tightbeam::testing::fixtures::{TestCertificate, TestKey};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::urn::Urn;

/// The gateway identity bundle that the colony fuzz topology uses.
///
/// [`GatewayCerts::new`] reads the canonical key once, so the shadow oracle
/// borrows it on each attempt in place of a key read per prediction.
pub(crate) struct GatewayCerts {
	/// The gateway leaf certificate, which dials and trust anchors share.
	pub cert: Arc<Certificate>,
	/// The signing key for control frames and mutual-auth dials.
	pub key: Secp256k1SigningKey,
	/// The trust store that anchors this gateway identity alone.
	pub trust: Arc<dyn CertificateTrust>,
	/// The canonical form of the certificate's key, by which a session proves
	/// its peer. The shadow and ACL lookups share it.
	pub canonical: Option<CanonicalKey>,
}

impl GatewayCerts {
	/// Build a bundle from a certificate and its key, and read the canonical
	/// key once. For a certificate whose key the encoder refuses, the bundle
	/// holds `None`, which the shadow treats as an unmatched identity.
	pub fn new(cert: Arc<Certificate>, key: Secp256k1SigningKey, trust: Arc<dyn CertificateTrust>) -> Self {
		let canonical = CanonicalKey::of(&cert.tbs_certificate.subject_public_key_info).ok();
		Self { cert, key, trust, canonical }
	}

	#[allow(dead_code)]
	pub fn generate_colony(colony_urn: &Urn<'_>) -> Self {
		let raw = TestKey::insecure_fixed_signing();
		let data = TestCertificate::with_cn_and_uri_sans(&raw, "Colony Gateway", &[&colony_urn.to_string()]);

		let cert = Arc::new(data);
		let key = Secp256k1SigningKey::from(raw);
		let trust = combined_trust(&[cert.as_ref()]);
		Self::new(cert, key, trust)
	}
}

pub(crate) type ClusterTestCerts = GatewayCerts;

pub(crate) fn colony_ns() -> ColonyNamespace {
	ColonyNamespace::default()
}

pub(crate) fn colony_urn(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let name = name.as_ref();
	colony_ns().colony(name).expect("static colony name")
}

pub(crate) fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let name = name.as_ref();
	colony_ns().servlet(name).expect("static servlet name")
}

/// Build a fixed secp256k1 key from a seed byte, where a seed of `0` gives
/// the key of seed `1`.
///
/// Distinct orgs MUST use distinct seeds so SPKIs and trust anchors stay
/// unique, and each stays identical across AFL executions.
pub(crate) fn fixed_signing_key(seed: u8) -> k256::ecdsa::SigningKey {
	let secret = [seed.max(1); 32];
	k256::ecdsa::SigningKey::from_bytes(&secret.into()).expect("non-zero seed is a valid secp256k1 key")
}

/// Build a deterministic gateway identity for AFL, with a seeded key and a
/// fixed CN and URI SAN.
pub(crate) fn colony_identity(
	cn: impl AsRef<str>,
	colony: &Urn<'_>,
	key_seed: u8,
) -> (Certificate, Secp256k1SigningKey) {
	let cn = cn.as_ref();
	let raw = fixed_signing_key(key_seed);
	let cert = TestCertificate::with_cn_and_uri_sans(&raw, cn, &[&colony.to_string()]);
	(cert, Secp256k1SigningKey::from(raw))
}

fn combined_trust_builder(certs: &[&Certificate]) -> CertificateTrustBuilder {
	let mut builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
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

	ClusterTlsConfig::new(certificate, key)
		.expect("the test certificate must decode")
		.with_hive_trust(Arc::clone(&certs.trust))
}

pub(crate) fn hive_tls_config(certs: &ClusterTestCerts) -> HiveConfig {
	let certificate = CertificateSpec::Built(Box::new(certs.cert.as_ref().clone()));
	let key = Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned()));
	let hive_tls = Arc::new(HiveTlsConfig::new(certificate, key, vec![]).expect("hive TLS material must decode"));
	let offer = Arc::new(TransportOffer::mux(8));
	let mut conf = HiveConfig {
		hive_tls: Some(hive_tls),
		trust_store: Some(Arc::clone(&certs.trust)),
		..HiveConfig::default()
	};

	conf.pool.mux_offer = Some(offer);
	conf
}

//! The colony fixtures that the colony, payment, and seam suites share, in
//! their plain tests and their scenarios.
//!
//! They configure a scenario hive and its control plane, and name servlet
//! types.

use tightbeam::colony::hive::{HiveConfig, HiveTlsConfig};
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::KeyPurposes;
use tightbeam::transport::handshake::PeerAuthentication;
use tightbeam::urn::Urn;

/// The base config of a scenario hive: the default config with the
/// anti-entropy re-registration beat off.
///
/// The specs count `CLUSTER_HIVE_REGISTERED` exactly, so a scenario hive
/// registers only when its scenario asks it to. A scenario that tests the
/// beat sets the interval itself.
pub fn scenario_hive_config() -> HiveConfig {
	let mut conf = HiveConfig::default();
	conf.control.reregister_interval = None;
	conf
}

/// The control-plane TLS of a hive that presents `identity` under the house
/// key purposes, and that admits a client with no certificate.
pub fn anonymous_hive_tls(identity: impl Into<SigningIdentity>) -> HiveTlsConfig {
	let tls = HiveTlsConfig::from_identity(identity.into(), PeerAuthentication::Anonymous, KeyPurposes::HOUSE);
	tls.expect("a fixture certificate admits the house signer purpose")
}

/// The type URN of the servlet `name` in the default colony namespace.
pub fn servlet_urn(name: &(impl AsRef<str> + ?Sized)) -> Urn<'static> {
	let name = name.as_ref();
	let urn = ColonyNamespace::default().servlet(name);
	urn.expect("test names satisfy the mint grammar")
}

//! Hive fixtures that the colony and payment scenarios share.

use tightbeam::colony::hive::HiveConfig;

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

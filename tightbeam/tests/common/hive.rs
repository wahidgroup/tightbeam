//! Hive fixtures that the colony and payment scenarios share.
//!
//! The hive and cluster suites of the colony also read the labels of their
//! records here.

use tightbeam::colony::hive::HiveConfig;

#[cfg(feature = "instrument")]
use tightbeam::trace::TraceCollector;
#[cfg(feature = "instrument")]
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

/// The label of each record of `event` that `trace` filed, in the order the
/// trace filed them.
#[cfg(feature = "instrument")]
pub fn recorded_labels(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<String>> {
	let recorded = trace.drain_events().into_iter();
	recorded
		.filter(|record| record.urn == event)
		.map(|record| record.label.as_deref().map(String::from))
		.collect()
}

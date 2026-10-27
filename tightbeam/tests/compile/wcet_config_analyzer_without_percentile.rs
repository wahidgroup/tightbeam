use std::sync::Arc;
use std::time::Duration;

use tightbeam::testing::timing::{DefaultStatisticalAnalyzer, WcetConfig};

// An analyzer computes the percentile that a WCET bound names, so a config
// holds its analyzer inside the percentile. A config with an analyzer and no
// percentile must fail to compile.
fn main() {
	let config = WcetConfig {
		duration: Duration::from_millis(10),
		percentile: None,
		analyzer: Some(Arc::new(DefaultStatisticalAnalyzer)),
	};
	let _ = config;
}

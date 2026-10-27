use tightbeam::testing::timing::WcetConfig;

// An analyzer computes the percentile that a WCET bound names, so a bound with
// an analyzer and no percentile must fail to compile.
fn main() {
	let config: WcetConfig = tightbeam::wcet!(
		std::time::Duration::from_millis(10),
		analyzer: tightbeam::testing::timing::DefaultStatisticalAnalyzer
	);
	let _ = config;
}

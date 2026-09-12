//! One `tb_scenario!` body, compiled under two tightbeam feature selections.
//!
//! `narrow` enables `testing` alone; `wide` adds `testing-csp`, `testing-fdr`
//! and `instrument`. Restoring a `#[cfg(feature = ...)]` to
//! [`SpecViolation::CspProcessViolation`] or `EventOrderViolationDetail` stops
//! `narrow` from building.

use std::sync::Arc;

use tightbeam::testing::specs::{EventOrderViolationDetail, SpecViolation};
use tightbeam::testing::TestHooks;

/// Names the verification layer that produced a violation.
///
/// Each arm binds its variant's payload, so both payload types must resolve
/// under whichever selection compiled this.
pub fn layer_of(violation: &SpecViolation) -> String {
	match violation {
		SpecViolation::CspProcessViolation(violations) => {
			format!("csp: {} violation(s)", violations.len())
		}
		SpecViolation::EventOrderViolation(detail) => {
			let order: &EventOrderViolationDetail = detail;
			format!("order: position {}", order.position)
		}
		other => format!("assertion: {other:?}"),
	}
}

/// Installs an observer that reads every violation the run produced.
pub fn observing_hooks() -> TestHooks {
	TestHooks {
		on_pass: None,
		on_fail: Some(Arc::new(|_ctx, violations| {
			let _layers: Vec<String> = violations.iter().map(layer_of).collect();
			Ok(())
		})),
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::specs::SpecViolation;
	use tightbeam::testing::ScenarioConfig;

	use super::{layer_of, observing_hooks};

	tightbeam::tb_scenario! {
		name: one_scenario_body_compiles_under_this_selection,
		config: ScenarioConfig::builder().with_hooks(observing_hooks()).build(),
		environment Bare {
			exec: |_env: SetupEnv<()>| Ok(())
		}
	}

	#[test]
	fn both_violation_payloads_are_nameable_under_this_selection() {
		let csp = SpecViolation::CspProcessViolation(Vec::new());

		assert_eq!(layer_of(&csp), "csp: 0 violation(s)");
	}
}

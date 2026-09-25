//! One `tb_scenario!` body, compiled under two tightbeam feature selections.
//!
//! `narrow` enables `testing` alone; `wide` adds `testing-csp`, `testing-fdr`
//! and `instrument`. Restoring a `#[cfg(feature = ...)]` to
//! [`SpecViolation::CspProcessViolation`] or `EventOrderViolationDetail` stops
//! `narrow` from building.

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
	TestHooks::on_fail(|_context, violations| {
		let _layers: Vec<String> = violations.iter().map(layer_of).collect();
	})
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::specs::SpecViolation;
	use tightbeam::testing::ScenarioConfig;
	use tightbeam::utils::urn::Urn;

	use super::{layer_of, observing_hooks};

	const SCENARIO_RAN: Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");

	// `narrow` compiles without a CSP or refinement layer, so the assertion
	// layer is the one verifier both selections share.
	tightbeam::tb_assert_spec! {
		pub ScenarioRanSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SCENARIO_RAN, tightbeam::exactly!(1))
			]
		}
	}

	// Neither selection enables `testing-timing`, so this spec is the proof
	// that the schedulability block expands to nothing rather than to a name
	// the consumer cannot resolve. The `task_set:` expression is dropped with
	// the block, which is why it may name a feature-gated type.
	tightbeam::tb_assert_spec! {
		pub ScheduleBlockSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SCENARIO_RAN, tightbeam::exactly!(1))
			],
			schedulability: {
				task_set: tightbeam::testing::schedulability::TaskSet {
					tasks: vec![],
					scheduler: tightbeam::testing::schedulability::SchedulerType::RateMonotonic,
				},
				scheduler: RateMonotonic,
				must_be_schedulable: true,
			}
		}
	}

	tightbeam::tb_scenario! {
		name: one_scenario_body_compiles_under_this_selection,
		config: ScenarioConfig::builder()
			.with_spec(ScenarioRanSpec::latest())
			.with_hooks(observing_hooks())
			.build(),
		environment Bare {
			exec: |env: SetupEnv<()>| {
				env.trace.event(SCENARIO_RAN)?;
				Ok(())
			}
		}
	}

	#[test]
	fn both_violation_payloads_are_nameable_under_this_selection() {
		let csp = SpecViolation::CspProcessViolation(Vec::new());
		assert_eq!(layer_of(&csp), "csp: 0 violation(s)");
	}
}

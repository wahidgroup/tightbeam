//! This crate compiles one `tb_scenario!` body under two tightbeam feature
//! selections.
//!
//! `narrow` enables `testing` alone, and `wide` adds `testing-csp`,
//! `testing-fdr`, `testing-timing`, and `instrument`. A
//! `#[cfg(feature = ...)]` on [`SpecViolation::CspProcessViolation`] or
//! [`EventOrderViolationDetail`] breaks the `narrow` build, and so does a
//! `#[cfg]` on `ScenarioVerdict::exploration`, which the observer reads.

use tightbeam::testing::specs::{EventOrderViolationDetail, SpecViolation};
use tightbeam::testing::TestHooks;

/// Under `narrow`, a `tb_assert_spec!` block whose feature is off fails to
/// compile, so a spec keeps every check it states.
///
/// The `schedulability:` block needs `testing-timing`:
///
/// ```compile_fail
/// const RAN: tightbeam::urn::Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");
///
/// tightbeam::tb_assert_spec! {
///     pub ScheduleBlockSpec,
///     V(1,0,0): {
///         mode: Accept,
///         assertions: [
///             (RAN, tightbeam::exactly!(1))
///         ],
///         schedulability: {
///             task_set: tightbeam::testing::schedulability::TaskSet {
///                 tasks: vec![],
///                 scheduler: tightbeam::testing::schedulability::SchedulerType::RateMonotonic,
///             },
///             scheduler: RateMonotonic,
///             must_be_schedulable: true,
///         }
///     }
/// }
/// ```
///
/// The `events:` list needs `instrument`:
///
/// ```compile_fail
/// const RAN: tightbeam::urn::Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");
///
/// tightbeam::tb_assert_spec! {
///     pub OrderedSpec,
///     V(1,0,0): {
///         mode: Accept,
///         assertions: [],
///         events: [ RAN ]
///     }
/// }
/// ```
#[cfg(not(feature = "wide"))]
pub struct RefusedSpecForms;

/// Names the verification layer that produced a violation.
///
/// Each arm binds its variant's payload, so both payload types must resolve
/// under whichever selection compiles this crate.
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

/// Returns hooks whose `on_fail` observer reads every violation of the run
/// and the trace of the Layer 3 exploration.
pub fn observing_hooks() -> TestHooks {
	TestHooks::on_fail(|context, violations| {
		let _layers: Vec<String> = violations.iter().map(layer_of).collect();
		let _explored = context.verdict().exploration().map(|exploration| exploration.assertions.len());
	})
}

#[cfg(test)]
mod tests {
	use tightbeam::testing::env::SetupEnv;
	use tightbeam::testing::specs::SpecViolation;
	use tightbeam::testing::ScenarioConfig;
	use tightbeam::urn::Urn;

	use super::{layer_of, observing_hooks};

	const SCENARIO_RAN: Urn<'static> = tightbeam::urn!("test", "event:consumer-expansion/scenario-ran");

	// `narrow` compiles the assertion layer alone, so that layer is the one
	// verifier both selections share.
	tightbeam::tb_assert_spec! {
		pub ScenarioRanSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(SCENARIO_RAN, tightbeam::exactly!(1))
			]
		}
	}

	// `wide` turns `testing-timing` on, so the schedulability block expands
	// to its assertion. Under `narrow` the block fails to compile, as the
	// `compile_fail` examples of `RefusedSpecForms` show.
	#[cfg(feature = "wide")]
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

//! The refusals of `ScenarioConfigBuilder::build`.
//!
//! A scenario is only worth running when some layer can reject it. These
//! tests hold the two halves of that rule against specs the macro built,
//! which is the only shape a caller can hand the builder.

use tightbeam::testing::{Expect, Layer, ScenarioConfig, ScenarioConfigError};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_cases, tb_process_spec};

const STEP: Urn<'static> = tightbeam::urn!("test", "event:config/step");

// Names no assertion, no gate decision, no required event and no task set, so
// it constrains the execution mode alone.
tb_assert_spec! {
	pub InertSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: []
	}
}

/// The config that a build accepts, or its refusal.
type Built = Result<ScenarioConfig, ScenarioConfigError>;

// A config builds when each layer it relies on can reject a run: some layer
// for a scenario that expects to pass, and the expected layer for a scenario
// that expects a violation.
tb_cases! {
	fn a_config_builds_when_the_layers_it_relies_on_can_reject(
		(build, refusal): (fn() -> Built, Option<ScenarioConfigError>)
	) {
		let built = build();
		assert_eq!(built.err(), refusal);
	}
	cases {
		/// A spec that grades nothing is no effective verifier.
		for_a_spec_that_grades_nothing => (
			|| ScenarioConfig::builder().with_spec(InertSpec::latest()).build(),
			Some(ScenarioConfigError::NoEffectiveVerifier),
		),
		/// A trace that never records a required event refutes it, so a spec
		/// that names one makes the assertion layer a verifier.
		#[cfg(feature = "instrument")]
		for_a_spec_that_only_orders_events => (
			|| ScenarioConfig::builder().with_spec(required_events::EventOrderSpec::latest()).build(),
			None,
		),
		/// The CSP layer makes the config able to reject, and the assertion
		/// layer that the scenario expects to reject grades nothing.
		#[cfg(feature = "testing-csp")]
		for_an_inert_spec_under_an_expected_assertion_violation => (
			|| {
				ScenarioConfig::builder()
					.with_spec(InertSpec::latest())
					.with_csp(with_another_layer::OneStep)
					.with_expect(Expect::Violation(Layer::Assertion))
					.build()
			},
			Some(ScenarioConfigError::ExpectViolationWithoutVerifier(Layer::Assertion)),
		),
	}
}

#[cfg(feature = "instrument")]
mod required_events {
	use super::*;

	tb_assert_spec! {
		pub EventOrderSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [],
			events: [ STEP ]
		}
	}
}

#[cfg(feature = "testing-csp")]
mod with_another_layer {
	use super::*;

	tb_process_spec! {
		pub OneStep,
		events {
			observable { STEP }
			hidden { }
		}
		states {
			S0 => { STEP => S1 }
		}
		terminal { S1 }
	}
}

#[cfg(feature = "testing-csp")]
mod progress {
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;

	use super::*;

	const UNRELATED: Urn<'static> = tightbeam::urn!("test", "event:config/unrelated");

	tb_assert_spec! {
		pub UnrelatedSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(UNRELATED, exactly!(1))
			]
		}
	}

	tb_process_spec! {
		pub NeverReached,
		events {
			observable { STEP }
			hidden { }
		}
		states {
			S0 => { STEP => S1 }
		}
		terminal { S1 }
	}

	// A trace that takes no transition satisfies every process, so a Layer 2
	// check over an alphabet the run never touches would hold whatever the
	// run did. The run below records only an event this process does not
	// model, which is the shape that check has to reject.
	tb_scenario! {
		name: a_process_whose_alphabet_the_run_never_touches_is_refused,
		config: ScenarioConfig::builder()
			.with_spec(UnrelatedSpec::latest())
			.with_csp(NeverReached)
			.with_expect(Expect::Violation(Layer::Csp))
			.build(),
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				trace.event(UNRELATED)?;

				Ok(())
			}
		}
	}
}

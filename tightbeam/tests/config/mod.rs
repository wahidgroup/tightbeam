//! What `ScenarioConfigBuilder::build` refuses
//!
//! A scenario is only worth running when some layer can reject it. These
//! tests hold the two halves of that rule against specs the macro built,
//! which is the only shape a caller can hand the builder.

use tightbeam::testing::{Expect, Layer, ScenarioConfig, ScenarioConfigError};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec};

const STEP: Urn<'static> = Urn::new("test", "event:config/step");

// Names no assertion, no gate decision, no required event and no task set, so
// it constrains the execution mode alone.
tb_assert_spec! {
	pub InertSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: []
	}
}

#[test]
fn a_spec_that_grades_nothing_is_not_an_effective_verifier() {
	let refused = ScenarioConfig::builder().with_spec(InertSpec::latest()).build();

	assert_eq!(refused.err(), Some(ScenarioConfigError::NoEffectiveVerifier));
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

	// A required event is refuted by a trace that never records it, so naming
	// one is enough on its own to make the assertion layer a verifier.
	#[test]
	fn a_spec_that_only_orders_events_can_reject() {
		let accepted = ScenarioConfig::builder().with_spec(EventOrderSpec::latest()).build();

		assert!(accepted.is_ok(), "a required event is a rejection this spec can produce");
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

	// The CSP layer makes the configuration able to reject, so the effective
	// verifier check passes.
	#[test]
	fn an_inert_spec_cannot_satisfy_an_expected_assertion_violation() {
		let refused = ScenarioConfig::builder()
			.with_spec(InertSpec::latest())
			.with_csp(OneStep)
			.with_expect(Expect::Violation(Layer::Assertion))
			.build();

		assert_eq!(
			refused.err(),
			Some(ScenarioConfigError::ExpectViolationWithoutVerifier(Layer::Assertion))
		);
	}
}

#[cfg(feature = "testing-csp")]
mod progress {
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;

	use super::*;

	const UNRELATED: Urn<'static> = Urn::new("test", "event:config/unrelated");

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

//! An outside crate writes its own [`ProcessSpec`] and its own
//! [`CompositionSpec`] by hand, and a scenario that takes either one through
//! [`ScenarioConfigBuilder::with_csp`] checks its run against the process that
//! the spec builds.
//!
//! [`ScenarioConfigBuilder::with_csp`]: tightbeam::testing::ScenarioConfigBuilder::with_csp

use std::borrow::Cow;

use tightbeam::testing::specs::composition::{
	CompositionError, CompositionMetadata, CompositionProperties, CompositionSpec,
};
use tightbeam::testing::specs::csp::{Process, ProcessBuildError, ProcessSpec, State};
use tightbeam::testing::ScenarioConfig;
use tightbeam::urn::Urn;

use super::consumed_trace_of;

/// The event that the `Send` process offers once.
const SEND: Urn<'static> = tightbeam::urn!("outside", "event:csp/send");
/// The event that the `Done` process offers once.
const DONE: Urn<'static> = tightbeam::urn!("outside", "event:csp/done");

/// A process that offers `event` at `Ready`, and stops at the terminal `End`.
fn once(name: &'static str, event: Urn<'static>) -> Result<Process, ProcessBuildError> {
	Process::builder(name)
		.initial_state(State("Ready"))
		.add_observable(event.clone())
		.add_transition(State("Ready"), event, State("End"))
		.add_terminal(State("End"))
		.build()
}

/// A spec that an outside crate writes: it builds the `Send` process itself,
/// and lends it as an owned process.
struct SendOnce;

impl ProcessSpec for SendOnce {
	fn to_process_cow(&self) -> Result<Cow<'_, Process>, CompositionError> {
		Ok(Cow::Owned(once("Send", SEND)?))
	}
}

/// A composition that an outside crate writes by hand: `Send` beside `Done`,
/// interleaved, which claims deadlock freedom.
struct SendBesideDone;

impl CompositionSpec for SendBesideDone {
	fn process() -> Result<Process, CompositionError> {
		Process::interleaved_parallel(&once("Send", SEND)?, &once("Done", DONE)?)
	}

	fn metadata() -> Result<CompositionMetadata, CompositionError> {
		let properties = CompositionProperties { deadlock_free: Some(true), ..CompositionProperties::default() };
		Ok(CompositionMetadata { name: "SendBesideDone", properties, ..CompositionMetadata::default() })
	}
}

/// Whether a scenario under `spec` finds the run of `labels` valid by its
/// CSP layer, or `None` when the scenario holds no CSP layer.
fn csp_verdict_of(spec: impl ProcessSpec + Send + Sync + 'static, labels: &[Urn<'static>]) -> Option<bool> {
	let built = ScenarioConfig::builder().with_csp(spec).build();
	let config = built.expect("the spec builds its process");
	let verified = config.verify(&consumed_trace_of(labels.iter().cloned()), Ok(()));
	let verdict = verified.expect("a scenario with no FDR layer verifies");
	verdict.csp().map(|csp| csp.valid)
}

/// A function that answers the verdict of a scenario under one outside spec
/// on the run of the labels it takes.
type VerdictOf = fn(&[Urn<'static>]) -> Option<bool>;

/// The verdict of a scenario under [`SendOnce`] on the run of `labels`.
fn process_verdict(labels: &[Urn<'static>]) -> Option<bool> {
	csp_verdict_of(SendOnce, labels)
}

/// The verdict of a scenario under [`SendBesideDone`] on the run of `labels`.
fn composition_verdict(labels: &[Urn<'static>]) -> Option<bool> {
	csp_verdict_of(SendBesideDone, labels)
}

// A scenario judges a run by the CSP layer that an outside spec builds.
tightbeam::tb_cases! {
	fn a_scenario_judges_a_run_by_an_outside_spec(
		(verdict_of, labels, valid): (VerdictOf, &[Urn<'static>], bool)
	) {
		let verdict = verdict_of(labels);
		assert_eq!(verdict, Some(valid));
	}
	cases {
		/// The process of an outside spec refuses a second `Send`.
		whose_process_refuses_a_repeat => (process_verdict, &[SEND, SEND], false),
		/// An outside composition refuses a second `Done`.
		whose_composition_refuses_a_repeat => (composition_verdict, &[DONE, DONE], false),
		/// An outside composition admits `Done` beside `Send`.
		whose_composition_admits_an_interleaving => (composition_verdict, &[DONE, SEND], true),
	}
}

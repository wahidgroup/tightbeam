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
use tightbeam::trace::{ConsumedTrace, TraceCollector};
use tightbeam::urn::Urn;

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

/// The trace of a run that records each of `labels` once, in order.
fn run_of(labels: &[Urn<'static>]) -> ConsumedTrace {
	let collector = TraceCollector::new();
	for label in labels {
		collector.event(label).expect("the run injects no fault").emit();
	}

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);
	trace
}

/// Whether a scenario under `spec` finds the run of `labels` valid by its
/// CSP layer, or `None` when the scenario holds no CSP layer.
fn csp_verdict_of(spec: impl ProcessSpec + Send + Sync + 'static, labels: &[Urn<'static>]) -> Option<bool> {
	let built = ScenarioConfig::builder().with_csp(spec).build();
	let config = built.expect("the spec builds its process");
	let verified = config.verify(&run_of(labels), Ok(()));
	let verdict = verified.expect("a scenario with no FDR layer verifies");
	verdict.csp().map(|csp| csp.valid)
}

#[test]
fn a_scenario_refuses_a_run_that_the_process_of_an_outside_spec_refuses() {
	assert_eq!(csp_verdict_of(SendOnce, &[SEND, SEND]), Some(false));
}

#[test]
fn a_scenario_refuses_a_run_that_an_outside_composition_refuses() {
	assert_eq!(csp_verdict_of(SendBesideDone, &[DONE, DONE]), Some(false));
}

#[test]
fn a_scenario_admits_a_run_that_an_outside_composition_interleaves() {
	assert_eq!(csp_verdict_of(SendBesideDone, &[DONE, SEND]), Some(true));
}

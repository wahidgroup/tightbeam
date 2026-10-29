//! The scheduler constraint of an FDR run, `FdrConfig::scheduler`, through the
//! public API.
//!
//! The subject interleaves two processes, `A` (`a1` then `a2`) and `B` (`b1`
//! then `b2`). One cooperative scheduler runs a process until it blocks, so
//! the subject takes one process to its end before the other starts. A
//! preemptive scheduler can switch after each event, so it keeps every
//! interleaving.

use core::error::Error;
use core::num::NonZeroU32;

use std::borrow::Cow;

use tightbeam::testing::error::{FdrConfigError, TestingError};
use tightbeam::testing::fdr::{
	Decision, DefaultFdrExplorer, FaultModel, FdrConfig, FdrVerdict, SchedulerConstraint, SchedulerCounts,
	SchedulerModel,
};
use tightbeam::testing::specs::composition::CompositionOperator;
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::testing::{ProcessEvent, ProcessState};
use tightbeam::TightBeamError;

#[cfg(feature = "instrument")]
use tightbeam::instrumentation::events::ENABLED_SET_SAMPLE;
#[cfg(feature = "instrument")]
use tightbeam::instrumentation::TbInstrumentationConfig;
#[cfg(feature = "instrument")]
use tightbeam::trace::{TraceCollector, TraceConfig};

/// The process `A`, which takes `a1` and then `a2`, and ends.
fn a() -> Result<Process, ProcessBuildError> {
	Process::builder("A")
		.initial_state(State("A0"))
		.add_observable(Event("a1"))
		.add_observable(Event("a2"))
		.add_transition(State("A0"), Event("a1"), State("A1"))
		.add_transition(State("A1"), Event("a2"), State("A2"))
		.add_terminal(State("A2"))
		.build()
}

/// The process `B`, which takes `b1` and then `b2`, and ends.
fn b() -> Result<Process, ProcessBuildError> {
	Process::builder("B")
		.initial_state(State("B0"))
		.add_observable(Event("b1"))
		.add_observable(Event("b2"))
		.add_transition(State("B0"), Event("b1"), State("B1"))
		.add_transition(State("B1"), Event("b2"), State("B2"))
		.add_terminal(State("B2"))
		.build()
}

/// The interleaving `A ||| B`.
fn interleaved() -> Result<Process, Box<dyn Error>> {
	let composed = CompositionOperator::Interleaved.compose(&a()?, &b()?)?;
	Ok(composed)
}

/// The spec that runs `A` to its end and then `B`, or `B` and then `A`.
fn serial() -> Result<Process, ProcessBuildError> {
	Process::builder("Serial")
		.initial_state(State("s0"))
		.add_observable(Event("a1"))
		.add_observable(Event("a2"))
		.add_observable(Event("b1"))
		.add_observable(Event("b2"))
		.add_transition(State("s0"), Event("a1"), State("p1"))
		.add_transition(State("p1"), Event("a2"), State("p2"))
		.add_transition(State("p2"), Event("b1"), State("p3"))
		.add_transition(State("p3"), Event("b2"), State("end"))
		.add_transition(State("s0"), Event("b1"), State("q1"))
		.add_transition(State("q1"), Event("b2"), State("q2"))
		.add_transition(State("q2"), Event("a1"), State("q3"))
		.add_transition(State("q3"), Event("a2"), State("end"))
		.add_terminal(State("end"))
		.build()
}

/// One scheduler of `model` for `processes` processes.
fn one_scheduler(model: SchedulerModel, processes: u32) -> Result<SchedulerConstraint, Box<dyn Error>> {
	let processes = NonZeroU32::try_from(processes)?;
	let counts = SchedulerCounts { schedulers: NonZeroU32::MIN, processes };
	let constraint = SchedulerConstraint::new(model, counts)?;
	Ok(constraint)
}

/// The verdict of the interleaving against the serial spec, under
/// `scheduler`.
fn refined_under(scheduler: SchedulerConstraint) -> Result<FdrVerdict, Box<dyn Error>> {
	let subject = interleaved()?;
	let config = FdrConfig { specs: vec![serial()?], scheduler: Some(scheduler), ..FdrConfig::default() };

	let verdict = DefaultFdrExplorer::with_defaults(&subject, config).explore()?;
	Ok(verdict)
}

#[test]
fn one_cooperative_scheduler_runs_each_process_until_it_blocks() -> Result<(), Box<dyn Error>> {
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 2)?;

	let verdict = refined_under(scheduler)?;
	assert_eq!(verdict.trace_refines, Decision::Holds, "{:?}", verdict.trace_refinement_witness);
	Ok(())
}

#[test]
fn a_preemptive_scheduler_keeps_every_interleaving() -> Result<(), Box<dyn Error>> {
	let scheduler = one_scheduler(SchedulerModel::Preemptive, 2)?;

	let verdict = refined_under(scheduler)?;
	assert_eq!(verdict.trace_refines, Decision::Refuted);
	Ok(())
}

/// The FDR configuration error of `explored`, or `None` for another outcome.
fn config_error(explored: Result<FdrVerdict, TightBeamError>) -> Option<FdrConfigError> {
	match explored {
		Err(TightBeamError::TestingError(TestingError::FdrConfig(error))) => Some(error),
		_ => None,
	}
}

#[test]
fn a_constraint_on_more_processes_than_the_subject_composes_is_refused() -> Result<(), Box<dyn Error>> {
	let subject = interleaved()?;
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 3)?;
	let config = FdrConfig { scheduler: Some(scheduler), ..FdrConfig::default() };

	let explored = DefaultFdrExplorer::with_defaults(&subject, config).explore();

	let reason = "counts processes other than the components of the process";
	let misfit = FdrConfigError { field: "scheduler", reason };
	assert_eq!(config_error(explored), Some(misfit));
	Ok(())
}

/// The walk of each seed offers `a2` alone after `a1`, because `A` holds the
/// one scheduler until it ends.
#[cfg(feature = "instrument")]
#[test]
fn the_walk_offers_the_running_process_alone() -> Result<(), Box<dyn Error>> {
	let subject = interleaved()?;
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 2)?;
	let config = FdrConfig { scheduler: Some(scheduler), ..FdrConfig::default() };
	let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));

	DefaultFdrExplorer::with_defaults(&subject, config).explore_into(&trace)?;

	let events = trace.drain_events();
	let samples = events.iter().filter(|event| event.urn == ENABLED_SET_SAMPLE);
	let labels: Vec<&str> = samples.filter_map(|event| event.label.as_deref()).collect();
	assert!(labels.contains(&"(A ||| B).(A1,B0)@{0}: {a2}"), "{labels:?}");
	Ok(())
}

/// A state of the interleaving `A ||| B`, as a fault point names it.
#[derive(Clone, Copy, Debug)]
struct Interleaved(&'static str);

impl ProcessState for Interleaved {
	fn process_name(&self) -> &'static str {
		"(A ||| B)"
	}

	fn state_name(&self) -> &'static str {
		self.0
	}
}

/// An event of `A` or `B`, as a fault point names it.
#[derive(Clone, Debug)]
struct Named(&'static str);

impl ProcessEvent for Named {
	fn event_label(&self) -> Cow<'static, str> {
		Cow::Borrowed(self.0)
	}
}

/// The fault model that fails each `event` at `state`.
fn failing(state: &'static str, event: &'static str) -> FaultModel {
	let closed = || TightBeamError::ChannelClosed;
	FaultModel::default().with_fault(Interleaved(state), Named(event), closed, tightbeam::bps!(10000))
}

#[test]
fn a_fault_point_at_a_state_of_the_subject_fires_in_its_scheduled_walk() -> Result<(), Box<dyn Error>> {
	let subject = interleaved()?;
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 2)?;
	let fault_model = failing("(A0,B0)", "a1");
	let faulted = FdrConfig { fault_model: Some(fault_model), ..FdrConfig::default() };
	let config = FdrConfig { scheduler: Some(scheduler), ..faulted };

	let verdict = DefaultFdrExplorer::with_defaults(&subject, config).explore()?;

	let fired = verdict.faults_injected.first().map(|fault| fault.csp_state.as_str());
	assert_eq!(fired, Some("(A ||| B).(A0,B0)"));
	Ok(())
}

/// A spec under faults runs scheduled, so one scheduler never reaches
/// `(A1,B1)`, where both processes are midway.
#[test]
fn a_spec_under_faults_runs_scheduled() -> Result<(), Box<dyn Error>> {
	let subject = interleaved()?;
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 2)?;
	let fault_model = failing("(A1,B1)", "a2");
	let specs = vec![interleaved()?];
	let faulted = FdrConfig { specs, fault_model: Some(fault_model), ..FdrConfig::default() };
	let config = FdrConfig { scheduler: Some(scheduler), ..faulted };

	let verdict = DefaultFdrExplorer::with_defaults(&subject, config).explore()?;
	assert_eq!(verdict.faults_injected, []);
	Ok(())
}

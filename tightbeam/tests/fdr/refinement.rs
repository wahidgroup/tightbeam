//! A refinement checker that an outside crate brings, built through the
//! public API of tightbeam alone.
//!
//! The checker reads the failure rule through the default
//! [`RefinementChecker::compute_refusals`] and the divergence rule through
//! [`Process::divergent_states`], so each rule keeps its one home in
//! tightbeam.

use std::collections::HashSet;
use std::sync::Arc;

use tightbeam::testing::fdr::{
	DefaultExplorationEngine, Failure, FdrConfig, FdrExplorer, FdrVerdict, RefinementChecker, RefinementOutcome, Trace,
};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, ProcessBuilder, State};

/// A refinement checker that compares the failures and the divergences of the
/// states each process reaches.
struct OutsideChecker;

impl OutsideChecker {
	/// Each state that `process` reaches within `depth` observable events,
	/// paired with the trace that first reaches it, in breadth-first order.
	fn reached(process: &Process, depth: usize) -> Vec<(State, Trace)> {
		let mut reached = vec![(process.initial, Vec::new())];
		let mut next = 0;
		while let Some((state, trace)) = reached.get(next).cloned() {
			next += 1;
			for action in process.enabled(state) {
				for to in process.step(state, &action.event) {
					let mut longer = trace.clone();
					if action.is_observable() {
						longer.push(action.event);
					}

					let known = reached.iter().any(|(seen, _trace)| *seen == to);
					if !known && longer.len() <= depth {
						reached.push((to, longer));
					}
				}
			}
		}

		reached
	}

	/// The first item of `found` that `allowed` lacks, as a refinement
	/// outcome.
	fn outcome<W: PartialEq>(found: Vec<W>, allowed: &[W]) -> RefinementOutcome<W> {
		let missing = found.into_iter().find(|item| !allowed.contains(item));
		match missing {
			Some(witness) => RefinementOutcome::Violated(witness),
			None => RefinementOutcome::Holds { complete: true },
		}
	}
}

impl RefinementChecker for OutsideChecker {
	fn check_trace_refinement(&mut self, _spec: &Process, _impl_process: &Process) -> RefinementOutcome<Trace> {
		RefinementOutcome::Holds { complete: true }
	}

	fn check_failures_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Failure> {
		let (allowed, _complete) = self.compute_failures(spec, 8);
		let (found, _complete) = self.compute_failures(impl_process, 8);
		Self::outcome(found, &allowed)
	}

	fn check_divergence_refinement(&mut self, spec: &Process, impl_process: &Process) -> RefinementOutcome<Trace> {
		let (allowed, _complete) = self.compute_divergences(spec, 8);
		let (found, _complete) = self.compute_divergences(impl_process, 8);
		let allowed: Vec<Trace> = allowed.into_iter().collect();
		Self::outcome(found.into_iter().collect(), &allowed)
	}

	fn compute_traces(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let reached = Self::reached(process, max_depth);
		(reached.into_iter().map(|(_state, trace)| trace).collect(), true)
	}

	fn compute_failures(&mut self, process: &Process, max_depth: usize) -> (Vec<Failure>, bool) {
		let reached = Self::reached(process, max_depth);
		let refused = |(state, trace): (State, Trace)| self.compute_refusals(process, state).map(|set| (trace, set));
		(reached.into_iter().filter_map(refused).collect(), true)
	}

	fn compute_divergences(&mut self, process: &Process, max_depth: usize) -> (HashSet<Trace>, bool) {
		let divergent = process.divergent_states();
		let reached = Self::reached(process, max_depth);
		let diverging = reached.into_iter().filter(|(state, _trace)| divergent.contains(*state));
		(diverging.map(|(_state, trace)| trace).collect(), true)
	}
}

/// A process whose hidden `t` and `u` take `S1` to `S2` and back, with the
/// observable exit `b` at `S2`, so it can diverge after `a`.
fn spinning() -> Result<Process, ProcessBuildError> {
	Process::builder("Spinning")
		.initial_state(State("S0"))
		.add_observable(Event("a"))
		.add_observable(Event("b"))
		.add_hidden(Event("t"))
		.add_hidden(Event("u"))
		.add_transition(State("S0"), Event("a"), State("S1"))
		.add_transition(State("S1"), Event("t"), State("S2"))
		.add_transition(State("S2"), Event("u"), State("S1"))
		.add_transition(State("S2"), Event("b"), State("S3"))
		.add_terminal(State("S3"))
		.build()
}

/// A process of observable events alone, which performs `a` and then `b`.
fn steady() -> Result<Process, ProcessBuildError> {
	Process::builder("Steady")
		.initial_state(State("S0"))
		.add_observable(Event("a"))
		.add_observable(Event("b"))
		.add_transition(State("S0"), Event("a"), State("S1"))
		.add_transition(State("S1"), Event("b"), State("S2"))
		.add_terminal(State("S2"))
		.build()
}

/// The builder of a process that offers `a` at `Idle`, which leads to
/// `Done`, where the process can stop.
fn idling_builder() -> ProcessBuilder {
	Process::builder("Idling")
		.initial_state(State("Idle"))
		.add_observable(Event("a"))
		.add_observable(Event("b"))
		.add_transition(State("Idle"), Event("a"), State("Done"))
		.add_terminal(State("Done"))
}

/// The process of [`idling_builder`], which can also stop at `Idle`.
fn accepting() -> Result<Process, ProcessBuildError> {
	idling_builder().add_terminal(State("Idle")).build()
}

/// What the outside checker decided about `subject` against `spec`.
fn verdict_of(subject: &Process, spec: Process) -> FdrVerdict {
	let config = Arc::new(FdrConfig { specs: vec![spec], fail_fast: false, ..Default::default() });
	let engine = DefaultExplorationEngine::new(subject, Arc::clone(&config));
	let mut explorer = FdrExplorer::new_with_arc(subject, config, engine, OutsideChecker);
	explorer.explore()
}

#[test]
fn an_outside_checker_finds_a_divergence_through_the_divergence_rule() -> Result<(), ProcessBuildError> {
	let subject = spinning()?;

	let verdict = verdict_of(&subject, steady()?);

	let after_a = Some(vec![Event("a")]);
	assert_eq!(verdict.divergence_refinement_witness, after_a, "`S1` and `S2` can spin");
	Ok(())
}

#[test]
fn an_outside_checker_finds_an_accepting_refusal_through_the_failure_rule() -> Result<(), ProcessBuildError> {
	let subject = accepting()?;

	let verdict = verdict_of(&subject, idling_builder().build()?);

	let every_event = Some((vec![], HashSet::from([Event("a"), Event("b")])));
	assert_eq!(verdict.failures_refinement_witness, every_event, "it can stop at `Idle`");
	Ok(())
}

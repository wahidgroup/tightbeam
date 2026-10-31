//! The scheduler constraint of an FDR run: m schedulers that run the n
//! component processes of a process.
//!
//! [`SchedulerConstraint::schedule`] builds the process that the schedulers
//! let a process run. Each of its states pairs a state of the process with the
//! components that hold a scheduler, and `SchedulerModel::after` decides each
//! step. The walk and the refinement checks read the scheduled process as they
//! read any process.
//!
//! # Sources
//!
//! - M. Pedersen and K. Chalmers, "Refinement Checking of Cooperatively
//!   Scheduled Concurrent Systems," SBMF 2024: <https://doi.org/10.1007/978-3-031-78561-1_1>

use std::collections::{BTreeSet, HashSet, VecDeque};

use crate::testing::error::FdrConfigError;
use crate::testing::fdr::config::{SchedulerConstraint, SchedulerModel};
use crate::testing::specs::csp::{intern, Components, Event, Process, State, TransitionRelation};

/// A state of a process, paired with the components that hold a scheduler.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Placement {
	/// The state of the process before scheduling.
	state: State,
	/// The components that hold a scheduler.
	running: BTreeSet<u32>,
}

impl Placement {
	/// The scheduled state of this placement, named `state@{c,...}` after the
	/// components that hold a scheduler.
	fn scheduled(&self) -> State {
		let running: Vec<String> = self.running.iter().map(u32::to_string).collect();
		let name = format!("{}@{{{}}}", self.state.0, running.join(","));
		State(intern(name))
	}
}

impl SchedulerConstraint {
	/// The process that the schedulers of this constraint let `process` run.
	///
	/// - Each state pairs a state of `process` with the components that hold a
	///   scheduler, from none at the start.
	/// - An edge leads to its target when `SchedulerModel::after` admits its movers.
	/// - The process keeps the name, the alphabets, and the timing constraints of `process`.
	/// - Each state is accepting or a choice point when its state of `process` is.
	///
	/// # Errors
	///
	/// - [`FdrConfigError`] -- the constraint counts processes other than the components of `process`.
	/// - [`FdrConfigError`] -- `process` has a timed transition, whose guard a scheduled edge cannot carry.
	pub(crate) fn schedule(&self, process: &Process) -> Result<Process, FdrConfigError> {
		let components = process.components.count();
		if components != self.processes().get() {
			let reason = "counts processes other than the components of the process";
			return Err(FdrConfigError { field: "scheduler", reason });
		}
		#[cfg(feature = "testing-timing")]
		if process.has_timed_transitions() {
			let reason = "cannot schedule a process with a timed transition";
			return Err(FdrConfigError { field: "scheduler", reason });
		}

		let start = Placement { state: process.initial, running: BTreeSet::new() };
		let mut scheduled = process.clone();
		scheduled.initial = start.scheduled();
		scheduled.states = HashSet::new();
		scheduled.terminal = HashSet::new();
		scheduled.choice = HashSet::new();
		scheduled.transitions = TransitionRelation::new();
		scheduled.components = Components::default();

		let mut queue = VecDeque::from([start.clone()]);
		let mut placed = HashSet::from([start]);
		while let Some(placement) = queue.pop_front() {
			let from = scheduled.place(&placement, process);
			for (event, next) in self.steps(process, &placement) {
				scheduled.transitions.add(from, event, next.scheduled());
				if placed.insert(next.clone()) {
					queue.push_back(next);
				}
			}
		}

		Ok(scheduled)
	}

	/// Each step from `placement` of `process` that the schedulers admit, as
	/// its event and the placement it leads to, each once.
	fn steps(&self, process: &Process, placement: &Placement) -> Vec<(Event, Placement)> {
		let schedulers = self.schedulers().get();
		let mut steps = Vec::new();
		for action in process.enabled(placement.state) {
			let mut targets = process.step(placement.state, &action.event);
			targets.sort_unstable();
			targets.dedup();

			for target in targets {
				let active = process.active_at(target);
				let edge = (placement.state, action.event, target);
				for movers in process.components.moving(edge, 0) {
					let Some(running) = self.model().after(schedulers, &placement.running, &movers, &active) else {
						continue;
					};

					let step = (action.event, Placement { state: target, running });
					if !steps.contains(&step) {
						steps.push(step);
					}
				}
			}
		}

		steps
	}
}

impl SchedulerModel {
	/// The components that hold a scheduler after `movers` take an edge, or
	/// `None` when no scheduler admits the edge.
	///
	/// - The edge runs when one of `movers` holds a scheduler, or when one of `schedulers` is free.
	/// - `running` holds a scheduler before the edge, and `active` names each
	///   component with an edge at its target.
	/// - A component with no edge at the target is blocked, so it yields its scheduler.
	fn after(
		self,
		schedulers: u32,
		running: &BTreeSet<u32>,
		movers: &BTreeSet<u32>,
		active: &BTreeSet<u32>,
	) -> Option<BTreeSet<u32>> {
		let holds = movers.iter().any(|mover| running.contains(mover));
		let free = u32::try_from(running.len()).is_ok_and(|held| held < schedulers);
		if !holds && !free {
			return None;
		}

		let next = match self {
			Self::Preemptive => BTreeSet::new(),
			Self::Cooperative if movers.len() > 1 => running - movers,
			Self::Cooperative => running | movers,
		};

		Some(&next & active)
	}
}

impl Process {
	/// Each component that moves on an edge at `state`.
	fn active_at(&self, state: State) -> BTreeSet<u32> {
		let mut active = BTreeSet::new();
		for action in self.enabled(state) {
			for target in self.step(state, &action.event) {
				let alternatives = self.components.moving((state, action.event, target), 0);
				active.extend(alternatives.into_iter().flatten());
			}
		}

		active
	}

	/// Adds the scheduled state of `placement` to this scheduled process, and
	/// returns it.
	///
	/// The state is accepting or a choice point when its state of `base` is,
	/// and it records the state of `base` that it runs.
	fn place(&mut self, placement: &Placement, base: &Process) -> State {
		let scheduled = placement.scheduled();
		self.states.insert(scheduled);
		if base.is_terminal(placement.state) {
			self.terminal.insert(scheduled);
		}
		if base.is_choice(placement.state) {
			self.choice.insert(scheduled);
		}

		self.components.schedule_as(scheduled, placement.state);
		scheduled
	}
}

#[cfg(test)]
mod tests {
	use core::num::NonZeroU32;
	use std::collections::{HashMap, HashSet};

	use crate::testing::fdr::{SchedulerConstraint, SchedulerCounts, SchedulerModel};
	use crate::testing::fixtures::TestProcess;
	use crate::testing::specs::composition::CompositionOperator;
	use crate::testing::specs::csp::{Event, Process};
	use crate::testing::TestResult;

	/// A fixture that builds the process of a row.
	type Fixture = fn() -> Process;

	/// The interleaving of `a1` then `a2` with `b1` then `b2`.
	fn interleaved() -> Process {
		let a = TestProcess::chain("A", &["A0", "A1", "A2"], &["a1", "a2"]);
		let b = TestProcess::chain("B", &["B0", "B1", "B2"], &["b1", "b2"]);
		let composed = CompositionOperator::Interleaved.compose(&a, &b);
		composed.expect("an interleaving builds")
	}

	/// The interleaving of [`interleaved`] with `a1` renamed to `z`.
	fn renamed_interleaving() -> Process {
		let renamed = interleaved().rename(HashMap::from([(Event("a1"), Event("z"))]));
		renamed.expect("a renaming of one event builds")
	}

	/// `A` (`a1`, the shared `x`, `a2`) beside `B` (`x`, `b2`), synchronized on
	/// `x`, and interleaved with `C` (`c`).
	fn shared_beside_a_third() -> Process {
		let a = TestProcess::chain("A", &["A0", "A1", "A2", "A3"], &["a1", "x", "a2"]);
		let b = TestProcess::chain("B", &["B0", "B1", "B2"], &["x", "b2"]);
		let c = TestProcess::chain("C", &["C0", "C1"], &["c"]);

		let interface = CompositionOperator::Interface { events: HashSet::from([Event("x")]) };
		let ab = interface.compose(&a, &b).expect("the interface parallel builds");
		let composed = CompositionOperator::Interleaved.compose(&ab, &c);
		composed.expect("the interleaving builds")
	}

	/// The constraint of one scheduler of `model` for `processes` processes.
	fn one_scheduler(model: SchedulerModel, processes: u32) -> SchedulerConstraint {
		let processes = NonZeroU32::try_from(processes).expect("the count is not zero");
		let counts = SchedulerCounts { schedulers: NonZeroU32::MIN, processes };
		SchedulerConstraint::new(model, counts).expect("one scheduler runs at least one process")
	}

	/// The observable events that `process` offers after `trace`, along the
	/// first target of each event.
	fn offers_after(process: &Process, trace: &[&'static str]) -> HashSet<Event> {
		let mut state = process.initial();
		for event in trace {
			let targets = process.step(state, &Event(event));
			state = *targets.first().expect("the trace is a trace of the process");
		}

		process.offers(state)
	}

	// One cooperative scheduler runs a process until it blocks or takes a
	// shared event, so the composition offers the events of the process that
	// holds the scheduler, or of each process once a holder yields.
	crate::tb_cases! {
		fn a_cooperative_scheduler_offers(
			(process, processes, trace, offered): (Fixture, u32, &'static [&'static str], HashSet<Event>)
		) -> TestResult {
			let scheduled = one_scheduler(SchedulerModel::Cooperative, processes).schedule(&process())?;
			let offers = offers_after(&scheduled, trace);
			assert_eq!(offers, offered);
			Ok(())
		}

		cases {
			the_next_event_of_the_running_process => (interleaved, 2, &["a1"], HashSet::from([Event("a2")])),
			the_events_of_another_process_once_one_blocks => (
				interleaved,
				2,
				&["a1", "a2"],
				HashSet::from([Event("b1")]),
			),
			the_events_of_each_mover_after_a_shared_event => (
				shared_beside_a_third,
				3,
				&["a1", "x"],
				HashSet::from([Event("a2"), Event("b2"), Event("c")]),
			),
			the_components_of_a_renamed_edge => (renamed_interleaving, 2, &["z"], HashSet::from([Event("a2")])),
		}
	}
}

//! The CSP processes, the scheduler, and the explorer that the FDR and seam
//! suites share.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(feature = "testing-fault")]
use core::num::NonZeroU32;

use tightbeam::testing::fdr::{DefaultCache, DefaultRefinementChecker, ExplorationCore, FdrConfig, FdrExplorer};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};

#[cfg(feature = "testing-fault")]
use tightbeam::testing::fdr::{SchedulerConstraint, SchedulerCounts, SchedulerModel};

/// A process named `name` that takes `event` from `start` to the accepting
/// `end`.
pub fn once(name: &'static str, (start, end): (&'static str, &'static str), event: &'static str) -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder(name)
		.initial_state(State(start))
		.add_observable(Event(event))
		.add_transition(State(start), Event(event), State(end))
		.add_terminal(State(end))
		.build();

	built.expect("a process of one event builds")
}

/// One scheduler of `model` for `processes` processes.
#[cfg(feature = "testing-fault")]
pub fn one_scheduler(model: SchedulerModel, processes: u32) -> SchedulerConstraint {
	let processes = NonZeroU32::try_from(processes).expect("a scheduler runs at least one process");
	let counts = SchedulerCounts { schedulers: NonZeroU32::MIN, processes };
	let constraint = SchedulerConstraint::new(model, counts);
	constraint.expect("one scheduler of a nonzero count of processes builds")
}

/// `config` under one cooperative scheduler of two processes, the two sides
/// of an interleaving.
#[cfg(feature = "testing-fault")]
pub fn cooperative(config: FdrConfig) -> FdrConfig {
	let scheduler = one_scheduler(SchedulerModel::Cooperative, 2);
	FdrConfig { scheduler: Some(scheduler), ..config }
}

/// An explorer of `process` under `config` that explores through the engine
/// that `engine` builds over the process and the shared config, and checks
/// refinement through the house checker.
pub fn explorer_of<'a, E: ExplorationCore>(
	process: &'a Process,
	config: FdrConfig,
	engine: impl FnOnce(&'a Process, Arc<FdrConfig>) -> E,
) -> FdrExplorer<'a, E, DefaultRefinementChecker<'a, DefaultCache>> {
	let config = Arc::new(config);
	let engine = engine(process, Arc::clone(&config));
	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(process, Arc::clone(&config), cache);

	FdrExplorer::new_with_arc(process, config, engine, checker)
}

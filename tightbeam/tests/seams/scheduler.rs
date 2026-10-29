//! An outside crate brings its own [`ExplorationCore`], and an FDR run with a
//! scheduler constraint hands that engine the scheduled subject through
//! [`ExplorationCore::for_process`].

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use core::num::NonZeroU32;

use tightbeam::testing::fdr::{
	DefaultCache, DefaultExplorationEngine, DefaultRefinementChecker, ExplorationCore, FdrConfig, FdrExplorer,
	SchedulerConstraint, SchedulerCounts, SchedulerModel, SeedResult, Trace,
};
use tightbeam::testing::specs::composition::CompositionOperator;
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};

/// An exploration engine that notes the initial state of each process that
/// [`ExplorationCore::for_process`] hands it, and walks with the house engine.
struct NotingEngine<'a> {
	/// The process under exploration.
	process: &'a Process,
	/// The configuration of the exploration.
	config: Arc<FdrConfig>,
	/// The initial state of each process that `for_process` received.
	handed: Arc<Mutex<Vec<State>>>,
	/// The result of each seed.
	results: Vec<(u64, SeedResult)>,
	/// The engine that walks each seed.
	walker: DefaultExplorationEngine<'a>,
}

impl<'a> NotingEngine<'a> {
	/// An engine of `process` under `config` that notes into `handed`.
	fn new(process: &'a Process, config: Arc<FdrConfig>, handed: Arc<Mutex<Vec<State>>>) -> Self {
		let walker = DefaultExplorationEngine::new(process, Arc::clone(&config));
		Self { process, config, handed, results: Vec::new(), walker }
	}
}

impl ExplorationCore for NotingEngine<'_> {
	type ForProcess<'p> = NotingEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> NotingEngine<'p> {
		let mut handed = self.handed.lock().expect("no test panics while it holds the lock");
		handed.push(process.initial());
		drop(handed);

		NotingEngine::new(process, Arc::clone(&self.config), Arc::clone(&self.handed))
	}

	fn process(&self) -> &Process {
		self.process
	}

	fn config(&self) -> &FdrConfig {
		&self.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		self.walker.explore_seed(seed)
	}

	fn traces(&self) -> Vec<Trace> {
		self.walker.traces()
	}

	fn visited_states(&self) -> &HashSet<State> {
		self.walker.visited_states()
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.results.push((seed, result));
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.results
	}
}

/// A process named `name` that takes `event` from `start` to the accepting
/// `end`.
fn once(name: &'static str, (start, end): (&'static str, &'static str), event: &'static str) -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder(name)
		.initial_state(State(start))
		.add_observable(Event(event))
		.add_transition(State(start), Event(event), State(end))
		.add_terminal(State(end))
		.build();

	built.expect("a process of one event builds")
}

#[test]
fn an_outside_engine_walks_the_scheduled_subject() -> Result<(), Box<dyn core::error::Error>> {
	let (a, b) = (once("A", ("A0", "A1"), "a"), once("B", ("B0", "B1"), "b"));
	let subject = CompositionOperator::Interleaved.compose(&a, &b)?;
	let counts = SchedulerCounts { schedulers: NonZeroU32::MIN, processes: NonZeroU32::try_from(2)? };
	let scheduler = SchedulerConstraint::new(SchedulerModel::Cooperative, counts)?;
	let config = Arc::new(FdrConfig { scheduler: Some(scheduler), ..FdrConfig::default() });
	let handed = Arc::new(Mutex::new(Vec::new()));
	let engine = NotingEngine::new(&subject, Arc::clone(&config), Arc::clone(&handed));
	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(&subject, Arc::clone(&config), cache);

	FdrExplorer::new_with_arc(&subject, config, engine, checker).explore()?;

	let handed = handed.lock().map(|handed| handed.clone()).unwrap_or_default();
	assert_eq!(handed, [State("(A0,B0)@{}")]);
	Ok(())
}

//! An outside crate brings its own [`ExplorationCore`], and an FDR run with a
//! scheduler constraint hands that engine the scheduled subject through
//! [`ExplorationCore::for_process`].

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig, SeedResult, Trace};
use tightbeam::testing::specs::composition::CompositionOperator;
use tightbeam::testing::specs::csp::{Process, State};

use crate::common::csp::{cooperative, explorer_of, once};
use crate::common::result::TestResult;

/// The seeds of the exploration.
const SEEDS: u32 = 4;

/// The initial states that a [`NotingEngine`] and each engine it builds note.
#[derive(Clone, Default)]
struct Notes {
	/// The initial state of each process that `for_process` received.
	handed: Arc<Mutex<Vec<State>>>,
	/// The initial state of the process that each seed walked.
	walked: Arc<Mutex<Vec<State>>>,
}

/// An exploration engine that notes the initial state of each process that
/// [`ExplorationCore::for_process`] hands it, and of the process that each
/// seed walks, and walks with the house engine.
struct NotingEngine<'a> {
	/// The process under exploration.
	process: &'a Process,
	/// The configuration of the exploration.
	config: Arc<FdrConfig>,
	/// The states that this engine notes.
	notes: Notes,
	/// The result of each seed.
	results: Vec<(u64, SeedResult)>,
	/// The engine that walks each seed.
	walker: DefaultExplorationEngine<'a>,
}

impl<'a> NotingEngine<'a> {
	/// An engine of `process` under `config` that notes into `notes`.
	fn new(process: &'a Process, config: Arc<FdrConfig>, notes: Notes) -> Self {
		let walker = DefaultExplorationEngine::new(process, Arc::clone(&config));
		Self { process, config, notes, results: Vec::new(), walker }
	}
}

impl ExplorationCore for NotingEngine<'_> {
	type ForProcess<'p> = NotingEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> NotingEngine<'p> {
		let mut handed = self.notes.handed.lock().expect("no test panics while it holds the lock");
		handed.push(process.initial());
		drop(handed);

		NotingEngine::new(process, Arc::clone(&self.config), self.notes.clone())
	}

	fn process(&self) -> &Process {
		self.process
	}

	fn config(&self) -> &FdrConfig {
		&self.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		let mut walked = self.notes.walked.lock().expect("no test panics while it holds the lock");
		walked.push(self.process.initial());
		drop(walked);

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

/// The states that an engine noted into `noted`, in the order it noted them.
fn noted_states(noted: &Mutex<Vec<State>>) -> Vec<State> {
	let noted = noted.lock().expect("no engine panics while it holds the lock");
	noted.to_vec()
}

/// An FDR run with a scheduler constraint hands an outside engine the
/// scheduled subject, the interleaving of two processes, through
/// [`ExplorationCore::for_process`], and each seed of the run walks that
/// engine.
#[test]
fn an_outside_engine_walks_the_scheduled_subject() -> TestResult {
	let (a, b) = (once("A", ("A0", "A1"), "a"), once("B", ("B0", "B1"), "b"));
	let subject = CompositionOperator::Interleaved.compose(&a, &b)?;
	let notes = Notes::default();
	let noting = |process, config| NotingEngine::new(process, config, notes.clone());
	let config = cooperative(FdrConfig { seeds: SEEDS, ..FdrConfig::default() });
	let mut explorer = explorer_of(&subject, config, noting);
	explorer.explore()?;

	assert_eq!(noted_states(&notes.handed), [State("(A0,B0)@{}")]);
	assert_eq!(noted_states(&notes.walked), [State("(A0,B0)@{}"); SEEDS as usize]);
	Ok(())
}

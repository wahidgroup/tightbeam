//! An exploration engine that an outside crate brings, built through the
//! public API of tightbeam alone.
//!
//! The engine walks each seed with [`DefaultExplorationEngine`] and keeps its
//! visited states in its own set, so the events of `explore_into` show that the
//! explorer reads them through [`ExplorationCore`]. A second engine reports
//! every state of its process as visited, so its events show that a divergence
//! event names a state where a seed diverged.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use tightbeam::instrumentation::events::{DIVERGENCE_DETECT, ENABLED_SET_SAMPLE};
use tightbeam::instrumentation::TbInstrumentationConfig;
use tightbeam::testing::fdr::{
	DefaultCache, DefaultExplorationEngine, DefaultRefinementChecker, ExplorationCore, FdrConfig, FdrExplorer,
	SeedResult, Trace,
};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::trace::{TraceCollector, TraceConfig};
use tightbeam::urn::Urn;

/// An exploration engine with a visited set of its own.
struct OutsideEngine<'a> {
	/// The process under exploration.
	process: &'a Process,
	/// The configuration of the exploration.
	config: Arc<FdrConfig>,
	/// The result of each seed, in the order the seeds ran.
	results: Vec<(u64, SeedResult)>,
	/// The states that the seeds visited.
	visited: HashSet<State>,
	/// The engine that walks each seed.
	walker: DefaultExplorationEngine<'a>,
}

impl<'a> OutsideEngine<'a> {
	/// An engine of `process` under `config`, before its first seed.
	fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		let walker = DefaultExplorationEngine::new(process, Arc::clone(&config));
		Self { process, config, results: Vec::new(), visited: HashSet::new(), walker }
	}
}

impl ExplorationCore for OutsideEngine<'_> {
	fn process(&self) -> &Process {
		self.process
	}

	fn config(&self) -> &FdrConfig {
		&self.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		let result = self.walker.explore_seed(seed);
		self.visited.extend(self.walker.visited_states());
		result
	}

	fn traces(&self) -> Vec<Trace> {
		Vec::new()
	}

	fn visited_states(&self) -> &HashSet<State> {
		&self.visited
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.results.push((seed, result));
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		&self.results
	}
}

/// The labels of the `urn` events that `trace` recorded, in order.
fn labels_of(trace: &TraceCollector, urn: Urn<'static>) -> Vec<String> {
	let events = trace.drain_events();
	let named = events.into_iter().filter(|event| event.urn == urn);
	named.filter_map(|event| event.label.map(String::from)).collect()
}

/// A process that offers `go` at `Ready` and stops at `Done`.
fn ready() -> Result<Process, ProcessBuildError> {
	Process::builder("Ready")
		.initial_state(State("Ready"))
		.add_observable(Event("go"))
		.add_transition(State("Ready"), Event("go"), State("Done"))
		.add_terminal(State("Done"))
		.build()
}

#[test]
fn an_outside_engine_hands_its_visited_states_to_the_recorded_events() -> Result<(), Box<dyn std::error::Error>> {
	let process = ready()?;
	let config = Arc::new(FdrConfig::default());
	let engine = OutsideEngine::new(&process, Arc::clone(&config));
	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(&process, Arc::clone(&config), cache);
	let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
	let mut explorer = FdrExplorer::new_with_arc(&process, config, engine, checker);

	explorer.explore_into(&trace)?;

	let labels = labels_of(&trace, ENABLED_SET_SAMPLE);
	assert_eq!(labels, ["Ready.Done: {}", "Ready.Ready: {go}"]);
	Ok(())
}

/// An exploration engine whose visited set names every state of its process,
/// more than its seeds visited.
struct OverReportingEngine<'a> {
	/// The engine that explores each seed.
	inner: OutsideEngine<'a>,
}

impl ExplorationCore for OverReportingEngine<'_> {
	fn process(&self) -> &Process {
		self.inner.process
	}

	fn config(&self) -> &FdrConfig {
		&self.inner.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		self.inner.explore_seed(seed)
	}

	fn traces(&self) -> Vec<Trace> {
		Vec::new()
	}

	fn visited_states(&self) -> &HashSet<State> {
		&self.inner.process.states
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.inner.add_seed_result(seed, result);
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		self.inner.seed_results()
	}
}

/// An exploration engine that counts the seeds it walks.
struct CountingEngine<'a> {
	/// The engine that explores each seed.
	inner: OutsideEngine<'a>,
	/// The count of the seeds that the engine walked.
	walked: Rc<Cell<u64>>,
}

impl ExplorationCore for CountingEngine<'_> {
	fn process(&self) -> &Process {
		self.inner.process
	}

	fn config(&self) -> &FdrConfig {
		&self.inner.config
	}

	fn explore_seed(&mut self, seed: u64) -> SeedResult {
		self.walked.set(self.walked.get() + 1);
		self.inner.explore_seed(seed)
	}

	fn traces(&self) -> Vec<Trace> {
		Vec::new()
	}

	fn visited_states(&self) -> &HashSet<State> {
		self.inner.visited_states()
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.inner.add_seed_result(seed, result);
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		self.inner.seed_results()
	}
}

#[test]
fn an_outside_engine_walks_every_seed() -> Result<(), ProcessBuildError> {
	let process = ready()?;
	let config = Arc::new(FdrConfig { seeds: 4, ..Default::default() });
	let walked = Rc::new(Cell::new(0));
	let engine = CountingEngine {
		inner: OutsideEngine::new(&process, Arc::clone(&config)),
		walked: Rc::clone(&walked),
	};

	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(&process, Arc::clone(&config), cache);
	let mut explorer = FdrExplorer::new_with_arc(&process, config, engine, checker);

	explorer.explore();

	assert_eq!(walked.get(), 4, "the explorer hands each of the four seeds to the engine");
	Ok(())
}

#[test]
fn the_verdict_reads_each_result_that_an_outside_engine_records() -> Result<(), ProcessBuildError> {
	let process = ready()?;
	let config = Arc::new(FdrConfig { seeds: 4, ..Default::default() });
	let engine = OutsideEngine::new(&process, Arc::clone(&config));
	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(&process, Arc::clone(&config), cache);
	let mut explorer = FdrExplorer::new_with_arc(&process, config, engine, checker);

	let verdict = explorer.explore();

	assert_eq!(
		verdict.seeds_completed, 4,
		"the provided `explore_seeds` records each of the four results"
	);
	Ok(())
}

/// A process whose hidden `t` and `u` take `S1` to `S2` and back, with the
/// observable exit `b` at `S2`, so each seed diverges at `S1`.
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

#[test]
fn a_divergence_event_names_a_state_where_a_seed_diverged() -> Result<(), Box<dyn std::error::Error>> {
	let process = spinning()?;
	let config = Arc::new(FdrConfig::default());
	let engine = OverReportingEngine { inner: OutsideEngine::new(&process, Arc::clone(&config)) };
	let cache = Rc::new(RefCell::new(DefaultCache::new()));
	let checker = DefaultRefinementChecker::new(&process, Arc::clone(&config), cache);
	let settings = TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
	let mut explorer = FdrExplorer::new_with_arc(&process, config, engine, checker);

	explorer.explore_into(&trace)?;

	let labels = labels_of(&trace, DIVERGENCE_DETECT);
	let at_s1 = ["Spinning.S1: <t, u>"];
	assert_eq!(labels, at_s1, "no seed diverged at `S2`, which the engine reports");
	Ok(())
}

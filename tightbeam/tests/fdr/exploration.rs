//! An exploration engine that an outside crate brings, built through the
//! public API of tightbeam alone.
//!
//! The engine walks each seed with [`DefaultExplorationEngine`] and keeps its
//! visited states in its own set, so the events of `explore_into` show that the
//! explorer reads them through [`ExplorationCore`]. A second engine reports
//! every state of its process as visited, so its events show that a divergence
//! event names a state where a seed diverged.

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use tightbeam::instrumentation::events::{DIVERGENCE_DETECT, ENABLED_SET_SAMPLE};
use tightbeam::instrumentation::TbInstrumentationConfig;
use tightbeam::tb_cases;
use tightbeam::testing::fdr::{DefaultExplorationEngine, ExplorationCore, FdrConfig, SeedResult, Trace};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::TightBeamError;

#[cfg(feature = "testing-fault")]
use tightbeam::testing::fdr::FaultModel;

use crate::common::csp::{explorer_of, once};
use crate::common::result::TestResult;
use crate::common::trace::{instrumented_trace, recorded_labels};
use crate::fdr::spinning;

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
	type ForProcess<'p> = OutsideEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> OutsideEngine<'p> {
		OutsideEngine::new(process, Arc::clone(&self.config))
	}

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

/// A process that offers `go` at `Ready` and stops at `Done`.
fn ready() -> Process {
	once("Ready", ("Ready", "Done"), "go")
}

/// The process of [`ready`] beside `Island`, a state that offers `go` and that
/// no path from `Ready` reaches, so no seed visits it.
fn ready_beside_an_island() -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder("Ready")
		.initial_state(State("Ready"))
		.add_observable(Event("go"))
		.add_transition(State("Ready"), Event("go"), State("Done"))
		.add_transition(State("Island"), Event("go"), State("Done"))
		.add_terminal(State("Done"))
		.build();

	built.expect("a process of one event builds")
}

/// The label of each enabled set that an exploration of `process` records
/// through the engine that `engine` builds, in the order of the state names.
fn sampled_through<'a, E: ExplorationCore>(
	process: &'a Process,
	engine: impl FnOnce(&'a Process, Arc<FdrConfig>) -> E,
) -> Result<Vec<Option<String>>, TightBeamError> {
	let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
	let trace = instrumented_trace(settings);
	let mut explorer = explorer_of(process, FdrConfig::default(), engine);
	explorer.explore_into(&trace)?;

	Ok(recorded_labels(&trace, ENABLED_SET_SAMPLE))
}

/// The explorer reads the visited set of an outside engine, so the enabled set
/// of each state that a seed visits reaches the recorded events, and the set
/// of `Island`, which no seed visits, stays out.
#[test]
fn an_outside_engine_hands_its_visited_states_to_the_recorded_events() -> TestResult {
	let process = ready_beside_an_island();

	let labels = sampled_through(&process, OutsideEngine::new)?;
	let sampled = [Some("Ready.Done: {}".to_owned()), Some("Ready.Ready: {go}".to_owned())];
	assert_eq!(labels, sampled);
	Ok(())
}

/// An engine that reports `Island` gets its enabled set recorded, so the set
/// that the engine reports decides which states the events cover.
#[test]
fn an_engine_that_reports_a_state_gets_its_enabled_set_recorded() -> TestResult {
	let process = ready_beside_an_island();

	let labels = sampled_through(&process, OverReportingEngine::new)?;
	let sampled = [
		Some("Ready.Done: {}".to_owned()),
		Some("Ready.Island: {go}".to_owned()),
		Some("Ready.Ready: {go}".to_owned()),
	];
	assert_eq!(labels, sampled);
	Ok(())
}

/// An exploration engine whose visited set names every state of its process,
/// more than its seeds visited.
struct OverReportingEngine<'a> {
	/// The engine that explores each seed.
	inner: OutsideEngine<'a>,
}

impl<'a> OverReportingEngine<'a> {
	/// An engine of `process` under `config`, before its first seed.
	fn new(process: &'a Process, config: Arc<FdrConfig>) -> Self {
		Self { inner: OutsideEngine::new(process, config) }
	}
}

impl ExplorationCore for OverReportingEngine<'_> {
	type ForProcess<'p> = OverReportingEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> OverReportingEngine<'p> {
		OverReportingEngine { inner: self.inner.for_process(process) }
	}

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
		self.inner.process.states()
	}

	fn add_seed_result(&mut self, seed: u64, result: SeedResult) {
		self.inner.add_seed_result(seed, result);
	}

	fn seed_results(&self) -> &[(u64, SeedResult)] {
		self.inner.seed_results()
	}
}

/// An exploration engine that counts the seeds it walks, and shares the count
/// with each engine that its `for_process` builds.
struct CountingEngine<'a> {
	/// The engine that explores each seed.
	inner: OutsideEngine<'a>,
	/// The count of the seeds that the engine walked.
	walked: Rc<Cell<u64>>,
}

impl<'a> CountingEngine<'a> {
	/// An engine of `process` under `config` that counts its seeds into
	/// `walked`.
	fn new(process: &'a Process, config: Arc<FdrConfig>, walked: Rc<Cell<u64>>) -> Self {
		Self { inner: OutsideEngine::new(process, config), walked }
	}
}

impl ExplorationCore for CountingEngine<'_> {
	type ForProcess<'p> = CountingEngine<'p>;

	fn for_process<'p>(&self, process: &'p Process) -> CountingEngine<'p> {
		CountingEngine { inner: self.inner.for_process(process), walked: Rc::clone(&self.walked) }
	}

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

// An outside engine walks each seed that the explorer hands it, the seeds of
// each spec included.
tb_cases! {
	fn an_outside_engine_walks_each_seed((config, walked): (FdrConfig, u64)) -> TestResult {
		let process = ready();
		let counter = Rc::new(Cell::new(0));
		let counting = |process, config| CountingEngine::new(process, config, Rc::clone(&counter));

		let mut explorer = explorer_of(&process, config, counting);
		explorer.explore()?;
		assert_eq!(counter.get(), walked);
		Ok(())
	}
	cases {
		/// The explorer hands each of four seeds to the engine.
		four_seeds => (FdrConfig { seeds: 4, ..Default::default() }, 4),
		/// Each of two specs runs its three seeds through the engine.
		#[cfg(feature = "testing-fault")]
		three_seeds_of_each_of_two_specs => (
			FdrConfig {
				seeds: 3,
				specs: vec![ready(), ready()],
				fault_model: Some(FaultModel::default()),
				..Default::default()
			},
			6,
		),
	}
}

/// The provided `explore_seeds` records the result of each seed that an
/// outside engine walks, and the verdict counts each of them.
#[test]
fn the_verdict_reads_each_result_that_an_outside_engine_records() -> TestResult {
	let process = ready();
	let config = FdrConfig { seeds: 4, ..Default::default() };
	let mut explorer = explorer_of(&process, config, OutsideEngine::new);

	let verdict = explorer.explore()?;
	assert_eq!(verdict.seeds_completed, 4);
	Ok(())
}

/// An engine that reports `S2` as visited leaves the divergence event at `S1`,
/// the one state where each seed diverged.
#[test]
fn a_divergence_event_names_a_state_where_a_seed_diverged() -> TestResult {
	let process = spinning();
	let settings = TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() };
	let trace = instrumented_trace(settings);
	let mut explorer = explorer_of(&process, FdrConfig::default(), OverReportingEngine::new);
	explorer.explore_into(&trace)?;

	let labels = recorded_labels(&trace, DIVERGENCE_DETECT);
	let at_s1 = [Some("Spinning.S1: <t, u>".to_owned())];
	assert_eq!(labels, at_s1);
	Ok(())
}

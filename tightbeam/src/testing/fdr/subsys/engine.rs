//! The engine subsystem of FDR.
//!
//! This module holds [`FdrExplorer`], which runs exploration and refinement
//! checks through subsystems that a caller can replace.

use core::convert::Infallible;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use super::cache::DefaultCache;
use super::exploration::DefaultExplorationEngine;
use super::refinement::DefaultRefinementChecker;
use crate::testing::fdr::config::FdrConfig;
use crate::testing::fdr::explorer::{ExplorationCore, RefinementChecker, RefinementOutcome, SeedResult};
use crate::testing::fdr::verdict::{Decision, FdrVerdict};
use crate::testing::specs::csp::{Event, Process, State};

use crate::trace::TraceCollector;
use crate::TightBeamError;

#[cfg(feature = "instrument")]
use super::recorder::ExplorationRecorder;

/// The FDR explorer, generic over its two subsystems.
///
/// The type parameters name the subsystems:
/// - `E` is the exploration engine, an [`ExplorationCore`].
/// - `R` is the refinement checker, a [`RefinementChecker`].
///
/// The refinement checker owns its memoization cache.
pub struct FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// The process under verification.
	process: &'a Process,

	/// The FDR configuration, which the subsystems share.
	config: Arc<FdrConfig>,

	/// The exploration engine, which runs each seed.
	explorer: E,

	/// The refinement checker, which tests the process against each spec.
	refinement: R,

	/// The verdict that the run accumulates.
	verdict: FdrVerdict,
}

/// The FDR explorer with the default exploration engine and refinement checker.
pub type DefaultFdrExplorer<'a> =
	FdrExplorer<'a, DefaultExplorationEngine<'a>, DefaultRefinementChecker<'a, DefaultCache>>;

/// A divergence that a seed found: the state where the seed diverged, and the
/// hidden events of the run that diverges from it.
pub(crate) type Divergence = (State, Vec<Event>);

/// The type of the `None` recording that [`FdrExplorer::explore`] passes,
/// whose error is [`Infallible`].
type Unrecorded = fn(&Process, &HashSet<State>, &[Divergence]) -> Result<(), Infallible>;

/// The divergences that the seeds of one explored process found, which an
/// exploration keeps when it records them.
struct FoundDivergences(Option<Vec<Divergence>>);

impl FoundDivergences {
	/// A collection that keeps each divergence when `recording` holds.
	fn kept_when(recording: bool) -> Self {
		Self(recording.then(Vec::new))
	}

	/// Keeps the divergence of `result` when the result has one and this
	/// collection keeps divergences.
	fn note(&mut self, result: &SeedResult) {
		let found = result.divergence();
		if let (Some(kept), Some((state, run))) = (self.0.as_mut(), found) {
			kept.push((state, run.to_vec()));
		}
	}

	/// The divergences kept so far, in the order of the seeds.
	fn divergences(&self) -> &[Divergence] {
		self.0.as_deref().unwrap_or_default()
	}
}

impl<'a, E, R> FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// An explorer of `process` under `config` with the given subsystems.
	///
	/// The refinement checker owns the cache, which it receives at its
	/// construction.
	pub fn new(process: &'a Process, config: FdrConfig, explorer: E, refinement: R) -> Self {
		Self {
			process,
			config: Arc::new(config),
			explorer,
			refinement,
			verdict: FdrVerdict::default(),
		}
	}

	/// An explorer of `process` under a shared `config` with the given
	/// subsystems.
	///
	/// Use it when the subsystems already share `config` through an [`Arc`].
	pub fn new_with_arc(process: &'a Process, config: Arc<FdrConfig>, explorer: E, refinement: R) -> Self {
		Self { process, config, explorer, refinement, verdict: FdrVerdict::default() }
	}

	/// Runs Layer 3 and reports what it decided.
	pub fn explore(&mut self) -> FdrVerdict {
		let explored = self.explore_recording(None::<Unrecorded>);
		let Ok(verdict) = explored;

		verdict
	}

	/// Runs Layer 3, records into `trace` the exploration events that its
	/// instrumentation settings ask for, and reports what Layer 3 decided.
	///
	/// Each event covers one state of one explored process, in the order of
	/// the state names, and its label names the process and the state:
	///
	/// - `sample_enabled_sets` records [`ENABLED_SET_SAMPLE`] at each state that a seed visited.
	/// - `sample_refusals` records [`REFUSAL_SNAPSHOT`] at each visited state that is stable or accepting.
	/// - `divergence_heuristics` records [`DIVERGENCE_DETECT`] at each state where a seed diverged.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that `trace` refused.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events::ENABLED_SET_SAMPLE;
	/// use tightbeam::instrumentation::TbInstrumentationConfig;
	/// use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::trace::{TraceCollector, TraceConfig};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
	/// let trace = TraceCollector::from(TraceConfig::with_instrumentation(settings));
	/// let mut explorer = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default());
	/// explorer.explore_into(&trace)?;
	///
	/// let events = trace.drain_events();
	/// let samples = events.iter().filter(|event| event.urn == ENABLED_SET_SAMPLE);
	/// let labels: Vec<_> = samples.filter_map(|event| event.label.as_deref()).collect();
	/// assert_eq!(labels, ["Send.S0: {send}", "Send.S1: {}"]);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	///
	/// [`ENABLED_SET_SAMPLE`]: crate::instrumentation::events::ENABLED_SET_SAMPLE
	/// [`REFUSAL_SNAPSHOT`]: crate::instrumentation::events::REFUSAL_SNAPSHOT
	/// [`DIVERGENCE_DETECT`]: crate::instrumentation::events::DIVERGENCE_DETECT
	#[cfg(feature = "instrument")]
	pub fn explore_into(&mut self, trace: &TraceCollector) -> Result<FdrVerdict, TightBeamError> {
		let Some(recorder) = ExplorationRecorder::of(trace) else {
			let verdict = self.explore();
			return Ok(verdict);
		};

		let record = |process: &Process, visited: &HashSet<State>, divergences: &[Divergence]| {
			recorder.record(process, visited, divergences)
		};
		self.explore_recording(Some(record))
	}

	/// Runs Layer 3 and reports what it decided. A build without `instrument`
	/// ignores `trace` and runs [`FdrExplorer::explore`].
	///
	/// # Errors
	///
	/// - In a build with `instrument`, the error of the first exploration event that `trace` refused.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	/// use tightbeam::trace::TraceCollector;
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let mut explorer = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default());
	/// let verdict = explorer.explore_into(&TraceCollector::default())?;
	/// assert_eq!(verdict.states_visited, 2);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[cfg(not(feature = "instrument"))]
	#[expect(unused_variables)]
	pub fn explore_into(&mut self, trace: &TraceCollector) -> Result<FdrVerdict, TightBeamError> {
		let verdict = self.explore();
		Ok(verdict)
	}

	/// Runs Layer 3, hands `record` what the seeds of each explored process
	/// found, and reports what Layer 3 decided.
	///
	/// This one exit path decides schedulability, so a spec that misses its
	/// deadlines cannot reach a consumer as a verdict that held.
	fn explore_recording<X, F>(&mut self, mut record: Option<F>) -> Result<FdrVerdict, X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
	{
		let mut verdict = self.explore_modes(&mut record)?;
		verdict.schedulable = self.schedulability();

		Ok(verdict)
	}

	/// What schedulability analysis decided about the configured specs.
	///
	/// A spec with no schedulability block has no task set, so it decides
	/// [`Decision::Holds`]. An analysis error decides [`Decision::Refuted`] and
	/// not [`Decision::Unknown`], because every `SchedulabilityError` names a
	/// defect in the declared task set, such as a period with no WCET.
	#[cfg(feature = "testing-schedulability")]
	fn schedulability(&self) -> Decision {
		let mut decision = Decision::NotAsserted;
		for spec in self.config.specs.iter() {
			let analysed = match spec.schedulability_violated() {
				Ok(false) => Decision::Holds,
				Ok(true) | Err(_) => Decision::Refuted,
			};

			decision = decision.and(analysed);
		}

		decision
	}

	/// A build without `testing-schedulability` leaves schedulability
	/// [`Decision::NotAsserted`].
	#[cfg(not(feature = "testing-schedulability"))]
	fn schedulability(&self) -> Decision {
		Decision::NotAsserted
	}

	/// Whether this run asserts deadlock freedom and divergence freedom.
	///
	/// Fault injection measures what the faults cause, so the deadlock it
	/// reaches is an observation for the error-recovery counters and the FMEA
	/// report, not a claim.
	#[cfg(feature = "testing-fault")]
	fn asserts_freedom(&self) -> bool {
		self.config.fault_model.is_none()
	}

	/// A build without `testing-fault` has no fault model, so every run asserts
	/// freedom.
	#[cfg(not(feature = "testing-fault"))]
	fn asserts_freedom(&self) -> bool {
		true
	}

	/// Runs the exploration mode that the configuration selects, and hands
	/// `record` the states that the seeds of each explored process visited and
	/// the divergences they found.
	fn explore_modes<X, F>(&mut self, record: &mut Option<F>) -> Result<FdrVerdict, X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
	{
		// Mode 1: a fault model with specs explores each spec under faults.
		#[cfg(feature = "testing-fault")]
		if self.config.fault_model.is_some() && !self.config.specs.is_empty() {
			// The run tests whether each spec models the error conditions that
			// the faults cause.
			self.explore_specification_with_faults(record)?;
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return Ok(self.verdict.clone());
		}

		// Mode 2: specs with no fault model run the refinement checks.
		if !self.config.specs.is_empty() {
			self.check_refinement();
			#[cfg(feature = "testing-fmea")]
			self.generate_fmea_if_configured();
			return Ok(self.verdict.clone());
		}

		// Mode 3: a run with no spec explores the process over every seed.
		if self.asserts_freedom() {
			self.verdict.divergence_free = Decision::Holds;
			self.verdict.deadlock_free = Decision::Holds;
		}

		let mut found = FoundDivergences::kept_when(record.is_some());

		#[cfg(feature = "rayon")]
		{
			use rayon::prelude::*;
			let seeds: Vec<u64> = (0..self.config.seeds).map(|s| s as u64).collect();
			let process = self.process;
			let config = &self.config;
			let divergent = process.divergent_states();

			let results: Vec<(u64, SeedResult, HashSet<State>, usize)> = seeds
				.par_iter()
				.map(|&seed| {
					let (result, visited, pruned) =
						DefaultExplorationEngine::explore_seed_static(process, config, &divergent, seed);
					(seed, result, visited, pruned)
				})
				.collect();

			for (seed, result, visited, pruned) in results {
				self.update_verdict_from_result(seed, &result);
				found.note(&result);
				self.explorer.add_seed_result(seed, result);
				self.explorer.update_visited_states(&visited);
				self.explorer.add_timing_pruned(pruned);
			}
		}

		#[cfg(not(feature = "rayon"))]
		{
			for seed in 0..self.config.seeds {
				let result = self.explorer.explore_seed(seed as u64);
				self.update_verdict_from_result(seed as u64, &result);
				found.note(&result);
				self.explorer.add_seed_result(seed as u64, result);
			}
		}

		self.verdict.traces_explored = self.explorer.traces().len();
		self.verdict.states_visited = self.explorer.visited_states().len();
		self.verdict.timing_pruned = self.explorer.timing_pruned();

		if let Some(record) = record.as_mut() {
			record(self.process, self.explorer.visited_states(), found.divergences())?;
		}

		self.check_determinism();

		#[cfg(feature = "testing-fmea")]
		self.generate_fmea_if_configured();

		Ok(self.verdict.clone())
	}

	/// Adds the result of `seed` to the verdict.
	///
	/// A seed that injected a fault feeds the error-recovery counters, which
	/// FMEA detection ratings divide.
	fn update_verdict_from_result(&mut self, seed: u64, result: &SeedResult) {
		match result {
			#[cfg(feature = "testing-fault")]
			SeedResult::Divergence(_trace, _state, hidden, faults) => {
				self.verdict.divergence_free = self.verdict.divergence_free.refute();
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Divergence(_trace, _state, hidden) => {
				self.verdict.divergence_free = self.verdict.divergence_free.refute();
				self.verdict.divergence_witness = Some((seed, hidden.clone()));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Deadlock(trace, state, faults) => {
				self.verdict.deadlock_free = self.verdict.deadlock_free.refute();
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.verdict.error_recovery_failed += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Deadlock(trace, state) => {
				self.verdict.deadlock_free = self.verdict.deadlock_free.refute();
				self.verdict.deadlock_witness = Some((seed, trace.clone(), *state));
				self.verdict.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Success(_trace, _failures, faults) => {
				self.verdict.seeds_completed += 1;
				if !faults.is_empty() {
					self.verdict.error_recovery_successful += 1;
				}
				self.verdict.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Success(..) => {
				self.verdict.seeds_completed += 1;
			}
		}
	}

	/// Explores every configured spec under fault injection, over every seed,
	/// and hands `record` the states that each spec's seeds visited and the
	/// divergences they found.
	///
	/// - The verdict describes the spec runs that this mode judges, and the subject's engine stays empty.
	/// - `states_visited` counts the distinct states of each spec.
	/// - The loop covers every spec, because a fault run of `specs[0]` alone would leave the rest untested.
	#[cfg(feature = "testing-fault")]
	fn explore_specification_with_faults<X, F>(&mut self, record: &mut Option<F>) -> Result<(), X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
	{
		if self.config.specs.is_empty() {
			return Ok(());
		}

		let config = Arc::clone(&self.config);
		for spec_process in &config.specs {
			let divergent = spec_process.divergent_states();
			let mut visited = HashSet::new();
			let mut found = FoundDivergences::kept_when(record.is_some());

			#[cfg(feature = "rayon")]
			{
				use rayon::prelude::*;
				let seeds: Vec<u64> = (0..config.seeds).map(|s| s as u64).collect();

				let results: Vec<(u64, SeedResult, HashSet<State>, usize)> = seeds
					.par_iter()
					.map(|&seed| {
						let (result, visited, pruned) =
							DefaultExplorationEngine::explore_seed_static(spec_process, &config, &divergent, seed);
						(seed, result, visited, pruned)
					})
					.collect();

				for (seed, result, seed_visited, pruned) in results {
					visited.extend(seed_visited);
					self.add_spec_seed(seed, &result, pruned);
					found.note(&result);
				}
			}

			#[cfg(not(feature = "rayon"))]
			{
				for seed in 0..config.seeds {
					let seed = seed as u64;
					let mut pruned = 0usize;
					let track = |state| {
						visited.insert(state);
					};
					let result = DefaultExplorationEngine::explore_seed_core(
						spec_process,
						&config,
						&divergent,
						seed,
						track,
						&mut pruned,
					);
					self.add_spec_seed(seed, &result, pruned);
					found.note(&result);
				}
			}

			self.verdict.states_visited += visited.len();
			if let Some(record) = record.as_mut() {
				record(spec_process, &visited, found.divergences())?;
			}
		}

		self.check_determinism();

		Ok(())
	}

	/// Adds the result of `seed` of a spec run under faults to the verdict,
	/// with the count of the branches that the seed pruned for timing.
	#[cfg(feature = "testing-fault")]
	fn add_spec_seed(&mut self, seed: u64, result: &SeedResult, pruned: usize) {
		self.update_verdict_from_result(seed, result);
		self.verdict.traces_explored += usize::from(result.succeeded());
		self.verdict.timing_pruned += pruned;
	}

	/// Builds the FMEA report when the FMEA configuration sets `auto_generate`
	/// and the run injected a fault.
	#[cfg(feature = "testing-fmea")]
	fn generate_fmea_if_configured(&mut self) {
		if let Some(ref fmea_config) = self.config.fmea_config {
			if fmea_config.auto_generate && !self.verdict.faults_injected.is_empty() {
				match self.verdict.fmea_report(self.process, Some(fmea_config.clone())) {
					Ok(report) => self.verdict.fmea_report = Some(report),
					Err(e) => eprintln!("Warning: FMEA generation failed: {}", e),
				}
			}
		}
	}

	/// Records whether the process is structurally deterministic.
	///
	/// A process with no hidden action and no multi-target `(state, event)`
	/// transition is deterministic in CSP (Roscoe 2010, §10.5). External choice
	/// is deterministic, so the check passes it.
	fn check_determinism(&mut self) {
		let mut states: Vec<State> = self.process.states.iter().copied().collect();
		states.sort_unstable_by_key(|state| state.0);

		let mut witness = None;
		'states: for state in states {
			for action in self.process.enabled(state) {
				if action.is_hidden() || self.process.step(state, &action.event).len() > 1 {
					witness = Some((state, action.event));
					break 'states;
				}
			}
		}

		self.verdict.is_deterministic = witness.is_none();
		self.verdict.determinism_witness = witness;
	}

	/// Checks `spec ⊑ process` in the models that the subject admits.
	///
	/// The check always asks traces refinement. It asks failures and
	/// divergences only of a subject whose observation carries refusals, or the
	/// checker would grade the subject on refusals it synthesized. Under
	/// `fail_fast`, each pass stops at its first violation.
	fn check_refinement(&mut self) {
		if self.config.specs.is_empty() {
			return;
		}

		// The check reads the spec list through an `Arc` clone and not a copy,
		// because a clone of `Vec<Process>` duplicates every state set and
		// transition map that the checker only reads.
		let config = Arc::clone(&self.config);
		let specs = config.specs.as_slice();
		self.verdict.unmodelled_events = self.unmodelled_events();

		self.verdict.trace_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_trace_refinement(s, self.process),
			|v, w| {
				v.trace_refinement_witness = Some(w);
			},
		);

		if !self.process.observation.carries_refusals() {
			return;
		}

		self.verdict.failures_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_failures_refinement(s, self.process),
			|v, w| {
				v.failures_refinement_witness = Some(w);
			},
		);

		self.verdict.divergence_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_divergence_refinement(s, self.process),
			|v, w| {
				v.divergence_refinement_witness = Some(w);
			},
		);
	}

	/// The events the subject can perform that no configured spec models,
	/// sorted by name.
	///
	/// An event that one spec models counts as modelled, so the result is the
	/// intersection of the unmodelled events of each spec.
	fn unmodelled_events(&self) -> Vec<Event> {
		let Some((first, rest)) = self.config.specs.split_first() else {
			return Vec::new();
		};

		let mut shared = first.unmodelled(self.process);
		for spec in rest {
			let modelled_by_spec = spec.unmodelled(self.process);
			shared.retain(|event| modelled_by_spec.contains(event));
		}

		shared
	}

	/// What one refinement model decided across every spec.
	///
	/// A check that ran out of budget decides [`Decision::Unknown`], because it
	/// holds neither a counterexample nor a finished search. A truncated
	/// enumeration decides the same way, because refinement quantifies over
	/// every trace of the subject.
	fn check_refinement_for_specs<W, F, G>(
		&mut self,
		specs: impl AsRef<[Process]>,
		check: F,
		record_witness: G,
	) -> Decision
	where
		F: Fn(&mut R, &Process) -> RefinementOutcome<W>,
		G: Fn(&mut FdrVerdict, W),
	{
		let specs = specs.as_ref();
		let mut decision = Decision::NotAsserted;
		for spec in specs {
			match check(&mut self.refinement, spec) {
				RefinementOutcome::Holds { complete } => {
					let held = match complete {
						true => Decision::Holds,
						false => Decision::Unknown,
					};

					decision = decision.and(held);
				}
				RefinementOutcome::Violated(witness) => {
					record_witness(&mut self.verdict, witness);
					decision = decision.and(Decision::Refuted);
					if self.config.fail_fast {
						return decision;
					}
				}
				RefinementOutcome::Inconclusive => decision = decision.and(Decision::Unknown),
			}
		}

		decision
	}
}

impl<'a> DefaultFdrExplorer<'a> {
	/// An explorer of `process` under `config` with the default subsystems.
	///
	/// The default subsystems are [`DefaultExplorationEngine`] and
	/// [`DefaultRefinementChecker`] over a [`DefaultCache`].
	/// [`FdrExplorer::new`] takes other subsystems.
	///
	/// `config` is an owned [`FdrConfig`] or an `Arc<FdrConfig>`.
	pub fn with_defaults(process: &'a Process, config: impl Into<Arc<FdrConfig>>) -> Self {
		let config = config.into();
		let explorer_config = Arc::clone(&config);
		let explorer = DefaultExplorationEngine::new(process, explorer_config);
		let cache = Rc::new(RefCell::new(DefaultCache::new()));
		let refinement_config = Arc::clone(&config);
		let refinement = DefaultRefinementChecker::new(process, refinement_config, cache);

		FdrExplorer::new_with_arc(process, config, explorer, refinement)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "testing-timing")]
	use core::time::Duration;

	use super::Decision;
	use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	use crate::testing::specs::csp::{Event, Process, ProcessBuildError, State};

	#[cfg(feature = "testing-fault")]
	use crate::testing::fdr::FaultModel;
	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::TimingGuard;

	/// A spec that models `start` and nothing else.
	fn narrow_spec() -> Result<Process, ProcessBuildError> {
		Process::builder("NarrowSpec")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_transition(State("S0"), Event("start"), State("S1"))
			.add_terminal(State("S1"))
			.build()
	}

	/// A subject in which `arm` takes `S0` to `S1` when `clk` reads at most
	/// 5 ms, and `S1` is not terminal and offers no event.
	#[cfg(feature = "testing-timing")]
	fn guarded_deadlock() -> Result<Process, ProcessBuildError> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));

		Process::builder("GuardedDeadlock")
			.initial_state(State("S0"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), Some(guard), Vec::new())
			.build()
	}

	/// A subject in which `start` takes `S0` to `S1` and resets `clk`, and
	/// `arm` takes `S1` to the terminal `S2` when `clk` reads at most 5 ms.
	#[cfg(feature = "testing-timing")]
	fn reset_then_guard() -> Result<Process, ProcessBuildError> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));

		Process::builder("ResetThenGuard")
			.initial_state(State("S0"))
			.add_observable(Event("start"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("start"), State("S1"), None, ["clk".to_string()])
			.add_timed_transition(State("S1"), Event("arm"), State("S2"), Some(guard), Vec::new())
			.add_terminal(State("S2"))
			.build()
	}

	/// A subject whose hidden `t` and `u` take `S1` to `S2` and back, with
	/// the exit `b` at `S2`, so a seed that takes `b` never runs past
	/// `max_internal_run` hidden events.
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

	/// A subject that performs `start`, then an event no spec mentions.
	fn wider_subject() -> Result<Process, ProcessBuildError> {
		Process::builder("WiderSubject")
			.initial_state(State("T0"))
			.add_observable(Event("start"))
			.add_observable(Event("audit"))
			.add_transition(State("T0"), Event("start"), State("T1"))
			.add_transition(State("T1"), Event("audit"), State("T2"))
			.add_terminal(State("T2"))
			.build()
	}

	/// A subject whose hidden `p` takes `S0` onto the hidden cycle of `t` and
	/// `u` between `S1` and `S2`, so `S0` lies off the cycle and reaches it.
	fn lasso() -> Result<Process, ProcessBuildError> {
		Process::builder("Lasso")
			.initial_state(State("S0"))
			.add_observable(Event("b"))
			.add_hidden(Event("p"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("p"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("u"), State("S1"))
			.add_transition(State("S2"), Event("b"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	/// A subject in which `a` takes `I` to `X`, whose two hidden runs meet at
	/// `Q`, which loops on the hidden `first`.
	///
	/// The run through `P` takes `first` twice, and the run that `second`
	/// names takes one hidden event, so the order of the event names decides
	/// which run a search takes first.
	fn meeting(first: &'static str, second: &'static str) -> Result<Process, ProcessBuildError> {
		Process::builder("Meeting")
			.initial_state(State("I"))
			.add_observable(Event("a"))
			.add_hidden(Event(first))
			.add_hidden(Event(second))
			.add_transition(State("I"), Event("a"), State("X"))
			.add_transition(State("X"), Event(first), State("P"))
			.add_transition(State("P"), Event(first), State("Q"))
			.add_transition(State("X"), Event(second), State("Q"))
			.add_transition(State("Q"), Event(first), State("Q"))
			.build()
	}

	/// A subject whose hidden `t` and `u` take `S0` through `S1` to `S2`, a run
	/// of two hidden events with no cycle, before `c` ends it at `S3`.
	fn hidden_chain() -> Result<Process, ProcessBuildError> {
		Process::builder("HiddenChain")
			.initial_state(State("S0"))
			.add_observable(Event("c"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("t"), State("S1"))
			.add_transition(State("S1"), Event("u"), State("S2"))
			.add_transition(State("S2"), Event("c"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	/// A subject whose hidden `p` comes before the observable `a`, and whose
	/// hidden run `t`, `u` comes after it.
	fn chain_after_a_run() -> Result<Process, ProcessBuildError> {
		Process::builder("ChainAfterARun")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("c"))
			.add_hidden(Event("p"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("p"), State("S1"))
			.add_transition(State("S1"), Event("a"), State("S2"))
			.add_transition(State("S2"), Event("t"), State("S3"))
			.add_transition(State("S3"), Event("u"), State("S4"))
			.add_transition(State("S4"), Event("c"), State("S5"))
			.add_terminal(State("S5"))
			.build()
	}

	/// What an exploration of `subject` under `config` decided about
	/// divergence freedom.
	fn divergence_of(subject: &Process, config: FdrConfig) -> Decision {
		let mut explorer = DefaultFdrExplorer::with_defaults(subject, config);
		let verdict = explorer.explore();
		verdict.divergence_free
	}

	#[test]
	fn refinement_reports_what_the_projection_discarded() -> Result<(), ProcessBuildError> {
		let subject = wider_subject()?;
		let config = FdrConfig { specs: vec![narrow_spec()?], ..Default::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore();
		assert_eq!(verdict.unmodelled_events, vec![Event("audit")]);
		assert_eq!(
			verdict.trace_refines,
			Decision::Holds,
			"`audit` is projected away, so it is coverage and not a counterexample"
		);

		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guarded_process_over_a_deadlock_is_not_deadlock_free() -> Result<(), ProcessBuildError> {
		let subject = guarded_deadlock()?;
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::default());

		let verdict = explorer.explore();
		assert_eq!(verdict.deadlock_free, Decision::Refuted);

		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_reset_clock_lets_exploration_take_the_guard_behind_it() -> Result<(), ProcessBuildError> {
		let subject = reset_then_guard()?;
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::default());

		let verdict = explorer.explore();
		assert_eq!(verdict.deadlock_free, Decision::Holds);

		Ok(())
	}

	#[test]
	fn a_reachable_hidden_cycle_refutes_divergence_freedom() -> Result<(), ProcessBuildError> {
		let subject = spinning()?;
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::default());

		let verdict = explorer.explore();

		let run = verdict.divergence_witness.map(|(_seed, run)| run);
		assert_eq!(verdict.divergence_free, Decision::Refuted);
		assert_eq!(run, Some(vec![Event("t"), Event("u")]), "the witness is the run of the cycle");
		Ok(())
	}

	#[test]
	fn a_renamed_process_keeps_its_divergence_verdict() -> Result<(), ProcessBuildError> {
		let config = FdrConfig { seeds: 8, max_depth: 1, max_internal_run: 2, ..Default::default() };

		let named_t = divergence_of(&meeting("t", "u")?, config.clone());
		let named_z = divergence_of(&meeting("z", "u")?, config);

		let refuted = [Decision::Refuted, Decision::Refuted];
		assert_eq!([named_t, named_z], refuted, "`X` reaches the loop at `Q`");
		Ok(())
	}

	#[test]
	fn a_state_off_a_hidden_cycle_diverges_along_the_run_that_reaches_it() -> Result<(), ProcessBuildError> {
		let subject = lasso()?;
		let config = FdrConfig { max_internal_run: 1, ..Default::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore();

		let run = verdict.divergence_witness.map(|(_seed, run)| run);
		let to_the_cycle_and_around = vec![Event("p"), Event("t"), Event("u")];
		assert_eq!(run, Some(to_the_cycle_and_around), "`S0` reaches the cycle of `t` and `u`");
		Ok(())
	}

	#[test]
	fn a_hidden_cycle_at_the_depth_cut_off_refutes_divergence_freedom() -> Result<(), ProcessBuildError> {
		let subject = spinning()?;
		let config = FdrConfig { max_depth: 1, ..Default::default() };

		let decided = divergence_of(&subject, config);

		assert_eq!(decided, Decision::Refuted, "`a` reaches `S1` at the depth cut-off");
		Ok(())
	}

	#[test]
	fn a_hidden_run_past_max_internal_run_refutes_divergence_freedom() -> Result<(), ProcessBuildError> {
		let subject = hidden_chain()?;

		let at_the_bound = divergence_of(&subject, FdrConfig { max_internal_run: 2, ..Default::default() });
		let past_the_bound = divergence_of(&subject, FdrConfig { max_internal_run: 1, ..Default::default() });

		assert_eq!([at_the_bound, past_the_bound], [Decision::Holds, Decision::Refuted]);
		Ok(())
	}

	#[test]
	fn a_hidden_run_past_max_internal_run_reports_that_run_alone() -> Result<(), ProcessBuildError> {
		let subject = chain_after_a_run()?;
		let config = FdrConfig { max_internal_run: 1, ..Default::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore();

		let run = verdict.divergence_witness.map(|(_seed, run)| run);
		assert_eq!(run, Some(vec![Event("t"), Event("u")]), "`a` ends the run of `p`");
		Ok(())
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_run_describes_the_spec_runs_it_judged() -> Result<(), ProcessBuildError> {
		let subject = wider_subject()?;
		let specs = vec![narrow_spec()?];
		let fault_model = Some(FaultModel::default());
		let config = FdrConfig { specs, fault_model, seeds: 4, ..Default::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore();

		let statistics = (verdict.states_visited, verdict.traces_explored, verdict.seeds_completed);
		assert_eq!(statistics, (2, 4, 4), "the spec visits `S0` and `S1` on each of four seeds");
		Ok(())
	}
}

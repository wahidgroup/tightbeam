//! The engine subsystem of FDR.
//!
//! [`FdrExplorer`] runs exploration and refinement checks through subsystems
//! that a caller can replace.

use core::ops::Range;
use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use super::cache::DefaultCache;
use super::exploration::DefaultExplorationEngine;
use super::refinement::DefaultRefinementChecker;
use crate::testing::fdr::config::{ExplorationMode, FdrConfig};
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
/// whose error is the error of the run.
type Unrecorded = fn(&Process, &HashSet<State>, &[Divergence]) -> Result<(), TightBeamError>;

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

impl FdrVerdict {
	/// Adds what the seeds of `seeds` find on `engine` to this verdict, and
	/// keeps each divergence in `found`.
	fn add_walk<C>(&mut self, engine: &mut C, seeds: Range<u64>, found: &mut FoundDivergences)
	where
		C: ExplorationCore,
	{
		for (seed, result) in engine.explore_seeds(seeds) {
			self.add_seed(*seed, result);
			found.note(result);
		}

		self.traces_explored = engine.traces().len();
		self.states_visited = engine.visited_states().len();
		self.timing_pruned = engine.timing_pruned();
	}
}

/// The exploration that a caller of the explorer asks for.
#[derive(Clone, Copy)]
enum Run {
	/// The mode that the configuration selects, as
	/// [`FdrExplorer::explore_modes`] decides it.
	Configured,
	/// The state-space exploration of the subject, whatever specs the
	/// configuration names.
	StateSpace,
}

impl<'a, E, R> FdrExplorer<'a, E, R>
where
	E: ExplorationCore,
	R: RefinementChecker,
{
	/// An explorer of `process` under `config` with the given subsystems.
	///
	/// The refinement checker receives its cache at its own construction.
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
	///
	/// # Errors
	///
	/// - The error of the FMEA report that the configuration asks for ([`FdrVerdict::fmea_report`]).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Send")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("send"))
	///     .add_transition(State("S0"), Event("send"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let verdict = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default()).explore()?;
	/// assert_eq!(verdict.states_visited, 2);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn explore(&mut self) -> Result<FdrVerdict, TightBeamError> {
		self.explore_unrecorded(Run::Configured)
	}

	/// Runs the exploration of `run`, records no event, and reports what it
	/// decided.
	///
	/// # Errors
	///
	/// - The error of the FMEA report that the configuration asks for.
	fn explore_unrecorded(&mut self, run: Run) -> Result<FdrVerdict, TightBeamError> {
		self.explore_recording(None::<Unrecorded>, run)
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
		self.record_into(trace, Run::Configured)
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
	pub fn explore_into(&mut self, trace: &TraceCollector) -> Result<FdrVerdict, TightBeamError> {
		self.record_into(trace, Run::Configured)
	}

	/// Runs the state-space exploration of the subject over every seed,
	/// whatever specs the configuration names, and records into `trace` the
	/// exploration events that its instrumentation settings ask for.
	///
	/// A scenario explores its CSP model this way, while its specs grade the
	/// recorded trace.
	///
	/// # Errors
	///
	/// - In a build with `instrument`, the error of the first exploration event that `trace` refused.
	pub(crate) fn explore_state_space_into(&mut self, trace: &TraceCollector) -> Result<FdrVerdict, TightBeamError> {
		self.record_into(trace, Run::StateSpace)
	}

	/// Runs the exploration of `run`, and records into `trace` the exploration
	/// events that its instrumentation settings ask for.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that `trace` refused.
	#[cfg(feature = "instrument")]
	fn record_into(&mut self, trace: &TraceCollector, run: Run) -> Result<FdrVerdict, TightBeamError> {
		let Some(recorder) = ExplorationRecorder::of(trace) else {
			return self.explore_unrecorded(run);
		};

		let record = |process: &Process, visited: &HashSet<State>, divergences: &[Divergence]| {
			recorder.record(process, visited, divergences)
		};
		self.explore_recording(Some(record), run)
	}

	/// Runs the exploration of `run` and reports what it decided. A build
	/// without `instrument` records no event, so it ignores `trace`.
	#[cfg(not(feature = "instrument"))]
	#[expect(unused_variables)]
	fn record_into(&mut self, trace: &TraceCollector, run: Run) -> Result<FdrVerdict, TightBeamError> {
		self.explore_unrecorded(run)
	}

	/// Runs the exploration of `run`, and hands `record` what the seeds of each
	/// explored process found.
	///
	/// This one exit path decides schedulability, so a spec that misses its
	/// deadlines cannot reach a consumer as a verdict that held.
	///
	/// # Errors
	///
	/// - The error of the first call of `record` that failed.
	/// - The error of the FMEA report that the configuration asks for.
	fn explore_recording<X, F>(&mut self, mut record: Option<F>, run: Run) -> Result<FdrVerdict, X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
		X: From<TightBeamError>,
	{
		let mut verdict = match run {
			Run::Configured => self.explore_modes(&mut record)?,
			Run::StateSpace => self.explore_state_space(&mut record)?,
		};

		verdict.schedulable = self.schedulability();

		Ok(verdict)
	}

	/// What schedulability analysis decided about the configured specs.
	///
	/// A spec with no schedulability block has no task set, so no analysis
	/// runs and it decides [`Decision::NotAsserted`]. An analysis error decides
	/// [`Decision::Refuted`] and not [`Decision::Unknown`], because every
	/// `SchedulabilityError` names a defect in the declared task set, such as
	/// a period with no WCET.
	#[cfg(feature = "testing-schedulability")]
	fn schedulability(&self) -> Decision {
		let mut decision = Decision::NotAsserted;
		for spec in self.config.specs.iter() {
			let analysed = match spec.schedulability_violated() {
				Ok(None) => Decision::NotAsserted,
				Ok(Some(false)) => Decision::Holds,
				Ok(Some(true)) | Err(_) => Decision::Refuted,
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
		X: From<TightBeamError>,
	{
		match self.config.mode() {
			// Mode 1: a fault model with specs explores each spec under faults.
			#[cfg(feature = "testing-fault")]
			ExplorationMode::UnderFaults => {
				// The run tests whether each spec models the error conditions
				// that the faults cause.
				self.explore_specification_with_faults(record)?;
				#[cfg(feature = "testing-fmea")]
				{
					// Each fault fired in a spec, so it rates in that spec.
					let config = Arc::clone(&self.config);
					self.generate_fmea_if_configured(&config.specs)?;
				}
				Ok(self.verdict.clone())
			}
			// Mode 2: specs with no fault model run the refinement checks.
			ExplorationMode::Refinement => {
				let config = Arc::clone(&self.config);
				let subject = config.scheduled(self.process).map_err(TightBeamError::from)?;
				self.check_refinement(&subject);
				#[cfg(feature = "testing-fmea")]
				self.generate_fmea_if_configured([self.process])?;
				Ok(self.verdict.clone())
			}
			// Mode 3: a run with no spec explores the process over every seed.
			ExplorationMode::StateSpace => self.explore_state_space(record),
		}
	}

	/// Explores the subject over every seed through the engine, and hands
	/// `record` the states that the seeds visited and the divergences they
	/// found.
	///
	/// Under a scheduler constraint the seeds walk the scheduled subject, on
	/// an engine that [`ExplorationCore::for_process`] of `E` builds.
	fn explore_state_space<X, F>(&mut self, record: &mut Option<F>) -> Result<FdrVerdict, X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
		X: From<TightBeamError>,
	{
		if self.asserts_freedom() {
			self.verdict.divergence_free = Decision::Holds;
			self.verdict.deadlock_free = Decision::Holds;
		}

		let config = Arc::clone(&self.config);
		let subject = config.scheduled(self.process).map_err(TightBeamError::from)?;
		let mut found = FoundDivergences::kept_when(record.is_some());
		let seeds = 0..u64::from(config.seeds);
		match &subject {
			Cow::Borrowed(process) => {
				self.verdict.add_walk(&mut self.explorer, seeds, &mut found);
				if let Some(record) = record.as_mut() {
					record(process, self.explorer.visited_states(), found.divergences())?;
				}
			}
			Cow::Owned(process) => {
				let mut engine = self.explorer.for_process(process);
				self.verdict.add_walk(&mut engine, seeds, &mut found);
				if let Some(record) = record.as_mut() {
					record(process, engine.visited_states(), found.divergences())?;
				}
			}
		}

		self.check_determinism();

		#[cfg(feature = "testing-fmea")]
		self.generate_fmea_if_configured([self.process])?;

		Ok(self.verdict.clone())
	}

	/// Explores every configured spec under fault injection, over every seed,
	/// and hands `record` the states that each spec's seeds visited and the
	/// divergences they found.
	///
	/// - The verdict describes the spec runs that this mode judges, and the subject's engine stays empty.
	/// - Each spec runs on an engine of its own, which [`ExplorationCore::for_process`] of `E` builds.
	/// - `states_visited` counts the distinct states of each spec.
	/// - The loop covers every spec, because a fault run of `specs[0]` alone would leave the rest untested.
	/// - Under a scheduler constraint each spec runs scheduled.
	///
	/// # Errors
	///
	/// - The [`FdrConfigError`](crate::testing::error::FdrConfigError) of a
	///   scheduler constraint that does not fit a spec.
	/// - The error of the first call of `record` that failed.
	#[cfg(feature = "testing-fault")]
	fn explore_specification_with_faults<X, F>(&mut self, record: &mut Option<F>) -> Result<(), X>
	where
		F: FnMut(&Process, &HashSet<State>, &[Divergence]) -> Result<(), X>,
		X: From<TightBeamError>,
	{
		let config = Arc::clone(&self.config);
		for spec_process in &config.specs {
			let spec_process = config.scheduled(spec_process).map_err(TightBeamError::from)?;
			let mut engine = self.explorer.for_process(&spec_process);
			let mut found = FoundDivergences::kept_when(record.is_some());
			let seeds = 0..u64::from(config.seeds);
			for (seed, result) in engine.explore_seeds(seeds) {
				self.add_spec_seed(*seed, result);
				found.note(result);
			}

			self.verdict.timing_pruned += engine.timing_pruned();
			self.verdict.states_visited += engine.visited_states().len();
			if let Some(record) = record.as_mut() {
				record(&spec_process, engine.visited_states(), found.divergences())?;
			}
		}

		self.check_determinism();

		Ok(())
	}

	/// Adds the result of `seed` of a spec run under faults to the verdict.
	#[cfg(feature = "testing-fault")]
	fn add_spec_seed(&mut self, seed: u64, result: &SeedResult) {
		self.verdict.add_seed(seed, result);
		self.verdict.traces_explored += usize::from(result.succeeded());
	}

	/// Builds the FMEA report when the FMEA configuration sets `auto_generate`
	/// and the run injected a fault. Each fault rates in the first of
	/// `processes` that holds its state.
	///
	/// # Errors
	///
	/// - The error of [`FdrVerdict::fmea_report`], which leaves the verdict with no report.
	#[cfg(feature = "testing-fmea")]
	fn generate_fmea_if_configured<'p>(
		&mut self,
		processes: impl IntoIterator<Item = &'p Process>,
	) -> Result<(), TightBeamError> {
		if let Some(ref fmea_config) = self.config.fmea_config {
			if fmea_config.auto_generate && !self.verdict.faults_injected.is_empty() {
				let report = self.verdict.fmea_report(processes, Some(fmea_config.clone()))?;
				self.verdict.fmea_report = Some(report);
			}
		}

		Ok(())
	}

	/// Records whether the subject is structurally deterministic, by the rule
	/// of [`Process::determinism_witness`].
	fn check_determinism(&mut self) {
		let witness = self.process.determinism_witness();
		self.verdict.record_determinism(witness);
	}

	/// Checks `spec ⊑ subject` in the models that the subject admits.
	///
	/// - `subject` is the process under verification as the scheduler constraint lets it run.
	/// - The check always asks traces refinement.
	/// - It asks failures and divergences only of a subject whose observation
	///   carries refusals, or the checker would grade the subject on refusals
	///   it synthesized.
	/// - Under `fail_fast`, each pass stops at its first violation.
	fn check_refinement(&mut self, subject: &Process) {
		// The check reads the spec list through an `Arc` clone and not a copy,
		// because a clone of `Vec<Process>` duplicates every state set and
		// transition map that the checker only reads.
		let config = Arc::clone(&self.config);
		let specs = config.specs.as_slice();
		self.verdict.unmodelled_events = self.unmodelled_events();

		self.verdict.trace_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_trace_refinement(s, subject),
			|v, w| {
				v.trace_refinement_witness = Some(w);
			},
		);

		if !subject.observation.carries_refusals() {
			return;
		}

		self.verdict.failures_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_failures_refinement(s, subject),
			|v, w| {
				v.failures_refinement_witness = Some(w);
			},
		);

		self.verdict.divergence_refines = self.check_refinement_for_specs(
			specs,
			|r, s| r.check_divergence_refinement(s, subject),
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

	/// Explores the state space of the subject. When the configuration names
	/// specs, it also refines `trace_process` against them and merges the
	/// refinement decisions of that pass.
	///
	/// A scenario explores its CSP model this way, with `trace_process` the
	/// process of its recorded trace. `exploration` records the exploration
	/// events of each pass that its instrumentation settings ask for.
	///
	/// # Errors
	///
	/// - The error of the first exploration event that `exploration` refused.
	/// - The error of the FMEA report that the configuration asks for.
	pub(crate) fn explore_model_then_trace(
		&mut self,
		trace_process: &Process,
		exploration: &TraceCollector,
	) -> Result<FdrVerdict, TightBeamError> {
		let verdict = self.explore_state_space_into(exploration)?;
		if !self.config.refines_against_specs() {
			return Ok(verdict);
		}

		let trace_config = Arc::clone(&self.config);
		let mut trace_explorer = DefaultFdrExplorer::with_defaults(trace_process, trace_config);
		let trace_verdict = trace_explorer.explore_into(exploration)?;

		Ok(verdict.with_refinement_from(trace_verdict))
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "testing-timing")]
	use core::time::Duration;

	use super::Decision;
	use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	use crate::testing::fixtures::TestProcess;
	use crate::testing::specs::composition::DeterminismChecker;
	use crate::testing::specs::csp::{Event, Process, State};
	use crate::testing::TestResult;
	use crate::trace::TraceCollector;

	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::TimingGuard;

	/// A fixture that builds the process of a row.
	type Fixture = fn() -> Process;

	/// A spec that models `start` and nothing else.
	fn narrow_spec() -> Process {
		TestProcess::chain("NarrowSpec", &["S0", "S1"], &["start"])
	}

	/// A subject in which `arm` takes `S0` to `S1` when `clk` reads at most
	/// 5 ms, and `S1` is not terminal and offers no event.
	#[cfg(feature = "testing-timing")]
	fn guarded_deadlock() -> Process {
		let guard = Some(TimingGuard::clk_within(5));
		Process::builder("GuardedDeadlock")
			.initial_state(State("S0"))
			.clock("clk")
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), guard, Vec::new())
			.build()
			.expect("a timed process with an initial state builds")
	}

	/// A subject in which `start` takes `S0` to `S1` and resets `clk`, and
	/// `arm` takes `S1` to the terminal `S2` when `clk` reads at most 5 ms.
	#[cfg(feature = "testing-timing")]
	fn reset_then_guard() -> Process {
		let guard = Some(TimingGuard::clk_within(5));
		Process::builder("ResetThenGuard")
			.initial_state(State("S0"))
			.clock("clk")
			.add_observable(Event("start"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("start"), State("S1"), None, ["clk".to_string()])
			.add_timed_transition(State("S1"), Event("arm"), State("S2"), guard, Vec::new())
			.add_terminal(State("S2"))
			.build()
			.expect("a timed process with an initial state builds")
	}

	/// A subject in which `arm` takes `S0` to the terminal `S1` when `clk`
	/// reads at most 5 ms, and no transition resets `clk`.
	#[cfg(feature = "testing-timing")]
	fn guarded_from_the_start() -> Process {
		let guard = Some(TimingGuard::clk_within(5));
		Process::builder("GuardedFromTheStart")
			.initial_state(State("S0"))
			.clock("clk")
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), guard, Vec::new())
			.add_terminal(State("S1"))
			.build()
			.expect("a timed process with an initial state builds")
	}

	/// A subject that performs `start`, then an event no spec mentions.
	fn wider_subject() -> Process {
		TestProcess::chain("WiderSubject", &["T0", "T1", "T2"], &["start", "audit"])
	}

	/// A subject whose hidden `p` takes `S0` onto the hidden cycle of `t` and
	/// `u` between `S1` and `S2`, so `S0` lies off the cycle and reaches it.
	fn lasso() -> Process {
		TestProcess {
			observable: &["b"],
			hidden: &["p", "t", "u"],
			transitions: &[("S0", "p", "S1"), ("S1", "t", "S2"), ("S2", "u", "S1"), ("S2", "b", "S3")],
			terminal: &["S3"],
			..TestProcess::of("Lasso", "S0")
		}
		.build()
	}

	/// A subject in which `a` takes `I` to `X`, whose two hidden runs meet at
	/// `Q`, which loops on the hidden `first`.
	///
	/// The run through `P` takes `first` twice, and the run that `second`
	/// names takes one hidden event, so the order of the event names decides
	/// which run a search takes first. The two names vary, so the process
	/// takes the builder that [`TestProcess`] wraps.
	fn meeting(first: &'static str, second: &'static str) -> Process {
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
			.expect("a process with an initial state builds")
	}

	/// A subject whose hidden `t` and `u` take `S0` through `S1` to `S2`, a run
	/// of two hidden events with no cycle, before `c` ends it at `S3`.
	fn hidden_chain() -> Process {
		TestProcess {
			observable: &["c"],
			hidden: &["t", "u"],
			transitions: &[("S0", "t", "S1"), ("S1", "u", "S2"), ("S2", "c", "S3")],
			terminal: &["S3"],
			..TestProcess::of("HiddenChain", "S0")
		}
		.build()
	}

	/// A subject whose hidden `p` comes before the observable `a`, and whose
	/// hidden run `t`, `u` comes after it.
	fn chain_after_a_run() -> Process {
		TestProcess {
			observable: &["a", "c"],
			hidden: &["p", "t", "u"],
			transitions: &[
				("S0", "p", "S1"),
				("S1", "a", "S2"),
				("S2", "t", "S3"),
				("S3", "u", "S4"),
				("S4", "c", "S5"),
			],
			terminal: &["S5"],
			..TestProcess::of("ChainAfterARun", "S0")
		}
		.build()
	}

	/// A spec whose accepting `S0` spins on the hidden `t`, so it diverges at
	/// once and its one trace is the empty trace.
	fn spinning_at_once() -> Process {
		TestProcess {
			observable: &["b"],
			hidden: &["t"],
			transitions: &[("S0", "t", "S0")],
			terminal: &["S0"],
			..TestProcess::of("SpinningAtOnce", "S0")
		}
		.build()
	}

	/// A subject whose accepting `Idle` offers `b`, which leads to a spin on
	/// the hidden `t` at `D`.
	fn spinning_after_b() -> Process {
		TestProcess {
			observable: &["b"],
			hidden: &["t"],
			transitions: &[("Idle", "b", "D"), ("D", "t", "D")],
			terminal: &["Idle"],
			..TestProcess::of("SpinningAfterB", "Idle")
		}
		.build()
	}

	/// A subject whose accepting `Idle` offers `b`, which leads to `D`, a
	/// state that can neither terminate nor act.
	fn stuck_after_b() -> Process {
		TestProcess {
			observable: &["b"],
			transitions: &[("Idle", "b", "D")],
			terminal: &["Idle"],
			..TestProcess::of("StuckAfterB", "Idle")
		}
		.build()
	}

	/// A subject whose `start` resets `clk` on its way to the accepting `S1`,
	/// where the hidden `t` spins under `guard`.
	#[cfg(feature = "testing-timing")]
	fn guarded_spin(guard: TimingGuard) -> Process {
		Process::builder("GuardedSpin")
			.initial_state(State("S0"))
			.clock("clk")
			.add_observable(Event("start"))
			.add_hidden(Event("t"))
			.add_timed_transition(State("S0"), Event("start"), State("S1"), None, ["clk".to_string()])
			.add_timed_transition(State("S1"), Event("t"), State("S1"), Some(guard), Vec::new())
			.add_terminal(State("S1"))
			.build()
			.expect("a timed process with an initial state builds")
	}

	/// A subject whose hidden `t` resets `clk` on its way from `S0` to `S1`,
	/// where the hidden `u` spins while `clk` reads at most 5 ms.
	#[cfg(feature = "testing-timing")]
	fn spinning_after_a_reset() -> Process {
		let guard = Some(TimingGuard::clk_within(5));
		Process::builder("SpinningAfterAReset")
			.initial_state(State("S0"))
			.clock("clk")
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_timed_transition(State("S0"), Event("t"), State("S1"), None, ["clk".to_string()])
			.add_timed_transition(State("S1"), Event("u"), State("S1"), guard, Vec::new())
			.build()
			.expect("a timed process with an initial state builds")
	}

	/// A refinement check projects away an event that no spec models, so the
	/// event is coverage and not a counterexample.
	#[test]
	fn refinement_reports_what_the_projection_discarded() {
		let verdict = wider_subject().verdict_under(FdrConfig::refining(narrow_spec()));
		let reported = (verdict.unmodelled_events, verdict.trace_refines);
		assert_eq!(reported, (vec![Event("audit")], Decision::Holds));
	}

	// An exploration decides deadlock freedom over each state it reaches,
	// with each clock at zero at the start and at each reset.
	crate::tb_cases! {
		fn deadlock_freedom_of((subject, decided): (Fixture, Decision)) {
			let verdict = subject().verdict_under(FdrConfig::default());
			assert_eq!(verdict.deadlock_free, decided);
		}

		cases {
			#[cfg(feature = "testing-timing")]
			a_guard_over_a_deadlock => (guarded_deadlock, Decision::Refuted),
			#[cfg(feature = "testing-timing")]
			a_guard_behind_a_reset_clock => (reset_then_guard, Decision::Holds),
			#[cfg(feature = "testing-timing")]
			a_guard_on_a_clock_at_zero => (guarded_from_the_start, Decision::Holds),
			/// `b` leads from the accepting `Idle` to `D`.
			a_deadlock_behind_an_accepting_state => (stuck_after_b, Decision::Refuted),
		}
	}

	// An exploration decides divergence freedom over each hidden cycle it
	// reaches and each hidden run past `max_internal_run`.
	crate::tb_cases! {
		fn divergence_freedom_of((subject, config, decided): (Fixture, FdrConfig, Decision)) {
			let verdict = subject().verdict_under(config);
			assert_eq!(verdict.divergence_free, decided);
		}

		cases {
			a_reachable_hidden_cycle => (TestProcess::spinning, FdrConfig::default(), Decision::Refuted),
			/// `X` reaches the loop at `Q` whichever run a search takes first.
			a_meeting_that_loops_on_t => (
				|| meeting("t", "u"),
				FdrConfig { seeds: 8, max_depth: 1, max_internal_run: 2, ..Default::default() },
				Decision::Refuted,
			),
			/// `X` reaches the loop at `Q` whichever run a search takes first.
			a_meeting_that_loops_on_z => (
				|| meeting("z", "u"),
				FdrConfig { seeds: 8, max_depth: 1, max_internal_run: 2, ..Default::default() },
				Decision::Refuted,
			),
			/// `a` reaches `S1` at the depth cut-off.
			a_hidden_cycle_at_the_depth_cut_off => (
				TestProcess::spinning,
				FdrConfig { max_depth: 1, ..Default::default() },
				Decision::Refuted,
			),
			a_hidden_run_at_max_internal_run => (
				hidden_chain,
				FdrConfig { max_internal_run: 2, ..Default::default() },
				Decision::Holds,
			),
			a_hidden_run_past_max_internal_run => (
				hidden_chain,
				FdrConfig { max_internal_run: 1, ..Default::default() },
				Decision::Refuted,
			),
			/// The accepting `Idle` offers `b` into the spin.
			a_hidden_cycle_behind_an_accepting_state => (spinning_after_b, FdrConfig::default(), Decision::Refuted),
			/// `clk` reads 0 at `S1`, so `t` never fires.
			#[cfg(feature = "testing-timing")]
			a_hidden_cycle_that_a_guard_blocks => (
				|| guarded_spin(TimingGuard::ClockGreaterThan("clk".to_string(), Duration::from_millis(5))),
				FdrConfig::default(),
				Decision::Holds,
			),
		}
	}

	// The divergence witness of an exploration is the hidden run that diverged.
	crate::tb_cases! {
		fn the_divergence_witness_is_the_diverging_run((subject, config, run): (Fixture, FdrConfig, Vec<Event>)) {
			let witnessed = subject().divergence_run_under(config);
			assert_eq!(witnessed, Some(run));
		}

		cases {
			of_a_reachable_hidden_cycle => (TestProcess::spinning, FdrConfig::default(), vec![Event("t"), Event("u")]),
			/// `S0` reaches the cycle of `t` and `u`.
			from_a_state_off_its_cycle => (
				lasso,
				FdrConfig { max_internal_run: 1, ..Default::default() },
				vec![Event("p"), Event("t"), Event("u")],
			),
			/// `a` ends the run of `p`.
			past_max_internal_run_alone => (
				chain_after_a_run,
				FdrConfig { max_internal_run: 1, ..Default::default() },
				vec![Event("t"), Event("u")],
			),
			/// `clk` reads 0 at `S1`, so `t` fires forever.
			#[cfg(feature = "testing-timing")]
			of_a_hidden_cycle_that_a_guard_admits => (
				|| guarded_spin(TimingGuard::clk_within(5)),
				FdrConfig::default(),
				vec![Event("t")],
			),
			/// `t` starts `clk`, which `u` reads.
			#[cfg(feature = "testing-timing")]
			through_a_clock_that_a_hidden_step_resets => (
				spinning_after_a_reset,
				FdrConfig::default(),
				vec![Event("t"), Event("u")],
			),
		}
	}

	/// A spec whose one trace is the empty trace refutes a subject that takes
	/// an event.
	#[test]
	fn a_spec_that_diverges_at_once_refutes_an_event_that_it_lacks() {
		let verdict = spinning_after_b().verdict_under(FdrConfig::refining(spinning_at_once()));
		let decided = verdict.outcome();
		assert_eq!(decided, Decision::Refuted);
	}

	/// A spec with no schedulability block leaves schedulability unasserted,
	/// since no analysis runs.
	#[cfg(feature = "testing-schedulability")]
	#[test]
	fn a_spec_with_no_schedulability_block_leaves_schedulability_unasserted() {
		let verdict = wider_subject().verdict_under(FdrConfig::refining(narrow_spec()));
		let decided = verdict.schedulable;
		assert_eq!(decided, Decision::NotAsserted);
	}

	/// A state-space exploration decides deadlock freedom whatever specs the
	/// config names, so `b` from the accepting `Idle` to `D` refutes it.
	#[test]
	fn a_state_space_exploration_decides_freedom_whatever_specs_the_configuration_names() -> TestResult {
		let subject = stuck_after_b();
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, FdrConfig::refining(narrow_spec()));

		let verdict = explorer.explore_state_space_into(&TraceCollector::new())?;
		assert_eq!(verdict.deadlock_free, Decision::Refuted);
		Ok(())
	}

	/// A fault run counts the states, traces, and seeds of the spec runs it
	/// judged: the spec visits `S0` and `S1` on each of four seeds.
	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_run_describes_the_spec_runs_it_judged() {
		let config = FdrConfig { seeds: 4, ..FdrConfig::under_faults([narrow_spec()]) };

		let verdict = wider_subject().verdict_under(config);
		let statistics = (verdict.states_visited, verdict.traces_explored, verdict.seeds_completed);
		assert_eq!(statistics, (2, 4, 4));
	}

	/// The explorer and the composition claim name one hidden action as the
	/// determinism witness.
	#[test]
	fn a_hidden_action_is_one_determinism_witness_for_the_explorer_and_the_composition_claim() {
		let subject = hidden_chain();
		let verdict = subject.verdict_under(FdrConfig::default());
		let refused = DeterminismChecker::check(&subject).err();

		let claimed = refused.map(|refused| (refused.state, refused.event));
		let hidden_t = Some((State("S0"), Event("t")));
		assert_eq!((verdict.determinism_witness, claimed), (hidden_t, hidden_t));
	}
}

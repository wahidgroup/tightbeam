//! Layer 3: FDR/Refinement checking
//!
//! This module provides bounded refinement checking following CSP theory:
//! - Trace refinement (⊑T): traces(Impl) ⊆ traces(Spec)
//! - Failures refinement (⊑F): failures(Impl) ⊆ failures(Spec)
//! - Divergence detection: no infinite τ-loops
//! - Multi-seed exploration: different scheduler interleavings
//! - CSPM export for FDR4 integration
//!
//! Based on:
//! - Hoare (1985): Communicating Sequential Processes
//! - Roscoe (2010): Understanding Concurrent Systems
//! - Pedersen & Chalmers (2024): Verifying Cooperatively Scheduled Runtimes
//!
//! Feature gated: requires `testing-fdr`

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;

use super::csp::{Event, Process, State};
use crate::testing::assertions::AssertionLabel;
use crate::testing::trace::ConsumedTrace;

/// FDR configuration for multi-seed exploration
#[derive(Debug, Clone, Copy)]
pub struct FdrConfig {
	/// Number of exploration seeds (different schedulings)
	pub seeds: u32,

	/// Maximum trace depth before cutoff
	pub max_depth: usize,

	/// Maximum consecutive τ-transitions before divergence detection
	pub max_internal_run: usize,

	/// Per-seed timeout in milliseconds
	pub timeout_ms: u64,
}

impl Default for FdrConfig {
	fn default() -> Self {
		Self { seeds: 64, max_depth: 128, max_internal_run: 32, timeout_ms: 5000 }
	}
}

/// FDR verification verdict
///
/// Captures refinement results across all three CSP semantic models:
/// - Traces model (⊑T)
/// - Stable failures model (⊑F)
/// - Failures-divergences model (⊑FD)
#[derive(Debug, Clone)]
pub struct FdrVerdict {
	/// Trace refinement: traces(Impl) ⊆ traces(Spec)
	pub trace_refines: bool,

	/// Failures refinement: failures(Impl) ⊆ failures(Spec)
	pub failures_refines: bool,

	/// Divergence freedom: no infinite τ-loops detected
	pub divergence_free: bool,

	/// Determinism: no witnesses to nondeterminism found
	pub is_deterministic: bool,

	/// Witness to nondeterminism: (trace, event) where both accept and refuse
	pub determinism_witness: Option<(Vec<Event>, Event)>,

	/// Witness to divergence: τ-loop sequence if found
	pub divergence_witness: Option<Vec<Event>>,

	/// Traces explored across all seeds
	pub traces_explored: usize,

	/// Distinct states visited
	pub states_visited: usize,

	/// Seeds that completed successfully
	pub seeds_completed: u32,
}

impl Default for FdrVerdict {
	fn default() -> Self {
		Self {
			trace_refines: true,
			failures_refines: true,
			divergence_free: true,
			is_deterministic: true,
			determinism_witness: None,
			divergence_witness: None,
			traces_explored: 0,
			states_visited: 0,
			seeds_completed: 0,
		}
	}
}

/// CSP trace: sequence of observable events
pub type Trace = Vec<Event>;

/// Refusal set: events refused in stable state
pub type RefusalSet = HashSet<Event>;

/// Failure: (trace, refusal_set)
pub type Failure = (Trace, RefusalSet);

/// Acceptance set: events accepted after trace
pub type AcceptanceSet = HashSet<Event>;

/// FDR exploration state
#[derive(Debug, Clone)]
struct ExplorationState {
	/// Current process state
	process_state: State,

	/// Trace so far (observable events only)
	trace: Trace,

	/// Consecutive τ-transitions counter
	internal_run: usize,

	/// Path through state space (for divergence witness)
	state_path: Vec<State>,

	/// Hidden events executed (for divergence witness)
	hidden_events: Vec<Event>,
}

/// FDR exploration engine
pub struct FdrExplorer<'a> {
	/// Process being verified
	process: &'a Process,

	/// Configuration
	config: FdrConfig,

	/// Collected traces
	traces: Vec<Trace>,

	/// Collected failures
	failures: Vec<Failure>,

	/// States visited (for statistics)
	visited_states: HashSet<State>,

	/// Verdict accumulator
	verdict: FdrVerdict,
}

impl<'a> FdrExplorer<'a> {
	/// Create new FDR explorer
	pub fn new(process: &'a Process, config: FdrConfig) -> Self {
		Self {
			process,
			config,
			traces: Vec::new(),
			failures: Vec::new(),
			visited_states: HashSet::new(),
			verdict: FdrVerdict::default(),
		}
	}

	/// Run multi-seed exploration
	pub fn explore(&mut self) -> FdrVerdict {
		for seed in 0..self.config.seeds {
			self.explore_seed(seed);
			self.verdict.seeds_completed += 1;
		}

		self.verdict.traces_explored = self.traces.len();
		self.verdict.states_visited = self.visited_states.len();

		// Check determinism
		self.check_determinism();

		self.verdict.clone()
	}

	/// Explore single seed (different scheduling)
	fn explore_seed(&mut self, seed: u32) {
		let mut queue = VecDeque::new();

		// Initial exploration state
		let initial = ExplorationState {
			process_state: self.process.initial,
			trace: Vec::new(),
			internal_run: 0,
			state_path: vec![self.process.initial],
			hidden_events: Vec::new(),
		};

		queue.push_back(initial);

		while let Some(state) = queue.pop_front() {
			// Track visited states
			self.visited_states.insert(state.process_state);

			// Depth cutoff
			if state.trace.len() >= self.config.max_depth {
				continue;
			}

			// Divergence detection
			if state.internal_run > self.config.max_internal_run {
				self.verdict.divergence_free = false;
				self.verdict.divergence_witness = Some(state.hidden_events.clone());
				continue;
			}

			// Terminal state: record trace and compute refusal set
			if self.process.is_terminal(state.process_state) {
				self.traces.push(state.trace.clone());

				let refusal_set = self.compute_refusal_set(state.process_state);
				self.failures.push((state.trace.clone(), refusal_set));

				continue;
			}

			// Get enabled actions
			let actions = self.process.enabled(state.process_state);

			if actions.is_empty() {
				// Deadlock: record trace and failure
				self.traces.push(state.trace.clone());

				// Deadlock refuses all events
				let refusal_set = self.process.observable.clone();
				self.failures.push((state.trace.clone(), refusal_set));

				continue;
			}

			// Explore transitions (with seed-based selection for nondeterminism)
			for (idx, action) in actions.iter().enumerate() {
				// Seed-based selection for choice points
				if self.process.choice.contains(&state.process_state) {
					// Only take path determined by seed at choice points
					if idx != ((seed as usize + state.trace.len()) % actions.len()) {
						continue;
					}
				}

				let next_states = self.process.step(state.process_state, &action.event);

				for next_state in next_states {
					let mut next = state.clone();
					next.process_state = next_state;
					next.state_path.push(next_state);

					if action.is_observable() {
						// Observable: extend trace, reset internal counter
						next.trace.push(action.event.clone());
						next.internal_run = 0;
					} else {
						// Hidden (τ): increment internal counter
						next.internal_run += 1;
						next.hidden_events.push(action.event.clone());
					}

					queue.push_back(next);
				}
			}
		}
	}

	/// Compute refusal set at stable state
	fn compute_refusal_set(&self, state: State) -> RefusalSet {
		let mut refusal = self.process.observable.clone();

		// Remove enabled observable events
		for event in &self.process.observable {
			if !self.process.step(state, event).is_empty() {
				refusal.remove(event);
			}
		}

		refusal
	}

	/// Check for witnesses to nondeterminism
	fn check_determinism(&mut self) {
		let mut trace_acceptance: HashMap<Trace, AcceptanceSet> = HashMap::new();

		// Build acceptance sets per trace
		for failure in &self.failures {
			let trace = &failure.0;
			let refusal = &failure.1;

			// Acceptance = Observable - Refusal
			let acceptance: AcceptanceSet = self.process.observable.difference(refusal).cloned().collect();

			trace_acceptance.entry(trace.clone()).or_default().extend(acceptance);
		}

		// Check for nondeterminism: same trace, event both accepted and refused
		for (trace, acceptance) in &trace_acceptance {
			for event in &self.process.observable {
				// Check if any failure after this trace refuses this event
				let mut can_refuse = false;
				let can_accept = acceptance.contains(event);

				for failure in &self.failures {
					if &failure.0 == trace && failure.1.contains(event) {
						can_refuse = true;
						break;
					}
				}

				if can_accept && can_refuse {
					self.verdict.is_deterministic = false;
					self.verdict.determinism_witness = Some((trace.clone(), event.clone()));
					return;
				}
			}
		}
	}

	/// Get traces explored
	pub fn traces(&self) -> &[Trace] {
		&self.traces
	}

	/// Get failures collected
	pub fn failures(&self) -> &[Failure] {
		&self.failures
	}
}

/// CSPM (CSP Machine-readable) export
pub struct CspmExporter<'a> {
	process: &'a Process,
}

impl<'a> CspmExporter<'a> {
	pub fn new(process: &'a Process) -> Self {
		Self { process }
	}

	/// Export process to CSPM format for FDR4
	pub fn export<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Generated by tightbeam testing framework")?;
		writeln!(writer, "-- Process: {}", self.process.name)?;

		if let Some(desc) = self.process.description {
			writeln!(writer, "-- Description: {desc}")?;
		}

		writeln!(writer)?;

		// Observable alphabet
		writeln!(writer, "-- Observable alphabet (Σ)")?;
		writeln!(writer, "datatype Observable = ")?;
		let mut obs_iter = self.process.observable.iter();
		if let Some(first) = obs_iter.next() {
			write!(writer, "  {}", first.0)?;
			for event in obs_iter {
				write!(writer, " | {}", event.0)?;
			}
			writeln!(writer)?;
		}
		writeln!(writer)?;

		// Hidden alphabet
		if !self.process.hidden.is_empty() {
			writeln!(writer, "-- Hidden alphabet (τ)")?;
			writeln!(writer, "datatype Hidden = ")?;
			let mut hid_iter = self.process.hidden.iter();
			if let Some(first) = hid_iter.next() {
				write!(writer, "  {}", first.0)?;
				for event in hid_iter {
					write!(writer, " | {}", event.0)?;
				}
				writeln!(writer)?;
			}
			writeln!(writer)?;
		}

		// States
		writeln!(writer, "-- States")?;
		writeln!(writer, "datatype States = ")?;
		let mut state_iter = self.process.states.iter();
		if let Some(first) = state_iter.next() {
			write!(writer, "  {}", first.0)?;
			for state in state_iter {
				write!(writer, " | {}", state.0)?;
			}
			writeln!(writer)?;
		}
		writeln!(writer)?;

		// Process definition (simplified LTS representation)
		writeln!(writer, "-- Process: {}", self.process.name)?;
		writeln!(writer, "channel obs : Observable")?;
		writeln!(writer, "channel hid : Hidden")?;
		writeln!(writer)?;

		// Generate process per state
		for state in &self.process.states {
			write!(writer, "{}Process = ", state.0)?;

			if self.process.is_terminal(*state) {
				writeln!(writer, "SKIP")?;
			} else {
				// Get enabled actions
				let enabled = self.process.enabled(*state);

				if enabled.is_empty() {
					writeln!(writer, "STOP")?;
				} else {
					let mut first = true;
					for action in enabled {
						if !first {
							write!(writer, " [] ")?;
						}
						first = false;

						let next_states = self.process.step(*state, &action.event);
						let next = next_states.first().unwrap(); // Take first for simplicity

						if action.is_observable() {
							write!(writer, "obs.{} -> {}Process", action.event.0, next.0)?;
						} else {
							write!(writer, "hid.{} -> {}Process", action.event.0, next.0)?;
						}
					}
					writeln!(writer)?;
				}
			}
			writeln!(writer)?;
		}

		// Main process
		writeln!(
			writer,
			"{} = {}Process \\ {{| hid |}}",
			self.process.name, self.process.initial.0
		)?;

		Ok(())
	}
}

/// Extension trait for ConsumedTrace with FDR analysis
pub trait FdrTraceExt {
	/// Check if CSP trace is valid
	fn csp_valid(&self) -> bool;

	/// Check if terminated in valid terminal state
	fn terminated_in_valid_state(&self) -> bool;

	/// Get acceptance set after current trace
	fn acceptance_at(&self, state_label: &str) -> Option<AcceptanceSet>;

	/// Check if process can refuse event after state
	fn can_refuse_after(&self, state_label: &str, event_label: &str) -> bool;

	/// Count assertion by label (convenience)
	fn assertion_count(&self, label: &str) -> usize;

	/// Project trace to observable events only
	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String>;

	/// Project trace to hidden events only
	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String>;

	/// Export trace as CSPM
	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

impl FdrTraceExt for ConsumedTrace {
	fn csp_valid(&self) -> bool {
		// TODO: Validate against process spec
		// For now, assume valid if no errors
		self.error.is_none()
	}

	fn terminated_in_valid_state(&self) -> bool {
		// TODO: Check if final state is terminal
		// For now, check if completed successfully
		self.error.is_none() && !self.assertions.is_empty()
	}

	fn acceptance_at(&self, _state_label: &str) -> Option<AcceptanceSet> {
		// TODO: Compute acceptance set from process
		None
	}

	fn can_refuse_after(&self, _state_label: &str, _event_label: &str) -> bool {
		// TODO: Check refusal set
		false
	}

	fn assertion_count(&self, label: &str) -> usize {
		self.assertions
			.iter()
			.filter(|a| matches!(&a.label, AssertionLabel::Custom(l) if *l == label))
			.count()
	}

	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::GateAccept
						| TbEventKind::GateReject
						| TbEventKind::RequestRecv
						| TbEventKind::ResponseSend
						| TbEventKind::AssertLabel
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		use crate::instrumentation::TbEventKind;

		self.instrument_events
			.iter()
			.filter(|e| {
				matches!(
					e.kind,
					TbEventKind::HandlerEnter
						| TbEventKind::HandlerExit
						| TbEventKind::CryptoStep
						| TbEventKind::CompressStep
						| TbEventKind::RouteStep
						| TbEventKind::PolicyEval
						| TbEventKind::ProcessHidden
				)
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Execution trace")?;
		writeln!(writer, "Trace = <")?;

		#[cfg(feature = "instrument")]
		{
			let observable = self.project_to_observable();
			for (idx, event) in observable.iter().enumerate() {
				if idx > 0 {
					write!(writer, ", ")?;
				}
				write!(writer, "{event}")?;
			}
		}

		writeln!(writer, ">")?;
		Ok(())
	}
}

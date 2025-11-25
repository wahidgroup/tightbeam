//! Process Composition Specifications
//!
//! Provides CSP parallel composition operators and process algebra operations
//! for composing multiple processes into complex concurrent systems.
//!
//! Based on Hoare's CSP theory and Roscoe's refinement checking.

use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::testing::specs::csp::{CspValidationResult, Event, Process, ProcessSpec, State};
use crate::trace::ConsumedTrace;

// Submodules
pub mod algebra;
pub mod operators;
pub mod verification;

// Re-export key types
pub use verification::{DeadlockChecker, DeterminismChecker, LivelockChecker};

/// Trait for process composition specifications
///
/// Similar to `ProcessSpec`, this trait allows both declarative macro usage
/// (`tb_compose_spec!`) and manual implementation for defining how multiple
/// processes are composed.
pub trait CompositionSpec {
	/// Get the composed process
	fn process() -> Process;

	/// Get composition metadata
	fn metadata() -> CompositionMetadata {
		CompositionMetadata::default()
	}

	/// Verify composition properties (deadlock-free, livelock-free, etc.)
	fn verify_properties() -> Result<(), CompositionError> {
		Ok(())
	}
}

/// Blanket implementation of ProcessSpec for CompositionSpec types
///
/// This allows composed processes to be used directly in tb_scenario! and
/// other testing macros that expect a ProcessSpec.
impl<T: CompositionSpec> ProcessSpec for T {
	fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult {
		let process = T::process();
		process.validate_trace(trace)
	}
}

/// Metadata about a process composition
#[derive(Debug, Clone)]
pub struct CompositionMetadata {
	/// Name of the composition
	pub name: &'static str,

	/// Optional description
	pub description: Option<&'static str>,

	/// Names of component processes
	pub component_processes: Vec<&'static str>,

	/// Synchronization alphabet (events that must synchronize)
	pub sync_alphabet: HashSet<Event>,

	/// Expected properties of the composition
	pub properties: CompositionProperties,
}

impl Default for CompositionMetadata {
	fn default() -> Self {
		Self {
			name: "UnnamedComposition",
			description: None,
			component_processes: Vec::new(),
			sync_alphabet: HashSet::new(),
			properties: CompositionProperties::default(),
		}
	}
}

/// Properties expected of a composition
#[derive(Debug, Clone, Default)]
pub struct CompositionProperties {
	/// Should be deadlock-free (None = not checked)
	pub deadlock_free: Option<bool>,

	/// Should be livelock-free (None = not checked)
	pub livelock_free: Option<bool>,

	/// Should be deterministic (None = not checked)
	pub deterministic: Option<bool>,
}

/// Errors that can occur during composition
#[derive(Debug, Clone)]
pub enum CompositionError {
	/// Alphabets don't match expectations
	AlphabetMismatch { expected: HashSet<Event>, actual: HashSet<Event> },

	/// Deadlock detected at a state
	DeadlockDetected { state: State },

	/// Livelock detected (infinite τ-cycle)
	LivelockDetected { cycle: Vec<State> },

	/// Non-determinism detected
	NonDeterminismDetected { state: State, events: Vec<Event> },

	/// Invalid composition structure
	InvalidComposition { reason: String },

	/// Process construction failed
	ProcessConstructionFailed { reason: String },
}

impl fmt::Display for CompositionError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::AlphabetMismatch { expected, actual } => {
				write!(f, "Alphabet mismatch: expected {:?}, got {:?}", expected, actual)
			}
			Self::DeadlockDetected { state } => write!(f, "Deadlock detected at state {}", state),
			Self::LivelockDetected { cycle } => {
				write!(f, "Livelock detected in cycle: {:?}", cycle)
			}
			Self::NonDeterminismDetected { state, events } => {
				write!(f, "Non-determinism at state {}: events {:?}", state, events)
			}
			Self::InvalidComposition { reason } => write!(f, "Invalid composition: {}", reason),
			Self::ProcessConstructionFailed { reason } => {
				write!(f, "Process construction failed: {}", reason)
			}
		}
	}
}

impl std::error::Error for CompositionError {}

/// Process expression AST for composition
///
/// Represents CSP process algebra expressions that can be evaluated
/// to produce concrete Process instances.
#[derive(Debug, Clone)]
pub enum ProcessExpr {
	/// Reference to an atomic process
	Atomic { name: &'static str, process: Box<Process> },

	/// Synchronized parallel: P || Q
	/// Processes synchronize on ALL shared events
	Synchronized { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Interleaved parallel: P ||| Q
	/// Processes run independently with no synchronization
	Interleaved { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Interface parallel: P [| A |] Q
	/// Processes synchronize only on events in alphabet A
	InterfaceParallel { left: Box<ProcessExpr>, sync_alphabet: HashSet<Event>, right: Box<ProcessExpr> },

	/// Alphabetized parallel: P [| αP | αQ |] Q
	/// Each process restricted to its alphabet, sync on intersection
	AlphabetizedParallel {
		left: Box<ProcessExpr>,
		left_alphabet: HashSet<Event>,
		right_alphabet: HashSet<Event>,
		right: Box<ProcessExpr>,
	},

	/// Sequential composition: P ; Q
	/// When P terminates, start Q
	Sequential { first: Box<ProcessExpr>, second: Box<ProcessExpr> },

	/// Hiding: P \ A
	/// Make events in A hidden (internal τ-transitions)
	Hiding { process: Box<ProcessExpr>, hidden_events: HashSet<Event> },

	/// Renaming: P [[ old <- new ]]
	/// Rename events according to mapping
	Renaming { process: Box<ProcessExpr>, mapping: HashMap<Event, Event> },

	/// External choice: P [] Q
	/// Environment determines which process (first event decides)
	ExternalChoice { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Internal choice: P |~| Q
	/// Process non-deterministically chooses
	InternalChoice { left: Box<ProcessExpr>, right: Box<ProcessExpr> },
}

impl ProcessExpr {
	/// Create an atomic process expression
	pub fn atomic(name: &'static str, process: Process) -> Self {
		Self::Atomic { name, process: Box::new(process) }
	}

	/// Get the name of this expression (for debugging/error messages)
	pub fn name(&self) -> String {
		match self {
			Self::Atomic { name, .. } => name.to_string(),
			Self::Synchronized { left, right } => format!("({} || {})", left.name(), right.name()),
			Self::Interleaved { left, right } => format!("({} ||| {})", left.name(), right.name()),
			Self::InterfaceParallel { left, right, .. } => {
				format!("({} [|A|] {})", left.name(), right.name())
			}
			Self::AlphabetizedParallel { left, right, .. } => {
				format!("({} [|α|] {})", left.name(), right.name())
			}
			Self::Sequential { first, second } => {
				format!("({} ; {})", first.name(), second.name())
			}
			Self::Hiding { process, .. } => format!("({} \\ A)", process.name()),
			Self::Renaming { process, .. } => format!("({} [[r]])", process.name()),
			Self::ExternalChoice { left, right } => {
				format!("({} [] {})", left.name(), right.name())
			}
			Self::InternalChoice { left, right } => {
				format!("({} |~| {})", left.name(), right.name())
			}
		}
	}

	/// Evaluate this expression to a concrete Process
	///
	/// This recursively evaluates the expression tree and applies
	/// the appropriate composition operators.
	pub fn evaluate(&self) -> Result<Process, CompositionError> {
		match self {
			Self::Atomic { process, .. } => Ok((**process).clone()),

			Self::Synchronized { left, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::synchronized_parallel(&p, &q)
			}

			Self::Interleaved { left, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::interleaved_parallel(&p, &q)
			}

			Self::InterfaceParallel { left, sync_alphabet, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::interface_parallel(&p, &q, sync_alphabet.clone())
			}

			Self::AlphabetizedParallel { left, left_alphabet, right_alphabet, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::alphabetized_parallel(&p, left_alphabet.clone(), &q, right_alphabet.clone())
			}

			Self::Sequential { first, second } => {
				let p = first.evaluate()?;
				let q = second.evaluate()?;
				Process::sequential(&p, &q)
			}

			Self::Hiding { process, hidden_events } => {
				let p = process.evaluate()?;
				p.hide(hidden_events.clone())
			}

			Self::Renaming { process, mapping } => {
				let p = process.evaluate()?;
				p.rename(mapping.clone())
			}

			Self::ExternalChoice { left, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::external_choice(&p, &q)
			}

			Self::InternalChoice { left, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				Process::internal_choice(&p, &q)
			}
		}
	}
}

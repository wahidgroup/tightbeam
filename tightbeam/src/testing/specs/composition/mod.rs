//! The specifications that compose CSP processes into one concurrent system.
//!
//! The module holds the CSP parallel operators and the process algebra
//! operations that build one process from two or more.
//!
//! The operators follow Hoare's CSP theory and Roscoe's refinement checking.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::testing::specs::csp::{CspValidationResult, Event, Process, ProcessBuildError, ProcessSpec, State};
use crate::trace::ConsumedTrace;
use crate::Errorizable;

pub mod algebra;
pub mod operators;
pub mod verification;

pub use verification::{DeadlockChecker, DeterminismChecker, LivelockChecker};

/// The parallel operators that compose two CSP processes.
///
/// Each variant names one operator and its symbol in the standard CSP
/// notation.
#[derive(Debug, Clone, PartialEq)]
pub enum CompositionOperator {
	/// Synchronized parallel, `||`. The processes synchronize on every shared
	/// event, so an event of both alphabets must occur in both together, and
	/// an event of one alphabet interleaves.
	Synchronized,

	/// Interleaved parallel, `|||`. Every event of both processes interleaves
	/// independently.
	Interleaved,

	/// Interface parallel, `[| A |]`. The processes synchronize only on the
	/// events of the alphabet `A`, and every other event interleaves.
	Interface { events: Vec<&'static str> },

	/// Alphabetized parallel, `[| αP | αQ |]`. Each process keeps to its own
	/// alphabet, and the processes synchronize on the intersection.
	Alphabetized { left: Vec<&'static str>, right: Vec<&'static str> },
}

/// A specification of how two or more processes compose into one.
///
/// As with [`ProcessSpec`], the declarative
/// [`tb_compose_spec!`](crate::tb_compose_spec) macro implements it, and a
/// manual implementation is also valid.
pub trait CompositionSpec {
	/// Returns the composed process.
	fn process() -> Process;

	/// Returns the metadata of the composition.
	fn metadata() -> CompositionMetadata {
		CompositionMetadata::default()
	}

	/// Checks the properties that the composition claims, such as deadlock
	/// freedom, livelock freedom, and determinism. The default returns `Ok`.
	fn verify_properties() -> Result<(), CompositionError> {
		Ok(())
	}
}

/// Every [`CompositionSpec`] is a [`ProcessSpec`].
///
/// A composed process serves `tb_scenario!` and every other testing macro
/// that takes a process spec.
///
/// A composition spec is usually a zero-sized struct that `tb_compose_spec!`
/// generates. [`CompositionSpec::process`] builds the process on each call, so
/// `to_process_cow` returns `Cow::Owned`. A test calls it once.
impl<T: CompositionSpec> ProcessSpec for T {
	fn validate_trace(&self, trace: &ConsumedTrace) -> CspValidationResult {
		let process = T::process();
		process.validate_trace(trace)
	}

	fn to_process_cow(&self) -> Cow<'_, Process> {
		Cow::Owned(T::process())
	}
}

/// The metadata of a process composition.
#[derive(Debug, Clone)]
pub struct CompositionMetadata {
	/// The name of the composition.
	pub name: &'static str,

	/// The description of the composition, when the spec states one.
	pub description: Option<&'static str>,

	/// The names of the component processes.
	pub component_processes: Vec<&'static str>,

	/// The synchronization alphabet, which holds the events that must
	/// synchronize.
	pub sync_alphabet: HashSet<Event>,

	/// The properties that the spec expects of the composition.
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

/// The properties that a spec expects of a composition. The
/// `verify_properties` of [`tb_compose_spec!`](crate::tb_compose_spec) checks
/// each property that reads `Some(true)`, and `None` leaves it unchecked.
#[derive(Debug, Clone, Default)]
pub struct CompositionProperties {
	/// Whether the spec expects the composition to be deadlock-free.
	pub deadlock_free: Option<bool>,

	/// Whether the spec expects the composition to be livelock-free.
	pub livelock_free: Option<bool>,

	/// Whether the spec expects the composition to be deterministic.
	pub deterministic: Option<bool>,
}

/// The errors of a process composition and of its property checks.
#[derive(Errorizable, Debug, Clone)]
pub enum CompositionError {
	/// An alphabet differs from the alphabet that the composition expects.
	#[error("Alphabet mismatch: expected {expected:?}, got {actual:?}")]
	AlphabetMismatch { expected: HashSet<Event>, actual: HashSet<Event> },

	/// The process deadlocks at `state`.
	#[error("Deadlock detected at state {state}")]
	DeadlockDetected { state: State },

	/// The process livelocks in `cycle`, a τ cycle that can repeat forever.
	#[error("Livelock detected in cycle: {cycle:?}")]
	LivelockDetected { cycle: Vec<State> },

	/// The process is nondeterministic at `state` on `events`.
	#[error("Non-determinism at state {state}: events {events:?}")]
	NonDeterminismDetected { state: State, events: Vec<Event> },

	/// The structure of the composition is invalid for the stated `reason`.
	#[error("Invalid composition: {reason}")]
	InvalidComposition { reason: String },

	/// The operands state timing that does not agree for one event: two
	/// timing constraints, or two schedulability periods.
	#[error("the operands state timing for the event {event} that does not agree")]
	ConflictingTiming {
		/// The event whose timing the operands state twice.
		event: Event,
	},

	/// The operands name different schedulers for schedulability analysis.
	#[error("the operands name different schedulers")]
	ConflictingScheduler,

	/// The process builder refuses the composed process.
	#[error("Process construction failed: {0}")]
	#[from]
	ProcessConstructionFailed(ProcessBuildError),
}

/// The syntax tree of a CSP process algebra expression.
///
/// [`ProcessExpr::evaluate`] turns an expression into a concrete [`Process`].
#[derive(Debug, Clone)]
pub enum ProcessExpr {
	/// An atomic process under its name.
	Atomic { name: &'static str, process: Box<Process> },

	/// Synchronized parallel, `P || Q`. The processes synchronize on every
	/// shared event.
	Synchronized { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Interleaved parallel, `P ||| Q`. The processes run independently, and
	/// every event interleaves.
	Interleaved { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Interface parallel, `P [| A |] Q`. The processes synchronize only on
	/// the events of the alphabet `A`.
	InterfaceParallel { left: Box<ProcessExpr>, sync_alphabet: HashSet<Event>, right: Box<ProcessExpr> },

	/// Alphabetized parallel, `P [| αP | αQ |] Q`. Each process keeps to its
	/// alphabet, and the processes synchronize on the intersection.
	AlphabetizedParallel {
		left: Box<ProcessExpr>,
		left_alphabet: HashSet<Event>,
		right_alphabet: HashSet<Event>,
		right: Box<ProcessExpr>,
	},

	/// Sequential composition, `P ; Q`. When `P` terminates, `Q` starts.
	Sequential { first: Box<ProcessExpr>, second: Box<ProcessExpr> },

	/// Hiding, `P \ A`. The events of `A` become hidden, so their transitions
	/// are internal τ transitions.
	Hiding { process: Box<ProcessExpr>, hidden_events: HashSet<Event> },

	/// Renaming, `P [[ old <- new ]]`. Each old event of `mapping` becomes its
	/// new event.
	Renaming { process: Box<ProcessExpr>, mapping: HashMap<Event, Event> },

	/// External choice, `P [] Q`. The environment chooses the process with the
	/// first observable event.
	ExternalChoice { left: Box<ProcessExpr>, right: Box<ProcessExpr> },

	/// Internal choice, `P |~| Q`. The process chooses an operand
	/// nondeterministically.
	InternalChoice { left: Box<ProcessExpr>, right: Box<ProcessExpr> },
}

impl ProcessExpr {
	/// Returns the atomic expression of `process` under `name`.
	pub fn atomic(name: &'static str, process: Process) -> Self {
		Self::Atomic { name, process: Box::new(process) }
	}

	/// Returns the name of the expression in CSP notation, for debug output
	/// and error messages.
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

	/// Evaluates the expression into a concrete [`Process`].
	///
	/// The evaluation recurses through the expression tree, and each node
	/// applies its composition operator to the processes of its operands.
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
				Ok(p.hide(hidden_events.clone()))
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

//! The specifications that compose CSP processes into one concurrent system.
//!
//! It holds the CSP parallel operators and the process algebra operations
//! that build one process from two or more.
//!
//! The operators follow Hoare's CSP theory and Roscoe's refinement checking.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use crate::testing::specs::csp::{Event, Process, ProcessBuildError, ProcessSpec, State};
use crate::Errorizable;

pub mod algebra;
pub mod operators;
pub mod verification;

pub use verification::{DeadlockChecker, DeterminismChecker, LivelockChecker};

/// The parallel operators that compose two CSP processes.
///
/// Each variant names one operator and its symbol in standard CSP notation.
#[derive(Debug, Clone, PartialEq)]
pub enum CompositionOperator {
	/// Synchronized parallel, `||`. An event of both alphabets occurs in both
	/// processes together, and an event of one alphabet interleaves.
	Synchronized,

	/// Interleaved parallel, `|||`. Every event of both processes interleaves.
	Interleaved,

	/// Interface parallel, `[| A |]`. The processes synchronize only on the
	/// events of the alphabet `A`, and every other event interleaves.
	Interface {
		/// The alphabet `A`.
		events: HashSet<Event>,
	},

	/// Alphabetized parallel, `[| αP | αQ |]`. Each process keeps to its own
	/// alphabet, and the processes synchronize on the intersection.
	Alphabetized {
		/// The alphabet `αP` of the left process.
		left: HashSet<Event>,
		/// The alphabet `αQ` of the right process.
		right: HashSet<Event>,
	},
}

/// A specification of how two or more processes compose into one.
///
/// As with [`ProcessSpec`], implement it with the declarative
/// [`tb_compose_spec!`](crate::tb_compose_spec) macro or by hand.
pub trait CompositionSpec {
	/// Returns the composed process.
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of an operand that does not build, or of an operator that refuses them.
	fn process() -> Result<Process, CompositionError>;

	/// Returns the metadata of the composition.
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of an operand that does not build, when the metadata reads the operands.
	fn metadata() -> Result<CompositionMetadata, CompositionError> {
		Ok(CompositionMetadata::default())
	}

	/// Checks the properties that [`Self::metadata`] claims of
	/// [`Self::process`], such as deadlock freedom, livelock freedom, and
	/// determinism, through [`CompositionProperties::verify`].
	///
	/// The `tb_compose_spec!` implementation also checks the claims of each
	/// operand ([`ProcessSpec::verify_claims`]), so a composition used as an
	/// operand keeps its claims checked.
	///
	/// # Errors
	///
	/// - The [`CompositionError`] of a process that does not build.
	/// - The error of [`CompositionProperties::verify`] -- the process breaks a claim.
	fn verify_properties() -> Result<(), CompositionError> {
		let process = Self::process()?;
		Self::metadata()?.properties.verify(&process)
	}
}

/// Every [`CompositionSpec`] is a [`ProcessSpec`].
///
/// A scenario builds the process once through `to_process_cow`, and checks
/// the claims once through `verify_claims`. A composition spec is usually a
/// zero-sized struct from `tb_compose_spec!`, and [`CompositionSpec::process`]
/// builds the process on each call, so `to_process_cow` returns `Cow::Owned`.
impl<T: CompositionSpec> ProcessSpec for T {
	fn to_process_cow(&self) -> Result<Cow<'_, Process>, CompositionError> {
		T::process().map(Cow::Owned)
	}

	fn verify_claims(&self) -> Result<(), CompositionError> {
		T::verify_properties()
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

	/// The synchronization alphabet: the events that must synchronize.
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

/// The properties that a spec expects of a composition, which
/// [`Self::verify`] checks.
#[derive(Debug, Clone, Default)]
pub struct CompositionProperties {
	/// Whether the spec expects the composition to be deadlock-free.
	pub deadlock_free: Option<bool>,

	/// Whether the spec expects the composition to be livelock-free.
	pub livelock_free: Option<bool>,

	/// Whether the spec expects the composition to be deterministic.
	pub deterministic: Option<bool>,
}

impl CompositionProperties {
	/// Checks each claim of these properties against `process`.
	///
	/// - `Some(true)` claims that `process` holds the property.
	/// - `Some(false)` claims that `process` lacks the property.
	/// - `None` makes no claim, and the property stays unchecked.
	///
	/// The claims run in field order, and the first claim that `process`
	/// breaks stops the check.
	///
	/// # Errors
	///
	/// - [`CompositionError::DeadlockDetected`] -- `process` deadlocks against a claim of `Some(true)`.
	/// - [`CompositionError::LivelockDetected`] -- `process` livelocks against a claim of `Some(true)`.
	/// - [`CompositionError::NonDeterminismDetected`] -- `process` branches against a claim of `Some(true)`.
	/// - [`CompositionError::PropertyHolds`] -- `process` holds a property against a claim of `Some(false)`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::composition::{CompositionError, CompositionProperties, CompositionProperty};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let ping = Process::builder("Ping")
	///     .initial_state(State("idle"))
	///     .add_observable(Event("ping"))
	///     .add_transition(State("idle"), Event("ping"), State("done"))
	///     .add_terminal(State("done"))
	///     .build()?;
	///
	/// let claims = CompositionProperties { deadlock_free: Some(false), ..Default::default() };
	/// let refused = claims.verify(&ping);
	///
	/// let deadlock_free = CompositionProperty::DeadlockFree;
	/// assert!(matches!(refused, Err(CompositionError::PropertyHolds { property }) if property == deadlock_free));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn verify(&self, process: &Process) -> Result<(), CompositionError> {
		let claims = [
			(CompositionProperty::DeadlockFree, self.deadlock_free),
			(CompositionProperty::LivelockFree, self.livelock_free),
			(CompositionProperty::Deterministic, self.deterministic),
		];

		for (property, claim) in claims {
			if let Some(claimed) = claim {
				property.verify_claim(claimed, process)?;
			}
		}

		Ok(())
	}
}

/// A property that a composition spec can claim of its process.
///
/// Each property has the checker that decides it:
///
/// - [`DeadlockChecker`] decides [`Self::DeadlockFree`].
/// - [`LivelockChecker`] decides [`Self::LivelockFree`].
/// - [`DeterminismChecker`] decides [`Self::Deterministic`].
///
/// # Examples
///
/// ```
/// use tightbeam::testing::specs::composition::{CompositionError, CompositionProperty};
///
/// let refused = CompositionError::PropertyHolds { property: CompositionProperty::Deterministic };
/// assert_eq!(refused.to_string(), "The composition holds Deterministic, which the spec claims it lacks");
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositionProperty {
	/// Each state that the process reaches enables an action or is terminal.
	DeadlockFree,

	/// Each state that the process reaches is free of divergence.
	LivelockFree,

	/// No state enables a hidden action, and each event of each state leads to
	/// one state at most.
	Deterministic,
}

impl CompositionProperty {
	/// Checks that `process` holds this property.
	///
	/// # Errors
	///
	/// - The witness of the checker of this property -- `process` lacks the property.
	fn check(self, process: &Process) -> Result<(), CompositionError> {
		match self {
			Self::DeadlockFree => DeadlockChecker::check(process).map_err(Into::into),
			Self::LivelockFree => LivelockChecker::check(process).map_err(Into::into),
			Self::Deterministic => DeterminismChecker::check(process).map_err(Into::into),
		}
	}

	/// Checks the claim that `process` holds this property, when `claimed` is
	/// `true`, or that it lacks this property, when `claimed` is `false`.
	///
	/// # Errors
	///
	/// - The witness of the checker -- `claimed` is `true`, and `process` lacks the property.
	/// - [`CompositionError::PropertyHolds`] -- `claimed` is `false`, and `process` holds the property.
	fn verify_claim(self, claimed: bool, process: &Process) -> Result<(), CompositionError> {
		let checked = self.check(process);
		if claimed {
			return checked;
		}

		// The witness of a failed check proves the claim that the process
		// lacks the property.
		match checked {
			Ok(()) => Err(CompositionError::PropertyHolds { property: self }),
			Err(_witness) => Ok(()),
		}
	}
}

/// The errors of a process composition and of its property checks.
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
	/// A declared alphabet holds an event outside the alphabet of its operands.
	#[error("Alphabet mismatch: expected {expected:?}, got {actual:?}")]
	AlphabetMismatch {
		/// The declared alphabet.
		expected: HashSet<Event>,
		/// The alphabet of the operands, which lacks an event of `expected`.
		actual: HashSet<Event>,
	},

	/// The process deadlocks at `state`.
	#[error("Deadlock detected at state {state}")]
	DeadlockDetected { state: State },

	/// The process livelocks in `cycle`, a τ cycle that can repeat forever.
	#[error("Livelock detected in cycle: {cycle:?}")]
	LivelockDetected { cycle: Vec<State> },

	/// The process is nondeterministic at `state` on `events`.
	#[error("Non-determinism at state {state}: events {events:?}")]
	NonDeterminismDetected { state: State, events: Vec<Event> },

	/// The process holds `property`, and the spec claims that it lacks it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::composition::{CompositionError, CompositionProperty};
	///
	/// let refused = CompositionError::PropertyHolds { property: CompositionProperty::LivelockFree };
	/// assert_eq!(refused.to_string(), "The composition holds LivelockFree, which the spec claims it lacks");
	/// ```
	#[error("The composition holds {property:?}, which the spec claims it lacks")]
	PropertyHolds {
		/// The property that the process holds.
		property: CompositionProperty,
	},

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

	/// Parallel composition of `left` and `right` under `operator`, such as
	/// synchronized parallel `P || Q` or interface parallel `P [| A |] Q`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::specs::composition::{CompositionOperator, ProcessExpr};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let ping = Process::builder("Ping")
	///     .initial_state(State("idle"))
	///     .add_observable(Event("ping"))
	///     .add_transition(State("idle"), Event("ping"), State("done"))
	///     .add_terminal(State("done"))
	///     .build()?;
	///
	/// let left = Box::new(ProcessExpr::atomic("P", ping.clone()));
	/// let right = Box::new(ProcessExpr::atomic("Q", ping));
	/// let expression = ProcessExpr::Parallel { operator: CompositionOperator::Interleaved, left, right };
	///
	/// assert_eq!(expression.name(), "(P ||| Q)");
	/// assert_eq!(expression.evaluate()?.name(), "(Ping ||| Ping)");
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	Parallel {
		/// The parallel operator that composes `left` and `right`.
		operator: CompositionOperator,
		/// The left operand, `P`.
		left: Box<ProcessExpr>,
		/// The right operand, `Q`.
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
			Self::Parallel { operator, left, right } => {
				format!("({} {} {})", left.name(), operator.symbol(), right.name())
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
	/// Each node applies its operator to the processes of its operands.
	///
	/// # Errors
	///
	/// - [`CompositionError`] -- the first node whose operator refuses its operands, in evaluation order.
	pub fn evaluate(&self) -> Result<Process, CompositionError> {
		match self {
			Self::Atomic { process, .. } => Ok(Process::clone(process)),

			Self::Parallel { operator, left, right } => {
				let p = left.evaluate()?;
				let q = right.evaluate()?;
				operator.compose(&p, &q)
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

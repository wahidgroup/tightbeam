//! AFL fuzzing guided by a CSP oracle.
//!
//! [`CspOracle`] reads the fuzz input as event choices in a CSP process, so
//! AFL explores protocol states as well as code paths. AFL.rs runs every fuzz
//! target (<https://github.com/rust-fuzz/afl.rs>).
//!
//! # AFL Integration Architecture
//!
//! 1. **`tb_scenario!` with `fuzz: afl`** generates `fn main() { afl::fuzz!(|data: &[u8]| { ... }) }`.
//! 2. **AFL.rs** supplies mutated byte arrays and tracks code coverage.
//! 3. **CspOracle** reads the bytes as event choices, which steers AFL toward valid protocol states.
//! 4. **Coverage feedback**: AFL finds new code paths through its own instrumentation.
//! 5. **IJON integration**: the `testing-fuzz-ijon` feature adds state-aware guidance.
//!
//! # How AFL Discovers Coverage
//!
//! AFL.rs uses compile-time instrumentation (through LLVM) to track:
//! - Basic block transitions (edge coverage)
//! - Hit counts for each edge (frequency analysis)
//! - New execution paths through code
//!
//! # Optional: IJON State-Space Guidance
//!
//! Enable the `testing-fuzz-ijon` feature to guide AFL toward unexplored CSP
//! states:
//!
//! ```bash
//! cargo afl build --bin fuzz_colony --features "full,testing-fuzz,testing-fuzz-ijon"
//! ```
//!
//! With the feature on, each successful CSP step reports to AFL IJON:
//! - `ijon_max(coverage_score)` maximizes state and transition coverage.
//! - `afl::ijon_set!(track_state)` tracks unique states visited.
//!
//! A structure-aware target that drives work through `fuzz_u8` also feeds
//! CSP IJON when `trace.event` steps the oracle live, so AFL favors inputs
//! that reach new protocol states as well as new code.
//!
//! # Verifying AFL Integration
//!
//! ## Unit Tests
//! Run the oracle unit tests:
//! ```bash
//! cargo test --features "std,testing-fuzz,testing-csp" fuzz::tests
//! ```
//!
//! Each key test checks one property:
//! - `oracle_fuzz_from_bytes_reaches_terminal`: the oracle reads bytes as choices up to a terminal state.
//! - `oracle_coverage_increases_during_fuzzing`: the coverage score rises as the run visits states.
//! - `oracle_track_state_differs_between_states`: two states give two different hashes.
//! - `oracle_crash_context_provides_debug_info`: the crash context names the state, trace, and coverage.
//!
//! ## IJON Feature Test
//! Check that the IJON feature compiles and that a fuzz run passes with it:
//! ```bash
//! cargo test --features "std,testing-fuzz,testing-fuzz-ijon,testing-csp" oracle_ijon_feature_enabled
//! ```
//!
//! The IJON calls (`afl::ijon_set!` and `afl::ijon_max`) need the AFL
//! runtime, so they compile only under `--cfg fuzzing` and run only inside
//! `afl::fuzz!()`. A `cargo check` or `cargo test` build compiles the empty
//! report instead, and the unit test checks the oracle's coverage methods.
//!
//! ## AFL Runtime Verification
//! These steps check that AFL receives IJON data at runtime:
//!
//! 1. Build with IJON enabled:
//!    ```bash
//!    RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing \
//!      --features "std,testing-fuzz,testing-fuzz-ijon,testing-csp"
//!    ```
//!
//! 2. Run AFL with verbose output:
//!    ```bash
//!    cargo afl fuzz -i built/fuzz/in -o built/fuzz/out \
//!      target/debug/deps/fuzzing-* -- -V
//!    ```
//!
//! 3. Confirm the IJON symbols and the map activity:
//!    - The binary exports `ijon_set`, `ijon_max`, and `__afl_ijon_*`.
//!    - AFL discovers more unique paths with IJON enabled.
//!
//! 4. Compare a build with IJON against a build without it:
//!    ```bash
//!    # Without IJON (baseline)
//!    RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing \
//!      --features "std,testing-fuzz,testing-csp"
//!    # Run for 60 seconds, note coverage
//!
//!    # With IJON (should find more states)
//!    RUSTFLAGS="--cfg fuzzing" cargo afl build --test fuzzing \
//!      --features "std,testing-fuzz,testing-fuzz-ijon,testing-csp"
//!    # Run for 60 seconds, compare coverage
//!    ```
//!
//! Expect the IJON build to find more unique test cases and to reach higher
//! state coverage in the same time.
//!
//! # Creating Fuzz Targets
//!
//! A scenario names `fuzz: afl` and `csp:`, and the oracle makes the IJON
//! calls itself:
//!
//! ```ignore
//! tb_scenario! {
//!     fuzz: afl,
//!     csp: MyProcess,
//!     spec: MySpec,
//!     environment Bare {
//!         exec: |SetupEnv { trace, .. }| {
//!             // Oracle-guided fuzzing - IJON automatic with feature flag
//!             let oracle = trace.oracle();
//!             oracle.fuzz_from_bytes()?;
//!
//!             // Make assertions based on execution trace
//!             for event in oracle.trace() {
//!                 trace.collector().event(event)?;
//!             }
//!             Ok(())
//!         }
//!     }
//! }
//! ```

#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard};

use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process, State};
use crate::trace::TraceCollector;
use crate::Errorizable;

/// An error of an oracle-guided fuzz run.
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzError {
	/// The non-terminal state that `state` names has no valid event.
	#[error("deadlock: no valid events in non-terminal state {state}")]
	Deadlock { state: State },
	/// The input ran out before a terminal state, and `state` names where the
	/// run stopped.
	#[error("input exhausted before terminal state (stopped in {state})")]
	InputExhausted { state: State },
	/// The oracle rejected `event` in `state` after it listed the event as
	/// valid, which breaks an internal invariant.
	#[error("oracle rejected valid event {event} in state {state}")]
	EventRejected { state: State, event: Event },
}

impl From<FuzzError> for TestingError {
	fn from(error: FuzzError) -> Self {
		match error {
			FuzzError::Deadlock { state } => TestingError::FuzzDeadlock(state.0),
			FuzzError::InputExhausted { .. } => TestingError::FuzzInputExhausted,
			FuzzError::EventRejected { event, .. } => TestingError::FuzzEventRejected(event.0),
		}
	}
}

/// Harness access to the CSP oracle of a guided fuzz run.
///
/// A `tb_scenario!` body needs the oracle itself, so the collector a guided
/// run hands it, [`FuzzTraceCollector`], holds one by construction.
pub trait OracleAccess {
	/// The CSP oracle that this collector holds.
	fn oracle(&self) -> &FuzzContext;
}

/// The trace collector of a guided fuzz run, which holds its CSP oracle.
///
/// `tb_scenario!` builds one for each AFL iteration of a scenario that names
/// `fuzz: afl` and `csp:`:
///
/// - Each scenario closure receives a share of it as its `trace`.
/// - The [`TraceCollector`] it holds steps the oracle live as it records each event.
/// - [`OracleAccess::oracle`] returns that oracle.
/// - [`Self::collector`] lends the [`TraceCollector`] to a harness that takes one, as a named test does.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::fuzz::{FuzzTraceCollector, OracleAccess};
/// use tightbeam::testing::specs::csp::{Event, Process, State};
///
/// let process = Process::builder("Step")
///     .initial_state(State("S0"))
///     .add_observable(Event("step"))
///     .add_transition(State("S0"), Event("step"), State("S1"))
///     .add_terminal(State("S1"))
///     .build()?;
///
/// let trace = FuzzTraceCollector::new([0u8], process);
/// trace.oracle().fuzz_from_bytes()?;
///
/// assert!(trace.oracle().is_terminal());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct FuzzTraceCollector {
	trace: TraceCollector,
	oracle: FuzzContext,
}

impl FuzzTraceCollector {
	/// Builds the collector of one guided iteration, whose oracle reads
	/// `input` as choices in `process`.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fuzz::{FuzzTraceCollector, OracleAccess};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Step")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("step"))
	///     .add_transition(State("S0"), Event("step"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let trace = FuzzTraceCollector::new([7u8], process);
	///
	/// assert_eq!(trace.oracle().fuzz_u8()?, 7);
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn new(input: impl Into<Vec<u8>>, process: Process) -> Self {
		let oracle = FuzzContext::new(input, process);
		let trace = TraceCollector::with_fuzz_context(oracle.clone());
		Self { trace, oracle }
	}

	/// Creates an additional handle that records into the same state and
	/// reads the same oracle.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fuzz::{FuzzTraceCollector, OracleAccess};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Step")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("step"))
	///     .add_transition(State("S0"), Event("step"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let trace = FuzzTraceCollector::new(Vec::new(), process);
	/// trace.share().collector().event(Event("step"))?;
	///
	/// assert_eq!(trace.oracle().current_state(), Some(State("S1")));
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn share(&self) -> Self {
		Self { trace: self.trace.share(), oracle: self.oracle.clone() }
	}

	/// The [`TraceCollector`] this run records into, whose events step the
	/// oracle.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fuzz::{FuzzTraceCollector, OracleAccess};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let process = Process::builder("Step")
	///     .initial_state(State("S0"))
	///     .add_observable(Event("step"))
	///     .add_transition(State("S0"), Event("step"), State("S1"))
	///     .add_terminal(State("S1"))
	///     .build()?;
	///
	/// let trace = FuzzTraceCollector::new(Vec::new(), process);
	/// trace.collector().event(Event("step"))?;
	///
	/// assert!(trace.oracle().is_terminal());
	/// # Ok::<(), Box<dyn std::error::Error>>(())
	/// ```
	pub fn collector(&self) -> &TraceCollector {
		&self.trace
	}
}

impl AsRef<TraceCollector> for FuzzTraceCollector {
	fn as_ref(&self) -> &TraceCollector {
		self.collector()
	}
}

impl OracleAccess for FuzzTraceCollector {
	fn oracle(&self) -> &FuzzContext {
		&self.oracle
	}
}

/// The CSP state oracle of AFL-guided fuzzing.
///
/// The oracle joins AFL's byte-level mutation to CSP protocol semantics:
///
/// ## Core Functionality
/// - **State Machine Tracking**: holds the current state of the CSP process.
/// - **Event Interpretation**: maps each input byte to one of the valid events.
/// - **Coverage Metrics**: records the visited states and transitions.
/// - **Crash Triage**: reports the run's context when a fuzz target fails.
///
/// ## AFL Integration
/// - AFL discovers code coverage through its compile-time instrumentation.
/// - The oracle steers AFL toward valid protocol states, so even random bytes form a valid trace.
/// - [`Self::track_state`] and [`Self::coverage_score`] feed IJON state-space guidance.
///
/// ## Usage Pattern
/// ```ignore
/// // In fuzz target (generated by tb_scenario! fuzz: afl):
/// let trace = FuzzTraceCollector::new(data, process);
/// let oracle = trace.oracle();
/// oracle.fuzz_from_bytes()?;  // Run oracle-guided execution
/// // AFL sees the code paths taken and mutates input accordingly
/// ```
#[derive(Debug, Clone)]
pub struct CspOracle {
	process: Process,
	current_state: State,
	visited_states: HashSet<State>,
	visited_transitions: HashSet<(State, Event)>,
	trace: Vec<Event>,
}

impl CspOracle {
	/// Creates an oracle at the initial state of `process`.
	pub fn new(process: Process) -> Self {
		let initial = process.initial;
		let mut visited_states = HashSet::new();
		visited_states.insert(initial);

		Self {
			process,
			current_state: initial,
			visited_states,
			visited_transitions: HashSet::new(),
			trace: Vec::new(),
		}
	}

	/// The state the last step reached, or the initial state after a reset.
	pub fn current_state(&self) -> State {
		self.current_state
	}

	/// Every state visited since the last reset, the initial state included.
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// Every `(state, event)` pair taken since the last reset.
	pub fn visited_transitions(&self) -> &HashSet<(State, Event)> {
		&self.visited_transitions
	}

	/// The events taken since the last reset, in order.
	pub fn trace(&self) -> &[Event] {
		&self.trace
	}

	/// Whether the current state is a terminal state of the process.
	pub fn is_terminal(&self) -> bool {
		self.process.is_terminal(self.current_state)
	}

	/// The observable events that the current state enables, or an empty list
	/// at a terminal state.
	///
	/// [`Process::enabled`] sorts the list by event label, so the mapping from
	/// a byte to an index in [`Self::fuzz_from_bytes`] picks the same event on
	/// every run. AFL replay and corpus minimization rely on that contract.
	pub fn valid_events(&self) -> Vec<Event> {
		if self.is_terminal() {
			return Vec::new();
		}

		self.process
			.enabled(self.current_state)
			.iter()
			.filter(|a| a.is_observable())
			.map(|a| a.event)
			.collect()
	}

	/// Takes the transition that `event` labels from the current state.
	///
	/// A successful step returns `true` and updates the current state and the
	/// coverage. The return is `false` when the state does not enable `event`.
	///
	/// A nondeterministic transition resolves to its first target by state
	/// name. Use [`Self::step_with_target`] to select among multiple targets.
	pub fn step(&mut self, event: &Event) -> bool {
		self.step_with_target(event, 0)
	}

	/// Takes the transition that `event` labels, and uses `choice` to pick
	/// among nondeterministic targets.
	///
	/// It sorts the targets by state name before it indexes them
	/// (`choice % targets`), so the same choice byte selects the same target
	/// on every run.
	pub fn step_with_target(&mut self, event: &Event, choice: u8) -> bool {
		let mut next_states = self.process.step(self.current_state, event);

		if next_states.is_empty() {
			return false;
		}

		next_states.sort_unstable();

		self.visited_transitions.insert((self.current_state, *event));
		self.trace.push(*event);

		self.current_state = next_states[(choice as usize) % next_states.len()];
		self.visited_states.insert(self.current_state);
		self.report_ijon();

		true
	}

	/// Reports the CSP state and coverage to AFL IJON after a successful step.
	///
	/// - The body needs `testing-fuzz-ijon` and `--cfg fuzzing`, which cargo-afl builds set.
	/// - A plain `cargo test` or `cargo build` compiles an empty body, so the
	///   link step needs no AFL runtime symbol.
	///
	/// The coverage score reaches AFL through the function form of IJON
	/// maximization, at a stable line-hashed location. The AFL IJON entry
	/// points are `unsafe extern "C"`, so this harness-only path waives the
	/// crate-wide `deny(unsafe_code)`.
	#[cfg(all(fuzzing, feature = "testing-fuzz-ijon"))]
	#[allow(unsafe_code)]
	fn report_ijon(&self) {
		// The import is function-scoped, because only this fuzzing-gated body
		// needs `CString`.
		use std::ffi::CString;

		afl::ijon_set!(self.track_state());
		// SAFETY: A single-threaded AFL worker writes `LOC` once, before
		// `ijon_max` reads it. `file!()` has no interior NUL, so `CString::new`
		// succeeds.
		unsafe {
			static mut LOC: u32 = 0;
			if LOC == 0 {
				let Ok(cfile) = CString::new(file!()) else {
					return;
				};

				LOC = afl::ijon_hashstr(line!(), cfile.as_ptr());
			}

			afl::ijon_max(LOC, self.coverage_score());
		}
	}

	#[cfg(not(all(fuzzing, feature = "testing-fuzz-ijon")))]
	fn report_ijon(&self) {}

	/// Returns the oracle to the initial state and clears the coverage and the
	/// trace.
	pub fn reset(&mut self) {
		let initial = self.process.initial;
		self.current_state = initial;
		self.visited_states.clear();
		self.visited_states.insert(initial);
		self.visited_transitions.clear();
		self.trace.clear();
	}

	/// A stable 32-bit hash of the current state, for IJON state tracking.
	///
	/// ## IJON Integration
	/// ```ignore
	/// // Automatic after each successful step when testing-fuzz-ijon is on:
	/// afl::ijon_set!(oracle.track_state());
	/// ```
	///
	/// Through `ijon_set!`, AFL favors inputs that produce an unseen state
	/// hash.
	///
	/// ## When to Use
	/// - The protocol has a large state space.
	/// - Code coverage alone does not tell the states apart.
	/// - The target needs to explore states beyond its code paths.
	///
	/// ## Note
	/// IJON needs `cargo install afl` with IJON support and the `AFL_PRELOAD`
	/// environment variable. Standard AFL.rs runs without them.
	pub fn track_state(&self) -> u32 {
		let mut hasher = DefaultHasher::new();
		self.current_state.hash(&mut hasher);
		hasher.finish() as u32
	}

	/// The coverage score that IJON maximizes.
	///
	/// The 64-bit score combines state and transition coverage:
	/// - **Upper 32 bits**: the number of unique states visited.
	/// - **Lower 32 bits**: the number of unique transitions taken.
	///
	/// ## IJON Integration
	/// ```ignore
	/// // Automatic after each successful step when testing-fuzz-ijon is on:
	/// afl::ijon_max(loc, oracle.coverage_score());
	/// ```
	///
	/// Through `ijon_max`, AFL favors inputs that raise the score: inputs that
	/// reach new states or transitions.
	///
	/// ## When to Use
	/// - AFL needs to optimize for CSP coverage directly.
	/// - The protocol state machine has many paths.
	/// - Code coverage does not capture the semantic coverage.
	///
	/// ## Note
	/// IJON needs `cargo install afl` with IJON support. Standard AFL.rs
	/// discovers coverage through code instrumentation.
	pub fn coverage_score(&self) -> u64 {
		((self.visited_states.len() as u64) << 32) | (self.visited_transitions.len() as u64)
	}

	/// The percentage of the process states visited, or 0 for a process with
	/// no state.
	pub fn state_coverage(&self) -> f64 {
		let total_states = self.process.states.len();
		if total_states == 0 {
			return 0.0;
		}

		(self.visited_states.len() as f64) / (total_states as f64) * 100.0
	}

	/// The transition coverage as `(visited, total)`, where `total` counts each
	/// state and event pair that has a target.
	pub fn transition_coverage(&self) -> (usize, usize) {
		let mut total_transitions = 0;
		for state in &self.process.states {
			for event in self.process.observable.iter().chain(&self.process.hidden) {
				if !self.process.step(*state, event).is_empty() {
					total_transitions += 1;
				}
			}
		}

		(self.visited_transitions.len(), total_transitions)
	}

	/// Formats the run's context for triage of a failed fuzz run.
	///
	/// The text holds:
	/// - The current state, where execution stopped.
	/// - The event trace, in the order the run took the events.
	/// - The coverage statistics of the states and transitions explored.
	/// - The valid events, which are the choices open at the crash point.
	pub fn crash_context(&self) -> String {
		let (visited_trans, total_trans) = self.transition_coverage();
		format!(
			"AFL Crash Context:\n\
             Current State: {:?}\n\
             Terminal: {}\n\
             Trace: {:?}\n\
             State Coverage: {:.1}% ({}/{})\n\
             Transition Coverage: {:.1}% ({}/{})\n\
             Valid Events: {:?}",
			self.current_state,
			self.is_terminal(),
			self.trace,
			self.state_coverage(),
			self.visited_states.len(),
			self.process.states.len(),
			if total_trans > 0 {
				(visited_trans as f64 / total_trans as f64) * 100.0
			} else {
				0.0
			},
			visited_trans,
			total_trans,
			self.valid_events()
		)
	}

	/// Runs the oracle over `input`, which holds the event choices.
	///
	/// AFL drives the oracle through it, and each byte chooses the event at the
	/// current state of the CSP process.
	///
	/// ## How It Works
	/// 1. Reset the oracle to the initial state.
	/// 2. For each input byte:
	///    - Get the valid events at the current state, sorted for deterministic replay.
	///    - Choose the event with the byte value: `choice = byte % valid_events.len()`.
	///    - When the chosen event has multiple target states, consume one more
	///      byte to choose the target: `target = byte % targets.len()`.
	///    - Take the transition with the chosen event and target.
	///    - Update the state and the coverage.
	///    - Report to IJON when the `testing-fuzz-ijon` feature is on.
	/// 3. Return `Ok(())` when the run reaches a terminal state, and an error otherwise.
	///
	/// ## AFL Coverage Discovery
	/// AFL observes:
	/// - Which code paths the run takes (edge coverage)
	/// - How many valid events each state had
	/// - Whether execution reached a terminal state
	/// - Every panic or crash during execution
	///
	/// ## IJON Integration (Automatic)
	/// When built with `--features testing-fuzz-ijon` and `--cfg fuzzing`
	/// (cargo-afl), each successful step reports CSP exploration through
	/// `afl::ijon_set!(track_state)` and `afl::ijon_max(coverage_score)`.
	///
	/// ## Returns
	/// - `Ok(())`: execution reached a terminal state.
	/// - [`FuzzError::Deadlock`]: a non-terminal state has no valid event.
	/// - [`FuzzError::EventRejected`]: the oracle refused an event it listed as valid, an internal fault.
	/// - [`FuzzError::InputExhausted`]: the input ran out before a terminal state.
	///
	/// ## Crash Triage
	/// When a fuzz run fails, check:
	/// - [`Self::current_state`]: where execution stopped.
	/// - [`Self::trace`]: the events taken, in order.
	/// - [`Self::visited_states`]: the states explored.
	pub fn fuzz_from_bytes(&mut self, input: impl AsRef<[u8]>) -> Result<(), FuzzError> {
		let input = input.as_ref();
		self.reset();

		let mut byte_idx = 0;
		while !self.is_terminal() && byte_idx < input.len() {
			let valid = self.valid_events();
			if valid.is_empty() {
				return Err(FuzzError::Deadlock { state: self.current_state });
			}

			let choice = (input[byte_idx] as usize) % valid.len();
			let event = valid[choice];

			byte_idx += 1;

			// Nondeterministic transitions consume one more byte so every
			// target state stays reachable under AFL mutation.
			let target_count = self.process.step(self.current_state, &event).len();
			let target_choice = if target_count > 1 {
				let Some(byte) = input.get(byte_idx) else {
					return Err(FuzzError::InputExhausted { state: self.current_state });
				};

				byte_idx += 1;

				*byte
			} else {
				0
			};

			if !self.step_with_target(&event, target_choice) {
				return Err(FuzzError::EventRejected { state: self.current_state, event });
			}
		}

		if self.is_terminal() {
			Ok(())
		} else {
			Err(FuzzError::InputExhausted { state: self.current_state })
		}
	}
}

/// The shared fuzz state of a `tb_scenario!` run: the input, its cursor, and
/// the CSP oracle.
///
/// The context gives test scenarios shared access to [`CspOracle`].
/// [`FuzzTraceCollector::new`] creates one and holds it, and
/// [`OracleAccess::oracle`] returns it.
///
/// ## Architecture
/// - **TraceCollector** records the events that the test assertions read.
/// - **FuzzContext** wraps `CspOracle` in a mutex for thread-safe access.
/// - **CspOracle** runs the CSP-guided fuzzing.
///
/// ## Usage
/// ```ignore
/// tb_scenario! {
///     fuzz: afl,
///     csp: MyProcess,
///     spec: MySpec,
///     environment Bare {
///         exec: |SetupEnv { trace, .. }| {
///             // FuzzContext provides oracle access
///             let oracle = trace.oracle();
///             oracle.fuzz_from_bytes()?;
///
///             // Can also query oracle state
///             for event in oracle.trace() {
///                 trace.collector().event(event)?;
///             }
///             Ok(())
///         }
///     }
/// }
/// ```
///
/// ## Advanced: Direct Byte Consumption
/// The byte readers, such as [`Self::fuzz_u8`] and [`Self::fuzz_u16`], serve
/// custom fuzzing logic that needs structured data beyond oracle-guided
/// execution. Most fuzz targets should use [`Self::fuzz_from_bytes`] instead.
#[derive(Debug, Clone)]
pub struct FuzzContext {
	inner: Arc<Mutex<FuzzContextInner>>,
}

#[derive(Debug)]
struct FuzzContextInner {
	input: Vec<u8>,
	cursor: usize,
	oracle: CspOracle,
}

impl FuzzContextInner {
	/// The number of input bytes from the cursor to the end.
	fn remaining(&self) -> usize {
		self.input.len().saturating_sub(self.cursor)
	}

	/// Reads `n` bytes and leaves the cursor in place.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain.
	///   The cursor stays in place, so a caller may read a shorter run instead.
	fn peek(&self, n: usize) -> Result<&[u8], TestingError> {
		if self.remaining() < n {
			return Err(TestingError::FuzzInputExhausted);
		}

		Ok(&self.input[self.cursor..self.cursor + n])
	}

	/// Consumes `n` bytes and advances the cursor past them.
	///
	/// The cursor moves only here, so one check decides exhaustion for every
	/// width a caller reads.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain, and the cursor stays in place.
	fn take(&mut self, n: usize) -> Result<&[u8], TestingError> {
		if self.remaining() < n {
			return Err(TestingError::FuzzInputExhausted);
		}

		let start = self.cursor;
		self.cursor += n;

		Ok(&self.input[start..self.cursor])
	}

	/// Consumes exactly `N` bytes as an array, for the fixed-width readers.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `N` bytes remain.
	fn take_array<const N: usize>(&mut self) -> Result<[u8; N], TestingError> {
		let mut taken = [0u8; N];
		taken.copy_from_slice(self.take(N)?);

		Ok(taken)
	}
}

impl FuzzContext {
	/// Creates a context whose oracle reads `input` as choices in `process`,
	/// with the cursor at the first byte.
	pub fn new(input: impl Into<Vec<u8>>, process: Process) -> Self {
		let input: Vec<u8> = input.into();
		Self {
			inner: Arc::new(Mutex::new(FuzzContextInner {
				input,
				cursor: 0,
				oracle: CspOracle::new(process),
			})),
		}
	}

	/// The guard of the context, or [`TestingError::FuzzInputLockPoisoned`]
	/// when a panic poisoned it.
	fn lock(&self) -> Result<MutexGuard<'_, FuzzContextInner>, TestingError> {
		self.inner.lock().map_err(|_poisoned| TestingError::FuzzInputLockPoisoned)
	}

	/// Runs the oracle over the whole input buffer, whatever the cursor
	/// position, as [`CspOracle::fuzz_from_bytes`] reads it.
	///
	/// The run succeeds when it reaches a terminal state. Each failure maps to
	/// its own [`TestingError`] variant, so a real deadlock never reads as
	/// exhaustion.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzDeadlock`] -- a non-terminal state has no valid event.
	/// - [`TestingError::FuzzEventRejected`] -- the oracle refused an event it listed as valid.
	/// - [`TestingError::FuzzInputExhausted`] -- the input ran out before a terminal state.
	pub fn fuzz_from_bytes(&self) -> Result<(), TestingError> {
		let mut guard = self.lock()?;
		let input = guard.input.clone();

		guard.oracle.fuzz_from_bytes(&input)?;

		Ok(())
	}

	/// The events the oracle took, in order, or an empty list when the lock is
	/// poisoned.
	pub fn trace(&self) -> Vec<Event> {
		self.inner.lock().map(|g| g.oracle.trace().to_vec()).unwrap_or_default()
	}

	/// Whether the current state is terminal. A poisoned lock reads as `false`.
	pub fn is_terminal(&self) -> bool {
		self.inner.lock().map(|g| g.oracle.is_terminal()).unwrap_or(false)
	}

	/// The valid events at the current state, or an empty list when the lock
	/// is poisoned.
	pub fn valid_events(&self) -> Vec<Event> {
		self.inner.lock().map(|g| g.oracle.valid_events()).unwrap_or_default()
	}

	/// The current state, or `None` when the lock is poisoned.
	pub fn current_state(&self) -> Option<State> {
		self.inner.lock().ok().map(|g| g.oracle.current_state())
	}

	/// Formats the oracle's context for triage of a failed fuzz target.
	///
	/// The text is [`CspOracle::crash_context`], or a lock failure message.
	pub fn crash_context(&self) -> String {
		self.inner
			.lock()
			.map(|g| g.oracle.crash_context())
			.unwrap_or_else(|_| "Failed to acquire oracle lock".to_string())
	}

	/// The oracle's combined state and transition coverage score, or 0 when
	/// the lock is poisoned.
	///
	/// The oracle reports the same score to IJON after each successful step
	/// when the `testing-fuzz-ijon` feature is on.
	pub fn coverage_score(&self) -> u64 {
		self.inner.lock().map(|g| g.oracle.coverage_score()).unwrap_or(0)
	}

	/// The stable hash of the current CSP state, or 0 when the lock is
	/// poisoned.
	///
	/// The oracle reports the same hash to IJON after each successful step
	/// when the `testing-fuzz-ijon` feature is on.
	pub fn track_state(&self) -> u32 {
		self.inner.lock().map(|g| g.oracle.track_state()).unwrap_or(0)
	}

	/// Steps the oracle with `event` outside a byte-driven run.
	///
	/// The return is `Ok(true)` when the transition succeeds, and `Ok(false)`
	/// when the current state does not enable `event`.
	///
	/// ## Usage
	/// ```ignore
	/// // Manually step CSP state machine with a process-alphabet event
	/// oracle.step_event(&Event::from(events::ACTION_RUN))?;
	/// ```
	///
	/// A successful step reports the CSP state to IJON in a cargo-afl build
	/// (`--cfg fuzzing`) with `testing-fuzz-ijon` on. An ordinary `cargo test`
	/// build skips the report.
	///
	/// ## Errors
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	pub fn step_event(&self, event: &Event) -> Result<bool, TestingError> {
		let mut guard = self.lock()?;
		Ok(guard.oracle.step(event))
	}

	/// Consumes one byte of the fuzz input.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- no input byte remains.
	pub fn fuzz_u8(&self) -> Result<u8, TestingError> {
		let mut guard = self.lock()?;
		Ok(u8::from_be_bytes(guard.take_array()?))
	}

	/// Consumes two bytes of the fuzz input as a big-endian `u16`.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than two bytes remain.
	pub fn fuzz_u16(&self) -> Result<u16, TestingError> {
		let mut guard = self.lock()?;
		Ok(u16::from_be_bytes(guard.take_array()?))
	}

	/// Consumes four bytes of the fuzz input as a big-endian `u32`.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than four bytes remain.
	pub fn fuzz_u32(&self) -> Result<u32, TestingError> {
		let mut guard = self.lock()?;
		Ok(u32::from_be_bytes(guard.take_array()?))
	}

	/// Consumes eight bytes of the fuzz input as a big-endian `u64`.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than eight bytes remain.
	pub fn fuzz_u64(&self) -> Result<u64, TestingError> {
		let mut guard = self.lock()?;
		Ok(u64::from_be_bytes(guard.take_array()?))
	}

	/// Consumes `n` bytes of the fuzz input.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain.
	pub fn fuzz_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let mut guard = self.lock()?;
		Ok(guard.take(n)?.to_vec())
	}

	/// A copy of the whole fuzz input, whatever the cursor position.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	pub fn fuzz_input(&self) -> Result<Vec<u8>, TestingError> {
		let guard = self.lock()?;
		Ok(guard.input.clone())
	}

	/// Whether at least `n` bytes remain past the cursor.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	pub fn fuzz_has_bytes(&self, n: usize) -> Result<bool, TestingError> {
		let guard = self.lock()?;
		Ok(guard.remaining() >= n)
	}

	/// The number of input bytes past the cursor.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	pub fn fuzz_remaining(&self) -> Result<usize, TestingError> {
		let guard = self.lock()?;
		Ok(guard.remaining())
	}

	/// Reads the next byte of the fuzz input and leaves the cursor in place.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- no input byte remains.
	pub fn fuzz_peek_u8(&self) -> Result<u8, TestingError> {
		let guard = self.lock()?;
		Ok(guard.peek(1)?[0])
	}

	/// Reads the next `n` bytes of the fuzz input and leaves the cursor in
	/// place.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputLockPoisoned`] -- the context mutex is poisoned.
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain.
	pub fn fuzz_peek_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let guard = self.lock()?;
		Ok(guard.peek(n)?.to_vec())
	}
}

/// Unit tests of the oracle and the fuzz context, in one module per concern.
#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::fixtures::TestProcess;
	use crate::testing::TestResult;
	use crate::urn::Urn;

	/// The text of the crash context of the process of [`one_step`] once it
	/// took `go`.
	const CRASH_AFTER_GO: &str = "AFL Crash Context:\n\
		Current State: State(\"S1\")\n\
		Terminal: true\n\
		Trace: [Event(\"go\")]\n\
		State Coverage: 100.0% (2/2)\n\
		Transition Coverage: 100.0% (1/1)\n\
		Valid Events: []";

	// The fixtures below build small CSP processes for the tests.

	/// The one-step process in which `event` moves `S0` to the terminal `S1`.
	fn one_step(event: &'static str) -> Process {
		TestProcess::chain("TestProc", &["S0", "S1"], &[event])
	}

	/// The two-step process in which `first` moves `S0` to `S1` and `second`
	/// moves `S1` to the terminal `S2`.
	fn two_steps(first: &'static str, second: &'static str) -> Process {
		TestProcess::chain("TestProc", &["S0", "S1", "S2"], &[first, second])
	}

	/// The three-step process in which `a`, `b`, and `c` move `S0` through
	/// `S1` and `S2` to the terminal `S3`.
	fn three_steps() -> Process {
		TestProcess::chain("TestProc", &["S0", "S1", "S2", "S3"], &["a", "b", "c"])
	}

	/// The choice process in which `choice` moves `S0` to `S1` or `S2`, both
	/// terminal.
	fn choice() -> Process {
		TestProcess::choosing("TestProc", "S0", "choice", &["S1", "S2"])
	}

	/// The branching process in which `a`, `b`, and `c` move `S0` to `S1`,
	/// `S2`, and `S3`, all terminal.
	fn branching() -> Process {
		TestProcess {
			observable: &["a", "b", "c"],
			transitions: &[("S0", "a", "S1"), ("S0", "b", "S2"), ("S0", "c", "S3")],
			terminal: &["S1", "S2", "S3"],
			..TestProcess::of("TestProc", "S0")
		}
		.build()
	}

	/// The process in which `go` moves `S0` to `Stuck`, which is not terminal
	/// and enables no event.
	fn stuck() -> Process {
		TestProcess {
			observable: &["go"],
			transitions: &[("S0", "go", "Stuck")],
			..TestProcess::of("TestProc", "S0")
		}
		.build()
	}

	/// The oracle of `process` once it took each of `steps` in turn.
	fn stepped(process: Process, steps: &[&'static str]) -> CspOracle {
		let mut oracle = CspOracle::new(process);
		for &event in steps {
			let taken = oracle.step(&Event(event));
			taken.then_some(()).expect("each step of a test run is enabled");
		}

		oracle
	}

	/// The distinct traces of `count` fresh oracles of [`branching`], each
	/// run over `input`.
	fn traces_of_fresh_oracles(count: usize, input: &[u8]) -> HashSet<Vec<Event>> {
		let runs = (0..count).map(|_| {
			let mut oracle = CspOracle::new(branching());
			oracle.fuzz_from_bytes(input).expect("the branching process ends in one step");
			oracle.trace().to_vec()
		});

		runs.collect()
	}

	/// The coverage score, the state hash, the terminal flag, and the current
	/// state that a reader of a context sees.
	type Reading = (u64, u32, bool, Option<State>);

	/// What one reader of `context` sees.
	fn reading_of(context: &FuzzContext) -> Reading {
		(
			context.coverage_score(),
			context.track_state(),
			context.is_terminal(),
			context.current_state(),
		)
	}

	/// What each of `threads` threads reads from `context` at once.
	fn read_from_threads(context: &Arc<FuzzContext>, threads: usize) -> Vec<Reading> {
		let spawned = (0..threads).map(|_| {
			let context = Arc::clone(context);
			std::thread::spawn(move || reading_of(&context))
		});

		let handles: Vec<_> = spawned.collect();
		let joined = handles.into_iter().map(|handle| handle.join().expect("a reading thread ends"));
		joined.collect()
	}

	// These tests cover the IJON feature, URN labels, and timed transitions.

	/// An IJON build runs a byte-driven fuzz run as a plain build runs it.
	///
	/// `report_ijon` is `cfg(fuzzing)`, so `cargo test` runs the empty arm, and
	/// a cargo-afl build compiles the real IJON calls.
	#[cfg(feature = "testing-fuzz-ijon")]
	#[test]
	fn an_ijon_build_fuzzes_as_a_plain_build() {
		let mut oracle = CspOracle::new(one_step("go"));

		let fuzzed = oracle.fuzz_from_bytes([0]);
		let visited = (oracle.visited_states().len(), oracle.visited_transitions().len());
		assert_eq!((fuzzed, visited, oracle.coverage_score()), (Ok(()), (2, 1), (2 << 32) | 1));
	}

	/// A step takes an event that the full URN of a transition label names.
	#[test]
	fn a_step_takes_an_event_named_by_its_full_urn() -> TestResult {
		const GO: Urn<'static> = crate::urn!("fuzz", "event:test/go");
		let go = Event::from(GO);

		let context = FuzzContext::new(Vec::new(), one_step(go.0));
		let stepped = context.step_event(&go)?;
		assert_eq!((stepped, context.current_state()), (true, Some(State("S1"))));
		Ok(())
	}

	/// A timed transition counts toward the transitions a run can cover.
	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_timed_transition_counts_toward_transition_coverage() -> TestResult {
		let process = Process::builder("Timed")
			.initial_state(State("S0"))
			.add_observable(Event("arm"))
			.add_timed_transition(State("S0"), Event("arm"), State("S1"), None, Vec::new())
			.add_terminal(State("S1"))
			.build()?;

		let oracle = CspOracle::new(process);
		assert_eq!(oracle.transition_coverage(), (0, 1));
		Ok(())
	}

	/// The core oracle tests: steps, refusals, reset, and choice points.
	mod oracle_core {
		use super::*;

		/// A new oracle stands at the initial state, which offers the first
		/// event alone.
		#[test]
		fn a_new_oracle_stands_at_its_initial_state() {
			let oracle = CspOracle::new(two_steps("go", "stop"));
			let standing = (oracle.current_state(), oracle.visited_states().len(), oracle.is_terminal());
			assert_eq!((standing, oracle.valid_events()), ((State("S0"), 1, false), vec![Event("go")]));
		}

		/// A valid step moves the oracle and records the state, the transition,
		/// and the event it took.
		#[test]
		fn a_valid_step_moves_the_oracle_and_records_the_transition() {
			let mut oracle = CspOracle::new(two_steps("go", "stop"));

			let taken = oracle.step(&Event("go"));
			let visited = (oracle.visited_states().len(), oracle.visited_transitions().len());
			assert_eq!((taken, oracle.current_state(), visited), (true, State("S1"), (2, 1)));
			assert_eq!(oracle.trace(), [Event("go")]);
		}

		/// The last step reaches a terminal state, which offers no event.
		#[test]
		fn the_last_step_reaches_a_terminal_state_that_offers_no_event() {
			let mut oracle = stepped(two_steps("go", "stop"), &["go"]);

			let taken = oracle.step(&Event("stop"));

			let ended = (oracle.current_state(), oracle.is_terminal(), oracle.valid_events());
			assert_eq!((taken, ended), (true, (State("S2"), true, Vec::new())));
		}

		/// An event that the current state does not enable leaves the oracle
		/// where it stands.
		#[test]
		fn an_event_the_state_does_not_enable_leaves_the_oracle_in_place() {
			let mut oracle = CspOracle::new(one_step("valid"));

			let taken = oracle.step(&Event("invalid"));
			let standing = (oracle.current_state(), oracle.visited_transitions().len());
			assert_eq!((taken, standing), (false, (State("S0"), 0)));
		}

		/// A reset returns the oracle to its initial state and clears what the
		/// run recorded.
		#[test]
		fn a_reset_returns_the_oracle_to_its_initial_state() {
			let mut oracle = stepped(one_step("go"), &["go"]);
			oracle.reset();

			let visited = (oracle.visited_states().len(), oracle.visited_transitions().len());
			let standing = (oracle.current_state(), oracle.trace().len());
			assert_eq!((standing, visited), ((State("S0"), 0), (1, 0)));
		}

		/// A choice point offers its event once, and the event steps to the
		/// first target.
		#[test]
		fn a_choice_point_offers_its_event_once_and_steps_to_the_first_target() {
			let mut oracle = CspOracle::new(choice());
			let offered = oracle.valid_events();

			let taken = oracle.step(&Event("choice"));
			let moved = (taken, oracle.current_state());
			assert_eq!((offered, moved), (vec![Event("choice")], (true, State("S1"))));
		}
	}

	/// The tests of the coverage metrics and the state hash.
	mod coverage {
		use super::*;

		// The state coverage is the share of the three states of the process
		// that its steps visited.
		crate::tb_cases! {
			fn the_state_coverage_after((steps, coverage): (&[&'static str], f64)) {
				let oracle = stepped(two_steps("a", "b"), steps);
				let measured = oracle.state_coverage();
				assert!((measured - coverage).abs() < 0.1);
			}

			cases {
				no_step => (&[], 33.33),
				one_step => (&["a"], 66.66),
				both_steps => (&["a", "b"], 100.0),
			}
		}

		/// Both steps of the process cover both of its transitions.
		#[test]
		fn both_steps_cover_both_transitions() {
			let oracle = stepped(two_steps("a", "b"), &["a", "b"]);
			let covered = oracle.transition_coverage();
			assert_eq!(covered, (2, 2));
		}

		/// Two oracles of one process hash their initial states alike.
		#[test]
		fn two_oracles_of_one_process_hash_their_state_alike() {
			let process = one_step("go");
			let first = CspOracle::new(process.clone());
			let second = CspOracle::new(process);

			let hashes = (first.track_state(), second.track_state());
			assert_eq!(hashes.0, hashes.1);
		}

		/// A step raises the coverage score by one state in the upper half and
		/// one transition in the lower half.
		#[test]
		fn a_step_raises_the_coverage_score() {
			let mut oracle = CspOracle::new(one_step("go"));
			let before = oracle.coverage_score();

			let taken = oracle.step(&Event("go"));
			assert_eq!((taken, before, oracle.coverage_score()), (true, 1 << 32, (2 << 32) | 1));
		}
	}

	/// The tests of byte-driven fuzzing.
	mod fuzzing {
		use super::*;

		/// A process, the bytes of a run of it, and the state and the trace
		/// that the run ends with.
		type Reach = (fn() -> Process, &'static [u8], State, &'static [Event]);

		// A run over enough bytes ends at the terminal state that the bytes
		// choose, after the events it took. A choice takes one byte for its
		// event and one byte for its target.
		crate::tb_cases! {
			fn a_run_reaches((process, input, state, trace): Reach) {
				let mut oracle = CspOracle::new(process());

				let fuzzed = oracle.fuzz_from_bytes(input);
				let ended = (oracle.current_state(), oracle.is_terminal(), oracle.trace());
				assert_eq!((fuzzed, ended), (Ok(()), (state, true, trace)));
			}

			cases {
				the_terminal_state_of_one_step => (|| one_step("go"), &[0], State("S1"), &[Event("go")]),
				the_terminal_state_of_two_steps => (
					|| two_steps("a", "b"),
					&[0, 0],
					State("S2"),
					&[Event("a"), Event("b")],
				),
				the_first_target_of_a_choice => (choice, &[0, 0], State("S1"), &[Event("choice")]),
				the_second_target_of_a_choice => (choice, &[0, 1], State("S2"), &[Event("choice")]),
			}
		}

		// A run that stops short of a terminal state fails with the state it
		// stopped in.
		crate::tb_cases! {
			fn a_run_that_stops_short_fails_with((process, input, failure): (fn() -> Process, &[u8], FuzzError)) {
				let mut oracle = CspOracle::new(process());
				let fuzzed = oracle.fuzz_from_bytes(input);
				assert_eq!(fuzzed, Err(failure));
			}

			cases {
				an_exhausted_input => (|| two_steps("a", "b"), &[0], FuzzError::InputExhausted { state: State("S1") }),
				a_deadlock => (stuck, &[0, 0], FuzzError::Deadlock { state: State("Stuck") }),
			}
		}

		/// Every fresh oracle maps one byte to one trace.
		#[test]
		fn every_oracle_maps_a_byte_to_one_trace() {
			let traces = traces_of_fresh_oracles(8, &[1]);
			assert_eq!(traces, HashSet::from([vec![Event("b")]]));
		}

		/// A run raises the coverage score by the states and the transitions
		/// it took.
		#[test]
		fn a_run_raises_the_coverage_score() {
			let mut oracle = CspOracle::new(two_steps("a", "b"));
			let before = oracle.coverage_score();

			let fuzzed = oracle.fuzz_from_bytes([0, 0]);
			let visited = (oracle.visited_states().len(), oracle.visited_transitions().len());
			assert_eq!((fuzzed, before, oracle.coverage_score()), (Ok(()), 1 << 32, (3 << 32) | 2));
			assert_eq!(visited, (3, 2));
		}

		/// Two states of one process hash apart.
		#[test]
		fn two_states_hash_apart() {
			let mut oracle = CspOracle::new(one_step("go"));
			let at_s0 = oracle.track_state();

			let taken = oracle.step(&Event("go"));
			assert!(taken);
			assert_ne!(at_s0, oracle.track_state());
		}

		/// The crash context names the state, the terminal flag, the trace,
		/// the coverage, and the open events of the oracle.
		#[test]
		fn the_crash_context_reports_where_the_run_stands() {
			let oracle = stepped(one_step("go"), &["go"]);
			let context = oracle.crash_context();
			assert_eq!(context, CRASH_AFTER_GO);
		}
	}

	/// The tests of the `FuzzContext` wrapper.
	mod context {
		use super::*;

		/// A context runs its oracle over its input.
		#[test]
		fn a_context_runs_its_oracle_over_its_input() -> TestResult {
			let context = FuzzContext::new(vec![0], one_step("go"));
			context.fuzz_from_bytes()?;

			assert_eq!((context.is_terminal(), context.trace()), (true, vec![Event("go")]));
			Ok(())
		}

		/// A run of a context raises its coverage score and moves its state
		/// hash.
		#[test]
		fn a_context_run_raises_the_score_and_moves_the_state_hash() -> TestResult {
			let context = FuzzContext::new(vec![0, 0], two_steps("a", "b"));
			let (score, hash) = (context.coverage_score(), context.track_state());

			context.fuzz_from_bytes()?;

			assert_eq!((score, context.coverage_score()), (1 << 32, (3 << 32) | 2));
			assert_ne!(hash, context.track_state());
			Ok(())
		}

		/// A context reports the crash context of its oracle.
		#[test]
		fn a_context_reports_the_crash_context_of_its_oracle() -> TestResult {
			let context = FuzzContext::new(vec![0], one_step("go"));
			context.fuzz_from_bytes()?;
			assert_eq!(context.crash_context(), CRASH_AFTER_GO);
			Ok(())
		}

		/// A clone of a context shares its oracle, so a run of one moves the
		/// other.
		#[test]
		fn a_clone_of_a_context_shares_its_oracle() -> TestResult {
			let context = FuzzContext::new(vec![0], one_step("go"));
			let clone = context.clone();

			context.fuzz_from_bytes()?;

			assert_eq!(clone.current_state(), Some(State("S1")));
			Ok(())
		}
	}

	/// The tests of byte selection, reset between runs, and concurrent
	/// access.
	mod advanced {
		use super::*;

		// A byte picks the event at `byte % 3` among the three that `S0`
		// enables, in the name order `a`, `b`, `c`.
		crate::tb_cases! {
			fn oracle_input_modulo_selection((input_byte, expected): (u8, State)) {
				let mut oracle = CspOracle::new(branching());
				let stepped = oracle.fuzz_from_bytes([input_byte]);
				assert_eq!((stepped, oracle.current_state()), (Ok(()), expected));
			}

			cases {
				first_event => (0, State("S1")),
				second_event => (1, State("S2")),
				third_event => (2, State("S3")),
				wraps_to_the_first_event => (3, State("S1")),
				wraps_from_the_top_byte => (255, State("S1")),
			}
		}

		/// A second run starts from the initial state, so it ends where the
		/// first run ended, with the trace of its own events alone.
		#[test]
		fn a_second_run_starts_from_the_initial_state() {
			let mut oracle = CspOracle::new(one_step("go"));

			let first = oracle.fuzz_from_bytes([0]);
			let second = oracle.fuzz_from_bytes([0]);
			assert_eq!((first, second, oracle.current_state()), (Ok(()), Ok(()), State("S1")));
			assert_eq!(oracle.trace(), [Event("go")]);
		}

		/// A run through every state of a chain covers every state and every
		/// transition.
		#[test]
		fn a_run_through_every_state_covers_them_all() {
			let mut oracle = CspOracle::new(three_steps());

			let fuzzed = oracle.fuzz_from_bytes([0, 0, 0]);
			let visited = (oracle.visited_states().len(), oracle.visited_transitions().len());
			assert_eq!((fuzzed, visited, oracle.state_coverage()), (Ok(()), (4, 3), 100.0));
		}

		/// Threads that share one context read what one thread reads alone.
		#[test]
		fn threads_that_share_a_context_read_what_one_thread_reads() {
			let context = Arc::new(FuzzContext::new(vec![0], one_step("go")));

			let readings = read_from_threads(&context, 4);
			let alone = (1 << 32, context.track_state(), false, Some(State("S0")));
			assert_eq!(readings, vec![alone; 4]);
		}
	}

	/// An event the guided collector records steps the oracle that
	/// `oracle` returns.
	#[test]
	fn a_guided_collector_steps_the_oracle_it_holds() -> TestResult {
		let trace = FuzzTraceCollector::new(Vec::new(), one_step("go"));
		trace.collector().event(Event("go"))?;
		assert_eq!(trace.oracle().current_state(), Some(State("S1")));
		Ok(())
	}

	/// An event a share records steps the oracle of the collector it shares.
	#[test]
	fn a_share_of_a_guided_collector_steps_the_same_oracle() -> TestResult {
		let trace = FuzzTraceCollector::new(Vec::new(), one_step("go"));
		let share = trace.share();
		share.collector().event(Event("go"))?;
		assert_eq!(trace.oracle().current_state(), Some(State("S1")));
		Ok(())
	}
}

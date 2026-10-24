//! AFL fuzzing guided by a CSP oracle.
//!
//! `CspOracle` reads the fuzz input as event choices in a CSP process, so AFL
//! explores protocol states as well as code paths. AFL.rs runs every fuzz
//! target (<https://github.com/rust-fuzz/afl.rs>).
//!
//! # AFL Integration Architecture
//!
//! 1. **tb_scenario! with fuzz: afl** generates `fn main() { afl::fuzz!(|data: &[u8]| { ... }) }`.
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
//! The key tests, and what each one checks:
//! - `oracle_fuzz_from_bytes_reaches_terminal`: the oracle reads bytes as choices up to a terminal state.
//! - `oracle_coverage_increases_during_fuzzing`: the coverage score rises as the run visits states.
//! - `oracle_track_state_differs_between_states`: two states give two different hashes.
//! - `oracle_crash_context_provides_debug_info`: the crash context names the state, trace, and coverage.
//!
//! ## IJON Feature Test
//! Check that the IJON feature compiles and that fuzzing still works:
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
//! To check that AFL receives IJON data at runtime:
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
use std::sync::{Arc, Mutex};

use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process, State};
use crate::trace::TraceCollector;
use crate::Errorizable;

/// Error of an oracle-guided fuzz run.
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
/// A `tb_scenario!` body wants the oracle itself, so the collector a guided
/// run hands it, [`FuzzTraceCollector`], holds one by construction.
pub trait OracleAccess {
	/// The CSP oracle this collector was built with.
	fn oracle(&self) -> &FuzzContext;
}

/// The trace collector of a guided fuzz run, which holds its CSP oracle.
///
/// `tb_scenario!` builds one for each AFL iteration of a scenario that names
/// `fuzz: afl` and `csp:`:
///
/// - Each scenario closure receives a share of it as its `trace`.
/// - The [`TraceCollector`] it holds steps the oracle live as each event is recorded.
/// - [`OracleAccess::oracle`] returns that oracle.
/// - [`Self::collector`] lends the [`TraceCollector`] that a harness passes as a named test does.
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

/// CSP state oracle for AFL-guided fuzzing.
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
/// - The oracle steers AFL toward valid protocol states, so random bytes still form a valid trace.
/// - `track_state` and `coverage_score` feed IJON state-space guidance.
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

	/// The observable events that the current state enables.
	///
	/// A terminal state yields an empty list.
	///
	/// The list is sorted by event label (through `Process::enabled`), so the
	/// mapping from a byte to an index in [`Self::fuzz_from_bytes`] picks the
	/// same event on every run. AFL replay and corpus minimization rely on
	/// that contract.
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
	/// Targets are sorted by state name before indexing (`choice % targets`),
	/// so the same choice byte selects the same target on every run.
	pub fn step_with_target(&mut self, event: &Event, choice: u8) -> bool {
		let mut next_states = self.process.step(self.current_state, event);

		if next_states.is_empty() {
			return false;
		}

		next_states.sort_unstable();

		// Record transition
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
	/// Coverage reports through the function form of IJON maximization with
	/// a stable line-hashed location. The AFL IJON entry points are
	/// `unsafe extern "C"`, so this harness-only path waives crate-wide
	/// `deny(unsafe_code)`.
	#[cfg(all(fuzzing, feature = "testing-fuzz-ijon"))]
	#[allow(unsafe_code)]
	fn report_ijon(&self) {
		// The import is function-scoped, because `CString` exists only in std
		// and only this fuzzing-gated body needs it.
		use std::ffi::CString;

		afl::ijon_set!(self.track_state());
		// SAFETY: LOC is written once from a single-threaded AFL worker before
		// ijon_max reads it. file!() has no interior NUL, so CString::new
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

	/// A hash of the current state, for IJON state tracking.
	///
	/// The hash is a stable 32-bit value. AFL's IJON `ijon_set!()` macro reads
	/// it to guide fuzzing toward unexplored states.
	///
	/// ## IJON Integration
	/// ```ignore
	/// // Automatic after each successful step when testing-fuzz-ijon is on:
	/// afl::ijon_set!(oracle.track_state());
	/// ```
	///
	/// Through `ijon_set!`, AFL favors inputs that produce a state hash it has
	/// not seen.
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
	/// - **Upper 32 bits**: Number of unique states visited
	/// - **Lower 32 bits**: Number of unique transitions taken
	///
	/// ## IJON Integration
	/// ```ignore
	/// // Automatic after each successful step when testing-fuzz-ijon is on:
	/// afl::ijon_max(loc, oracle.coverage_score());
	/// ```
	///
	/// Through `ijon_max`, AFL favors inputs that raise the score, which are
	/// inputs that reach new states or transitions.
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
				if self.process.transitions.targets(*state, event).is_some() {
					total_transitions += 1;
				}
			}
		}

		(self.visited_transitions.len(), total_transitions)
	}

	/// Formats the run's context for triage of a failed fuzz run.
	///
	/// The text helps explain why a fuzz target crashed or failed. It holds:
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
	/// This method is the core AFL integration point. It reads each AFL byte
	/// as the choice of event at the current state of the CSP process.
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
	/// - `self.current_state()`: where execution stopped.
	/// - `self.trace()`: the events taken, in order.
	/// - `self.visited_states()`: the states explored.
	pub fn fuzz_from_bytes(&mut self, input: impl AsRef<[u8]>) -> Result<(), FuzzError> {
		let input = input.as_ref();
		self.reset();

		let mut byte_idx = 0;
		while !self.is_terminal() && byte_idx < input.len() {
			let valid = self.valid_events();
			if valid.is_empty() {
				return Err(FuzzError::Deadlock { state: self.current_state });
			}

			// Use input byte to choose which event to take
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

/// Shared fuzz state of a `tb_scenario!` run: the input, its cursor, and the
/// CSP oracle.
///
/// The context gives test scenarios shared access to `CspOracle`.
/// [`FuzzTraceCollector::new`] creates one and holds it, and `trace.oracle()`
/// returns it.
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
/// The byte readers, such as `fuzz_u8()` and `fuzz_u16()`, serve custom
/// fuzzing logic that needs structured data beyond oracle-guided execution.
/// Most fuzz targets should use `fuzz_from_bytes()` instead.
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

	/// Reads `n` bytes without advancing.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain.
	///   The cursor does not move, so a caller may read a shorter run instead.
	fn peek(&self, n: usize) -> Result<&[u8], TestingError> {
		if self.remaining() < n {
			return Err(TestingError::FuzzInputExhausted);
		}

		Ok(&self.input[self.cursor..self.cursor + n])
	}

	/// Consumes `n` bytes and advances the cursor past them.
	///
	/// This is the one place the cursor moves, so exhaustion is decided once
	/// rather than at each width a caller happens to ask for.
	///
	/// # Errors
	///
	/// - [`TestingError::FuzzInputExhausted`] -- fewer than `n` bytes remain, and the cursor does not move.
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

	/// Runs the oracle over the whole input buffer, one event choice per byte.
	///
	/// The run succeeds when it reaches a terminal state. A deadlock, an oracle
	/// rejection, and input exhaustion each map to a distinct [`TestingError`]
	/// variant, so a real deadlock is never reported as exhaustion.
	pub fn fuzz_from_bytes(&self) -> Result<(), TestingError> {
		let mut guard = self.inner.lock()?;
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
	/// The text is the oracle's crash context, which explains what the run did
	/// before the target failed, or a lock failure message.
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
	/// - `TestingError::FuzzInputLockPoisoned` -- the mutex is poisoned.
	pub fn step_event(&self, event: &Event) -> Result<bool, TestingError> {
		let mut guard = self.inner.lock()?;
		Ok(guard.oracle.step(event))
	}

	/// Consumes one byte of the fuzz input.
	pub fn fuzz_u8(&self) -> Result<u8, TestingError> {
		let mut guard = self.inner.lock()?;

		Ok(u8::from_be_bytes(guard.take_array()?))
	}

	/// Consumes two bytes of the fuzz input as a big-endian `u16`.
	pub fn fuzz_u16(&self) -> Result<u16, TestingError> {
		let mut guard = self.inner.lock()?;

		Ok(u16::from_be_bytes(guard.take_array()?))
	}

	/// Consumes four bytes of the fuzz input as a big-endian `u32`.
	pub fn fuzz_u32(&self) -> Result<u32, TestingError> {
		let mut guard = self.inner.lock()?;

		Ok(u32::from_be_bytes(guard.take_array()?))
	}

	/// Consumes eight bytes of the fuzz input as a big-endian `u64`.
	pub fn fuzz_u64(&self) -> Result<u64, TestingError> {
		let mut guard = self.inner.lock()?;

		Ok(u64::from_be_bytes(guard.take_array()?))
	}

	/// Consumes `n` bytes of the fuzz input.
	pub fn fuzz_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let mut guard = self.inner.lock()?;

		Ok(guard.take(n)?.to_vec())
	}

	/// A copy of the whole fuzz input, whatever the cursor position.
	pub fn fuzz_input(&self) -> Result<Vec<u8>, TestingError> {
		let guard = self.inner.lock()?;
		Ok(guard.input.clone())
	}

	/// Whether at least `n` bytes remain past the cursor.
	pub fn fuzz_has_bytes(&self, n: usize) -> Result<bool, TestingError> {
		let guard = self.inner.lock()?;

		Ok(guard.remaining() >= n)
	}

	/// The number of input bytes past the cursor.
	pub fn fuzz_remaining(&self) -> Result<usize, TestingError> {
		let guard = self.inner.lock()?;

		Ok(guard.remaining())
	}

	/// Reads the next byte of the fuzz input and leaves the cursor in place.
	pub fn fuzz_peek_u8(&self) -> Result<u8, TestingError> {
		let guard = self.inner.lock()?;

		Ok(guard.peek(1)?[0])
	}

	/// Reads the next `n` bytes of the fuzz input and leaves the cursor in
	/// place.
	pub fn fuzz_peek_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let guard = self.inner.lock()?;

		Ok(guard.peek(n)?.to_vec())
	}
}

/// Unit tests of the oracle and the fuzz context, which macros group into one
/// module per concern.
mod tests {
	use super::*;
	use crate::urn::Urn;

	// The fixtures below build small CSP processes for the tests.

	/// Builds a one-step process in which `event` moves `S0` to the terminal
	/// `S1`.
	#[allow(dead_code)]
	fn build_simple_process(event: &'static str) -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event(event))
			.add_transition(State("S0"), Event(event), State("S1"))
			.add_terminal(State("S1"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	/// Builds a two-step process in which `e1` moves `S0` to `S1` and `e2`
	/// moves `S1` to the terminal `S2`.
	#[allow(dead_code)]
	fn build_two_step_process(e1: &'static str, e2: &'static str) -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event(e1))
			.add_observable(Event(e2))
			.add_transition(State("S0"), Event(e1), State("S1"))
			.add_transition(State("S1"), Event(e2), State("S2"))
			.add_terminal(State("S2"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	/// Builds a three-step process in which `a`, `b`, and `c` move `S0`
	/// through `S1` and `S2` to the terminal `S3`.
	#[allow(dead_code)]
	fn build_three_step_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_observable(Event("c"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("b"), State("S2"))
			.add_transition(State("S2"), Event("c"), State("S3"))
			.add_terminal(State("S3"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	/// Builds a choice process in which `choice` moves `S0` to `S1` or `S2`,
	/// both terminal.
	#[allow(dead_code)]
	fn build_choice_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event("choice"))
			.add_transition(State("S0"), Event("choice"), State("S1"))
			.add_transition(State("S0"), Event("choice"), State("S2"))
			.add_choice(State("S0"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	/// Builds a branching process in which `a`, `b`, and `c` move `S0` to
	/// `S1`, `S2`, and `S3`, all terminal.
	#[allow(dead_code)]
	fn build_branching_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_observable(Event("c"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S0"), Event("b"), State("S2"))
			.add_transition(State("S0"), Event("c"), State("S3"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.add_terminal(State("S3"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	/// Builds a one-step process whose transition label is the full URN
	/// `event`, which moves `S0` to the terminal `S1`.
	#[allow(dead_code)]
	fn build_urn_step_process(event: Urn<'static>) -> Process {
		Process::builder("UrnStep")
			.initial_state(State("S0"))
			.add_observable(event.clone())
			.add_transition(State("S0"), event, State("S1"))
			.add_terminal(State("S1"))
			.build()
			.expect("fixture process builder has a valid initial state")
	}

	// The tests below cover the IJON feature and URN event labels.

	#[cfg(feature = "testing-fuzz-ijon")]
	#[test]
	fn oracle_ijon_feature_enabled() {
		// report_ijon is cfg(fuzzing), so cargo test runs the empty arm and
		// cargo-afl builds compile the real IJON calls.
		let proc = build_simple_process("go");
		let mut oracle = CspOracle::new(proc);

		let input = vec![0];
		let result = oracle.fuzz_from_bytes(&input);
		assert!(result.is_ok(), "IJON feature should not break fuzzing");
		assert_eq!(oracle.visited_states().len(), 2);
		assert_eq!(oracle.visited_transitions().len(), 1);

		let _ = oracle.track_state();
		let _ = oracle.coverage_score();
	}

	#[test]
	fn step_event_accepts_full_urn_label() {
		const GO: Urn<'static> = crate::urn!("fuzz", "event:test/go");
		let proc = build_urn_step_process(GO);

		let ctx = FuzzContext::new(Vec::new(), proc);
		let event = Event::from(GO);
		assert!(matches!(ctx.step_event(&event), Ok(true)));
		assert!(matches!(ctx.current_state(), Some(State("S1"))));
	}

	/// Generates the core oracle tests: steps, refusals, reset, and choice
	/// points.
	macro_rules! generate_oracle_core_tests {
		($module_name:ident) => {
			mod $module_name {
				#[test]
				fn tracks_state_transitions() {
					let mut oracle = super::CspOracle::new(super::build_two_step_process("go", "stop"));
					assert_eq!(oracle.current_state(), super::State("S0"));
					assert_eq!(oracle.visited_states().len(), 1);
					assert!(!oracle.is_terminal());

					let valid = oracle.valid_events();
					assert_eq!(valid.len(), 1);
					assert_eq!(valid[0].0, "go");

					assert!(oracle.step(&super::Event("go")));
					assert_eq!(oracle.current_state(), super::State("S1"));
					assert_eq!(oracle.visited_states().len(), 2);
					assert_eq!(oracle.visited_transitions().len(), 1);
					assert_eq!(oracle.trace().len(), 1);

					assert!(oracle.step(&super::Event("stop")));
					assert_eq!(oracle.current_state(), super::State("S2"));
					assert!(oracle.is_terminal());
					assert_eq!(oracle.valid_events().len(), 0);
				}

				#[test]
				fn rejects_invalid_events() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("valid"));
					assert!(!oracle.step(&super::Event("invalid")));
					assert_eq!(oracle.current_state(), super::State("S0"));
					assert_eq!(oracle.visited_transitions().len(), 0);
				}

				#[test]
				fn oracle_reset() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("go"));
					oracle.step(&super::Event("go"));
					assert_eq!(oracle.current_state(), super::State("S1"));

					oracle.reset();
					assert_eq!(oracle.current_state(), super::State("S0"));
					assert_eq!(oracle.visited_states().len(), 1);
					assert_eq!(oracle.visited_transitions().len(), 0);
					assert_eq!(oracle.trace().len(), 0);
				}

				#[test]
				fn oracle_with_choice_points() {
					let mut oracle = super::CspOracle::new(super::build_choice_process());
					let valid = oracle.valid_events();
					assert_eq!(valid.len(), 1);
					assert_eq!(valid[0].0, "choice");

					assert!(oracle.step(&super::Event("choice")));
					assert_eq!(oracle.current_state(), super::State("S1"));
				}
			}
		};
	}

	/// Generates the tests of the coverage metrics and the state hash.
	macro_rules! generate_coverage_tests {
		($module_name:ident) => {
			mod $module_name {
				#[test]
				fn oracle_coverage_metrics() {
					let mut oracle = super::CspOracle::new(super::build_two_step_process("a", "b"));
					let coverage = oracle.state_coverage();
					assert!((coverage - 33.33).abs() < 0.1);

					oracle.step(&super::Event("a"));
					let coverage = oracle.state_coverage();
					assert!((coverage - 66.66).abs() < 0.1);

					oracle.step(&super::Event("b"));
					let coverage = oracle.state_coverage();
					assert!((coverage - 100.0).abs() < 0.1);

					let (visited, _total) = oracle.transition_coverage();
					assert_eq!(visited, 2);
				}

				#[test]
				fn oracle_track_state_is_stable() {
					let proc = super::build_simple_process("go");
					let oracle1 = super::CspOracle::new(proc.clone());
					let oracle2 = super::CspOracle::new(proc);
					assert_eq!(oracle1.track_state(), oracle2.track_state());
				}

				#[test]
				fn oracle_coverage_score_increases() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("go"));
					let score1 = oracle.coverage_score();

					oracle.step(&super::Event("go"));
					let score2 = oracle.coverage_score();
					assert!(score2 > score1);
				}
			}
		};
	}

	/// Generates the tests of byte-driven fuzzing.
	macro_rules! generate_fuzzing_tests {
		($module_name:ident) => {
			mod $module_name {
				#[test]
				fn oracle_fuzz_from_bytes_reaches_terminal() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("go"));
					let input = vec![0];
					assert!(oracle.fuzz_from_bytes(&input).is_ok());
					assert_eq!(oracle.current_state(), super::State("S1"));
					assert!(oracle.is_terminal());
				}

				#[test]
				fn oracle_fuzz_from_bytes_multiple_transitions() {
					let mut oracle = super::CspOracle::new(super::build_two_step_process("a", "b"));
					let input = vec![0, 0];
					assert!(oracle.fuzz_from_bytes(&input).is_ok());
					assert_eq!(oracle.current_state(), super::State("S2"));
					assert_eq!(oracle.trace().len(), 2);
				}

				#[test]
				fn oracle_fuzz_from_bytes_fails_on_insufficient_input() {
					let mut oracle = super::CspOracle::new(super::build_two_step_process("a", "b"));
					let input = vec![0];
					assert!(matches!(
						oracle.fuzz_from_bytes(&input),
						Err(super::FuzzError::InputExhausted { .. })
					));
				}

				#[test]
				fn oracle_deadlock_reported_as_deadlock() {
					let process = super::Process::builder("TestProc")
						.initial_state(super::State("S0"))
						.add_observable(super::Event("go"))
						.add_transition(super::State("S0"), super::Event("go"), super::State("Stuck"))
						.build()
						.expect("fixture process builder has a valid initial state");

					let mut oracle = super::CspOracle::new(process);
					assert!(matches!(
						oracle.fuzz_from_bytes(&[0, 0]),
						Err(super::FuzzError::Deadlock { state: super::State("Stuck") })
					));
				}

				#[test]
				fn oracle_byte_mapping_deterministic_across_oracles() {
					let traces: Vec<Vec<super::Event>> = (0..8)
						.map(|_| {
							let mut oracle = super::CspOracle::new(super::build_branching_process());
							oracle.fuzz_from_bytes(&[1]).expect("branching process reaches terminal");
							oracle.trace().to_vec()
						})
						.collect();

					for trace in &traces {
						assert_eq!(trace, &traces[0]);
					}
				}

				#[test]
				fn oracle_coverage_increases_during_fuzzing() {
					let mut oracle = super::CspOracle::new(super::build_two_step_process("a", "b"));
					let initial_score = oracle.coverage_score();

					let input = vec![0, 0];
					let _ = oracle.fuzz_from_bytes(&input);
					let final_score = oracle.coverage_score();
					assert!(final_score > initial_score);

					assert_eq!(oracle.visited_states().len(), 3);
					assert_eq!(oracle.visited_transitions().len(), 2);
				}

				#[test]
				fn oracle_track_state_differs_between_states() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("go"));
					let hash_s0 = oracle.track_state();

					oracle.step(&super::Event("go"));

					let hash_s1 = oracle.track_state();
					assert_ne!(hash_s0, hash_s1);
				}

				#[test]
				fn oracle_crash_context_provides_debug_info() {
					let mut oracle = super::CspOracle::new(super::build_simple_process("go"));
					oracle.step(&super::Event("go"));

					let context = oracle.crash_context();
					assert!(context.contains("Current State:"));
					assert!(context.contains("S1"));
					assert!(context.contains("Terminal: true"));
					assert!(context.contains("Trace:"));
					assert!(context.contains("Coverage:"));
				}
			}
		};
	}

	/// Generates the tests of the `FuzzContext` wrapper.
	macro_rules! generate_context_tests {
		($module_name:ident) => {
			mod $module_name {
				#[test]
				fn fuzz_context_executes_oracle() {
					let proc = super::build_simple_process("go");
					let ctx = super::FuzzContext::new(vec![0], proc);
					assert!(ctx.fuzz_from_bytes().is_ok());
					assert!(ctx.is_terminal());
					assert_eq!(ctx.trace().len(), 1);
				}

				#[test]
				fn fuzz_context_ijon_accessors() {
					let proc = super::build_two_step_process("a", "b");
					let ctx = super::FuzzContext::new(vec![0, 0], proc);

					let initial_score = ctx.coverage_score();
					let initial_hash = ctx.track_state();

					let _ = ctx.fuzz_from_bytes();

					let final_score = ctx.coverage_score();
					let final_hash = ctx.track_state();
					assert!(final_score > initial_score);
					assert_ne!(initial_hash, final_hash);
				}

				#[test]
				fn fuzz_context_crash_context() {
					let proc = super::build_simple_process("go");
					let ctx = super::FuzzContext::new(vec![0], proc);
					let _ = ctx.fuzz_from_bytes();

					let context = ctx.crash_context();
					assert!(context.contains("AFL Crash Context"));
					assert!(context.contains("Current State:"));
					assert!(context.contains("S1"));
					assert!(context.contains("Coverage:"));
				}

				#[test]
				fn fuzz_context_thread_safe_clone() {
					let proc = super::build_simple_process("go");
					let ctx1 = super::FuzzContext::new(vec![0], proc);
					let ctx2 = ctx1.clone();

					let _ = ctx1.fuzz_from_bytes();
					assert_eq!(ctx1.current_state(), ctx2.current_state());
				}
			}
		};
	}

	/// Generates the tests of byte selection, choice points, reset, and
	/// concurrent access.
	macro_rules! generate_advanced_tests {
		($module_name:ident) => {
			mod $module_name {
				#[test]
				fn oracle_input_modulo_selection() {
					let proc = super::build_branching_process();
					let oracle_ref = super::CspOracle::new(proc.clone());
					let valid = oracle_ref.valid_events();
					assert_eq!(valid.len(), 3);

					let state_for_choice: Vec<super::State> = (0..3)
						.map(|choice| {
							let mut oracle = super::CspOracle::new(proc.clone());
							oracle
								.fuzz_from_bytes(&[choice as u8])
								.expect("oracle accepts a valid choice byte");
							oracle.current_state()
						})
						.collect();

					let test_cases = vec![
						(0, 0, "byte=0: 0 % 3 = 0 -> first event"),
						(1, 1, "byte=1: 1 % 3 = 1 -> second event"),
						(2, 2, "byte=2: 2 % 3 = 2 -> third event"),
						(3, 0, "byte=3: 3 % 3 = 0 -> wraps to first"),
						(255, 0, "byte=255: 255 % 3 = 0 -> wraps to first"),
					];

					for (input_byte, expected_choice, desc) in test_cases {
						let mut oracle = super::CspOracle::new(proc.clone());
						assert!(oracle.fuzz_from_bytes(&[input_byte]).is_ok());
						assert_eq!(oracle.current_state(), state_for_choice[expected_choice], "{}", desc);
					}
				}

				#[test]
				fn oracle_choice_point_fuzzing() {
					let proc = super::build_choice_process();
					let mut oracle = super::CspOracle::new(proc);
					assert!(oracle.fuzz_from_bytes(&[0, 0]).is_ok());
					assert_eq!(oracle.current_state(), super::State("S1"));
				}

				#[test]
				fn oracle_target_byte_reaches_second_nondeterministic_target() {
					let proc = super::build_choice_process();
					let mut oracle = super::CspOracle::new(proc);
					assert!(oracle.fuzz_from_bytes(&[0, 1]).is_ok());
					assert_eq!(oracle.current_state(), super::State("S2"));
				}

				#[test]
				fn oracle_reset_between_fuzz_runs() {
					let proc = super::build_simple_process("go");
					let mut oracle = super::CspOracle::new(proc);
					assert!(oracle.fuzz_from_bytes(&[0]).is_ok());
					assert_eq!(oracle.current_state(), super::State("S1"));
					assert_eq!(oracle.trace().len(), 1);
					assert!(oracle.fuzz_from_bytes(&[0]).is_ok());
					assert_eq!(oracle.current_state(), super::State("S1"));
					assert_eq!(oracle.trace().len(), 1);
				}

				#[test]
				fn oracle_exhaustive_state_exploration() {
					let proc = super::build_three_step_process();
					let mut oracle = super::CspOracle::new(proc);

					let input = vec![0, 0, 0];
					assert!(oracle.fuzz_from_bytes(&input).is_ok());
					assert_eq!(oracle.visited_states().len(), 4);
					assert_eq!(oracle.visited_transitions().len(), 3);
					assert_eq!(oracle.state_coverage(), 100.0);
				}

				#[test]
				fn fuzz_context_concurrent_access() {
					let proc = super::build_simple_process("go");
					let ctx = std::sync::Arc::new(super::FuzzContext::new(vec![0], proc));

					let handles: Vec<_> = (0..4)
						.map(|_| {
							let ctx_clone = std::sync::Arc::clone(&ctx);
							std::thread::spawn(move || {
								let _ = ctx_clone.coverage_score();
								let _ = ctx_clone.track_state();
								let _ = ctx_clone.is_terminal();
								let _ = ctx_clone.current_state();
							})
						})
						.collect();

					for handle in handles {
						handle.join().expect("Thread should not panic");
					}
				}
			}
		};
	}

	generate_oracle_core_tests!(oracle_core);
	generate_coverage_tests!(coverage);
	generate_fuzzing_tests!(fuzzing);
	generate_context_tests!(context);
	generate_advanced_tests!(advanced);

	/// An event the guided collector records steps the oracle that
	/// `oracle` returns.
	#[test]
	fn a_guided_collector_steps_the_oracle_it_holds() -> Result<(), crate::TightBeamError> {
		let trace = FuzzTraceCollector::new(Vec::new(), build_simple_process("go"));

		trace.collector().event(Event("go"))?;

		assert_eq!(trace.oracle().current_state(), Some(State("S1")));
		Ok(())
	}

	/// An event a share records steps the oracle of the collector it shares.
	#[test]
	fn a_share_of_a_guided_collector_steps_the_same_oracle() -> Result<(), crate::TightBeamError> {
		let trace = FuzzTraceCollector::new(Vec::new(), build_simple_process("go"));
		let share = trace.share();

		share.collector().event(Event("go"))?;

		assert_eq!(trace.oracle().current_state(), Some(State("S1")));
		Ok(())
	}
}

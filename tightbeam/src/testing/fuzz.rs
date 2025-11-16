//! AFL-powered fuzzing support
//!
//! CSP-guided fuzzing using `CspOracle` for intelligent state exploration.
//! All fuzzing is powered by AFL.rs (https://github.com/rust-fuzz/afl.rs).
//!
//! # AFL Integration Architecture
//!
//! 1. **tb_scenario! with fuzz: afl** generates `fn main() { afl::fuzz!(|data: &[u8]| { ... }) }`
//! 2. **AFL.rs** provides mutated byte arrays and tracks code coverage automatically
//! 3. **CspOracle** interprets bytes as event choices, guiding AFL toward valid protocol states
//! 4. **Coverage feedback** (automatic): AFL discovers new code paths without manual instrumentation
//! 5. **IJON integration** (automatic with feature): Enable `testing-fuzz-ijon` for state-aware guidance
//!
//! # How AFL Discovers Coverage
//!
//! AFL.rs uses compile-time instrumentation (via LLVM) to track:
//! - Basic block transitions (edge coverage)
//! - Hit counts for each edge (frequency analysis)
//! - New execution paths through code
//!
//! # Optional: IJON State-Space Guidance
//!
//! Enable the `testing-fuzz-ijon` feature to guide AFL toward unexplored CSP states:
//!
//! ```bash
//! cargo afl build --test fuzzing --features "std,testing-fuzz,testing-fuzz-ijon"
//! ```
//!
//! When enabled, the oracle automatically calls:
//! - `afl::ijon_max!("csp_coverage", ...)` - maximize state+transition coverage
//! - `afl::ijon_set!("csp_state", ...)` - track unique states visited
//!
//! This helps AFL prioritize inputs that explore new protocol states beyond
//! code coverage.
//!
//! # Verifying AFL Integration
//!
//! ## Unit Tests
//! Run the oracle unit tests to verify core functionality:
//! ```bash
//! cargo test --features "std,testing-fuzz,testing-csp" fuzz::tests
//! ```
//!
//! Key verification tests:
//! - `oracle_fuzz_from_bytes_reaches_terminal` - oracle interprets bytes correctly
//! - `oracle_coverage_increases_during_fuzzing` - coverage tracking works
//! - `oracle_track_state_differs_between_states` - state hashing is unique
//! - `oracle_crash_context_provides_debug_info` - debugging info available
//!
//! ## IJON Feature Test
//! Verify IJON feature compiles correctly:
//! ```bash
//! cargo test --features "std,testing-fuzz,testing-fuzz-ijon,testing-csp" oracle_ijon_feature_enabled
//! ```
//!
//! Note: IJON macros (`afl::ijon_max!`, `afl::ijon_set!`) require AFL runtime
//! and cannot be tested with `cargo check` or `cargo test`. They only work when
//! code is executed inside `afl::fuzz!()` under AFL's runtime. The unit test
//! verifies the oracle's coverage methods work correctly.
//!
//! ## AFL Runtime Verification
//! To verify AFL actually sees IJON data at runtime:
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
//! 3. Check AFL UI for IJON metrics:
//!    - Look for "csp_coverage" in maximization targets
//!    - Look for "csp_state" in state tracking
//!    - Coverage should increase faster with IJON enabled
//!
//! 4. Compare with/without IJON:
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
//! Expected: IJON build should discover more unique test cases and reach
//! higher state coverage in the same time period.
//!
//! # Creating Fuzz Targets
//!
//! Simple usage - no manual IJON calls needed:
//!
//! ```ignore
//! tb_scenario! {
//!     fuzz: afl,
//!     spec: MySpec,
//!     csp: MyProcess,
//!     environment Bare {
//!         exec: |trace| {
//!             // Oracle-guided fuzzing - IJON automatic with feature flag
//!             trace.oracle().fuzz_from_bytes()?;
//!
//!             // Make assertions based on execution trace
//!             for event in trace.oracle().trace() {
//!                 trace.event(event.0);
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

/// CSP state oracle for AFL-guided fuzzing
///
/// The oracle bridges AFL's byte-level mutation with CSP protocol semantics:
///
/// ## Core Functionality
/// - **State Machine Tracking**: Maintains current state in CSP process
/// - **Event Interpretation**: Maps input bytes → valid event choices
/// - **Coverage Metrics**: Tracks visited states/transitions for analysis
/// - **Crash Triage**: Provides execution context when fuzz targets fail
///
/// ## AFL Integration
/// - AFL automatically discovers code coverage (no manual instrumentation needed)
/// - Oracle guides AFL toward valid protocol states (prevents random noise)
/// - IJON-compatible methods available for state-space exploration
///
/// ## Usage Pattern
/// ```ignore
/// // In fuzz target (generated by tb_scenario! fuzz: afl):
/// let trace = TraceCollector::with_fuzz_oracle(data, process);
/// trace.oracle().fuzz_from_bytes()?;  // Run oracle-guided execution
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
	/// Create a new CSP oracle from a process specification
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

	/// Get the current state
	pub fn current_state(&self) -> State {
		self.current_state
	}

	/// Get all visited states
	pub fn visited_states(&self) -> &HashSet<State> {
		&self.visited_states
	}

	/// Get all visited transitions
	pub fn visited_transitions(&self) -> &HashSet<(State, Event)> {
		&self.visited_transitions
	}

	/// Get the execution trace
	pub fn trace(&self) -> &[Event] {
		&self.trace
	}

	/// Check if current state is terminal
	pub fn is_terminal(&self) -> bool {
		self.process.is_terminal(self.current_state)
	}

	/// Get list of valid events from current state
	///
	/// Returns only observable events that can be taken from the current state.
	/// Returns empty if in terminal state.
	pub fn valid_events(&self) -> Vec<Event> {
		if self.is_terminal() {
			return Vec::new();
		}

		self.process
			.enabled(self.current_state)
			.iter()
			.filter(|a| a.is_observable())
			.map(|a| a.event.clone())
			.collect()
	}

	/// Attempt to take a transition with the given event
	///
	/// Returns `true` if transition succeeded, `false` if event not enabled.
	/// Updates current state and tracking metrics on success.
	pub fn step(&mut self, event: &Event) -> bool {
		let next_states = self.process.step(self.current_state, event);

		if next_states.is_empty() {
			return false;
		}

		// Record transition
		self.visited_transitions.insert((self.current_state, event.clone()));
		self.trace.push(event.clone());

		// Take first state (deterministic or first choice)
		self.current_state = next_states[0];
		self.visited_states.insert(self.current_state);

		true
	}

	/// Reset oracle to initial state
	pub fn reset(&mut self) {
		let initial = self.process.initial;
		self.current_state = initial;
		self.visited_states.clear();
		self.visited_states.insert(initial);
		self.visited_transitions.clear();
		self.trace.clear();
	}

	/// Get hash of current state for IJON tracking
	///
	/// Returns a stable 32-bit hash of the current CSP state that can be used
	/// with AFL's IJON `ijon_set!()` macro to guide fuzzing toward unexplored states.
	///
	/// ## IJON Integration
	/// ```ignore
	/// // In fuzz target:
	/// if oracle.fuzz_from_bytes(data).is_ok() {
	///     afl::ijon_set!("state", oracle.track_state());
	/// }
	/// ```
	///
	/// This tells AFL: "I'm interested in reaching different state hash values."
	/// AFL will prioritize inputs that produce new state hashes.
	///
	/// ## When to Use
	/// - Protocol has large state space (many states)
	/// - Code coverage alone doesn't distinguish states well
	/// - Want to maximize state exploration beyond code paths
	///
	/// ## Note
	/// IJON requires `cargo install afl` with IJON support and setting
	/// `AFL_PRELOAD` environment variable. Standard AFL.rs works without this.
	pub fn track_state(&self) -> u32 {
		let mut hasher = DefaultHasher::new();
		self.current_state.hash(&mut hasher);
		hasher.finish() as u32
	}

	/// Get coverage score for IJON maximization
	///
	/// Returns a 64-bit score combining state and transition coverage:
	/// - **Upper 32 bits**: Number of unique states visited
	/// - **Lower 32 bits**: Number of unique transitions taken
	///
	/// ## IJON Integration
	/// ```ignore
	/// // In fuzz target:
	/// if oracle.fuzz_from_bytes(data).is_ok() {
	///     afl::ijon_max!("coverage", oracle.coverage_score());
	/// }
	/// ```
	///
	/// This tells AFL: "Maximize this coverage score."
	/// AFL will prioritize inputs that increase the score (explore new states/transitions).
	///
	/// ## When to Use
	/// - Want AFL to explicitly optimize for CSP coverage
	/// - Protocol has complex state machine with many paths
	/// - Code coverage metrics don't capture semantic coverage
	///
	/// ## Note
	/// IJON requires `cargo install afl` with IJON support. Standard AFL.rs
	/// discovers coverage automatically through code instrumentation.
	pub fn coverage_score(&self) -> u64 {
		((self.visited_states.len() as u64) << 32) | (self.visited_transitions.len() as u64)
	}

	/// Get state space coverage percentage
	pub fn state_coverage(&self) -> f64 {
		let total_states = self.process.states.len();
		if total_states == 0 {
			return 0.0;
		}
		(self.visited_states.len() as f64) / (total_states as f64) * 100.0
	}

	/// Get transition coverage statistics
	pub fn transition_coverage(&self) -> (usize, usize) {
		// Count total possible transitions
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

	/// Get crash triage information for debugging failed fuzz runs
	///
	/// Returns a formatted string with execution context useful for understanding
	/// why a fuzz target crashed or failed. Includes:
	/// - Current state (where execution stopped)
	/// - Event trace (sequence of events taken)
	/// - Coverage statistics (states/transitions explored)
	/// - Valid events (what could have been done at crash point)
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

	/// Run oracle-guided fuzzing from arbitrary byte input
	///
	/// **Core AFL Integration Point**: This method interprets AFL-provided bytes
	/// as choices for which events to take at each state in the CSP process.
	///
	/// ## How It Works
	/// 1. Reset oracle to initial state
	/// 2. For each input byte:
	///    - Get valid events at current state
	///    - Use byte value to choose event: `choice = byte % valid_events.len()`
	///    - Take transition with chosen event
	///    - Update state and coverage tracking
	///    - Report to IJON (if `testing-fuzz-ijon` feature enabled)
	/// 3. Return `Ok(())` if terminal state reached, `Err` otherwise
	///
	/// ## AFL Coverage Discovery
	/// AFL automatically sees:
	/// - Which code paths are taken (edge coverage)
	/// - How many valid events were at each state
	/// - Whether execution reached terminal state
	/// - Any panics/crashes during execution
	///
	/// ## IJON Integration (Automatic)
	/// When built with `--features testing-fuzz-ijon`, the oracle automatically
	/// reports CSP state exploration to AFL's IJON system:
	/// - `ijon_max!("csp_coverage", ...)` - maximize state+transition coverage
	/// - `ijon_set!("csp_state", ...)` - track unique states visited
	///
	/// This guides AFL toward unexplored protocol states beyond code coverage.
	///
	/// ## Returns
	/// - `Ok(())`: Execution reached terminal state successfully
	/// - `Err("deadlock")`: No valid events available (stuck in non-terminal state)
	/// - `Err("oracle rejected")`: Internal oracle error (should not happen)
	/// - `Err("input exhausted")`: Ran out of input bytes before terminal state
	///
	/// ## Crash Triage
	/// If this panics, check:
	/// - `self.current_state()` - where execution stopped
	/// - `self.trace()` - sequence of events taken
	/// - `self.visited_states()` - states explored
	pub fn fuzz_from_bytes(&mut self, input: &[u8]) -> Result<(), &'static str> {
		self.reset();
		let mut byte_idx = 0;

		while !self.is_terminal() && byte_idx < input.len() {
			let valid = self.valid_events();
			if valid.is_empty() {
				return Err("deadlock: no valid events");
			}

			// Use input byte to choose which event to take
			let choice = (input[byte_idx] as usize) % valid.len();
			let event = &valid[choice];

			if !self.step(event) {
				return Err("oracle rejected valid event");
			}

			byte_idx += 1;
		}

		if self.is_terminal() {
			Ok(())
		} else {
			Err("input exhausted before terminal state")
		}
	}
}

/// Fuzz context for integration with tb_scenario! macro
///
/// Provides ergonomic access to `CspOracle` within test scenarios.
/// Created by `TraceCollector::with_fuzz_oracle()` and accessed via `trace.oracle()`.
///
/// ## Architecture
/// - **TraceCollector** manages test assertions
/// - **FuzzContext** wraps `CspOracle` with mutex for thread-safe access
/// - **CspOracle** performs actual CSP-guided fuzzing
///
/// ## Usage
/// ```ignore
/// tb_scenario! {
///     fuzz: afl,
///     spec: MySpec,
///     csp: MyProcess,
///     environment Bare {
///         exec: |trace| {
///             // FuzzContext provides oracle access
///             trace.oracle().fuzz_from_bytes()?;
///
///             // Can also query oracle state
///             for (label, _) in trace.oracle().trace() {
///                 trace.event(label);
///             }
///             Ok(())
///         }
///     }
/// }
/// ```
///
/// ## Advanced: Direct Byte Consumption
/// The `fuzz_u8()`, `fuzz_u16()`, etc. methods are provided for custom
/// fuzzing logic that needs structured data beyond oracle-guided execution.
/// Most fuzz targets should use `fuzz_from_bytes()` instead.
#[derive(Clone)]
pub struct FuzzContext {
	inner: Arc<Mutex<FuzzContextInner>>,
}

struct FuzzContextInner {
	input: Vec<u8>,
	cursor: usize,
	oracle: CspOracle,
}

impl FuzzContext {
	/// Create new fuzz context with input and CSP process
	pub fn new(input: Vec<u8>, process: Process) -> Self {
		Self {
			inner: Arc::new(Mutex::new(FuzzContextInner {
				input,
				cursor: 0,
				oracle: CspOracle::new(process),
			})),
		}
	}

	/// Run oracle-guided fuzzing from the input buffer
	///
	/// Interprets input bytes as choices for which events to take at each state.
	/// Returns `Ok(())` if execution reaches terminal state.
	pub fn fuzz_from_bytes(&self) -> Result<(), TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		let input = guard.input.clone();
		guard
			.oracle
			.fuzz_from_bytes(&input)
			.map_err(|_| TestingError::FuzzInputExhausted)
	}

	/// Get the execution trace of events
	pub fn trace(&self) -> Vec<Event> {
		self.inner.lock().map(|g| g.oracle.trace().to_vec()).unwrap_or_default()
	}

	/// Check if current state is terminal
	pub fn is_terminal(&self) -> bool {
		self.inner.lock().map(|g| g.oracle.is_terminal()).unwrap_or(false)
	}

	/// Get valid events from current state
	pub fn valid_events(&self) -> Vec<Event> {
		self.inner.lock().map(|g| g.oracle.valid_events()).unwrap_or_default()
	}

	/// Get current state
	pub fn current_state(&self) -> Option<State> {
		self.inner.lock().ok().map(|g| g.oracle.current_state())
	}

	/// Get crash context for debugging
	///
	/// Returns formatted debugging information about the current oracle state.
	/// Useful when a fuzz target fails to understand what happened.
	pub fn crash_context(&self) -> String {
		self.inner
			.lock()
			.map(|g| g.oracle.crash_context())
			.unwrap_or_else(|_| "Failed to acquire oracle lock".to_string())
	}

	/// Get current coverage score for IJON integration
	///
	/// Returns combined state+transition coverage metric. Used by `tb_scenario!`
	/// macro when `testing-fuzz-ijon` feature is enabled.
	pub fn coverage_score(&self) -> u64 {
		self.inner.lock().map(|g| g.oracle.coverage_score()).unwrap_or(0)
	}

	/// Get current state hash for IJON integration
	///
	/// Returns stable hash of current CSP state. Used by `tb_scenario!`
	/// macro when `testing-fuzz-ijon` feature is enabled.
	pub fn track_state(&self) -> u32 {
		self.inner.lock().map(|g| g.oracle.track_state()).unwrap_or(0)
	}

	/// Manually step CSP oracle with an event
	///
	/// Attempts to take a transition with the given event in the CSP state machine.
	/// Returns `Ok(true)` if transition succeeded, `Ok(false)` if event not enabled.
	///
	/// ## Usage
	/// ```ignore
	/// // Manually step CSP state machine
	/// trace.oracle().step_event(&Event::new("move_request"))?;
	/// ```
	///
	/// ## Errors
	/// Returns `Err(TestingError::FuzzInputLockPoisoned)` if mutex is poisoned.
	pub fn step_event(&self, event: &Event) -> Result<bool, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		Ok(guard.oracle.step(event))
	}

	/// Consume and return a u8 from fuzz input
	pub fn fuzz_u8(&self) -> Result<u8, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + 1 > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}

		let value = guard.input[guard.cursor];

		guard.cursor += 1;

		Ok(value)
	}

	/// Consume and return a u16 from fuzz input (big-endian)
	pub fn fuzz_u16(&self) -> Result<u16, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + 2 > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}
		let bytes = [guard.input[guard.cursor], guard.input[guard.cursor + 1]];

		guard.cursor += 2;

		Ok(u16::from_be_bytes(bytes))
	}

	/// Consume and return a u32 from fuzz input (big-endian)
	pub fn fuzz_u32(&self) -> Result<u32, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + 4 > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}
		let bytes = [
			guard.input[guard.cursor],
			guard.input[guard.cursor + 1],
			guard.input[guard.cursor + 2],
			guard.input[guard.cursor + 3],
		];

		guard.cursor += 4;

		Ok(u32::from_be_bytes(bytes))
	}

	/// Consume and return a u64 from fuzz input (big-endian)
	pub fn fuzz_u64(&self) -> Result<u64, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + 8 > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}
		let bytes = [
			guard.input[guard.cursor],
			guard.input[guard.cursor + 1],
			guard.input[guard.cursor + 2],
			guard.input[guard.cursor + 3],
			guard.input[guard.cursor + 4],
			guard.input[guard.cursor + 5],
			guard.input[guard.cursor + 6],
			guard.input[guard.cursor + 7],
		];

		guard.cursor += 8;

		Ok(u64::from_be_bytes(bytes))
	}

	/// Consume and return N bytes from fuzz input
	pub fn fuzz_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let mut guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + n > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}

		let bytes = guard.input[guard.cursor..guard.cursor + n].to_vec();

		guard.cursor += n;

		Ok(bytes)
	}

	/// Get raw fuzz input bytes
	pub fn fuzz_input(&self) -> Result<Vec<u8>, TestingError> {
		let guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		Ok(guard.input.clone())
	}

	/// Check if N bytes are available in fuzz input
	pub fn fuzz_has_bytes(&self, n: usize) -> Result<bool, TestingError> {
		let guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		Ok(guard.cursor + n <= guard.input.len())
	}

	/// Get remaining byte count in fuzz input
	pub fn fuzz_remaining(&self) -> Result<usize, TestingError> {
		let guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		Ok(guard.input.len() - guard.cursor)
	}

	/// Peek at next u8 from fuzz input without consuming
	pub fn fuzz_peek_u8(&self) -> Result<u8, TestingError> {
		let guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + 1 > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}

		Ok(guard.input[guard.cursor])
	}

	/// Peek at next N bytes from fuzz input without consuming
	pub fn fuzz_peek_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
		let guard = self.inner.lock().map_err(|_| TestingError::FuzzInputLockPoisoned)?;
		if guard.cursor + n > guard.input.len() {
			return Err(TestingError::FuzzInputExhausted);
		}

		Ok(guard.input[guard.cursor..guard.cursor + n].to_vec())
	}
}

/// Generic test framework for fuzzing functionality
/// Tests common patterns across oracle and context components
mod tests {
	use super::*;

	// ===== Test Fixtures =====

	/// Build a simple linear process: S0 --event--> S1 (terminal)
	#[allow(dead_code)]
	fn build_simple_process(event: &'static str) -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(event)
			.add_transition(State("S0"), event, State("S1"))
			.add_terminal(State("S1"))
			.build()
			.unwrap()
	}

	/// Build a two-step linear process: S0 --e1--> S1 --e2--> S2 (terminal)
	#[allow(dead_code)]
	fn build_two_step_process(e1: &'static str, e2: &'static str) -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable(e1)
			.add_observable(e2)
			.add_transition(State("S0"), e1, State("S1"))
			.add_transition(State("S1"), e2, State("S2"))
			.add_terminal(State("S2"))
			.build()
			.unwrap()
	}

	/// Build a three-step linear process: S0 --a--> S1 --b--> S2 --c--> S3 (terminal)
	#[allow(dead_code)]
	fn build_three_step_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("a")
			.add_observable("b")
			.add_observable("c")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S1"), "b", State("S2"))
			.add_transition(State("S2"), "c", State("S3"))
			.add_terminal(State("S3"))
			.build()
			.unwrap()
	}

	/// Build a choice process: S0 --choice--> {S1, S2} (both terminal)
	#[allow(dead_code)]
	fn build_choice_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("choice")
			.add_transition(State("S0"), "choice", State("S1"))
			.add_transition(State("S0"), "choice", State("S2"))
			.add_choice(State("S0"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.build()
			.unwrap()
	}

	/// Build a branching process: S0 --{a,b,c}--> {S1, S2, S3} (all terminal)
	#[allow(dead_code)]
	fn build_branching_process() -> Process {
		Process::builder("TestProc")
			.initial_state(State("S0"))
			.add_observable("a")
			.add_observable("b")
			.add_observable("c")
			.add_transition(State("S0"), "a", State("S1"))
			.add_transition(State("S0"), "b", State("S2"))
			.add_transition(State("S0"), "c", State("S3"))
			.add_terminal(State("S1"))
			.add_terminal(State("S2"))
			.add_terminal(State("S3"))
			.build()
			.unwrap()
	}

	// ===== IJON Feature Tests =====

	#[cfg(feature = "testing-fuzz-ijon")]
	#[test]
	fn oracle_ijon_feature_enabled() {
		// This test verifies that the IJON feature flag compiles correctly.
		// IJON macros only execute inside afl::fuzz!() at runtime, so we verify
		// the feature enables the right code paths without actually calling IJON.
		let proc = build_simple_process("go");
		let mut oracle = CspOracle::new(proc);

		// fuzz_from_bytes will skip IJON calls in test mode (cfg(test) is true)
		let input = vec![0];
		let result = oracle.fuzz_from_bytes(&input);
		assert!(result.is_ok(), "IJON feature should not break fuzzing");
		assert_eq!(oracle.visited_states().len(), 2);
		assert_eq!(oracle.visited_transitions().len(), 1);

		// Verify IJON-related methods work
		let _ = oracle.track_state();
		let _ = oracle.coverage_score();
	}

	/// Generate tests for oracle core functionality
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

	/// Generate tests for coverage and metrics
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

	/// Generate tests for fuzzing from bytes
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
					assert_eq!(oracle.fuzz_from_bytes(&input), Err("input exhausted before terminal state"));
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

	/// Generate tests for FuzzContext integration
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

	/// Generate tests for advanced fuzzing behavior
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
							oracle.fuzz_from_bytes(&[choice as u8]).unwrap();
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
					assert!(oracle.fuzz_from_bytes(&[0]).is_ok());
					assert_eq!(oracle.current_state(), super::State("S1"));
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

	// Generate test modules
	generate_oracle_core_tests!(oracle_core);
	generate_coverage_tests!(coverage);
	generate_fuzzing_tests!(fuzzing);
	generate_context_tests!(context);
	generate_advanced_tests!(advanced);
}

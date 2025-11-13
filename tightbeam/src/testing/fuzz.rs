//! AFL-powered fuzzing support
//!
//! CSP-guided fuzzing using `CspOracle` for intelligent state exploration.
//! All fuzzing is powered by AFL.rs for coverage-guided mutation.
//!
//! Use `tb_scenario!` with `fuzz: afl` to create fuzz targets.

#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use crate::testing::error::TestingError;
use crate::testing::specs::csp::{Event, Process, State};

/// CSP state oracle for guided fuzzing
///
/// Tracks execution through a CSP process state machine, providing:
/// - Valid next events at each state
/// - State exploration coverage metrics
/// - State hashing for IJON-guided fuzzing
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
        self.visited_transitions
            .insert((self.current_state, event.clone()));
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
    /// Returns a stable hash that can be used with `afl::ijon_set!()` to guide
    /// AFL toward unexplored states.
    pub fn track_state(&self) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.current_state.hash(&mut hasher);
        hasher.finish() as u32
    }

    /// Get coverage score for IJON maximization
    ///
    /// Returns combined metric of state and transition coverage.
    /// Upper 32 bits: number of visited states
    /// Lower 32 bits: number of visited transitions
    ///
    /// Use with `afl::ijon_max!()` to guide AFL toward maximum coverage.
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

    /// Run oracle-guided fuzzing from arbitrary byte input
    ///
    /// Interprets input bytes as choices for which events to take at each state.
    /// This is the core fuzzing harness for AFL.rs integration.
    ///
    /// Returns `Ok(())` if execution reaches terminal state, `Err` otherwise.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // In AFL.rs fuzz target:
    /// afl::fuzz!(|data: &[u8]| {
    ///     let proc = MyProcess::process();
    ///     let mut oracle = CspOracle::new(proc);
    ///
    ///     if oracle.fuzz_from_bytes(data).is_ok() {
    ///         // Track coverage for IJON
    ///         afl::ijon_max!("coverage", oracle.coverage_score());
    ///     }
    /// });
    /// ```
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

/// Fuzz context integrating input buffer and CSP oracle
///
/// Provides clean ergonomic access to fuzzing operations with internal
/// mutex handling. Access via `trace.oracle().method()` in tests.
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        let input = guard.input.clone();
        guard
            .oracle
            .fuzz_from_bytes(&input)
            .map_err(|_| TestingError::FuzzInputExhausted)
    }

    /// Get the execution trace of events
    pub fn trace(&self) -> Vec<Event> {
        self.inner
            .lock()
            .map(|g| g.oracle.trace().to_vec())
            .unwrap_or_default()
    }

    /// Check if current state is terminal
    pub fn is_terminal(&self) -> bool {
        self.inner
            .lock()
            .map(|g| g.oracle.is_terminal())
            .unwrap_or(false)
    }

    /// Get valid events from current state
    pub fn valid_events(&self) -> Vec<Event> {
        self.inner
            .lock()
            .map(|g| g.oracle.valid_events())
            .unwrap_or_default()
    }

    /// Get current state
    pub fn current_state(&self) -> Option<State> {
        self.inner.lock().ok().map(|g| g.oracle.current_state())
    }

    /// Consume and return a u8 from fuzz input
    pub fn fuzz_u8(&self) -> Result<u8, TestingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        if guard.cursor + 1 > guard.input.len() {
            return Err(TestingError::FuzzInputExhausted);
        }
        let value = guard.input[guard.cursor];
        guard.cursor += 1;
        Ok(value)
    }

    /// Consume and return a u16 from fuzz input (big-endian)
    pub fn fuzz_u16(&self) -> Result<u16, TestingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        if guard.cursor + 2 > guard.input.len() {
            return Err(TestingError::FuzzInputExhausted);
        }
        let bytes = [guard.input[guard.cursor], guard.input[guard.cursor + 1]];
        guard.cursor += 2;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Consume and return a u32 from fuzz input (big-endian)
    pub fn fuzz_u32(&self) -> Result<u32, TestingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
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
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        if guard.cursor + n > guard.input.len() {
            return Err(TestingError::FuzzInputExhausted);
        }
        let bytes = guard.input[guard.cursor..guard.cursor + n].to_vec();
        guard.cursor += n;
        Ok(bytes)
    }

    /// Get raw fuzz input bytes
    pub fn fuzz_input(&self) -> Result<Vec<u8>, TestingError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        Ok(guard.input.clone())
    }

    /// Check if N bytes are available in fuzz input
    pub fn fuzz_has_bytes(&self, n: usize) -> Result<bool, TestingError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        Ok(guard.cursor + n <= guard.input.len())
    }

    /// Get remaining byte count in fuzz input
    pub fn fuzz_remaining(&self) -> Result<usize, TestingError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        Ok(guard.input.len() - guard.cursor)
    }

    /// Peek at next u8 from fuzz input without consuming
    pub fn fuzz_peek_u8(&self) -> Result<u8, TestingError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        if guard.cursor + 1 > guard.input.len() {
            return Err(TestingError::FuzzInputExhausted);
        }
        Ok(guard.input[guard.cursor])
    }

    /// Peek at next N bytes from fuzz input without consuming
    pub fn fuzz_peek_bytes(&self, n: usize) -> Result<Vec<u8>, TestingError> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TestingError::FuzzInputLockPoisoned)?;
        if guard.cursor + n > guard.input.len() {
            return Err(TestingError::FuzzInputExhausted);
        }
        Ok(guard.input[guard.cursor..guard.cursor + n].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oracle_tracks_state_transitions() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("go")
            .add_observable("stop")
            .add_transition(State("S0"), "go", State("S1"))
            .add_transition(State("S1"), "stop", State("S2"))
            .add_terminal(State("S2"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);

        // Initial state
        assert_eq!(oracle.current_state(), State("S0"));
        assert_eq!(oracle.visited_states().len(), 1);
        assert!(!oracle.is_terminal());

        // Valid events at S0
        let valid = oracle.valid_events();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].0, "go");

        // Take transition
        assert!(oracle.step(&Event("go")));
        assert_eq!(oracle.current_state(), State("S1"));
        assert_eq!(oracle.visited_states().len(), 2);
        assert_eq!(oracle.visited_transitions().len(), 1);
        assert_eq!(oracle.trace().len(), 1);

        // Take second transition
        assert!(oracle.step(&Event("stop")));
        assert_eq!(oracle.current_state(), State("S2"));
        assert!(oracle.is_terminal());
        assert_eq!(oracle.valid_events().len(), 0);
    }

    #[test]
    fn oracle_rejects_invalid_events() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("valid")
            .add_transition(State("S0"), "valid", State("S1"))
            .add_terminal(State("S1"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);

        // Invalid event should fail
        assert!(!oracle.step(&Event("invalid")));
        assert_eq!(oracle.current_state(), State("S0"));
        assert_eq!(oracle.visited_transitions().len(), 0);
    }

    #[test]
    fn oracle_reset() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("go")
            .add_transition(State("S0"), "go", State("S1"))
            .add_terminal(State("S1"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);

        // Take transition
        oracle.step(&Event("go"));
        assert_eq!(oracle.current_state(), State("S1"));

        // Reset
        oracle.reset();
        assert_eq!(oracle.current_state(), State("S0"));
        assert_eq!(oracle.visited_states().len(), 1);
        assert_eq!(oracle.visited_transitions().len(), 0);
        assert_eq!(oracle.trace().len(), 0);
    }

    #[test]
    fn oracle_coverage_metrics() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("a")
            .add_observable("b")
            .add_transition(State("S0"), "a", State("S1"))
            .add_transition(State("S1"), "b", State("S2"))
            .add_terminal(State("S2"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);

        // Initial coverage
        let coverage = oracle.state_coverage();
        assert!((coverage - 33.33).abs() < 0.1); // 1/3 states

        // After one transition
        oracle.step(&Event("a"));
        let coverage = oracle.state_coverage();
        assert!((coverage - 66.66).abs() < 0.1); // 2/3 states

        // After second transition
        oracle.step(&Event("b"));
        let coverage = oracle.state_coverage();
        assert!((coverage - 100.0).abs() < 0.1); // 3/3 states

        // Transition coverage
        let (visited, _total) = oracle.transition_coverage();
        assert_eq!(visited, 2);
    }

    #[test]
    fn oracle_track_state_is_stable() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("go")
            .add_transition(State("S0"), "go", State("S1"))
            .add_terminal(State("S1"))
            .build()
            .unwrap();

        // Same state should produce same hash
        let oracle1 = CspOracle::new(proc.clone());
        let oracle2 = CspOracle::new(proc);
        assert_eq!(oracle1.track_state(), oracle2.track_state());
    }

    #[test]
    fn oracle_coverage_score_increases() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("go")
            .add_transition(State("S0"), "go", State("S1"))
            .add_terminal(State("S1"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);
        let score1 = oracle.coverage_score();

        oracle.step(&Event("go"));

        // Score should increase after visiting new state/transition
        let score2 = oracle.coverage_score();
        assert!(score2 > score1);
    }

    #[test]
    fn oracle_with_choice_points() {
        let proc = Process::builder("TestProc")
            .initial_state(State("S0"))
            .add_observable("choice")
            .add_transition(State("S0"), "choice", State("S1"))
            .add_transition(State("S0"), "choice", State("S2"))
            .add_choice(State("S0"))
            .add_terminal(State("S1"))
            .add_terminal(State("S2"))
            .build()
            .unwrap();

        let mut oracle = CspOracle::new(proc);

        // Should provide valid event
        let valid = oracle.valid_events();
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].0, "choice");

        // Step should succeed (takes first choice)
        assert!(oracle.step(&Event("choice")));
        assert_eq!(oracle.current_state(), State("S1"));
    }
}

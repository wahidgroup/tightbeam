//! The FDR integration tests, built on canonical CSP examples.
//!
//! These tests check the FDR refinement checker against well-known CSP
//! examples from the FDR Manual:
//! - Tennis Game Scoring System: state transitions and trace refinement.
//! - Dining Philosophers: deadlock detection.
//!
//! The `exploration` suite builds an exploration engine, and the `refinement`
//! suite builds a refinement checker and a memoization cache, through the
//! public API alone, as an outside crate must. The `scenario` suite grades a
//! scenario that names a CSP model and FDR specs.

mod diners;
mod refinement;
mod scenario;
#[cfg(feature = "testing-fault")]
mod scheduler;
mod tennis;

#[cfg(feature = "instrument")]
mod exploration;

use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};

/// A process whose hidden `t` and `u` take `S1` to `S2` and back, with the
/// observable exit `b` at `S2`, so it can diverge after `a`.
pub fn spinning() -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder("Spinning")
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
		.build();

	built.expect("a process with a hidden cycle builds")
}

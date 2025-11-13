//! AFL-powered fuzzing targets for CSP-guided exploration
//!
//! These fuzz targets use AFL.rs for coverage-guided fuzzing of protocol
//! implementations. Each target can be run with cargo-afl:
//!
//!     cargo install afl
//!     cargo afl build --test suite
//!     cargo afl fuzz -i inputs -o outputs target/debug/deps/suite-*
//!
//! The fuzz targets are disabled by default (no_main). To enable for AFL fuzzing,
//! compile with: cargo afl build

#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::testing::{assertions::AssertionPhase, error::TestingError};
use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

// ============================================================================
// Simple 3-State Workflow Fuzz Target
// ============================================================================

tb_assert_spec! {
    pub SimpleFuzzSpec,
    V(1,0,0): {
        mode: Accept,
        gate: Accepted,
        assertions: [
            (HandlerStart, "start", exactly!(1)),
            (HandlerStart, "action_a", at_least!(0)),
            (HandlerStart, "action_b", at_least!(0)),
            (HandlerStart, "done", exactly!(1))
        ]
    },
}

tb_process_spec! {
    pub struct SimpleFuzzProc;
    events {
        observable { "start", "action_a", "action_b", "done" }
        hidden { }
    }
    states {
        S0 => { "start" => S1 },
        S1 => { "action_a" => S1, "action_b" => S1, "done" => S2 }
    }
    terminal { S2 }
}

// AFL fuzz target - use tb_scenario! with fuzz: afl
#[cfg(fuzzing)] // Only compile when fuzzing
tb_scenario! {
    fuzz: afl,
    spec: SimpleFuzzSpec,
    csp: SimpleFuzzProc,
    environment Bare {
        exec: |trace| {
            // Run the oracle with AFL-provided input
            match trace.oracle().fuzz_from_bytes() {
                Ok(()) => {
                    // Oracle successfully reached terminal state
                    for event in trace.oracle().trace() {
                        trace.assert(AssertionPhase::HandlerStart, event.0);
                    }
                    Ok(())
                }
                Err(_) => {
                    // Input exhausted or invalid path - normal for fuzzing
                    Err(TestingError::FuzzInputExhausted.into())
                }
            }
        }
    }
}

// ============================================================================
// Complex Multi-Stage Workflow Fuzz Target
// ============================================================================

tb_assert_spec! {
    pub WorkflowFuzzSpec,
    V(1,0,0): {
        mode: Accept,
        gate: Accepted,
        assertions: [
            (HandlerStart, "init", exactly!(1)),
            (HandlerStart, "authenticate", exactly!(1)),
            (HandlerStart, "complete", exactly!(1))
        ]
    },
}

tb_process_spec! {
    pub struct WorkflowFuzzProc;
    events {
        observable {
            "init",
            "authenticate",
            "read",
            "write",
            "delete",
            "commit",
            "rollback",
            "complete"
        }
        hidden { }
    }
    states {
        S0 => { "init" => S1 },
        S1 => { "authenticate" => S2 },
        S2 => {
            "read" => S3,
            "write" => S3,
            "delete" => S3
        },
        S3 => {
            "read" => S3,
            "write" => S3,
            "delete" => S3,
            "commit" => S4,
            "rollback" => S5
        },
        S4 => { "complete" => S6 },
        S5 => { "complete" => S6 }
    }
    terminal { S6 }
}

#[cfg(fuzzing)] // Only compile when fuzzing
tb_scenario! {
    fuzz: afl,
    spec: WorkflowFuzzSpec,
    csp: WorkflowFuzzProc,
    environment Bare {
        exec: |trace| {
            // Fuzz through the workflow state machine
            match trace.oracle().fuzz_from_bytes() {
                Ok(()) => {
                    // Successfully completed workflow!
                    for event in trace.oracle().trace() {
                        trace.assert(AssertionPhase::HandlerStart, event.0);
                    }
                    Ok(())
                }
                Err(_) => {
                    // Failed to complete workflow - normal for fuzzing
                    Err(TestingError::FuzzInputExhausted.into())
                }
            }
        }
    }
}

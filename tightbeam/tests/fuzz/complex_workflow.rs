//! Complex multi-stage workflow fuzz target for AFL

#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::testing::{assertions::AssertionPhase, error::TestingError};
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

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

#[cfg(fuzzing)]
tb_scenario! {
    fuzz: afl,
    spec: WorkflowFuzzSpec,
    csp: WorkflowFuzzProc,
    environment Bare {
        exec: |trace| {
            // Oracle-guided fuzzing through complex 6-state workflow
            // IJON state tracking is automatic when built with testing-fuzz-ijon feature
            trace.oracle().fuzz_from_bytes()?;

            // Make assertions based on execution trace
            for event in trace.oracle().trace() {
                trace.assert(AssertionPhase::HandlerStart, event.0);
            }
            Ok(())
        }
    }
}

//! Complex multi-stage workflow fuzz target for AFL

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

tb_assert_spec! {
	pub WorkflowFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("init", exactly!(1)),
			("authenticate", exactly!(1)),
			("complete", exactly!(1))
		]
	},
}

tb_process_spec! {
	pub WorkflowFuzzProc,
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

tb_scenario! {
	fuzz: afl,
	config: tightbeam::testing::ScenarioConf::<()>::builder()
		.with_spec(WorkflowFuzzSpec::latest())
		.with_csp(WorkflowFuzzProc)
		.build(),
	environment Bare {
		exec: |trace| {
			// Oracle-guided fuzzing through complex 6-state workflow
			// IJON state tracking is automatic
			trace.as_ref().oracle().fuzz_from_bytes()?;

			// Make assertions based on execution trace
			for event in trace.as_ref().oracle().trace() {
				trace.event(event.0)?;
			}
			Ok(())
		}
	}
}

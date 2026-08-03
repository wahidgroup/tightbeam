//! Complex multi-stage workflow fuzz target for AFL

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-fuzz"))]

use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

const INIT: Urn<'static> = Urn::new("fuzz", "event:workflow/init");
const AUTHENTICATE: Urn<'static> = Urn::new("fuzz", "event:workflow/authenticate");
const READ: Urn<'static> = Urn::new("fuzz", "event:workflow/read");
const WRITE: Urn<'static> = Urn::new("fuzz", "event:workflow/write");
const DELETE: Urn<'static> = Urn::new("fuzz", "event:workflow/delete");
const COMMIT: Urn<'static> = Urn::new("fuzz", "event:workflow/commit");
const ROLLBACK: Urn<'static> = Urn::new("fuzz", "event:workflow/rollback");
const COMPLETE: Urn<'static> = Urn::new("fuzz", "event:workflow/complete");

tb_assert_spec! {
	pub WorkflowFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(INIT, exactly!(1)),
			(AUTHENTICATE, exactly!(1)),
			(COMPLETE, exactly!(1))
		]
	},
}

tb_process_spec! {
	pub WorkflowFuzzProc,
	events {
		observable {
			INIT,
			AUTHENTICATE,
			READ,
			WRITE,
			DELETE,
			COMMIT,
			ROLLBACK,
			COMPLETE
		}
		hidden { }
	}
	states {
		S0 => { INIT => S1 },
		S1 => { AUTHENTICATE => S2 },
		S2 => {
			READ => S3,
			WRITE => S3,
			DELETE => S3
		},
		S3 => {
			READ => S3,
			WRITE => S3,
			DELETE => S3,
			COMMIT => S4,
			ROLLBACK => S5
		},
		S4 => { COMPLETE => S6 },
		S5 => { COMPLETE => S6 }
	}
	terminal { S6 }
}

tb_scenario! {
	fuzz: afl,
	csp: WorkflowFuzzProc,
	config: ScenarioConfig::builder()
		.with_spec(WorkflowFuzzSpec::latest())
		.with_csp(WorkflowFuzzProc)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Oracle-guided fuzzing through complex 6-state workflow
			// IJON state tracking is automatic
			trace.oracle().fuzz_from_bytes()?;

			// Make assertions based on execution trace
			for event in trace.oracle().trace() {
				trace.event(event)?;
			}

			Ok::<(), tightbeam::TightBeamError>(())
		}
	}
}

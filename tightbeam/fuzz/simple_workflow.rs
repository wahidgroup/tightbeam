//! Simple 3-state workflow fuzz target for AFL
//!
//! Run with:
//!   cargo install cargo-afl
//!   cargo afl build --test simple_workflow --features "std,testing-csp"
//!   mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/deps/simple_workflow-*

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

tb_assert_spec! {
	pub SimpleFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("start", exactly!(1)),
			("action_a", at_least!(0)),
			("action_b", at_least!(0)),
			("done", exactly!(1))
		]
	},
}

tb_process_spec! {
	pub SimpleFuzzProc,
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

tb_scenario! {
	fuzz: afl,
	csp: SimpleFuzzProc,
	config: ScenarioConf::<()>::builder()
		.with_spec(SimpleFuzzSpec::latest())
		.with_csp(SimpleFuzzProc)
		.build(),
	environment Bare {
		exec: |trace| {
			// Oracle-guided fuzzing: interprets AFL input as event choices
			trace.oracle().fuzz_from_bytes()?;

			// Make assertions based on execution trace
			for event in trace.oracle().trace() {
				trace.event(event.0)?;
			}
			Ok(())
		}
	}
}

//! Simple 3-state workflow fuzz target for AFL
//!
//! Run with:
//!   cargo install cargo-afl
//!   cargo afl build --test simple_workflow --features "std,testing-csp"
//!   mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/deps/simple_workflow-*

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::utils::urn::Urn;
use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

const START: Urn<'static> = Urn::new("fuzz", "event:simple/start");
const ACTION_A: Urn<'static> = Urn::new("fuzz", "event:simple/action-a");
const ACTION_B: Urn<'static> = Urn::new("fuzz", "event:simple/action-b");
const DONE: Urn<'static> = Urn::new("fuzz", "event:simple/done");

tb_assert_spec! {
	pub SimpleFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(START, exactly!(1)),
			(ACTION_A, at_least!(0)),
			(ACTION_B, at_least!(0)),
			(DONE, exactly!(1))
		]
	},
}

tb_process_spec! {
	pub SimpleFuzzProc,
	events {
		observable { START, ACTION_A, ACTION_B, DONE }
		hidden { }
	}
	states {
		S0 => { START => S1 },
		S1 => { ACTION_A => S1, ACTION_B => S1, DONE => S2 }
	}
	terminal { S2 }
}

tb_scenario! {
	fuzz: afl,
	csp: SimpleFuzzProc,
	config: ScenarioConfig::builder()
		.with_spec(SimpleFuzzSpec::latest())
		.with_csp(SimpleFuzzProc)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Oracle-guided fuzzing: interprets AFL input as event choices
			trace.oracle().fuzz_from_bytes()?;

			// Make assertions based on execution trace
			for event in trace.oracle().trace() {
				trace.event(*event)?;
			}

			Ok(())
		}
	}
}

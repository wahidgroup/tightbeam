//! A simple three-state workflow fuzz target for AFL.
//!
//! Run it with these commands:
//!   cargo install cargo-afl
//!   cargo afl build --bin fuzz_simple_workflow --features "std,testing-fuzz"
//!   mkdir -p fuzz_in && echo "seed" > fuzz_in/seed.txt
//!   cargo afl fuzz -i fuzz_in -o fuzz_out target/debug/fuzz_simple_workflow

#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "testing-csp"))]

use tightbeam::testing::fuzz::OracleAccess;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

const START: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/start");
const ACTION_A: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/action-a");
const ACTION_B: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/action-b");
const DONE: Urn<'static> = tightbeam::urn!("fuzz", "event:simple/done");

tb_assert_spec! {
	pub SimpleFuzzSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(START, exactly!(1)),
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
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The oracle reads the AFL input as event choices.
			let oracle = trace.oracle();
			oracle.fuzz_from_bytes()?;

			// The collector records the oracle trace, which the spec checks.
			for event in oracle.trace() {
				trace.collector().event(event)?;
			}

			Ok::<(), tightbeam::TightBeamError>(())
		}
	}
}

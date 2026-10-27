//! The tennis scoring tests.
//!
//! They refine traces against the tennis scoring CSP process:
//! - A trace that A wins refines the process.
//! - A trace that scores a point after the game ends fails refinement.
//! - A trace through deuce and advantage refines the process.
//! - A partial game passes failures refinement.

#![cfg(feature = "testing-fdr")]

use core::error::Error;

use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::{fdr::FdrConfig, specs::csp::Process, Expect, Layer, ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

pub(crate) const POINTA: Urn<'static> = tightbeam::urn!("test", "event:tennis/pointa");
pub(crate) const POINTB: Urn<'static> = tightbeam::urn!("test", "event:tennis/pointb");

fn build_fdr_config(
	specs: impl IntoIterator<Item = Process>,
	seeds: u32,
	max_depth: usize,
	max_internal_run: usize,
	timeout_ms: u64,
) -> FdrConfig {
	let specs: Vec<Process> = specs.into_iter().collect();
	FdrConfig {
		seeds,
		max_depth,
		max_internal_run,
		timeout_ms,
		specs,
		fail_fast: true,
		..Default::default()
	}
}

/// The configuration that grades `spec`, refines the run against
/// [`TennisScorer`] under the bounds that every tennis scenario takes, and
/// expects `expect`.
fn tennis_config(spec: &'static BuiltAssertSpec, expect: Expect) -> Result<ScenarioConfig, Box<dyn Error>> {
	let fdr = build_fdr_config(vec![TennisScorer::process()?], 4, 16, 8, 500);
	let builder = ScenarioConfig::builder().with_spec(spec).with_fdr(fdr);
	Ok(builder.with_expect(expect).build()?)
}

// The tennis scoring process.

tb_process_spec! {
	/// The tennis scoring CSP process of one game.
	///
	/// Its states are:
	/// - A state per score pair, such as (0,0), (15,0), (40,15), and (30,40).
	/// - The special states Deuce, AdvantageA, and AdvantageB.
	/// - The terminal states GameA, which A wins, and GameB, which B wins.
	pub TennisScorer,
	events {
		observable { POINTA, POINTB }
		hidden { }
	}
	states {
		// The game starts at (0,0).
		S0_0 => { POINTA => S15_0, POINTB => S0_15 },
		S15_0 => { POINTA => S30_0, POINTB => S15_15 },
		S0_15 => { POINTA => S15_15, POINTB => S0_30 },
		S30_0 => { POINTA => S40_0, POINTB => S30_15 },
		S15_15 => { POINTA => S30_15, POINTB => S15_30 },
		S0_30 => { POINTA => S15_30, POINTB => S0_40 },
		// At (40,0), the next point of A wins the game, or B scores.
		S40_0 => { POINTA => GameA, POINTB => S40_15 },
		S30_15 => { POINTA => S40_15, POINTB => S30_30 },
		S15_30 => { POINTA => S30_30, POINTB => S15_40 },
		// At (0,40), the next point of B wins the game, or A scores.
		S0_40 => { POINTA => S15_40, POINTB => GameB },
		S40_15 => { POINTA => GameA, POINTB => S40_30 },
		S30_30 => { POINTA => S40_30, POINTB => S30_40 },
		S15_40 => { POINTA => S30_40, POINTB => GameB },
		// At (40,30), the next point of A wins the game, or B brings Deuce.
		S40_30 => { POINTA => GameA, POINTB => Deuce },
		// At (30,40), the next point of B wins the game, or A brings Deuce.
		S30_40 => { POINTA => Deuce, POINTB => GameB },

		// From Deuce, a player wins with two points in a row.
		Deuce => { POINTA => AdvantageA, POINTB => AdvantageB },
		AdvantageA => { POINTA => GameA, POINTB => Deuce },
		AdvantageB => { POINTA => Deuce, POINTB => GameB },

		GameA => {},
		GameB => {}
	}
	terminal { GameA, GameB }
	annotations { description: "Tennis game scoring system" }
}

// Test 1: a trace that A wins refines the process.

// In the valid trace, A scores twice, B once, and A twice, so A wins. The
// score runs (0,0), (15,0), (30,0), (30,15), (40,15), and then GameA.
tb_assert_spec! {
	pub ValidTennisSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POINTA, exactly!(4)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_tennis_valid_trace_refinement,
	config: tennis_config(ValidTennisSpec::latest(), Expect::Pass),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The points go A, A, B, A, A, and A wins the game.
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			Ok(())
		}
	}
}

// Test 2: a trace that scores a point after the game ends fails refinement.

// A wins the game with four points in a row, and then B scores. GameA is
// terminal, so the process has no trace with a point after it. The trace
// holds four points for A and one for B, as the valid trace of Test 1 does,
// so the assertion spec passes it, and refinement alone refuses the order.
tb_assert_spec! {
	pub InvalidTennisSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POINTA, exactly!(4)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_tennis_invalid_trace_refinement,
	config: tennis_config(InvalidTennisSpec::latest(), Expect::Violation(Layer::Refinement)),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The points go A, A, A, A, and A wins the game. The point of B
			// comes after the end of the game.
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			Ok(())
		}
	}
}

// Test 3: a trace through deuce and advantage refines the process.

// The trace alternates A and B for six points, and then A scores twice. The
// score runs (0,0), (15,0), (15,15), (30,15), (30,30), (40,30), Deuce,
// AdvantageA, and then GameA.
tb_assert_spec! {
	pub DeuceTennisSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POINTA, exactly!(5)),
			(POINTB, exactly!(3))
		]
	},
}

tb_scenario! {
	name: test_tennis_deuce_to_advantage,
	config: tennis_config(DeuceTennisSpec::latest(), Expect::Pass),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The points go A, B, A, B, A, B, A, A, and A wins through Deuce.
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			Ok(())
		}
	}
}

// Test 4: a partial game passes failures refinement.

// The partial game takes three points and stays open at (30,15).
tb_assert_spec! {
	pub FailuresTennisSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POINTA, exactly!(2)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_failures_refinement,
	config: tennis_config(FailuresTennisSpec::latest(), Expect::Pass),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// The points go A, B, A, and the game stays open.
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			Ok(())
		}
	}
}

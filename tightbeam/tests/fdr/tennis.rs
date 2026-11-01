//! The tennis scoring tests.
//!
//! They refine traces against the tennis scoring CSP process:
//! - A trace that A wins refines the process.
//! - A trace that scores a point after the game ends fails refinement.
//! - A trace through deuce and advantage refines the process.
//! - A partial game refines the traces of the process.
//!
//! A recorded trace carries no refusals, so a model answers failures
//! refinement: the process refines itself, and a scorer that stops mid-game
//! keeps the traces of the process and breaks its failures.

#![cfg(feature = "testing-fdr")]

use core::error::Error;
use std::collections::HashSet;

use tightbeam::testing::fdr::{Decision, DefaultFdrExplorer, Failure, FdrConfig};
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError};
use tightbeam::testing::{Expect, Layer, ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_cases, tb_process_spec, tb_scenario};

use crate::common::result::TestResult;

pub(crate) const POINTA: Urn<'static> = tightbeam::urn!("test", "event:tennis/pointa");
pub(crate) const POINTB: Urn<'static> = tightbeam::urn!("test", "event:tennis/pointb");

/// The bound of a failures check, which reaches Deuce and the advantage after
/// it. The check compares each failure of the subject with the failures of
/// the spec, so a longer bound adds work and reaches no new state.
const GAME_DEPTH: usize = 8;

/// The builder of a scorer model.
type Scorer = fn() -> Result<Process, ProcessBuildError>;

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

// Test 4: a partial game refines the traces of the process.

// The partial game takes three points and stays open at (30,15). A recorded
// trace names no refusal, so its stop at an open score breaks no trace.
tb_assert_spec! {
	pub PartialGameSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(POINTA, exactly!(2)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: a_partial_game_refines_the_traces_of_the_process,
	config: tennis_config(PartialGameSpec::latest(), Expect::Pass),
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

// Test 5: failures refinement reads what a scorer refuses.

tb_process_spec! {
	/// The scorer of [`TennisScorer`] that stops at (30,0), where the game is
	/// open and each player can score. It performs no trace that the game
	/// lacks, so its refusals alone tell it from the game.
	pub StallingScorer,
	events {
		observable { POINTA, POINTB }
		hidden { }
	}
	states {
		S0_0 => { POINTA => S15_0, POINTB => S0_15 },
		S15_0 => { POINTA => S30_0, POINTB => S15_15 },
		S0_15 => { POINTA => S15_15, POINTB => S0_30 },
		// The game offers two points here, and this scorer offers none.
		S30_0 => {},
		S15_15 => { POINTA => S30_15, POINTB => S15_30 },
		S0_30 => { POINTA => S15_30, POINTB => S0_40 },
		S30_15 => { POINTA => S40_15, POINTB => S30_30 },
		S15_30 => { POINTA => S30_30, POINTB => S15_40 },
		S0_40 => { POINTA => S15_40, POINTB => GameB },
		S40_15 => { POINTA => GameA, POINTB => S40_30 },
		S30_30 => { POINTA => S40_30, POINTB => S30_40 },
		S15_40 => { POINTA => S30_40, POINTB => GameB },
		S40_30 => { POINTA => GameA, POINTB => Deuce },
		S30_40 => { POINTA => Deuce, POINTB => GameB },
		Deuce => { POINTA => AdvantageA, POINTB => AdvantageB },
		AdvantageA => { POINTA => GameA, POINTB => Deuce },
		AdvantageB => { POINTA => Deuce, POINTB => GameB },
		GameA => {},
		GameB => {}
	}
	terminal { GameA, GameB }
}

/// The failure of [`StallingScorer`]: after two points of A, it refuses each
/// point.
fn stalled_at_thirty_love() -> Failure {
	let (point_a, point_b) = (Event::from(POINTA), Event::from(POINTB));
	(vec![point_a, point_a], HashSet::from([point_a, point_b]))
}

// Each scorer performs the traces of the game alone, so trace refinement holds
// for each, and failures refinement tells a scorer that stops from the game.
tb_cases! {
	fn failures_refinement_reads_what_a_scorer_refuses(
		(scorer, failures_refine, witness): (Scorer, Decision, Option<Failure>)
	) -> TestResult {
		let subject = scorer()?;
		let specs = vec![TennisScorer::process()?];
		let config = FdrConfig { specs, max_depth: GAME_DEPTH, ..FdrConfig::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore()?;
		let decided = (verdict.trace_refines, verdict.failures_refines, verdict.failures_refinement_witness);
		assert_eq!(decided, (Decision::Holds, failures_refine, witness));
		Ok(())
	}
	cases {
		/// The game offers what the game offers after each trace.
		the_game_itself => (TennisScorer::process, Decision::Holds, None),
		/// The stalling scorer refuses each point at (30,0), where the game
		/// refuses none.
		a_scorer_that_stops_mid_game => (StallingScorer::process, Decision::Refuted, Some(stalled_at_thirty_love())),
	}
}

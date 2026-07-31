//! Tennis Game Scoring System tests
//!
//! Tests for the tennis scoring CSP process, including:
//! - Valid trace refinement
//! - Invalid trace refinement
//! - Deuce to advantage scenarios
//! - Failures refinement

#![cfg(feature = "testing-fdr")]

use tightbeam::testing::{fdr::FdrConfig, specs::csp::Process, ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

pub(crate) const POINTA: Urn<'static> = Urn::new("test", "event:tennis/pointa");
pub(crate) const POINTB: Urn<'static> = Urn::new("test", "event:tennis/pointb");

fn build_fdr_config(
	specs: Vec<Process>,
	seeds: u32,
	max_depth: usize,
	max_internal_run: usize,
	timeout_ms: u64,
) -> FdrConfig {
	FdrConfig {
		seeds,
		max_depth,
		max_internal_run,
		timeout_ms,
		specs,
		fail_fast: true,
		expect_failure: false,
		..Default::default()
	}
}

// ===== Tennis Game Scoring System =====

tb_process_spec! {
	/// Tennis Game Scoring System CSP Process
	///
	/// Models tennis scoring with states:
	/// - Score pairs: (0,0), (15,0), (30,0), (40,0), (40,15), (40,30)
	/// - Special states: Deuce, AdvantageA, AdvantageB
	/// - Terminal states: GameA (A wins), GameB (B wins)
	///
	/// Events: pointA, pointB
	pub TennisScorer,
	events {
		observable { POINTA, POINTB }
		hidden { }
	}
	states {
		// Initial state: (0,0)
		S0_0 => { POINTA => S15_0, POINTB => S0_15 },
		// Score (15,0)
		S15_0 => { POINTA => S30_0, POINTB => S15_15 },
		// Score (0,15)
		S0_15 => { POINTA => S15_15, POINTB => S0_30 },
		// Score (30,0)
		S30_0 => { POINTA => S40_0, POINTB => S30_15 },
		// Score (15,15)
		S15_15 => { POINTA => S30_15, POINTB => S15_30 },
		// Score (0,30)
		S0_30 => { POINTA => S15_30, POINTB => S0_40 },
		// Score (40,0) - A can win or B can score
		S40_0 => { POINTA => GameA, POINTB => S40_15 },
		// Score (30,15)
		S30_15 => { POINTA => S40_15, POINTB => S30_30 },
		// Score (15,30)
		S15_30 => { POINTA => S30_30, POINTB => S15_40 },
		// Score (0,40) - B can win or A can score
		S0_40 => { POINTA => S15_40, POINTB => GameB },
		// Score (40,15)
		S40_15 => { POINTA => GameA, POINTB => S40_30 },
		// Score (30,30)
		S30_30 => { POINTA => S40_30, POINTB => S30_40 },
		// Score (15,40)
		S15_40 => { POINTA => S30_40, POINTB => GameB },
		// Score (40,30) - A can win or go to Deuce
		S40_30 => { POINTA => GameA, POINTB => Deuce },
		// Score (30,40) - B can win or go to Deuce
		S30_40 => { POINTA => Deuce, POINTB => GameB },

		// Deuce state
		Deuce => { POINTA => AdvantageA, POINTB => AdvantageB },
		// Advantage A
		AdvantageA => { POINTA => GameA, POINTB => Deuce },
		// Advantage B
		AdvantageB => { POINTA => Deuce, POINTB => GameB },

		// Terminal states
		GameA => {},
		GameB => {}
	}
	terminal { GameA, GameB }
	annotations { description: "Tennis game scoring system" }
}

// ===== Test 1: Tennis Game - Valid Trace Refinement =====

// Define assertion spec for valid trace: pointA -> pointA -> pointB -> pointA -> pointA (A wins)
// Score progression: (0,0) -> (15,0) -> (30,0) -> (30,15) -> (40,15) -> GameA
tb_assert_spec! {
	pub ValidTennisSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(POINTA, exactly!(4)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_tennis_valid_trace_refinement,
	config: ScenarioConfig::builder()
		.with_spec(ValidTennisSpec::latest())
		.with_fdr(build_fdr_config(
			vec![TennisScorer::process()],
			4,
			16,
			8,
			500,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Valid trace: pointA -> pointA -> pointB -> pointA -> pointA (A wins)
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			trace.event(POINTA)?;
			Ok(())
		}
	}
}

// ===== Test 2: Tennis Game - Invalid Trace Refinement =====

// Define assertion spec for invalid trace: pointA -> pointB -> pointB -> pointB -> pointB
// This is impossible because after (0,40), B should win, not continue scoring
tb_assert_spec! {
	pub InvalidTennisSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(POINTA, exactly!(1)),
			(POINTB, exactly!(4))
		]
	},
}

tb_scenario! {
	name: test_tennis_invalid_trace_refinement,
	config: ScenarioConfig::builder()
		.with_spec(InvalidTennisSpec::latest())
		.with_fdr(build_fdr_config(
			vec![TennisScorer::process()],
			4,
			16,
			8,
			500,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Invalid trace: pointA -> pointB -> pointB -> pointB -> pointB
			// This violates the tennis scoring rules - after (0,40), B should win
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTB)?;
			trace.event(POINTB)?;
			trace.event(POINTB)?;
			Ok(())
		}
	}
}

// ===== Test 3: Tennis Game - Deuce to Advantage Trace =====

// Define assertion spec for complex valid trace going through deuce
// Valid trace: pointA -> pointB -> pointA -> pointB -> pointA -> pointB -> pointA -> pointA
// Score progression: (0,0) -> (15,0) -> (15,15) -> (30,15) -> (30,30) -> (40,30) -> Deuce -> AdvantageA -> GameA
tb_assert_spec! {
	pub DeuceTennisSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(POINTA, exactly!(5)),
			(POINTB, exactly!(3))
		]
	},
}

tb_scenario! {
	name: test_tennis_deuce_to_advantage,
	config: ScenarioConfig::builder()
		.with_spec(DeuceTennisSpec::latest())
		.with_fdr(build_fdr_config(
			vec![TennisScorer::process()],
			4,
			16,
			8,
			500,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Valid trace going through deuce: pointA -> pointB -> pointA -> pointB -> pointA -> pointB -> pointA -> pointA
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

// ===== Test 4: Failures Refinement =====

// Create a trace that should pass failures refinement
tb_assert_spec! {
	pub FailuresTennisSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(POINTA, exactly!(2)),
			(POINTB, exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_failures_refinement,
	config: ScenarioConfig::builder()
		.with_spec(FailuresTennisSpec::latest())
		.with_fdr(build_fdr_config(
			vec![TennisScorer::process()],
			4,
			16,
			8,
			500,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Create a trace that should pass failures refinement
			trace.event(POINTA)?;
			trace.event(POINTB)?;
			trace.event(POINTA)?;
			Ok(())
		}
	}
}

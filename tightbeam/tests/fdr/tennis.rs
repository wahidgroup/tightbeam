//! Tennis Game Scoring System tests
//!
//! Tests for the tennis scoring CSP process, including:
//! - Valid trace refinement
//! - Invalid trace refinement
//! - Deuce to advantage scenarios
//! - Failures refinement

#![cfg(feature = "testing-fdr")]

use tightbeam::testing::{fdr::FdrConfig, specs::csp::Process, ScenarioConf};
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

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
		observable { "pointA", "pointB" }
		hidden { }
	}
	states {
		// Initial state: (0,0)
		S0_0 => { "pointA" => S15_0, "pointB" => S0_15 },
		// Score (15,0)
		S15_0 => { "pointA" => S30_0, "pointB" => S15_15 },
		// Score (0,15)
		S0_15 => { "pointA" => S15_15, "pointB" => S0_30 },
		// Score (30,0)
		S30_0 => { "pointA" => S40_0, "pointB" => S30_15 },
		// Score (15,15)
		S15_15 => { "pointA" => S30_15, "pointB" => S15_30 },
		// Score (0,30)
		S0_30 => { "pointA" => S15_30, "pointB" => S0_40 },
		// Score (40,0) - A can win or B can score
		S40_0 => { "pointA" => GameA, "pointB" => S40_15 },
		// Score (30,15)
		S30_15 => { "pointA" => S40_15, "pointB" => S30_30 },
		// Score (15,30)
		S15_30 => { "pointA" => S30_30, "pointB" => S15_40 },
		// Score (0,40) - B can win or A can score
		S0_40 => { "pointA" => S15_40, "pointB" => GameB },
		// Score (40,15)
		S40_15 => { "pointA" => GameA, "pointB" => S40_30 },
		// Score (30,30)
		S30_30 => { "pointA" => S40_30, "pointB" => S30_40 },
		// Score (15,40)
		S15_40 => { "pointA" => S30_40, "pointB" => GameB },
		// Score (40,30) - A can win or go to Deuce
		S40_30 => { "pointA" => GameA, "pointB" => Deuce },
		// Score (30,40) - B can win or go to Deuce
		S30_40 => { "pointA" => Deuce, "pointB" => GameB },

		// Deuce state
		Deuce => { "pointA" => AdvantageA, "pointB" => AdvantageB },
		// Advantage A
		AdvantageA => { "pointA" => GameA, "pointB" => Deuce },
		// Advantage B
		AdvantageB => { "pointA" => Deuce, "pointB" => GameB },

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
		gate: Accepted,
		assertions: [
			("pointA", exactly!(4)),
			("pointB", exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_tennis_valid_trace_refinement,
	config: ScenarioConf::<()>::builder()
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
		exec: |trace| {
			// Valid trace: pointA -> pointA -> pointB -> pointA -> pointA (A wins)
			trace.event("pointA")?;
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointA")?;
			trace.event("pointA")?;
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
		gate: Accepted,
		assertions: [
			("pointA", exactly!(1)),
			("pointB", exactly!(4))
		]
	},
}

tb_scenario! {
	name: test_tennis_invalid_trace_refinement,
	config: ScenarioConf::<()>::builder()
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
		exec: |trace| {
			// Invalid trace: pointA -> pointB -> pointB -> pointB -> pointB
			// This violates the tennis scoring rules - after (0,40), B should win
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointB")?;
			trace.event("pointB")?;
			trace.event("pointB")?;
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
		gate: Accepted,
		assertions: [
			("pointA", exactly!(5)),
			("pointB", exactly!(3))
		]
	},
}

tb_scenario! {
	name: test_tennis_deuce_to_advantage,
	config: ScenarioConf::<()>::builder()
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
		exec: |trace| {
			// Valid trace going through deuce: pointA -> pointB -> pointA -> pointB -> pointA -> pointB -> pointA -> pointA
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointA")?;
			trace.event("pointA")?;
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
		gate: Accepted,
		assertions: [
			("pointA", exactly!(2)),
			("pointB", exactly!(1))
		]
	},
}

tb_scenario! {
	name: test_failures_refinement,
	config: ScenarioConf::<()>::builder()
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
		exec: |trace| {
			// Create a trace that should pass failures refinement
			trace.event("pointA")?;
			trace.event("pointB")?;
			trace.event("pointA")?;
			Ok(())
		}
	}
}

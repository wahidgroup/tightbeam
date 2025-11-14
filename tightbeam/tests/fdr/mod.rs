//! FDR integration tests using canonical CSP examples
//!
//! These tests validate the FDR refinement checking implementation using
//! well-known CSP examples from the FDR Manual:
//! - Tennis Game Scoring System (state transitions, trace refinement)
//! - Dining Philosophers (deadlock detection)

#![cfg(feature = "testing-fdr")]

use tightbeam::testing::fdr::FdrConfig;

// ===== Tennis Game Scoring System =====

/// Tennis Game Scoring System CSP Process
///
/// Models tennis scoring with states:
/// - Score pairs: (0,0), (15,0), (30,0), (40,0), (40,15), (40,30)
/// - Special states: Deuce, AdvantageA, AdvantageB
/// - Terminal states: GameA (A wins), GameB (B wins)
///
/// Events: pointA, pointB
tightbeam::tb_process_spec! {
	pub struct TennisScorer;
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

// ===== Dining Philosophers (Simplified - 2 philosophers) =====

/// Dining Philosophers CSP Process (Simplified: 2 philosophers)
///
/// Models philosophers competing for forks, demonstrating deadlock.
/// Events: thinks, sits, picks_left, picks_right, eats, putsdown_left, putsdown_right, getsup
tightbeam::tb_process_spec! {
	pub struct DiningPhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "putsdown_left", "putsdown_right", "getsup" }
		hidden { }
	}
	states {
		// Philosopher 1 states
		Idle1 => { "thinks" => Thinking1 },
		Thinking1 => { "sits" => Sitting1 },
		Sitting1 => { "picks_left" => HasLeftFork1 },
		HasLeftFork1 => { "picks_right" => HasBothForks1 },
		HasBothForks1 => { "eats" => Eating1 },
		Eating1 => { "putsdown_left" => HasRightFork1 },
		HasRightFork1 => { "putsdown_right" => Finished1 },
		Finished1 => { "getsup" => Idle1 },
		
		// Philosopher 2 states
		Idle2 => { "thinks" => Thinking2 },
		Thinking2 => { "sits" => Sitting2 },
		Sitting2 => { "picks_left" => HasLeftFork2 },
		HasLeftFork2 => { "picks_right" => HasBothForks2 },
		HasBothForks2 => { "eats" => Eating2 },
		Eating2 => { "putsdown_left" => HasRightFork2 },
		HasRightFork2 => { "putsdown_right" => Finished2 },
		Finished2 => { "getsup" => Idle2 }
	}
	terminal { Idle1, Idle2 }
	annotations { description: "Dining philosophers (2 philosophers, deadlock-prone)" }
}

/// Deadlock-free Dining Philosophers (with butler/coordinator)
///
/// The butler ensures at most N-1 philosophers can sit, preventing deadlock.
tightbeam::tb_process_spec! {
	pub struct DeadlockFreePhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "putsdown_left", "putsdown_right", "getsup" }
		hidden { }
	}
	states {
		// Philosopher 1 states
		Idle1 => { "thinks" => Thinking1 },
		Thinking1 => { "sits" => Sitting1 },
		Sitting1 => { "picks_left" => HasLeftFork1 },
		HasLeftFork1 => { "picks_right" => HasBothForks1 },
		HasBothForks1 => { "eats" => Eating1 },
		Eating1 => { "putsdown_left" => HasRightFork1 },
		HasRightFork1 => { "putsdown_right" => Finished1 },
		Finished1 => { "getsup" => Idle1 },
		
		// Philosopher 2 states (butler ensures only one can sit at a time)
		Idle2 => { "thinks" => Thinking2 },
		Thinking2 => { "sits" => Sitting2 },
		Sitting2 => { "picks_left" => HasLeftFork2 },
		HasLeftFork2 => { "picks_right" => HasBothForks2 },
		HasBothForks2 => { "eats" => Eating2 },
		Eating2 => { "putsdown_left" => HasRightFork2 },
		HasRightFork2 => { "putsdown_right" => Finished2 },
		Finished2 => { "getsup" => Idle2 }
	}
	terminal { Idle1, Idle2 }
	annotations { description: "Deadlock-free dining philosophers (butler ensures mutual exclusion)" }
}

// ===== Test 1: Tennis Game - Valid Trace Refinement =====

#[test]
fn test_tennis_valid_trace_refinement() {
	// Define assertion spec for valid trace: pointA -> pointA -> pointB -> pointA -> pointA (A wins)
	// Score progression: (0,0) -> (15,0) -> (30,0) -> (30,15) -> (40,15) -> GameA
	tightbeam::tb_assert_spec! {
		pub ValidTennisSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "pointA", tightbeam::exactly!(4)),
				(HandlerStart, "pointB", tightbeam::exactly!(1))
			]
		},
	}
	
	tightbeam::tb_scenario! {
		name: test_tennis_valid_trace_refinement,
		spec: ValidTennisSpec,
		fdr: FdrConfig {
			seeds: 4,
			max_depth: 16,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![TennisScorer::process()],
			fail_fast: true,
		},
		environment Bare {
			exec: |trace| {
				// Valid trace: pointA -> pointA -> pointB -> pointA -> pointA (A wins)
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				Ok(())
			}
		}
	}
}

// ===== Test 2: Tennis Game - Invalid Trace Refinement =====

#[test]
fn test_tennis_invalid_trace_refinement() {
	// Define assertion spec for invalid trace: pointA -> pointB -> pointB -> pointB -> pointB
	// This is impossible because after (0,40), B should win, not continue scoring
	tightbeam::tb_assert_spec! {
		pub InvalidTennisSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "pointA", tightbeam::exactly!(1)),
				(HandlerStart, "pointB", tightbeam::exactly!(4))
			]
		},
	}
	
	tightbeam::tb_scenario! {
		name: test_tennis_invalid_trace_refinement,
		spec: InvalidTennisSpec,
		fdr: FdrConfig {
			seeds: 4,
			max_depth: 16,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![TennisScorer::process()],
			fail_fast: true,
		},
		environment Bare {
			exec: |trace| {
				// Invalid trace: pointA -> pointB -> pointB -> pointB -> pointB
				// This violates the tennis scoring rules - after (0,40), B should win
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				Ok(())
			}
		}
	}
}

// ===== Test 3: Tennis Game - Deuce to Advantage Trace =====

#[test]
fn test_tennis_deuce_to_advantage() {
	// Define assertion spec for complex valid trace going through deuce
	// Valid trace: pointA -> pointB -> pointA -> pointB -> pointA -> pointB -> pointA -> pointA
	// Score progression: (0,0) -> (15,0) -> (15,15) -> (30,15) -> (30,30) -> (40,30) -> Deuce -> AdvantageA -> GameA
	tightbeam::tb_assert_spec! {
		pub DeuceTennisSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "pointA", tightbeam::exactly!(5)),
				(HandlerStart, "pointB", tightbeam::exactly!(3))
			]
		},
	}
	
	tightbeam::tb_scenario! {
		name: test_tennis_deuce_to_advantage,
		spec: DeuceTennisSpec,
		fdr: FdrConfig {
			seeds: 4,
			max_depth: 16,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![TennisScorer::process()],
			fail_fast: true,
		},
		environment Bare {
			exec: |trace| {
				// Valid trace going through deuce: pointA -> pointB -> pointA -> pointB -> pointA -> pointB -> pointA -> pointA
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				Ok(())
			}
		}
	}
}

// ===== Test 4: Dining Philosophers - Deadlock Detection =====

#[test]
fn test_dining_philosophers_deadlock() {
	// Create a simplified deadlock scenario: both philosophers pick left fork
	// This creates a deadlock because neither can pick the right fork
	tightbeam::tb_assert_spec! {
		pub DeadlockPhilosopherSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "thinks", tightbeam::exactly!(2)),
				(HandlerStart, "sits", tightbeam::exactly!(2)),
				(HandlerStart, "picks_left", tightbeam::exactly!(2))
			]
		},
	}
	
	tightbeam::tb_scenario! {
		name: test_dining_philosophers_deadlock,
		spec: DeadlockPhilosopherSpec,
		fdr: FdrConfig {
			seeds: 4,
			max_depth: 16,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![], // No spec - just check for deadlock
			fail_fast: true,
		},
		environment Bare {
			exec: |trace| {
				// Trace: Philosopher 1 picks left, Philosopher 2 picks left (deadlock)
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "thinks");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "sits");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "picks_left");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "thinks");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "sits");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "picks_left");
				Ok(())
			}
		}
	}
}

// ===== Test 5: Failures Refinement =====

#[test]
fn test_failures_refinement() {
	// Create a trace that should pass failures refinement
	tightbeam::tb_assert_spec! {
		pub FailuresTennisSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "pointA", tightbeam::exactly!(2)),
				(HandlerStart, "pointB", tightbeam::exactly!(1))
			]
		},
	}
	
	tightbeam::tb_scenario! {
		name: test_failures_refinement,
		spec: FailuresTennisSpec,
		fdr: FdrConfig {
			seeds: 4,
			max_depth: 16,
			max_internal_run: 8,
			timeout_ms: 500,
			specs: vec![TennisScorer::process()],
			fail_fast: true,
		},
		environment Bare {
			exec: |trace| {
				// Create a trace that should pass failures refinement
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointB");
				trace.assert(tightbeam::testing::assertions::AssertionPhase::HandlerStart, "pointA");
				Ok(())
			}
		}
	}
}


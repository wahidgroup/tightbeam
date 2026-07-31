//! Dining Philosophers tests
//!
//! Tests for the dining philosophers CSP process, including:
//! - Deadlock detection scenarios

#![cfg(feature = "testing-fdr")]

use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;

pub(crate) const EATS: Urn<'static> = Urn::new("test", "event:diners/eats");
pub(crate) const GETS_UP: Urn<'static> = Urn::new("test", "event:diners/gets-up");
pub(crate) const PICKS_LEFT: Urn<'static> = Urn::new("test", "event:diners/picks-left");
pub(crate) const PICKS_RIGHT: Urn<'static> = Urn::new("test", "event:diners/picks-right");
pub(crate) const PUTS_DOWN_LEFT: Urn<'static> = Urn::new("test", "event:diners/puts-down-left");
pub(crate) const PUTS_DOWN_RIGHT: Urn<'static> = Urn::new("test", "event:diners/puts-down-right");
pub(crate) const SITS: Urn<'static> = Urn::new("test", "event:diners/sits");
pub(crate) const THINKS: Urn<'static> = Urn::new("test", "event:diners/thinks");

fn build_fdr_config(
	specs: Vec<Process>,
	seeds: u32,
	max_depth: usize,
	max_internal_run: usize,
	timeout_ms: u64,
	expect_failure: bool,
) -> FdrConfig {
	FdrConfig {
		seeds,
		max_depth,
		max_internal_run,
		timeout_ms,
		specs,
		fail_fast: true,
		expect_failure,
		..Default::default()
	}
}

// ===== Dining Philosophers (Simplified - 2 philosophers) =====

tightbeam::tb_process_spec! {
	/// Dining Philosophers CSP Process (Simplified: 2 philosophers)
	///
	/// Models philosophers competing for forks, demonstrating deadlock.
	/// Fork sharing: P1's right fork = P2's left fork, P1's left fork = P2's right fork
	/// Deadlock occurs when both pick their left fork - neither can pick right fork.
	/// Events: thinks, sits, picks_left, picks_right, eats, puts_down_left, puts_down_right, gets_up
	pub DiningPhilosophers,
	events {
		observable { THINKS, SITS, PICKS_LEFT, PICKS_RIGHT, EATS, PUTS_DOWN_LEFT, PUTS_DOWN_RIGHT, GETS_UP }
		hidden { }
	}
	states {
		// Initial: both idle
		BothIdle => { THINKS => P1Thinking_P2Idle, THINKS => P1Idle_P2Thinking },

		// P1 thinking, P2 idle
		P1Thinking_P2Idle => { SITS => P1Sitting_P2Idle, THINKS => BothThinking },
		P1Sitting_P2Idle => { PICKS_LEFT => P1HasLeft_P2Idle, THINKS => P1Sitting_P2Thinking },
		P1HasLeft_P2Idle => { PICKS_RIGHT => P1HasBoth_P2Idle, THINKS => P1HasLeft_P2Thinking, SITS => P1HasLeft_P2Sitting },
		P1HasBoth_P2Idle => { EATS => P1Eating_P2Idle },
		P1Eating_P2Idle => { PUTS_DOWN_LEFT => P1HasRight_P2Idle },
		P1HasRight_P2Idle => { PUTS_DOWN_RIGHT => P1Finished_P2Idle },
		P1Finished_P2Idle => { GETS_UP => P1Idle_P2Idle, THINKS => P1Finished_P2Thinking },
		P1Idle_P2Idle => { THINKS => BothIdle },

		// P1 idle, P2 thinking
		P1Idle_P2Thinking => { SITS => P1Idle_P2Sitting, THINKS => BothThinking },
		P1Idle_P2Sitting => { PICKS_LEFT => P1Idle_P2HasLeft, THINKS => P1Thinking_P2Sitting },
		P1Idle_P2HasLeft => { PICKS_RIGHT => P1Idle_P2HasBoth, THINKS => P1Thinking_P2HasLeft, SITS => P1Sitting_P2HasLeft },
		P1Idle_P2HasBoth => { EATS => P1Idle_P2Eating },
		P1Idle_P2Eating => { PUTS_DOWN_LEFT => P1Idle_P2HasRight },
		P1Idle_P2HasRight => { PUTS_DOWN_RIGHT => P1Idle_P2Finished },
		P1Idle_P2Finished => { GETS_UP => P1Idle_P2Idle, THINKS => P1Thinking_P2Finished },

		// Both thinking
		BothThinking => { SITS => P1Sitting_P2Thinking, SITS => P1Thinking_P2Sitting },

		// P1 sitting, P2 thinking
		P1Sitting_P2Thinking => { PICKS_LEFT => P1HasLeft_P2Thinking, SITS => BothSitting },
		P1HasLeft_P2Thinking => { PICKS_RIGHT => P1HasBoth_P2Thinking, SITS => P1HasLeft_P2Sitting },
		P1HasBoth_P2Thinking => { EATS => P1Eating_P2Thinking },
		P1Eating_P2Thinking => { PUTS_DOWN_LEFT => P1HasRight_P2Thinking },
		P1HasRight_P2Thinking => { PUTS_DOWN_RIGHT => P1Finished_P2Thinking },
		P1Finished_P2Thinking => { GETS_UP => P1Idle_P2Thinking, SITS => P1Finished_P2Sitting },

		// P1 thinking, P2 sitting
		P1Thinking_P2Sitting => { PICKS_LEFT => P1Thinking_P2HasLeft, SITS => BothSitting },
		P1Thinking_P2HasLeft => { PICKS_RIGHT => P1Thinking_P2HasBoth, SITS => P1Sitting_P2HasLeft },
		P1Thinking_P2HasBoth => { EATS => P1Thinking_P2Eating },
		P1Thinking_P2Eating => { PUTS_DOWN_LEFT => P1Thinking_P2HasRight },
		P1Thinking_P2HasRight => { PUTS_DOWN_RIGHT => P1Thinking_P2Finished },
		P1Thinking_P2Finished => { GETS_UP => P1Thinking_P2Idle, SITS => P1Sitting_P2Finished },

		// Both sitting - can both pick left (deadlock possible)
		BothSitting => { PICKS_LEFT => P1HasLeft_P2Sitting, PICKS_LEFT => P1Sitting_P2HasLeft },

		// P1 has left, P2 sitting - P2 can pick left (leading to deadlock) or P1 can pick right
		P1HasLeft_P2Sitting => { PICKS_LEFT => Deadlock, PICKS_RIGHT => P1HasBoth_P2Sitting },
		P1HasBoth_P2Sitting => { EATS => P1Eating_P2Sitting },
		P1Eating_P2Sitting => { PUTS_DOWN_LEFT => P1HasRight_P2Sitting },
		P1HasRight_P2Sitting => { PUTS_DOWN_RIGHT => P1Finished_P2Sitting },
		P1Finished_P2Sitting => { GETS_UP => P1Idle_P2Sitting },

		// P1 sitting, P2 has left - P1 can pick left (leading to deadlock) or P2 can pick right
		P1Sitting_P2HasLeft => { PICKS_LEFT => Deadlock, PICKS_RIGHT => P1Sitting_P2HasBoth },

		// Deadlock: both have left fork - neither can pick right fork
		Deadlock => {}, // Terminal deadlock state - no transitions available
		P1Sitting_P2HasBoth => { EATS => P1Sitting_P2Eating },
		P1Sitting_P2Eating => { PUTS_DOWN_LEFT => P1Sitting_P2HasRight },
		P1Sitting_P2HasRight => { PUTS_DOWN_RIGHT => P1Sitting_P2Finished },
		P1Sitting_P2Finished => { GETS_UP => P1Sitting_P2Idle },

		// P1 has left, P2 has left - deadlock (both need right fork, but it's the same fork)
		P1HasLeft_P2HasLeft => {}, // Terminal deadlock state

		// P1 has left, P2 thinking - P2 can sit and pick left (deadlock) or P1 can pick right
		P1HasLeft_P2Thinking => { PICKS_RIGHT => P1HasBoth_P2Thinking, SITS => P1HasLeft_P2Sitting },

		// P1 thinking, P2 has left - P1 can sit and pick left (deadlock) or P2 can pick right
		P1Thinking_P2HasLeft => { PICKS_RIGHT => P1Thinking_P2HasBoth, SITS => P1Sitting_P2HasLeft },

		// P1 finished, P2 sitting (merge with earlier definition)
		// P1Finished_P2Sitting already defined above, adding transitions here
		// Note: This state transition is already covered by P1Finished_P2Sitting => { GETS_UP => P1Idle_P2Sitting }
		P1Finished_P2HasLeft => { PICKS_RIGHT => P1Finished_P2HasBoth },
		P1Finished_P2HasBoth => { EATS => P1Finished_P2Eating },
		P1Finished_P2Eating => { PUTS_DOWN_LEFT => P1Finished_P2HasRight },
		P1Finished_P2HasRight => { PUTS_DOWN_RIGHT => P1Finished_P2Finished },
		P1Finished_P2Finished => { GETS_UP => P1Finished_P2Idle, GETS_UP => P1Idle_P2Finished },
		P1Finished_P2Idle => { THINKS => BothIdle },
	}
	terminal { BothIdle, Deadlock, P1HasLeft_P2HasLeft, P1Finished_P2Finished }
	annotations { description: "Dining philosophers (2 philosophers, deadlock-prone) - models fork sharing constraint" }
}

tightbeam::tb_process_spec! {
	/// Deadlock-free Dining Philosophers (with butler/coordinator)
	///
	/// The butler ensures at most N-1 philosophers can sit, preventing deadlock.
	/// With 2 philosophers, at most 1 can sit at a time.
	/// This prevents the deadlock scenario where both pick their left fork.
	pub DeadlockFreePhilosophers,
	events {
		observable { THINKS, SITS, PICKS_LEFT, PICKS_RIGHT, EATS, PUTS_DOWN_LEFT, PUTS_DOWN_RIGHT, GETS_UP }
		hidden { }
	}
	states {
		// Initial: both idle
		BothIdleDF => { THINKS => P1Thinking_P2IdleDF, THINKS => P1Idle_P2ThinkingDF },

		// P1 thinking, P2 idle - P1 can sit (butler allows)
		P1Thinking_P2IdleDF => { SITS => P1Sitting_P2IdleDF, THINKS => BothThinkingDF },
		P1Sitting_P2IdleDF => { PICKS_LEFT => P1HasLeft_P2IdleDF, THINKS => P1Sitting_P2ThinkingDF },
		P1HasLeft_P2IdleDF => { PICKS_RIGHT => P1HasBoth_P2IdleDF, THINKS => P1HasLeft_P2ThinkingDF },
		P1HasBoth_P2IdleDF => { EATS => P1Eating_P2IdleDF },
		P1Eating_P2IdleDF => { PUTS_DOWN_LEFT => P1HasRight_P2IdleDF },
		P1HasRight_P2IdleDF => { PUTS_DOWN_RIGHT => P1Finished_P2IdleDF },
		P1Finished_P2IdleDF => { GETS_UP => P1Idle_P2IdleDF, THINKS => P1Finished_P2ThinkingDF },
		// P1 idle, P2 idle - either can think (both are idle, no constraints)
		P1Idle_P2IdleDF => { THINKS => BothIdleDF, THINKS => P1Idle_P2ThinkingDF },

		// P1 idle, P2 thinking - P2 can sit (butler allows, P1 not sitting)
		P1Idle_P2ThinkingDF => { SITS => P1Idle_P2SittingDF, THINKS => BothThinkingDF },
		P1Idle_P2SittingDF => { PICKS_LEFT => P1Idle_P2HasLeftDF, THINKS => P1Thinking_P2SittingDF },
		P1Idle_P2HasLeftDF => { PICKS_RIGHT => P1Idle_P2HasBothDF, THINKS => P1Thinking_P2HasLeftDF },
		P1Idle_P2HasBothDF => { EATS => P1Idle_P2EatingDF },
		P1Idle_P2EatingDF => { PUTS_DOWN_LEFT => P1Idle_P2HasRightDF },
		P1Idle_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Idle_P2FinishedDF },
		P1Idle_P2FinishedDF => { GETS_UP => P1Idle_P2IdleDF, THINKS => P1Thinking_P2FinishedDF },

		// Both thinking - only one can sit (butler constraint)
		BothThinkingDF => { SITS => P1Sitting_P2ThinkingDF, SITS => P1Thinking_P2SittingDF },

		// P1 sitting, P2 thinking - P2 CANNOT sit (butler prevents both sitting)
		// P2 can think but cannot sit while P1 is sitting
		P1Sitting_P2ThinkingDF => { PICKS_LEFT => P1HasLeft_P2ThinkingDF, THINKS => P1Sitting_P2IdleDF },
		P1Sitting_P2IdleDF => { THINKS => P1Sitting_P2ThinkingDF },
		P1HasLeft_P2ThinkingDF => { PICKS_RIGHT => P1HasBoth_P2ThinkingDF },
		P1HasBoth_P2ThinkingDF => { EATS => P1Eating_P2ThinkingDF },
		P1Eating_P2ThinkingDF => { PUTS_DOWN_LEFT => P1HasRight_P2ThinkingDF },
		P1HasRight_P2ThinkingDF => { PUTS_DOWN_RIGHT => P1Finished_P2ThinkingDF },
		P1Finished_P2ThinkingDF => { GETS_UP => P1Idle_P2ThinkingDF },

		// P1 thinking, P2 sitting - P1 CANNOT sit (butler prevents both sitting)
		// P1 can think but cannot sit while P2 is sitting
		P1Thinking_P2SittingDF => { PICKS_LEFT => P1Thinking_P2HasLeftDF, THINKS => P1Idle_P2SittingDF },
		P1Idle_P2SittingDF => { THINKS => P1Thinking_P2SittingDF },
		P1Thinking_P2HasLeftDF => { PICKS_RIGHT => P1Thinking_P2HasBothDF },
		P1Thinking_P2HasBothDF => { EATS => P1Thinking_P2EatingDF },
		P1Thinking_P2EatingDF => { PUTS_DOWN_LEFT => P1Thinking_P2HasRightDF },
		P1Thinking_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Thinking_P2FinishedDF },
		P1Thinking_P2FinishedDF => { GETS_UP => P1Thinking_P2IdleDF },

		// P1 finished, P2 thinking - P2 can now sit (P1 not sitting)
		P1Finished_P2ThinkingDF => { SITS => P1Finished_P2SittingDF },
		P1Finished_P2SittingDF => { PICKS_LEFT => P1Finished_P2HasLeftDF },
		P1Finished_P2HasLeftDF => { PICKS_RIGHT => P1Finished_P2HasBothDF },
		P1Finished_P2HasBothDF => { EATS => P1Finished_P2EatingDF },
		P1Finished_P2EatingDF => { PUTS_DOWN_LEFT => P1Finished_P2HasRightDF },
		P1Finished_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Finished_P2FinishedDF },
		P1Finished_P2FinishedDF => { GETS_UP => P1Finished_P2IdleDF, GETS_UP => P1Idle_P2FinishedDF },
		P1Finished_P2IdleDF => { THINKS => BothIdleDF },

		// P1 thinking, P2 finished - P1 can now sit (P2 not sitting)
		P1Thinking_P2FinishedDF => { SITS => P1Sitting_P2FinishedDF },
		P1Sitting_P2FinishedDF => { PICKS_LEFT => P1HasLeft_P2FinishedDF },
		P1HasLeft_P2FinishedDF => { PICKS_RIGHT => P1HasBoth_P2FinishedDF },
		P1HasBoth_P2FinishedDF => { EATS => P1Eating_P2FinishedDF },
		P1Eating_P2FinishedDF => { PUTS_DOWN_LEFT => P1HasRight_P2FinishedDF },
		P1HasRight_P2FinishedDF => { PUTS_DOWN_RIGHT => P1Finished_P2FinishedDF },
		P1Idle_P2FinishedDF => { THINKS => BothIdleDF },
	}
	terminal { BothIdleDF, P1Finished_P2FinishedDF }
	annotations { description: "Deadlock-free dining philosophers (butler ensures mutual exclusion - only one can sit at a time)" }
}

// ===== Test 1: Valid Trace Refinement =====

// Define assertion spec for valid trace: one philosopher completes full cycle
tightbeam::tb_assert_spec! {
	pub ValidPhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(THINKS, tightbeam::exactly!(1)),
			(SITS, tightbeam::exactly!(1)),
			(PICKS_LEFT, tightbeam::exactly!(1)),
			(PICKS_RIGHT, tightbeam::exactly!(1)),
			(EATS, tightbeam::exactly!(1)),
			(PUTS_DOWN_LEFT, tightbeam::exactly!(1)),
			(PUTS_DOWN_RIGHT, tightbeam::exactly!(1)),
			(GETS_UP, tightbeam::exactly!(1))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_valid_trace_refinement,
	config: ScenarioConfig::builder()
		.with_spec(ValidPhilosopherSpec::latest())
		.with_fdr(build_fdr_config(
			vec![DiningPhilosophers::process()],
			4,
			16,
			8,
			500,
			false,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Valid trace: one philosopher completes full cycle
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(PICKS_RIGHT)?;
			trace.event(EATS)?;
			trace.event(PUTS_DOWN_LEFT)?;
			trace.event(PUTS_DOWN_RIGHT)?;
			trace.event(GETS_UP)?;
			Ok(())
		}
	}
}

// ===== Test 2: Deadlock Trace Refinement =====

// Create a deadlock scenario: both philosophers pick left fork
// This trace should refine DiningPhilosophers (spec allows deadlock)
tightbeam::tb_assert_spec! {
	pub DeadlockPhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(THINKS, tightbeam::exactly!(2)),
			(SITS, tightbeam::exactly!(2)),
			(PICKS_LEFT, tightbeam::exactly!(2))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_trace_refinement,
	config: ScenarioConfig::builder()
		.with_spec(DeadlockPhilosopherSpec::latest())
		.with_fdr(build_fdr_config(
			vec![DiningPhilosophers::process()],
			1,
			10,
			8,
			2000,
			false,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Trace: Philosopher 1 picks left, Philosopher 2 picks left (deadlock)
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			Ok(())
		}
	}
}

// ===== Test 3: Deadlock-Free Refinement =====

// Define assertion spec for deadlock-free trace: philosophers complete cycles sequentially
tightbeam::tb_assert_spec! {
	pub DeadlockFreePhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(THINKS, tightbeam::exactly!(2)),
			(SITS, tightbeam::exactly!(2)),
			(PICKS_LEFT, tightbeam::exactly!(2)),
			(PICKS_RIGHT, tightbeam::exactly!(2)),
			(EATS, tightbeam::exactly!(2)),
			(PUTS_DOWN_LEFT, tightbeam::exactly!(2)),
			(PUTS_DOWN_RIGHT, tightbeam::exactly!(2)),
			(GETS_UP, tightbeam::exactly!(2))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_free_refinement,
	config: ScenarioConfig::builder()
		.with_spec(DeadlockFreePhilosopherSpec::latest())
		.with_fdr(build_fdr_config(
			vec![DeadlockFreePhilosophers::process()],
			4,
			18,
			8,
			500,
			false,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Valid deadlock-free trace: P1 completes cycle, then P2 completes cycle
			// (butler ensures they don't sit simultaneously)
			// P1 cycle
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(PICKS_RIGHT)?;
			trace.event(EATS)?;
			trace.event(PUTS_DOWN_LEFT)?;
			trace.event(PUTS_DOWN_RIGHT)?;
			trace.event(GETS_UP)?;
			// P2 cycle
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(PICKS_RIGHT)?;
			trace.event(EATS)?;
			trace.event(PUTS_DOWN_LEFT)?;
			trace.event(PUTS_DOWN_RIGHT)?;
			trace.event(GETS_UP)?;
			Ok(())
		}
	}
}

// ===== Test 4: Deadlock Violates Deadlock-Free Spec =====

// Test that deadlock trace does NOT refine DeadlockFreePhilosophers
// The deadlock trace (both pick left) should fail refinement against deadlock-free spec
tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_violates_deadlock_free,
	config: ScenarioConfig::builder()
		.with_spec(DeadlockPhilosopherSpec::latest())
		.with_fdr(build_fdr_config(
			vec![DeadlockFreePhilosophers::process()],
			4,
			16,
			8,
			500,
			true,
		))
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// Trace: Philosopher 1 picks left, Philosopher 2 picks left (deadlock)
			// This should NOT refine DeadlockFreePhilosophers (butler prevents both sitting)
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			Ok(())
		}
	}
}

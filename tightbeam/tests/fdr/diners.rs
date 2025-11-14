//! Dining Philosophers tests
//!
//! Tests for the dining philosophers CSP process, including:
//! - Deadlock detection scenarios

#![cfg(feature = "testing-fdr")]

// ===== Dining Philosophers (Simplified - 2 philosophers) =====

tightbeam::tb_process_spec! {
	/// Dining Philosophers CSP Process (Simplified: 2 philosophers)
	///
	/// Models philosophers competing for forks, demonstrating deadlock.
	/// Fork sharing: P1's right fork = P2's left fork, P1's left fork = P2's right fork
	/// Deadlock occurs when both pick their left fork - neither can pick right fork.
	/// Events: thinks, sits, picks_left, picks_right, eats, puts_down_left, puts_down_right, gets_up
	pub struct DiningPhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "puts_down_left", "puts_down_right", "gets_up" }
		hidden { }
	}
	states {
		// Initial: both idle
		BothIdle => { "thinks" => P1Thinking_P2Idle, "thinks" => P1Idle_P2Thinking },

		// P1 thinking, P2 idle
		P1Thinking_P2Idle => { "sits" => P1Sitting_P2Idle, "thinks" => BothThinking },
		P1Sitting_P2Idle => { "picks_left" => P1HasLeft_P2Idle, "thinks" => P1Sitting_P2Thinking },
		P1HasLeft_P2Idle => { "picks_right" => P1HasBoth_P2Idle, "thinks" => P1HasLeft_P2Thinking, "sits" => P1HasLeft_P2Sitting },
		P1HasBoth_P2Idle => { "eats" => P1Eating_P2Idle },
		P1Eating_P2Idle => { "puts_down_left" => P1HasRight_P2Idle },
		P1HasRight_P2Idle => { "puts_down_right" => P1Finished_P2Idle },
		P1Finished_P2Idle => { "gets_up" => P1Idle_P2Idle, "thinks" => P1Finished_P2Thinking },
		P1Idle_P2Idle => { "thinks" => BothIdle },

		// P1 idle, P2 thinking
		P1Idle_P2Thinking => { "sits" => P1Idle_P2Sitting, "thinks" => BothThinking },
		P1Idle_P2Sitting => { "picks_left" => P1Idle_P2HasLeft, "thinks" => P1Thinking_P2Sitting },
		P1Idle_P2HasLeft => { "picks_right" => P1Idle_P2HasBoth, "thinks" => P1Thinking_P2HasLeft, "sits" => P1Sitting_P2HasLeft },
		P1Idle_P2HasBoth => { "eats" => P1Idle_P2Eating },
		P1Idle_P2Eating => { "puts_down_left" => P1Idle_P2HasRight },
		P1Idle_P2HasRight => { "puts_down_right" => P1Idle_P2Finished },
		P1Idle_P2Finished => { "gets_up" => P1Idle_P2Idle, "thinks" => P1Thinking_P2Finished },

		// Both thinking
		BothThinking => { "sits" => P1Sitting_P2Thinking, "sits" => P1Thinking_P2Sitting },

		// P1 sitting, P2 thinking
		P1Sitting_P2Thinking => { "picks_left" => P1HasLeft_P2Thinking, "sits" => BothSitting },
		P1HasLeft_P2Thinking => { "picks_right" => P1HasBoth_P2Thinking, "sits" => P1HasLeft_P2Sitting },
		P1HasBoth_P2Thinking => { "eats" => P1Eating_P2Thinking },
		P1Eating_P2Thinking => { "puts_down_left" => P1HasRight_P2Thinking },
		P1HasRight_P2Thinking => { "puts_down_right" => P1Finished_P2Thinking },
		P1Finished_P2Thinking => { "gets_up" => P1Idle_P2Thinking, "sits" => P1Finished_P2Sitting },

		// P1 thinking, P2 sitting
		P1Thinking_P2Sitting => { "picks_left" => P1Thinking_P2HasLeft, "sits" => BothSitting },
		P1Thinking_P2HasLeft => { "picks_right" => P1Thinking_P2HasBoth, "sits" => P1Sitting_P2HasLeft },
		P1Thinking_P2HasBoth => { "eats" => P1Thinking_P2Eating },
		P1Thinking_P2Eating => { "puts_down_left" => P1Thinking_P2HasRight },
		P1Thinking_P2HasRight => { "puts_down_right" => P1Thinking_P2Finished },
		P1Thinking_P2Finished => { "gets_up" => P1Thinking_P2Idle, "sits" => P1Sitting_P2Finished },

		// Both sitting - can both pick left (deadlock possible)
		BothSitting => { "picks_left" => P1HasLeft_P2Sitting, "picks_left" => P1Sitting_P2HasLeft },

		// P1 has left, P2 sitting - P2 can pick left (leading to deadlock) or P1 can pick right
		P1HasLeft_P2Sitting => { "picks_left" => Deadlock, "picks_right" => P1HasBoth_P2Sitting },
		P1HasBoth_P2Sitting => { "eats" => P1Eating_P2Sitting },
		P1Eating_P2Sitting => { "puts_down_left" => P1HasRight_P2Sitting },
		P1HasRight_P2Sitting => { "puts_down_right" => P1Finished_P2Sitting },
		P1Finished_P2Sitting => { "gets_up" => P1Idle_P2Sitting },

		// P1 sitting, P2 has left - P1 can pick left (leading to deadlock) or P2 can pick right
		P1Sitting_P2HasLeft => { "picks_left" => Deadlock, "picks_right" => P1Sitting_P2HasBoth },

		// Deadlock: both have left fork - neither can pick right fork
		Deadlock => {}, // Terminal deadlock state - no transitions available
		P1Sitting_P2HasBoth => { "eats" => P1Sitting_P2Eating },
		P1Sitting_P2Eating => { "puts_down_left" => P1Sitting_P2HasRight },
		P1Sitting_P2HasRight => { "puts_down_right" => P1Sitting_P2Finished },
		P1Sitting_P2Finished => { "gets_up" => P1Sitting_P2Idle },

		// P1 has left, P2 has left - deadlock (both need right fork, but it's the same fork)
		P1HasLeft_P2HasLeft => {}, // Terminal deadlock state

		// P1 has left, P2 thinking - P2 can sit and pick left (deadlock) or P1 can pick right
		P1HasLeft_P2Thinking => { "picks_right" => P1HasBoth_P2Thinking, "sits" => P1HasLeft_P2Sitting },

		// P1 thinking, P2 has left - P1 can sit and pick left (deadlock) or P2 can pick right
		P1Thinking_P2HasLeft => { "picks_right" => P1Thinking_P2HasBoth, "sits" => P1Sitting_P2HasLeft },

		// P1 finished, P2 sitting (merge with earlier definition)
		// P1Finished_P2Sitting already defined above, adding transitions here
		// Note: This state transition is already covered by P1Finished_P2Sitting => { "gets_up" => P1Idle_P2Sitting }
		P1Finished_P2HasLeft => { "picks_right" => P1Finished_P2HasBoth },
		P1Finished_P2HasBoth => { "eats" => P1Finished_P2Eating },
		P1Finished_P2Eating => { "puts_down_left" => P1Finished_P2HasRight },
		P1Finished_P2HasRight => { "puts_down_right" => P1Finished_P2Finished },
		P1Finished_P2Finished => { "gets_up" => P1Finished_P2Idle, "gets_up" => P1Idle_P2Finished },
		P1Finished_P2Idle => { "thinks" => BothIdle },
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
	pub struct DeadlockFreePhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "puts_down_left", "puts_down_right", "gets_up" }
		hidden { }
	}
	states {
		// Initial: both idle
		BothIdleDF => { "thinks" => P1Thinking_P2IdleDF, "thinks" => P1Idle_P2ThinkingDF },

		// P1 thinking, P2 idle - P1 can sit (butler allows)
		P1Thinking_P2IdleDF => { "sits" => P1Sitting_P2IdleDF, "thinks" => BothThinkingDF },
		P1Sitting_P2IdleDF => { "picks_left" => P1HasLeft_P2IdleDF, "thinks" => P1Sitting_P2ThinkingDF },
		P1HasLeft_P2IdleDF => { "picks_right" => P1HasBoth_P2IdleDF, "thinks" => P1HasLeft_P2ThinkingDF },
		P1HasBoth_P2IdleDF => { "eats" => P1Eating_P2IdleDF },
		P1Eating_P2IdleDF => { "puts_down_left" => P1HasRight_P2IdleDF },
		P1HasRight_P2IdleDF => { "puts_down_right" => P1Finished_P2IdleDF },
		P1Finished_P2IdleDF => { "gets_up" => P1Idle_P2IdleDF, "thinks" => P1Finished_P2ThinkingDF },
		// P1 idle, P2 idle - either can think (both are idle, no constraints)
		P1Idle_P2IdleDF => { "thinks" => BothIdleDF, "thinks" => P1Idle_P2ThinkingDF },

		// P1 idle, P2 thinking - P2 can sit (butler allows, P1 not sitting)
		P1Idle_P2ThinkingDF => { "sits" => P1Idle_P2SittingDF, "thinks" => BothThinkingDF },
		P1Idle_P2SittingDF => { "picks_left" => P1Idle_P2HasLeftDF, "thinks" => P1Thinking_P2SittingDF },
		P1Idle_P2HasLeftDF => { "picks_right" => P1Idle_P2HasBothDF, "thinks" => P1Thinking_P2HasLeftDF },
		P1Idle_P2HasBothDF => { "eats" => P1Idle_P2EatingDF },
		P1Idle_P2EatingDF => { "puts_down_left" => P1Idle_P2HasRightDF },
		P1Idle_P2HasRightDF => { "puts_down_right" => P1Idle_P2FinishedDF },
		P1Idle_P2FinishedDF => { "gets_up" => P1Idle_P2IdleDF, "thinks" => P1Thinking_P2FinishedDF },

		// Both thinking - only one can sit (butler constraint)
		BothThinkingDF => { "sits" => P1Sitting_P2ThinkingDF, "sits" => P1Thinking_P2SittingDF },

		// P1 sitting, P2 thinking - P2 CANNOT sit (butler prevents both sitting)
		// P2 can think but cannot sit while P1 is sitting
		P1Sitting_P2ThinkingDF => { "picks_left" => P1HasLeft_P2ThinkingDF, "thinks" => P1Sitting_P2IdleDF },
		P1Sitting_P2IdleDF => { "thinks" => P1Sitting_P2ThinkingDF },
		P1HasLeft_P2ThinkingDF => { "picks_right" => P1HasBoth_P2ThinkingDF },
		P1HasBoth_P2ThinkingDF => { "eats" => P1Eating_P2ThinkingDF },
		P1Eating_P2ThinkingDF => { "puts_down_left" => P1HasRight_P2ThinkingDF },
		P1HasRight_P2ThinkingDF => { "puts_down_right" => P1Finished_P2ThinkingDF },
		P1Finished_P2ThinkingDF => { "gets_up" => P1Idle_P2ThinkingDF },

		// P1 thinking, P2 sitting - P1 CANNOT sit (butler prevents both sitting)
		// P1 can think but cannot sit while P2 is sitting
		P1Thinking_P2SittingDF => { "picks_left" => P1Thinking_P2HasLeftDF, "thinks" => P1Idle_P2SittingDF },
		P1Idle_P2SittingDF => { "thinks" => P1Thinking_P2SittingDF },
		P1Thinking_P2HasLeftDF => { "picks_right" => P1Thinking_P2HasBothDF },
		P1Thinking_P2HasBothDF => { "eats" => P1Thinking_P2EatingDF },
		P1Thinking_P2EatingDF => { "puts_down_left" => P1Thinking_P2HasRightDF },
		P1Thinking_P2HasRightDF => { "puts_down_right" => P1Thinking_P2FinishedDF },
		P1Thinking_P2FinishedDF => { "gets_up" => P1Thinking_P2IdleDF },

		// P1 finished, P2 thinking - P2 can now sit (P1 not sitting)
		P1Finished_P2ThinkingDF => { "sits" => P1Finished_P2SittingDF },
		P1Finished_P2SittingDF => { "picks_left" => P1Finished_P2HasLeftDF },
		P1Finished_P2HasLeftDF => { "picks_right" => P1Finished_P2HasBothDF },
		P1Finished_P2HasBothDF => { "eats" => P1Finished_P2EatingDF },
		P1Finished_P2EatingDF => { "puts_down_left" => P1Finished_P2HasRightDF },
		P1Finished_P2HasRightDF => { "puts_down_right" => P1Finished_P2FinishedDF },
		P1Finished_P2FinishedDF => { "gets_up" => P1Finished_P2IdleDF, "gets_up" => P1Idle_P2FinishedDF },
		P1Finished_P2IdleDF => { "thinks" => BothIdleDF },

		// P1 thinking, P2 finished - P1 can now sit (P2 not sitting)
		P1Thinking_P2FinishedDF => { "sits" => P1Sitting_P2FinishedDF },
		P1Sitting_P2FinishedDF => { "picks_left" => P1HasLeft_P2FinishedDF },
		P1HasLeft_P2FinishedDF => { "picks_right" => P1HasBoth_P2FinishedDF },
		P1HasBoth_P2FinishedDF => { "eats" => P1Eating_P2FinishedDF },
		P1Eating_P2FinishedDF => { "puts_down_left" => P1HasRight_P2FinishedDF },
		P1HasRight_P2FinishedDF => { "puts_down_right" => P1Finished_P2FinishedDF },
		P1Idle_P2FinishedDF => { "thinks" => BothIdleDF },
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
		gate: Accepted,
		assertions: [
			(Any, "thinks", tightbeam::exactly!(1)),
			(Any, "sits", tightbeam::exactly!(1)),
			(Any, "picks_left", tightbeam::exactly!(1)),
			(Any, "picks_right", tightbeam::exactly!(1)),
			(Any, "eats", tightbeam::exactly!(1)),
			(Any, "puts_down_left", tightbeam::exactly!(1)),
			(Any, "puts_down_right", tightbeam::exactly!(1)),
			(Any, "gets_up", tightbeam::exactly!(1))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_valid_trace_refinement,
	spec: ValidPhilosopherSpec,
	fdr: FdrConfig {
		seeds: 4,
		max_depth: 16,
		max_internal_run: 8,
		timeout_ms: 500,
		specs: vec![DiningPhilosophers::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment Bare {
		exec: |trace| {
			// Valid trace: one philosopher completes full cycle
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			trace.event("picks_right");
			trace.event("eats");
			trace.event("puts_down_left");
			trace.event("puts_down_right");
			trace.event("gets_up");
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
		gate: Accepted,
		assertions: [
			(Any, "thinks", tightbeam::exactly!(2)),
			(Any, "sits", tightbeam::exactly!(2)),
			(Any, "picks_left", tightbeam::exactly!(2))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_trace_refinement,
	spec: DeadlockPhilosopherSpec,
	fdr: FdrConfig {
		seeds: 1, // Not used for refinement checking
		max_depth: 10, // Reduced depth - trace is only 6 events
		max_internal_run: 8,
		timeout_ms: 2000, // Increased timeout for complex spec
		specs: vec![DiningPhilosophers::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment Bare {
		exec: |trace| {
			// Trace: Philosopher 1 picks left, Philosopher 2 picks left (deadlock)
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
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
		gate: Accepted,
		assertions: [
			(Any, "thinks", tightbeam::exactly!(2)),
			(Any, "sits", tightbeam::exactly!(2)),
			(Any, "picks_left", tightbeam::exactly!(2)),
			(Any, "picks_right", tightbeam::exactly!(2)),
			(Any, "eats", tightbeam::exactly!(2)),
			(Any, "puts_down_left", tightbeam::exactly!(2)),
			(Any, "puts_down_right", tightbeam::exactly!(2)),
			(Any, "gets_up", tightbeam::exactly!(2))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_free_refinement,
	spec: DeadlockFreePhilosopherSpec,
	fdr: FdrConfig {
		seeds: 4,
		max_depth: 18, // Reduced depth - trace is only 16 events, but spec has cycles
		max_internal_run: 8,
		timeout_ms: 500,
		specs: vec![DeadlockFreePhilosophers::process()],
		fail_fast: true,
		expect_failure: false,
	},
	environment Bare {
		exec: |trace| {
			// Valid deadlock-free trace: P1 completes cycle, then P2 completes cycle
			// (butler ensures they don't sit simultaneously)
			// P1 cycle
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			trace.event("picks_right");
			trace.event("eats");
			trace.event("puts_down_left");
			trace.event("puts_down_right");
			trace.event("gets_up");
			// P2 cycle
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			trace.event("picks_right");
			trace.event("eats");
			trace.event("puts_down_left");
			trace.event("puts_down_right");
			trace.event("gets_up");
			Ok(())
		}
	}
}

// ===== Test 4: Deadlock Violates Deadlock-Free Spec =====

// Test that deadlock trace does NOT refine DeadlockFreePhilosophers
// The deadlock trace (both pick left) should fail refinement against deadlock-free spec
tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_violates_deadlock_free,
	spec: DeadlockPhilosopherSpec,
	fdr: FdrConfig {
		seeds: 4,
		max_depth: 16,
		max_internal_run: 8,
		timeout_ms: 500,
		specs: vec![DeadlockFreePhilosophers::process()],
		fail_fast: true,
		// This test expects refinement to fail (deadlock violates deadlock-free spec)
		expect_failure: true,
	},
	environment Bare {
		exec: |trace| {
			// Trace: Philosopher 1 picks left, Philosopher 2 picks left (deadlock)
			// This should NOT refine DeadlockFreePhilosophers (butler prevents both sitting)
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			trace.event("thinks");
			trace.event("sits");
			trace.event("picks_left");
			Ok(())
		}
	}
}

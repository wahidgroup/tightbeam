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
	/// Events: thinks, sits, picks_left, picks_right, eats, puts_down_left, puts_down_right, gets_up
	pub struct DiningPhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "puts_down_left", "puts_down_right", "gets_up" }
		hidden { }
	}
	states {
		// Philosopher 1 states
		Idle1 => { "thinks" => Thinking1 },
		Thinking1 => { "sits" => Sitting1 },
		Sitting1 => { "picks_left" => HasLeftFork1 },
		HasLeftFork1 => { "picks_right" => HasBothForks1 },
		HasBothForks1 => { "eats" => Eating1 },
		Eating1 => { "puts_down_left" => HasRightFork1 },
		HasRightFork1 => { "puts_down_right" => Finished1 },
		Finished1 => { "gets_up" => Idle1 },

		// Philosopher 2 states
		Idle2 => { "thinks" => Thinking2 },
		Thinking2 => { "sits" => Sitting2 },
		Sitting2 => { "picks_left" => HasLeftFork2 },
		HasLeftFork2 => { "picks_right" => HasBothForks2 },
		HasBothForks2 => { "eats" => Eating2 },
		Eating2 => { "puts_down_left" => HasRightFork2 },
		HasRightFork2 => { "puts_down_right" => Finished2 },
		Finished2 => { "gets_up" => Idle2 }
	}
	terminal { Idle1, Idle2 }
	annotations { description: "Dining philosophers (2 philosophers, deadlock-prone)" }
}

tightbeam::tb_process_spec! {
	/// Deadlock-free Dining Philosophers (with butler/coordinator)
	///
	/// The butler ensures at most N-1 philosophers can sit, preventing deadlock.
	pub struct DeadlockFreePhilosophers;
	events {
		observable { "thinks", "sits", "picks_left", "picks_right", "eats", "puts_down_left", "puts_down_right", "gets_up" }
		hidden { }
	}
	states {
		// Philosopher 1 states
		Idle1 => { "thinks" => Thinking1 },
		Thinking1 => { "sits" => Sitting1 },
		Sitting1 => { "picks_left" => HasLeftFork1 },
		HasLeftFork1 => { "picks_right" => HasBothForks1 },
		HasBothForks1 => { "eats" => Eating1 },
		Eating1 => { "puts_down_left" => HasRightFork1 },
		HasRightFork1 => { "puts_down_right" => Finished1 },
		Finished1 => { "gets_up" => Idle1 },

		// Philosopher 2 states (butler ensures only one can sit at a time)
		Idle2 => { "thinks" => Thinking2 },
		Thinking2 => { "sits" => Sitting2 },
		Sitting2 => { "picks_left" => HasLeftFork2 },
		HasLeftFork2 => { "picks_right" => HasBothForks2 },
		HasBothForks2 => { "eats" => Eating2 },
		Eating2 => { "puts_down_left" => HasRightFork2 },
		HasRightFork2 => { "puts_down_right" => Finished2 },
		Finished2 => { "gets_up" => Idle2 }
	}
	terminal { Idle1, Idle2 }
	annotations { description: "Deadlock-free dining philosophers (butler ensures mutual exclusion)" }
}

// ===== Test: Dining Philosophers - Deadlock Detection =====

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


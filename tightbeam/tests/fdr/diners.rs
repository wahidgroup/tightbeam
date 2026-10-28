//! The dining philosophers tests.
//!
//! They refine traces against two CSP processes of two philosophers, and detect
//! the deadlock of the process with no butler. Each process reaches every state
//! it defines.

#![cfg(feature = "testing-fdr")]

use core::error::Error;
use std::collections::HashSet;

use tightbeam::testing::fdr::FdrConfig;
use tightbeam::testing::macros::BuiltAssertSpec;
use tightbeam::testing::specs::csp::{Process, ProcessBuildError, State};
use tightbeam::testing::{Expect, Layer, ScenarioConfig, SetupEnv};
use tightbeam::urn::Urn;

pub(crate) const EATS: Urn<'static> = tightbeam::urn!("test", "event:diners/eats");
pub(crate) const GETS_UP: Urn<'static> = tightbeam::urn!("test", "event:diners/gets-up");
pub(crate) const PICKS_LEFT: Urn<'static> = tightbeam::urn!("test", "event:diners/picks-left");
pub(crate) const PICKS_RIGHT: Urn<'static> = tightbeam::urn!("test", "event:diners/picks-right");
pub(crate) const PUTS_DOWN_LEFT: Urn<'static> = tightbeam::urn!("test", "event:diners/puts-down-left");
pub(crate) const PUTS_DOWN_RIGHT: Urn<'static> = tightbeam::urn!("test", "event:diners/puts-down-right");
pub(crate) const SITS: Urn<'static> = tightbeam::urn!("test", "event:diners/sits");
pub(crate) const THINKS: Urn<'static> = tightbeam::urn!("test", "event:diners/thinks");

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

/// The states of `process` that no path from its initial state reaches.
fn unreachable_states(process: &Process) -> HashSet<State> {
	let mut reached = HashSet::from([process.initial()]);
	let mut frontier = vec![process.initial()];
	while let Some(state) = frontier.pop() {
		for action in process.enabled(state) {
			for target in process.step(state, &action.event) {
				if reached.insert(target) {
					frontier.push(target);
				}
			}
		}
	}

	process.states().difference(&reached).copied().collect()
}

/// The configuration that grades `spec`, refines the run against `process`
/// under the FDR bounds of `fdr`, and expects `expect`.
fn philosophers_config(
	spec: &'static BuiltAssertSpec,
	process: Result<Process, ProcessBuildError>,
	fdr: impl FnOnce(Process) -> FdrConfig,
	expect: Expect,
) -> Result<ScenarioConfig, Box<dyn Error>> {
	let fdr = fdr(process?);
	let builder = ScenarioConfig::builder().with_spec(spec).with_fdr(fdr);
	Ok(builder.with_expect(expect).build()?)
}

// The dining philosophers process, simplified to two philosophers.

tightbeam::tb_process_spec! {
	/// The dining philosophers CSP process, simplified to two philosophers.
	///
	/// The two philosophers share two forks: the right fork of P1 is the left
	/// fork of P2, and the left fork of P1 is the right fork of P2. When both
	/// pick up their left fork, neither can pick up a right fork, and the
	/// process deadlocks.
	pub DiningPhilosophers,
	events {
		observable { THINKS, SITS, PICKS_LEFT, PICKS_RIGHT, EATS, PUTS_DOWN_LEFT, PUTS_DOWN_RIGHT, GETS_UP }
		hidden { }
	}
	states {
		// Both philosophers start idle.
		BothIdle => { THINKS => P1Thinking_P2Idle, THINKS => P1Idle_P2Thinking },

		// P1 runs its cycle while P2 is idle.
		P1Thinking_P2Idle => { SITS => P1Sitting_P2Idle, THINKS => BothThinking },
		P1Sitting_P2Idle => { PICKS_LEFT => P1HasLeft_P2Idle, THINKS => P1Sitting_P2Thinking },
		P1HasLeft_P2Idle => { PICKS_RIGHT => P1HasBoth_P2Idle, THINKS => P1HasLeft_P2Thinking, SITS => P1HasLeft_P2Sitting },
		P1HasBoth_P2Idle => { EATS => P1Eating_P2Idle },
		P1Eating_P2Idle => { PUTS_DOWN_LEFT => P1HasRight_P2Idle },
		P1HasRight_P2Idle => { PUTS_DOWN_RIGHT => P1Finished_P2Idle },
		P1Finished_P2Idle => { GETS_UP => P1Idle_P2Idle, THINKS => P1Finished_P2Thinking, THINKS => BothIdle },
		P1Idle_P2Idle => { THINKS => BothIdle },

		// P2 runs its cycle while P1 is idle.
		P1Idle_P2Thinking => { SITS => P1Idle_P2Sitting, THINKS => BothThinking },
		P1Idle_P2Sitting => { PICKS_LEFT => P1Idle_P2HasLeft, THINKS => P1Thinking_P2Sitting },
		P1Idle_P2HasLeft => { PICKS_RIGHT => P1Idle_P2HasBoth, THINKS => P1Thinking_P2HasLeft, SITS => P1Sitting_P2HasLeft },
		P1Idle_P2HasBoth => { EATS => P1Idle_P2Eating },
		P1Idle_P2Eating => { PUTS_DOWN_LEFT => P1Idle_P2HasRight },
		P1Idle_P2HasRight => { PUTS_DOWN_RIGHT => P1Idle_P2Finished },
		P1Idle_P2Finished => { GETS_UP => P1Idle_P2Idle, THINKS => P1Thinking_P2Finished },

		// Both philosophers think.
		BothThinking => { SITS => P1Sitting_P2Thinking, SITS => P1Thinking_P2Sitting },

		// P1 runs its cycle while P2 thinks.
		P1Sitting_P2Thinking => { PICKS_LEFT => P1HasLeft_P2Thinking, SITS => BothSitting },
		P1HasLeft_P2Thinking => { PICKS_RIGHT => P1HasBoth_P2Thinking, SITS => P1HasLeft_P2Sitting },
		P1HasBoth_P2Thinking => { EATS => P1Eating_P2Thinking },
		P1Eating_P2Thinking => { PUTS_DOWN_LEFT => P1HasRight_P2Thinking },
		P1HasRight_P2Thinking => { PUTS_DOWN_RIGHT => P1Finished_P2Thinking },
		P1Finished_P2Thinking => { GETS_UP => P1Idle_P2Thinking, SITS => P1Finished_P2Sitting },

		// P2 runs its cycle while P1 thinks.
		P1Thinking_P2Sitting => { PICKS_LEFT => P1Thinking_P2HasLeft, SITS => BothSitting },
		P1Thinking_P2HasLeft => { PICKS_RIGHT => P1Thinking_P2HasBoth, SITS => P1Sitting_P2HasLeft },
		P1Thinking_P2HasBoth => { EATS => P1Thinking_P2Eating },
		P1Thinking_P2Eating => { PUTS_DOWN_LEFT => P1Thinking_P2HasRight },
		P1Thinking_P2HasRight => { PUTS_DOWN_RIGHT => P1Thinking_P2Finished },
		P1Thinking_P2Finished => { GETS_UP => P1Thinking_P2Idle, SITS => P1Sitting_P2Finished },

		// Both sit, and a deadlock follows when each picks up its left fork.
		BothSitting => { PICKS_LEFT => P1HasLeft_P2Sitting, PICKS_LEFT => P1Sitting_P2HasLeft },

		// P1 holds its left fork while P2 sits. P2 can pick up its left fork,
		// which deadlocks, or P1 can pick up its right fork.
		P1HasLeft_P2Sitting => { PICKS_LEFT => Deadlock, PICKS_RIGHT => P1HasBoth_P2Sitting },
		P1HasBoth_P2Sitting => { EATS => P1Eating_P2Sitting },
		P1Eating_P2Sitting => { PUTS_DOWN_LEFT => P1HasRight_P2Sitting },
		P1HasRight_P2Sitting => { PUTS_DOWN_RIGHT => P1Finished_P2Sitting },
		P1Finished_P2Sitting => { GETS_UP => P1Idle_P2Sitting, PICKS_LEFT => P1Finished_P2HasLeft },

		// P2 holds its left fork while P1 sits. P1 can pick up its left fork,
		// which deadlocks, or P2 can pick up its right fork.
		P1Sitting_P2HasLeft => { PICKS_LEFT => Deadlock, PICKS_RIGHT => P1Sitting_P2HasBoth },

		// The deadlock: each philosopher holds a left fork, and neither can
		// pick up a right fork.
		Deadlock => {}, // A terminal state with an empty set of transitions.
		P1Sitting_P2HasBoth => { EATS => P1Sitting_P2Eating },
		P1Sitting_P2Eating => { PUTS_DOWN_LEFT => P1Sitting_P2HasRight },
		P1Sitting_P2HasRight => { PUTS_DOWN_RIGHT => P1Sitting_P2Finished },
		P1Sitting_P2Finished => { GETS_UP => P1Sitting_P2Idle },

		// P2 runs its cycle after P1 finishes. At P1Finished_P2Sitting, P2
		// picks up its left fork.
		P1Finished_P2HasLeft => { PICKS_RIGHT => P1Finished_P2HasBoth },
		P1Finished_P2HasBoth => { EATS => P1Finished_P2Eating },
		P1Finished_P2Eating => { PUTS_DOWN_LEFT => P1Finished_P2HasRight },
		P1Finished_P2HasRight => { PUTS_DOWN_RIGHT => P1Finished_P2Finished },
		P1Finished_P2Finished => { GETS_UP => P1Finished_P2Idle, GETS_UP => P1Idle_P2Finished },
	}
	terminal { BothIdle, Deadlock, P1Finished_P2Finished }
	annotations { description: "Dining philosophers (2 philosophers, deadlock-prone) - models fork sharing constraint" }
}

tightbeam::tb_process_spec! {
	/// The deadlock-free dining philosophers process, with a butler.
	///
	/// The butler lets at most N-1 philosophers sit at once, so with two
	/// philosophers one sits at a time, and the state where both hold their
	/// left fork is out of reach.
	pub DeadlockFreePhilosophers,
	events {
		observable { THINKS, SITS, PICKS_LEFT, PICKS_RIGHT, EATS, PUTS_DOWN_LEFT, PUTS_DOWN_RIGHT, GETS_UP }
		hidden { }
	}
	states {
		// Both philosophers start idle.
		BothIdleDF => { THINKS => P1Thinking_P2IdleDF, THINKS => P1Idle_P2ThinkingDF },

		// P1 runs its cycle while P2 is idle, and the butler lets P1 sit.
		P1Thinking_P2IdleDF => { SITS => P1Sitting_P2IdleDF, THINKS => BothThinkingDF },
		P1Sitting_P2IdleDF => { PICKS_LEFT => P1HasLeft_P2IdleDF, THINKS => P1Sitting_P2ThinkingDF },
		P1HasLeft_P2IdleDF => { PICKS_RIGHT => P1HasBoth_P2IdleDF, THINKS => P1HasLeft_P2ThinkingDF },
		P1HasBoth_P2IdleDF => { EATS => P1Eating_P2IdleDF },
		P1Eating_P2IdleDF => { PUTS_DOWN_LEFT => P1HasRight_P2IdleDF },
		P1HasRight_P2IdleDF => { PUTS_DOWN_RIGHT => P1Finished_P2IdleDF },
		P1Finished_P2IdleDF => { GETS_UP => P1Idle_P2IdleDF, THINKS => P1Finished_P2ThinkingDF, THINKS => BothIdleDF },
		// Both philosophers are idle, so either one can think.
		P1Idle_P2IdleDF => { THINKS => BothIdleDF, THINKS => P1Idle_P2ThinkingDF },

		// P2 runs its cycle while P1 is idle, and the butler lets P2 sit.
		P1Idle_P2ThinkingDF => { SITS => P1Idle_P2SittingDF, THINKS => BothThinkingDF },
		P1Idle_P2SittingDF => { PICKS_LEFT => P1Idle_P2HasLeftDF, THINKS => P1Thinking_P2SittingDF },
		P1Idle_P2HasLeftDF => { PICKS_RIGHT => P1Idle_P2HasBothDF, THINKS => P1Thinking_P2HasLeftDF },
		P1Idle_P2HasBothDF => { EATS => P1Idle_P2EatingDF },
		P1Idle_P2EatingDF => { PUTS_DOWN_LEFT => P1Idle_P2HasRightDF },
		P1Idle_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Idle_P2FinishedDF },
		P1Idle_P2FinishedDF => { GETS_UP => P1Idle_P2IdleDF, THINKS => P1Thinking_P2FinishedDF, THINKS => BothIdleDF },

		// Both philosophers think, and the butler lets one of them sit.
		BothThinkingDF => { SITS => P1Sitting_P2ThinkingDF, SITS => P1Thinking_P2SittingDF },

		// P1 sits while P2 thinks. The butler keeps P2 from its seat until P1
		// finishes, so P2 can only think.
		P1Sitting_P2ThinkingDF => { PICKS_LEFT => P1HasLeft_P2ThinkingDF, THINKS => P1Sitting_P2IdleDF },
		P1HasLeft_P2ThinkingDF => { PICKS_RIGHT => P1HasBoth_P2ThinkingDF },
		P1HasBoth_P2ThinkingDF => { EATS => P1Eating_P2ThinkingDF },
		P1Eating_P2ThinkingDF => { PUTS_DOWN_LEFT => P1HasRight_P2ThinkingDF },
		P1HasRight_P2ThinkingDF => { PUTS_DOWN_RIGHT => P1Finished_P2ThinkingDF },
		P1Finished_P2ThinkingDF => { GETS_UP => P1Idle_P2ThinkingDF, SITS => P1Finished_P2SittingDF },

		// P2 sits while P1 thinks. The butler keeps P1 from its seat until P2
		// finishes, so P1 can only think.
		P1Thinking_P2SittingDF => { PICKS_LEFT => P1Thinking_P2HasLeftDF, THINKS => P1Idle_P2SittingDF },
		P1Thinking_P2HasLeftDF => { PICKS_RIGHT => P1Thinking_P2HasBothDF },
		P1Thinking_P2HasBothDF => { EATS => P1Thinking_P2EatingDF },
		P1Thinking_P2EatingDF => { PUTS_DOWN_LEFT => P1Thinking_P2HasRightDF },
		P1Thinking_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Thinking_P2FinishedDF },
		P1Thinking_P2FinishedDF => { GETS_UP => P1Thinking_P2IdleDF, SITS => P1Sitting_P2FinishedDF },

		// P1 has finished, and P2 sits and runs its cycle.
		P1Finished_P2SittingDF => { PICKS_LEFT => P1Finished_P2HasLeftDF },
		P1Finished_P2HasLeftDF => { PICKS_RIGHT => P1Finished_P2HasBothDF },
		P1Finished_P2HasBothDF => { EATS => P1Finished_P2EatingDF },
		P1Finished_P2EatingDF => { PUTS_DOWN_LEFT => P1Finished_P2HasRightDF },
		P1Finished_P2HasRightDF => { PUTS_DOWN_RIGHT => P1Finished_P2FinishedDF },
		P1Finished_P2FinishedDF => { GETS_UP => P1Finished_P2IdleDF, GETS_UP => P1Idle_P2FinishedDF },

		// P2 has finished, and P1 sits and runs its cycle.
		P1Sitting_P2FinishedDF => { PICKS_LEFT => P1HasLeft_P2FinishedDF },
		P1HasLeft_P2FinishedDF => { PICKS_RIGHT => P1HasBoth_P2FinishedDF },
		P1HasBoth_P2FinishedDF => { EATS => P1Eating_P2FinishedDF },
		P1Eating_P2FinishedDF => { PUTS_DOWN_LEFT => P1HasRight_P2FinishedDF },
		P1HasRight_P2FinishedDF => { PUTS_DOWN_RIGHT => P1Finished_P2FinishedDF },
	}
	terminal { BothIdleDF, P1Finished_P2FinishedDF }
	annotations { description: "Deadlock-free dining philosophers (butler ensures mutual exclusion - only one can sit at a time)" }
}

// Test 1: a valid trace refines the process.

// In the valid trace, one philosopher completes a full cycle.
tightbeam::tb_assert_spec! {
	pub ValidPhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
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
	config: philosophers_config(
		ValidPhilosopherSpec::latest(),
		DiningPhilosophers::process(),
		|process| build_fdr_config([process], 4, 16, 8, 500),
		Expect::Pass,
	),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// One philosopher completes a full cycle.
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

// Test 2: a deadlock trace refines the process that allows it.

// In the deadlock trace, both philosophers pick up their left fork. The trace
// refines DiningPhilosophers, whose spec allows the deadlock.
tightbeam::tb_assert_spec! {
	pub DeadlockPhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(THINKS, tightbeam::exactly!(2)),
			(SITS, tightbeam::exactly!(2)),
			(PICKS_LEFT, tightbeam::exactly!(2))
		]
	},
}

tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_trace_refinement,
	config: philosophers_config(
		DeadlockPhilosopherSpec::latest(),
		DiningPhilosophers::process(),
		|process| build_fdr_config([process], 1, 10, 8, 2000),
		Expect::Pass,
	),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// P1 picks up its left fork, and then P2 picks up its left fork.
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

// Test 3: a deadlock-free trace refines the butler process.

// In the deadlock-free trace, the philosophers complete their cycles in turn.
tightbeam::tb_assert_spec! {
	pub DeadlockFreePhilosopherSpec,
	V(1,0,0): {
		mode: Accept,
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
	config: philosophers_config(
		DeadlockFreePhilosopherSpec::latest(),
		DeadlockFreePhilosophers::process(),
		|process| build_fdr_config([process], 4, 18, 8, 500),
		Expect::Pass,
	),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// P1 completes its cycle, then P2, because the butler lets one
			// philosopher sit at a time.
			// The cycle of P1.
			trace.event(THINKS)?;
			trace.event(SITS)?;
			trace.event(PICKS_LEFT)?;
			trace.event(PICKS_RIGHT)?;
			trace.event(EATS)?;
			trace.event(PUTS_DOWN_LEFT)?;
			trace.event(PUTS_DOWN_RIGHT)?;
			trace.event(GETS_UP)?;
			// The cycle of P2.
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

// Test 4: a deadlock trace violates the deadlock-free spec.

// The deadlock trace, in which both philosophers pick up their left fork,
// fails refinement against DeadlockFreePhilosophers.
tightbeam::tb_scenario! {
	name: test_philosophers_deadlock_violates_deadlock_free,
	config: philosophers_config(
		DeadlockPhilosopherSpec::latest(),
		DeadlockFreePhilosophers::process(),
		|process| build_fdr_config([process], 4, 16, 8, 500),
		Expect::Violation(Layer::Refinement),
	),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			// P1 picks up its left fork, and then P2 picks up its left fork.
			// The butler seats one philosopher at a time, so the trace fails.
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

// Test 5: each process reaches every state that it defines.

#[test]
fn the_dining_philosophers_reach_every_state_they_define() -> Result<(), Box<dyn Error>> {
	let unreachable = unreachable_states(&DiningPhilosophers::process()?);
	assert_eq!(unreachable, HashSet::new());
	Ok(())
}

#[test]
fn the_philosophers_with_a_butler_reach_every_state_they_define() -> Result<(), Box<dyn Error>> {
	let unreachable = unreachable_states(&DeadlockFreePhilosophers::process()?);
	assert_eq!(unreachable, HashSet::new());
	Ok(())
}

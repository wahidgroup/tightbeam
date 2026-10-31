//! The dining philosophers tests.
//!
//! They refine traces against two CSP processes of two philosophers, and detect
//! the deadlock of the process with no butler. Each process reaches every state
//! it defines.

use std::collections::HashSet;

use tightbeam::tb_cases;
use tightbeam::testing::fdr::{Decision, DefaultFdrExplorer, FdrConfig};
use tightbeam::testing::specs::csp::{Process, ProcessBuildError, State};
use tightbeam::trace::{ConsumedTrace, TraceCollector};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

use crate::common::result::TestResult;

pub(crate) const EATS: Urn<'static> = tightbeam::urn!("test", "event:diners/eats");
pub(crate) const GETS_UP: Urn<'static> = tightbeam::urn!("test", "event:diners/gets-up");
pub(crate) const PICKS_LEFT: Urn<'static> = tightbeam::urn!("test", "event:diners/picks-left");
pub(crate) const PICKS_RIGHT: Urn<'static> = tightbeam::urn!("test", "event:diners/picks-right");
pub(crate) const PUTS_DOWN_LEFT: Urn<'static> = tightbeam::urn!("test", "event:diners/puts-down-left");
pub(crate) const PUTS_DOWN_RIGHT: Urn<'static> = tightbeam::urn!("test", "event:diners/puts-down-right");
pub(crate) const SITS: Urn<'static> = tightbeam::urn!("test", "event:diners/sits");
pub(crate) const THINKS: Urn<'static> = tightbeam::urn!("test", "event:diners/thinks");

/// The bound of an exploration, which covers two cycles and the start of a
/// third. A walk keeps each target of the event it takes, so its work doubles
/// at each nondeterministic edge, and the default bound of 128 spends the state
/// budget of a walk and leaves the deadlock check undecided.
const WALK_DEPTH: usize = 18;

/// The builder of a philosophers process.
type ProcessBuilder = fn() -> Result<Process, ProcessBuildError>;

/// One philosopher thinks, sits, eats, and gets up.
const ONE_CYCLE: &[Urn<'static>] = &[
	THINKS,
	SITS,
	PICKS_LEFT,
	PICKS_RIGHT,
	EATS,
	PUTS_DOWN_LEFT,
	PUTS_DOWN_RIGHT,
	GETS_UP,
];

/// One philosopher runs a cycle, and then the other runs a cycle.
const TWO_CYCLES: &[Urn<'static>] = &[
	THINKS,
	SITS,
	PICKS_LEFT,
	PICKS_RIGHT,
	EATS,
	PUTS_DOWN_LEFT,
	PUTS_DOWN_RIGHT,
	GETS_UP,
	THINKS,
	SITS,
	PICKS_LEFT,
	PICKS_RIGHT,
	EATS,
	PUTS_DOWN_LEFT,
	PUTS_DOWN_RIGHT,
	GETS_UP,
];

/// Each philosopher sits and picks up its left fork.
const BOTH_LEFT: &[Urn<'static>] = &[THINKS, SITS, PICKS_LEFT, THINKS, SITS, PICKS_LEFT];

/// The process of a run that records each event of `run` in order, as a
/// scenario hands its trace to refinement.
fn recorded(run: &[Urn<'static>]) -> Result<Process, TightBeamError> {
	let collector = TraceCollector::new();
	for event in run {
		collector.event(event)?;
	}

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);
	Ok(trace.to_process())
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
		Deadlock => {},
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
	terminal { BothIdle, P1Finished_P2Finished }
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

// Test 1: refinement decides whether a process can perform a run.

// Trace refinement accepts a run that a philosophers process can perform. The
// butler seats one philosopher at a time, so it refutes the run where both
// philosophers hold their left fork.
tb_cases! {
	fn refinement_decides_whether_a_philosophers_process_can_perform_a_run(
		(process, run, decided): (ProcessBuilder, &'static [Urn<'static>], Decision)
	) -> TestResult {
		let spec = process()?;
		let subject = recorded(run)?;
		let config = FdrConfig { specs: vec![spec], ..FdrConfig::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore()?;
		assert_eq!(verdict.trace_refines, decided);
		Ok(())
	}
	cases {
		/// The process with no butler runs one cycle.
		one_cycle_with_no_butler => (DiningPhilosophers::process, ONE_CYCLE, Decision::Holds),
		/// The process with no butler reaches its deadlock.
		the_deadlock_with_no_butler => (DiningPhilosophers::process, BOTH_LEFT, Decision::Holds),
		/// The process with a butler runs one cycle and then the other.
		two_cycles_in_turn_with_a_butler => (DeadlockFreePhilosophers::process, TWO_CYCLES, Decision::Holds),
		/// The butler keeps the second philosopher from its seat, so the
		/// process with a butler refuses the second `SITS`.
		the_deadlock_with_a_butler => (DeadlockFreePhilosophers::process, BOTH_LEFT, Decision::Refuted),
	}
}

// Test 2: exploration decides whether a process deadlocks.

// Exploration finds the deadlock of the process with no butler at the state
// where each philosopher holds its left fork.
tb_cases! {
	fn exploration_decides_whether_a_philosophers_process_deadlocks(
		(process, decided): (ProcessBuilder, (Decision, Option<State>))
	) -> TestResult {
		let subject = process()?;
		let config = FdrConfig { max_depth: WALK_DEPTH, ..FdrConfig::default() };
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let verdict = explorer.explore()?;
		let stuck = verdict.deadlock_witness.map(|(_, _, state)| state);
		assert_eq!((verdict.deadlock_free, stuck), decided);
		Ok(())
	}
	cases {
		/// Each philosopher can hold its left fork, so the process deadlocks.
		with_no_butler => (DiningPhilosophers::process, (Decision::Refuted, Some(State("Deadlock")))),
		/// The butler seats one philosopher at a time, so the process is free
		/// of deadlock.
		with_a_butler => (DeadlockFreePhilosophers::process, (Decision::Holds, None)),
	}
}

// Test 3: each process reaches every state that it defines.

// A philosophers process reaches each state that it defines from its initial
// state.
tb_cases! {
	fn a_philosophers_process_reaches_every_state_it_defines(
		process: ProcessBuilder
	) -> TestResult {
		let unreachable = unreachable_states(&process()?);
		assert_eq!(unreachable, HashSet::new());
		Ok(())
	}
	cases {
		/// The process with no butler reaches every state it defines.
		with_no_butler => DiningPhilosophers::process,
		/// The process with a butler reaches every state it defines.
		with_a_butler => DeadlockFreePhilosophers::process,
	}
}

//! CSP parallel composition operators.
//!
//! This module implements these CSP parallel operators on [`Process`]:
//! - Synchronized parallel: `P || Q`.
//! - Interleaved parallel: `P ||| Q`.
//! - Interface parallel: `P [| A |] Q`.
//! - Alphabetized parallel: `P [| αP | αQ |] Q`.
//!
//! Each operator holds the timing constraints and the schedulability periods
//! of both operands.

use std::collections::HashSet;

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{intern, Event, Process, State};

impl Process {
	/// Synchronized parallel composition: `P || Q`.
	///
	/// The processes synchronize on every shared event, which is an event of
	/// both observable alphabets. An event of one process alone interleaves.
	///
	/// ## State Space
	/// `S = S_P × S_Q`, the Cartesian product of the state spaces.
	///
	/// ## Transitions
	/// - `(p,q) --[e]--> (p',q')` if `e ∈ αP ∩ αQ`, `p --[e]--> p'`, `q --[e]--> q'`
	/// - `(p,q) --[e]--> (p',q)` if `e ∈ αP \ αQ`, `p --[e]--> p'`
	/// - `(p,q) --[e]--> (p,q')` if `e ∈ αQ \ αP`, `q --[e]--> q'`
	///
	/// # Errors
	///
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn synchronized_parallel(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let sync_alphabet: HashSet<Event> = p.observable.intersection(&q.observable).copied().collect();
		let name = intern(format!("({} || {})", p.name, q.name));
		Self::parallel_compose(name, p, q, sync_alphabet)
	}

	/// Interleaved parallel composition: `P ||| Q`.
	///
	/// The processes run independently, and every event interleaves in any
	/// order.
	///
	/// ## State Space
	/// `S = S_P × S_Q`.
	///
	/// ## Transitions
	/// - `(p,q) --[e]--> (p',q)` for any `p --[e]--> p'`
	/// - `(p,q) --[e]--> (p,q')` for any `q --[e]--> q'`
	///
	/// # Errors
	///
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn interleaved_parallel(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = intern(format!("({} ||| {})", p.name, q.name));
		Self::parallel_compose(name, p, q, HashSet::new())
	}

	/// Interface parallel composition: `P [| A |] Q`.
	///
	/// The processes synchronize only on the events of the sync alphabet `A`,
	/// and every other event interleaves.
	///
	/// ## Parameters
	/// - `sync_alphabet`: the set `A` of events that the processes synchronize on.
	///
	/// ## State Space
	/// `S = S_P × S_Q`.
	///
	/// ## Transitions
	/// - `(p,q) --[e]--> (p',q')` if `e ∈ A`, `p --[e]--> p'`, `q --[e]--> q'`
	/// - `(p,q) --[e]--> (p',q)` if `e ∉ A`, `p --[e]--> p'`
	/// - `(p,q) --[e]--> (p,q')` if `e ∉ A`, `q --[e]--> q'`
	///
	/// # Errors
	///
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn interface_parallel(
		p: &Process,
		q: &Process,
		sync_alphabet: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		let name = intern(format!("({} [|A|] {})", p.name, q.name));
		Self::parallel_compose(name, p, q, sync_alphabet)
	}

	/// Alphabetized parallel composition: `P [| αP | αQ |] Q`.
	///
	/// Each process performs only the observable events of its own alphabet,
	/// as Roscoe's alphabetized parallel states (A.W. Roscoe, *The Theory and
	/// Practice of Concurrency*, 2005 revision):
	///
	/// - An event of `alpha_p` and of `alpha_q` moves both processes together.
	/// - An event of one alphabet alone moves its process alone.
	/// - An observable event outside the alphabet of its process cannot occur.
	/// - A hidden event of either process interleaves.
	///
	/// ## Parameters
	/// - `alpha_p`: the alphabet of process `P`.
	/// - `alpha_q`: the alphabet of process `Q`.
	///
	/// # Errors
	///
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn alphabetized_parallel(
		p: &Process,
		alpha_p: HashSet<Event>,
		q: &Process,
		alpha_q: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		let sync_alphabet: HashSet<Event> = alpha_p.intersection(&alpha_q).copied().collect();
		let name = intern(format!("({} [|α|] {})", p.name, q.name));
		let p = p.restricted(&alpha_p);
		let q = q.restricted(&alpha_q);
		Self::parallel_compose(name, &p, &q, sync_alphabet)
	}

	/// This process with each observable event outside `alphabet` refused.
	///
	/// A hidden event stays, because an alphabet of a parallel composition
	/// names observable events alone.
	fn restricted(&self, alphabet: &HashSet<Event>) -> Process {
		let permitted = |event: &Event| self.hidden.contains(event) || alphabet.contains(event);
		let mut restricted = self.clone();
		restricted.observable.retain(|event| alphabet.contains(event));
		restricted.transitions.retain(permitted);

		#[cfg(feature = "testing-timing")]
		if let Some(timed) = restricted.timed_transitions.as_mut() {
			timed.retain(|(_, event), _| permitted(event));
		}

		restricted
	}

	/// The product construction that every parallel operator shares.
	///
	/// The operators differ only in their synchronization set:
	/// - [`Self::synchronized_parallel`]: `αP ∩ αQ`, every shared observable event.
	/// - [`Self::interface_parallel`]: the caller's `A`.
	/// - [`Self::interleaved_parallel`]: `∅`, which is pure interleaving.
	///
	/// ## Transitions over S = S_P × S_Q
	/// - `(p,q) --[e]--> (p',q')` if `e ∈ sync`, `p --[e]--> p'`, `q --[e]--> q'`
	/// - `(p,q) --[e]--> (p',q)` if `e ∉ sync`, `p --[e]--> p'`
	/// - `(p,q) --[e]--> (p,q')` if `e ∉ sync`, `q --[e]--> q'`
	///
	/// The composition keeps the alphabet of each event, so a hidden (τ) event
	/// of either component stays hidden. On a name collision between the
	/// components, the alphabet of `P` wins.
	///
	/// The function refuses an operand with a timed transition. A guard has no
	/// conjunction, so the product has no single guard for an event that both
	/// operands guard.
	fn parallel_compose(
		name: &'static str,
		p: &Process,
		q: &Process,
		sync_alphabet: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		#[cfg(feature = "testing-timing")]
		if let Some(timed) = [p, q].into_iter().find(|operand| operand.has_timed_transitions()) {
			let operand = timed.name;
			let reason = format!("{operand} has a timed transition, which a parallel composition cannot carry");
			return Err(CompositionError::InvalidComposition { reason });
		}

		let builder = p.observable.iter().fold(
			Process::builder(name).initial_state(State::product(p.initial, q.initial)),
			|b, event| b.add_observable(event),
		);
		let builder = p.hidden.iter().fold(builder, |b, event| b.add_hidden(event));
		let builder = q
			.observable
			.iter()
			.filter(|event| !p.observable.contains(event) && !p.hidden.contains(event))
			.fold(builder, |b, event| b.add_observable(event));
		let builder = q
			.hidden
			.iter()
			.filter(|event| !p.observable.contains(event) && !p.hidden.contains(event))
			.fold(builder, |b, event| b.add_hidden(event));

		// Collect the transitions in a vector first to keep the closures flat.
		let mut all_transitions = Vec::new();
		for (p_state, q_state) in p.states.iter().flat_map(|p_s| q.states.iter().map(move |q_s| (p_s, q_s))) {
			let product_state = State::product(*p_state, *q_state);
			let p_actions = p.enabled(*p_state);
			let q_actions = q.enabled(*q_state);

			// A synchronized event moves both components together.
			for p_action in p_actions.iter().filter(|a| sync_alphabet.contains(&a.event)) {
				if q_actions.iter().any(|a| a.event == p_action.event) {
					let p_targets = p.step(*p_state, &p_action.event);
					let q_targets = q.step(*q_state, &p_action.event);
					for (p_target, q_target) in
						p_targets.iter().flat_map(|p_t| q_targets.iter().map(move |q_t| (p_t, q_t)))
					{
						all_transitions.push((product_state, p_action.event, State::product(*p_target, *q_target)));
					}
				}
			}

			// P moves alone on an event outside the sync set.
			for p_action in p_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for p_target in p.step(*p_state, &p_action.event) {
					all_transitions.push((product_state, p_action.event, State::product(p_target, *q_state)));
				}
			}

			// Q moves alone on an event outside the sync set.
			for q_action in q_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for q_target in q.step(*q_state, &q_action.event) {
					all_transitions.push((product_state, q_action.event, State::product(*p_state, q_target)));
				}
			}
		}

		let builder = all_transitions.into_iter().fold(builder, |b, (state, event, target)| {
			b.add_state(state).add_state(target).add_transition(state, event, target)
		});

		let builder = p
			.terminal
			.iter()
			.flat_map(|p_t| q.terminal.iter().map(move |q_t| (p_t, q_t)))
			.fold(builder, |b, (p_term, q_term)| b.add_terminal(State::product(*p_term, *q_term)));

		#[cfg(feature = "testing-timing")]
		let builder = builder.timing_of_both(p, q)?;

		Ok(builder.build()?)
	}
}

impl State {
	/// Creates the product state of two component states, named `(s1,s2)`.
	pub fn product(s1: State, s2: State) -> State {
		State(intern(format!("({},{})", s1.0, s2.0)))
	}
}

#[cfg(test)]
mod tests {
	#[cfg(feature = "testing-timing")]
	use core::time::Duration;

	use super::*;
	use crate::testing::specs::csp::Process;

	#[cfg(feature = "testing-timing")]
	use crate::builder::TypeBuilder;
	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::{TimingConstraint, TimingConstraints, TimingGuard, WcetConfigBuilder};

	fn simple_process_p() -> Process {
		Process::builder("P")
			.initial_state(State("p0"))
			.add_state(State("p0"))
			.add_state(State("p1"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("p0"), Event("a"), State("p1"))
			.add_terminal(State("p1"))
			.build()
			.expect("Failed to build process P")
	}

	fn simple_process_q() -> Process {
		Process::builder("Q")
			.initial_state(State("q0"))
			.add_state(State("q0"))
			.add_state(State("q1"))
			.add_observable(Event("b"))
			.add_observable(Event("c"))
			.add_transition(State("q0"), Event("b"), State("q1"))
			.add_terminal(State("q1"))
			.build()
			.expect("Failed to build process Q")
	}

	#[test]
	fn test_synchronized_parallel_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process_p();
		let q = simple_process_q();

		let composed = Process::synchronized_parallel(&p, &q)?;
		assert_eq!(composed.name, "(P || Q)");
		assert!(composed.states.len() >= 2);
		Ok(())
	}

	#[test]
	fn test_interleaved_parallel_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process_p();
		let q = simple_process_q();

		let composed = Process::interleaved_parallel(&p, &q)?;
		assert_eq!(composed.name, "(P ||| Q)");
		assert!(composed.states.len() >= 2);
		Ok(())
	}

	#[test]
	fn test_interface_parallel_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process_p();
		let q = simple_process_q();
		let sync_alphabet = [Event("b")].iter().copied().collect();

		let composed = Process::interface_parallel(&p, &q, sync_alphabet)?;
		assert_eq!(composed.name, "(P [|A|] Q)");
		assert!(composed.states.len() >= 2);
		Ok(())
	}

	#[test]
	fn test_alphabetized_parallel_basic() -> Result<(), Box<dyn core::error::Error>> {
		let p = simple_process_p();
		let q = simple_process_q();
		let alpha_p = [Event("a"), Event("b")].iter().copied().collect();
		let alpha_q = [Event("b"), Event("c")].iter().copied().collect();

		let composed = Process::alphabetized_parallel(&p, alpha_p, &q, alpha_q)?;
		assert!(composed.states.len() >= 2);

		Ok(())
	}

	/// One parallel operator over two processes.
	type Compose = fn(&Process, &Process) -> Result<Process, CompositionError>;

	/// A process `P` that takes its hidden `tau_p` and then `a`.
	fn hiding_p() -> Process {
		Process::builder("P")
			.initial_state(State("p0"))
			.add_observable(Event("a"))
			.add_hidden(Event("tau_p"))
			.add_transition(State("p0"), Event("tau_p"), State("p1"))
			.add_transition(State("p1"), Event("a"), State("p2"))
			.add_terminal(State("p2"))
			.build()
			.expect("Failed to build process P")
	}

	/// A process `Q` that takes its hidden `tau_q` and then `b`.
	fn hiding_q() -> Process {
		Process::builder("Q")
			.initial_state(State("q0"))
			.add_observable(Event("b"))
			.add_hidden(Event("tau_q"))
			.add_transition(State("q0"), Event("tau_q"), State("q1"))
			.add_transition(State("q1"), Event("b"), State("q2"))
			.add_terminal(State("q2"))
			.build()
			.expect("Failed to build process Q")
	}

	// Each parallel operator keeps the hidden events of both operands hidden.
	crate::tb_cases! {
		fn parallel_composition_preserves_hidden_alphabet(compose: Compose) -> Result<(), CompositionError> {
			let p = hiding_p();
			let q = hiding_q();

			let composed = compose(&p, &q)?;

			assert!(composed.hidden.contains(&Event("tau_p")));
			assert!(composed.hidden.contains(&Event("tau_q")));
			assert!(!composed.observable.contains(&Event("tau_p")));
			assert!(!composed.observable.contains(&Event("tau_q")));
			Ok(())
		}

		cases {
			synchronized => Process::synchronized_parallel,
			interleaved => Process::interleaved_parallel,
			interface => |p, q| Process::interface_parallel(p, q, HashSet::new()),
		}
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_timed_operand_does_not_compose_in_parallel() -> Result<(), Box<dyn core::error::Error>> {
		let guard = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let timed = Process::builder("T")
			.initial_state(State("t0"))
			.clock("clk")
			.add_observable(Event("a"))
			.add_timed_transition(State("t0"), Event("a"), State("t1"), Some(guard), Vec::new())
			.build()?;

		let composed = Process::interleaved_parallel(&timed, &simple_process_q());
		assert!(matches!(composed, Err(CompositionError::InvalidComposition { .. })));
		Ok(())
	}

	/// A process in which `a` or `c` takes `p0` to the terminal `p1`.
	fn a_or_c() -> Process {
		Process::builder("AC")
			.initial_state(State("p0"))
			.add_observable(Event("a"))
			.add_observable(Event("c"))
			.add_transition(State("p0"), Event("a"), State("p1"))
			.add_transition(State("p0"), Event("c"), State("p1"))
			.add_terminal(State("p1"))
			.build()
			.expect("a process with an initial state builds")
	}

	/// The process of `simple_process_p`, with a WCET of 10 ms on `a`.
	#[cfg(feature = "testing-timing")]
	fn timed_p() -> Process {
		let wcet = WcetConfigBuilder::default().with_duration(Duration::from_millis(10)).build();
		let wcet = wcet.expect("a WCET with a duration builds");
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("a"), TimingConstraint::Wcet(wcet));

		Process::builder("P")
			.initial_state(State("p0"))
			.add_observable(Event("a"))
			.add_transition(State("p0"), Event("a"), State("p1"))
			.add_terminal(State("p1"))
			.timing_constraints(constraints)
			.build()
			.expect("a process with an initial state builds")
	}

	#[test]
	fn an_alphabetized_operand_performs_its_own_alphabet_alone() -> Result<(), Box<dyn core::error::Error>> {
		let alpha_p = HashSet::from([Event("a")]);
		let alpha_q = HashSet::from([Event("b"), Event("c")]);

		let composed = Process::alphabetized_parallel(&a_or_c(), alpha_p, &simple_process_q(), alpha_q)?;
		assert_eq!(composed.offers(composed.initial), HashSet::from([Event("a"), Event("b")]));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn an_interleaving_holds_the_timing_of_its_operands() -> Result<(), Box<dyn core::error::Error>> {
		let composed = Process::interleaved_parallel(&timed_p(), &simple_process_q())?;
		let constraints = composed.timing_constraints.as_ref();
		assert!(constraints.is_some_and(|constraints| constraints.has_constraint(&Event("a"))));
		Ok(())
	}
}

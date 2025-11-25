//! CSP Parallel Composition Operators
//!
//! Implements the core parallel composition operators from CSP theory:
//! - Synchronized parallel (||)
//! - Interleaved parallel (|||)
//! - Interface parallel ([| A |])
//! - Alphabetized parallel ([| αP | αQ |])

use std::collections::HashSet;

use crate::testing::specs::composition::CompositionError;
use crate::testing::specs::csp::{Event, Process, State};

impl Process {
	/// Synchronized parallel composition: P || Q
	///
	/// Processes synchronize on ALL shared events (events in both alphabets).
	/// Events unique to each process interleave independently.
	///
	/// ## State Space
	/// S = S_P × S_Q (Cartesian product of state spaces)
	///
	/// ## Transitions
	/// - (p,q) --[e]--> (p',q') if e ∈ αP ∩ αQ, p --[e]--> p', q --[e]--> q'
	/// - (p,q) --[e]--> (p',q)  if e ∈ αP \ αQ, p --[e]--> p'
	/// - (p,q) --[e]--> (p,q')  if e ∈ αQ \ αP, q --[e]--> q'
	pub fn synchronized_parallel(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let shared_events: HashSet<Event> = p.observable.intersection(&q.observable).copied().collect();
		let name = Box::leak(format!("({} || {})", p.name, q.name).into_boxed_str());
		let builder = p.observable.iter().chain(p.hidden.iter()).fold(
			Process::builder(name).initial_state(State::product(p.initial, q.initial)),
			|b, event| b.add_observable(event.0),
		);

		let builder = q
			.observable
			.iter()
			.chain(q.hidden.iter())
			.filter(|event| !p.observable.contains(event) && !p.hidden.contains(event))
			.fold(builder, |b, event| b.add_observable(event.0));

		// Collect all transitions into a vec to avoid complex nested closures
		let mut all_transitions = Vec::new();
		for (p_state, q_state) in p.states.iter().flat_map(|p_s| q.states.iter().map(move |q_s| (p_s, q_s))) {
			let product_state = State::product(*p_state, *q_state);
			let p_actions = p.enabled(*p_state);
			let q_actions = q.enabled(*q_state);

			// Synchronized events
			for p_action in p_actions.iter().filter(|a| shared_events.contains(&a.event)) {
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

			// P-only events
			for p_action in p_actions.iter().filter(|a| !shared_events.contains(&a.event)) {
				for p_target in p.step(*p_state, &p_action.event) {
					all_transitions.push((product_state, p_action.event, State::product(p_target, *q_state)));
				}
			}

			// Q-only events
			for q_action in q_actions.iter().filter(|a| !shared_events.contains(&a.event)) {
				for q_target in q.step(*q_state, &q_action.event) {
					all_transitions.push((product_state, q_action.event, State::product(*p_state, q_target)));
				}
			}
		}

		let builder = all_transitions.into_iter().fold(builder, |b, (state, event, target)| {
			b.add_state(target).add_transition(state, event.0, target)
		});

		let builder = p
			.terminal
			.iter()
			.flat_map(|p_t| q.terminal.iter().map(move |q_t| (p_t, q_t)))
			.fold(builder, |b, (p_term, q_term)| b.add_terminal(State::product(*p_term, *q_term)));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Interleaved parallel composition: P ||| Q
	///
	/// Processes run independently with no synchronization.
	/// All events interleave arbitrarily.
	///
	/// ## State Space
	/// S = S_P × S_Q
	///
	/// ## Transitions
	/// - (p,q) --[e]--> (p',q) for any p --[e]--> p'
	/// - (p,q) --[e]--> (p,q') for any q --[e]--> q'
	pub fn interleaved_parallel(p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = Box::leak(format!("({} ||| {})", p.name, q.name).into_boxed_str());
		let builder = p.observable.iter().chain(p.hidden.iter()).fold(
			Process::builder(name).initial_state(State::product(p.initial, q.initial)),
			|b, event| b.add_observable(event.0),
		);

		let builder = q
			.observable
			.iter()
			.chain(q.hidden.iter())
			.filter(|event| !p.observable.contains(event) && !p.hidden.contains(event))
			.fold(builder, |b, event| b.add_observable(event.0));

		// Collect all product states and transitions
		let mut all_transitions = Vec::new();
		for (p_state, q_state) in p.states.iter().flat_map(|p_s| q.states.iter().map(move |q_s| (p_s, q_s))) {
			let product_state = State::product(*p_state, *q_state);

			for p_action in p.enabled(*p_state) {
				for p_target in p.step(*p_state, &p_action.event) {
					all_transitions.push((product_state, p_action.event, State::product(p_target, *q_state)));
				}
			}

			for q_action in q.enabled(*q_state) {
				for q_target in q.step(*q_state, &q_action.event) {
					all_transitions.push((product_state, q_action.event, State::product(*p_state, q_target)));
				}
			}
		}

		let builder = all_transitions.into_iter().fold(builder, |b, (state, event, target)| {
			b.add_state(state).add_state(target).add_transition(state, event.0, target)
		});

		let builder = p
			.terminal
			.iter()
			.flat_map(|p_t| q.terminal.iter().map(move |q_t| (p_t, q_t)))
			.fold(builder, |b, (p_term, q_term)| b.add_terminal(State::product(*p_term, *q_term)));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Interface parallel composition: P [| A |] Q
	///
	/// Processes synchronize only on events in the sync alphabet A.
	/// All other events interleave.
	///
	/// ## Parameters
	/// - `sync_alphabet`: Set of events on which to synchronize
	///
	/// ## State Space
	/// S = S_P × S_Q
	///
	/// ## Transitions
	/// - (p,q) --[e]--> (p',q') if e ∈ A, p --[e]--> p', q --[e]--> q'
	/// - (p,q) --[e]--> (p',q)  if e ∉ A, p --[e]--> p'
	/// - (p,q) --[e]--> (p,q')  if e ∉ A, q --[e]--> q'
	pub fn interface_parallel(
		p: &Process,
		q: &Process,
		sync_alphabet: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		let name = Box::leak(format!("({} [|A|] {})", p.name, q.name).into_boxed_str());
		let builder = p.observable.iter().chain(p.hidden.iter()).fold(
			Process::builder(name).initial_state(State::product(p.initial, q.initial)),
			|b, event| b.add_observable(event.0),
		);

		let builder = q
			.observable
			.iter()
			.chain(q.hidden.iter())
			.filter(|event| !p.observable.contains(event) && !p.hidden.contains(event))
			.fold(builder, |b, event| b.add_observable(event.0));

		// Collect all transitions
		let mut all_transitions = Vec::new();
		for (p_state, q_state) in p.states.iter().flat_map(|p_s| q.states.iter().map(move |q_s| (p_s, q_s))) {
			let product_state = State::product(*p_state, *q_state);
			let p_actions = p.enabled(*p_state);
			let q_actions = q.enabled(*q_state);

			// Synchronized events
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

			// P-only events
			for p_action in p_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for p_target in p.step(*p_state, &p_action.event) {
					all_transitions.push((product_state, p_action.event, State::product(p_target, *q_state)));
				}
			}

			// Q-only events
			for q_action in q_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for q_target in q.step(*q_state, &q_action.event) {
					all_transitions.push((product_state, q_action.event, State::product(*p_state, q_target)));
				}
			}
		}

		let builder = all_transitions.into_iter().fold(builder, |b, (state, event, target)| {
			b.add_state(state).add_state(target).add_transition(state, event.0, target)
		});

		let builder = p
			.terminal
			.iter()
			.flat_map(|p_t| q.terminal.iter().map(move |q_t| (p_t, q_t)))
			.fold(builder, |b, (p_term, q_term)| b.add_terminal(State::product(*p_term, *q_term)));

		builder
			.build()
			.map_err(|e| CompositionError::ProcessConstructionFailed { reason: e.to_string() })
	}

	/// Alphabetized parallel composition: P [| αP | αQ |] Q
	///
	/// Each process is restricted to its alphabet, then they synchronize
	/// on the intersection of their alphabets.
	///
	/// ## Parameters
	/// - `alpha_p`: Alphabet for process P
	/// - `alpha_q`: Alphabet for process Q
	pub fn alphabetized_parallel(
		p: &Process,
		alpha_p: HashSet<Event>,
		q: &Process,
		alpha_q: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		// Sync on intersection of alphabets
		let sync_alphabet: HashSet<Event> = alpha_p.intersection(&alpha_q).copied().collect();
		// Use interface parallel with the intersection as sync alphabet
		Self::interface_parallel(p, q, sync_alphabet)
	}
}

impl State {
	/// Create a product state from two component states
	pub fn product(s1: State, s2: State) -> State {
		let name = Box::leak(format!("({},{})", s1.0, s2.0).into_boxed_str());
		State(name)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::specs::csp::Process;

	fn simple_process_p() -> Process {
		Process::builder("P")
			.initial_state(State("p0"))
			.add_state(State("p0"))
			.add_state(State("p1"))
			.add_observable("a")
			.add_observable("b")
			.add_transition(State("p0"), "a", State("p1"))
			.add_terminal(State("p1"))
			.build()
			.expect("Failed to build process P")
	}

	fn simple_process_q() -> Process {
		Process::builder("Q")
			.initial_state(State("q0"))
			.add_state(State("q0"))
			.add_state(State("q1"))
			.add_observable("b")
			.add_observable("c")
			.add_transition(State("q0"), "b", State("q1"))
			.add_terminal(State("q1"))
			.build()
			.expect("Failed to build process Q")
	}

	#[test]
	fn test_synchronized_parallel_basic() {
		let p = simple_process_p();
		let q = simple_process_q();

		let composed = Process::synchronized_parallel(&p, &q).expect("Composition failed");
		assert_eq!(composed.name, "(P || Q)");
		assert!(composed.states.len() >= 2);
	}

	#[test]
	fn test_interleaved_parallel_basic() {
		let p = simple_process_p();
		let q = simple_process_q();

		let composed = Process::interleaved_parallel(&p, &q).expect("Composition failed");
		assert_eq!(composed.name, "(P ||| Q)");
		assert!(composed.states.len() >= 2);
	}

	#[test]
	fn test_interface_parallel_basic() {
		let p = simple_process_p();
		let q = simple_process_q();
		let sync_alphabet = [Event("b")].iter().copied().collect();

		let composed = Process::interface_parallel(&p, &q, sync_alphabet).expect("Composition failed");
		assert_eq!(composed.name, "(P [|A|] Q)");
		assert!(composed.states.len() >= 2);
	}

	#[test]
	fn test_alphabetized_parallel_basic() {
		let p = simple_process_p();
		let q = simple_process_q();
		let alpha_p = [Event("a"), Event("b")].iter().copied().collect();
		let alpha_q = [Event("b"), Event("c")].iter().copied().collect();

		let composed = Process::alphabetized_parallel(&p, alpha_p, &q, alpha_q).expect("Composition failed");
		assert!(composed.states.len() >= 2);
	}
}

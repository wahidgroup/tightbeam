//! CSP parallel composition operators.
//!
//! It implements these CSP parallel operators on [`Process`]:
//! - Synchronized parallel: `P || Q`.
//! - Interleaved parallel: `P ||| Q`.
//! - Interface parallel: `P [| A |] Q`.
//! - Alphabetized parallel: `P [| αP | αQ |] Q`.
//!
//! Each operator holds the timing constraints and the schedulability periods
//! of both operands. [`CompositionOperator`] decides the semantics of each
//! operator, and the functions on [`Process`] and
//! [`ProcessExpr::Parallel`](super::ProcessExpr::Parallel) compose through it.

use std::collections::HashSet;

use crate::testing::specs::composition::{CompositionError, CompositionOperator};
use crate::testing::specs::csp::{intern, Components, Event, Process, State};

impl CompositionOperator {
	/// Composes `p` and `q` under this operator.
	///
	/// A declared alphabet names observable events of the operands:
	/// - Each event of an interface is an event of `p` or of `q`.
	/// - An alphabetized composition holds events of `p` in its left alphabet and of `q` in its right one.
	///
	/// The operator refuses a declared event outside them, such as a misspelled
	/// name, because no operand performs it.
	///
	/// # Errors
	///
	/// - [`CompositionError::AlphabetMismatch`] -- a declared alphabet holds an event outside its operands.
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	///
	/// # Examples
	///
	/// ```
	/// use std::collections::HashSet;
	///
	/// use tightbeam::testing::specs::composition::{CompositionError, CompositionOperator};
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let ping = Process::builder("Ping")
	///     .initial_state(State("idle"))
	///     .add_observable(Event("ping"))
	///     .add_transition(State("idle"), Event("ping"), State("done"))
	///     .add_terminal(State("done"))
	///     .build()?;
	///
	/// let interface = CompositionOperator::Interface { events: HashSet::from([Event("ping")]) };
	/// let composed = interface.compose(&ping, &ping)?;
	/// assert_eq!(composed.name(), "(Ping [|A|] Ping)");
	///
	/// let misspelled = CompositionOperator::Interface { events: HashSet::from([Event("pnig")]) };
	/// let refused = misspelled.compose(&ping, &ping);
	/// assert!(matches!(refused, Err(CompositionError::AlphabetMismatch { .. })));
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn compose(&self, p: &Process, q: &Process) -> Result<Process, CompositionError> {
		let name = self.name_of(p, q);
		let sync_alphabet = self.sync_alphabet(p, q);

		match self {
			Self::Synchronized | Self::Interleaved => Process::parallel_compose(name, p, q, sync_alphabet),
			Self::Interface { events } => {
				let operands: HashSet<Event> = p.observable.union(&q.observable).copied().collect();
				Self::check_within(events, &operands)?;
				Process::parallel_compose(name, p, q, sync_alphabet)
			}
			Self::Alphabetized { left, right } => {
				Self::check_within(left, &p.observable)?;
				Self::check_within(right, &q.observable)?;
				Process::parallel_compose(name, &p.restricted(left), &q.restricted(right), sync_alphabet)
			}
		}
	}

	/// The events on which `p` and `q` synchronize under this operator.
	///
	/// - Synchronized: each observable event that both operands share, `αP ∩ αQ`.
	/// - Interleaved: no event.
	/// - Interface: the events of the interface `A`.
	/// - Alphabetized: each event that both declared alphabets share.
	///
	/// # Examples
	///
	/// ```
	/// use std::collections::HashSet;
	///
	/// use tightbeam::testing::specs::composition::CompositionOperator;
	/// use tightbeam::testing::specs::csp::{Event, Process, State};
	///
	/// let both = |name, first, second| {
	///     let builder = Process::builder(name).initial_state(State("s"));
	///     builder.add_observable(Event(first)).add_observable(Event(second)).build()
	/// };
	/// let (ab, bc) = (both("AB", "a", "b")?, both("BC", "b", "c")?);
	///
	/// let synchronized = CompositionOperator::Synchronized.sync_alphabet(&ab, &bc);
	/// let interleaved = CompositionOperator::Interleaved.sync_alphabet(&ab, &bc);
	/// assert_eq!(synchronized, HashSet::from([Event("b")]));
	/// assert_eq!(interleaved, HashSet::new());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn sync_alphabet(&self, p: &Process, q: &Process) -> HashSet<Event> {
		match self {
			Self::Synchronized => p.observable.intersection(&q.observable).copied().collect(),
			Self::Interleaved => HashSet::new(),
			Self::Interface { events } => events.clone(),
			Self::Alphabetized { left, right } => left.intersection(right).copied().collect(),
		}
	}

	/// The name of the composition of `p` and `q` under this operator, in CSP
	/// notation.
	fn name_of(&self, p: &Process, q: &Process) -> &'static str {
		intern(format!("({} {} {})", p.name, self.symbol(), q.name))
	}

	/// The symbol of this operator in the CSP notation of a name, which
	/// [`Self::name_of`] and [`ProcessExpr::name`](super::ProcessExpr::name)
	/// share.
	pub(crate) fn symbol(&self) -> &'static str {
		match self {
			Self::Synchronized => "||",
			Self::Interleaved => "|||",
			Self::Interface { .. } => "[|A|]",
			Self::Alphabetized { .. } => "[|α|]",
		}
	}

	/// Checks that each event of `declared` is an event of `alphabet`.
	///
	/// # Errors
	///
	/// - [`CompositionError::AlphabetMismatch`] -- `declared` holds an event outside `alphabet`.
	fn check_within(declared: &HashSet<Event>, alphabet: &HashSet<Event>) -> Result<(), CompositionError> {
		if declared.is_subset(alphabet) {
			return Ok(());
		}

		let expected = declared.clone();
		let actual = alphabet.clone();
		Err(CompositionError::AlphabetMismatch { expected, actual })
	}
}

impl Process {
	/// Synchronized parallel composition: `P || Q`.
	///
	/// The processes synchronize on every event of both observable alphabets.
	/// An event of one process alone interleaves.
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
		CompositionOperator::Synchronized.compose(p, q)
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
		CompositionOperator::Interleaved.compose(p, q)
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
	/// - [`CompositionError::AlphabetMismatch`] -- `sync_alphabet` holds an event of neither `p` nor `q`.
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn interface_parallel(
		p: &Process,
		q: &Process,
		sync_alphabet: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		CompositionOperator::Interface { events: sync_alphabet }.compose(p, q)
	}

	/// Alphabetized parallel composition: `P [| αP | αQ |] Q`.
	///
	/// Each process performs only the observable events of its own alphabet,
	/// by Roscoe's alphabetized parallel (A.W. Roscoe, *The Theory and
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
	/// - [`CompositionError::AlphabetMismatch`] -- an alphabet holds an event outside its operand.
	/// - [`CompositionError::InvalidComposition`] -- `p` or `q` has a timed transition.
	/// - [`CompositionError::ConflictingTiming`] -- `p` and `q` state timing for one event that differs.
	/// - [`CompositionError::ConflictingScheduler`] -- `p` and `q` name different schedulers.
	pub fn alphabetized_parallel(
		p: &Process,
		alpha_p: HashSet<Event>,
		q: &Process,
		alpha_q: HashSet<Event>,
	) -> Result<Process, CompositionError> {
		CompositionOperator::Alphabetized { left: alpha_p, right: alpha_q }.compose(p, q)
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
	/// The operators differ in their synchronization set
	/// ([`CompositionOperator::sync_alphabet`]). The alphabetized operator also
	/// restricts each operand to its alphabet first.
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
	/// It refuses an operand with a timed transition. A guard has no
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

		// The components of `Q` follow those of `P`, so an edge of `Q` moves
		// its own components, raised by the count of `P`.
		let offset = p.components.count();
		let builder = builder.components(offset.saturating_add(q.components.count()));

		// Collect the transitions in a vector first to keep the closures flat.
		let mut all_transitions = Vec::new();
		for (p_state, q_state) in p.states.iter().flat_map(|p_s| q.states.iter().map(move |q_s| (p_s, q_s))) {
			let product_state = State::product(*p_state, *q_state);
			let p_actions = p.enabled(*p_state);
			let q_actions = q.enabled(*q_state);

			// A synchronized event moves both components together.
			for p_action in p_actions.iter().filter(|a| sync_alphabet.contains(&a.event)) {
				if q_actions.iter().any(|a| a.event == p_action.event) {
					let event = p_action.event;
					let p_targets = p.step(*p_state, &event);
					let q_targets = q.step(*q_state, &event);
					for (p_target, q_target) in
						p_targets.iter().flat_map(|p_t| q_targets.iter().map(move |q_t| (p_t, q_t)))
					{
						let p_movers = p.components.moving((*p_state, event, *p_target), 0);
						let q_movers = q.components.moving((*q_state, event, *q_target), offset);
						let movers = Components::together(&p_movers, &q_movers);
						let target = State::product(*p_target, *q_target);
						all_transitions.push((product_state, event, target, movers));
					}
				}
			}

			// P moves alone on an event outside the sync set.
			for p_action in p_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for p_target in p.step(*p_state, &p_action.event) {
					let movers = p.components.moving((*p_state, p_action.event, p_target), 0);
					let target = State::product(p_target, *q_state);
					all_transitions.push((product_state, p_action.event, target, movers));
				}
			}

			// Q moves alone on an event outside the sync set.
			for q_action in q_actions.iter().filter(|a| !sync_alphabet.contains(&a.event)) {
				for q_target in q.step(*q_state, &q_action.event) {
					let movers = q.components.moving((*q_state, q_action.event, q_target), offset);
					let target = State::product(*p_state, q_target);
					all_transitions.push((product_state, q_action.event, target, movers));
				}
			}
		}

		let builder = all_transitions.into_iter().fold(builder, |b, (state, event, target, movers)| {
			let edge = (state, event, target);
			let placed = b.add_state(state).add_state(target);
			placed.add_transition(state, event, target).add_movers(edge, movers)
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
	use crate::testing::specs::composition::ProcessExpr;
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
	fn timed_p() -> Result<Process, crate::testing::error::TestingError> {
		let wcet = WcetConfigBuilder::default().with_duration(Duration::from_millis(10)).build();
		let wcet = wcet.expect("a WCET with a duration builds");
		let mut constraints = TimingConstraints::default();
		constraints.add(Event("a"), TimingConstraint::Wcet(wcet))?;

		let process = Process::builder("P")
			.initial_state(State("p0"))
			.add_observable(Event("a"))
			.add_transition(State("p0"), Event("a"), State("p1"))
			.add_terminal(State("p1"))
			.timing_constraints(constraints)
			.build()
			.expect("a process with an initial state builds");
		Ok(process)
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
		let composed = Process::interleaved_parallel(&timed_p()?, &simple_process_q())?;
		let constraints = composed.timing_constraints.as_ref();
		assert!(constraints.is_some_and(|constraints| constraints.has_constraint(&Event("a"))));
		Ok(())
	}

	/// A process `name` that takes `ping` from `idle` to the terminal `done`.
	fn ping(name: &'static str) -> Process {
		Process::builder(name)
			.initial_state(State("idle"))
			.add_observable(Event("ping"))
			.add_transition(State("idle"), Event("ping"), State("done"))
			.add_terminal(State("done"))
			.build()
			.expect("a process with an initial state builds")
	}

	#[test]
	fn an_interface_on_an_event_of_both_operands_moves_them_together() -> Result<(), CompositionError> {
		let interface = CompositionOperator::Interface { events: HashSet::from([Event("ping")]) };
		let composed = interface.compose(&ping("P"), &ping("Q"))?;

		let after_ping = composed.step(composed.initial, &Event("ping"));
		assert_eq!(after_ping, vec![State::product(State("done"), State("done"))]);
		Ok(())
	}

	#[test]
	fn an_interface_that_names_an_event_outside_both_operands_is_refused() -> Result<(), CompositionError> {
		let interface = CompositionOperator::Interface { events: HashSet::from([Event("pnig")]) };
		let composed = interface.compose(&ping("P"), &ping("Q"));
		assert!(matches!(composed, Err(CompositionError::AlphabetMismatch { .. })));
		Ok(())
	}

	#[test]
	fn an_alphabetized_operand_that_declares_an_event_it_lacks_is_refused() -> Result<(), CompositionError> {
		let left = HashSet::from([Event("ping")]);
		let alphabetized = CompositionOperator::Alphabetized { left, right: HashSet::from([Event("pong")]) };

		let composed = alphabetized.compose(&ping("P"), &ping("Q"));
		assert!(matches!(composed, Err(CompositionError::AlphabetMismatch { .. })));
		Ok(())
	}

	#[test]
	fn a_synchronized_composition_synchronizes_on_the_shared_events() -> Result<(), CompositionError> {
		let synchronized = CompositionOperator::Synchronized.sync_alphabet(&simple_process_p(), &simple_process_q());
		assert_eq!(synchronized, HashSet::from([Event("b")]));
		Ok(())
	}

	#[test]
	fn an_expression_names_each_parallel_operator_by_its_symbol() -> Result<(), CompositionError> {
		let atom = |name| Box::new(ProcessExpr::atomic(name, ping(name)));
		let operator = CompositionOperator::Synchronized;
		let synchronized = ProcessExpr::Parallel { operator, left: atom("P"), right: atom("Q") };
		let operator = CompositionOperator::Interleaved;

		let interleaved = ProcessExpr::Parallel { operator, left: Box::new(synchronized), right: atom("R") };
		assert_eq!(interleaved.name(), "((P || Q) ||| R)");
		Ok(())
	}

	#[test]
	fn an_expression_with_an_interface_outside_its_operands_is_refused() -> Result<(), CompositionError> {
		let left = Box::new(ProcessExpr::atomic("P", ping("P")));
		let right = Box::new(ProcessExpr::atomic("Q", ping("Q")));
		let operator = CompositionOperator::Interface { events: HashSet::from([Event("pnig")]) };

		let expression = ProcessExpr::Parallel { operator, left, right };
		assert!(matches!(expression.evaluate(), Err(CompositionError::AlphabetMismatch { .. })));
		Ok(())
	}
}

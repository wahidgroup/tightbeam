//! The [`tb_process_spec!`](crate::tb_process_spec!) macro, which defines a CSP
//! process.

/// Defines a CSP process with a declarative syntax.
///
/// Each state lists its transitions in three forms:
///
/// - `EVENT => STATE` is a plain transition.
/// - `EVENT [ GUARD ] => STATE` is a transition that a timing guard enables.
/// - `EVENT [ GUARD, reset: [CLOCK, ...] ] => STATE` also resets the clocks it names.
///
/// A guard follows these rules:
///
/// - `GUARD` is the input of [`guard!`](crate::guard!), such as `clk <= Duration::from_millis(5)`.
/// - A guard needs the `testing-timing` feature.
/// - A bracket after an event is its guard, so an event that is an index expression takes parentheses.
/// - The CSP trace check reads no clock, so it accepts a guarded event at any time.
/// - A guard binds in FDR exploration alone, as [`ProcessBuilder::add_timed_transition`] states.
///
/// [`ProcessBuilder::add_timed_transition`]: crate::testing::specs::csp::ProcessBuilder::add_timed_transition
///
/// # Examples
///
/// ```
/// use core::time::Duration;
///
/// use tightbeam::testing::specs::csp::{Event, State};
/// use tightbeam::urn::Urn;
/// use tightbeam::{tb_process_spec, urn};
///
/// const REQUEST: Urn<'static> = urn!("test", "event:doc/request");
/// const REPLY: Urn<'static> = urn!("test", "event:doc/reply");
///
/// tb_process_spec! {
///     pub Exchange,
///     events {
///         observable { REQUEST, REPLY }
///         hidden { }
///     }
///     states {
///         Idle => { REQUEST => Busy },
///         Busy => { REPLY [ wait <= Duration::from_millis(50), reset: ["wait"] ] => Idle }
///     }
///     terminal { Idle }
/// }
///
/// let process = Exchange::process();
/// assert_eq!(process.step(State("Busy"), &Event::from(REPLY)), [State("Idle")]);
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[cfg(feature = "testing-csp")]
#[macro_export]
macro_rules! tb_process_spec {
	// The entry arm forwards every optional block to the `@impl` arm.
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		events {
			observable { $($obs_event:expr),* $(,)? }
			hidden { $($hid_event:expr),* $(,)? }
		}
		states {
			$($from_state:ident => { $($transitions:tt)* }),* $(,)?
		}
		$(terminal { $($term_state:ident),* $(,)? })?
		$(choice { $($choice_state:ident),* $(,)? })?
		$(annotations { description: $desc:expr })?
		$(clocks: { $($clock_name:expr),* $(,)? })?
		$(timing {
			$($timing_content:tt)*
		})?
		$(schedulability {
			$($schedulability_content:tt)*
		})?
	) => {
		$crate::tb_process_spec! {
			@impl
			$(#[$meta])*
			$vis $name,
			events {
				observable { $($obs_event),* }
				hidden { $($hid_event),* }
			}
		states {
			$($from_state => { $($transitions)* }),*
		}
		$(terminal { $($term_state),* })?
		$(choice { $($choice_state),* })?
		$(annotations { description: $desc })?
		$(timing {
			$($timing_content)*
		})?
		$(clocks: { $($clock_name:expr),* $(,)? })?
		$(schedulability {
			$($schedulability_content)*
		})?
		}
	};
	// The `@impl` arm emits the process type and its `process` builder.
	(@impl
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		events {
			observable { $($obs_event:expr),* }
			hidden { $($hid_event:expr),* }
		}
		states {
			$($from_state:ident => { $($transitions:tt)* }),* $(,)?
		}
		$(terminal { $($term_state:ident),* })?
		$(choice { $($choice_state:ident),* })?
		$(annotations { description: $desc:expr })?
		$(clocks: { $($clock_name:expr),* $(,)? })?
		$(timing {
			$($timing_content:tt)*
		})?
		$(schedulability {
			$($schedulability_content:tt)*
		})?
	) => {
		// The process type sits in the scope of the invocation.
		$(#[$meta])*
		$vis struct $name;

		impl Default for $name {
			fn default() -> Self {
				Self
			}
		}

		impl $name {
			#[allow(clippy::vec_init_then_push)]
			#[allow(dead_code)]
			pub fn process() -> $crate::testing::specs::csp::Process {
				use $crate::testing::specs::csp::State;

				let mut builder = $crate::testing::specs::csp::Process::builder(stringify!($name));

				// The from states keep their source order.
				let state_names = vec![$(stringify!($from_state)),*];

				// The first from state is the initial state.
				let initial = State(state_names[0]);
				builder = builder.initial_state(initial);

				// Every from state joins the process, even with no transition.
				$(
					builder = builder.add_state(State(stringify!($from_state)));
				)*

				$(
					builder = builder.add_observable($obs_event);
				)*

				$(
					builder = builder.add_hidden($hid_event);
				)*

				// The `@transitions` arms expand the transitions of each state.
				$(
					$crate::tb_process_spec! {
						@transitions
						builder,
						$from_state,
						[]
						$($transitions)*
					}
			)*

			$($(
				builder = builder.add_terminal(State(stringify!($term_state)));
			)*)?

				$($(
					builder = builder.add_choice(State(stringify!($choice_state)));
				)*)?

				$(
					builder = builder.description($desc);
				)?


				// Only a build with `testing-timing` applies a timing block.
				$(
					$crate::__tb_if_testing_timing! {
						{
							use $crate::testing::specs::csp::Event;
							use $crate::testing::timing::{DeadlineBuilder, TimingConstraints};
							use $crate::testing::macros::DeadlineParams;
							let mut timing_constraints = TimingConstraints::default();

							$crate::tb_process_spec! {
								@parse_timing
								timing_constraints,
								$($timing_content)*
							}

							builder = builder.timing_constraints(timing_constraints);
						}
					};
				)?

				$(
					$crate::__tb_if_testing_schedulability! {
						{
							use $crate::testing::specs::csp::Event;
							use std::collections::HashMap;
							use core::time::Duration;

							$crate::tb_process_spec! {
								@parse_schedulability
								builder,
								$($schedulability_content)*
							}
						}
					};
				)?

				builder.build().expect("Failed to build Process")
			}
		}

		$crate::__tb_if_testing_csp! {
			impl $crate::testing::specs::csp::ProcessSpec for $name {
				fn validate_trace(&self, trace: &$crate::trace::ConsumedTrace) -> $crate::testing::specs::csp::CspValidationResult {
					Self::process().validate_trace(trace)
				}

				fn to_process_cow(&self) -> std::borrow::Cow<'_, $crate::testing::specs::csp::Process> {
					std::borrow::Cow::Owned(Self::process())
				}
			}
		}
	};

	// The `@gen_module` arm emits a module with a `States` enum and an `Event`
	// wrapper for fault injection.
	(@gen_module
		$name:ident,
		observable_events: [ $($obs_event:expr),* ],
		hidden_events: [ $($hid_event:expr),* ],
		all_states: [ $($state:ident),* ],
		terminal_states: [ $($term_state:ident),* ]
	) => {
		$crate::paste::paste! {
			#[allow(non_snake_case)]
			mod [<$name:snake>] {
				/// Every state of this process: the from states, then the
				/// terminal states. A state in both lists becomes a duplicate
				/// variant, which fails to compile.
				#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
				#[allow(dead_code)]
				pub enum States {
					$( $state, )*
					$( $term_state, )*
				}

				impl $crate::testing::fault::ProcessState for States {
					fn process_name(&self) -> &'static str {
						stringify!($name)
					}

					fn state_name(&self) -> &'static str {
						match self {
							$( Self::$state => stringify!($state), )*
							$( Self::$term_state => stringify!($term_state), )*
						}
					}
				}

				/// A typed event label for fault injection.
				///
				/// An event wraps a string literal:
				/// ```ignore
				/// use my_process::Event;
				/// fault_model.with_fault(States::Idle, Event("connect"), ...);
				/// ```
				#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
				pub struct Event(pub &'static str);

				impl $crate::testing::fault::ProcessEvent for Event {
					fn event_label(&self) -> ::std::borrow::Cow<'static, str> {
						::std::borrow::Cow::Borrowed(self.0)
					}
				}
			}
		}
	};

	// The `@parse_timing` arm reads the grouped `wcet`, `jitter`, and
	// `deadline` blocks.
	(@parse_timing
		$constraints:ident,
		$(wcet: { $($wcet_event:expr => $wcet_constraint:expr),* $(,)? })?
		$(, jitter: { $($jitter_event:expr => $jitter_constraint:expr),* $(,)? })?
		$(, deadline: { $($deadline_start:expr => $deadline_end:expr, $deadline_params:expr),* $(,)? })?
		$(,)?
	) => {
		$($(
			$constraints.add(
				Event::from($wcet_event),
				$crate::testing::timing::TimingConstraint::Wcet($wcet_constraint)
			);
		)*)?

		$($(
			$constraints.add(
				Event::from($jitter_event),
				$jitter_constraint
			);
		)*)?

		$($(
			$crate::tb_process_spec! {
				@parse_deadline
				$constraints,
				$deadline_start,
				$deadline_end,
				$deadline_params
			}
		)*)?
	};

	// The `@parse_deadline` arm builds one deadline from its `DeadlineParams`.
	(@parse_deadline
		$constraints:ident,
		$deadline_start:expr,
		$deadline_end:expr,
		$deadline_params:expr
	) => {
		{
			let params: DeadlineParams = $deadline_params;
			let mut builder = DeadlineBuilder::default()
				.with_duration(params.duration)
				.with_start_event(Event::from($deadline_start))
				.with_end_event(Event::from($deadline_end));

			if let Some(slack) = params.min_slack {
				builder = builder.with_min_slack(slack);
			}

			let deadline = builder
				.build()
				.expect("Failed to build deadline");
			$constraints.add_deadline(deadline);
		}
	};

	// An empty timing block leaves the constraints as they are.
	(@parse_timing $constraints:ident,) => {};

	// The `@parse_schedulability` arm sets the scheduler and the event periods.
	(@parse_schedulability
		$builder:ident,
		scheduler: $scheduler:ident,
		periods: {
			$($event_period:expr => $period:expr),* $(,)?
		}
	) => {
		{
			let scheduler = $crate::testing::schedulability::SchedulerType::$scheduler;
			let mut periods = HashMap::new();
			$(
				periods.insert(Event::from($event_period), $period);
			)*
			$builder = $builder.with_schedulability_periods(scheduler, periods);
		}
	};

	// An empty schedulability block leaves the builder as it is.
	(@parse_schedulability $builder:ident,) => {};

	// The `@transitions` arms read the transitions of one state, in order.
	//
	// The bracket after an event holds its timing guard, so each guarded arm
	// comes before the plain arm that reads the same tokens. The bracket after
	// `$from` holds the event tokens read so far. An event that is a path, or
	// a call on a path, matches whole, so a long state stays inside the
	// recursion limit. Any other event is read one token at a time.
	(@transitions
		$builder:ident,
		$from:ident,
		[$($event:tt)+]
		[ $($guard:tt)+ ] => $to:ident $(, $($rest:tt)*)?
	) => {
		$crate::tb_process_spec! {
			@guard
			$builder,
			$from,
			[$($event)+],
			$to,
			[]
			$($guard)+
		}
		$crate::tb_process_spec! {
			@transitions
			$builder,
			$from,
			[]
			$($($rest)*)?
		}
	};

	(@transitions
		$builder:ident,
		$from:ident,
		[$($event:tt)+]
		=> $to:ident $(, $($rest:tt)*)?
	) => {
		$crate::tb_process_spec! {
			@plain
			$builder,
			$from,
			[$($event)+],
			$to
		}
		$crate::tb_process_spec! {
			@transitions
			$builder,
			$from,
			[]
			$($($rest)*)?
		}
	};

	(@transitions
		$builder:ident,
		$from:ident,
		[]
		$($segment:ident)::+ $(( $($argument:tt)* ))? => $to:ident $(, $($rest:tt)*)?
	) => {
		$crate::tb_process_spec! {
			@plain
			$builder,
			$from,
			[$($segment)::+ $(( $($argument)* ))?],
			$to
		}
		$crate::tb_process_spec! {
			@transitions
			$builder,
			$from,
			[]
			$($($rest)*)?
		}
	};

	(@transitions
		$builder:ident,
		$from:ident,
		[]
	) => {};

	(@transitions
		$builder:ident,
		$from:ident,
		[$($event:tt)*]
		$next:tt $($rest:tt)*
	) => {
		$crate::tb_process_spec! {
			@transitions
			$builder,
			$from,
			[$($event)* $next]
			$($rest)*
		}
	};

	// The `@plain` arm adds one transition with no guard.
	(@plain
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident
	) => {
		$builder = $builder.add_transition(
			$crate::testing::specs::csp::State(stringify!($from)),
			$($event)+,
			$crate::testing::specs::csp::State(stringify!($to)),
		);
	};

	// The `@guard` arms split a guard from its clock resets. `guard!` reads the
	// guard, so the guard grammar has one home.
	(@guard
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)+]
		, reset: [ $($reset:expr),* $(,)? ]
	) => {
		$crate::tb_process_spec! {
			@timed
			$builder,
			$from,
			[$($event)+],
			$to,
			[$($guard)+],
			[$($reset),*]
		}
	};

	(@guard
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)+]
	) => {
		$crate::tb_process_spec! {
			@timed
			$builder,
			$from,
			[$($event)+],
			$to,
			[$($guard)+],
			[]
		}
	};

	(@guard
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)*]
		$next:tt $($rest:tt)*
	) => {
		$crate::tb_process_spec! {
			@guard
			$builder,
			$from,
			[$($event)+],
			$to,
			[$($guard)* $next]
			$($rest)*
		}
	};

	// The `@timed` arm adds one transition that a timing guard enables.
	//
	// A build without `testing-timing` stops at the guard with a compile
	// error, so a spec keeps every guard it states.
	(@timed
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)+],
		[$($reset:expr),*]
	) => {
		$crate::__tb_select_testing_timing! {
			{
				$builder = $builder.add_timed_transition(
					$crate::testing::specs::csp::State(stringify!($from)),
					$crate::testing::specs::csp::Event::from($($event)+),
					$crate::testing::specs::csp::State(stringify!($to)),
					::core::option::Option::Some($crate::guard!($($guard)+)),
					[$(::std::string::String::from($reset)),*],
				);
			}
			{
				::core::compile_error!("a guarded transition needs the `testing-timing` feature");
			}
		}
	};
}

#[cfg(all(test, feature = "testing-timing"))]
mod tests {
	use core::error::Error;
	use core::time::Duration;
	use std::collections::HashMap;

	use crate::testing::specs::csp::{Event, State, Successor};
	use crate::testing::timing::{TimedTransition, TimingGuard};
	use crate::urn::Urn;

	const ARM: Urn<'static> = crate::urn!("test", "event:process-spec/arm");
	const FIRE: Urn<'static> = crate::urn!("test", "event:process-spec/fire");

	crate::tb_process_spec! {
		pub GuardedProcess,
		events {
			observable { ARM, FIRE }
			hidden { }
		}
		states {
			S0 => { ARM [ clk <= Duration::from_millis(5) ] => S1 },
			S1 => { FIRE [ clk <= Duration::from_millis(5), reset: ["clk"] ] => S0 }
		}
		terminal { S0 }
	}

	/// The timed transition that `event` labels from `from`.
	///
	/// The plain arm records no timed transition, so the lookup fails where a
	/// guarded form falls through to it.
	fn timed_transition(from: &'static str, event: Urn<'static>) -> Result<TimedTransition, Box<dyn Error>> {
		let key = (State(from), Event::from(event));
		let mut table = GuardedProcess::process().timed_transitions.unwrap_or_default();
		let transition = table.remove(&key).and_then(|transitions| transitions.into_iter().next());

		transition.ok_or_else(|| "the guarded form recorded no timed transition".into())
	}

	/// The clock readings once `clk` has run `span`.
	fn readings_after(span: Duration) -> HashMap<String, Duration> {
		HashMap::from([("clk".to_string(), span)])
	}

	#[test]
	fn a_guarded_event_expands_to_a_timed_transition() -> Result<(), Box<dyn Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));

		let transition = timed_transition("S0", ARM)?;

		assert_eq!(transition.guard, Some(bound));
		assert_eq!(transition.to, State("S1"));
		Ok(())
	}

	#[test]
	fn a_guard_allows_its_edge_at_its_bound() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process();
		let readings = readings_after(Duration::from_millis(5));

		let successors: Vec<Successor> = process.successors(State("S0"), &Event::from(ARM), &readings).collect();

		assert_eq!(successors, [Successor { to: State("S1"), resets: &[] }]);
		Ok(())
	}

	#[test]
	fn a_guard_refuses_its_edge_past_its_bound() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process();
		let readings = readings_after(Duration::from_micros(5_001));

		let successors: Vec<Successor> = process.successors(State("S0"), &Event::from(ARM), &readings).collect();

		assert!(successors.is_empty());
		Ok(())
	}

	#[test]
	fn a_guard_with_resets_names_its_clocks() -> Result<(), Box<dyn Error>> {
		let transition = timed_transition("S1", FIRE)?;

		assert_eq!(transition.reset_clocks, ["clk"]);
		Ok(())
	}

	#[test]
	fn a_guarded_transition_is_an_edge_of_the_process() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process();

		assert_eq!(process.step(State("S0"), &Event::from(ARM)), [State("S1")]);
		Ok(())
	}
}

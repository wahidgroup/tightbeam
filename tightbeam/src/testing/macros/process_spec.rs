//! The [`tb_process_spec!`](crate::tb_process_spec!) macro, which defines a CSP
//! process.

/// Defines a CSP process with a declarative syntax, as a unit struct that
/// implements [`ProcessSpec`].
///
/// Each state takes one definition, which lists its transitions in three
/// forms. A state defined twice fails to compile.
///
/// - `EVENT => STATE` is a plain transition.
/// - `EVENT [ GUARD ] => STATE` is a transition that a timing guard enables.
/// - `EVENT [ GUARD, reset: [CLOCK, ...] ] => STATE` also resets the clocks it names.
///
/// A guard follows these rules:
///
/// - `GUARD` is the input of [`guard!`](crate::guard!), such as `clk <= Duration::from_millis(5)`.
/// - A guard or a reset names its clock as an identifier that the `clocks: { CLOCK, ... }` block declares.
/// - A bracket after an event is its guard, so an event that is an index expression takes parentheses.
/// - The CSP trace check reads the event order alone, so it accepts a guarded event at any time.
/// - A guard binds in FDR exploration alone ([`ProcessBuilder::add_timed_transition`]).
///
/// The blocks follow these rules:
///
/// - The `timing` block holds any of `wcet:`, `jitter:`, and `deadline:`, in any order, with commas between.
/// - A build without `testing-timing` fails to compile on a `clocks:` block, a `timing` block, or a guard.
/// - A build without `testing-schedulability` fails to compile on a `schedulability` block.
///
/// # Errors
///
/// The struct's `process()` returns a [`ProcessBuildError`]:
///
/// - [`ProcessBuildError::MissingInitialState`] -- the `states` block names no state.
/// - [`ProcessBuildError::UndeclaredClock`] -- a guard or a reset names a clock that `clocks:` lacks.
/// - [`ProcessBuildError::ConflictingTiming`] -- the `timing` block gives one event two bounds that disagree.
/// - [`ProcessBuildError::InvalidDeadline`] -- the slack of a `timing` deadline passes its duration.
///
/// [`ProcessBuilder::add_timed_transition`]: crate::testing::specs::csp::ProcessBuilder::add_timed_transition
/// [`ProcessSpec`]: crate::testing::specs::csp::ProcessSpec
/// [`ProcessBuildError`]: crate::testing::specs::csp::ProcessBuildError
/// [`ProcessBuildError::MissingInitialState`]: crate::testing::specs::csp::ProcessBuildError::MissingInitialState
/// [`ProcessBuildError::UndeclaredClock`]: crate::testing::specs::csp::ProcessBuildError::UndeclaredClock
/// [`ProcessBuildError::ConflictingTiming`]: crate::testing::specs::csp::ProcessBuildError::ConflictingTiming
/// [`ProcessBuildError::InvalidDeadline`]: crate::testing::specs::csp::ProcessBuildError::InvalidDeadline
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
///         Busy => { REPLY [ wait <= Duration::from_millis(50), reset: [wait] ] => Idle }
///     }
///     terminal { Idle }
///     clocks: { wait }
/// }
///
/// let process = Exchange::process()?;
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
		$(clocks: { $($clock:ident),* $(,)? })?
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
		$(clocks: { $($clock),* })?
		$(timing {
			$($timing_content)*
		})?
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
		$(clocks: { $($clock:ident),* })?
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
			/// The process that this spec declares.
			///
			/// # Errors
			///
			/// - `ProcessBuildError::MissingInitialState` -- the spec names no state.
			/// - `ProcessBuildError::UndeclaredClock` -- a guard or a reset names an undeclared clock.
			/// - `ProcessBuildError::ConflictingTiming` -- the spec gives one event two bounds that disagree.
			/// - `ProcessBuildError::InvalidDeadline` -- a deadline has a slack past its duration.
			#[allow(clippy::vec_init_then_push)]
			#[allow(dead_code)]
			pub fn process() -> ::core::result::Result<
				$crate::testing::specs::csp::Process,
				$crate::testing::specs::csp::ProcessBuildError,
			> {
				use $crate::testing::specs::csp::State;

				// Each from state takes one definition, so its transitions sit
				// in one place. A second definition is a duplicate variant,
				// which fails to compile.
				#[allow(dead_code, non_camel_case_types, clippy::enum_variant_names)]
				enum FromStates {
					$($from_state),*
				}

				let mut builder = $crate::testing::specs::csp::Process::builder(stringify!($name));

				// The first from state in source order is the initial state. A
				// spec with no state leaves it unset, so its build refuses it.
				let state_names: &[&'static str] = &[$(stringify!($from_state)),*];
				if let ::core::option::Option::Some(initial) = state_names.first() {
					builder = builder.initial_state(State(*initial));
				}

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

				// A build without `testing-timing` stops at the `clocks:`
				// block, so a spec keeps every clock it declares.
				$(
					$crate::__tb_select_testing_timing! {
						{
							$(
								builder = builder.clock(stringify!($clock));
							)*
						}
						{
							::core::compile_error!("the `clocks:` block of `tb_process_spec!` needs the `testing-timing` feature");
						}
					}
				)?

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


				// A build without `testing-timing` stops at the timing block,
				// so a spec keeps every timing constraint it states.
				$(
					$crate::__tb_select_testing_timing! {
						{
							{
								use $crate::testing::specs::csp::Event;
								use $crate::testing::timing::TimingConstraints;
								let mut timing_constraints = TimingConstraints::default();

								$crate::tb_process_spec! {
									@parse_timing
									timing_constraints,
									$($timing_content)*
								}

								builder = builder.timing_constraints(timing_constraints);
							}
						}
						{
							::core::compile_error!("the `timing` block of `tb_process_spec!` needs the `testing-timing` feature");
						}
					}
				)?

				// A build without `testing-schedulability` stops at the
				// schedulability block, so a spec keeps every period it states.
				$(
					$crate::__tb_select_testing_schedulability! {
						{
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
						}
						{
							::core::compile_error!(
								"the `schedulability` block of `tb_process_spec!` needs the `testing-schedulability` feature"
							);
						}
					}
				)?

				builder.build()
			}
		}

		$crate::__tb_if_testing_csp! {
			impl $crate::testing::specs::csp::ProcessSpec for $name {
				fn to_process_cow(
					&self,
				) -> ::core::result::Result<
					::std::borrow::Cow<'_, $crate::testing::specs::csp::Process>,
					$crate::testing::specs::composition::CompositionError,
				> {
					::core::result::Result::Ok(::std::borrow::Cow::Owned(Self::process()?))
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

				/// An event of this process, which wraps the URN of the
				/// event.
				///
				/// A fault keyed by an `Event` matches the label that the
				/// trace records for the URN.
				#[derive(Debug, Clone, PartialEq, Eq, Hash)]
				pub struct Event(pub $crate::urn::Urn<'static>);

				impl $crate::testing::fault::ProcessEvent for Event {
					fn event_label(&self) -> ::std::borrow::Cow<'static, str> {
						$crate::testing::fault::ProcessEvent::event_label(&self.0)
					}
				}
			}
		}
	};

	// The `@parse_timing` arms read the `wcet`, `jitter`, and `deadline`
	// blocks one at a time, so a block stands alone or follows a comma. Each
	// refusal of `add` is a conflict with the bound that its event holds.
	(@parse_timing
		$constraints:ident,
		wcet: { $($wcet_event:expr => $wcet_constraint:expr),* $(,)? }
		$(, $($rest:tt)*)?
	) => {
		$(
			{
				let event = Event::from($wcet_event);
				let bound = $crate::testing::timing::TimingConstraint::Wcet($wcet_constraint);
				$constraints
					.add(event, bound)
					.map_err(|_conflict| $crate::testing::specs::csp::ProcessBuildError::ConflictingTiming { event })?;
			}
		)*

		$crate::tb_process_spec! { @parse_timing $constraints, $($($rest)*)? }
	};
	(@parse_timing
		$constraints:ident,
		jitter: { $($jitter_event:expr => $jitter_constraint:expr),* $(,)? }
		$(, $($rest:tt)*)?
	) => {
		$(
			{
				let event = Event::from($jitter_event);
				$constraints
					.add(event, $jitter_constraint)
					.map_err(|_conflict| $crate::testing::specs::csp::ProcessBuildError::ConflictingTiming { event })?;
			}
		)*

		$crate::tb_process_spec! { @parse_timing $constraints, $($($rest)*)? }
	};
	(@parse_timing
		$constraints:ident,
		deadline: { $($deadline_start:expr => $deadline_end:expr, $deadline_params:expr),* $(,)? }
		$(, $($rest:tt)*)?
	) => {
		$(
			$crate::tb_process_spec! {
				@parse_deadline
				$constraints,
				$deadline_start,
				$deadline_end,
				$deadline_params
			}
		)*

		$crate::tb_process_spec! { @parse_timing $constraints, $($($rest)*)? }
	};

	// The `@parse_deadline` arm builds one deadline from its `DeadlineParams`.
	(@parse_deadline
		$constraints:ident,
		$deadline_start:expr,
		$deadline_end:expr,
		$deadline_params:expr
	) => {
		{
			use $crate::builder::TypeBuilder as _;
			use $crate::testing::macros::DeadlineParams;
			use $crate::testing::timing::DeadlineBuilder;

			let params: DeadlineParams = $deadline_params;
			let start = Event::from($deadline_start);
			let end = Event::from($deadline_end);
			let mut builder = DeadlineBuilder::default()
				.with_duration(params.duration)
				.with_start_event(start)
				.with_end_event(end);

			if let Some(slack) = params.min_slack {
				builder = builder.with_min_slack(slack);
			}

			// The builder holds each part, so it refuses only a slack past the
			// duration.
			let deadline = builder
				.build()
				.map_err(|_slack| $crate::testing::specs::csp::ProcessBuildError::InvalidDeadline { start, end })?;
			$constraints.add_deadline(deadline);
		}
	};

	// An empty timing block, or the end of one, leaves the constraints as
	// they are.
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

	// The `@transitions` arms read the transitions of one state, in order:
	//
	// - The bracket after `$from` holds the event tokens read so far.
	// - The bracket after an event holds its timing guard, so each guarded arm
	//   precedes the plain arm that reads the same tokens.
	// - A path event, or a call on a path, matches whole, so a long state stays inside the recursion limit.
	// - The last arm reads any other event one token at a time.
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
	// guard, so the guard grammar has one home. A reset names its clock as an
	// identifier, as the guard does.
	(@guard
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)+]
		, reset: [ $($reset:ident),* $(,)? ]
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

	// The `@timed` arm adds one transition that a timing guard enables. A build
	// without `testing-timing` stops at the guard with a compile error, so a
	// spec keeps every guard it states.
	(@timed
		$builder:ident,
		$from:ident,
		[$($event:tt)+],
		$to:ident,
		[$($guard:tt)+],
		[$($reset:ident),*]
	) => {
		$crate::__tb_select_testing_timing! {
			{
				$builder = $builder.add_timed_transition(
					$crate::testing::specs::csp::State(stringify!($from)),
					$($event)+,
					$crate::testing::specs::csp::State(stringify!($to)),
					::core::option::Option::Some($crate::guard!($($guard)+)),
					[$(::std::string::String::from(stringify!($reset))),*],
				);
			}
			{
				::core::compile_error!("a guarded transition needs the `testing-timing` feature");
			}
		}
	};
}

#[cfg(all(test, feature = "testing-csp"))]
mod tests {
	use core::error::Error;

	#[cfg(feature = "testing-timing")]
	use core::time::Duration;
	#[cfg(feature = "testing-timing")]
	use std::collections::HashMap;

	use crate::testing::specs::csp::ProcessSpec;
	use crate::trace::{ConsumedTrace, TraceCollector};
	use crate::urn::Urn;

	#[cfg(feature = "testing-timing")]
	use crate::testing::specs::csp::{Event, ProcessBuildError, State, Successor};
	#[cfg(feature = "testing-timing")]
	use crate::testing::timing::{TimedTransition, TimingGuard};

	const ARM: Urn<'static> = crate::urn!("test", "event:process-spec/arm");
	const FIRE: Urn<'static> = crate::urn!("test", "event:process-spec/fire");

	crate::tb_process_spec! {
		pub PlainProcess,
		events {
			observable { ARM, FIRE }
			hidden { }
		}
		states {
			S0 => { ARM => S1 },
			S1 => { FIRE => S0 }
		}
		terminal { S0 }
	}

	#[cfg(feature = "testing-timing")]
	crate::tb_process_spec! {
		pub GuardedProcess,
		events {
			observable { ARM, FIRE }
			hidden { }
		}
		states {
			S0 => { ARM [ clk <= Duration::from_millis(5) ] => S1 },
			S1 => { FIRE [ clk <= Duration::from_millis(5), reset: [clk] ] => S0 }
		}
		terminal { S0 }
		clocks: { clk }
	}

	#[cfg(feature = "testing-timing")]
	crate::tb_process_spec! {
		pub BoundsArmTwice,
		events {
			observable { ARM }
			hidden { }
		}
		states {
			S0 => { ARM => S1 }
		}
		terminal { S1 }
		timing {
			wcet: {
				ARM => crate::wcet!(Duration::from_millis(5)),
				ARM => crate::wcet!(Duration::from_millis(9))
			}
		}
	}

	#[cfg(feature = "testing-timing")]
	crate::tb_process_spec! {
		pub SlackPastItsDeadline,
		events {
			observable { ARM, FIRE }
			hidden { }
		}
		states {
			S0 => { ARM => S1 },
			S1 => { FIRE => S2 }
		}
		terminal { S2 }
		timing {
			wcet: { ARM => crate::wcet!(Duration::from_millis(5)) },
			deadline: {
				ARM => FIRE, crate::testing::macros::DeadlineParams {
					duration: Duration::from_millis(5),
					min_slack: Some(Duration::from_millis(9)),
				}
			}
		}
	}

	#[cfg(feature = "testing-timing")]
	crate::tb_process_spec! {
		pub DeadlineAlone,
		events {
			observable { ARM, FIRE }
			hidden { }
		}
		states {
			S0 => { ARM => S1 },
			S1 => { FIRE => S2 }
		}
		terminal { S2 }
		timing {
			deadline: {
				ARM => FIRE, crate::testing::macros::DeadlineParams {
					duration: Duration::from_millis(5),
					min_slack: None,
				}
			}
		}
	}

	/// A trace that records each of `events` once, in order.
	fn trace_of(events: &[Urn<'static>]) -> ConsumedTrace {
		let collector = TraceCollector::new();
		for event in events {
			collector.event(event).expect("the run injects no fault").emit();
		}

		ConsumedTrace::drained_from(&collector)
	}

	/// The timed transition that `event` labels from `from`.
	///
	/// The plain arm records no timed transition, so the lookup fails where a
	/// guarded form falls through to it.
	#[cfg(feature = "testing-timing")]
	fn timed_transition(from: &'static str, event: Urn<'static>) -> Result<TimedTransition, Box<dyn Error>> {
		let key = (State(from), Event::from(event));
		let mut table = GuardedProcess::process()?.timed_transitions.unwrap_or_default();

		let transition = table.remove(&key).and_then(|transitions| transitions.into_iter().next());
		transition.ok_or_else(|| "the guarded form recorded no timed transition".into())
	}

	/// The clock readings once `clk` has run `span`.
	#[cfg(feature = "testing-timing")]
	fn readings_after(span: Duration) -> HashMap<String, Duration> {
		HashMap::from([("clk".to_string(), span)])
	}

	#[test]
	fn a_spec_accepts_a_trace_that_its_process_allows() -> Result<(), Box<dyn Error>> {
		let trace = trace_of(&[ARM, FIRE]);
		let result = PlainProcess.validate_trace(&PlainProcess::process()?, &trace);
		assert!(result.valid, "{:?}", result.violations);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_spec_that_bounds_an_event_twice_does_not_build() -> Result<(), Box<dyn Error>> {
		let refused = BoundsArmTwice::process();
		let conflict = ProcessBuildError::ConflictingTiming { event: Event::from(ARM) };
		assert_eq!(refused.err(), Some(conflict));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_spec_whose_deadline_slack_passes_its_duration_does_not_build() -> Result<(), Box<dyn Error>> {
		let refused = SlackPastItsDeadline::process();
		let invalid = ProcessBuildError::InvalidDeadline { start: Event::from(ARM), end: Event::from(FIRE) };
		assert_eq!(refused.err(), Some(invalid));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_timing_block_that_holds_a_deadline_alone_builds_the_deadline() -> Result<(), Box<dyn Error>> {
		let process = DeadlineAlone::process()?;
		let constraints = process.timing_constraints.unwrap_or_default();

		let deadline = constraints.deadlines().first();
		let window = deadline.map(|deadline| (deadline.start_event, deadline.end_event));
		assert_eq!(window, Some((Event::from(ARM), Event::from(FIRE))));
		Ok(())
	}

	#[test]
	fn a_spec_rejects_an_event_that_its_state_does_not_enable() -> Result<(), Box<dyn Error>> {
		let trace = trace_of(&[FIRE]);
		let result = PlainProcess.validate_trace(&PlainProcess::process()?, &trace);
		assert!(!result.valid);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guarded_event_expands_to_a_timed_transition() -> Result<(), Box<dyn Error>> {
		let bound = TimingGuard::ClockLessEqual("clk".to_string(), Duration::from_millis(5));
		let transition = timed_transition("S0", ARM)?;
		assert_eq!(transition.guard, Some(bound));
		assert_eq!(transition.to, State("S1"));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guard_allows_its_edge_at_its_bound() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process()?;
		let readings = readings_after(Duration::from_millis(5));

		let successors: Vec<Successor> = process.successors(State("S0"), &Event::from(ARM), &readings).collect();
		assert_eq!(successors, [Successor { to: State("S1"), resets: &[] }]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guard_refuses_its_edge_past_its_bound() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process()?;
		let readings = readings_after(Duration::from_micros(5_001));

		let successors: Vec<Successor> = process.successors(State("S0"), &Event::from(ARM), &readings).collect();
		assert!(successors.is_empty());
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guard_with_resets_names_its_clocks() -> Result<(), Box<dyn Error>> {
		let transition = timed_transition("S1", FIRE)?;
		assert_eq!(transition.reset_clocks, ["clk"]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guarded_transition_is_an_edge_of_the_process() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process()?;
		assert_eq!(process.step(State("S0"), &Event::from(ARM)), [State("S1")]);
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_declared_clock_starts_at_zero() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process()?;
		let clocks = process.initial_clocks();
		assert_eq!(clocks, HashMap::from([("clk".to_string(), Duration::ZERO)]));
		Ok(())
	}

	#[cfg(feature = "testing-timing")]
	#[test]
	fn a_guard_allows_its_edge_when_a_run_starts() -> Result<(), Box<dyn Error>> {
		let process = GuardedProcess::process()?;
		let readings = process.initial_clocks();

		let successors: Vec<Successor> = process.successors(State("S0"), &Event::from(ARM), &readings).collect();
		assert_eq!(successors, [Successor { to: State("S1"), resets: &[] }]);
		Ok(())
	}
}

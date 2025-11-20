//! tb_process_spec! macro for defining CSP processes

/// Define a CSP Process with declarative syntax.
#[macro_export]
macro_rules! tb_process_spec {
	// Pattern with timing block and optional terminal
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		events {
			observable { $($obs_event:expr),* $(,)? }
			hidden { $($hid_event:expr),* $(,)? }
		}
		states {
			$($from_state:ident => { $($event:expr => $to_state:ident),* $(,)? }),* $(,)?
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
			$($from_state => { $($event => $to_state),* }),*
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
	// Implementation pattern with optional terminal
	(@impl
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		events {
			observable { $($obs_event:expr),* }
			hidden { $($hid_event:expr),* }
		}
		states {
			$($from_state:ident => { $($event:expr => $to_state:ident),* $(,)? }),* $(,)?
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
		$(#[$meta])*
		$vis struct $name;

		impl Default for $name {
			fn default() -> Self {
				Self
			}
		}

		impl $name {
			#[allow(clippy::vec_init_then_push)]
			pub fn process() -> $crate::testing::specs::csp::Process {
				use $crate::testing::specs::csp::State;

				let mut builder = $crate::testing::specs::csp::Process::builder(stringify!($name));

				// Collect all state names first (from_states)
				let state_names = vec![$(stringify!($from_state)),*];

				// Get first state as initial state
				let initial = State(state_names[0]);
				builder = builder.initial_state(initial);

				// Add all states explicitly (including those with no transitions)
				$(
					builder = builder.add_state(State(stringify!($from_state)));
				)*

				// Add observable events
				$(
					builder = builder.add_observable($obs_event);
				)*

				// Add hidden events
				$(
					builder = builder.add_hidden($hid_event);
				)*

				// Add all transitions
				$(
					$(
						builder = builder.add_transition(
							State(stringify!($from_state)),
							$event,
							State(stringify!($to_state))
						);
					)*
			)*

			// Add terminal states if present
			$($(
				builder = builder.add_terminal(State(stringify!($term_state)));
			)*)?

			// Add choice states if present
				$($(
					builder = builder.add_choice(State(stringify!($choice_state)));
				)*)?

				// Add description if present
				$(
					builder = builder.description($desc);
				)?


				// Build timing constraints if present
				$(
					#[cfg(feature = "testing-timing")]
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
				)?

				$(
					#[cfg(feature = "testing-schedulability")]
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
				)?

				builder.build().expect("Failed to build Process")
			}
		}

		#[cfg(feature = "testing-csp")]
		impl $crate::testing::specs::csp::ProcessSpec for $name {
			fn validate_trace(&self, trace: &$crate::trace::ConsumedTrace) -> $crate::testing::specs::csp::CspValidationResult {
				Self::process().validate_trace(trace)
			}
		}
	};

	// Parse grouped timing syntax - unified pattern
	(@parse_timing
		$constraints:ident,
		$(wcet: { $($wcet_event:expr => $wcet_constraint:expr),* $(,)? })?
		$(, jitter: { $($jitter_event:expr => $jitter_constraint:expr),* $(,)? })?
		$(, deadline: { $($deadline_start:expr => $deadline_end:expr, $deadline_params:expr),* $(,)? })?
		$(,)?
	) => {
		// Parse WCET constraints
		$($(
			$constraints.add(
				Event($wcet_event),
				$crate::testing::timing::TimingConstraint::Wcet($wcet_constraint)
			);
		)*)?

		// Parse Jitter constraints
		$($(
			$constraints.add(
				Event($jitter_event),
				$jitter_constraint
			);
		)*)?

		// Parse Deadline constraints
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

	// Helper to parse a single deadline constraint
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
				.with_start_event(Event($deadline_start))
				.with_end_event(Event($deadline_end));
			if let Some(slack) = params.min_slack {
				builder = builder.with_min_slack(slack);
			}
			let deadline = builder
				.build()
				.expect("Failed to build deadline");
			$constraints.add_deadline(deadline);
		}
	};

	// Fallback: empty timing block
	(@parse_timing $constraints:ident,) => {};

	// Parse schedulability block
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
				periods.insert(Event($event_period), $period);
			)*
			$builder = $builder.with_schedulability_periods(scheduler, periods);
		}
	};

	// Fallback: empty schedulability block
	(@parse_schedulability $builder:ident,) => {};

	// Parse transitions from a state - handle multiple transitions
	// Recursively parse each transition
	(@parse_transitions
		$builder:ident,
		$from_state:expr,
		$($transitions:tt)*
	) => {
		$crate::tb_process_spec! {
			@parse_transitions_inner
			$builder,
			$from_state,
			$($transitions)*
		}
	};

	// Inner helper to parse transitions recursively
	(@parse_transitions_inner
		$builder:ident,
		$from_state:expr,
		$transition:tt $(, $($rest:tt),*)?
	) => {
		$crate::tb_process_spec! {
			@parse_transition
			$builder,
			$from_state,
			$transition
		}
		$(
			$crate::tb_process_spec! {
				@parse_transitions_inner
				$builder,
				$from_state,
				$($rest),*
			}
		)?
	};
	// Fallback: empty transitions
	(@parse_transitions_inner
		$builder:ident,
		$from_state:expr,
	) => {};

	// Parse transition - simple case (backward compatible)
	(@parse_transition
		$builder:ident,
		$from_state:expr,
		$event:expr => $to_state:ident
	) => {
		$builder = $builder.add_transition($from_state, $event, $crate::testing::specs::csp::State(stringify!($to_state)));
	};

	// Parse transition - with timing guard
	(@parse_transition
		$builder:ident,
		$from_state:expr,
		$event:tt [ $guard_expr:tt ] => $to_state:ident
	) => {
		$crate::tb_process_spec! {
			@parse_timed_transition
			$builder,
			$from_state,
			$event,
			$guard_expr,
			$to_state,
		}
	};

	// Parse transition - with timing guard and clock resets
	(@parse_transition
		$builder:ident,
		$from_state:expr,
		$event:tt [ $guard_expr:tt, reset: [ $($reset_clock:expr),* $(,)? ] ] => $to_state:ident
	) => {
		$crate::tb_process_spec! {
			@parse_timed_transition
			$builder,
			$from_state,
			$event,
			$guard_expr,
			$to_state,
			$( $reset_clock ),*
		}
	};

	// Helper to parse timed transition (with optional clock resets)
	(@parse_timed_transition
		$builder:ident,
		$from_state:expr,
		$event:tt,
		$guard_expr:tt,
		$to_state:ident,
	) => {
		$crate::tb_process_spec! {
			@parse_timed_transition_impl
			$builder,
			$from_state,
			$event,
			$guard_expr,
			$to_state,
		}
	};
	(@parse_timed_transition
		$builder:ident,
		$from_state:expr,
		$event:tt,
		$guard_expr:tt,
		$to_state:ident,
		$($reset_clock:expr),* $(,)?
	) => {
		$crate::tb_process_spec! {
			@parse_timed_transition_impl
			$builder,
			$from_state,
			$event,
			$guard_expr,
			$to_state,
			$($reset_clock),*
		}
	};
	// Implementation helper for timed transition
	(@parse_timed_transition_impl
		$builder:ident,
		$from_state:expr,
		$event:tt,
		$guard_expr:tt,
		$to_state:ident,
		$( $reset_clock:expr ),* $(,)?
	) => {
		#[cfg(feature = "testing-timing")]
		{
			use $crate::testing::specs::csp::{Event, State};
			use $crate::testing::timing::TimingGuard;
			let guard: TimingGuard = $crate::guard!($guard_expr);
			let reset_clocks: Vec<String> = vec![$( $reset_clock.to_string() ),*];
			$builder = $builder.add_timed_transition(
				$from_state,
				Event($event),
				State(stringify!($to_state)),
				Some(guard),
				reset_clocks,
			);
		}
		#[cfg(not(feature = "testing-timing"))]
		{
			$builder = $builder.add_transition($from_state, $event, $crate::testing::specs::csp::State(stringify!($to_state)));
		}
	};
}

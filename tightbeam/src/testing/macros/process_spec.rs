//! tb_process_spec! macro for defining CSP processes

/// Define a CSP Process with declarative syntax.
#[macro_export]
macro_rules! tb_process_spec {
	// Pattern with timing block
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
		terminal { $($term_state:ident),* $(,)? }
		$(choice { $($choice_state:ident),* $(,)? })?
		$(annotations { description: $desc:expr })?
		$(timing {
			$($timing_event:expr => $timing_constraint:expr),* $(,)?
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
			terminal { $($term_state),* }
			$(choice { $($choice_state),* })?
			$(annotations { description: $desc })?
			$(timing {
				$($timing_event => $timing_constraint),*
			})?
		}
	};
	// Implementation pattern
	(@impl
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		events {
			observable { $($obs_event:expr),* }
			hidden { $($hid_event:expr),* }
		}
		states {
			$($from_state:ident => { $($event:expr => $to_state:ident),* }),*
		}
		terminal { $($term_state:ident),* }
		$(choice { $($choice_state:ident),* })?
		$(annotations { description: $desc:expr })?
		$(timing {
			$($timing_event:expr => $timing_constraint:expr),*
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

				// Add terminal states
				$(
					builder = builder.add_terminal(State(stringify!($term_state)));
				)*

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
						use $crate::testing::timing::TimingConstraints;
						let mut timing_constraints = TimingConstraints::new();
						$(
							timing_constraints.add(
								Event($timing_event),
								$timing_constraint
							);
						)*
						builder = builder.timing_constraints(timing_constraints);
					}
				)?

				builder.build().expect("Failed to build Process")
			}
		}

		#[cfg(feature = "testing-csp")]
		impl $crate::testing::specs::csp::ProcessSpec for $name {
			fn validate_trace(&self, trace: &$crate::testing::trace::ConsumedTrace) -> $crate::testing::specs::csp::CspValidationResult {
				Self::process().validate_trace(trace)
			}
		}
	};
}

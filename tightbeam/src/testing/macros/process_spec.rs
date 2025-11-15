//! tb_process_spec! macro for defining CSP processes

/// Define a CSP Process with declarative syntax
///
/// # Syntax
///
/// ```ignore
/// tb_process_spec! {
///     pub HandshakeSpec,
///     events {
///         observable { "start", "send", "ack", "fail" }
///         hidden { "serialize", "encrypt", "queue", "dispatch" }
///     }
///     states {
///         S0  => { "start" => S1 },
///         S1  => { "serialize" => S1s, "queue" => S1q },
///         S1s => { "encrypt" => S1e },
///         S1e => { "send" => S2 },
///         S1q => { "dispatch" => S1d },
///         S1d => { "send" => S2 },
///         S2  => { "ack" => S3, "fail" => S3f },
///         S3  => {},
///         S3f => {}
///     }
///     terminal { S3, S3f }
///     choice { S1 }
///     annotations { description: "Queued or direct send" }
/// }
/// ```
///
/// **Note**: State definitions must be separated by commas.
#[macro_export]
macro_rules! tb_process_spec {
	// Main pattern with all sections
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

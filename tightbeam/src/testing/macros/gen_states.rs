//! tb_gen_process_types! macro for generating States enum and Event wrapper
//!
//! This is an opt-in companion to tb_process_spec! that generates type-safe
//! enums for fault injection. Call it AFTER defining your process spec.

/// Generate States enum and Event wrapper for a CSP process.
///
/// This macro creates a snake_case module containing:
/// - `States` enum with all process states
/// - `Event` struct for type-safe event labels
/// - ProcessState and ProcessEvent trait implementations
///
/// # Usage
///
/// ```ignore
/// tb_process_spec! {
///     pub MyProcess,
///     events { observable { "send", "ack" } hidden { } }
///     states {
///         Ready => { "send" => Sending },
///         Sending => { "ack" => Ready }
///     }
/// }
///
/// // Generate types for fault injection
/// tb_gen_process_types!(MyProcess, Ready, Sending);
///
/// // Use in fault injection
/// use my_process::{States, Event};
/// fault_model.with_fault(States::Ready, Event("send"), || Error, 1000);
/// ```
#[macro_export]
macro_rules! tb_gen_process_types {
	(
		$name:ident,
		$($state:ident),+ $(,)?
	) => {
		$crate::paste::paste! {
			#[allow(non_snake_case)]
			pub mod [<$name:snake>] {
				/// All states in this process
				#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
				pub enum States {
					$(
						$state,
					)+
				}

				impl $crate::testing::fault::ProcessState for States {
					fn process_name(&self) -> &'static str {
						stringify!($name)
					}

					fn state_name(&self) -> &'static str {
						match self {
							$(
								Self::$state => stringify!($state),
							)+
						}
					}
				}

				/// Event wrapper for type-safe fault injection
				///
				/// Create events using string literals:
				/// ```ignore
				/// use my_process::Event;
				/// fault_model.with_fault(States::Idle, Event("connect"), ...);
				/// ```
				#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
				pub struct Event(pub &'static str);

				impl $crate::testing::fault::ProcessEvent for Event {
					fn event_label(&self) -> &'static str {
						self.0
					}
				}
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use crate::testing::fault::{ProcessEvent, ProcessState};

	// Test process definition
	crate::tb_process_spec! {
		pub MacroTestProcess,
		events {
			observable { "connect", "send", "ack", "disconnect" }
			hidden { }
		}
		states {
			Idle => { "connect" => Connected },
			Connected => { "send" => Sending, "disconnect" => Idle },
			Sending => { "ack" => Connected }
		}
		terminal { Idle }
	}

	// Generate types
	tb_gen_process_types!(MacroTestProcess, Idle, Connected, Sending);

	#[test]
	fn generates_states_enum() {
		use macro_test_process::States;

		let idle = States::Idle;
		let connected = States::Connected;
		let sending = States::Sending;
		assert_eq!(core::mem::discriminant(&idle), core::mem::discriminant(&States::Idle));
		assert_eq!(core::mem::discriminant(&connected), core::mem::discriminant(&States::Connected));
		assert_eq!(core::mem::discriminant(&sending), core::mem::discriminant(&States::Sending));
	}

	#[test]
	fn implements_process_state_trait() {
		use macro_test_process::States;

		assert_eq!(States::Idle.process_name(), "MacroTestProcess");
		assert_eq!(States::Connected.process_name(), "MacroTestProcess");
		assert_eq!(States::Sending.process_name(), "MacroTestProcess");

		assert_eq!(States::Idle.state_name(), "Idle");
		assert_eq!(States::Connected.state_name(), "Connected");
		assert_eq!(States::Sending.state_name(), "Sending");
	}

	#[test]
	fn generates_event_wrapper() {
		use macro_test_process::Event;

		let connect = Event("connect");
		let send = Event("send");
		let ack = Event("ack");
		let disconnect = Event("disconnect");
		assert_eq!(connect.0, "connect");
		assert_eq!(send.0, "send");
		assert_eq!(ack.0, "ack");
		assert_eq!(disconnect.0, "disconnect");
	}

	#[test]
	fn implements_process_event_trait() {
		use macro_test_process::Event;

		assert_eq!(Event("connect").event_label(), "connect");
		assert_eq!(Event("send").event_label(), "send");
		assert_eq!(Event("ack").event_label(), "ack");
		assert_eq!(Event("disconnect").event_label(), "disconnect");
	}
}

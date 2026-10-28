//! tb_gen_process_types! macro for generating States enum and Event wrapper
//!
//! This is an opt-in companion to tb_process_spec! that generates type-safe
//! enums for fault injection. Call it AFTER defining your process spec.

/// Generate States enum and Event wrapper for a CSP process.
///
/// This macro creates a snake_case module containing:
/// - `States` enum with all process states
/// - `Event` struct, which wraps an event URN and keys a fault by the label that the trace records
/// - ProcessState and ProcessEvent trait implementations
///
/// # Examples
///
/// ```
/// use tightbeam::testing::{FaultModel, ProcessEvent, ProcessState};
/// use tightbeam::urn::Urn;
/// use tightbeam::{tb_gen_process_types, tb_process_spec, urn, TightBeamError};
///
/// const SEND: Urn<'static> = urn!("doc", "event:gen-states/send");
/// const ACK: Urn<'static> = urn!("doc", "event:gen-states/ack");
///
/// tb_process_spec! {
///     pub MyProcess,
///     events { observable { SEND, ACK } hidden { } }
///     states {
///         Ready => { SEND => Sending },
///         Sending => { ACK => Ready }
///     }
/// }
///
/// // Generate types for fault injection
/// tb_gen_process_types!(MyProcess, Ready, Sending);
///
/// // A state keys as `Process.State`, and an event as the label of its URN.
/// use my_process::{Event, States};
/// assert_eq!(States::Ready.full_key(), "MyProcess.Ready");
/// assert_eq!(Event(SEND).event_label(), SEND.to_string());
///
/// // Use in fault injection
/// let fault = || TightBeamError::ChannelClosed;
/// let model = FaultModel::default();
/// let model = model.with_fault(States::Ready, Event(SEND), fault, tightbeam::bps!(1000));
/// ```
#[cfg(feature = "testing-fault")]
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
}

#[cfg(all(test, feature = "testing-fault"))]
mod tests {
	use crate::testing::fault::{ProcessEvent, ProcessState};
	use crate::testing::fdr::FaultModel;
	use crate::trace::TraceCollector;
	use crate::urn::Urn;
	use crate::TightBeamError;

	const CONNECT: Urn<'static> = crate::urn!("test", "event:gen-states/connect");
	const SEND: Urn<'static> = crate::urn!("test", "event:gen-states/send");
	const ACK: Urn<'static> = crate::urn!("test", "event:gen-states/ack");
	const DISCONNECT: Urn<'static> = crate::urn!("test", "event:gen-states/disconnect");

	// Test process definition
	crate::tb_process_spec! {
		pub MacroTestProcess,
		events {
			observable { CONNECT, SEND, ACK, DISCONNECT }
			hidden { }
		}
		states {
			Idle => { CONNECT => Connected },
			Connected => { SEND => Sending, DISCONNECT => Idle },
			Sending => { ACK => Connected }
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

		let connect = Event(CONNECT);
		let send = Event(SEND);
		let ack = Event(ACK);
		let disconnect = Event(DISCONNECT);
		assert_eq!(connect.0, CONNECT);
		assert_eq!(send.0, SEND);
		assert_eq!(ack.0, ACK);
		assert_eq!(disconnect.0, DISCONNECT);
	}

	#[test]
	fn implements_process_event_trait() {
		use macro_test_process::Event;

		assert_eq!(Event(CONNECT).event_label(), "urn:test:event:gen-states/connect");
		assert_eq!(Event(SEND).event_label(), "urn:test:event:gen-states/send");
		assert_eq!(Event(ACK).event_label(), "urn:test:event:gen-states/ack");
		assert_eq!(Event(DISCONNECT).event_label(), "urn:test:event:gen-states/disconnect");
	}

	#[test]
	fn a_fault_keyed_by_a_generated_event_fires_at_the_label_the_trace_records() {
		use macro_test_process::Event;

		let fault = || TightBeamError::ChannelClosed;
		let model = FaultModel::default().with_event_fault(Event(CONNECT), fault, crate::bps!(10000));
		let trace = TraceCollector::new().with_fault_model(model);
		assert!(matches!(trace.event(CONNECT), Err(TightBeamError::ChannelClosed)));
	}
}

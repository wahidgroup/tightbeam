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

	use macro_test_process::{Event, States};

	const CONNECT: Urn<'static> = crate::urn!("test", "event:gen-states/connect");
	const SEND: Urn<'static> = crate::urn!("test", "event:gen-states/send");
	const ACK: Urn<'static> = crate::urn!("test", "event:gen-states/ack");
	const DISCONNECT: Urn<'static> = crate::urn!("test", "event:gen-states/disconnect");

	// The process whose states and events the macro wraps.
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

	// The state and event types of the process.
	tb_gen_process_types!(MacroTestProcess, Idle, Connected, Sending);

	// A generated state keys by the name of its process and its own name.
	crate::tb_cases! {
		fn a_generated_state_names_its_process_and_itself((state, name): (States, &str)) {
			let key = (state.process_name(), state.state_name());
			assert_eq!(key, ("MacroTestProcess", name));
		}

		cases {
			idle => (States::Idle, "Idle"),
			connected => (States::Connected, "Connected"),
			sending => (States::Sending, "Sending"),
		}
	}

	// A generated event labels itself with the full rendering of its URN.
	crate::tb_cases! {
		fn a_generated_event_labels_itself_with_its_urn((event, label): (Event, &str)) {
			let labelled = event.event_label();
			assert_eq!(labelled, label);
		}

		cases {
			connect => (Event(CONNECT), "urn:test:event:gen-states/connect"),
			send => (Event(SEND), "urn:test:event:gen-states/send"),
			ack => (Event(ACK), "urn:test:event:gen-states/ack"),
			disconnect => (Event(DISCONNECT), "urn:test:event:gen-states/disconnect"),
		}
	}

	/// A fault keyed by a generated event fires at the label that the trace
	/// records for its URN.
	#[test]
	fn a_fault_keyed_by_a_generated_event_fires_at_the_label_the_trace_records() {
		let fault = || TightBeamError::ChannelClosed;
		let model = FaultModel::default().with_event_fault(Event(CONNECT), fault, crate::bps!(10000));
		let trace = TraceCollector::new().with_fault_model(model);

		let recorded = trace.event(CONNECT);
		assert!(matches!(recorded, Err(TightBeamError::ChannelClosed)));
	}
}

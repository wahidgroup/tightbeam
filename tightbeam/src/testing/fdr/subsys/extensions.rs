//! The FDR analysis of a [`ConsumedTrace`], as an extension trait.
//!
//! [`FdrTraceExt`] analyzes one execution trace for FDR. Its conversion of the
//! trace to a process serves refinement checking alone, which compares
//! `spec_process ⊑ trace_process`.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Write;

use crate::policy::TransitStatus;
use crate::testing::assertions::AssertionLabel;
use crate::testing::fdr::verdict::AcceptanceSet;
use crate::testing::specs::csp::{intern, Event, Observation, Process, State, TransitionRelation};
use crate::trace::{ConsumedTrace, InternalEvent};

/// The state label of a trace before its gate decides.
pub const INITIAL: &str = "initial";
/// The state label of a trace after its gate accepts.
pub const GATE_ACCEPT: &str = "gate_accept";
/// The state label of a trace while its handler runs.
pub const HANDLER: &str = "handler";
/// The state label of a trace after its gate rejects.
pub const GATE_REJECT: &str = "gate_reject";
/// The state label of a trace after its response or its rejection.
pub const TERMINAL: &str = "terminal";

/// The events that a trace keeps when it converts to a CSP process for FDR.
///
/// The mode selects the events of a [`ConsumedTrace`] that join the
/// [`Process`] of FDR refinement checking, from the events that the trace
/// captured under its [`TbInstrumentationConfig`].
///
/// `FullInstrumentation` reads the hidden events, which a trace captures
/// when its [`TbInstrumentationConfig`] sets `enable_internal_detail`.
///
/// [`TbInstrumentationConfig`]: crate::instrumentation::TbInstrumentationConfig
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceProcessMode {
	/// The assertion events alone, which [`FdrTraceExt::to_process`] selects.
	AssertionsOnly,
	/// The assertions and the observable instrumentation events.
	///
	/// The observable events are `gate/accept`, `gate/reject`,
	/// `transport/request-recv`, `transport/response-send`, and `assert/label`.
	/// The mode suits a CSP spec that models the full protocol flow, gate
	/// decisions included.
	#[cfg(feature = "instrument")]
	WithObservableInstrumentation,
	/// The assertions and the observable and hidden instrumentation events.
	///
	/// The hidden events are the internal events `handler/enter`,
	/// `handler/exit`, `crypto/step`, `compress/step`, `route/step`, and
	/// `policy/eval`, and each `process/hidden` event. A trace captures the
	/// internal events only when its instrumentation sets
	/// `enable_internal_detail: true`.
	#[cfg(feature = "instrument")]
	FullInstrumentation,
}

/// An extension trait that adds FDR analysis to a [`ConsumedTrace`].
///
/// Each method reads the trace alone. Layer 1 grades what the scenario body
/// returned, in [`ScenarioConfig::verify`].
///
/// [`ScenarioConfig::verify`]: crate::testing::ScenarioConfig::verify
pub trait FdrTraceExt {
	/// Whether the trace is valid, which requires a run whose gate accepted to
	/// record an assertion or a response.
	fn csp_valid(&self) -> bool;

	/// Whether the run ended in a valid terminal state.
	fn terminated_in_valid_state(&self) -> bool;

	/// The acceptance set at the state `state_label`, or `None` for a label
	/// outside [`INITIAL`], [`GATE_ACCEPT`], [`HANDLER`], [`GATE_REJECT`], and
	/// [`TERMINAL`].
	fn acceptance_at(&self, state_label: impl AsRef<str>) -> Option<AcceptanceSet>;

	/// Whether the process can refuse the event `event_label` at the state
	/// `state_label`.
	fn can_refuse_after(&self, state_label: impl AsRef<str>, event_label: impl AsRef<str>) -> bool;

	/// The count of the assertions whose label is `label`.
	fn assertion_count(&self, label: impl AsRef<str>) -> usize;

	/// The labels of the observable instrumentation events of the trace.
	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String>;

	/// The labels of the hidden instrumentation events of the trace.
	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String>;

	/// Writes the observable events of the trace to `writer` as the CSPM
	/// sequence `Trace`, which is empty in a build without `instrument`.
	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()>;

	/// Converts the trace to a CSP process of its assertion events, for FDR
	/// refinement checking.
	///
	/// The process is a linear model of the execution trace, which refinement
	/// checking compares as `spec_process ⊑ trace_process`.
	///
	/// [`Self::to_process_with_mode`] adds the instrumentation events under the
	/// `instrument` feature.
	fn to_process(&self) -> Process {
		self.to_process_with_mode(TraceProcessMode::AssertionsOnly)
	}

	/// Converts the trace to a CSP process of the events that `mode` selects.
	///
	/// [`TraceProcessMode`] lists the modes and the events that each one reads.
	fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process;
}

impl FdrTraceExt for ConsumedTrace {
	fn csp_valid(&self) -> bool {
		// A run whose gate accepted is valid when it shows an assertion or a
		// response. A run with no gate decision took no gate, so it passes.
		if matches!(self.gate_decision, Some(TransitStatus::Ok))
			&& self.assertions.is_empty()
			&& self.response.is_none()
		{
			return false;
		}

		true
	}

	fn terminated_in_valid_state(&self) -> bool {
		match self.gate_decision {
			// An accepted run ends validly when the handler left a response
			// or an assertion.
			Some(TransitStatus::Ok) => self.response.is_some() || !self.assertions.is_empty(),
			// A gate that reached no decision did not terminate.
			Some(TransitStatus::Unknown) => false,
			// Every other status is a rejection, which is terminal.
			Some(_) => true,
			// A run that took no gate passes, because the check reads the
			// gate decision alone.
			None => true,
		}
	}

	fn acceptance_at(&self, state_label: impl AsRef<str>) -> Option<AcceptanceSet> {
		let state_label = state_label.as_ref();
		// The state label alone decides the acceptance set, whatever events
		// the trace recorded.
		let mut acceptance = AcceptanceSet::new();
		match state_label {
			INITIAL => {
				// Before the gate decides, the state accepts the request.
				acceptance.insert(Event("request"));
			}
			GATE_ACCEPT => {
				// After the gate accepts, the state accepts the handler entry.
				acceptance.insert(Event(InternalEvent::HandlerEnter.label()));
			}
			HANDLER => {
				// While the handler runs, the state accepts the handler exit
				// and the response.
				acceptance.insert(Event(InternalEvent::HandlerExit.label()));
				acceptance.insert(Event("response"));
			}
			GATE_REJECT | TERMINAL => {
				// A rejected or terminal state has an empty acceptance set.
			}
			_ => {
				// An unknown state label has no acceptance set.
				return None;
			}
		}

		Some(acceptance)
	}

	fn can_refuse_after(&self, state_label: impl AsRef<str>, event_label: impl AsRef<str>) -> bool {
		let state_label = state_label.as_ref();
		let event_label = event_label.as_ref();
		// A state refuses each event outside its acceptance set.
		if let Some(acceptance) = self.acceptance_at(state_label) {
			!acceptance.iter().any(|e| e.0 == event_label)
		} else {
			// An unknown state label refuses every event, which is the
			// conservative answer.
			true
		}
	}

	fn assertion_count(&self, label: impl AsRef<str>) -> usize {
		let label = label.as_ref();
		self.assertions
			.iter()
			.filter(|a| matches!(&a.label, AssertionLabel::Custom(l) if l.as_ref() == label))
			.count()
	}

	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String> {
		use crate::instrumentation::events;

		self.instrument_events
			.iter()
			.filter(|e| {
				e.urn == events::GATE_ACCEPT
					|| e.urn == events::GATE_REJECT
					|| e.urn == events::REQUEST_RECV
					|| e.urn == events::RESPONSE_SEND
					|| e.urn == events::ASSERT_LABEL
			})
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		use crate::instrumentation::events;

		self.instrument_events
			.iter()
			.filter(|e| InternalEvent::of(&e.urn).is_some() || e.urn == events::PROCESS_HIDDEN)
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	fn export_cspm<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
		writeln!(writer, "-- Execution trace")?;
		writeln!(writer, "Trace = <")?;

		#[cfg(feature = "instrument")]
		{
			let observable = self.project_to_observable();
			for (idx, event) in observable.iter().enumerate() {
				if idx > 0 {
					write!(writer, ", ")?;
				}
				write!(writer, "{event}")?;
			}
		}

		writeln!(writer, ">")?;
		Ok(())
	}

	/// Converts the trace to a CSP process of the events that `mode` selects,
	/// for FDR refinement checking.
	///
	/// The process models the one execution path of the trace as a linear,
	/// acyclic chain of states, so BFS exploration of it ends.
	fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process {
		let mut states = HashSet::new();
		let mut terminal = HashSet::new();
		let mut observable = HashSet::new();
		let mut hidden = HashSet::new();
		let mut transitions = TransitionRelation::new();

		let s_initial = State(INITIAL);
		let s_terminal = State(TERMINAL);

		states.insert(s_initial);
		states.insert(s_terminal);
		terminal.insert(s_terminal);

		// An event of the trace, with the sequence number that orders it.
		#[derive(Clone)]
		enum TraceEvent {
			Assertion {
				seq: usize,
				label: &'static str,
			},
			#[cfg(feature = "instrument")]
			ObservableInstrumentation {
				seq: u32,
				label: String,
			},
			#[cfg(feature = "instrument")]
			HiddenInstrumentation {
				seq: u32,
				label: String,
			},
		}

		let mut events: Vec<TraceEvent> = Vec::new();

		// Every mode includes the assertions.
		for assertion in &self.assertions {
			let AssertionLabel::Custom(label) = &assertion.label;
			let static_label: &'static str = match label {
				Cow::Borrowed(s) => s,
				Cow::Owned(s) => intern(s.as_str()),
			};

			events.push(TraceEvent::Assertion { seq: assertion.seq, label: static_label });
		}

		// The mode selects the instrumentation events that join the
		// assertions.
		#[cfg(feature = "instrument")]
		{
			match mode {
				TraceProcessMode::AssertionsOnly => {
					// This mode takes the assertions alone.
				}
				TraceProcessMode::WithObservableInstrumentation | TraceProcessMode::FullInstrumentation => {
					// Both modes take the observable instrumentation events.
					use crate::instrumentation::events;
					for event in &self.instrument_events {
						if event.urn == events::GATE_ACCEPT
							|| event.urn == events::GATE_REJECT
							|| event.urn == events::REQUEST_RECV
							|| event.urn == events::RESPONSE_SEND
							|| event.urn == events::ASSERT_LABEL
						{
							if let Some(label) = &event.label {
								events.push(TraceEvent::ObservableInstrumentation {
									seq: event.seq,
									label: label.clone(),
								});
							}
						}
					}
				}
			}

			if matches!(mode, TraceProcessMode::FullInstrumentation) {
				// `FullInstrumentation` also takes the hidden instrumentation
				// events.
				use crate::instrumentation::events;
				for event in &self.instrument_events {
					if InternalEvent::of(&event.urn).is_some() || event.urn == events::PROCESS_HIDDEN {
						if let Some(label) = &event.label {
							events.push(TraceEvent::HiddenInstrumentation { seq: event.seq, label: label.clone() });
						}
					}
				}
			}
		}

		// The events sort by sequence number, so each kind keeps its recorded
		// order. An assertion counts the assertions before it, and an
		// instrumentation event counts the instrumentation events before it,
		// so the two kinds interleave by those two counts.
		events.sort_by(|a, b| {
			let seq_a = match a {
				TraceEvent::Assertion { seq, .. } => *seq as u64,
				#[cfg(feature = "instrument")]
				TraceEvent::ObservableInstrumentation { seq, .. } | TraceEvent::HiddenInstrumentation { seq, .. } => *seq as u64,
			};
			let seq_b = match b {
				TraceEvent::Assertion { seq, .. } => *seq as u64,
				#[cfg(feature = "instrument")]
				TraceEvent::ObservableInstrumentation { seq, .. } | TraceEvent::HiddenInstrumentation { seq, .. } => *seq as u64,
			};

			seq_a.cmp(&seq_b)
		});

		// Each event takes one state of the chain to the next.
		if !events.is_empty() {
			let mut from_state = s_initial;
			for (idx, event) in events.iter().enumerate() {
				let (event, is_hidden) = match event {
					TraceEvent::Assertion { label, .. } => (Event(label), false),
					#[cfg(feature = "instrument")]
					TraceEvent::ObservableInstrumentation { label, .. } => (Event(intern(label.as_str())), false),
					#[cfg(feature = "instrument")]
					TraceEvent::HiddenInstrumentation { label, .. } => (Event(intern(label.as_str())), true),
				};

				// A hidden instrumentation event joins the hidden alphabet, and
				// every other event joins the observable alphabet.
				if is_hidden {
					hidden.insert(event);
				} else {
					observable.insert(event);
				}

				// The last event reaches the terminal state, and each earlier
				// event reaches an intermediate state of its own.
				let to_state = if idx == events.len() - 1 {
					s_terminal
				} else {
					let to_state = State(intern(format!("trace_state_{idx}")));
					states.insert(to_state);

					to_state
				};

				transitions.add(from_state, event, to_state);
				from_state = to_state;
			}
		}

		// A trace with no event leaves the initial state with no transition,
		// and that state is not terminal, so the process is STOP.

		let description = match mode {
			TraceProcessMode::AssertionsOnly => "Process derived from ConsumedTrace (assertion events only)",
			#[cfg(feature = "instrument")]
			TraceProcessMode::WithObservableInstrumentation => {
				"Process derived from ConsumedTrace (assertions + observable instrumentation)"
			}
			#[cfg(feature = "instrument")]
			TraceProcessMode::FullInstrumentation => {
				"Process derived from ConsumedTrace (all events including hidden instrumentation)"
			}
		};

		Process {
			name: "TraceProcess",
			observation: Observation::RecordedTrace,
			requires_progress: false,
			initial: s_initial,
			states,
			terminal,
			choice: HashSet::new(), // A single trace follows one path.
			observable,
			hidden,
			transitions,
			description: Some(description),
			#[cfg(feature = "testing-timing")]
			timing_constraints: None,
			#[cfg(feature = "testing-timing")]
			timed_transitions: None,
			#[cfg(feature = "testing-schedulability")]
			schedulability_periods: None,
		}
	}
}

// The inherent forms of the two conversions, which a caller reaches with
// `ConsumedTrace` alone in scope.
impl ConsumedTrace {
	/// Converts this trace to a CSP process of its assertion events, for FDR
	/// refinement checking.
	///
	/// It calls [`FdrTraceExt::to_process`], which documents the conversion.
	pub fn to_process(&self) -> Process {
		<Self as FdrTraceExt>::to_process(self)
	}

	/// Converts this trace to a CSP process of the events that `mode` selects.
	///
	/// It calls [`FdrTraceExt::to_process_with_mode`], which documents the
	/// conversion.
	pub fn to_process_with_mode(&self, mode: TraceProcessMode) -> Process {
		<Self as FdrTraceExt>::to_process_with_mode(self, mode)
	}
}

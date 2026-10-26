//! The FDR analysis of a [`ConsumedTrace`], as an extension trait.
//!
//! [`FdrTraceExt`] analyzes one execution trace for FDR. Its conversion of the
//! trace to a process serves refinement checking alone, which compares
//! `spec_process ⊑ trace_process`.

use std::borrow::Cow;
use std::collections::HashSet;
use std::io::Write;

use crate::policy::TransitStatus;
use crate::testing::assertions::{Assertion, AssertionLabel};
use crate::testing::fdr::verdict::AcceptanceSet;
use crate::testing::specs::csp::{intern, Action, Event, Observation, Process, State, TransitionRelation};
use crate::trace::{ConsumedTrace, InternalEvent};

#[cfg(feature = "instrument")]
use crate::urn::Urn;

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
/// - `FullInstrumentation` reads the hidden events, which a trace captures
///   when its [`TbInstrumentationConfig`] sets `enable_internal_detail`.
/// - The two instrumentation modes read each assertion from its own record,
///   `assert/label`, `assert/payload`, or `timing/wcet`, so each event enters
///   once, in the order that the trace recorded it.
/// - A sink that drops records also drops the assertions among them.
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

impl TraceProcessMode {
	/// The events of `trace` that this mode selects, each as an action of its
	/// alphabet, in the order that the trace recorded them.
	fn chain(self, trace: &ConsumedTrace) -> Vec<Action> {
		match self {
			Self::AssertionsOnly => trace.assertions.iter().map(Self::assertion_action).collect(),
			#[cfg(feature = "instrument")]
			Self::WithObservableInstrumentation | Self::FullInstrumentation => {
				let records = trace.instrument_events.iter();
				let selected = records.filter_map(|record| {
					let kind = Record::of(&record.urn).filter(|kind| self.admits(*kind))?;
					let label = intern(record.label.as_deref()?);
					match kind {
						Record::Hidden => Some(Action::hidden(label)),
						Record::Observable | Record::Measured => Some(Action::observable(label)),
					}
				});

				selected.collect()
			}
		}
	}

	/// The observable action of `assertion`, named by its label.
	fn assertion_action(assertion: &Assertion) -> Action {
		let AssertionLabel::Custom(label) = &assertion.label;
		let name: &'static str = match label {
			Cow::Borrowed(name) => name,
			Cow::Owned(name) => intern(name.as_str()),
		};

		Action::observable(name)
	}

	/// Whether this mode admits an instrumentation record of `kind`.
	#[cfg(feature = "instrument")]
	fn admits(self, kind: Record) -> bool {
		kind != Record::Hidden || self == Self::FullInstrumentation
	}
}

/// The kind of an instrumentation record, as the process of a trace reads it.
#[cfg(feature = "instrument")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Record {
	/// An observable instrumentation event: `gate/accept`, `gate/reject`,
	/// `transport/request-recv`, `transport/response-send`, or `assert/label`,
	/// the record of an assertion with no value.
	Observable,
	/// The record of an assertion with a value or a duration, `assert/payload`
	/// or `timing/wcet`.
	Measured,
	/// A hidden instrumentation event, an internal event or `process/hidden`.
	Hidden,
}

#[cfg(feature = "instrument")]
impl Record {
	/// The kind of a record of `urn`, or `None` for a record that the process
	/// of a trace leaves out.
	fn of(urn: &Urn<'static>) -> Option<Self> {
		use crate::instrumentation::events;

		let observable = [
			events::GATE_ACCEPT,
			events::GATE_REJECT,
			events::REQUEST_RECV,
			events::RESPONSE_SEND,
		];
		if observable.contains(urn) || *urn == events::ASSERT_LABEL {
			return Some(Self::Observable);
		}

		if *urn == events::ASSERT_PAYLOAD || *urn == events::TIMING_WCET {
			return Some(Self::Measured);
		}

		let hidden = InternalEvent::of(urn).is_some() || *urn == events::PROCESS_HIDDEN;
		hidden.then_some(Self::Hidden)
	}
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
		// response. A run with no gate decision takes no gate, so it passes.
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
			// An accepted run ends validly when the handler leaves a response
			// or an assertion.
			Some(TransitStatus::Ok) => self.response.is_some() || !self.assertions.is_empty(),
			// A gate whose status is unknown leaves the run unterminated.
			Some(TransitStatus::Unknown) => false,
			// Every other status is a rejection, which is terminal.
			Some(_) => true,
			// A run that takes no gate passes, because the check reads the
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
				acceptance.insert(Event("request"));
			}
			GATE_ACCEPT => {
				acceptance.insert(Event(InternalEvent::HandlerEnter.label()));
			}
			HANDLER => {
				acceptance.insert(Event(InternalEvent::HandlerExit.label()));
				acceptance.insert(Event("response"));
			}
			GATE_REJECT | TERMINAL => {
				// A rejected or terminal state has an empty acceptance set.
			}
			_ => {
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
		self.instrument_events
			.iter()
			.filter(|e| Record::of(&e.urn) == Some(Record::Observable))
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		self.instrument_events
			.iter()
			.filter(|e| Record::of(&e.urn) == Some(Record::Hidden))
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

		// Each event takes one state of the chain to the next.
		let chain = mode.chain(self);
		let last = chain.len().saturating_sub(1);
		let mut from_state = s_initial;
		for (idx, action) in chain.into_iter().enumerate() {
			if action.is_hidden() {
				hidden.insert(action.event);
			} else {
				observable.insert(action.event);
			}

			let to_state = if idx == last {
				s_terminal
			} else {
				State(intern(format!("trace_state_{idx}")))
			};

			states.insert(to_state);
			transitions.add(from_state, action.event, to_state);
			from_state = to_state;
		}

		// The run ends where the chain ends, so that state is accepting. A
		// trace with no event ends at its initial state.
		terminal.insert(from_state);

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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::fdr::{Decision, DefaultFdrExplorer, FdrConfig};
	use crate::trace::TraceCollector;
	use crate::urn::Urn;
	use crate::TightBeamError;

	#[cfg(feature = "instrument")]
	use crate::instrumentation::events::GATE_ACCEPT;

	/// An assertion that a run records first.
	const FIRST: Urn<'static> = crate::urn!("test", "event:extensions/first");

	/// An assertion that a run records after its gate decides.
	#[cfg(feature = "instrument")]
	const AFTER: Urn<'static> = crate::urn!("test", "event:extensions/after");

	/// The trace that `collector` recorded, with `gate` as its gate decision.
	fn consumed(collector: &TraceCollector, gate: Option<TransitStatus>) -> ConsumedTrace {
		let mut trace = ConsumedTrace::new();
		trace.populate_from_collector(collector);
		trace.gate_decision = gate;
		trace
	}

	/// The events along the one chain of `process`, from its initial state.
	#[cfg(feature = "instrument")]
	fn chain_of(process: &Process) -> Vec<&'static str> {
		let mut chain = Vec::new();
		let mut state = process.initial;
		while let Some(action) = process.enabled(state).into_iter().next() {
			chain.push(action.event.0);
			let Some(next) = process.step(state, &action.event).into_iter().next() else {
				break;
			};

			state = next;
		}

		chain
	}

	#[test]
	fn a_run_whose_gate_accepted_with_no_assertion_and_no_response_is_invalid() {
		let trace = consumed(&TraceCollector::new(), Some(TransitStatus::Ok));
		assert!(!trace.csp_valid(), "an accepted run shows neither an assertion nor a response");
	}

	#[test]
	fn a_run_whose_gate_accepted_with_an_assertion_is_valid() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.event(FIRST)?.emit();

		let trace = consumed(&collector, Some(TransitStatus::Ok));
		assert!(trace.csp_valid(), "the accepted run recorded an assertion");
		Ok(())
	}

	#[test]
	fn a_gate_that_reached_no_decision_ends_in_an_invalid_state() {
		let trace = consumed(&TraceCollector::new(), Some(TransitStatus::Unknown));
		assert!(!trace.terminated_in_valid_state(), "an undecided gate did not terminate");
	}

	#[test]
	fn a_rejected_run_ends_in_a_valid_state() {
		let trace = consumed(&TraceCollector::new(), Some(TransitStatus::PermissionDenied));

		assert!(trace.terminated_in_valid_state(), "a rejection is terminal");
	}

	#[test]
	fn a_trace_with_no_event_converts_to_a_process_free_of_deadlock() {
		let process = ConsumedTrace::new().to_process();
		let mut explorer = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default());

		let verdict = explorer.explore();
		assert_eq!(verdict.deadlock_free, Decision::Holds, "the run ended where it started");
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn a_valueless_assertion_enters_the_chain_once() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.event(FIRST)?.emit();
		let trace = consumed(&collector, None);

		let process = trace.to_process_with_mode(TraceProcessMode::WithObservableInstrumentation);
		let first = FIRST.to_string();
		assert_eq!(chain_of(&process), [first.as_str()]);
		Ok(())
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn an_instrumentation_event_keeps_its_place_among_the_assertions() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.emit_event_with_evidence(GATE_ACCEPT, "Ok", None)?;
		collector.event(AFTER)?.emit();
		let trace = consumed(&collector, None);

		let process = trace.to_process_with_mode(TraceProcessMode::WithObservableInstrumentation);
		let (gate, after) = (GATE_ACCEPT.to_string(), AFTER.to_string());
		assert_eq!(chain_of(&process), [gate.as_str(), "Ok", after.as_str()]);
		Ok(())
	}
}

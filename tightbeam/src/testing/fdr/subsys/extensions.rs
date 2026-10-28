//! The FDR analysis of a [`ConsumedTrace`], as an extension trait.
//!
//! [`FdrTraceExt`] analyzes one execution trace for FDR. Its conversion of the
//! trace to a process serves refinement checking alone, as
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
use crate::instrumentation::TbEvent;

/// A state of the house request path.
///
/// Each state accepts the events of [`Self::acceptance`] and can refuse the
/// rest.
///
/// # Examples
///
/// ```
/// use tightbeam::testing::fdr::RequestPathState;
///
/// assert!(RequestPathState::Handler.refuses("request"));
/// assert!(!RequestPathState::Handler.refuses("response"));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestPathState {
	/// The state of a request before its gate decides.
	Initial,
	/// The state of a request after its gate accepts it.
	GateAccept,
	/// The state of a request while its handler runs.
	Handler,
	/// The state of a request after its gate rejects it.
	GateReject,
	/// The state of a request after its response or its rejection.
	Terminal,
}

impl RequestPathState {
	/// The label of this state.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::RequestPathState;
	///
	/// assert_eq!(RequestPathState::GateAccept.as_str(), "gate_accept");
	/// ```
	pub const fn as_str(self) -> &'static str {
		match self {
			Self::Initial => "initial",
			Self::GateAccept => "gate_accept",
			Self::Handler => "handler",
			Self::GateReject => "gate_reject",
			Self::Terminal => "terminal",
		}
	}

	/// The events that this state accepts.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::{AcceptanceSet, RequestPathState};
	/// use tightbeam::testing::specs::csp::Event;
	///
	/// let accepted = AcceptanceSet::from([Event("handler_exit"), Event("response")]);
	/// assert_eq!(RequestPathState::Handler.acceptance(), accepted);
	/// ```
	pub fn acceptance(self) -> AcceptanceSet {
		self.accepted().iter().copied().map(Event).collect()
	}

	/// Whether this state can refuse the event `event_label`.
	///
	/// A state can refuse each event outside [`Self::acceptance`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::fdr::RequestPathState;
	///
	/// assert!(RequestPathState::Initial.refuses("response"));
	/// assert!(!RequestPathState::Initial.refuses("request"));
	/// ```
	pub fn refuses(self, event_label: impl AsRef<str>) -> bool {
		let event_label = event_label.as_ref();
		!self.accepted().contains(&event_label)
	}

	/// The labels of the events that this state accepts.
	fn accepted(self) -> &'static [&'static str] {
		const AFTER_ACCEPT: &[&str] = &[InternalEvent::HandlerEnter.label()];
		const IN_HANDLER: &[&str] = &[InternalEvent::HandlerExit.label(), "response"];
		match self {
			Self::Initial => &["request"],
			Self::GateAccept => AFTER_ACCEPT,
			Self::Handler => IN_HANDLER,
			Self::GateReject | Self::Terminal => &[],
		}
	}
}

/// The events of a [`ConsumedTrace`] that join its CSP [`Process`] for FDR
/// refinement checking, out of the events it captured under its
/// [`TbInstrumentationConfig`].
///
/// - The two instrumentation modes read each event from its one record, in
///   recorded order. An event that [`TraceCollector::event`] records enters as
///   `assert/label`, `assert/payload`, or `timing/wcet`.
/// - A record that the event API wrote, such as [`TraceCollector::emit_event`],
///   carries [`TbEvent::FROM_EVENT_API`]. Such a record of another kind, or
///   with no label, enters under its URN.
/// - A record of another kind that the event API did not write stays out.
/// - A sink that drops records also drops the assertions among them.
///
/// [`TbInstrumentationConfig`]: crate::instrumentation::TbInstrumentationConfig
/// [`TraceCollector::event`]: crate::trace::TraceCollector::event
/// [`TraceCollector::emit_event`]: crate::trace::TraceCollector::emit_event
/// [`TbEvent::FROM_EVENT_API`]: crate::instrumentation::TbEvent::FROM_EVENT_API
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceProcessMode {
	/// The assertion events alone, which [`FdrTraceExt::to_process`] selects.
	AssertionsOnly,
	/// The assertions and the observable instrumentation events.
	///
	/// The observable events are `gate/accept`, `gate/reject`,
	/// `transport/request-recv`, `transport/response-send`, and `assert/label`.
	/// It suits a CSP spec that models the full protocol flow, gate decisions
	/// included.
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
			Self::AssertionsOnly => trace.assertions().iter().map(Self::assertion_action).collect(),
			#[cfg(feature = "instrument")]
			Self::WithObservableInstrumentation | Self::FullInstrumentation => {
				let records = trace.instrument_events().iter();
				let selected = records.filter_map(|record| self.action_of(record));
				selected.collect()
			}
		}
	}

	/// The action of `record` in the chain of this mode, or `None` for a
	/// record that the mode leaves out.
	#[cfg(feature = "instrument")]
	fn action_of(self, record: &TbEvent) -> Option<Action> {
		let kind = Record::of(record).filter(|kind| self.admits(*kind))?;
		let name = kind.name_of(record)?;
		match kind {
			Record::Hidden => Some(Action::hidden(name)),
			Record::Observable | Record::Measured | Record::Written => Some(Action::observable(name)),
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
	/// A record of another kind that the event API wrote, which enters as an
	/// observable event under its URN.
	Written,
}

#[cfg(feature = "instrument")]
impl Record {
	/// The kind of `record`, or `None` for a record that the process of a
	/// trace leaves out.
	fn of(record: &TbEvent) -> Option<Self> {
		use crate::instrumentation::events;

		let urn = &record.urn;
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
		if hidden {
			return Some(Self::Hidden);
		}

		record.is_from_event_api().then_some(Self::Written)
	}

	/// The name of the action of `record`, a record of this kind.
	///
	/// A [`Self::Written`] record enters under its URN. A record of another
	/// kind enters under its label, or under its URN when it has no label and
	/// the event API wrote it. The URN renders for those records alone.
	fn name_of(self, record: &TbEvent) -> Option<&'static str> {
		let under_urn = || intern(record.urn.to_string());
		match (self, record.label.as_deref()) {
			(Self::Written, _) => Some(under_urn()),
			(_, Some(label)) => Some(intern(label)),
			(_, None) => record.is_from_event_api().then(under_urn),
		}
	}
}

/// An extension trait that adds FDR analysis to a [`ConsumedTrace`].
///
/// Its methods read the trace alone. The acceptance and refusals of a state
/// are queries of [`RequestPathState`].
pub trait FdrTraceExt {
	/// Whether the trace is valid, which requires a run whose gate accepted to
	/// record an assertion or a response.
	fn csp_valid(&self) -> bool;

	/// Whether the run ended in a valid terminal state.
	fn terminated_in_valid_state(&self) -> bool;

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
			&& self.assertions().is_empty()
			&& self.response().is_none()
		{
			return false;
		}

		true
	}

	fn terminated_in_valid_state(&self) -> bool {
		match self.gate_decision {
			// An accepted run ends validly when the handler leaves a response
			// or an assertion.
			Some(TransitStatus::Ok) => self.response().is_some() || !self.assertions().is_empty(),
			// A gate whose status is unknown leaves the run unterminated.
			Some(TransitStatus::Unknown) => false,
			// Every other status is a rejection, which is terminal.
			Some(_) => true,
			// A run that takes no gate passes, because the check reads the
			// gate decision alone.
			None => true,
		}
	}

	fn assertion_count(&self, label: impl AsRef<str>) -> usize {
		let label = label.as_ref();
		self.assertions()
			.iter()
			.filter(|a| matches!(&a.label, AssertionLabel::Custom(l) if l.as_ref() == label))
			.count()
	}

	#[cfg(feature = "instrument")]
	fn project_to_observable(&self) -> Vec<String> {
		self.instrument_events()
			.iter()
			.filter(|e| Record::of(e) == Some(Record::Observable))
			.filter_map(|e| e.label.as_ref().map(|s| s.to_string()))
			.collect()
	}

	#[cfg(feature = "instrument")]
	fn project_to_hidden(&self) -> Vec<String> {
		self.instrument_events()
			.iter()
			.filter(|e| Record::of(e) == Some(Record::Hidden))
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

		let s_initial = State(RequestPathState::Initial.as_str());
		let s_terminal = State(RequestPathState::Terminal.as_str());

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
	fn a_trace_with_no_event_converts_to_a_process_free_of_deadlock() -> Result<(), TightBeamError> {
		let process = ConsumedTrace::new().to_process();
		let mut explorer = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default());

		let verdict = explorer.explore()?;
		assert_eq!(verdict.deadlock_free, Decision::Holds, "the run ended where it started");
		Ok(())
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
		let after = AFTER.to_string();
		assert_eq!(chain_of(&process), ["Ok", after.as_str()]);
		Ok(())
	}

	/// A dual-written event outside the observable kinds enters the chain once,
	/// under the URN that its assertion names.
	#[cfg(feature = "instrument")]
	#[test]
	fn a_dual_written_event_enters_the_chain_under_its_urn() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.emit_event_with_evidence(FIRST, "why", None)?;

		let trace = consumed(&collector, None);

		let process = trace.to_process_with_mode(TraceProcessMode::WithObservableInstrumentation);
		let first = FIRST.to_string();
		assert_eq!(chain_of(&process), [first.as_str()]);
		Ok(())
	}

	/// A record of another kind that the event API did not write stays out of
	/// the chain, though the event API wrote a record of the same URN.
	#[cfg(feature = "instrument")]
	#[test]
	fn a_plain_record_of_a_written_event_stays_out_of_the_chain() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.emit_event(FIRST)?;
		collector.emit(FIRST, "plain");

		let trace = consumed(&collector, None);

		let process = trace.to_process_with_mode(TraceProcessMode::WithObservableInstrumentation);
		let first = FIRST.to_string();
		assert_eq!(chain_of(&process), [first.as_str()]);
		Ok(())
	}

	/// An observable record that the event API wrote with no label enters the
	/// chain under its URN.
	#[cfg(feature = "instrument")]
	#[test]
	fn an_unlabelled_written_record_enters_the_chain_under_its_urn() -> Result<(), TightBeamError> {
		let collector = TraceCollector::new();
		collector.emit_event(GATE_ACCEPT)?;

		let trace = consumed(&collector, None);

		let process = trace.to_process_with_mode(TraceProcessMode::WithObservableInstrumentation);
		let accept = GATE_ACCEPT.to_string();
		assert_eq!(chain_of(&process), [accept.as_str()]);
		Ok(())
	}
}

//! The exploration events that a trace asks FDR exploration to record.
//!
//! [`ExplorationRecorder`] reads the three exploration flags of a trace's
//! instrumentation settings once. It then records the events they ask for
//! about each explored process, through the dual-write path of
//! [`TraceCollector`].

use std::collections::HashSet;

use super::engine::Divergence;
use crate::instrumentation::events::{DIVERGENCE_DETECT, ENABLED_SET_SAMPLE, REFUSAL_SNAPSHOT};
use crate::testing::specs::csp::{Event, Process, State};
use crate::trace::TraceCollector;
use crate::TightBeamError;

/// A trace, paired with the exploration events that its instrumentation
/// settings ask for.
pub(crate) struct ExplorationRecorder<'t> {
	/// The trace that receives each event.
	trace: &'t TraceCollector,
	/// Whether each visited state records the observable events it offers.
	enabled_sets: bool,
	/// Whether each visited stable or accepting state records its refusal set.
	refusals: bool,
	/// Whether each state where a seed diverged records the run of the
	/// divergence.
	divergences: bool,
}

impl<'t> ExplorationRecorder<'t> {
	/// The recorder of `trace`, or `None` when the settings of `trace` ask
	/// for no exploration event.
	///
	/// It is the one reader of `sample_enabled_sets`, `sample_refusals`, and
	/// `divergence_heuristics`, which [`TraceCollector::exploration_asks`]
	/// lends apart from the other settings.
	pub(crate) fn of(trace: &'t TraceCollector) -> Option<Self> {
		let asks = trace.exploration_asks();
		let recorder = Self {
			trace,
			enabled_sets: asks.enabled_sets,
			refusals: asks.refusals,
			divergences: asks.divergences,
		};

		let asked = recorder.enabled_sets || recorder.refusals || recorder.divergences;
		asked.then_some(recorder)
	}

	/// Records the asked events of one explored process.
	///
	/// The events of each state the seeds visited (`visited`) come first, in
	/// the order of the state names. One event per state where a seed diverged
	/// (`divergences`) follows, in the same order.
	///
	/// # Errors
	///
	/// - The error of the first event that the trace refused.
	pub(crate) fn record(
		&self,
		process: &Process,
		visited: &HashSet<State>,
		divergences: &[Divergence],
	) -> Result<(), TightBeamError> {
		self.record_states(process, visited)?;
		self.record_divergences(process, divergences)
	}

	/// Records the enabled set and the refusal set of each state in `visited`
	/// that the trace asks for, in the order of the state names.
	///
	/// # Errors
	///
	/// - The error of the first event that the trace refused.
	fn record_states(&self, process: &Process, visited: &HashSet<State>) -> Result<(), TightBeamError> {
		if !self.enabled_sets && !self.refusals {
			return Ok(());
		}

		let mut states: Vec<State> = visited.iter().copied().collect();
		states.sort_unstable();
		for state in states {
			self.record_state(process, state)?;
		}

		Ok(())
	}

	/// Records the asked events of `state`, one visited state of `process`.
	///
	/// # Errors
	///
	/// - The error of the first event that the trace refused.
	fn record_state(&self, process: &Process, state: State) -> Result<(), TightBeamError> {
		if self.enabled_sets {
			let offers = process.offers(state);
			let label = Notation::Set.label(process, state, offers);
			self.trace.emit_event_with_evidence(ENABLED_SET_SAMPLE, label, None)?;
		}

		let refusals = self.refusals.then(|| process.failure_refusals(state)).flatten();
		if let Some(refusals) = refusals {
			let label = Notation::Set.label(process, state, refusals);
			self.trace.emit_event_with_evidence(REFUSAL_SNAPSHOT, label, None)?;
		}

		Ok(())
	}

	/// Records the divergences in `divergences` when the trace asks for them,
	/// once per state in the order of the state names, with the run of the
	/// first seed that diverged there.
	///
	/// # Errors
	///
	/// - The error of the first event that the trace refused.
	fn record_divergences(&self, process: &Process, divergences: &[Divergence]) -> Result<(), TightBeamError> {
		if !self.divergences {
			return Ok(());
		}

		let mut found: Vec<&Divergence> = divergences.iter().collect();
		found.sort_by_key(|(state, _run)| *state);
		found.dedup_by_key(|(state, _run)| *state);
		for (state, run) in found {
			let label = Notation::Sequence.label(process, *state, run.iter().copied());
			self.trace.emit_event_with_evidence(DIVERGENCE_DETECT, label, None)?;
		}

		Ok(())
	}
}

/// The CSPM notation in which an exploration event writes its events.
#[derive(Clone, Copy)]
enum Notation {
	/// A set, written `{a, b}` with its members in the order of their names.
	Set,
	/// A sequence, written `<a, b>` in the order of its run.
	Sequence,
}

impl Notation {
	/// Returns the label of `state`, a state of `process`, and of `events`,
	/// such as `Offering.S0: {a, b}`, built in one `String`.
	fn label(self, process: &Process, state: State, events: impl IntoIterator<Item = Event>) -> String {
		let mut label = String::new();
		for part in [process.name, ".", state.0, ": "] {
			label.push_str(part);
		}

		let names = events.into_iter().map(|event| event.0);
		match self {
			Self::Set => {
				let mut sorted: Vec<&'static str> = names.collect();
				sorted.sort_unstable();
				Self::enclose(&mut label, ('{', '}'), sorted);
			}
			Self::Sequence => Self::enclose(&mut label, ('<', '>'), names),
		}

		label
	}

	/// Writes `names` into `label` inside `brackets`, with a comma and a space
	/// between each two names.
	fn enclose(label: &mut String, brackets: (char, char), names: impl IntoIterator<Item = &'static str>) {
		let (open, close) = brackets;
		label.push(open);
		for (at, name) in names.into_iter().enumerate() {
			if at > 0 {
				label.push_str(", ");
			}
			label.push_str(name);
		}

		label.push(close);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::instrumentation::TbInstrumentationConfig;
	use crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
	use crate::testing::specs::csp::ProcessBuildError;
	use crate::trace::TraceConfig;
	use crate::urn::Urn;

	#[cfg(feature = "testing-fault")]
	use crate::testing::fdr::FaultModel;

	/// The error type of these tests, which build processes and explore them.
	type TestResult = Result<(), Box<dyn core::error::Error>>;

	/// A process with stable states, an unstable state, and a terminal state.
	///
	/// `S0` offers `a` and `b`, and each leads to `S1`. The hidden `t` takes
	/// `S1` to `S2`, which offers `c`, and `c` leads to the terminal `S3`.
	fn offering() -> Result<Process, ProcessBuildError> {
		Process::builder("Offering")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_observable(Event("c"))
			.add_hidden(Event("t"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S0"), Event("b"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("c"), State("S3"))
			.add_terminal(State("S3"))
			.build()
	}

	/// A process with a hidden diamond and a hidden cycle.
	///
	/// `a` takes `S0` to both `S3` and `S1`, which exploration visits in that
	/// order. The hidden `t` takes `S3` to both `S4` and `S6`, and the hidden
	/// `v` takes each of them to `S7`, so two hidden runs meet at `S7` and
	/// close no cycle. The hidden `t` and `u` take `S1` to `S2` and back, so
	/// each seed diverges at `S1`.
	fn diverging() -> Result<Process, ProcessBuildError> {
		Process::builder("Diverging")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_hidden(Event("v"))
			.add_transition(State("S0"), Event("a"), State("S3"))
			.add_transition(State("S0"), Event("a"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.add_transition(State("S2"), Event("u"), State("S1"))
			.add_transition(State("S2"), Event("b"), State("S5"))
			.add_transition(State("S3"), Event("t"), State("S4"))
			.add_transition(State("S3"), Event("t"), State("S6"))
			.add_transition(State("S4"), Event("v"), State("S7"))
			.add_transition(State("S6"), Event("v"), State("S7"))
			.add_transition(State("S7"), Event("b"), State("S5"))
			.add_terminal(State("S5"))
			.build()
	}

	/// A process whose `a` leads to `S2`, where the hidden `u` and `t` take it
	/// to `S1` and back, so the run of its divergence takes `u` before `t`.
	fn turning() -> Result<Process, ProcessBuildError> {
		Process::builder("Turning")
			.initial_state(State("S0"))
			.add_observable(Event("a"))
			.add_hidden(Event("t"))
			.add_hidden(Event("u"))
			.add_transition(State("S0"), Event("a"), State("S2"))
			.add_transition(State("S2"), Event("u"), State("S1"))
			.add_transition(State("S1"), Event("t"), State("S2"))
			.build()
	}

	/// A specification that offers `send` at `Idle` and stops at `Sent`.
	#[cfg(feature = "testing-fault")]
	fn sending() -> Result<Process, ProcessBuildError> {
		Process::builder("Sending")
			.initial_state(State("Idle"))
			.add_observable(Event("send"))
			.add_transition(State("Idle"), Event("send"), State("Sent"))
			.add_terminal(State("Sent"))
			.build()
	}

	/// A process that can stop at `Idle`, which offers `a` as well, and at
	/// `Done`, which `a` leads to.
	fn accepting() -> Result<Process, ProcessBuildError> {
		Process::builder("Accepting")
			.initial_state(State("Idle"))
			.add_observable(Event("a"))
			.add_observable(Event("b"))
			.add_transition(State("Idle"), Event("a"), State("Done"))
			.add_terminal(State("Idle"))
			.add_terminal(State("Done"))
			.build()
	}

	/// A specification that offers `recv` at `Idle` and stops at `Sent`, so its
	/// states share their names with those of [`sending`].
	#[cfg(feature = "testing-fault")]
	fn receiving() -> Result<Process, ProcessBuildError> {
		Process::builder("Receiving")
			.initial_state(State("Idle"))
			.add_observable(Event("recv"))
			.add_transition(State("Idle"), Event("recv"), State("Sent"))
			.add_terminal(State("Sent"))
			.build()
	}

	/// Instrumentation settings that ask for every exploration event.
	fn every_flag() -> TbInstrumentationConfig {
		TbInstrumentationConfig {
			sample_enabled_sets: true,
			sample_refusals: true,
			divergence_heuristics: true,
			..Default::default()
		}
	}

	/// A trace with the instrumentation `settings`.
	fn trace_with(settings: TbInstrumentationConfig) -> TraceCollector {
		TraceCollector::from(TraceConfig::with_instrumentation(settings))
	}

	/// The labels of the `urn` events that exploring `process` under `config`
	/// records into a trace with `settings`.
	fn recorded(
		process: &Process,
		config: FdrConfig,
		settings: TbInstrumentationConfig,
		urn: Urn<'static>,
	) -> Result<Vec<String>, TightBeamError> {
		let trace = trace_with(settings);
		let mut explorer = DefaultFdrExplorer::with_defaults(process, config);
		explorer.explore_into(&trace)?;

		let events = trace.drain_events();
		let named = events.into_iter().filter(|event| event.urn == urn);
		let labels = named.filter_map(|event| event.label.map(String::from)).collect();
		Ok(labels)
	}

	#[test]
	fn a_visited_state_records_the_observable_events_it_offers() -> TestResult {
		let process = offering()?;
		let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };

		let labels = recorded(&process, FdrConfig::default(), settings, ENABLED_SET_SAMPLE)?;
		let offers = ["Offering.S0: {a, b}", "Offering.S1: {}", "Offering.S2: {c}", "Offering.S3: {}"];
		assert_eq!(labels, offers);
		Ok(())
	}

	#[test]
	fn a_trace_that_asks_for_no_enabled_set_records_none() -> TestResult {
		let process = offering()?;
		let settings = TbInstrumentationConfig { sample_enabled_sets: false, ..every_flag() };

		let labels = recorded(&process, FdrConfig::default(), settings, ENABLED_SET_SAMPLE)?;
		assert!(labels.is_empty(), "the trace asked for no enabled set, and recorded {labels:?}");
		Ok(())
	}

	#[test]
	fn a_visited_stable_state_records_its_refusal_set() -> TestResult {
		let process = offering()?;
		let settings = TbInstrumentationConfig { sample_refusals: true, ..Default::default() };

		let labels = recorded(&process, FdrConfig::default(), settings, REFUSAL_SNAPSHOT)?;
		let stable = ["Offering.S0: {c}", "Offering.S2: {a, b}", "Offering.S3: {a, b, c}"];
		assert_eq!(labels, stable, "`S1` enables the hidden `t`");
		Ok(())
	}

	#[test]
	fn an_accepting_state_records_every_observable_event_as_refused() -> TestResult {
		let process = accepting()?;
		let settings = TbInstrumentationConfig { sample_refusals: true, ..Default::default() };

		let labels = recorded(&process, FdrConfig::default(), settings, REFUSAL_SNAPSHOT)?;
		let refused = ["Accepting.Done: {a, b}", "Accepting.Idle: {a, b}"];
		assert_eq!(labels, refused, "the process can stop at `Idle` and at `Done`");
		Ok(())
	}

	#[test]
	fn a_trace_that_asks_for_no_refusals_records_none() -> TestResult {
		let process = offering()?;
		let settings = TbInstrumentationConfig { sample_refusals: false, ..every_flag() };

		let labels = recorded(&process, FdrConfig::default(), settings, REFUSAL_SNAPSHOT)?;
		assert!(labels.is_empty(), "the trace asked for no refusals, and recorded {labels:?}");
		Ok(())
	}

	#[test]
	fn a_state_where_a_seed_diverged_records_its_divergence() -> TestResult {
		let process = diverging()?;
		let settings = TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() };

		let labels = recorded(&process, FdrConfig::default(), settings, DIVERGENCE_DETECT)?;
		assert_eq!(labels, ["Diverging.S1: <t, u>"], "the diamond at `S3` closes no cycle");
		Ok(())
	}

	#[test]
	fn a_divergence_label_keeps_the_order_of_its_run() -> TestResult {
		let process = turning()?;
		let settings = TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() };

		let labels = recorded(&process, FdrConfig::default(), settings, DIVERGENCE_DETECT)?;
		assert_eq!(labels, ["Turning.S2: <u, t>"], "the run takes `u` first");
		Ok(())
	}

	#[test]
	fn a_trace_that_asks_for_no_divergence_records_none() -> TestResult {
		let process = diverging()?;
		let settings = TbInstrumentationConfig { divergence_heuristics: false, ..every_flag() };

		let labels = recorded(&process, FdrConfig::default(), settings, DIVERGENCE_DETECT)?;
		assert!(labels.is_empty(), "the trace asked for no divergence, and recorded {labels:?}");
		Ok(())
	}

	#[test]
	fn a_cycle_longer_than_the_hidden_run_bound_records_its_divergence() -> TestResult {
		let process = diverging()?;
		let config = FdrConfig { max_internal_run: 1, ..Default::default() };
		let settings = TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() };

		let labels = recorded(&process, config, settings, DIVERGENCE_DETECT)?;
		let divergence = ["Diverging.S1: <t, u>"];
		assert_eq!(labels, divergence, "the cycle of two hidden events needs no bound");
		Ok(())
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_run_records_the_states_of_the_spec_it_explores() -> TestResult {
		let subject = offering()?;
		let specs = vec![sending()?];
		let fault_model = Some(FaultModel::default());
		let config = FdrConfig { specs, fault_model, ..Default::default() };
		let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };

		let labels = recorded(&subject, config, settings, ENABLED_SET_SAMPLE)?;
		assert_eq!(labels, ["Sending.Idle: {send}", "Sending.Sent: {}"]);
		Ok(())
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_run_names_the_spec_of_each_state() -> TestResult {
		let subject = offering()?;
		let specs = vec![sending()?, receiving()?];
		let fault_model = Some(FaultModel::default());
		let config = FdrConfig { specs, fault_model, ..Default::default() };
		let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
		let sending = ["Sending.Idle: {send}", "Sending.Sent: {}"];
		let receiving = ["Receiving.Idle: {recv}", "Receiving.Sent: {}"];

		let labels = recorded(&subject, config, settings, ENABLED_SET_SAMPLE)?;
		let named = [sending, receiving].concat();
		assert_eq!(labels, named, "the two specs share the names of their states");
		Ok(())
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn an_exploration_event_the_trace_refuses_fails_the_exploration() -> TestResult {
		let process = offering()?;
		let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
		let refuse = || TightBeamError::ChannelClosed;
		let model = FaultModel::default().with_event_fault(ENABLED_SET_SAMPLE, refuse, crate::bps!(10000));
		let trace = trace_with(settings).with_fault_model(model);
		let mut explorer = DefaultFdrExplorer::with_defaults(&process, FdrConfig::default());

		let explored = explorer.explore_into(&trace);
		assert!(matches!(explored, Err(TightBeamError::ChannelClosed)));
		Ok(())
	}

	#[cfg(feature = "testing-fault")]
	#[test]
	fn a_fault_run_returns_the_error_of_a_refused_event() -> TestResult {
		let subject = offering()?;
		let specs = vec![sending()?];
		let fault_model = Some(FaultModel::default());
		let config = FdrConfig { specs, fault_model, ..Default::default() };
		let settings = TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() };
		let refuse = || TightBeamError::ChannelClosed;
		let model = FaultModel::default().with_event_fault(ENABLED_SET_SAMPLE, refuse, crate::bps!(10000));
		let trace = trace_with(settings).with_fault_model(model);
		let mut explorer = DefaultFdrExplorer::with_defaults(&subject, config);

		let explored = explorer.explore_into(&trace);
		assert!(matches!(explored, Err(TightBeamError::ChannelClosed)));
		Ok(())
	}
}

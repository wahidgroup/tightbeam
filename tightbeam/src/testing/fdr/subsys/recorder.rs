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
	use crate::testing::fixtures::{TestProcess, TestTrace};
	use crate::urn::Urn;

	#[cfg(feature = "testing-fault")]
	#[cfg(feature = "testing-fault")]
	use crate::testing::fdr::FaultModel;

	/// A process with stable states, an unstable state, and a terminal state.
	///
	/// `S0` offers `a` and `b`, and each leads to `S1`. The hidden `t` takes
	/// `S1` to `S2`, which offers `c`, and `c` leads to the terminal `S3`.
	fn offering() -> Process {
		TestProcess {
			observable: &["a", "b", "c"],
			hidden: &["t"],
			transitions: &[("S0", "a", "S1"), ("S0", "b", "S1"), ("S1", "t", "S2"), ("S2", "c", "S3")],
			terminal: &["S3"],
			..TestProcess::of("Offering", "S0")
		}
		.build()
	}

	/// A process with a hidden diamond and a hidden cycle.
	///
	/// `a` takes `S0` to both `S3` and `S1`, which exploration visits in that
	/// order. The hidden `t` takes `S3` to both `S4` and `S6`, and the hidden
	/// `v` takes each of them to `S7`, so two hidden runs meet at `S7` and
	/// close no cycle. The hidden `t` and `u` take `S1` to `S2` and back, so
	/// each seed diverges at `S1`.
	fn diverging() -> Process {
		TestProcess {
			observable: &["a", "b"],
			hidden: &["t", "u", "v"],
			transitions: &[
				("S0", "a", "S3"),
				("S0", "a", "S1"),
				("S1", "t", "S2"),
				("S2", "u", "S1"),
				("S2", "b", "S5"),
				("S3", "t", "S4"),
				("S3", "t", "S6"),
				("S4", "v", "S7"),
				("S6", "v", "S7"),
				("S7", "b", "S5"),
			],
			terminal: &["S5"],
			..TestProcess::of("Diverging", "S0")
		}
		.build()
	}

	/// A process whose `a` leads to `S2`, where the hidden `u` and `t` take it
	/// to `S1` and back, so the run of its divergence takes `u` before `t`.
	fn turning() -> Process {
		TestProcess {
			observable: &["a"],
			hidden: &["t", "u"],
			transitions: &[("S0", "a", "S2"), ("S2", "u", "S1"), ("S1", "t", "S2")],
			..TestProcess::of("Turning", "S0")
		}
		.build()
	}

	/// A specification that offers `send` at `Idle` and stops at `Sent`.
	#[cfg(feature = "testing-fault")]
	fn sending() -> Process {
		TestProcess::chain("Sending", &["Idle", "Sent"], &["send"])
	}

	/// A specification that offers `recv` at `Idle` and stops at `Sent`, so its
	/// states share their names with those of [`sending`].
	#[cfg(feature = "testing-fault")]
	fn receiving() -> Process {
		TestProcess::chain("Receiving", &["Idle", "Sent"], &["recv"])
	}

	/// The settings that ask for the enabled sets alone.
	fn enabled_sets() -> TbInstrumentationConfig {
		TbInstrumentationConfig { sample_enabled_sets: true, ..Default::default() }
	}

	/// The settings that ask for the refusal sets alone.
	fn refusals() -> TbInstrumentationConfig {
		TbInstrumentationConfig { sample_refusals: true, ..Default::default() }
	}

	/// The settings that ask for the divergences alone.
	fn divergences() -> TbInstrumentationConfig {
		TbInstrumentationConfig { divergence_heuristics: true, ..Default::default() }
	}

	/// The labels of the `urn` events that exploring `process` under `config`
	/// records into a trace with `settings`. The labels are the subject, so
	/// the verdict of the exploration goes unread.
	fn recorded(
		process: &Process,
		config: FdrConfig,
		settings: TbInstrumentationConfig,
		urn: Urn<'static>,
	) -> Vec<String> {
		let trace = TestTrace::with_config(settings);
		let mut explorer = DefaultFdrExplorer::with_defaults(process, config);
		explorer.explore_into(&trace).expect("the trace takes each exploration event");

		TestTrace::labels(&trace, urn).into_iter().flatten().collect()
	}

	// An exploration records the events its trace asks for: the offers of each
	// visited state, the refusals of each stable state, and the hidden run of
	// each divergence. A fault run records the states of the specs it
	// explores.
	crate::tb_cases! {
		fn an_exploration_records(
			(process, config, settings, urn, labels): (
				Process,
				FdrConfig,
				TbInstrumentationConfig,
				Urn<'static>,
				&[&str],
			)
		) {
			let recorded = recorded(&process, config, settings, urn);
			assert_eq!(recorded, labels);
		}

		cases {
			the_observable_events_each_visited_state_offers => (
				offering(),
				FdrConfig::default(),
				enabled_sets(),
				ENABLED_SET_SAMPLE,
				&["Offering.S0: {a, b}", "Offering.S1: {}", "Offering.S2: {c}", "Offering.S3: {}"],
			),
			/// `S1` enables the hidden `t`, so it is not stable.
			the_refusal_set_of_each_stable_state => (
				offering(),
				FdrConfig::default(),
				refusals(),
				REFUSAL_SNAPSHOT,
				&["Offering.S0: {c}", "Offering.S2: {a, b}", "Offering.S3: {a, b, c}"],
			),
			/// The process can stop at `Idle` and at `Done`.
			every_observable_event_as_refused_at_an_accepting_state => (
				TestProcess::accepting(),
				FdrConfig::default(),
				refusals(),
				REFUSAL_SNAPSHOT,
				&["Accepting.Done: {a, b}", "Accepting.Idle: {a, b}"],
			),
			/// The diamond at `S3` closes no cycle.
			the_divergence_of_the_state_where_a_seed_diverged => (
				diverging(),
				FdrConfig::default(),
				divergences(),
				DIVERGENCE_DETECT,
				&["Diverging.S1: <t, u>"],
			),
			/// The run takes `u` first.
			a_divergence_in_the_order_of_its_run => (
				turning(),
				FdrConfig::default(),
				divergences(),
				DIVERGENCE_DETECT,
				&["Turning.S2: <u, t>"],
			),
			/// The cycle of two hidden events needs no bound.
			the_divergence_of_a_cycle_longer_than_the_hidden_run_bound => (
				diverging(),
				FdrConfig { max_internal_run: 1, ..Default::default() },
				divergences(),
				DIVERGENCE_DETECT,
				&["Diverging.S1: <t, u>"],
			),
			#[cfg(feature = "testing-fault")]
			the_states_of_the_spec_a_fault_run_explores => (
				offering(),
				FdrConfig::under_faults([sending()]),
				enabled_sets(),
				ENABLED_SET_SAMPLE,
				&["Sending.Idle: {send}", "Sending.Sent: {}"],
			),
			/// The two specs share the names of their states.
			#[cfg(feature = "testing-fault")]
			the_spec_of_each_state_a_fault_run_explores => (
				offering(),
				FdrConfig::under_faults([sending(), receiving()]),
				enabled_sets(),
				ENABLED_SET_SAMPLE,
				&["Sending.Idle: {send}", "Sending.Sent: {}", "Receiving.Idle: {recv}", "Receiving.Sent: {}"],
			),
		}
	}

	// A trace that asks for every exploration event but one records none of
	// that one.
	crate::tb_cases! {
		fn a_trace_that_asks_for_no((process, settings, urn): (Process, TbInstrumentationConfig, Urn<'static>)) {
			let recorded = recorded(&process, FdrConfig::default(), settings, urn);
			assert!(recorded.is_empty());
		}

		cases {
			enabled_set_records_none => (
				offering(),
				TbInstrumentationConfig { sample_enabled_sets: false, ..TestTrace::every_flag() },
				ENABLED_SET_SAMPLE,
			),
			refusals_records_none => (
				offering(),
				TbInstrumentationConfig { sample_refusals: false, ..TestTrace::every_flag() },
				REFUSAL_SNAPSHOT,
			),
			divergence_records_none => (
				diverging(),
				TbInstrumentationConfig { divergence_heuristics: false, ..TestTrace::every_flag() },
				DIVERGENCE_DETECT,
			),
		}
	}

	// An exploration event that the trace refuses fails the exploration with
	// the error of the refusal, in a plain exploration and in a fault run.
	#[cfg(feature = "testing-fault")]
	crate::tb_cases! {
		fn an_exploration_event_the_trace_refuses_fails(config: FdrConfig) {
			let refuse = || TightBeamError::ChannelClosed;
			let model = FaultModel::default().with_event_fault(ENABLED_SET_SAMPLE, refuse, crate::bps!(10000));
			let trace = TestTrace::with_config(enabled_sets()).with_fault_model(model);
			let process = offering();
			let mut explorer = DefaultFdrExplorer::with_defaults(&process, config);

			let explored = explorer.explore_into(&trace);
			assert!(matches!(explored, Err(TightBeamError::ChannelClosed)));
		}

		cases {
			the_exploration => FdrConfig::default(),
			a_fault_run => FdrConfig::under_faults([sending()]),
		}
	}
}

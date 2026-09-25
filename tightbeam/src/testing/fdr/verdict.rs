//! Layer 3 verdict and the trace vocabulary it reports over
//!
//! Plain data, so every feature selection compiles it. The explorer that
//! fills a verdict is behind `testing-fdr`.

use std::collections::HashSet;

use crate::testing::specs::lts::{Event, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::InjectedFaultRecord;
#[cfg(feature = "testing-fmea")]
use crate::testing::fmea::FmeaReport;

/// CSP trace: sequence of observable events
pub type Trace = Vec<Event>;

/// Refusal set: events refused in stable state
pub type RefusalSet = HashSet<Event>;

/// Failure: (trace, refusal_set)
pub type Failure = (Trace, RefusalSet);

/// Acceptance set: events accepted after trace
pub type AcceptanceSet = HashSet<Event>;

/// What one Layer 3 assertion decided.
///
/// A check that ran out of budget gets its own value. Folding it into either
/// answer claims a proof that was not performed, or reports a defect with no
/// witness.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Decision {
	/// Not asked, or the subject cannot answer it.
	#[default]
	NotAsserted,

	/// Exploration completed and found no counterexample.
	Holds,

	/// Exploration found a counterexample, recorded in the matching witness.
	Refuted,

	/// Exploration stopped on a bound before either answer was established.
	Unknown,
}

impl Decision {
	/// How firmly this decision speaks, for [`Decision::and`].
	///
	/// An assertion that held does not make up for one never settled, and
	/// neither outranks a counterexample.
	fn rank(self) -> u8 {
		match self {
			Self::NotAsserted => 0,
			Self::Holds => 1,
			Self::Unknown => 2,
			Self::Refuted => 3,
		}
	}

	/// This decision taken with another over the same subject. Firmer wins.
	pub fn and(self, other: Self) -> Self {
		if other.rank() > self.rank() {
			return other;
		}

		self
	}

	/// This decision after a counterexample was found.
	///
	/// An assertion never made stays unmade, so the witness is kept without a
	/// claim being made.
	pub fn refute(self) -> Self {
		match self {
			Self::NotAsserted => Self::NotAsserted,
			_ => Self::Refuted,
		}
	}
}

/// FDR verification verdict
///
/// One [`Decision`] per assertion. [`FdrVerdict::outcome`] is the one place
/// they are read together.
#[derive(Debug, Clone, PartialEq)]
pub struct FdrVerdict {
	/// Divergence freedom: no infinite τ-loops detected
	pub divergence_free: Decision,

	/// Deadlock freedom: no unexpected STOP states
	///
	/// Not asserted under fault injection, which measures what the faults
	/// cause. [`FdrVerdict::deadlock_witness`] still records it.
	pub deadlock_free: Decision,

	/// Schedulability: every configured spec's task set meets its deadlines
	///
	/// A spec declaring no schedulability block has no task set. An analysis
	/// error refutes: every `SchedulabilityError` names a defect in the
	/// declared task set.
	pub schedulable: Decision,

	/// Determinism: structural proof that the LTS is deterministic
	///
	/// No hidden actions and no multi-target `(state, event)` transition, a
	/// sufficient condition (Roscoe 2010, §10.5). Not an assertion, so
	/// [`FdrVerdict::outcome`] does not read it.
	pub is_deterministic: bool,

	/// Trace refinement: traces(Impl) ⊆ traces(Spec)
	///
	/// Asserted whenever the configuration names a spec. The one refinement a
	/// recorded execution can answer.
	pub trace_refines: Decision,

	/// Failures refinement: failures(Impl) ⊆ failures(Spec)
	///
	/// Asserted only of a subject whose refusals are known.
	pub failures_refines: Decision,

	/// Divergence refinement: divergences(Impl) ⊆ divergences(Spec)
	///
	/// Asserted under the same condition as [`FdrVerdict::failures_refines`].
	pub divergence_refines: Decision,

	/// Witness to trace refinement violation: trace in Impl but not in Spec
	pub trace_refinement_witness: Option<Trace>,

	/// Witness to failures refinement violation: (trace, refusal) in Impl but not in Spec
	pub failures_refinement_witness: Option<Failure>,

	/// Witness to divergence refinement violation: divergent trace in Impl but not in Spec
	pub divergence_refinement_witness: Option<Trace>,

	/// Witness to structural nondeterminism: first `(state, event)` with a
	/// hidden action or multiple transition targets (sorted state order,
	/// reproducible)
	pub determinism_witness: Option<(State, Event)>,

	/// Witness to divergence: (seed, τ-loop sequence) if found
	pub divergence_witness: Option<(u64, Vec<Event>)>,

	/// Witness to deadlock: (seed, trace, state) if found
	pub deadlock_witness: Option<(u64, Trace, State)>,

	/// Events the subject can perform that no configured spec models
	///
	/// Projected away before refinement rather than counted against it, so
	/// this is coverage and [`FdrVerdict::outcome`] does not read it.
	pub unmodelled_events: Vec<Event>,

	/// Traces explored across all seeds
	pub traces_explored: usize,

	/// Distinct states visited
	pub states_visited: usize,

	/// Number of seeds successfully completed
	pub seeds_completed: u32,

	/// Seed that caused failure, if any
	pub failing_seed: Option<u64>,

	/// Number of exploration branches pruned for timing violations
	///
	/// Non-zero means model-level timing violations exist even though the
	/// surviving paths passed.
	pub timing_pruned: usize,

	/// Faults that were injected during exploration
	#[cfg(feature = "testing-fault")]
	pub faults_injected: Vec<InjectedFaultRecord>,

	/// Seeds that completed (reached exhaustion or terminal states)
	/// despite at least one injected fault suppressing a transition
	#[cfg(feature = "testing-fault")]
	pub error_recovery_successful: usize,

	/// Seeds that deadlocked or diverged after at least one injected
	/// fault suppressed a transition
	#[cfg(feature = "testing-fault")]
	pub error_recovery_failed: usize,

	/// FMEA report
	#[cfg(feature = "testing-fmea")]
	pub fmea_report: Option<FmeaReport>,
}

impl FdrVerdict {
	/// Every assertion this verdict carries.
	///
	/// No rest pattern, so a new field does not compile until it is
	/// classified.
	fn assertions(&self) -> [Decision; 6] {
		let Self {
			divergence_free,
			deadlock_free,
			trace_refines,
			failures_refines,
			divergence_refines,
			schedulable,

			// Not assertions: a modeling choice, the witnesses, and counts.
			is_deterministic: _,
			trace_refinement_witness: _,
			failures_refinement_witness: _,
			divergence_refinement_witness: _,
			determinism_witness: _,
			divergence_witness: _,
			deadlock_witness: _,
			unmodelled_events: _,
			traces_explored: _,
			states_visited: _,
			seeds_completed: _,
			failing_seed: _,
			timing_pruned: _,

			#[cfg(feature = "testing-fault")]
				faults_injected: _,
			#[cfg(feature = "testing-fault")]
				error_recovery_successful: _,
			#[cfg(feature = "testing-fault")]
				error_recovery_failed: _,
			#[cfg(feature = "testing-fmea")]
				fmea_report: _,
		} = self;

		[
			*divergence_free,
			*deadlock_free,
			*trace_refines,
			*failures_refines,
			*divergence_refines,
			*schedulable,
		]
	}

	/// This verdict carrying what a second pass decided about refinement.
	///
	/// A scenario naming both a CSP process and FDR specs explores twice. No
	/// rest pattern, so a new field does not compile until it is given a side.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn with_refinement_from(mut self, refinement: Self) -> Self {
		let Self {
			// The refinement pass ran with a spec list to refine against.
			trace_refines,
			failures_refines,
			divergence_refines,
			trace_refinement_witness,
			failures_refinement_witness,
			divergence_refinement_witness,
			unmodelled_events,
			schedulable,

			// This verdict's own pass explored the CSP process. The refinement
			// pass saw one recorded path, not the model.
			divergence_free: _,
			deadlock_free: _,
			is_deterministic: _,
			divergence_witness: _,
			deadlock_witness: _,
			determinism_witness: _,
			traces_explored: _,
			states_visited: _,
			seeds_completed: _,
			failing_seed: _,
			timing_pruned: _,

			#[cfg(feature = "testing-fault")]
				faults_injected: _,
			#[cfg(feature = "testing-fault")]
				error_recovery_successful: _,
			#[cfg(feature = "testing-fault")]
				error_recovery_failed: _,
			#[cfg(feature = "testing-fmea")]
				fmea_report: _,
		} = refinement;

		self.trace_refines = trace_refines;
		self.failures_refines = failures_refines;
		self.divergence_refines = divergence_refines;
		self.trace_refinement_witness = trace_refinement_witness;
		self.failures_refinement_witness = failures_refinement_witness;
		self.divergence_refinement_witness = divergence_refinement_witness;
		self.unmodelled_events = unmodelled_events;
		self.schedulable = schedulable;

		self
	}

	/// What Layer 3 decided, over every assertion it made.
	///
	/// Combined by [`Decision::and`], so the firmest one wins.
	pub fn outcome(&self) -> Decision {
		self.assertions().into_iter().fold(Decision::NotAsserted, Decision::and)
	}
}

impl Default for FdrVerdict {
	fn default() -> Self {
		Self {
			divergence_free: Decision::NotAsserted,
			deadlock_free: Decision::NotAsserted,
			schedulable: Decision::NotAsserted,
			is_deterministic: true,
			trace_refines: Decision::NotAsserted,
			failures_refines: Decision::NotAsserted,
			divergence_refines: Decision::NotAsserted,
			trace_refinement_witness: None,
			failures_refinement_witness: None,
			divergence_refinement_witness: None,
			unmodelled_events: Vec::new(),
			determinism_witness: None,
			divergence_witness: None,
			deadlock_witness: None,
			traces_explored: 0,
			states_visited: 0,
			seeds_completed: 0,
			failing_seed: None,
			timing_pruned: 0,
			#[cfg(feature = "testing-fault")]
			faults_injected: Vec::new(),
			#[cfg(feature = "testing-fault")]
			error_recovery_successful: 0,
			#[cfg(feature = "testing-fault")]
			error_recovery_failed: 0,
			#[cfg(feature = "testing-fmea")]
			fmea_report: None,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn verdict_default_asserts_nothing() {
		let verdict = FdrVerdict::default();
		assert_eq!(verdict.outcome(), Decision::NotAsserted);
		assert_eq!(verdict.divergence_free, Decision::NotAsserted);
		assert_eq!(verdict.deadlock_free, Decision::NotAsserted);
		assert!(verdict.is_deterministic);
		assert_eq!(verdict.traces_explored, 0);
		assert_eq!(verdict.states_visited, 0);
	}

	#[test]
	fn a_refutation_outranks_an_undecided_check() {
		let verdict = FdrVerdict {
			trace_refines: Decision::Unknown,
			deadlock_free: Decision::Refuted,
			..Default::default()
		};
		assert_eq!(verdict.outcome(), Decision::Refuted);
	}

	#[test]
	fn an_undecided_check_outranks_the_assertions_that_held() {
		let verdict = FdrVerdict {
			trace_refines: Decision::Holds,
			failures_refines: Decision::Unknown,
			..Default::default()
		};
		assert_eq!(verdict.outcome(), Decision::Unknown);
	}

	#[test]
	fn verdict_tracks_witnesses() {
		let trace = vec![Event("unexpected")];
		let verdict = FdrVerdict { trace_refinement_witness: Some(trace.clone()), ..Default::default() };
		assert_eq!(verdict.trace_refinement_witness, Some(trace));
	}
}

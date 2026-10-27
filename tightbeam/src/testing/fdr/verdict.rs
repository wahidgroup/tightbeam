//! The Layer 3 verdict and the trace vocabulary that it reports over.
//!
//! The module holds plain data, so every feature selection compiles it. The
//! explorer that fills a verdict needs `testing-fdr`.

use std::collections::HashSet;

use crate::testing::specs::lts::{Event, State};

#[cfg(feature = "testing-fault")]
use crate::testing::fdr::config::InjectedFaultRecord;
#[cfg(feature = "testing-fdr")]
use crate::testing::fdr::explorer::SeedResult;
#[cfg(feature = "testing-fmea")]
use crate::testing::fmea::FmeaReport;

/// A CSP trace, the sequence of observable events of one run.
pub type Trace = Vec<Event>;

/// A refusal set, the observable events that a process refuses at a stable
/// or accepting state.
pub type RefusalSet = HashSet<Event>;

/// A failure, a trace with the refusal set of the process after it.
pub type Failure = (Trace, RefusalSet);

/// An acceptance set, the events that a process accepts after a trace.
pub type AcceptanceSet = HashSet<Event>;

/// What one Layer 3 assertion decided.
///
/// A check that ran out of budget gets its own value. Either answer in its
/// place would claim a proof that the check never finished, or report a
/// defect with no witness.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Decision {
	/// The run left the assertion out, or the subject cannot answer it.
	#[default]
	NotAsserted,

	/// The check completed, and everything it searched satisfied the
	/// assertion.
	Holds,

	/// The check found a counterexample, which the witness of the assertion
	/// records.
	Refuted,

	/// The check stopped at a bound before it established either answer.
	Unknown,
}

impl Decision {
	/// How firmly this decision speaks, for [`Decision::and`].
	///
	/// An assertion never settled outranks one that held, and a counterexample
	/// outranks both.
	fn rank(self) -> u8 {
		match self {
			Self::NotAsserted => 0,
			Self::Holds => 1,
			Self::Unknown => 2,
			Self::Refuted => 3,
		}
	}

	/// This decision taken with `other` over the same subject, where the
	/// firmer of the two wins.
	pub fn and(self, other: Self) -> Self {
		if other.rank() > self.rank() {
			return other;
		}

		self
	}

	/// This decision after the check found a counterexample.
	///
	/// An assertion never made stays unmade, so the verdict keeps the witness
	/// and makes no claim.
	pub fn refute(self) -> Self {
		match self {
			Self::NotAsserted => Self::NotAsserted,
			_ => Self::Refuted,
		}
	}
}

/// The verdict of an FDR verification.
///
/// The verdict holds one [`Decision`] per assertion, and
/// [`FdrVerdict::outcome`] is the one place that reads them together.
#[derive(Debug, Clone, PartialEq)]
pub struct FdrVerdict {
	/// Divergence freedom, the absence of an infinite τ-loop.
	///
	/// A seed refutes it at a visited state from which a run of hidden events
	/// reaches a cycle of hidden events, or at a run of more than
	/// `max_internal_run` hidden events.
	pub divergence_free: Decision,

	/// Deadlock freedom, the absence of an unexpected STOP state.
	///
	/// A run under fault injection leaves it unasserted, because that run
	/// measures what the faults cause. Such a run records a deadlock in
	/// [`FdrVerdict::deadlock_witness`] alone.
	pub deadlock_free: Decision,

	/// Schedulability, which holds when the task set of every configured spec
	/// meets its deadlines.
	///
	/// A spec with no schedulability block has no task set, so it counts as
	/// schedulable. An analysis error refutes, because every
	/// `SchedulabilityError` names a defect in the declared task set.
	pub schedulable: Decision,

	/// Whether a structural proof shows that the LTS is deterministic.
	///
	/// The proof checks a sufficient condition (Roscoe 2010, §10.5): no hidden
	/// action and no `(state, event)` pair with more than one target. The field
	/// records a modeling choice, which [`FdrVerdict::outcome`] leaves out.
	pub is_deterministic: bool,

	/// Trace refinement, traces(Impl) ⊆ traces(Spec).
	///
	/// A run asserts it whenever the configuration names a spec and no fault
	/// model, and it is the one refinement that a recorded execution can
	/// answer.
	pub trace_refines: Decision,

	/// Failures refinement, failures(Impl) ⊆ failures(Spec).
	///
	/// A run that asserts trace refinement asserts this too, but only of a
	/// subject whose refusals are known.
	pub failures_refines: Decision,

	/// Divergence refinement, divergences(Impl) ⊆ divergences(Spec).
	///
	/// A run asserts it under the same condition as
	/// [`FdrVerdict::failures_refines`].
	pub divergence_refines: Decision,

	/// The witness of a trace refinement violation, a trace of Impl that Spec
	/// lacks.
	pub trace_refinement_witness: Option<Trace>,

	/// The witness of a failures refinement violation, a trace and refusal set
	/// of Impl that Spec does not allow.
	pub failures_refinement_witness: Option<Failure>,

	/// The witness of a divergence refinement violation, a divergent trace of
	/// Impl that Spec lacks.
	pub divergence_refinement_witness: Option<Trace>,

	/// The witness of structural nondeterminism, the first `(state, event)`
	/// pair with a hidden action or more than one target, in sorted state
	/// order, so the witness repeats from run to run.
	pub determinism_witness: Option<(State, Event)>,

	/// The witness of a divergence, the seed and the hidden events of the run
	/// that diverges, when a seed diverged.
	pub divergence_witness: Option<(u64, Vec<Event>)>,

	/// The witness of a deadlock, the seed, the trace, and the state, when a
	/// seed deadlocked.
	pub deadlock_witness: Option<(u64, Trace, State)>,

	/// The events that the subject can perform and no configured spec models.
	///
	/// Refinement projects them away before it compares the traces, so they
	/// measure coverage, and [`FdrVerdict::outcome`] leaves them out.
	pub unmodelled_events: Vec<Event>,

	/// The number of traces that the seeds explored.
	pub traces_explored: usize,

	/// The number of distinct states in the runs that this verdict judges.
	///
	/// A run under a fault model judges the configured specs, so it counts the
	/// distinct states of each spec. A run with no spec counts the states of
	/// the subject.
	pub states_visited: usize,

	/// The number of seeds that ran to their end with neither a deadlock nor a
	/// divergence.
	pub seeds_completed: u32,

	/// The seed of the last deadlock or divergence that the run recorded, if
	/// any.
	pub failing_seed: Option<u64>,

	/// The number of exploration branches pruned for timing violations.
	///
	/// A count above zero means the model holds a timing violation, even when
	/// every path that exploration kept passed.
	pub timing_pruned: usize,

	/// The faults that exploration injected.
	#[cfg(feature = "testing-fault")]
	pub faults_injected: Vec<InjectedFaultRecord>,

	/// The number of seeds that ran to their end, to exhaustion or a terminal
	/// state, after at least one injected fault suppressed a transition.
	#[cfg(feature = "testing-fault")]
	pub error_recovery_successful: usize,

	/// The number of seeds that deadlocked or diverged after at least one
	/// injected fault suppressed a transition.
	#[cfg(feature = "testing-fault")]
	pub error_recovery_failed: usize,

	/// The FMEA report, when the FMEA configuration sets `auto_generate` and
	/// the run injected a fault.
	#[cfg(feature = "testing-fmea")]
	pub fmea_report: Option<FmeaReport>,
}

impl FdrVerdict {
	/// Every assertion this verdict carries.
	///
	/// The pattern names every field, so a new field breaks the build until
	/// the pattern classifies it.
	fn assertions(&self) -> [Decision; 6] {
		let Self {
			divergence_free,
			deadlock_free,
			trace_refines,
			failures_refines,
			divergence_refines,
			schedulable,

			// A modeling choice, the witnesses, and the counts are not
			// assertions.
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

	/// Records `witness`, the first witness against structural determinism,
	/// and that the process is deterministic when there is none.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn record_determinism(&mut self, witness: Option<(State, Event)>) {
		self.is_deterministic = witness.is_none();
		self.determinism_witness = witness;
	}

	/// This verdict with what a second pass decided about refinement.
	///
	/// A scenario that names both a CSP process and FDR specs explores twice.
	/// The pattern names every field, so a new field breaks the build until
	/// the pattern gives it a side.
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

	/// Adds the result of `seed` to this verdict.
	///
	/// A seed that injected a fault feeds the error-recovery counters, which
	/// FMEA detection ratings divide.
	#[cfg(feature = "testing-fdr")]
	pub(crate) fn add_seed(&mut self, seed: u64, result: &SeedResult) {
		match result {
			#[cfg(feature = "testing-fault")]
			SeedResult::Divergence(_trace, _state, hidden, faults) => {
				self.divergence_free = self.divergence_free.refute();
				self.divergence_witness = Some((seed, hidden.clone()));
				self.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.error_recovery_failed += 1;
				}
				self.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Divergence(_trace, _state, hidden) => {
				self.divergence_free = self.divergence_free.refute();
				self.divergence_witness = Some((seed, hidden.clone()));
				self.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Deadlock(trace, state, faults) => {
				self.deadlock_free = self.deadlock_free.refute();
				self.deadlock_witness = Some((seed, trace.clone(), *state));
				self.failing_seed = Some(seed);
				if !faults.is_empty() {
					self.error_recovery_failed += 1;
				}
				self.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Deadlock(trace, state) => {
				self.deadlock_free = self.deadlock_free.refute();
				self.deadlock_witness = Some((seed, trace.clone(), *state));
				self.failing_seed = Some(seed);
			}
			#[cfg(feature = "testing-fault")]
			SeedResult::Success(_trace, _failures, faults) => {
				self.seeds_completed += 1;
				if !faults.is_empty() {
					self.error_recovery_successful += 1;
				}
				self.faults_injected.extend(faults.clone());
			}
			#[cfg(not(feature = "testing-fault"))]
			SeedResult::Success(..) => {
				self.seeds_completed += 1;
			}
		}
	}

	/// What Layer 3 decided, over every assertion it made.
	///
	/// [`Decision::and`] combines the assertions, so the firmest one wins.
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

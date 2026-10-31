//! The refusal replies to gossip and peer-ad control frames.
//!
//! [`Refusal`] binds one inbound frame to the audit of its request, so the
//! reply and its record name the same frame.

use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::runtime::{LoopFault, VerifiedSignerId};
use crate::colony::cluster::ClusterError;
use crate::colony::protocol::{GossipResponse, GossipWant, PeerAdvertisementResponse, ReplyForm};
use crate::crypto::sign::VerifiedSignature;
use crate::instrumentation::events::{CLUSTER_GOSSIP_REFUSED, CLUSTER_PEER_ADVERTISE_REFUSED};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

/// One inbound control frame, the audit of its request, and the signer that
/// the frame's verification proved.
#[derive(Clone, Copy)]
pub(crate) struct Refusal<'f> {
	frame: &'f Frame,
	audit: &'f RequestAudit,
	/// The signer whose signature verified on the frame's plane, or `None`
	/// for a refusal before the verification passed. A record names this
	/// signer alone, so it never names a party that the frame only claims
	/// (CWE-345). A named signer puts the record on the audit trace.
	signer: Option<&'f VerifiedSignerId>,
}

impl<'f> Refusal<'f> {
	/// Binds a refusal of `frame` to `audit`. The refusal names no signer until
	/// [`Self::by`] names the verified one.
	pub(crate) fn to(frame: &'f Frame, audit: &'f RequestAudit) -> Self {
		Self { frame, audit, signer: None }
	}

	/// Names `signer`, whose signature verified on the frame's plane, as the
	/// party behind this refusal.
	pub(crate) fn by(self, signer: &'f VerifiedSignerId) -> Self {
		Self { signer: Some(signer), ..self }
	}

	/// Answers a gossip rumor with `status`.
	pub(crate) fn gossip(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.gossip_for(Cause::status(status))
	}

	/// Answers a gossip rumor with the status of `cause`, and records the
	/// refusal under its label.
	fn gossip_for(self, cause: Cause) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip(cause)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), GossipResponse { status: cause.status })
	}

	/// Answers a gossip rumor after the gateway scores its relay, a step that
	/// may itself fault.
	///
	/// A poisoned registry is this gateway's fault, so the reply carries
	/// [`TransitStatus::Unavailable`] in place of `status`, the verdict on
	/// the rumor itself.
	pub(crate) fn gossip_scored(
		self,
		scored: Result<(), LoopFault>,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		match scored {
			Ok(()) => self.gossip(status),
			Err(fault) => self.gossip_fault(fault),
		}
	}

	/// Answers a gossip rumor with the status that the settlement of its
	/// refusal returned.
	///
	/// A settlement that faulted is this gateway's fault, so it answers as
	/// [`Self::gossip_fault`] does.
	pub(crate) fn gossip_settled(
		self,
		settled: Result<TransitStatus, LoopFault>,
	) -> Result<Option<Frame>, TightBeamError> {
		match settled {
			Ok(status) => self.gossip(status),
			Err(fault) => self.gossip_fault(fault),
		}
	}

	/// Answers a gossip rumor that met `fault`.
	///
	/// - A local fault answers as [`Self::gossip_error`] does, by the split of [`LoopFault::local`].
	/// - A runtime fault, such as the trace's own refusal, propagates unchanged.
	pub(crate) fn gossip_fault(self, fault: LoopFault) -> Result<Option<Frame>, TightBeamError> {
		let error = fault.local()?;
		self.gossip_error(&error)
	}

	/// Answers a gossip rumor that met `error`, a fault of this gateway's own,
	/// with [`TransitStatus::Unavailable`] in place of a verdict on the rumor.
	///
	/// - The fault is a poisoned or failed registry, table, journal, or rate
	///   admission, or a failed local step, such as the build or the signature
	///   of a rumor.
	/// - The record of the refusal names the fault by its [`ClusterError::unavailable_label`].
	pub(crate) fn gossip_error(self, error: &ClusterError) -> Result<Option<Frame>, TightBeamError> {
		self.gossip_for(Cause::fault(error))
	}

	/// Answers a reconcile request with an empty want set and an empty
	/// peer-exchange sample.
	///
	/// The reply carries no status, so `status` names the cause of the
	/// refusal on its trace event alone.
	pub(crate) fn reconcile(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.reconcile_for(Cause::status(status))
	}

	/// Answers a reconcile request that met `error`, a fault of this
	/// gateway's own, as [`Self::reconcile`] answers it with
	/// [`TransitStatus::Unavailable`]. The record names the fault by its
	/// [`ClusterError::unavailable_label`].
	pub(crate) fn reconcile_fault(self, error: &ClusterError) -> Result<Option<Frame>, TightBeamError> {
		self.reconcile_for(Cause::fault(error))
	}

	/// Answers a reconcile request as [`Self::reconcile`] does, and records
	/// the refusal for `cause`.
	fn reconcile_for(self, cause: Cause) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip(cause)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), GossipWant { want: Vec::new(), pex: Vec::new() })
	}

	/// Answers a peer advertisement with `status`.
	pub(crate) fn peer_ad(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.peer_ad_for(Cause::status(status))
	}

	/// Answers a peer advertisement with the status of `cause`, and records
	/// the refusal under its label.
	fn peer_ad_for(self, cause: Cause) -> Result<Option<Frame>, TightBeamError> {
		let Cause { label, status } = cause;
		let trace = self.trace();
		trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ADVERTISE_REFUSED, label, status, None)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), PeerAdvertisementResponse { status })
	}

	/// Answers a peer advertisement with `status` and frees the freshness slot
	/// its verified `signature` spent.
	///
	/// A refused advertisement leaves the routes as they are. Releasing its
	/// signature keeps the peer's one admission for a frame this gateway
	/// accepts, where a hold would spend it on a refusal (CWE-645).
	pub(crate) fn peer_ad_release(
		self,
		replay_guard: &GatewayReplayGuard,
		signature: &VerifiedSignature,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		replay_guard.release(signature);
		self.peer_ad(status)
	}

	/// Answers a peer advertisement that met `error`, a fault of this
	/// gateway's own, with [`TransitStatus::Unavailable`], and frees the
	/// freshness slot its verified `signature` spent, as
	/// [`Self::peer_ad_release`] does.
	///
	/// The record names the fault by its [`ClusterError::unavailable_label`].
	pub(crate) fn peer_ad_fault_release(
		self,
		replay_guard: &GatewayReplayGuard,
		signature: &VerifiedSignature,
		error: &ClusterError,
	) -> Result<Option<Frame>, TightBeamError> {
		replay_guard.release(signature);
		self.peer_ad_for(Cause::fault(error))
	}

	/// The trace that the record of this refusal goes on.
	fn trace(&self) -> &'f TraceCollector {
		self.audit.signed(self.signer)
	}

	/// Records the refusal for `cause`, attributed to the verified signer when
	/// the refusal names one.
	fn trace_gossip(self, cause: Cause) -> Result<(), TightBeamError> {
		let Cause { label, status } = cause;
		let signer = self.signer.map(|signer| signer.as_shared().as_ref());
		let trace = self.trace();
		trace.emit_event_with_value_and_evidence(CLUSTER_GOSSIP_REFUSED, label, status, signer)
	}
}

/// What a refusal answers and what its record names: the status of the reply
/// and the label of the record, which the two constructors pair.
#[derive(Clone, Copy)]
struct Cause {
	/// The label of the record of the refusal.
	label: &'static str,
	/// The status that the reply carries.
	status: TransitStatus,
}

impl Cause {
	/// The cause of a refusal with `status`, whose record takes the name of
	/// that status.
	fn status(status: TransitStatus) -> Self {
		Self { label: status.as_str(), status }
	}

	/// The cause of a refusal that `error`, a fault of this gateway's own,
	/// draws: the reply answers [`TransitStatus::Unavailable`], and the record
	/// names the fault by its [`ClusterError::unavailable_label`].
	fn fault(error: &ClusterError) -> Self {
		Self { label: error.unavailable_label(), status: TransitStatus::Unavailable }
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use super::*;
	use crate::testing::{SetupEnv, TestRumor};
	use crate::{exactly, tb_assert_spec, tb_scenario};

	tb_assert_spec! {
		pub GossipAndPeerAdRefusalSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
				(CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
			]
		}
	}

	// A refusal records the status its reply carries, so a spec can tell one
	// refusal from another.
	tb_scenario! {
		name: a_refusal_records_the_status_it_answers_with,
		spec: GossipAndPeerAdRefusalSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let frame = TestRumor::fixed();
				let audit = RequestAudit::proven(&Arc::new(trace));
				Refusal::to(&frame, &audit).gossip(TransitStatus::ResourceExhausted)?;
				Refusal::to(&frame, &audit).peer_ad(TransitStatus::PermissionDenied)?;
				Ok(())
			}
		}
	}

	tb_assert_spec! {
		pub ReconcileRefusalSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(CLUSTER_GOSSIP_REFUSED, exactly!(1), equals!(TransitStatus::InvalidArgument))
			]
		}
	}

	// A refused reconcile round answers no status, so its event alone names
	// the cause.
	tb_scenario! {
		name: a_reconcile_refusal_records_its_cause,
		spec: ReconcileRefusalSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| {
				let frame = TestRumor::fixed();
				let audit = RequestAudit::proven(&Arc::new(trace));
				Refusal::to(&frame, &audit).reconcile(TransitStatus::InvalidArgument)?;
				Ok(())
			}
		}
	}

	/// The records of a refusal, read from a collector that records the digest
	/// of each payload.
	#[cfg(feature = "instrument")]
	mod audit {
		use super::*;
		use crate::tb_cases;
		use crate::testing::fixtures::TestTrace;
		use crate::testing::TestResult;

		/// A refusal of a frame whose signature has not verified names no
		/// signer, though the frame names one, so the trail never names a
		/// party that the frame only claims (CWE-345).
		#[test]
		fn an_unverified_refusal_names_no_signer() -> TestResult {
			let trace = Arc::new(TestTrace::with_payloads());
			let frame = TestRumor::fixed();
			Refusal::to(&frame, &RequestAudit::proven(&trace)).gossip(TransitStatus::PermissionDenied)?;
			assert_eq!(TestTrace::payloads(&trace, CLUSTER_GOSSIP_REFUSED), [None]);
			Ok(())
		}

		/// One refusal of a fault of the gateway's own.
		type Refuse = fn(Refusal<'_>) -> Result<Option<Frame>, TightBeamError>;

		// The gateway refuses a rumor or a reconcile round that meets a fault
		// of its own and names the fault in the record, so the trail tells a
		// failed journal from a failed rate admission (CWE-778).
		tb_cases! {
			fn a_fault_refusal_names_the_fault((refuse, label): (Refuse, &str)) -> TestResult {
				let trace = Arc::new(TraceCollector::default());
				let frame = TestRumor::fixed();
				refuse(Refusal::to(&frame, &RequestAudit::proven(&trace)))?;
				assert_eq!(TestTrace::labels(&trace, CLUSTER_GOSSIP_REFUSED), [Some(String::from(label))]);
				Ok(())
			}
			cases {
				gossip_journal => (
					|refusal| refusal.gossip_fault(LoopFault::Registry(ClusterError::GossipJournalUnavailable)),
					"Unavailable/gossip-journal-unavailable",
				),
				reconcile_lock => (
					|refusal| refusal.reconcile_fault(&ClusterError::LockPoisoned),
					"Unavailable/lock-poisoned",
				),
			}
		}
	}
}

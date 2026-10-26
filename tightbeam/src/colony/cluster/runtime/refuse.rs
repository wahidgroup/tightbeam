//! The refusal replies to gossip and peer-ad control frames.
//!
//! A refusal answers one inbound frame and records it against the same
//! collector that saw the frame arrive. [`Refusal`] holds that pair, so
//! the reply and its trace event always name the same frame.

use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::runtime::{LoopFault, VerifiedSignerId};
use crate::colony::protocol::{GossipResponse, GossipWant, PeerAdvertisementResponse, ReplyForm};
use crate::crypto::sign::VerifiedSignature;
use crate::instrumentation::events::{CLUSTER_GOSSIP_REFUSED, CLUSTER_PEER_ADVERTISE_REFUSED};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

/// One inbound control frame, the collector that saw it arrive, and the
/// signer that the frame's verification proved.
#[derive(Clone, Copy)]
pub(crate) struct Refusal<'f> {
	frame: &'f Frame,
	trace: &'f TraceCollector,
	/// The signer whose signature verified on the frame's plane, or `None`
	/// for a refusal before the verification passed. A record names this
	/// signer alone, so it never names a party that the frame only claims
	/// (CWE-345).
	signer: Option<&'f VerifiedSignerId>,
}

impl<'f> Refusal<'f> {
	/// Binds a refusal of `frame` to the collector that saw it arrive. The
	/// refusal names no signer until [`Self::by`] names the verified one.
	pub(crate) fn to(frame: &'f Frame, trace: &'f TraceCollector) -> Self {
		Self { frame, trace, signer: None }
	}

	/// Names `signer`, whose signature verified on the frame's plane, as the
	/// party that the record of this refusal names.
	pub(crate) fn by(self, signer: &'f VerifiedSignerId) -> Self {
		Self { signer: Some(signer), ..self }
	}

	/// Answers a gossip rumor with `status`.
	pub(crate) fn gossip(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip(status)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), GossipResponse { status })
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

	/// Answers a gossip rumor that met a fault of this gateway's own.
	///
	/// A poisoned registry, table, or journal is this gateway's fault, so it
	/// answers [`TransitStatus::Unavailable`] in place of a verdict on the
	/// rumor. A runtime fault, such as the trace's own refusal, propagates
	/// unchanged.
	pub(crate) fn gossip_fault(self, fault: LoopFault) -> Result<Option<Frame>, TightBeamError> {
		match fault {
			LoopFault::Registry(_) => self.gossip(TransitStatus::Unavailable),
			LoopFault::Runtime(error) => Err(error),
		}
	}

	/// Answers a reconcile request with an empty want set and an empty
	/// peer-exchange sample.
	///
	/// The reply carries no status, so `status` names the cause of the
	/// refusal on its trace event alone.
	pub(crate) fn reconcile(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip(status)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), GossipWant { want: Vec::new(), pex: Vec::new() })
	}

	/// Answers a peer advertisement with `status`.
	pub(crate) fn peer_ad(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		let trace = self.trace;
		trace.emit_event_with_value_and_evidence(CLUSTER_PEER_ADVERTISE_REFUSED, status.as_str(), status, None)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), PeerAdvertisementResponse { status })
	}

	/// Answers a peer advertisement with `status` and frees the freshness slot
	/// its verified `signature` spent.
	///
	/// A refused advertisement leaves the routes as they are. A release of its
	/// signature keeps the peer's one admission for a frame this gateway
	/// accepts, and a hold would spend that admission on a refusal (CWE-645).
	pub(crate) fn peer_ad_release(
		self,
		replay_guard: &GatewayReplayGuard,
		signature: &VerifiedSignature,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		replay_guard.release(signature);
		self.peer_ad(status)
	}

	/// Records the refusal with its `status`, attributed to the verified
	/// signer when the refusal names one.
	fn trace_gossip(self, status: TransitStatus) -> Result<(), TightBeamError> {
		let signer = self.signer.map(|signer| signer.as_shared().as_ref());
		let trace = self.trace;
		trace.emit_event_with_value_and_evidence(CLUSTER_GOSSIP_REFUSED, status.as_str(), status, signer)
	}
}

#[cfg(test)]
mod tests {
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
				let frame = TestRumor::application(1_000, [1, 2, 3]);
				Refusal::to(&frame, &trace).gossip(TransitStatus::ResourceExhausted)?;
				Refusal::to(&frame, &trace).peer_ad(TransitStatus::PermissionDenied)?;
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
				let frame = TestRumor::application(1_000, [1, 2, 3]);
				Refusal::to(&frame, &trace).reconcile(TransitStatus::InvalidArgument)?;
				Ok(())
			}
		}
	}

	/// The records of a refusal, read from a collector that records the digest
	/// of each payload.
	#[cfg(feature = "instrument")]
	mod audit {
		use super::*;
		use crate::instrumentation::TbInstrumentationConfig;
		use crate::trace::TraceConfig;

		/// A trace whose sink keeps the digest of each payload.
		fn payload_trace() -> TraceCollector {
			let config = TbInstrumentationConfig { enable_payloads: true, ..TbInstrumentationConfig::default() };
			TraceCollector::from(TraceConfig::with_instrumentation(config))
		}

		/// The digest of the payload of each [`CLUSTER_GOSSIP_REFUSED`] that
		/// `trace` holds.
		fn refused_payloads(trace: &TraceCollector) -> Vec<Option<[u8; 32]>> {
			let recorded = trace.drain_events().into_iter();
			let refused = recorded.filter(|record| record.urn == CLUSTER_GOSSIP_REFUSED);
			refused.map(|record| record.payload_hash).collect()
		}

		// A refusal of a frame whose signature has not verified names no
		// signer, though the frame names one, so the trail never names a
		// party that the frame only claims (CWE-345).
		#[test]
		fn an_unverified_refusal_names_no_signer() -> Result<(), TightBeamError> {
			let trace = payload_trace();
			let frame = TestRumor::application(1_000, [1, 2, 3]);
			Refusal::to(&frame, &trace).gossip(TransitStatus::PermissionDenied)?;
			assert_eq!(refused_payloads(&trace), [None]);
			Ok(())
		}
	}
}

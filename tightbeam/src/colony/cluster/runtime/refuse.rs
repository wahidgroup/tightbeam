//! The refusal replies to gossip and peer-ad control frames.
//!
//! A refusal answers one inbound frame and records it against the same
//! collector that saw the frame arrive. [`Refusal`] holds that pair, so
//! the reply and its trace event always name the same frame.

use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::runtime::LoopFault;
use crate::colony::protocol::{GossipResponse, GossipWant, PeerAdvertisementResponse, ReplyForm};
use crate::crypto::sign::VerifiedSignature;
use crate::instrumentation::events::{CLUSTER_GOSSIP_REFUSED, CLUSTER_PEER_ADVERTISE_REFUSED};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

/// One inbound control frame and the collector that saw it arrive.
#[derive(Clone, Copy)]
pub(crate) struct Refusal<'f> {
	frame: &'f Frame,
	trace: &'f TraceCollector,
}

impl<'f> Refusal<'f> {
	/// Binds a refusal of `frame` to the collector that saw it arrive.
	pub(crate) fn to(frame: &'f Frame, trace: &'f TraceCollector) -> Self {
		Self { frame, trace }
	}

	/// Answers a gossip rumor with `status`.
	pub(crate) fn gossip(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip()?;
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

	/// Answers a gossip rumor whose handling hit a fault of this gateway's.
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
	pub(crate) fn reconcile(self) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip()?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), GossipWant { want: Vec::new(), pex: Vec::new() })
	}

	/// Answers a peer advertisement with `status`.
	pub(crate) fn peer_ad(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace.event(CLUSTER_PEER_ADVERTISE_REFUSED)?;
		ReplyForm::Plain.reply(self.frame.metadata().id(), PeerAdvertisementResponse { status })
	}

	/// Answers a peer advertisement with `status` and frees the freshness slot
	/// its verified `signature` spent.
	///
	/// A refused advertisement did not apply. A release of its signature keeps
	/// the peer's one admission for a frame this gateway accepts, and a hold
	/// would spend that admission on a refusal (CWE-645).
	pub(crate) fn peer_ad_release(
		self,
		replay_guard: &GatewayReplayGuard,
		signature: &VerifiedSignature,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		replay_guard.release(signature);
		self.peer_ad(status)
	}

	/// Records the refusal, attributed to the frame's signer when the frame
	/// is signed.
	fn trace_gossip(self) -> Result<(), TightBeamError> {
		let event = self.trace.event(CLUSTER_GOSSIP_REFUSED)?;
		match self.frame.signer_id() {
			Some(signer) => event.with_payload(&signer).emit(),
			None => event.emit(),
		}

		Ok(())
	}
}

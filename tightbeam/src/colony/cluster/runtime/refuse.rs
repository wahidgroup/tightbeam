//! Refusal replies for gossip and peer-ad control frames.
//!
//! A refusal answers one inbound frame and records it against the same
//! collector that saw the frame arrive. [`Refusal`] holds that pair, so
//! a reply cannot be minted for one frame while the refusal is traced
//! against another.

use crate::colony::cluster::runtime::freshness::GatewayReplayGuard;
use crate::colony::cluster::signer_attribution;
use crate::colony::common::{reply_frame, GossipResponse, GossipWant, PeerAdvertisementResponse};
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
	/// Refuses `frame`, tracing against `trace`.
	pub(crate) fn to(frame: &'f Frame, trace: &'f TraceCollector) -> Self {
		Self { frame, trace }
	}

	/// Answers a gossip rumor with `status`.
	pub(crate) fn gossip(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip()?;
		reply_frame(&self.frame.metadata.id, GossipResponse { status })
	}

	/// Answers a reconcile request with an empty want set.
	pub(crate) fn reconcile(self) -> Result<Option<Frame>, TightBeamError> {
		self.trace_gossip()?;
		reply_frame(&self.frame.metadata.id, GossipWant { want: Vec::new(), pex: Vec::new() })
	}

	/// Answers a peer advertisement with `status`.
	pub(crate) fn peer_ad(self, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace.event(CLUSTER_PEER_ADVERTISE_REFUSED)?;
		reply_frame(&self.frame.metadata.id, PeerAdvertisementResponse { status })
	}

	/// Answers a peer advertisement and returns its freshness slot.
	///
	/// A refused advertisement never applied, so holding its signature
	/// would spend the peer's one admission on a frame this gateway
	/// declined (CWE-645).
	pub(crate) fn peer_ad_release(
		self,
		replay_guard: &GatewayReplayGuard,
		status: TransitStatus,
	) -> Result<Option<Frame>, TightBeamError> {
		replay_guard.release(self.frame);
		self.peer_ad(status)
	}

	/// Records the refusal, attributed to the frame's signer when signed.
	fn trace_gossip(self) -> Result<(), TightBeamError> {
		let event = self.trace.event(CLUSTER_GOSSIP_REFUSED)?;
		match signer_attribution(self.frame) {
			Some(signer) => event.with_payload(&signer).emit(),
			None => event.emit(),
		}

		Ok(())
	}
}

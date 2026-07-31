//! Shared refuse replies for gossip and peer-ad control frames.

use crate::colony::cluster::signer_attribution;
use crate::colony::common::{reply_frame, GossipResponse, GossipWant, PeerAdvertisementResponse};
use crate::instrumentation::events::{CLUSTER_GOSSIP_REFUSED, CLUSTER_PEER_ADVERTISE_REFUSED};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;

pub(crate) fn gossip_refused_event(frame: &Frame, trace: &TraceCollector) {
	if let Ok(event) = trace.event(CLUSTER_GOSSIP_REFUSED) {
		match signer_attribution(frame) {
			Some(signer) => event.with_payload(&signer).emit(),
			None => event.emit(),
		}
	}
}

pub(crate) fn refuse_gossip(
	frame: &Frame,
	trace: &TraceCollector,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	gossip_refused_event(frame, trace);
	reply_frame(&frame.metadata.id, GossipResponse { status })
}

pub(crate) fn refuse_reconcile(frame: &Frame, trace: &TraceCollector) -> Result<Option<Frame>, TightBeamError> {
	gossip_refused_event(frame, trace);
	reply_frame(&frame.metadata.id, GossipWant { want: Vec::new() })
}

pub(crate) fn refuse_peer_ad(
	frame: &Frame,
	trace: &TraceCollector,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	let _ = trace.event(CLUSTER_PEER_ADVERTISE_REFUSED);
	reply_frame(&frame.metadata.id, PeerAdvertisementResponse { status })
}

#[cfg(feature = "x509")]
pub(crate) fn refuse_peer_ad_release(
	frame: &Frame,
	trace: &TraceCollector,
	replay_guard: &ReplayGuard,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	if let Some(signer_info) = frame.nonrepudiation.as_ref() {
		replay_guard.forget(signer_info.signature.as_bytes());
	}

	refuse_peer_ad(frame, trace, status)
}

#[cfg(not(feature = "x509"))]
pub(crate) fn refuse_peer_ad_release(
	frame: &Frame,
	trace: &TraceCollector,
	_replay_guard: &(),
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	refuse_peer_ad(frame, trace, status)
}

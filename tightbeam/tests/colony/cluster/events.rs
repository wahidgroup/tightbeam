//! Client-side cluster scenario event markers.
//!
//! Facts the gateway cannot observe (the client reached its send, a probe
//! fired). Gateway decisions are asserted through the built-in `tightbeam`
//! events the cluster fires on the scenario trace.

use tightbeam::utils::urn::Urn;

pub(crate) const REGISTRATION_SENT: Urn<'static> = Urn::new("test", "event:cluster/registration-sent");
pub(crate) const REJECTED_HEARTBEAT_DECODED: Urn<'static> =
	Urn::new("test", "event:cluster/rejected-heartbeat-decoded");
pub(crate) const SERVLET_STOPPED: Urn<'static> = Urn::new("test", "event:cluster/servlet-stopped");
pub(crate) const WORK_SENT: Urn<'static> = Urn::new("test", "event:cluster/work-sent");
pub(crate) const WORK_ECHOED: Urn<'static> = Urn::new("test", "event:cluster/work-echoed");
pub(crate) const BALANCER_OFFERED: Urn<'static> = Urn::new("test", "event:cluster/balancer-offered");
pub(crate) const TOPOLOGY_REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-register-status");
pub(crate) const TOPOLOGY_ADD_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-add-status");
pub(crate) const TOPOLOGY_ROUTE_STATUS: Urn<'static> = Urn::new("test", "event:cluster/topology-route-status");
pub(crate) const MULTI_REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/multi-register-status");
pub(crate) const PEER_ADVERTISE_SENT: Urn<'static> = Urn::new("test", "event:cluster/peer-advertise-sent");
pub(crate) const PEER_AD_STATUS: Urn<'static> = Urn::new("test", "event:cluster/peer-ad-status");
pub(crate) const PEER_ROUTES_AFTER: Urn<'static> = Urn::new("test", "event:cluster/peer-routes-after");
pub(crate) const PEER_ROUTES_AFTER_INSTALLS: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-installs");
pub(crate) const PEER_ROUTES_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-routes-after-withdrawal");
pub(crate) const PEER_PING_LIVE_AFTER_WITHDRAWAL: Urn<'static> =
	Urn::new("test", "event:cluster/peer-ping-live-after-withdrawal");
pub(crate) const GOSSIP_PUBLISH_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-publish-status");
pub(crate) const GOSSIP_CONVERGED: Urn<'static> = Urn::new("test", "event:cluster/gossip-converged");
pub(crate) const GOSSIP_CLAMP_LEAKED: Urn<'static> = Urn::new("test", "event:cluster/gossip-clamp-leaked");
pub(crate) const WORK_STATUS: Urn<'static> = Urn::new("test", "event:cluster/work-status");
pub(crate) const WORK_PAYLOAD: Urn<'static> = Urn::new("test", "event:cluster/work-payload");
pub(crate) const REGISTER_STATUS: Urn<'static> = Urn::new("test", "event:cluster/register-status");
pub(crate) const REGISTRY_HIVES: Urn<'static> = Urn::new("test", "event:cluster/registry-hives");
pub(crate) const REGISTER_ASSIGNED_ID: Urn<'static> = Urn::new("test", "event:cluster/register-assigned-id");
pub(crate) const REGISTRY_EMPTIED: Urn<'static> = Urn::new("test", "event:cluster/registry-emptied");
pub(crate) const LOCAL_SERVLETS_AFTER_INSTALLS: Urn<'static> =
	Urn::new("test", "event:cluster/local-servlets-after-installs");
pub(crate) const PEER_ROUTE_EXPOSED: Urn<'static> = Urn::new("test", "event:cluster/peer-route-exposed");
pub(crate) const PEER_SLATE_MATCHES: Urn<'static> = Urn::new("test", "event:cluster/peer-slate-matches");
pub(crate) const PEER_PING_TYPE_LEARNED: Urn<'static> = Urn::new("test", "event:cluster/peer-ping-type-learned");
pub(crate) const BALANCER_SPREAD: Urn<'static> = Urn::new("test", "event:cluster/balancer-spread");
pub(crate) const GOSSIP_PENDING_BEFORE_REGISTER: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-pending-before-register");
pub(crate) const JOURNAL_RECORDS: Urn<'static> = Urn::new("test", "event:cluster/journal-records");
pub(crate) const JOURNAL_ACKS: Urn<'static> = Urn::new("test", "event:cluster/journal-acks");
pub(crate) const GOSSIP_LIMITED_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-limited-status");
pub(crate) const GOSSIP_RELAY_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-relay-status");
pub(crate) const GOSSIP_ROUTES_AFTER_SCORING: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-routes-after-scoring");
pub(crate) const GOSSIP_GREY_HOLE_CONTAINED: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-grey-hole-contained");
pub(crate) const GOSSIP_RECONCILE_MEMBER_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-member-want");
pub(crate) const GOSSIP_RECONCILE_FOREIGN_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-foreign-want");
pub(crate) const GOSSIP_RECONCILE_STRANGER_WANT: Urn<'static> =
	Urn::new("test", "event:cluster/gossip-reconcile-stranger-want");
pub(crate) const GOSSIP_REPLAY_STATUS: Urn<'static> = Urn::new("test", "event:cluster/gossip-replay-status");
pub(crate) const GOSSIP_HELD_NO_INGRESS: Urn<'static> = Urn::new("test", "event:cluster/gossip-held-no-ingress");
pub(crate) const GOSSIP_PENDING_NO_INGRESS: Urn<'static> = Urn::new("test", "event:cluster/gossip-pending-no-ingress");
pub(crate) const PEER_TABLE_FLOOD_ADMITTED: Urn<'static> = Urn::new("test", "event:cluster/peer-table-flood-admitted");
pub(crate) const PEER_TABLE_ANCHOR_RETAINED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-table-anchor-retained");
pub(crate) const PEER_TABLE_TARGETS_BOUNDED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-table-targets-bounded");
pub(crate) const PEER_PROBE_HINTS_ADMITTED: Urn<'static> = Urn::new("test", "event:cluster/peer-probe-hints-admitted");
pub(crate) const PEER_PROBE_MEMBER_PROMOTED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-probe-member-promoted");
pub(crate) const PEER_PROBE_FOREIGN_REFUSED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-probe-foreign-refused");
pub(crate) const PEER_HINT_LEARNED_ON_REFUSE: Urn<'static> =
	Urn::new("test", "event:cluster/peer-hint-learned-on-refuse");
pub(crate) const PEER_ABUSE_CANDIDATE_DISCARDED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-abuse-candidate-discarded");
pub(crate) const PEER_EVICT_MEMBER_PROMOTED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-evict-member-promoted");
pub(crate) const PEER_EVICT_TARGET_DROPPED: Urn<'static> = Urn::new("test", "event:cluster/peer-evict-target-dropped");
pub(crate) const PEER_LOCAL_FAULT_MEMBER_PROMOTED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-local-fault-member-promoted");
pub(crate) const PEER_LOCAL_FAULT_MEMBER_RETAINED: Urn<'static> =
	Urn::new("test", "event:cluster/peer-local-fault-member-retained");
pub(crate) const STREAM_SERVLET_HANDLED: Urn<'static> = Urn::new("test", "event:cluster/stream-servlet-handled");
pub(crate) const STREAM_ECHOED: Urn<'static> = Urn::new("test", "event:cluster/stream-echoed");
pub(crate) const DUPLEX_SERVLET_HANDLED: Urn<'static> = Urn::new("test", "event:cluster/duplex-servlet-handled");
pub(crate) const DUPLEX_ECHOED: Urn<'static> = Urn::new("test", "event:cluster/duplex-echoed");
pub(crate) const DUPLEX_LIVE_BEFORE_CANCEL: Urn<'static> = Urn::new("test", "event:cluster/duplex-live-before-cancel");
pub(crate) const DUPLEX_CANCEL_PROPAGATED: Urn<'static> = Urn::new("test", "event:cluster/duplex-cancel-propagated");
pub(crate) const SERVLET_DUPLEX_CANCELLED: Urn<'static> = Urn::new("test", "event:cluster/servlet-duplex-cancelled");

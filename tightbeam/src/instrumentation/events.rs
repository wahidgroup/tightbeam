//! Event URN constants for tightbeam instrumentation events.
//!
//! The single system-wide inventory assigns one URN per emit site or event
//! kind. Domain-scoped NSS segments keep identities from colliding across
//! subsystems.
//!
//! # Format
//!
//! `urn:tightbeam:event:<domain>/<event-name>`
//!
//! # Organization
//!
//! Short section headers group related constants by plane. Names are
//! self-explanatory; section blocks do not restate each symbol.

use crate::utils::urn::Urn;

pub const TIGHTBEAM_NID: &str = "tightbeam";

// Core lifecycle events
pub const START: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:core/start");
pub const END: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:core/end");
pub const WARN: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:core/warn");
pub const ERROR: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:core/error");

// Trace clock origin events
pub const TRACE_CLOCK_ORIGIN: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:trace/clock-origin");

// Gate events
pub const GATE_ACCEPT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:gate/accept");
pub const GATE_REJECT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:gate/reject");

// Transport events
pub const REQUEST_RECV: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:transport/request-recv");
pub const RESPONSE_SEND: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:transport/response-send");

// Connection lifecycle events
pub const CONNECTION_ACCEPTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:connection/accepted");
pub const CONNECTION_CLOSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:connection/closed");
pub const CONNECTION_STALE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:connection/stale");
pub const CONNECTION_RECONNECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:connection/reconnected");

// Assertion events
pub const ASSERT_LABEL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:assert/label");
pub const ASSERT_PAYLOAD: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:assert/payload");

// Handler events
pub const HANDLER_ENTER: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:handler/enter");
pub const HANDLER_EXIT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:handler/exit");

// Processing events
pub const CRYPTO_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:crypto/step");
pub const COMPRESS_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:compress/step");
pub const ROUTE_STEP: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:route/step");
pub const POLICY_EVAL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:policy/eval");

// Process events
pub const PROCESS_TRANSITION: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:process/transition");
pub const PROCESS_HIDDEN: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:process/hidden");

// FDR/exploration events
pub const SEED_START: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/seed-start");
pub const SEED_END: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/seed-end");
pub const STATE_EXPAND: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/state-expand");
pub const STATE_PRUNE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/state-prune");
pub const DIVERGENCE_DETECT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/divergence-detect");
pub const REFUSAL_SNAPSHOT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/refusal-snapshot");
pub const ENABLED_SET_SAMPLE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fdr/enabled-set-sample");

// Timing events
pub const TIMING_WCET: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:timing/wcet");
pub const TIMING_DEADLINE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:timing/deadline");
pub const TIMING_JITTER: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:timing/jitter");
pub const TIMING_SLACK: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:timing/slack");

// Fault events
pub const FAULT_INJECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fault/injected");
pub const FAULT_RECOVERED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fault/recovered");
pub const FAULT_DETECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:fault/detected");

// Schedulability events
pub const TASK_RELEASE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:task/release");
pub const TASK_COMPLETE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:task/complete");
pub const TASK_MISSED_DEADLINE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:task/missed-deadline");

// Scheduler events
pub const SCHEDULER_ALLOCATE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:scheduler/allocate");
pub const SCHEDULER_RELEASE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:scheduler/release");
pub const SCHEDULER_BLOCKED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:scheduler/blocked");

// Mux control-plane events
pub const MUX_EMIT_DRAINING: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/emit-draining");
pub const MUX_GOAWAY_SENT: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/goaway-sent");
pub const MUX_GOAWAY_RECV: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/goaway-recv");
pub const MUX_CANCEL_BUDGET: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/cancel-budget");
pub const MUX_PROTOCOL_ERROR: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/protocol-error");
pub const MUX_INTERNAL_ERROR: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/internal-error");
pub const MUX_STREAMS_EXHAUSTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/streams-exhausted");
pub const MUX_OPEN_DRAINING: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/open-draining");
pub const MUX_REKEY_REQUESTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/rekey-requested");
pub const MUX_REKEY_RENEWED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/rekey-renewed");
pub const MUX_REKEY_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/rekey-refused");
pub const MUX_REKEY_RECEIPT_ISSUED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/rekey-receipt-issued");
pub const MUX_REKEY_RECEIPT_COUNTERSIGNED: Urn<'static> =
	Urn::new(TIGHTBEAM_NID, "event:mux/rekey-receipt-countersigned");
pub const MUX_REKEY_VERIFY_FAILED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:mux/rekey-verify-failed");

// Connection-pool lifecycle events
pub const POOL_DIAL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/dial");
pub const POOL_REUSE_MUX: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/reuse-mux");
pub const POOL_REUSE_READY: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/reuse-ready");
pub const POOL_MUX_DECLINED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/mux-declined");
pub const POOL_EVICTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/evicted");
pub const POOL_PRUNED_IDLE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/pruned-idle");
pub const POOL_FAILOVER: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/failover");
pub const POOL_EXHAUSTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/exhausted");
pub const POOL_RELEASED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:pool/released");

// Session/handshake receipt lifecycle events
pub const SESSION_HANDSHAKE_COMPLETE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:session/handshake-complete");
pub const SESSION_RECEIPT_SETTLED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:session/receipt-settled");
pub const SESSION_RECEIPT_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:session/receipt-refused");
pub const SESSION_CERT_REJECTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:session/cert-rejected");

// Hive lifecycle events
pub const HIVE_REREGISTERED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:hive/reregistered");

// Cluster gateway events
pub const CLUSTER_GATE_BLOCKED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gate-blocked");
pub const CLUSTER_HIVE_REGISTERED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/hive-registered");
pub const CLUSTER_REGISTER_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/register-refused");
pub const CLUSTER_UPDATE_ACCEPTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/update-accepted");
pub const CLUSTER_UPDATE_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/update-refused");
pub const CLUSTER_WORK_ROUTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/work-routed");
pub const CLUSTER_WORK_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/work-refused");
pub const CLUSTER_WORK_UNAVAILABLE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/work-unavailable");
pub const CLUSTER_WORK_FAILED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/work-failed");
pub const CLUSTER_WORK_FORWARDED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/work-forwarded");
pub const CLUSTER_HIVE_EVICTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/hive-evicted");

// Cluster export events
pub const CLUSTER_EXPORT_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/export-refused");
pub const CLUSTER_EXPORT_GRANTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/export-granted");
pub const CLUSTER_EXPORT_UNBOUNDED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/export-unbounded");
pub const CLUSTER_EXPORT_IDENTITY_UNAVAILABLE: Urn<'static> =
	Urn::new(TIGHTBEAM_NID, "event:cluster/export-identity-unavailable");

// Cluster peer advertisement events
pub const CLUSTER_PEER_ADVERTISED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/peer-advertised");
pub const CLUSTER_PEER_AD_LEARNED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/peer-ad-learned");
pub const CLUSTER_PEER_AD_DROPPED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/peer-ad-dropped");
pub const CLUSTER_PEER_AD_PUBLISH_FAILED: Urn<'static> =
	Urn::new(TIGHTBEAM_NID, "event:cluster/peer-ad-publish-failed");
pub const CLUSTER_PEER_DISCOVERED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/peer-discovered");
pub const CLUSTER_PEER_EVICTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/peer-evicted");
pub const CLUSTER_PEER_ADVERTISE_REFUSED: Urn<'static> =
	Urn::new(TIGHTBEAM_NID, "event:cluster/peer-advertise-refused");

// Cluster relay events
pub const CLUSTER_RELAY_TRAIL_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/relay-trail-refused");
pub const CLUSTER_RELAY_TRAIL_PRUNED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/relay-trail-pruned");

// Cluster gossip events
pub const CLUSTER_GOSSIP_ACCEPTED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gossip-accepted");
pub const CLUSTER_GOSSIP_DUPLICATE: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gossip-duplicate");
pub const CLUSTER_GOSSIP_REFUSED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gossip-refused");
pub const CLUSTER_GOSSIP_RELAY_WEAKENED: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gossip-relay-weakened");
pub const CLUSTER_GOSSIP_DROP_SIGNAL: Urn<'static> = Urn::new(TIGHTBEAM_NID, "event:cluster/gossip-drop-signal");

//! Each constant here names one tightbeam instrumentation event by its URN.
//!
//! The single system-wide inventory assigns one URN per emit site or event
//! kind. Domain-scoped NSS segments keep identities distinct across
//! subsystems.
//!
//! # Format
//!
//! `urn:tightbeam:event:<domain>/<event-name>`
//!
//! # Organization
//!
//! Short section headers group related constants by plane. Each constant
//! name states its event, so a section header names the plane alone.

use crate::urn::Urn;

pub const TIGHTBEAM_NID: &str = "tightbeam";

// Core lifecycle events
pub const START: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:core/start");
pub const END: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:core/end");
pub const WARN: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:core/warn");
pub const ERROR: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:core/error");

// Trace clock origin events
pub const TRACE_CLOCK_ORIGIN: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:trace/clock-origin");

// Gate events
pub const GATE_ACCEPT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:gate/accept");
pub const GATE_REJECT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:gate/reject");

// Transport events
pub const REQUEST_RECV: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/request-recv");
pub const RESPONSE_SEND: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/response-send");

// Connection lifecycle events
pub const CONNECTION_ACCEPTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:connection/accepted");
pub const CONNECTION_CLOSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:connection/closed");
pub const CONNECTION_STALE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:connection/stale");
pub const CONNECTION_RECONNECTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:connection/reconnected");

// Assertion events
pub const ASSERT_LABEL: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:assert/label");
pub const ASSERT_PAYLOAD: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:assert/payload");

// Handler events
/// Marks the entry into the application handler of one call that a
/// collector gate admitted, on a connection that an async or a blocking
/// `server!`, a servlet, a hive, or a gateway serves. The connection's audit
/// trail records it, with the label `handler_enter`, when its config sets
/// [`enable_internal_detail`].
///
/// - A call that runs to its end closes at [`HANDLER_EXIT`].
/// - A call that the peer cancels on a mux stream closes at [`MUX_STREAM_CANCELLED`].
///
/// ```
/// use tightbeam::instrumentation::events::HANDLER_ENTER;
///
/// assert_eq!(HANDLER_ENTER.to_string(), "urn:tightbeam:event:handler/enter");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const HANDLER_ENTER: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:handler/enter");
/// Marks the exit from the application handler of one call that a collector
/// gate admitted, whatever the handler returned, on a connection that an async
/// or a blocking `server!`, a servlet, a hive, or a gateway serves. The
/// connection's audit trail records it, with the label `handler_exit`, when
/// its config sets [`enable_internal_detail`].
///
/// - The exit closes each call that runs to its end.
/// - A call that the peer cancels on a mux stream closes at [`MUX_STREAM_CANCELLED`] in place of its exit.
/// - A call that a shutdown aborts ends at its [`HANDLER_ENTER`].
///
/// ```
/// use tightbeam::instrumentation::events::HANDLER_EXIT;
///
/// assert_eq!(HANDLER_EXIT.to_string(), "urn:tightbeam:event:handler/exit");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const HANDLER_EXIT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:handler/exit");

// Processing events
/// Marks a frame body that a servlet decrypted for typed delivery. The decrypt
/// also inflates a body that the sender compressed before encryption. The
/// servlet's trace records it, with the label `crypto_step`, when its config
/// sets [`enable_internal_detail`].
///
/// ```
/// use tightbeam::instrumentation::events::CRYPTO_STEP;
///
/// assert_eq!(CRYPTO_STEP.to_string(), "urn:tightbeam:event:crypto/step");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const CRYPTO_STEP: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:crypto/step");
/// Marks a compressed cleartext frame body that a servlet inflated for typed
/// delivery. The servlet's trace records it, with the label `compress_step`,
/// when its config sets [`enable_internal_detail`].
///
/// ```
/// use tightbeam::instrumentation::events::COMPRESS_STEP;
///
/// assert_eq!(COMPRESS_STEP.to_string(), "urn:tightbeam:event:compress/step");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const COMPRESS_STEP: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:compress/step");
/// Marks one peer stream that the mux responder routes to the dispatch method
/// of its kind. The connection's audit trail records it, with the label
/// `route_step`, when its config sets [`enable_internal_detail`].
///
/// ```
/// use tightbeam::instrumentation::events::ROUTE_STEP;
///
/// assert_eq!(ROUTE_STEP.to_string(), "urn:tightbeam:event:route/step");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const ROUTE_STEP: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:route/step");
/// Marks the evaluation of one inbound call by a collector gate, ahead of the
/// [`GATE_ACCEPT`] or [`GATE_REJECT`] of its verdict. The connection's audit
/// trail records it, with the label `policy_eval`, when its config sets
/// [`enable_internal_detail`].
///
/// ```
/// use tightbeam::instrumentation::events::POLICY_EVAL;
///
/// assert_eq!(POLICY_EVAL.to_string(), "urn:tightbeam:event:policy/eval");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const POLICY_EVAL: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:policy/eval");

// Process events
pub const PROCESS_TRANSITION: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:process/transition");
pub const PROCESS_HIDDEN: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:process/hidden");

// FDR/exploration events
pub const SEED_START: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/seed-start");
pub const SEED_END: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/seed-end");
pub const STATE_EXPAND: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/state-expand");
pub const STATE_PRUNE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/state-prune");
/// Marks a state where a seed of FDR exploration diverged: a run of hidden
/// events from it reaches a cycle of hidden events, or passes
/// `max_internal_run`.
///
/// - The label names the process, the state, and the hidden events of the run
///   in CSPM notation, such as `Spin.S1: <t, u>`.
/// - An exploration records it where the config of its trace sets [`divergence_heuristics`].
///
/// ```
/// use tightbeam::instrumentation::events::DIVERGENCE_DETECT;
///
/// assert_eq!(DIVERGENCE_DETECT.to_string(), "urn:tightbeam:event:fdr/divergence-detect");
/// ```
///
/// [`divergence_heuristics`]: super::TbInstrumentationConfig::divergence_heuristics
pub const DIVERGENCE_DETECT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/divergence-detect");
/// Marks the refusal set of one stable or accepting state of an FDR
/// exploration, as the CSP failures model defines it. The label names the
/// process, the state, and the set in CSPM notation, such as
/// `Spin.S2: {a, b}`.
///
/// - A stable state enables no hidden event, and refuses each observable event it does not offer.
/// - A process that can terminate at an accepting state refuses every observable event there.
/// - An exploration records the event where the config of its trace sets [`sample_refusals`].
///
/// ```
/// use tightbeam::instrumentation::events::REFUSAL_SNAPSHOT;
///
/// assert_eq!(REFUSAL_SNAPSHOT.to_string(), "urn:tightbeam:event:fdr/refusal-snapshot");
/// ```
///
/// [`sample_refusals`]: super::TbInstrumentationConfig::sample_refusals
pub const REFUSAL_SNAPSHOT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/refusal-snapshot");
/// Marks the observable events that one state of an FDR exploration offers.
/// The label names the process, the state, and the set in CSPM notation, such
/// as `Spin.S0: {a, b}`. An exploration records it where the config of its
/// trace sets [`sample_enabled_sets`].
///
/// ```
/// use tightbeam::instrumentation::events::ENABLED_SET_SAMPLE;
///
/// assert_eq!(ENABLED_SET_SAMPLE.to_string(), "urn:tightbeam:event:fdr/enabled-set-sample");
/// ```
///
/// [`sample_enabled_sets`]: super::TbInstrumentationConfig::sample_enabled_sets
pub const ENABLED_SET_SAMPLE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fdr/enabled-set-sample");

// Timing events
pub const TIMING_WCET: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:timing/wcet");
pub const TIMING_DEADLINE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:timing/deadline");
pub const TIMING_JITTER: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:timing/jitter");
pub const TIMING_SLACK: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:timing/slack");

// Fault events
pub const FAULT_INJECTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fault/injected");
pub const FAULT_RECOVERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fault/recovered");
pub const FAULT_DETECTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:fault/detected");

// Schedulability events
pub const TASK_RELEASE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:task/release");
pub const TASK_COMPLETE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:task/complete");
pub const TASK_MISSED_DEADLINE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:task/missed-deadline");

// Scheduler events
pub const SCHEDULER_ALLOCATE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:scheduler/allocate");
pub const SCHEDULER_RELEASE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:scheduler/release");
pub const SCHEDULER_BLOCKED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:scheduler/blocked");

// Mux control-plane events
pub const MUX_EMIT_DRAINING: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/emit-draining");
pub const MUX_GOAWAY_SENT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/goaway-sent");
pub const MUX_GOAWAY_RECV: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/goaway-recv");
pub const MUX_CANCEL_BUDGET: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/cancel-budget");
/// Marks a peer cancel that the mux responder honours with an abort of the
/// stream's handler, so the call ends here in place of its [`HANDLER_EXIT`].
/// The connection's audit trail records it, and each one draws on the cancel
/// budget of the connection.
///
/// ```
/// use tightbeam::instrumentation::events::MUX_STREAM_CANCELLED;
///
/// assert_eq!(MUX_STREAM_CANCELLED.to_string(), "urn:tightbeam:event:mux/stream-cancelled");
/// ```
pub const MUX_STREAM_CANCELLED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/stream-cancelled");
pub const MUX_PROTOCOL_ERROR: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/protocol-error");
pub const MUX_INTERNAL_ERROR: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/internal-error");
pub const MUX_STREAMS_EXHAUSTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/streams-exhausted");
pub const MUX_OPEN_DRAINING: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/open-draining");
pub const MUX_REKEY_REQUESTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-requested");
pub const MUX_REKEY_RENEWED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-renewed");
pub const MUX_REKEY_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-refused");
pub const MUX_REKEY_RECEIPT_ISSUED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-receipt-issued");
pub const MUX_REKEY_RECEIPT_COUNTERSIGNED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-receipt-countersigned");
pub const MUX_REKEY_VERIFY_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-verify-failed");

// Connection-pool lifecycle events
pub const POOL_DIAL: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/dial");
pub const POOL_REUSE_MUX: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/reuse-mux");
pub const POOL_REUSE_READY: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/reuse-ready");
pub const POOL_MUX_DECLINED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/mux-declined");
pub const POOL_EVICTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/evicted");
pub const POOL_PRUNED_IDLE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/pruned-idle");
pub const POOL_FAILOVER: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/failover");
pub const POOL_EXHAUSTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/exhausted");
pub const POOL_RELEASED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/released");

// Session/handshake receipt lifecycle events
pub const SESSION_HANDSHAKE_COMPLETE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/handshake-complete");
pub const SESSION_RECEIPT_SETTLED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/receipt-settled");
pub const SESSION_RECEIPT_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/receipt-refused");
pub const SESSION_CERT_REJECTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/cert-rejected");

// Hive lifecycle events
pub const HIVE_REREGISTERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:hive/reregistered");

// Cluster gateway events
pub const CLUSTER_GATE_BLOCKED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gate-blocked");
pub const CLUSTER_HIVE_REGISTERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/hive-registered");
pub const CLUSTER_REGISTER_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/register-refused");
pub const CLUSTER_UPDATE_ACCEPTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/update-accepted");
pub const CLUSTER_UPDATE_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/update-refused");
pub const CLUSTER_WORK_ROUTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-routed");
pub const CLUSTER_WORK_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-refused");
pub const CLUSTER_WORK_UNAVAILABLE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-unavailable");
pub const CLUSTER_WORK_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-failed");
pub const CLUSTER_WORK_FORWARDED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-forwarded");
pub const CLUSTER_HIVE_EVICTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/hive-evicted");
/// Marks a dial of a target that a route or a registration names, refused
/// because the party that answered there presented another certificate or
/// none. The payload is the dialed address, and the dial ended before any
/// frame left.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_DIAL_REFUSED;
///
/// assert_eq!(CLUSTER_DIAL_REFUSED.to_string(), "urn:tightbeam:event:cluster/dial-refused");
/// ```
pub const CLUSTER_DIAL_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/dial-refused");
/// Marks a gateway loop that ended because a registry, table, or journal
/// lock it read is poisoned. The payload names the fault. A poisoned std
/// lock stays poisoned, and the loop's task returns `()` to its owner, so
/// this event is the one place the end is visible.
pub const CLUSTER_LOOP_POISONED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/loop-poisoned");

// Cluster export events
pub const CLUSTER_EXPORT_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-refused");
pub const CLUSTER_EXPORT_GRANTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-granted");
pub const CLUSTER_EXPORT_UNBOUNDED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-unbounded");
pub const CLUSTER_EXPORT_IDENTITY_UNAVAILABLE: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/export-identity-unavailable");

// Cluster peer advertisement events
pub const CLUSTER_PEER_ADVERTISED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-advertised");
pub const CLUSTER_PEER_AD_LEARNED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-learned");
pub const CLUSTER_PEER_AD_DROPPED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-dropped");
pub const CLUSTER_PEER_AD_PUBLISH_FAILED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-publish-failed");
pub const CLUSTER_PEER_DISCOVERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-discovered");
pub const CLUSTER_PEER_EVICTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-evicted");
/// Marks a peer address that answered from outside the flood, so it left the
/// peer exchange sample and each learned table that held it. The payload is
/// the address, and the routes that dial it stay.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_EXPELLED;
///
/// assert_eq!(CLUSTER_PEER_EXPELLED.to_string(), "urn:tightbeam:event:cluster/peer-expelled");
/// ```
pub const CLUSTER_PEER_EXPELLED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-expelled");
pub const CLUSTER_PEER_ADVERTISE_REFUSED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-advertise-refused");

// Cluster relay events
pub const CLUSTER_RELAY_TRAIL_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/relay-trail-refused");
pub const CLUSTER_RELAY_TRAIL_PRUNED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/relay-trail-pruned");

// Cluster gossip events
pub const CLUSTER_GOSSIP_ACCEPTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-accepted");
pub const CLUSTER_GOSSIP_DUPLICATE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-duplicate");
pub const CLUSTER_GOSSIP_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-refused");
pub const CLUSTER_GOSSIP_RELAY_WEAKENED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-relay-weakened");
pub const CLUSTER_GOSSIP_DROP_SIGNAL: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-drop-signal");
/// Marks a reflood whose outer relay frame this gateway could not build or
/// sign, so no peer received the rumor.
pub const CLUSTER_GOSSIP_REFLOOD_FAILED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-reflood-failed");
/// Carries the count of flood targets one reflood round failed to reach.
pub const CLUSTER_GOSSIP_FANOUT_UNREACHED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-fanout-unreached");
/// Marks a relayed rumor whose origin this gateway's peer trust does not
/// hold. The gateway drops the rumor, and the relay pays one rate token and
/// no score.
pub const CLUSTER_GOSSIP_ORIGIN_UNKNOWN: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-origin-unknown");
/// Marks a peer that answered a rumor's origin as outside its trust, so this
/// gateway offers that peer no further rumor of that origin for one window.
pub const CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-origin-refused-by-peer");
/// Marks a journal that refused to witness a digest this gateway published.
pub const CLUSTER_GOSSIP_WITNESS_REFUSED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-witness-refused");

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
//! # Fields
//!
//! An emit site attaches up to three fields to an event, and the doc of a
//! constant names the fields its emit sites attach:
//!
//! - The label names why the event fired, such as the name of a refusal status.
//! - The value is what a spec asserts with `equals!`, such as a status, a count, or a code.
//! - The payload names who, such as an address, a fingerprint, or a canonical public key.
//!
//! The audit sink keeps the SHA3-256 hash of a payload when the config of the
//! trace sets [`enable_payloads`]. Under `colony`, an event whose doc names no
//! label files an empty label.
//!
//! # Feature gates
//!
//! Where the doc of a constant names a feature, its emit sites need it:
//!
//! - Under `colony`, a gateway or a hive emits the event. A `testing` build
//!   records its value for a spec, and an `instrument` build files the label,
//!   the payload hash, and the trace clock stamp in the audit sink.
//! - Under `instrument`, a transport, a pool, or a server plane files the event
//!   in the audit sink, and a `testing` build also records its value for a
//!   spec.
//!
//! # Organization
//!
//! Short section headers group related constants by plane. Each constant
//! name states its event, so a section header names the plane alone.
//!
//! [`enable_payloads`]: super::TbInstrumentationConfig::enable_payloads

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
/// Marks one inbound call that a collector gate admits, after the
/// [`POLICY_EVAL`] of its evaluation. The mux responder and the cleartext and
/// encrypted single-flight collectors record it on the connection's audit
/// trail. It fires under `instrument`.
///
/// - The label is `Ok`, the name of the status.
/// - The value is `Ok`, the normalized `TransitStatus` of the verdict.
/// - The payload is the canonical form of the peer's key, when the session holds one.
///
/// ```
/// use tightbeam::instrumentation::events::GATE_ACCEPT;
///
/// assert_eq!(GATE_ACCEPT.to_string(), "urn:tightbeam:event:gate/accept");
/// ```
pub const GATE_ACCEPT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:gate/accept");
/// Marks one inbound call that a collector gate refuses, after the
/// [`POLICY_EVAL`] of its evaluation. The mux responder and the cleartext and
/// encrypted single-flight collectors record it on the connection's audit
/// trail. It fires under `instrument`.
///
/// - The label is the name of the status in the value.
/// - The value is the normalized `TransitStatus` of the verdict, so a gate
///   verdict of `Unknown` reads `Internal`.
/// - The payload is the canonical form of the peer's key, when the session holds one.
///
/// ```
/// use tightbeam::instrumentation::events::GATE_REJECT;
///
/// assert_eq!(GATE_REJECT.to_string(), "urn:tightbeam:event:gate/reject");
/// ```
pub const GATE_REJECT: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:gate/reject");

// Transport events
pub const REQUEST_RECV: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/request-recv");
pub const RESPONSE_SEND: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/response-send");
/// Marks an inbound envelope that the transport refuses at its read step. A
/// session read, the reader half of a split connection, and the read of an
/// answer by a client each record it. It fires under `instrument`.
///
/// - The label and the value name the failure:
///   - `SizeExceeded`: the envelope passes the size ceiling of its mode.
///   - `InvalidMessage`: the frame of the envelope ends early, or its length field is not canonical DER.
///   - `DerError`: the wire envelope, or the transport envelope that it carries, does not decode.
///   - `TamperDetected`: a record breaks the sequence of its direction by a replay, a reorder, or a deletion.
///   - `OpenFailed`: the receive key refuses a record that is no envelope of
///     the key, whose position does not decode or passes a renewal bound, or
///     whose tag fails.
///   - `WrongEpoch`: a record names another epoch than the receive key.
///   - `EncryptionFailed`: a record arrives on a session that holds no keys.
///   - `MissingEncryption`: cleartext arrives where the session requires encryption.
/// - The payload is the peer's key, when the session holds one.
/// - `OpenFailed` and `WrongEpoch` mark a forged record. The reader returns
///   the error that the open names, such as `TransportError::InvalidMessage`
///   for a tag that fails.
///
/// ```
/// use tightbeam::instrumentation::events::TRANSPORT_ENVELOPE_REFUSED;
///
/// assert_eq!(TRANSPORT_ENVELOPE_REFUSED.to_string(), "urn:tightbeam:event:transport/envelope-refused");
/// ```
pub const TRANSPORT_ENVELOPE_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/envelope-refused");
/// Marks an outbound envelope that the send cipher refuses because its key
/// reached its record limit, so the session needs a rekey before it sends
/// again. The writer half of a split connection and a session that seals a
/// message each record it. It fires under `instrument`.
///
/// - The label is `send`, the direction of the cipher.
/// - The value is the record limit of the key, as a `u64`.
///
/// ```
/// use tightbeam::instrumentation::events::TRANSPORT_REKEY_REQUIRED;
///
/// assert_eq!(TRANSPORT_REKEY_REQUIRED.to_string(), "urn:tightbeam:event:transport/rekey-required");
/// ```
pub const TRANSPORT_REKEY_REQUIRED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:transport/rekey-required");

// Connection lifecycle events
/// Marks one connection that a server accepts, at the first step of its
/// service, ahead of the negotiation of multiplexing. A connection that an
/// async `server!`, a servlet, a hive, or a gateway serves records it on its
/// audit trail. It fires under `instrument`.
///
/// - The payload is the address that the listener accepted the connection from.
/// - Each bare connect records one event before its first byte, so a flood of
///   them fills the bounded sink of a trace that names no sink of its own.
///   Give a server trace a sink that drains it.
///
/// ```
/// use tightbeam::instrumentation::events::CONNECTION_ACCEPTED;
///
/// assert_eq!(CONNECTION_ACCEPTED.to_string(), "urn:tightbeam:event:connection/accepted");
/// ```
pub const CONNECTION_ACCEPTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:connection/accepted");
/// Marks the end of the reader of a multiplexed connection, after it routes
/// its last envelope and before the pending streams observe the failure. It
/// fires under `instrument`.
///
/// - The label names why the reader stopped:
///   - `invalid-message`: the reader refused what the peer sent, such as an
///     envelope that `TRANSPORT_ENVELOPE_REFUSED` names.
///   - `connection-closed`: the connection ended under the reader, by a close,
///     a read failure, or a stall past the deadline.
///
/// ```
/// use tightbeam::instrumentation::events::CONNECTION_CLOSED;
///
/// assert_eq!(CONNECTION_CLOSED.to_string(), "urn:tightbeam:event:connection/closed");
/// ```
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
/// Marks one call whose application handler ran and returned an error of its
/// own, at the step where the plane maps the error to the status that the
/// caller reads. The mux planes and the single-flight turn of a `server!`
/// record it on the connection's audit trail.
///
/// - The label is the name of the status in the value.
/// - The value is the `TransitStatus` that the call answers, such as
///   `Unimplemented` for a handler that answers it.
/// - It fires under `instrument`, whatever [`enable_internal_detail`] holds, because it is an outcome.
/// - A fault that the trace injects at the span of a handler answers the call in place of this event.
/// - [`MUX_STREAM_REFUSED`] records a default method that refuses the kind of
///   a stream, in place of this event.
///
/// ```
/// use tightbeam::instrumentation::events::HANDLER_FAILED;
///
/// assert_eq!(HANDLER_FAILED.to_string(), "urn:tightbeam:event:handler/failed");
/// ```
///
/// [`enable_internal_detail`]: super::TbInstrumentationConfig::enable_internal_detail
pub const HANDLER_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:handler/failed");

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
/// Marks a peer cancel that the mux responder honors with an abort of the
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
/// Marks a peer stream that the mux responder refuses, on the connection's
/// audit trail. It fires under `instrument`, at one of two steps:
///
/// - The dispatch of the stream refuses its kind with
///   `TransportError::NotServed`, from a default method of the service or of
///   the dispatch, and the responder answers `Unimplemented`.
/// - A stream opens past the advertised concurrency cap, and the responder answers `ResourceExhausted`.
///
/// The label is the name of the status, and the value is the `TransitStatus`.
///
/// ```
/// use tightbeam::instrumentation::events::MUX_STREAM_REFUSED;
///
/// assert_eq!(MUX_STREAM_REFUSED.to_string(), "urn:tightbeam:event:mux/stream-refused");
/// ```
pub const MUX_STREAM_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/stream-refused");
pub const MUX_PROTOCOL_ERROR: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/protocol-error");
pub const MUX_INTERNAL_ERROR: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/internal-error");
pub const MUX_STREAMS_EXHAUSTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/streams-exhausted");
/// Marks a debit of the outbound session budget that the budget cannot carry,
/// so an emit, a push, or a response fails with `BudgetExhausted`. The debit
/// admission is the one budget check for all three. It fires under
/// `instrument`.
///
/// - The label is `reserved` for a debit that may spend the drain reserve, and `unreserved` otherwise.
/// - The value is the count of credits that the debit asked for, as a `u64`.
///
/// ```
/// use tightbeam::instrumentation::events::MUX_BUDGET_REFUSED;
///
/// assert_eq!(MUX_BUDGET_REFUSED.to_string(), "urn:tightbeam:event:mux/budget-refused");
/// ```
pub const MUX_BUDGET_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/budget-refused");
pub const MUX_OPEN_DRAINING: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/open-draining");
pub const MUX_REKEY_REQUESTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-requested");
pub const MUX_REKEY_RENEWED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-renewed");
pub const MUX_REKEY_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-refused");
/// Marks an in-band renewal whose deadline elapsed before its exchange
/// completed. The writer then drains the connection with a `Shutdown` GoAway,
/// which [`MUX_GOAWAY_SENT`] records. It fires under `instrument`, in a build
/// with `tokio` and with `transport-cms` or `transport-hpke`.
///
/// ```
/// use tightbeam::instrumentation::events::MUX_REKEY_EXPIRED;
///
/// assert_eq!(MUX_REKEY_EXPIRED.to_string(), "urn:tightbeam:event:mux/rekey-expired");
/// ```
pub const MUX_REKEY_EXPIRED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:mux/rekey-expired");
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
/// Marks a failover of a pooled lease that another peer answered, so the
/// failover ends before the frame leaves. A failover lands only on the
/// certificate that the lease pinned. This event follows the [`POOL_FAILOVER`]
/// of the attempt, ahead of the `CertificateNotPinned` error. It fires under
/// `instrument`.
///
/// - The label is `certificate-not-pinned`, the name of the refusal.
/// - The payload is the certificate that answered the failover, when it encodes.
/// - The error of the failover is `CertificateNotPinned`, ahead of a fault that the trace injects here.
///
/// ```
/// use tightbeam::instrumentation::events::POOL_FAILOVER_REFUSED;
///
/// assert_eq!(POOL_FAILOVER_REFUSED.to_string(), "urn:tightbeam:event:pool/failover-refused");
/// ```
pub const POOL_FAILOVER_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/failover-refused");
pub const POOL_EXHAUSTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/exhausted");
pub const POOL_RELEASED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:pool/released");

// Session/handshake receipt lifecycle events
/// Marks a handshake that establishes its session, when the endpoint reaches
/// the encrypted phase. A server that runs more than one round records it
/// once, at the round that completes the session. The endpoint records it on
/// its own trace. It fires under `instrument`, in a build with `transport-cms`
/// or `transport-hpke`.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_HANDSHAKE_COMPLETE;
///
/// assert_eq!(SESSION_HANDSHAKE_COMPLETE.to_string(), "urn:tightbeam:event:session/handshake-complete");
/// ```
pub const SESSION_HANDSHAKE_COMPLETE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/handshake-complete");
/// Marks a handshake that its deadline ends, at the record of the handshake
/// outcome. It fires under `instrument`, in a build with `tokio` and with
/// `transport-cms` or `transport-hpke`.
///
/// - A client records it when a handshake read or write passes its deadline.
/// - A server counts its `handshake_timeout` from the start of the handshake,
///   so the deadline can end a round before the round starts or while it runs.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_HANDSHAKE_EXPIRED;
///
/// assert_eq!(SESSION_HANDSHAKE_EXPIRED.to_string(), "urn:tightbeam:event:session/handshake-expired");
/// ```
pub const SESSION_HANDSHAKE_EXPIRED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/handshake-expired");
/// Marks a server handshake that its `TransportAuthorizer` refuses, at the
/// record of the handshake outcome. It fires under `instrument`, in a build
/// with `transport-cms` or `transport-hpke`.
///
/// - The label is the refusal code that the authorizer returned, in decimal, which the audit sink keeps.
/// - The value is the same refusal code, as a `u32`.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_AUTHORIZATION_REFUSED;
///
/// assert_eq!(SESSION_AUTHORIZATION_REFUSED.to_string(), "urn:tightbeam:event:session/authorization-refused");
/// ```
pub const SESSION_AUTHORIZATION_REFUSED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:session/authorization-refused");
/// Marks a budget-bearing session that holds its dual-signed receipt, right
/// after its [`SESSION_HANDSHAKE_COMPLETE`]. It fires under `instrument`, in
/// a build with `transport-cms` or `transport-hpke`. The event means one
/// thing on each side:
///
/// - On a server, the client's countersignature verified, and the authorizer accepted the settlement answer.
/// - On a client, the client countersigned the receipt. The server settles it
///   later, so a refused settlement records [`SESSION_RECEIPT_REFUSED`] on the
///   server's trace.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_RECEIPT_SETTLED;
///
/// assert_eq!(SESSION_RECEIPT_SETTLED.to_string(), "urn:tightbeam:event:session/receipt-settled");
/// ```
pub const SESSION_RECEIPT_SETTLED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/receipt-settled");
/// Marks a budget-bearing handshake that fails on its receipt. It fires under
/// `instrument`, in a build with `transport-cms` or `transport-hpke`.
///
/// - The label names the reason:
///   - `approval-refused`: the client's receipt approver refused the receipt.
///   - `settlement-rejected`: the server's authorizer rejected the settlement answer.
///   - `receipt-missing`: no receipt arrived for a budget-bearing session.
///   - `receipt-mismatch`: the receipt disagrees with the negotiated session.
///   - `countersignature-missing`: an issued receipt got no countersignature.
/// - The value is the refusal code of an approval refusal or a settlement rejection.
///
/// A receipt signature or countersignature that fails verification, and a
/// countersignature with a malformed answer, record [`SESSION_CERT_REJECTED`]
/// with the `signature` label.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_RECEIPT_REFUSED;
///
/// assert_eq!(SESSION_RECEIPT_REFUSED.to_string(), "urn:tightbeam:event:session/receipt-refused");
/// ```
pub const SESSION_RECEIPT_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/receipt-refused");
/// Marks a handshake that refuses the identity of its peer. It fires under
/// `instrument`, in a build with `transport-cms` or `transport-hpke`. The
/// label and the value name the reason:
///
/// - `certificate/<cause>`: the peer certificate failed validation, for the named cause.
/// - `signature`: a handshake signature, the server's signature over the
///   session receipt, or the client's countersignature of the receipt failed
///   verification. A countersignature with a malformed answer reads the same.
/// - `missing-client-certificate`: a server that requires a client certificate got none.
/// - `missing-server-certificate`: a client got no certificate from its server.
/// - `mutual-auth-required`: the server requires mutual authentication, and the client has no identity.
/// - `sealed-frame`: a sealed frame is malformed.
/// - `sealed-closing/<cause>`: the sealed closing failed to open, for the named cause.
/// - `key-confirmation`: the key-confirmation tag of the peer differs from the tag that its receiver derived.
/// - `subject-mismatch`, `anchor-mismatch`, `key-reuse`: the two certificates of a server disagree.
/// - `server-ephemeral-is-static`, `client-ephemeral-is-static`: the peer sent
///   its static key as its ephemeral.
///
/// ```
/// use tightbeam::instrumentation::events::SESSION_CERT_REJECTED;
///
/// assert_eq!(SESSION_CERT_REJECTED.to_string(), "urn:tightbeam:event:session/cert-rejected");
/// ```
pub const SESSION_CERT_REJECTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:session/cert-rejected");

// Hive events
/// Marks a hive that establishes, once it binds the control plane that its
/// config names and before that plane serves. A trace that refuses the event
/// fails the establish, and the hive stays provisional. It fires under
/// `colony`.
///
/// - The label is `control-plane` or `no-control-plane`, by whether the hive serves a control plane.
/// - The value is the count of servlets that the hive registered, as a `u64`.
/// - The payload is the address of the control plane, when the hive serves one.
///
/// ```
/// use tightbeam::instrumentation::events::HIVE_ESTABLISHED;
///
/// assert_eq!(HIVE_ESTABLISHED.to_string(), "urn:tightbeam:event:hive/established");
/// ```
pub const HIVE_ESTABLISHED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:hive/established");
/// Marks one registration that the anti-entropy beat of a hive sends to one
/// gateway, so the gateway refreshes the hive's slate in its soft state. The
/// beat sends one to each registered gateway every `reregister_interval`. It
/// fires under `colony`.
///
/// - The label is the name of the status in the value.
/// - The value is the status of the gateway's reply, or `Unavailable` when the registration failed.
/// - The payload is the address of the gateway.
///
/// ```
/// use tightbeam::instrumentation::events::HIVE_REREGISTERED;
///
/// assert_eq!(HIVE_REREGISTERED.to_string(), "urn:tightbeam:event:hive/reregistered");
/// ```
pub const HIVE_REREGISTERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:hive/reregistered");
/// Marks a cluster command that a hive refuses, as the refusal reply leaves.
/// It fires under `colony`.
///
/// - The label names why the hive refused:
///   - A command that the security gate refuses at admission takes the name of its status.
///   - A refusal after admission takes its own name, such as `Draining` or `UnknownInstance`.
/// - The value is the `TransitStatus` that the sender reads.
/// - The payload is the canonical key of the peer.
///
/// ```
/// use tightbeam::instrumentation::events::HIVE_COMMAND_REFUSED;
///
/// assert_eq!(HIVE_COMMAND_REFUSED.to_string(), "urn:tightbeam:event:hive/command-refused");
/// ```
pub const HIVE_COMMAND_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:hive/command-refused");

// Cluster gateway events
/// Marks a request or a stream open that a collector gate of the gateway
/// refuses, before the gateway decodes the request envelope. The first policy
/// that refuses decides, and the value is its normalized verdict, the status
/// that the caller reads. The label is the name of the status in the value. It
/// fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GATE_BLOCKED;
///
/// assert_eq!(CLUSTER_GATE_BLOCKED.to_string(), "urn:tightbeam:event:cluster/gate-blocked");
/// ```
pub const CLUSTER_GATE_BLOCKED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gate-blocked");
/// Marks a hive registration that the gateway admits. The membership step
/// installs the hive entry and its servlet slate, or replaces the rows of a
/// hive that registers again. The value is the count of hives in the registry
/// after the install. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_HIVE_REGISTERED;
///
/// assert_eq!(CLUSTER_HIVE_REGISTERED.to_string(), "urn:tightbeam:event:cluster/hive-registered");
/// ```
pub const CLUSTER_HIVE_REGISTERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/hive-registered");
/// Marks a hive registration that the gateway refuses, as the refusal reply
/// leaves. The value is the status that the hive reads, and the label is the
/// name of that status. It fires under `colony`, for one of these causes:
///
/// - The frame fails its signature or its freshness check.
/// - The hive address names no hive identity, or the protocol cannot dial it.
/// - The frame names no signer.
/// - A servlet address breaks the locator rule of the slate.
/// - The membership step fails.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_REGISTER_REFUSED;
///
/// assert_eq!(CLUSTER_REGISTER_REFUSED.to_string(), "urn:tightbeam:event:cluster/register-refused");
/// ```
pub const CLUSTER_REGISTER_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/register-refused");
/// Marks a servlet address update that the gateway applies for a registered
/// hive. The membership step binds the frame's signer to the hive and writes
/// the added and the removed routes in one step. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_UPDATE_ACCEPTED;
///
/// assert_eq!(CLUSTER_UPDATE_ACCEPTED.to_string(), "urn:tightbeam:event:cluster/update-accepted");
/// ```
pub const CLUSTER_UPDATE_ACCEPTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/update-accepted");
/// Marks a servlet address update that the gateway refuses, as the refusal
/// reply leaves. The label is the name of the status that the hive reads. It
/// fires under `colony`, for one of these causes:
///
/// - The frame fails its signature or its freshness check.
/// - The update does not parse.
/// - The frame names no signer.
/// - The membership step refuses the signer or the routes.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_UPDATE_REFUSED;
///
/// assert_eq!(CLUSTER_UPDATE_REFUSED.to_string(), "urn:tightbeam:event:cluster/update-refused");
/// ```
pub const CLUSTER_UPDATE_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/update-refused");
/// Marks a work request or a stream splice that its route answered, after the
/// gateway reinforces the trail. A peer gateway's answer counts here when its
/// status is `Ok`, after its [`CLUSTER_WORK_FORWARDED`]. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_WORK_ROUTED;
///
/// assert_eq!(CLUSTER_WORK_ROUTED.to_string(), "urn:tightbeam:event:cluster/work-routed");
/// ```
pub const CLUSTER_WORK_ROUTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-routed");
/// Marks a work request or a stream splice that the gateway refuses before it
/// selects a route. The value is the status that the caller reads, and the
/// label is the name of that status. It fires under `colony`.
///
/// - `PermissionDenied`: the target is not a servlet type of the gateway's namespace.
/// - `InvalidArgument`: the payload of a work request does not decode as a frame.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_WORK_REFUSED;
///
/// assert_eq!(CLUSTER_WORK_REFUSED.to_string(), "urn:tightbeam:event:cluster/work-refused");
/// ```
pub const CLUSTER_WORK_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-refused");
/// Marks a work request or a stream splice whose servlet type has no live
/// trail at its first route selection. It fires under `colony`.
///
/// - A caller of unary work reads `Unavailable`.
/// - A stream caller reads `Unknown`, because the mux answers a handler's `Unavailable` as `Unknown`.
/// - A retry that finds no second trail ends at the [`CLUSTER_WORK_FAILED`] of the trail it weakened.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_WORK_UNAVAILABLE;
///
/// assert_eq!(CLUSTER_WORK_UNAVAILABLE.to_string(), "urn:tightbeam:event:cluster/work-unavailable");
/// ```
pub const CLUSTER_WORK_UNAVAILABLE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-unavailable");
/// Marks a trail that failed a forward, after the gateway weakens the trail.
/// The value is the status of the failed forward, and the label is the name of
/// that status. It fires under `colony`.
///
/// - A dial or an exchange fault fails a forward, and so does a peer reply that does not decode.
/// - A peer gateway's answer other than `Ok` fails a unary forward.
/// - A failed dial or a failed relay of a stream splice fails the splice.
/// - A forward that proves the frame never ran fails here, ahead of one retry on the next-best trail.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_WORK_FAILED;
///
/// assert_eq!(CLUSTER_WORK_FAILED.to_string(), "urn:tightbeam:event:cluster/work-failed");
/// ```
pub const CLUSTER_WORK_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-failed");
/// Marks a forward to a peer gateway that answered, before the gateway scores
/// the trail. A unary forward records it for each reply that decodes, and
/// relays the peer's own reply envelope to the caller. A stream splice
/// records it when the splice succeeds. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_WORK_FORWARDED;
///
/// assert_eq!(CLUSTER_WORK_FORWARDED.to_string(), "urn:tightbeam:event:cluster/work-forwarded");
/// ```
pub const CLUSTER_WORK_FORWARDED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/work-forwarded");
/// Marks a call that the edge plane of a gateway refuses. The edge plane
/// serves work submission alone, so it answers each other call with
/// `PermissionDenied`: a unary envelope of another kind, such as a
/// registration, and each streaming or duplex open. It fires under `colony`.
///
/// - The label names the kind of the call: `unary`, `streaming`, or `duplex`.
/// - The value is `PermissionDenied`, the `TransitStatus` that the caller reads.
/// - The payload names the caller by the canonical key that its session proved, when the session holds one.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_EDGE_REFUSED;
///
/// assert_eq!(CLUSTER_EDGE_REFUSED.to_string(), "urn:tightbeam:event:cluster/edge-refused");
/// ```
pub const CLUSTER_EDGE_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/edge-refused");
/// Marks one heartbeat that a registered hive failed, as the gateway counts
/// the failure toward the eviction of the hive. A hive fails a heartbeat when
/// it answers a status other than `Ok` or `ResourceExhausted`, or when the
/// dial or the exchange fails. It fires under `colony`.
///
/// - The label is the name of the status in the value.
/// - The value is the `TransitStatus` that the hive answered, or the status
///   that a dial or an exchange fault forwards as.
/// - The payload is the hive's address.
/// - It precedes the [`CLUSTER_HIVE_EVICTED`] of the failure that reaches `max_failures`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_HEARTBEAT_FAILED;
///
/// assert_eq!(CLUSTER_HEARTBEAT_FAILED.to_string(), "urn:tightbeam:event:cluster/heartbeat-failed");
/// ```
pub const CLUSTER_HEARTBEAT_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/heartbeat-failed");
/// Marks a hive that the gateway retires with its servlet routes. It fires
/// under `colony`, once for each hive it retires.
///
/// - The heartbeat failure that reaches `max_failures` retires it, after its [`CLUSTER_HEARTBEAT_FAILED`].
/// - The heartbeat loop retires a hive whose lease expired.
/// - The value is the count of hives in the registry that its own retire left,
///   as a `u64`, so the hives of one lease sweep count down.
/// - The payload is the hive's address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_HIVE_EVICTED;
///
/// assert_eq!(CLUSTER_HIVE_EVICTED.to_string(), "urn:tightbeam:event:cluster/hive-evicted");
/// ```
pub const CLUSTER_HIVE_EVICTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/hive-evicted");
/// Marks a dial that the dialer refuses, because the party that answered at
/// the target of a route or a registration presented another certificate or
/// none. The dial ends before any frame leaves. It fires under `colony`.
///
/// - The label is `PeerMismatch`.
/// - The payload is the dialed address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_DIAL_REFUSED;
///
/// assert_eq!(CLUSTER_DIAL_REFUSED.to_string(), "urn:tightbeam:event:cluster/dial-refused");
/// ```
pub const CLUSTER_DIAL_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/dial-refused");
/// Marks a gateway loop that ended on a local fault. It fires under `colony`.
///
/// - The fault is a registry, table, or journal that the loop reads and that
///   is poisoned or failed, or a local step of the loop that failed, such as
///   the build, the signature, or the send of a repair.
/// - The payload names the fault.
/// - A poisoned std lock stays poisoned, and the loop's task returns `()` to
///   its owner, so this event is the one place the end is visible.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_LOOP_POISONED;
///
/// assert_eq!(CLUSTER_LOOP_POISONED.to_string(), "urn:tightbeam:event:cluster/loop-poisoned");
/// ```
pub const CLUSTER_LOOP_POISONED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/loop-poisoned");

// Cluster export events
/// Marks a request or a stream open that the export boundary of the gateway
/// refuses, after the collector gates pass and the target resolves to a
/// servlet type. It fires under `colony`.
///
/// - The label is `<status>/<route>`: the name of the refusal status, and
///   `relayed` for a request that a peer relayed or `direct` for an origin
///   request, such as `PermissionDenied/direct`.
/// - The value is `true` for a request that a peer relayed, and `false` for an origin request.
/// - The payload is the fingerprint of the caller's certificate, when mutual TLS captured one.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_EXPORT_REFUSED;
///
/// assert_eq!(CLUSTER_EXPORT_REFUSED.to_string(), "urn:tightbeam:event:cluster/export-refused");
/// ```
pub const CLUSTER_EXPORT_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-refused");
/// Marks a request or a stream open that a configured export grant admits
/// across the export boundary of the gateway. It fires under `colony`, and
/// only when the grant decides: the built-in allowlist refused the target, a
/// grant allowed it, and each deny gate passed it.
///
/// - The label is `Ok/relayed` for a request that a peer relayed, and `Ok/direct` for an origin request.
/// - The value is `true` for a request that a peer relayed, and `false` for an origin request.
/// - The payload is the fingerprint of the caller's certificate, when mutual TLS captured one.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_EXPORT_GRANTED;
///
/// assert_eq!(CLUSTER_EXPORT_GRANTED.to_string(), "urn:tightbeam:event:cluster/export-granted");
/// ```
pub const CLUSTER_EXPORT_GRANTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-granted");
/// Marks a federated gateway with no export list, which serves and advertises
/// each local servlet type to its external peers. A gateway federates when it
/// holds a peer trust or a list of peers. It records the event once, when it
/// starts, after the check of the address it advertises. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_EXPORT_UNBOUNDED;
///
/// assert_eq!(CLUSTER_EXPORT_UNBOUNDED.to_string(), "urn:tightbeam:event:cluster/export-unbounded");
/// ```
pub const CLUSTER_EXPORT_UNBOUNDED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/export-unbounded");
/// Marks a gateway with an export list whose sessions capture no client
/// identity, because its peer authentication requires no certificate or it
/// holds no hive trust. Each session is then anonymous, so an unexported
/// target is unreachable from the origin plane too. It fires under `colony`.
///
/// - The gateway records the event once, when it starts, after the check of the address it advertises.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_EXPORT_IDENTITY_UNAVAILABLE;
///
/// assert_eq!(
///     CLUSTER_EXPORT_IDENTITY_UNAVAILABLE.to_string(),
///     "urn:tightbeam:event:cluster/export-identity-unavailable"
/// );
/// ```
pub const CLUSTER_EXPORT_IDENTITY_UNAVAILABLE: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/export-identity-unavailable");

// Cluster peer advertisement events
/// Marks a direct peer advertisement that the gateway admits, ahead of the
/// `Ok` reply. The frame verified on the peer trust plane and passed its
/// freshness check, the advertiser's discovery hint reached the peer table,
/// and the advertiser's slate reconciled into the routes. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_ADVERTISED;
///
/// assert_eq!(CLUSTER_PEER_ADVERTISED.to_string(), "urn:tightbeam:event:cluster/peer-advertised");
/// ```
pub const CLUSTER_PEER_ADVERTISED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-advertised");
/// Marks an advertisement rumor that the gateway applies to its routes. The
/// inner advertisement verified on the peer trust plane under the origin of
/// the rumor, and the origin's slate reconciled into the routes. The payload
/// is the origin's fingerprint. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_AD_LEARNED;
///
/// assert_eq!(CLUSTER_PEER_AD_LEARNED.to_string(), "urn:tightbeam:event:cluster/peer-ad-learned");
/// ```
pub const CLUSTER_PEER_AD_LEARNED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-learned");
/// Marks an advertisement rumor that the gateway refuses to apply to its
/// routes, for a failed check of its admission or a slate that the registry
/// refuses. The payload is the signer of the rumor, when the signer is
/// verifiable. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_AD_DROPPED;
///
/// assert_eq!(CLUSTER_PEER_AD_DROPPED.to_string(), "urn:tightbeam:event:cluster/peer-ad-dropped");
/// ```
pub const CLUSTER_PEER_AD_DROPPED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-dropped");
/// Marks a beat that failed to publish the gateway's slate as an advertisement
/// rumor: the beat built no advertisement, or the creation of the rumor
/// failed. The next beat retries the publish. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_AD_PUBLISH_FAILED;
///
/// assert_eq!(CLUSTER_PEER_AD_PUBLISH_FAILED.to_string(), "urn:tightbeam:event:cluster/peer-ad-publish-failed");
/// ```
pub const CLUSTER_PEER_AD_PUBLISH_FAILED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-ad-publish-failed");
/// Marks a peer that a reconcile round promotes into the tried table of the
/// gateway's peer table, which holds the targets of each beat. The promotion
/// waits for the peer's decoded reply, after the handshake proved flood
/// membership. The payload is the peer's dial address. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_DISCOVERED;
///
/// assert_eq!(CLUSTER_PEER_DISCOVERED.to_string(), "urn:tightbeam:event:cluster/peer-discovered");
/// ```
pub const CLUSTER_PEER_DISCOVERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-discovered");
/// Marks a tried peer that the beat evicts, at the failed reconcile round that
/// reaches `MAX_PEER_TRIED_FAILURES`. The routes that dial the peer's address
/// leave the registry first, and [`CLUSTER_PEER_ROUTES_WITHDRAWN`] counts
/// them with the label `evicted`. The payload is the dial address. It fires
/// under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_EVICTED;
///
/// assert_eq!(CLUSTER_PEER_EVICTED.to_string(), "urn:tightbeam:event:cluster/peer-evicted");
/// ```
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
/// Marks a direct peer advertisement that the gateway refuses, as the refusal
/// reply leaves. The value is the status that the advertiser reads, and the
/// label is the name of that status. It fires under `colony`, for one of these
/// causes:
///
/// - The frame fails to verify on the peer trust plane, or fails its freshness check.
/// - The advertisement fails its admission.
/// - The peer table cannot record the advertiser's discovery hint, because its lock is poisoned.
/// - The registry refuses the advertiser's slate, such as a slate that conflicts with a held route.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED;
///
/// assert_eq!(CLUSTER_PEER_ADVERTISE_REFUSED.to_string(), "urn:tightbeam:event:cluster/peer-advertise-refused");
/// ```
pub const CLUSTER_PEER_ADVERTISE_REFUSED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-advertise-refused");
/// Marks the discovery hints that the gateway's peer table admits as
/// unverified candidates, which a later probe can promote. It fires under
/// `colony`, and only for a count above 0.
///
/// - The label names the source of the hints:
///   - `advertiser`: the signer of a direct peer advertisement.
///   - `origin`: the origin of an advertisement rumor.
///   - `pex`: the peer-exchange sample of a reconcile reply.
/// - The value is the count of hints admitted, as a `u64`.
/// - The payload names the source, by its fingerprint or its dial address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_HINTS_LEARNED;
///
/// assert_eq!(CLUSTER_PEER_HINTS_LEARNED.to_string(), "urn:tightbeam:event:cluster/peer-hints-learned");
/// ```
pub const CLUSTER_PEER_HINTS_LEARNED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-hints-learned");
/// Marks the new direct routes that one peer advertisement installs, when the
/// gateway reconciles the advertiser's slate from a direct advertisement or an
/// advertisement rumor. It fires under `colony`, and only for a count above 0.
///
/// - The label is `direct`, the kind of the trail. [`CLUSTER_RELAY_TRAIL_INSTALLED`] marks a relay trail.
/// - The value is the count of new routes, as a `u64`.
/// - The payload is the advertiser's fingerprint.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_ROUTES_INSTALLED;
///
/// assert_eq!(CLUSTER_PEER_ROUTES_INSTALLED.to_string(), "urn:tightbeam:event:cluster/peer-routes-installed");
/// ```
pub const CLUSTER_PEER_ROUTES_INSTALLED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-routes-installed");
/// Marks the peer routes that the gateway withdraws in one step. It fires
/// under `colony`, and only for a count above 0.
///
/// - The label names the cause:
///   - `slate`: a reconciled slate leaves out routes that the advertiser held
///     before. An emptied slate also withdraws the relay trails of its origin
///     in the same step, and the count includes them.
///   - `evicted`: the beat evicted the peer that the routes dial, ahead of its [`CLUSTER_PEER_EVICTED`].
///   - `evaporated`: the evaporation sweep drops routes that reached their abandonment limit.
/// - The value is the count of routes withdrawn, as a `u64`.
/// - The payload is the advertiser's fingerprint for `slate`, and the dial address for `evicted`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_ROUTES_WITHDRAWN;
///
/// assert_eq!(CLUSTER_PEER_ROUTES_WITHDRAWN.to_string(), "urn:tightbeam:event:cluster/peer-routes-withdrawn");
/// ```
pub const CLUSTER_PEER_ROUTES_WITHDRAWN: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-routes-withdrawn");
/// Marks the peer routes that one weaken event drives to their abandonment
/// limit, so route selection skips them until the evaporation sweep drops
/// them. It fires under `colony`, and only for a count above 0.
///
/// - The label names the cause:
///   - `relay-score`: a relay sent invalid gossip, and the gateway weakened each route attributed to it.
///   - `drop-signal`: a flood target dropped rumors that it acknowledged, and
///     the gateway weakened each route that dials it.
/// - The value is the count of routes abandoned, as a `u64`.
/// - The payload is the relay's fingerprint or, for `drop-signal`, the target's dial address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_PEER_ROUTE_ABANDONED;
///
/// assert_eq!(CLUSTER_PEER_ROUTE_ABANDONED.to_string(), "urn:tightbeam:event:cluster/peer-route-abandoned");
/// ```
pub const CLUSTER_PEER_ROUTE_ABANDONED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/peer-route-abandoned");

// Cluster relay events
/// Marks a new relay trail that an advertisement rumor installs beside the
/// direct trail to its origin, as a fallback path through the relay that
/// carried the rumor. It fires under `colony`, and only for a new trail. The
/// payload is the origin's fingerprint, as for [`CLUSTER_RELAY_TRAIL_REFUSED`].
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_RELAY_TRAIL_INSTALLED;
///
/// assert_eq!(CLUSTER_RELAY_TRAIL_INSTALLED.to_string(), "urn:tightbeam:event:cluster/relay-trail-installed");
/// ```
pub const CLUSTER_RELAY_TRAIL_INSTALLED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/relay-trail-installed");
/// Marks a relay trail that the registry refuses, by its caps or a stale
/// order, after an advertisement rumor installed the direct trail to its
/// origin. The direct trail stands, and the origin loses its fallback path
/// through the relay. The payload is the origin's fingerprint. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_RELAY_TRAIL_REFUSED;
///
/// assert_eq!(CLUSTER_RELAY_TRAIL_REFUSED.to_string(), "urn:tightbeam:event:cluster/relay-trail-refused");
/// ```
pub const CLUSTER_RELAY_TRAIL_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/relay-trail-refused");
/// Marks the relay trails that one evaporation sweep retires by age. A relay
/// trail refreshes through relayed advertisement rumors alone, so a trail
/// older than three refresh intervals lost its refresh path. The value is the
/// count retired, as a `u64`. It fires under `colony`, and only for a count
/// above 0.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_RELAY_TRAIL_PRUNED;
///
/// assert_eq!(CLUSTER_RELAY_TRAIL_PRUNED.to_string(), "urn:tightbeam:event:cluster/relay-trail-pruned");
/// ```
pub const CLUSTER_RELAY_TRAIL_PRUNED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/relay-trail-pruned");

// Cluster gossip events
/// Marks a rumor that the gossip pipeline of the gateway admits, ahead of its
/// reflood and its `Ok` reply. It fires once the journal admits the rumor as
/// new, the kind of the rumor consumes it, and the gateway reads its flood
/// targets. It fires under `colony`.
///
/// - The label is the kind of the rumor: `application` or `peer-advertisement`.
/// - The value is the hop TTL that the rumor arrived with, as a `u64`.
/// - The payload is the identifier of the signer whose budget the rumor spends:
///   the origin gateway of a relayed rumor, or the hive of a local publish.
/// - A rumor of the application kind reaches the local ingress at [`CLUSTER_GOSSIP_DELIVERED`].
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_ADMITTED;
///
/// assert_eq!(CLUSTER_GOSSIP_ADMITTED.to_string(), "urn:tightbeam:event:cluster/gossip-admitted");
/// ```
pub const CLUSTER_GOSSIP_ADMITTED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-admitted");
/// Marks a rumor of the application kind that the gateway delivers to its
/// local ingress servlet. It fires once the servlet answered the delivery and
/// the journal acknowledged the local delivery. It fires under `colony`.
///
/// - A delivery on the admission path fires ahead of the [`CLUSTER_GOSSIP_ADMITTED`] of the rumor.
/// - The beat retries the delivery of a rumor whose ingress registered after
///   its admission, or whose delivery hit a transient fault.
/// - [`CLUSTER_GOSSIP_ADMITTED`] marks the admission of a rumor of each kind,
///   and this event marks the local delivery of an application rumor alone.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_DELIVERED;
///
/// assert_eq!(CLUSTER_GOSSIP_DELIVERED.to_string(), "urn:tightbeam:event:cluster/gossip-delivered");
/// ```
pub const CLUSTER_GOSSIP_DELIVERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-delivered");
/// Marks a rumor that the gateway already holds, which it answers with `Ok`
/// at once. The journal finds the digest before rate admission, or again when
/// it records the rumor. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_DUPLICATE;
///
/// assert_eq!(CLUSTER_GOSSIP_DUPLICATE.to_string(), "urn:tightbeam:event:cluster/gossip-duplicate");
/// ```
pub const CLUSTER_GOSSIP_DUPLICATE: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-duplicate");
/// Marks a gossip rumor, a published rumor, or a reconcile request that the
/// gateway refuses, as the refusal reply leaves. It fires under `colony`.
///
/// - The label is the name of the status in the value.
/// - The value is the `TransitStatus` of the refusal, such as
///   `ResourceExhausted` for a sender past its rate limit.
/// - The payload is the fingerprint of the frame's signer, for a refusal
///   after the frame's signature verified on its plane.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_REFUSED;
///
/// assert_eq!(CLUSTER_GOSSIP_REFUSED.to_string(), "urn:tightbeam:event:cluster/gossip-refused");
/// ```
pub const CLUSTER_GOSSIP_REFUSED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-refused");
/// Marks a relay that sent invalid gossip, after the gateway scores it with
/// one weaken event on each live route attributed to the relay: each route the
/// relay advertised, and each relay trail learned for it or through it. It
/// fires under `colony`, and only when the score weakened a route. The payload
/// is the relay's fingerprint.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_RELAY_WEAKENED;
///
/// assert_eq!(CLUSTER_GOSSIP_RELAY_WEAKENED.to_string(), "urn:tightbeam:event:cluster/gossip-relay-weakened");
/// ```
pub const CLUSTER_GOSSIP_RELAY_WEAKENED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-relay-weakened");
/// Marks a flood target whose ledger shows drops of rumors that it
/// acknowledged: a reconcile reply wants again a digest that the target
/// acknowledged while the journal retains it. The gateway weakens each live
/// peer route that dials the target, once per round. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_DROP_SIGNAL;
///
/// assert_eq!(CLUSTER_GOSSIP_DROP_SIGNAL.to_string(), "urn:tightbeam:event:cluster/gossip-drop-signal");
/// ```
pub const CLUSTER_GOSSIP_DROP_SIGNAL: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-drop-signal");
/// Marks a reflood whose outer relay frame this gateway could not build or
/// sign, so no peer received the rumor. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_REFLOOD_FAILED;
///
/// assert_eq!(CLUSTER_GOSSIP_REFLOOD_FAILED.to_string(), "urn:tightbeam:event:cluster/gossip-reflood-failed");
/// ```
pub const CLUSTER_GOSSIP_REFLOOD_FAILED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-reflood-failed");
/// Marks a reflood round that failed to reach some of its flood targets. The
/// value is the count of the targets it failed to reach, as a `u64`. It fires
/// under `colony`, and only for a count above 0.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_FANOUT_UNREACHED;
///
/// assert_eq!(CLUSTER_GOSSIP_FANOUT_UNREACHED.to_string(), "urn:tightbeam:event:cluster/gossip-fanout-unreached");
/// ```
pub const CLUSTER_GOSSIP_FANOUT_UNREACHED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-fanout-unreached");
/// Marks a relayed rumor whose origin this gateway's peer trust does not
/// hold. The gateway drops the rumor, and the relay pays one rate token and
/// no score. The payload is the relay's fingerprint. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_ORIGIN_UNKNOWN;
///
/// assert_eq!(CLUSTER_GOSSIP_ORIGIN_UNKNOWN.to_string(), "urn:tightbeam:event:cluster/gossip-origin-unknown");
/// ```
pub const CLUSTER_GOSSIP_ORIGIN_UNKNOWN: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-origin-unknown");
/// Marks a peer that answered a rumor's origin as outside its trust, so this
/// gateway offers that peer no further rumor of that origin for one window.
/// The payload is the peer's dial address. It fires under `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER;
///
/// assert_eq!(
///     CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER.to_string(),
///     "urn:tightbeam:event:cluster/gossip-origin-refused-by-peer"
/// );
/// ```
pub const CLUSTER_GOSSIP_ORIGIN_REFUSED_BY_PEER: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-origin-refused-by-peer");
/// Marks a journal that refused to witness a digest this gateway published.
/// The rumor floods anyway, because it is already live. It fires under
/// `colony`.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_WITNESS_REFUSED;
///
/// assert_eq!(CLUSTER_GOSSIP_WITNESS_REFUSED.to_string(), "urn:tightbeam:event:cluster/gossip-witness-refused");
/// ```
pub const CLUSTER_GOSSIP_WITNESS_REFUSED: Urn<'static> =
	crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-witness-refused");
/// Marks one repair push that a reconcile round sends to a peer, once the
/// peer's reply decodes. A repair resends a journaled rumor that the peer
/// wants, with an outer lifetime of 0, so the rumor stops at that peer. It
/// fires under `colony`.
///
/// - The label is the name of the status in the value.
/// - The value is the `TransitStatus` of the peer's reply.
/// - The payload is the peer's dial address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_GOSSIP_REPAIR_PUSHED;
///
/// assert_eq!(CLUSTER_GOSSIP_REPAIR_PUSHED.to_string(), "urn:tightbeam:event:cluster/gossip-repair-pushed");
/// ```
pub const CLUSTER_GOSSIP_REPAIR_PUSHED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/gossip-repair-pushed");
/// Marks a reconcile request from a flood member that the gateway answers,
/// ahead of the reply. It fires once the request passes the membership check,
/// the freshness check, and the bound on its held digests, and the gateway
/// draws its peer-exchange sample. It fires under `colony`.
///
/// - The value is the count of digests that the reply wants, as a `u64`.
/// - The payload is the requester's fingerprint.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_RECONCILE_ANSWERED;
///
/// assert_eq!(CLUSTER_RECONCILE_ANSWERED.to_string(), "urn:tightbeam:event:cluster/reconcile-answered");
/// ```
pub const CLUSTER_RECONCILE_ANSWERED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/reconcile-answered");
/// Marks a reconcile round with a peer that ends early. It fires under
/// `colony`.
///
/// - The label names the step where the round ended:
///   - `journal`: the journal failed to list its held digests.
///   - `unreachable`: the dial or the handshake failed.
///   - `build`: the request frame failed to build.
///   - `sign`: the signature of the request failed.
///   - `reply`: the exchange failed, or the reply failed to decode or passed its size bound.
///   - `bookkeeping`: a local step after the reply failed, such as the promotion or the repair.
/// - The value is `true` when the round charges the failure to the peer, as `unreachable` and `reply` do.
/// - The payload is the peer's dial address.
///
/// ```
/// use tightbeam::instrumentation::events::CLUSTER_RECONCILE_FAILED;
///
/// assert_eq!(CLUSTER_RECONCILE_FAILED.to_string(), "urn:tightbeam:event:cluster/reconcile-failed");
/// ```
pub const CLUSTER_RECONCILE_FAILED: Urn<'static> = crate::urn!(TIGHTBEAM_NID, "event:cluster/reconcile-failed");

//! Origin and freshness checks for signed cluster control frames.

use crate::colony::cluster::runtime::bounds::GatewayReplayGuard;
use crate::colony::cluster::ClusterConfig;
use crate::policy::{GatePolicy, SessionContext, TransitStatus};
use crate::trace::TraceCollector;
use crate::Frame;

/// Run collector gate policies before decoding the request envelope.
pub(crate) fn evaluate_gates(
	frame: &Frame,
	session: &SessionContext,
	config: &ClusterConfig,
	trace: &TraceCollector,
) -> Result<(), TransitStatus> {
	for policy in config.policies.iter() {
		let status = GatePolicy::evaluate(policy.as_ref(), Some(frame), session);
		if status != TransitStatus::Ok {
			let _ = trace.event(crate::instrumentation::events::CLUSTER_GATE_BLOCKED);
			return Err(status);
		}
	}
	Ok(())
}

/// Hive-origin control frames verify against `tls.hive_trust` (CWE-306).
pub(crate) fn verify_hive_origin(config: &ClusterConfig, frame: &Frame) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		match config.tls.hive_trust.as_ref() {
			Some(trust) => match crate::colony::hive::verify_frame_signature(trust.as_ref(), frame) {
				crate::colony::hive::TrustVerification::Verified => TransitStatus::Ok,
				crate::colony::hive::TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (config, frame);
		TransitStatus::Ok
	}
}

/// Peer-origin control frames verify against `tls.peer_trust` (CWE-306).
pub(crate) fn verify_peer_origin(config: &ClusterConfig, frame: &Frame) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		match config.tls.peer_trust.as_ref() {
			Some(trust) => match crate::colony::hive::verify_frame_signature(trust.as_ref(), frame) {
				crate::colony::hive::TrustVerification::Verified => TransitStatus::Ok,
				crate::colony::hive::TrustVerification::MissingSignature => TransitStatus::Unauthenticated,
				_ => TransitStatus::PermissionDenied,
			},
			None => TransitStatus::PermissionDenied,
		}
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (config, frame);
		TransitStatus::Ok
	}
}

/// Freshness + replay partition for signed control frames (CWE-294).
pub(crate) fn verify_control_freshness(frame: &Frame, replay_guard: &GatewayReplayGuard) -> TransitStatus {
	#[cfg(feature = "x509")]
	{
		let now = crate::colony::common::current_timestamp_ms();
		if !replay_guard.is_fresh(frame.metadata.order, now) {
			return TransitStatus::PermissionDenied;
		}

		let Some(signer_info) = frame.nonrepudiation.as_ref() else {
			return TransitStatus::Unauthenticated;
		};

		let Ok(signer_id) = crate::der::Encode::to_der(&signer_info.sid) else {
			return TransitStatus::PermissionDenied;
		};
		if !replay_guard.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
	#[cfg(not(feature = "x509"))]
	{
		let _ = (frame, replay_guard);
		TransitStatus::Ok
	}
}

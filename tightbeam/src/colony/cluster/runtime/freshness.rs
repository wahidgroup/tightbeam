//! Freshness admission for signed gateway control frames.
//!
//! [`GatewayReplayGuard`] is the one home for how a gateway spends and
//! returns a control frame's replay slot.
//!
//! # Sources
//!
//! - CWE-294, authentication bypass by capture-replay:
//!   <https://cwe.mitre.org/data/definitions/294.html>

use std::sync::Arc;

use crate::colony::common::current_timestamp_ms;
use crate::colony::hive::ReplayGuard;
use crate::policy::TransitStatus;
use crate::Frame;

/// Ledger that admits each signed control frame once.
pub(crate) struct GatewayReplayGuard(Arc<ReplayGuard>);

impl GatewayReplayGuard {
	/// Admits a frame once inside `window_ms` of its stated order.
	pub(crate) fn new(window_ms: u64) -> Self {
		Self(Arc::new(ReplayGuard::new(window_ms)))
	}

	/// Whether `frame` is a fresh, first-seen signed control frame.
	///
	/// The checks apply in order:
	///
	/// 1. Reject when `metadata.order` falls outside the freshness window.
	/// 2. Require non-repudiation (`signer_info`) on the frame.
	/// 3. Insert the signature in the ledger, refusing a duplicate.
	pub(crate) fn admits(&self, frame: &Frame) -> TransitStatus {
		let now = current_timestamp_ms();
		if !self.0.is_fresh(frame.metadata.order, now) {
			return TransitStatus::PermissionDenied;
		}

		let Some(signer_info) = frame.nonrepudiation.as_ref() else {
			return TransitStatus::Unauthenticated;
		};
		let Some(signer_id) = frame.signer_id() else {
			return TransitStatus::PermissionDenied;
		};
		if !self.0.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}

	/// Returns the slot `frame` spent, so a refused frame stays admissible.
	///
	/// A gateway that refuses after admission would otherwise consume the
	/// peer's one chance to send that frame (CWE-645).
	pub(crate) fn release(&self, frame: &Frame) {
		if let Some(signer_info) = frame.nonrepudiation.as_ref() {
			self.0.forget(signer_info.signature.as_bytes());
		}
	}
}

impl Clone for GatewayReplayGuard {
	fn clone(&self) -> Self {
		Self(Arc::clone(&self.0))
	}
}

//! Freshness admission for signed gateway control frames.
//!
//! [`GatewayReplayGuard`] is the one home for how a gateway spends and
//! returns a control frame's replay slot.
//!
//! # Sources
//!
//! - CWE-294, authentication bypass by capture-replay:
//!   <https://cwe.mitre.org/data/definitions/294.html>

use crate::colony::common::IssuedAt;
use crate::colony::hive::ReplayGuard;
use crate::policy::TransitStatus;
use crate::utils::time::Clock;
use crate::Frame;
use core::time::Duration;
use std::sync::Arc;

/// Ledger that admits each signed control frame once.
pub(crate) struct GatewayReplayGuard {
	ledger: Arc<ReplayGuard>,
	/// The gateway's clock, which freshness is judged against.
	clock: Arc<dyn Clock>,
}

impl GatewayReplayGuard {
	/// Admits a frame once inside `window` of its stated issue time, as
	/// `clock` reads it.
	pub(crate) fn new(window: Duration, clock: Arc<dyn Clock>) -> Self {
		Self { ledger: Arc::new(ReplayGuard::new(window)), clock }
	}

	/// Whether `frame` is a fresh, first-seen signed control frame.
	///
	/// The checks apply in order:
	///
	/// 1. Reject when `metadata.order` falls outside the freshness window.
	/// 2. Require non-repudiation (`signer_info`) on the frame.
	/// 3. Insert the signature in the ledger, refusing a duplicate.
	pub(crate) fn admits(&self, frame: &Frame) -> TransitStatus {
		let now = self.clock.unix();
		if !self.ledger.is_fresh(frame.issued_at(), now) {
			return TransitStatus::PermissionDenied;
		}

		let Some(signer_info) = frame.nonrepudiation() else {
			return TransitStatus::Unauthenticated;
		};
		let Some(signer_id) = frame.signer_id() else {
			return TransitStatus::PermissionDenied;
		};
		if !self.ledger.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}

	/// Returns the slot `frame` spent, so a refused frame stays admissible.
	///
	/// A gateway that refuses after admission would otherwise consume the
	/// peer's one chance to send that frame (CWE-645).
	pub(crate) fn release(&self, frame: &Frame) {
		if let Some(signer_info) = frame.nonrepudiation() {
			self.ledger.forget(signer_info.signature.as_bytes());
		}
	}
}

impl Clone for GatewayReplayGuard {
	fn clone(&self) -> Self {
		Self { ledger: Arc::clone(&self.ledger), clock: Arc::clone(&self.clock) }
	}
}

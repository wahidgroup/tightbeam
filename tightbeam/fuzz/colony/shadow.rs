//! Independent shadow oracle for the colony harness export boundary.
//!
//! The shadow predicts allow or deny from harness-owned state: the dynamic
//! export list, ACL, policy gate, and fixed trust sets. It does not call
//! production `ExportPolicy::verdict`. The only shared production classifier
//! is [`TrustPlanes`], reused for the first-party origin stage. Drift
//! versus the live wire is the detection signal, not a defect. Wire
//! allowed and shadow denied fires `SHADOW_VIOLATION`. Wire denied and
//! shadow allowed fires `SHADOW_TOO_CLOSED`.
//!
//! # Composition
//!
//! [`GatewayShadow::predict`] walks one fixed order that mirrors the
//! production export stack (allowlist, grants, first-party origin, with
//! deny gates and the pre-decode policy gate ahead of it):
//!
//! 1. Pre-decode policy gate (`DynamicPolicyGate`)
//! 2. ACL deny gate
//! 3. Export allowlist
//! 4. ACL grant on origin requests only
//! 5. First-party origin via [`TrustPlanes`]
//!
//! # Peer advertisement
//!
//! [`GatewayShadow::predict_peer_ad`] models the pre-decode gate and the
//! fixed peer-trust set only. It does not model frame-signature checks,
//! freshness or replay guards, admit binding, or slate caps. The harness
//! keeps those stages non-refusing on the positive path by construction
//! (monotonic `control_order`, single-type slates). [`Prediction::Unmodeled`]
//! skips both oracle directions so an unmodeled stage cannot look like a
//! shadow miss.

use std::sync::Arc;

use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist, TrustPlanes};
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::Certificate;
use tightbeam::utils::urn::Urn;

use crate::acl::DynamicAclState;
use crate::policy::DynamicPolicyGate;

/// Prediction inputs for one work, stream, or CSR attempt.
pub(crate) struct AccessAttempt<'a> {
	/// Servlet type under the export boundary.
	pub target: &'a Urn<'static>,
	/// Caller certificate when the dial presents one; `None` for anonymous.
	pub caller_cert: Option<&'a Certificate>,
	/// Precomputed SPKI DER for ACL lookups; `None` when anonymous.
	pub caller_spki: Option<&'a [u8]>,
	/// `true` when the request carries a spent hop budget (peer-relayed).
	pub relayed: bool,
}

/// Tri-state shadow verdict for the security oracle.
///
/// [`Prediction::Allow`] and [`Prediction::Deny`] feed `SHADOW_VIOLATION`
/// and `SHADOW_TOO_CLOSED`. [`Prediction::Unmodeled`] skips both directions
/// when the outcome depends on state this shadow does not model (for
/// example mixed multi-hop verdicts or slate caps). Plain outcome events
/// still emit in that case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prediction {
	/// Shadow expects the wire to allow.
	Allow,
	/// Shadow expects the wire to deny.
	Deny,
	/// Outcome depends on unmodeled stages; skip both oracle directions.
	Unmodeled,
}

/// Per-gateway shadow of the export boundary and pre-decode gate.
pub(crate) struct GatewayShadow {
	/// Live export allowlist shared with the gateway config.
	pub exports: Arc<DynamicExportList>,
	/// Grant and deny ACL state behind the export grant and gate plugs.
	pub acl: Arc<DynamicAclState>,
	/// Pre-decode GatePolicy toggle shared with the gateway config.
	pub policy_gate: Arc<DynamicPolicyGate>,
	/// Trust store that marks first-party hive callers.
	pub hive_trust: Arc<dyn CertificateTrust>,
	/// Trust store that marks peer-gateway callers.
	pub peer_trust: Arc<dyn CertificateTrust>,
}

impl GatewayShadow {
	/// Predict allow or deny for one access attempt against harness state.
	///
	/// Per-attempt work is borrows only. Fixture code encodes SPKI DER once
	/// per identity; this path never re-encodes it.
	pub fn predict(&self, attempt: &AccessAttempt<'_>) -> Prediction {
		if self.policy_gate.is_rejecting() {
			return Prediction::Deny;
		}
		if self.acl.is_denied(attempt.caller_spki) {
			return Prediction::Deny;
		}
		if self.exports.contains(attempt.target) {
			return Prediction::Allow;
		}

		if !attempt.relayed && self.acl.is_granted(attempt.caller_spki, attempt.target) {
			return Prediction::Allow;
		}

		let planes = TrustPlanes::new(Some(self.hive_trust.as_ref()), Some(self.peer_trust.as_ref()));
		if !attempt.relayed && planes.is_first_party(attempt.caller_cert) {
			return Prediction::Allow;
		}

		Prediction::Deny
	}

	/// Predict whether a signed peer advertisement from `signer` admits.
	///
	/// Covers the pre-decode gate and peer-trust membership only. Other
	/// wire stages stay non-refusing by harness construction (see the
	/// module header).
	pub fn predict_peer_ad(&self, signer: &Certificate) -> Prediction {
		if self.policy_gate.is_rejecting() {
			return Prediction::Deny;
		}
		if self.peer_trust.is_trusted(signer) {
			return Prediction::Allow;
		}

		Prediction::Deny
	}
}

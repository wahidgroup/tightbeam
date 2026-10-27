//! Independent shadow oracle for the colony harness export boundary.
//!
//! The shadow predicts allow or deny from harness-owned state: the dynamic
//! export list, the ACL, the policy gate, and the fixed trust sets. It
//! predicts every stage in place of the production `ExportPolicy::verdict`,
//! and it shares two production parts:
//!
//! - [`TrustPlanes`], which the first-party origin stage reuses.
//! - [`CanonicalKey`], which keys the ACL, so the key rule rests on its own tests.
//!
//! A drift from the live wire is the detection signal, not a defect:
//!
//! - When the wire allows and the shadow denies, the oracle fires `SHADOW_VIOLATION`.
//! - When the wire denies and the shadow allows, the oracle fires `SHADOW_TOO_CLOSED`.
//!
//! # Composition
//!
//! [`GatewayShadow::predict`] walks one fixed order that follows the
//! production export stack (allowlist, grants, first-party origin, with
//! deny gates and the pre-decode policy gate ahead of it):
//!
//! 1. Pre-decode policy gate (`DynamicPolicyGate`)
//! 2. ACL deny gate
//! 3. Export allowlist
//! 4. ACL grant on origin requests only
//! 5. First-party origin through [`TrustPlanes`]
//!
//! # Peer advertisement
//!
//! [`GatewayShadow::predict_peer_ad`] models the pre-decode gate and the
//! fixed peer-trust set only. The harness builds its inputs so that the other
//! stages pass on the positive path (monotonic `control_order`, single-type
//! slates):
//!
//! - Frame-signature checks.
//! - Freshness and replay guards.
//! - Admit binding.
//! - Slate caps.
//!
//! [`Prediction::Unmodeled`] skips both oracle directions so an unmodeled
//! stage cannot look like a shadow miss.

use std::sync::Arc;

use tightbeam::colony::cluster::{DynamicExportList, ExportAllowlist, Party, TrustPlaneStores, TrustPlanes};
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::{CanonicalKey, Certificate};
use tightbeam::urn::Urn;

use crate::acl::DynamicAclState;
use crate::policy::DynamicPolicyGate;

/// Prediction inputs for one work, stream, or CSR attempt.
pub(crate) struct AccessAttempt<'a> {
	/// Servlet type under the export boundary.
	pub target: &'a Urn<'static>,
	/// Caller certificate when the dial presents one, or `None` when anonymous.
	pub caller_cert: Option<&'a Certificate>,
	/// The canonical key the fixtures read for ACL lookups, or `None` when
	/// anonymous.
	pub caller_key: Option<&'a CanonicalKey>,
	/// `true` when the request carries a spent hop budget (peer-relayed).
	pub relayed: bool,
}

/// Tri-state shadow verdict for the security oracle.
///
/// [`Prediction::Allow`] and [`Prediction::Deny`] feed `SHADOW_VIOLATION`
/// and `SHADOW_TOO_CLOSED`. [`Prediction::Unmodeled`] skips both directions
/// when the outcome depends on state outside this shadow's model (for
/// example mixed multi-hop verdicts or slate caps). Plain outcome events
/// still emit in that case.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Prediction {
	/// The shadow expects the wire to allow.
	Allow,
	/// The shadow expects the wire to deny.
	Deny,
	/// The outcome depends on unmodeled stages, so the oracle skips both
	/// directions.
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
	/// The fixtures read the canonical key once per identity, so the work of
	/// each attempt only borrows it.
	pub fn predict(&self, attempt: &AccessAttempt<'_>) -> Prediction {
		if self.policy_gate.is_rejecting() {
			return Prediction::Deny;
		}
		if self.acl.is_denied(attempt.caller_key) {
			return Prediction::Deny;
		}
		if self.exports.contains(attempt.target) {
			return Prediction::Allow;
		}
		if !attempt.relayed && self.acl.is_granted(attempt.caller_key, attempt.target) {
			return Prediction::Allow;
		}

		let planes = TrustPlanes::new(TrustPlaneStores {
			hive: Some(self.hive_trust.as_ref()),
			peer: Some(self.peer_trust.as_ref()),
		});
		let first_party = matches!(planes.classify(attempt.caller_cert), Party::FirstParty);
		if !attempt.relayed && first_party {
			return Prediction::Allow;
		}

		Prediction::Deny
	}

	/// Predict whether a signed peer advertisement from `signer` admits.
	///
	/// It covers the pre-decode gate and peer-trust membership only. The
	/// harness builds its inputs so that the other wire stages pass (see the
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

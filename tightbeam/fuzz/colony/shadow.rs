//! Shadow model for export allow/deny prediction.

use std::sync::Arc;

use tightbeam::colony::cluster::{cert_is_first_party, DynamicExportList, ExportAllowlist};
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::Certificate;
use tightbeam::utils::urn::Urn;

use crate::acl::DynamicAclState;
use crate::policy::DynamicPolicyGate;

/// Prediction inputs for one work/stream/CSR attempt.
pub(crate) struct AccessAttempt<'a> {
	pub target: &'a Urn<'static>,
	pub caller_cert: Option<&'a Certificate>,
	pub caller_spki: Option<&'a [u8]>,
	pub relayed: bool,
}

/// Per-gateway shadow of the export boundary and pre-decode gate.
pub(crate) struct GatewayShadow {
	pub exports: Arc<DynamicExportList>,
	pub acl: Arc<DynamicAclState>,
	pub policy_gate: Arc<DynamicPolicyGate>,
	pub hive_trust: Arc<dyn CertificateTrust>,
	pub peer_trust: Arc<dyn CertificateTrust>,
}

impl GatewayShadow {
	/// Whether the production composition order should allow this attempt.
	pub fn allows(&self, attempt: &AccessAttempt<'_>) -> bool {
		if self.policy_gate.is_rejecting() {
			return false;
		}

		if self.acl.is_denied(attempt.caller_spki) {
			return false;
		}

		let exported = self.exports.contains(attempt.target);
		if exported {
			return true;
		}

		if self.acl.is_granted(attempt.caller_spki, attempt.target) && !attempt.relayed {
			return true;
		}

		if !attempt.relayed
			&& cert_is_first_party(
				attempt.caller_cert,
				Some(self.hive_trust.as_ref()),
				Some(self.peer_trust.as_ref()),
			) {
			return true;
		}

		false
	}
}

//! Dynamic export grants and deny gates for the colony fuzz.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use tightbeam::colony::cluster::{ExportGate, ExportGrant};
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::utils::urn::Urn;

/// Shared mutable grant/gate tables for one gateway.
#[derive(Default)]
pub(crate) struct DynamicAclState {
	/// SPKI DER bytes granted per target URN string.
	grants: RwLock<HashSet<(Vec<u8>, String)>>,
	/// SPKI DER bytes denied for any target when present.
	denied: RwLock<HashSet<Vec<u8>>>,
}

impl DynamicAclState {
	pub fn grant(&self, spki: Vec<u8>, target: &Urn<'_>) {
		if let Ok(mut guard) = self.grants.write() {
			guard.insert((spki, target.to_string()));
		}
	}

	pub fn revoke_grant(&self, spki: &[u8], target: &Urn<'_>) {
		if let Ok(mut guard) = self.grants.write() {
			guard.remove(&(spki.to_vec(), target.to_string()));
		}
	}

	pub fn deny(&self, spki: Vec<u8>) {
		if let Ok(mut guard) = self.denied.write() {
			guard.insert(spki);
		}
	}

	pub fn allow(&self, spki: &[u8]) {
		if let Ok(mut guard) = self.denied.write() {
			guard.remove(spki);
		}
	}

	pub fn is_granted(&self, spki: Option<&[u8]>, target: &Urn<'_>) -> bool {
		let Some(spki) = spki else {
			return false;
		};
		let Ok(guard) = self.grants.read() else {
			return false;
		};

		guard.contains(&(spki.to_vec(), target.to_string()))
	}

	pub fn is_denied(&self, spki: Option<&[u8]>) -> bool {
		let Some(spki) = spki else {
			return false;
		};
		let Ok(guard) = self.denied.read() else {
			return true;
		};

		guard.contains(spki)
	}
}

/// Grant that consults a shared [`DynamicAclState`].
pub(crate) struct DynamicGrant {
	pub state: Arc<DynamicAclState>,
}

impl ExportGrant for DynamicGrant {
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool {
		if relayed {
			return false;
		}

		self.state.is_granted(session.peer_public_key(), target)
	}
}

/// Deny gate that consults a shared [`DynamicAclState`].
pub(crate) struct DynamicDenyGate {
	pub state: Arc<DynamicAclState>,
}

impl ExportGate for DynamicDenyGate {
	fn evaluate(&self, _target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> TransitStatus {
		if self.state.is_denied(session.peer_public_key()) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
}

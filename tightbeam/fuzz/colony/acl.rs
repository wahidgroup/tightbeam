//! Dynamic export grants and deny gates for the colony fuzz.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use tightbeam::colony::cluster::{ExportGate, ExportGrant, TrustPlanes};
use tightbeam::crypto::x509::CanonicalKey;
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::urn::Urn;

/// Shared mutable grant and deny tables for one gateway.
#[derive(Default)]
pub(crate) struct DynamicAclState {
	/// The canonical keys granted per target URN string.
	grants: RwLock<HashMap<CanonicalKey, HashSet<String>>>,
	/// The canonical keys denied for any target when present.
	denied: RwLock<HashSet<CanonicalKey>>,
}

impl DynamicAclState {
	/// Grant `target` to `key`, the canonical key of the grantee.
	pub fn grant(&self, key: &CanonicalKey, target: &Urn<'_>) {
		if let Ok(mut guard) = self.grants.write() {
			guard.entry(key.clone()).or_default().insert(target.to_string());
		}
	}

	pub fn revoke_grant(&self, key: &CanonicalKey, target: &Urn<'_>) {
		if let Ok(mut guard) = self.grants.write() {
			let empty = if let Some(targets) = guard.get_mut(key) {
				targets.remove(&target.to_string());
				targets.is_empty()
			} else {
				false
			};
			if empty {
				guard.remove(key);
			}
		}
	}

	pub fn deny(&self, key: &CanonicalKey) {
		if let Ok(mut guard) = self.denied.write() {
			guard.insert(key.clone());
		}
	}

	pub fn allow(&self, key: &CanonicalKey) {
		if let Ok(mut guard) = self.denied.write() {
			guard.remove(key);
		}
	}

	/// Whether `key` holds a grant to `target`, by a lookup that borrows the
	/// canonical key the session holds.
	pub fn is_granted(&self, key: Option<&CanonicalKey>, target: &Urn<'_>) -> bool {
		let Some(key) = key else {
			return false;
		};
		let Ok(guard) = self.grants.read() else {
			return false;
		};

		let target = target.to_string();
		guard.get(key).is_some_and(|targets| targets.contains(&target))
	}

	pub fn is_denied(&self, key: Option<&CanonicalKey>) -> bool {
		let Some(key) = key else {
			return false;
		};
		let Ok(guard) = self.denied.read() else {
			return true;
		};

		guard.contains(key)
	}
}

/// Grant that consults a shared [`DynamicAclState`].
pub(crate) struct DynamicGrant {
	/// Shared grant and deny tables consulted on each evaluation.
	pub state: Arc<DynamicAclState>,
}

impl ExportGrant for DynamicGrant {
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, relayed: bool) -> bool {
		if relayed {
			return false;
		}

		self.state.is_granted(session.peer_key(), target)
	}
}

/// Deny gate that consults a shared [`DynamicAclState`].
pub(crate) struct DynamicDenyGate {
	/// Shared grant and deny tables consulted on each evaluation.
	pub state: Arc<DynamicAclState>,
}

impl ExportGate for DynamicDenyGate {
	fn evaluate(
		&self,
		_target: &Urn<'_>,
		session: &SessionContext,
		_planes: &TrustPlanes<'_>,
		_relayed: bool,
	) -> TransitStatus {
		if self.state.is_denied(session.peer_key()) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
}

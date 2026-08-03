//! Dynamic export grants and deny gates for the colony fuzz.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use tightbeam::colony::cluster::{ExportGate, ExportGrant, TrustPlanes};
use tightbeam::policy::{SessionContext, TransitStatus};
use tightbeam::utils::urn::Urn;

/// Shared mutable grant/gate tables for one gateway.
#[derive(Default)]
pub(crate) struct DynamicAclState {
	/// SPKI DER bytes granted per target URN string.
	grants: RwLock<HashMap<Vec<u8>, HashSet<String>>>,
	/// SPKI DER bytes denied for any target when present.
	denied: RwLock<HashSet<Vec<u8>>>,
}

impl DynamicAclState {
	/// `spki` accepts any type that converts via `AsRef<[u8]>`.
	pub fn grant(&self, spki: impl AsRef<[u8]>, target: &Urn<'_>) {
		if let Ok(mut guard) = self.grants.write() {
			guard.entry(spki.as_ref().to_vec()).or_default().insert(target.to_string());
		}
	}

	pub fn revoke_grant(&self, spki: impl AsRef<[u8]>, target: &Urn<'_>) {
		let spki = spki.as_ref();
		if let Ok(mut guard) = self.grants.write() {
			let empty = if let Some(targets) = guard.get_mut(spki) {
				targets.remove(&target.to_string());
				targets.is_empty()
			} else {
				false
			};
			if empty {
				guard.remove(spki);
			}
		}
	}

	pub fn deny(&self, spki: impl AsRef<[u8]>) {
		if let Ok(mut guard) = self.denied.write() {
			guard.insert(spki.as_ref().to_vec());
		}
	}

	pub fn allow(&self, spki: impl AsRef<[u8]>) {
		if let Ok(mut guard) = self.denied.write() {
			guard.remove(spki.as_ref());
		}
	}

	/// Lookup borrows the SPKI bytes through [`HashMap`]'s `Borrow<[u8]>`
	/// support, so the hot path does not allocate a temporary SPKI key.
	pub fn is_granted(&self, spki: Option<&[u8]>, target: &Urn<'_>) -> bool {
		let Some(spki) = spki else {
			return false;
		};
		let Ok(guard) = self.grants.read() else {
			return false;
		};

		let target = target.to_string();
		guard.get(spki).is_some_and(|targets| targets.contains(&target))
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
	/// Shared grant and deny tables consulted on each evaluation.
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
		if self.state.is_denied(session.peer_public_key()) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
}

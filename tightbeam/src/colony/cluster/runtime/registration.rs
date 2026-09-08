//! Hive registration and servlet address-update request handlers.

use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayRuntimeCtx;
use crate::colony::common::{reply_frame, RegisterHiveRequest, ServletAddressUpdate};
use crate::colony::hive::{RegisterHiveResponse, ServletAddressUpdateResponse};
use crate::instrumentation::events::{
	CLUSTER_HIVE_REGISTERED, CLUSTER_REGISTER_REFUSED, CLUSTER_UPDATE_ACCEPTED, CLUSTER_UPDATE_REFUSED,
};
use crate::policy::TransitStatus;
use crate::transport::Protocol;
use crate::Frame;
use crate::TightBeamError;

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Admit one hive registration and install its servlet slate.
	pub(crate) async fn handle_register(
		&self,
		frame: Frame,
		request: RegisterHiveRequest,
	) -> Result<Option<Frame>, TightBeamError> {
		if let Err(status) = self.admit_hive_control(&frame) {
			return self.refuse_register(&frame, status);
		}

		// Instance URN locator MUST equal route address (CWE-639).
		let locators_ok = request
			.servlet_addresses
			.iter()
			.all(|info| self.config.namespace.locator_matches(info));
		if !locators_ok {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		}

		// Admit addresses that mint an exact hive identity URN.
		let Some(hive_identity) = self.config.namespace.hive_from_bytes(&request.hive_addr) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		};

		// A hive registered with no signer is claimable by the next signer
		// that names it, so an identifier that does not encode refuses here
		// rather than installing an unbound entry (CWE-639).
		let Some(signer_id) = frame.signer_id().map(Arc::from) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		};

		let hive_addr: Arc<[u8]> = request.hive_addr.clone().into();
		let slate = self.config.pheromone.servlet_slate(&request.servlet_addresses, &hive_addr);
		// Atomic: hive entry + full slate, or roll back. Re-register replaces prior rows.
		let registered = self.registry.register(request, signer_id).and_then(|()| {
			self.servlet_registry.reconcile_by_hive(&hive_addr, slate).inspect_err(|_| {
				let _ = self.registry.unregister(&hive_addr);
				let _ = self.servlet_registry.remove_by_hive(&hive_addr);
			})
		});

		match registered {
			Ok(()) => {
				let hive_count = self.registry.len().unwrap_or_default() as u64;
				self.trace.event_with(CLUSTER_HIVE_REGISTERED, &[], hive_count)?;

				let response = RegisterHiveResponse { status: TransitStatus::Ok, hive_id: Some(hive_identity) };
				reply_frame(&frame.metadata.id, response)
			}
			Err(_) => {
				// Forget replay so a legitimate retry of the same signed frame can proceed.
				self.refuse_register_release(&frame, TransitStatus::PermissionDenied)
			}
		}
	}

	/// Admit a servlet address update and apply the delta under signer bind.
	/// Apply one hive's servlet address additions and removals.
	pub(crate) async fn handle_address_update(
		&self,
		frame: Frame,
		update: ServletAddressUpdate,
	) -> Result<Option<Frame>, TightBeamError> {
		if let Err(status) = self.admit_hive_control(&frame) {
			return self.refuse_update(&frame, status);
		}

		let Some((hive_id, added, removed)) = self.config.parse_address_update(&update) else {
			return self.refuse_update(&frame, TransitStatus::PermissionDenied);
		};

		// Signer MUST match the hive bound at registration (CWE-639).
		if !self.registry.signer_matches(&frame, &hive_id) {
			return self.refuse_update_release(&frame, TransitStatus::PermissionDenied);
		}

		match self.servlet_registry.apply_address_update(&hive_id, added, &removed) {
			Ok(()) => {
				self.trace.event(CLUSTER_UPDATE_ACCEPTED)?;

				let response = ServletAddressUpdateResponse { status: TransitStatus::Ok };
				reply_frame(&frame.metadata.id, response)
			}
			Err(_) => {
				// Forget replay so the hive can resend the same signed update.
				self.refuse_update_release(&frame, TransitStatus::PermissionDenied)
			}
		}
	}

	/// Origin and freshness gate shared by register and address-update.
	fn admit_hive_control(&self, frame: &Frame) -> Result<(), TransitStatus> {
		let origin_status = self.config.verify_hive_origin(frame);
		if origin_status != TransitStatus::Ok {
			return Err(origin_status);
		}

		let freshness_status = self.replay_guard.admits(frame);
		if freshness_status != TransitStatus::Ok {
			return Err(freshness_status);
		}

		Ok(())
	}

	/// Answer a registration with `status` and no hive identity.
	fn refuse_register(&self, frame: &Frame, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace.event(CLUSTER_REGISTER_REFUSED)?;

		let response = RegisterHiveResponse { status, hive_id: None };
		reply_frame(&frame.metadata.id, response)
	}

	/// Refuse a registration and return the replay slot the frame spent, so
	/// the hive can retry the same signed frame.
	fn refuse_register_release(&self, frame: &Frame, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(frame);
		self.refuse_register(frame, status)
	}

	/// Answer an address update with `status`.
	fn refuse_update(&self, frame: &Frame, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.trace.event(CLUSTER_UPDATE_REFUSED)?;

		let response = ServletAddressUpdateResponse { status };
		reply_frame(&frame.metadata.id, response)
	}

	/// Refuse an address update and return the replay slot the frame spent,
	/// so the hive can resend the same signed update.
	fn refuse_update_release(&self, frame: &Frame, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(frame);
		self.refuse_update(frame, status)
	}
}

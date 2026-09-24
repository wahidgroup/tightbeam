//! Hive registration and servlet address-update request handlers.

use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayRuntimeCtx;
use crate::colony::cluster::{ClusterError, DialTarget};
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
	) -> Result<Option<Frame>, TightBeamError>
	where
		P::Address: FromStr,
	{
		if let Err(status) = self.admit_hive_control(&frame) {
			return self.refuse_register(&frame, status);
		}

		// Each instance URN locator MUST equal its route address (CWE-639).
		let locators_ok = request
			.servlet_addresses
			.iter()
			.all(|info| self.config.namespace.locator_matches(info));
		if !locators_ok {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		}

		// Admit only a hive address that yields an exact hive identity URN.
		let Some(hive_identity) = self.config.namespace.hive_from_bytes(&request.hive_addr) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		};

		// The heartbeat dials the control address, so a hive the protocol
		// cannot parse would register, go unbeaten, and leave by silent
		// eviction. The check runs before anything is installed.
		let hive_addr: Arc<[u8]> = request.hive_addr.clone().into();
		if DialTarget::of_registered(&hive_addr).protocol_address::<P::Address>().is_err() {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		}

		// A hive registered with no signer is claimable by the next signer
		// that names it, so an identifier that does not encode refuses here
		// rather than installing an unbound entry (CWE-639).
		let Some(signer_id) = frame.signer_id().map(Arc::from) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied);
		};

		let slate = self.config.pheromone.servlet_slate(&request.servlet_addresses, &hive_addr);
		// The membership step installs the hive entry and its full slate
		// atomically, or rolls both back. A re-registration replaces the
		// prior rows.
		let registered = self.membership().admit(request, signer_id, slate);
		let counted = registered.and_then(|()| self.registry.len());
		match counted {
			Ok(hive_count) => {
				let hive_count = u64::try_from(hive_count).unwrap_or(u64::MAX);
				self.trace.event_with(CLUSTER_HIVE_REGISTERED, &[], hive_count)?;

				let response = RegisterHiveResponse { status: TransitStatus::Ok, hive_id: Some(hive_identity) };
				reply_frame(frame.metadata().id(), response)
			}
			Err(error) => {
				// Releasing the replay slot lets a legitimate retry of the
				// same signed frame proceed.
				self.refuse_register_release(&frame, refusal_status(&error))
			}
		}
	}

	/// Apply one hive's servlet address additions and removals.
	pub(crate) async fn handle_address_update(
		&self,
		frame: Frame,
		update: ServletAddressUpdate,
	) -> Result<Option<Frame>, TightBeamError> {
		if let Err(status) = self.admit_hive_control(&frame) {
			return self.refuse_update(&frame, status);
		}

		let Some((added, removed)) = self.config.parse_address_update(&update) else {
			return self.refuse_update(&frame, TransitStatus::PermissionDenied);
		};

		// A hive registered with no signer is claimable by the next signer
		// that names it, so an unsigned update refuses here rather than
		// reaching the bind check (CWE-639).
		let Some(signer_id) = frame.signer_id().map(Arc::from) else {
			return self.refuse_update_release(&frame, TransitStatus::PermissionDenied);
		};

		// The signer bind and the route write are one membership step, so
		// a retirement cannot land between them (CWE-362).
		match self.membership().update_addresses(&signer_id, added, &removed) {
			Ok(()) => {
				self.trace.event(CLUSTER_UPDATE_ACCEPTED)?;

				let response = ServletAddressUpdateResponse { status: TransitStatus::Ok };
				reply_frame(frame.metadata().id(), response)
			}
			Err(error) => {
				// Releasing the replay slot lets the hive resend the same
				// signed update.
				self.refuse_update_release(&frame, refusal_status(&error))
			}
		}
	}

	/// Origin and freshness gate shared by register and address-update.
	fn admit_hive_control(&self, frame: &Frame) -> Result<(), TransitStatus> {
		self.config.verify_hive(frame)?;

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
		reply_frame(frame.metadata().id(), response)
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
		reply_frame(frame.metadata().id(), response)
	}

	/// Refuse an address update and return the replay slot the frame spent,
	/// so the hive can resend the same signed update.
	fn refuse_update_release(&self, frame: &Frame, status: TransitStatus) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(frame);
		self.refuse_update(frame, status)
	}
}

/// The status a refused membership move answers with.
///
/// A poisoned registry is this gateway's fault, so the hive is told the
/// gateway is unavailable rather than that it lacks the right to register.
/// Every other refusal is a claim the gateway judged and denied.
fn refusal_status(error: &ClusterError) -> TransitStatus {
	match error {
		ClusterError::LockPoisoned => TransitStatus::Unavailable,
		_ => TransitStatus::PermissionDenied,
	}
}

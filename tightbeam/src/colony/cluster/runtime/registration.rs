//! Hive registration and servlet address-update request handlers.

use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayRuntimeCtx;
use crate::colony::cluster::runtime::verify::RequestAudit;
use crate::colony::cluster::DialTarget;
use crate::colony::protocol::{
	RegisterHiveRequest, RegisterHiveResponse, ReplyForm, ServletAddressUpdate, ServletAddressUpdateResponse,
};
use crate::crypto::sign::VerifiedSignature;
use crate::instrumentation::events::{
	CLUSTER_HIVE_REGISTERED, CLUSTER_REGISTER_REFUSED, CLUSTER_UPDATE_ACCEPTED, CLUSTER_UPDATE_REFUSED,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::transport::Protocol;
use crate::Frame;
use crate::TightBeamError;

/// A hive control frame that the origin and freshness gate admitted.
struct AdmittedControl<'a> {
	/// The signature that verified, the replay key a refusal releases.
	signature: VerifiedSignature,
	/// The audit trace, which each record of the request goes on.
	trace: &'a TraceCollector,
}

/// A hive control frame that the origin and freshness gate refused.
struct RefusedControl<'a> {
	/// The status that the hive reads.
	status: TransitStatus,
	/// The trace that the record of the refusal goes on.
	trace: &'a TraceCollector,
}

impl<P: Protocol> GatewayRuntimeCtx<P> {
	/// Admits one hive registration and installs its servlet slate.
	pub(crate) async fn handle_register(
		&self,
		frame: Frame,
		request: RegisterHiveRequest,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError>
	where
		P::Address: FromStr,
	{
		let AdmittedControl { signature, trace } = match self.admit_hive_control(&frame, audit) {
			Ok(admitted) => admitted,
			Err(refused) => return self.refuse_register(&frame, refused.status, refused.trace),
		};

		// The gateway admits only a hive address that yields an exact hive
		// identity URN.
		let Some(hive_identity) = self.config.namespace.hive_from_bytes(&request.hive_addr) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied, trace);
		};

		// The heartbeat dials the control address, so a hive whose address the
		// protocol cannot parse would register, get no heartbeat, and leave by
		// silent eviction. This check refuses it before the membership install.
		let hive_addr: Arc<[u8]> = request.hive_addr.clone().into();
		if DialTarget::of_registered(&hive_addr).protocol_address::<P::Address>().is_err() {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied, trace);
		}

		// A hive registered with no signer is claimable by the next signer
		// that names it, so the gateway refuses a frame that names none and
		// installs no unbound entry (CWE-639).
		let Some(signer) = frame.nonrepudiation().map(|info| Arc::new(info.sid.clone())) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied, trace);
		};

		// The slate constructor owns the locator rule, so the gateway refuses a
		// servlet that advertises one address under another's identity.
		let Ok(slate) = self.config.servlet_slate(&request.servlet_addresses, &hive_addr) else {
			return self.refuse_register(&frame, TransitStatus::PermissionDenied, trace);
		};

		// The membership step installs the hive entry and its full slate
		// atomically, or rolls both back. A re-registration replaces the
		// prior rows.
		match self.membership().admit(request, signer, slate) {
			Ok(hive_count) => {
				trace.emit_event_with_value_and_evidence(CLUSTER_HIVE_REGISTERED, "", hive_count, None)?;

				let response = RegisterHiveResponse { status: TransitStatus::Ok, hive_id: Some(hive_identity) };
				ReplyForm::Plain.reply(frame.metadata().id(), response)
			}
			Err(error) => {
				// A release of the replay slot lets a legitimate retry of the
				// same signed frame proceed.
				self.refuse_register_release(&frame, &signature, error.transit_status(), trace)
			}
		}
	}

	/// Applies one hive's servlet address additions and removals.
	pub(crate) async fn handle_address_update(
		&self,
		frame: Frame,
		update: ServletAddressUpdate,
		audit: &RequestAudit,
	) -> Result<Option<Frame>, TightBeamError> {
		let AdmittedControl { signature, trace } = match self.admit_hive_control(&frame, audit) {
			Ok(admitted) => admitted,
			Err(refused) => return self.refuse_update(&frame, refused.status, refused.trace),
		};

		let Some((added, removed)) = self.config.parse_address_update(&update) else {
			return self.refuse_update(&frame, TransitStatus::PermissionDenied, trace);
		};

		// A hive registered with no signer is claimable by the next signer
		// that names it, so the gateway refuses an unsigned update here, before
		// the bind check (CWE-639).
		let Some(signer) = frame.nonrepudiation().map(|info| &info.sid) else {
			return self.refuse_update_release(&frame, &signature, TransitStatus::PermissionDenied, trace);
		};

		// The signer bind and the route write are one membership step, so
		// a retirement lands before or after both (CWE-362).
		match self.membership().update_addresses(signer, added, &removed) {
			Ok(()) => {
				trace.emit_marker(CLUSTER_UPDATE_ACCEPTED)?;

				let response = ServletAddressUpdateResponse { status: TransitStatus::Ok };
				ReplyForm::Plain.reply(frame.metadata().id(), response)
			}
			Err(error) => {
				// A release of the replay slot lets the hive resend the same
				// signed update.
				self.refuse_update_release(&frame, &signature, error.transit_status(), trace)
			}
		}
	}

	/// The origin and freshness gate that register and address-update share.
	///
	/// A record goes on the audit trace once the signature verifies.
	fn admit_hive_control<'a>(
		&self,
		frame: &Frame,
		audit: &'a RequestAudit,
	) -> Result<AdmittedControl<'a>, RefusedControl<'a>> {
		let verified = match self.config.verify_hive(frame) {
			Ok(verified) => verified,
			Err(refusal) => return Err(RefusedControl { status: refusal.into(), trace: audit.unproven() }),
		};

		let signer = verified.fingerprint();
		let trace = audit.signed(Some(&signer));
		let signature = verified.into_signature();

		let freshness_status = self.replay_guard.admits(frame, &signature);
		if freshness_status != TransitStatus::Ok {
			return Err(RefusedControl { status: freshness_status, trace });
		}

		Ok(AdmittedControl { signature, trace })
	}

	/// Answers a registration with `status` and no hive identity, and records
	/// the refusal on `trace`.
	fn refuse_register(
		&self,
		frame: &Frame,
		status: TransitStatus,
		trace: &TraceCollector,
	) -> Result<Option<Frame>, TightBeamError> {
		trace.emit_event_with_value_and_evidence(CLUSTER_REGISTER_REFUSED, status.as_str(), status, None)?;

		let response = RegisterHiveResponse { status, hive_id: None };
		ReplyForm::Plain.reply(frame.metadata().id(), response)
	}

	/// Refuses a registration and frees the replay slot its `signature` spent,
	/// so the hive can retry the same signed frame.
	fn refuse_register_release(
		&self,
		frame: &Frame,
		signature: &VerifiedSignature,
		status: TransitStatus,
		trace: &TraceCollector,
	) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(signature);
		self.refuse_register(frame, status, trace)
	}

	/// Answers an address update with `status`, and records the refusal on
	/// `trace`.
	fn refuse_update(
		&self,
		frame: &Frame,
		status: TransitStatus,
		trace: &TraceCollector,
	) -> Result<Option<Frame>, TightBeamError> {
		trace.emit_event_with_value_and_evidence(CLUSTER_UPDATE_REFUSED, status.as_str(), (), None)?;

		let response = ServletAddressUpdateResponse { status };
		ReplyForm::Plain.reply(frame.metadata().id(), response)
	}

	/// Refuses an address update and frees the replay slot its `signature`
	/// spent, so the hive can resend the same signed update.
	fn refuse_update_release(
		&self,
		frame: &Frame,
		signature: &VerifiedSignature,
		status: TransitStatus,
		trace: &TraceCollector,
	) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(signature);
		self.refuse_update(frame, status, trace)
	}
}

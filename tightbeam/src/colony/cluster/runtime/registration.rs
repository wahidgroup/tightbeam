//! Hive registration and servlet address-update request handlers.

use core::str::FromStr;
use std::borrow::Cow;
use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::runtime::bounds::{ColonyConfig, GatewayRuntimeCtx};
use crate::colony::cluster::runtime::verify::{RequestAudit, VerifiedControlFrame, VerifiedSignerId};
use crate::colony::cluster::{ClusterConfig, ClusterError, DialTarget, HiveSlate};
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
use crate::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

/// A hive control frame that the origin and freshness gate admitted.
struct AdmittedControl<'a> {
	/// The frame that verified on the hive plane, which names its signer and
	/// holds the replay key a refusal releases.
	verified: VerifiedControlFrame<'a>,
	/// The audit trace, which each record of the request goes on.
	trace: &'a TraceCollector,
}

/// A hive registration that the gateway admits: what the membership step
/// installs, beside the hive identity the reply names.
struct AdmittedRegistration {
	/// The identity URN that the hive's address yields.
	hive_identity: Urn<'static>,
	/// The signer the verified frame names, which the hive's entry binds, so
	/// the next registration of the hive must come from it (CWE-639).
	signer: Arc<SignerIdentifier>,
	/// The slate of the hive's servlets, each under the locator rule.
	slate: HiveSlate,
	/// The request, which the membership step installs.
	request: RegisterHiveRequest,
}

impl AdmittedRegistration {
	/// Admits `request`, which `verified` carried, under the namespace and the
	/// slate rule of `config`.
	///
	/// The checks run in this order:
	///
	/// 1. The hive address MUST yield an exact hive identity URN.
	/// 2. The protocol MUST parse the hive address to dial. The heartbeat dials
	///    that address, so a hive whose address no dial reaches would register,
	///    get no heartbeat, and leave by silent eviction.
	/// 3. Each servlet MUST name the address beside it as its locator, so no
	///    servlet advertises one address under the identity of another.
	///
	/// # Errors
	///
	/// - [`TransitStatus::PermissionDenied`] -- a check above refuses the registration.
	fn admit<P>(
		verified: &VerifiedControlFrame<'_>,
		request: RegisterHiveRequest,
		config: &ColonyConfig<P>,
	) -> Result<Self, TransitStatus>
	where
		P: Protocol,
		P::Address: FromStr,
	{
		let Some(hive_identity) = config.namespace.hive_from_bytes(&request.hive_addr) else {
			return Err(TransitStatus::PermissionDenied);
		};

		let hive_addr: Arc<[u8]> = Arc::from(request.hive_addr.as_slice());
		let dialable = DialTarget::of_registered(&hive_addr).protocol_address::<P::Address>();
		if dialable.is_err() {
			return Err(TransitStatus::PermissionDenied);
		}

		let slate = config.servlet_slate(&request.servlet_addresses, &hive_addr);
		let slate = slate.map_err(|_| TransitStatus::PermissionDenied)?;
		let signer = Arc::new(verified.signer_identifier().clone());
		Ok(Self { hive_identity, signer, slate, request })
	}
}

/// A servlet address update that the gateway admits: the signer the
/// membership step checks, and the parsed delta.
struct AdmittedUpdate<'a> {
	/// The signer the verified frame names, which the hive's entry MUST bind.
	signer: &'a SignerIdentifier,
	/// The added routes, which the hive owns.
	added: HiveSlate,
	/// The locators of the instances the update removes, percent-decoded.
	removed: Vec<Cow<'a, [u8]>>,
}

impl<'a> AdmittedUpdate<'a> {
	/// Admits `update`, which `verified` carried, under the namespace and the
	/// slate rule of `config`.
	///
	/// # Errors
	///
	/// - [`ClusterError`] -- the errors of [`ClusterConfig::parse_address_update`].
	fn admit(
		verified: &VerifiedControlFrame<'a>,
		update: &'a ServletAddressUpdate,
		config: &ClusterConfig,
	) -> Result<Self, ClusterError> {
		let (added, removed) = config.parse_address_update(update)?;
		let signer = verified.signer_identifier();
		Ok(Self { signer, added, removed })
	}
}

/// A hive control frame that the origin and freshness gate refused, one
/// variant per cause.
enum RefusedControl<'a> {
	/// The frame's signature failed verification.
	Unverified {
		/// The status that the hive reads.
		status: TransitStatus,
		/// The trace that the record of the refusal goes on.
		trace: &'a TraceCollector,
	},
	/// The frame verified, and the freshness gate refused it as a replay or
	/// as outside its window.
	Stale {
		/// The status that the hive reads.
		status: TransitStatus,
		/// The trace that the record of the refusal goes on.
		trace: &'a TraceCollector,
		/// The signer of the verified frame, which the record names.
		signer: VerifiedSignerId,
	},
}

impl<'a> RefusedControl<'a> {
	/// The status that the hive reads.
	fn status(&self) -> TransitStatus {
		match self {
			Self::Unverified { status, .. } | Self::Stale { status, .. } => *status,
		}
	}

	/// The trace that the record of the refusal goes on.
	fn trace(&self) -> &'a TraceCollector {
		match self {
			Self::Unverified { trace, .. } | Self::Stale { trace, .. } => trace,
		}
	}

	/// The signer that the record names: the signer of a verified frame, and
	/// none for a frame whose signature failed verification.
	fn signer(&self) -> Option<&VerifiedSignerId> {
		match self {
			Self::Unverified { .. } => None,
			Self::Stale { signer, .. } => Some(signer),
		}
	}
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
		let AdmittedControl { verified, trace } = match self.admit_hive_control(&frame, audit) {
			Ok(admitted) => admitted,
			Err(refused) => {
				return self.refuse_register(&frame, refused.status(), refused.trace(), refused.signer());
			}
		};

		// Each record after the verification names the verified signer
		// (CWE-778).
		let fingerprint = verified.fingerprint();
		let signer = Some(&fingerprint);

		let admitted = match AdmittedRegistration::admit(&verified, request, &self.config) {
			Ok(admitted) => admitted,
			Err(status) => return self.refuse_register(&frame, status, trace, signer),
		};

		// The entry and its slate install atomically and replace the rows of a
		// prior registration.
		let AdmittedRegistration { hive_identity, signer: bound, slate, request } = admitted;
		match self.membership().admit(request, bound, slate) {
			Ok(hive_count) => {
				let evidence = Some(fingerprint.as_shared().as_ref());
				trace.emit_event_with_value_and_evidence(CLUSTER_HIVE_REGISTERED, "", hive_count, evidence)?;

				let response = RegisterHiveResponse { status: TransitStatus::Ok, hive_id: Some(hive_identity) };
				ReplyForm::Plain.reply(frame.metadata().id(), response)
			}
			Err(error) => {
				// A release of the replay slot lets a legitimate retry of the
				// same signed frame proceed.
				let status = error.transit_status();
				self.refuse_register_release(&frame, verified.signature(), status, trace, signer)
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
		let AdmittedControl { verified, trace } = match self.admit_hive_control(&frame, audit) {
			Ok(admitted) => admitted,
			Err(refused) => {
				let status = refused.status();
				return self.refuse_update(&frame, status, || status.as_str(), refused.trace(), refused.signer());
			}
		};

		// Each record after the verification names the verified signer
		// (CWE-778).
		let fingerprint = verified.fingerprint();
		let signer = Some(&fingerprint);

		// An update that does not parse names its cause in the record, so the
		// trail tells a foreign identity from a refused route.
		let admitted = match AdmittedUpdate::admit(&verified, &update, &self.config) {
			Ok(admitted) => admitted,
			Err(error) => {
				let status = error.transit_status();
				return self.refuse_update(&frame, status, || error.refusal_label(), trace, signer);
			}
		};

		// The signer bind and the route write are one membership step, so
		// a retirement lands before or after both (CWE-362).
		let AdmittedUpdate { signer: claimed, added, removed } = admitted;
		let removed: Vec<&[u8]> = removed.iter().map(AsRef::as_ref).collect();
		match self.membership().update_addresses(claimed, added, &removed) {
			Ok(()) => {
				let evidence = || Some(fingerprint.as_shared().as_ref());
				trace.emit_marker_with_evidence(CLUSTER_UPDATE_ACCEPTED, evidence)?;

				let response = ServletAddressUpdateResponse { status: TransitStatus::Ok };
				ReplyForm::Plain.reply(frame.metadata().id(), response)
			}
			Err(error) => {
				// A release of the replay slot lets the hive resend the same
				// signed update.
				let status = error.transit_status();
				self.refuse_update_release(&frame, verified.signature(), status, trace, signer)
			}
		}
	}

	/// The origin and freshness gate that register and address-update share.
	///
	/// A record goes on the audit trace once the signature verifies.
	fn admit_hive_control<'a>(
		&'a self,
		frame: &'a Frame,
		audit: &'a RequestAudit,
	) -> Result<AdmittedControl<'a>, RefusedControl<'a>> {
		let verified = match self.config.verify_hive(frame) {
			Ok(verified) => verified,
			Err(refusal) => {
				let trace = audit.unproven();
				return Err(RefusedControl::Unverified { status: refusal.into(), trace });
			}
		};

		let signer = verified.fingerprint();
		let trace = audit.signed(Some(&signer));

		let freshness_status = self.replay_guard.admits(frame, verified.signature());
		if freshness_status != TransitStatus::Ok {
			return Err(RefusedControl::Stale { status: freshness_status, trace, signer });
		}

		Ok(AdmittedControl { verified, trace })
	}

	/// Answers a registration with `status` and no hive identity, and records
	/// the refusal on `trace`, with the fingerprint of the verified `signer`
	/// as its payload.
	fn refuse_register(
		&self,
		frame: &Frame,
		status: TransitStatus,
		trace: &TraceCollector,
		signer: Option<&VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError> {
		let evidence = signer.map(|signer| signer.as_shared().as_ref());
		trace.emit_event_with_value_and_evidence(CLUSTER_REGISTER_REFUSED, status.as_str(), status, evidence)?;

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
		signer: Option<&VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(signature);
		self.refuse_register(frame, status, trace, signer)
	}

	/// Answers an address update with `status`, and records the refusal on
	/// `trace` under the label that `label` renders, with the fingerprint of
	/// the verified `signer` as its payload.
	///
	/// The trace runs `label` only when its sink keeps the event, so a record
	/// that the sink drops renders no label.
	fn refuse_update<L>(
		&self,
		frame: &Frame,
		status: TransitStatus,
		label: impl FnOnce() -> L,
		trace: &TraceCollector,
		signer: Option<&VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError>
	where
		L: Into<Cow<'static, str>>,
	{
		let evidence = signer.map(|signer| signer.as_shared().as_ref());
		trace.emit_rendered_event(CLUSTER_UPDATE_REFUSED, label, (), || evidence)?;

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
		signer: Option<&VerifiedSignerId>,
	) -> Result<Option<Frame>, TightBeamError> {
		self.replay_guard.release(signature);
		self.refuse_update(frame, status, || status.as_str(), trace, signer)
	}
}

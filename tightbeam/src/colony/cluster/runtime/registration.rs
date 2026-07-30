//! Hive registration and servlet address-update request handlers.

use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayReplayGuard;
use crate::colony::cluster::runtime::verify::{verify_control_freshness, verify_hive_origin};
use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletEntry, ServletRegistry};
use crate::colony::common::{
	reply_frame, type_canonical_bytes, ColonyResource, RegisterHiveRequest, ServletAddressUpdate,
};
use crate::colony::hive::{RegisterHiveResponse, ServletAddressUpdateResponse};
use crate::instrumentation::events::{
	CLUSTER_HIVE_REGISTERED, CLUSTER_REGISTER_REFUSED, CLUSTER_UPDATE_ACCEPTED, CLUSTER_UPDATE_REFUSED,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::der::Encode;

/// Handle hive registration: hive-origin, freshness, URN alignment, atomic install.
pub(crate) async fn handle_register(
	frame: Frame,
	request: RegisterHiveRequest,
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	let origin_status = verify_hive_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		let _ = trace.event(CLUSTER_REGISTER_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			RegisterHiveResponse { status: origin_status, hive_id: None },
		);
	}

	let freshness_status = verify_control_freshness(&frame, replay_guard);
	if freshness_status != TransitStatus::Ok {
		let _ = trace.event(CLUSTER_REGISTER_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			RegisterHiveResponse { status: freshness_status, hive_id: None },
		);
	}

	// Instance URN locator MUST equal route address (CWE-639).
	let urns_valid = request
		.servlet_addresses
		.iter()
		.all(|info| match config.namespace.validate(&info.servlet_id) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => {
				locator.as_bytes() == info.address.as_slice()
			}
			_ => false,
		});
	if !urns_valid {
		let _ = trace.event(CLUSTER_REGISTER_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			RegisterHiveResponse {
				status: TransitStatus::PermissionDenied,
				hive_id: None,
			},
		);
	}

	// Refuse addresses that cannot mint an exact hive identity URN.
	let hive_identity = core::str::from_utf8(&request.hive_addr)
		.ok()
		.and_then(|addr| config.namespace.hive(addr).ok());
	let Some(hive_identity) = hive_identity else {
		let _ = trace.event(CLUSTER_REGISTER_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			RegisterHiveResponse {
				status: TransitStatus::PermissionDenied,
				hive_id: None,
			},
		);
	};

	let hive_addr: Arc<[u8]> = request.hive_addr.clone().into();

	// Work routes by type bytes; strip instance tails.
	let servlet_info: Vec<(Arc<[u8]>, Arc<[u8]>)> = request
		.servlet_addresses
		.iter()
		.map(|info| {
			(
				Arc::from(type_canonical_bytes(&info.servlet_id).as_slice()),
				Arc::from(info.address.as_slice()),
			)
		})
		.collect();

	#[cfg(feature = "x509")]
	let signer_id: Option<Arc<[u8]>> = frame
		.nonrepudiation
		.as_ref()
		.and_then(|info| Encode::to_der(&info.sid).ok())
		.map(Arc::from);
	#[cfg(not(feature = "x509"))]
	let signer_id: Option<Arc<[u8]>> = None;

	// Atomic: hive entry + full slate, or roll back. Re-register replaces prior rows.
	let registered = registry.register_with_signer(request, signer_id).and_then(|()| {
		let slate: Vec<ServletEntry> = servlet_info
			.iter()
			.map(|(servlet_type, servlet_addr)| {
				ServletEntry::new(
					Arc::clone(servlet_addr),
					Arc::clone(servlet_type),
					Arc::clone(&hive_addr),
					config.pheromone.initial_pheromone,
					config.pheromone.abandonment_limit,
				)
			})
			.collect();
		servlet_registry.reconcile_by_hive(&hive_addr, slate).inspect_err(|_| {
			let _ = registry.unregister(&hive_addr);
			let _ = servlet_registry.remove_by_hive(&hive_addr);
		})
	});

	let response = match registered {
		Ok(()) => {
			let hive_count = registry.len().unwrap_or_default() as u64;
			let _ = trace.event_with(CLUSTER_HIVE_REGISTERED, &[], hive_count);

			RegisterHiveResponse {
				status: TransitStatus::Ok,
				hive_id: Some(hive_identity),
			}
		}
		Err(_) => {
			// Forget replay so a legitimate retry of the same signed frame can proceed.
			#[cfg(feature = "x509")]
			if let Some(signer_info) = frame.nonrepudiation.as_ref() {
				replay_guard.forget(signer_info.signature.as_bytes());
			}

			let _ = trace.event(CLUSTER_REGISTER_REFUSED);
			RegisterHiveResponse {
				status: TransitStatus::PermissionDenied,
				hive_id: None,
			}
		}
	};

	reply_frame(frame.metadata.id.clone(), response)
}

/// Handle servlet address updates: hive-origin, freshness, signer bind, apply delta.
pub(crate) async fn handle_address_update(
	frame: Frame,
	update: ServletAddressUpdate,
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	let origin_status = verify_hive_origin(&config, &frame);
	if origin_status != TransitStatus::Ok {
		let _ = trace.event(CLUSTER_UPDATE_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			ServletAddressUpdateResponse { status: origin_status },
		);
	}

	let freshness_status = verify_control_freshness(&frame, replay_guard);
	if freshness_status != TransitStatus::Ok {
		let _ = trace.event(CLUSTER_UPDATE_REFUSED);
		return reply_frame(
			frame.metadata.id.clone(),
			ServletAddressUpdateResponse { status: freshness_status },
		);
	}

	// Hive URN + aligned add/remove instance URNs; unroute by instance locator.
	let claimed_hive = config.namespace.validate(&update.hive_id);
	let added_valid = update
		.added
		.iter()
		.all(|info| match config.namespace.validate(&info.servlet_id) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => {
				locator.as_bytes() == info.address.as_slice()
			}
			_ => false,
		});
	let removed_locators: Option<Vec<&[u8]>> = update
		.removed
		.iter()
		.map(|urn| match config.namespace.validate(urn) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => Some(locator.as_bytes()),
			_ => None,
		})
		.collect();
	let (hive_id, removed): (Arc<[u8]>, Vec<&[u8]>) = match (claimed_hive, added_valid, removed_locators) {
		(Ok(ColonyResource::Hive { addr }), true, Some(removed)) => (Arc::from(addr.as_bytes()), removed),
		_ => {
			let _ = trace.event(CLUSTER_UPDATE_REFUSED);
			return reply_frame(
				frame.metadata.id.clone(),
				ServletAddressUpdateResponse {
					status: TransitStatus::PermissionDenied,
				},
			);
		}
	};

	// Signer MUST match the hive bound at registration (CWE-639).
	#[cfg(feature = "x509")]
	{
		let bound_ok = match (frame.nonrepudiation.as_ref(), registry.signer_for(&hive_id)) {
			(Some(signer_info), Ok(Some(bound))) => match Encode::to_der(&signer_info.sid) {
				Ok(sid) => sid.as_slice() == bound.as_ref(),
				Err(_) => false,
			},
			_ => false,
		};
		if !bound_ok {
			if let Some(signer_info) = frame.nonrepudiation.as_ref() {
				replay_guard.forget(signer_info.signature.as_bytes());
			}

			let _ = trace.event(CLUSTER_UPDATE_REFUSED);
			return reply_frame(
				frame.metadata.id.clone(),
				ServletAddressUpdateResponse {
					status: TransitStatus::PermissionDenied,
				},
			);
		}
	}

	let added: Vec<ServletEntry> = update
		.added
		.iter()
		.map(|info| {
			ServletEntry::new(
				Arc::from(info.address.as_slice()),
				Arc::from(type_canonical_bytes(&info.servlet_id).as_slice()),
				Arc::clone(&hive_id),
				config.pheromone.initial_pheromone,
				config.pheromone.abandonment_limit,
			)
		})
		.collect();

	let updated = servlet_registry.apply_address_update(&hive_id, added, &removed);
	let status = match updated {
		Ok(()) => {
			let _ = trace.event(CLUSTER_UPDATE_ACCEPTED);
			TransitStatus::Ok
		}
		Err(_) => {
			// Forget replay so the hive can resend the same signed update.
			#[cfg(feature = "x509")]
			if let Some(signer_info) = frame.nonrepudiation.as_ref() {
				replay_guard.forget(signer_info.signature.as_bytes());
			}

			let _ = trace.event(CLUSTER_UPDATE_REFUSED);
			TransitStatus::PermissionDenied
		}
	};

	reply_frame(frame.metadata.id.clone(), ServletAddressUpdateResponse { status })
}

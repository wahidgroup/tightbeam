//! Hive registration and servlet address-update request handlers.

use core::str::from_utf8;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::GatewayReplayGuard;
use crate::colony::cluster::runtime::verify::{verify_control_freshness, verify_hive_origin};
use crate::colony::cluster::{ClusterConfig, HiveRegistry, ServletEntry, ServletRegistry};
use crate::colony::common::{
	reply_frame, type_canonical_bytes, ColonyNamespace, ColonyResource, RegisterHiveRequest, ServletAddressUpdate,
	ServletInfo,
};
use crate::colony::hive::{RegisterHiveResponse, ServletAddressUpdateResponse};
use crate::instrumentation::events::{
	CLUSTER_HIVE_REGISTERED, CLUSTER_REGISTER_REFUSED, CLUSTER_UPDATE_ACCEPTED, CLUSTER_UPDATE_REFUSED,
};
use crate::policy::TransitStatus;
use crate::trace::TraceCollector;
use crate::utils::urn::Urn;
use crate::Frame;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use crate::der::Encode;

/// Admit a hive registration and install its servlet slate atomically.
pub(crate) async fn handle_register(
	frame: Frame,
	request: RegisterHiveRequest,
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	if let Err(status) = admit_hive_control(&config, &frame, replay_guard) {
		return refuse_register(&frame, &trace, status);
	}

	// Instance URN locator MUST equal route address (CWE-639).
	let locators_ok = request
		.servlet_addresses
		.iter()
		.all(|info| servlet_locator_matches(&config.namespace, info));
	if !locators_ok {
		return refuse_register(&frame, &trace, TransitStatus::PermissionDenied);
	}

	// Refuse addresses that cannot mint an exact hive identity URN.
	let Some(hive_identity) = mint_hive_identity(&config.namespace, &request.hive_addr) else {
		return refuse_register(&frame, &trace, TransitStatus::PermissionDenied);
	};

	let hive_addr: Arc<[u8]> = request.hive_addr.clone().into();
	let slate = build_servlet_slate(&request.servlet_addresses, &hive_addr, &config);
	let signer_id = frame_signer_id(&frame);

	// Atomic: hive entry + full slate, or roll back. Re-register replaces prior rows.
	let registered = registry.register_with_signer(request, signer_id).and_then(|()| {
		servlet_registry.reconcile_by_hive(&hive_addr, slate).inspect_err(|_| {
			let _ = registry.unregister(&hive_addr);
			let _ = servlet_registry.remove_by_hive(&hive_addr);
		})
	});

	match registered {
		Ok(()) => {
			let hive_count = registry.len().unwrap_or_default() as u64;
			let _ = trace.event_with(CLUSTER_HIVE_REGISTERED, &[], hive_count);
			let response = RegisterHiveResponse { status: TransitStatus::Ok, hive_id: Some(hive_identity) };
			reply_frame(&frame.metadata.id, response)
		}
		Err(_) => {
			// Forget replay so a legitimate retry of the same signed frame can proceed.
			refuse_register_release(&frame, &trace, replay_guard, TransitStatus::PermissionDenied)
		}
	}
}

/// Admit a servlet address update and apply the delta under signer bind.
pub(crate) async fn handle_address_update(
	frame: Frame,
	update: ServletAddressUpdate,
	registry: Arc<HiveRegistry>,
	servlet_registry: Arc<ServletRegistry>,
	config: Arc<ClusterConfig>,
	trace: Arc<TraceCollector>,
	replay_guard: &GatewayReplayGuard,
) -> Result<Option<Frame>, TightBeamError> {
	if let Err(status) = admit_hive_control(&config, &frame, replay_guard) {
		return refuse_update(&frame, &trace, status);
	}

	let Some((hive_id, added, removed)) = parse_address_update(&config, &update) else {
		return refuse_update(&frame, &trace, TransitStatus::PermissionDenied);
	};

	// Signer MUST match the hive bound at registration (CWE-639).
	if !signer_matches_bound_hive(&frame, &registry, &hive_id) {
		return refuse_update_release(&frame, &trace, replay_guard, TransitStatus::PermissionDenied);
	}

	match servlet_registry.apply_address_update(&hive_id, added, &removed) {
		Ok(()) => {
			let _ = trace.event(CLUSTER_UPDATE_ACCEPTED);
			let response = ServletAddressUpdateResponse { status: TransitStatus::Ok };
			reply_frame(&frame.metadata.id, response)
		}
		Err(_) => {
			// Forget replay so the hive can resend the same signed update.
			refuse_update_release(&frame, &trace, replay_guard, TransitStatus::PermissionDenied)
		}
	}
}

/// Origin and freshness gate shared by register and address-update.
fn admit_hive_control(
	config: &ClusterConfig,
	frame: &Frame,
	replay_guard: &GatewayReplayGuard,
) -> Result<(), TransitStatus> {
	let origin_status = verify_hive_origin(config, frame);
	if origin_status != TransitStatus::Ok {
		return Err(origin_status);
	}

	let freshness_status = verify_control_freshness(frame, replay_guard);
	if freshness_status != TransitStatus::Ok {
		return Err(freshness_status);
	}

	Ok(())
}

/// Instance URN locator bytes must equal the advertised servlet address.
fn servlet_locator_matches(namespace: &ColonyNamespace, info: &ServletInfo) -> bool {
	match namespace.validate(&info.servlet_id) {
		Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => locator.as_bytes() == info.address.as_slice(),
		_ => false,
	}
}

fn mint_hive_identity(namespace: &ColonyNamespace, hive_addr: &[u8]) -> Option<Urn<'static>> {
	let addr = from_utf8(hive_addr).ok()?;
	let hive = namespace.hive(addr).ok()?;
	Some(hive)
}

fn build_servlet_slate(
	servlet_addresses: &[ServletInfo],
	hive_addr: &Arc<[u8]>,
	config: &ClusterConfig,
) -> Vec<ServletEntry> {
	let initial_pheromone = config.pheromone.initial_pheromone;
	let abandonment_limit = config.pheromone.abandonment_limit;
	servlet_addresses
		.iter()
		.map(|info| {
			ServletEntry::new(
				Arc::from(info.address.as_slice()),
				Arc::from(type_canonical_bytes(&info.servlet_id).as_slice()),
				Arc::clone(hive_addr),
				initial_pheromone,
				abandonment_limit,
			)
		})
		.collect()
}

/// Parse hive identity, added entries, and removed instance locators.
///
/// Returns `None` when the hive URN, any added locator, or any removed URN
/// fails validation.
fn parse_address_update<'a>(
	config: &ClusterConfig,
	update: &'a ServletAddressUpdate,
) -> Option<(Arc<[u8]>, Vec<ServletEntry>, Vec<&'a [u8]>)> {
	let claimed = config.namespace.validate(&update.hive_id).ok()?;
	let ColonyResource::Hive { addr } = claimed else {
		return None;
	};

	let added_ok = update.added.iter().all(|info| servlet_locator_matches(&config.namespace, info));
	if !added_ok {
		return None;
	}

	let mut removed = Vec::with_capacity(update.removed.len());
	for urn in &update.removed {
		match config.namespace.validate(urn) {
			Ok(ColonyResource::Servlet { instance: Some(locator), .. }) => {
				removed.push(locator.as_bytes());
			}
			_ => return None,
		}
	}

	let hive_id = Arc::from(addr.as_bytes());
	let added = build_servlet_slate(&update.added, &hive_id, config);
	Some((hive_id, added, removed))
}

fn refuse_register(
	frame: &Frame,
	trace: &TraceCollector,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	let _ = trace.event(CLUSTER_REGISTER_REFUSED);
	let response = RegisterHiveResponse { status, hive_id: None };
	reply_frame(&frame.metadata.id, response)
}

fn refuse_register_release(
	frame: &Frame,
	trace: &TraceCollector,
	replay_guard: &GatewayReplayGuard,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	forget_replay(frame, replay_guard);
	refuse_register(frame, trace, status)
}

fn refuse_update(
	frame: &Frame,
	trace: &TraceCollector,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	let _ = trace.event(CLUSTER_UPDATE_REFUSED);
	let response = ServletAddressUpdateResponse { status };
	reply_frame(&frame.metadata.id, response)
}

fn refuse_update_release(
	frame: &Frame,
	trace: &TraceCollector,
	replay_guard: &GatewayReplayGuard,
	status: TransitStatus,
) -> Result<Option<Frame>, TightBeamError> {
	forget_replay(frame, replay_guard);
	refuse_update(frame, trace, status)
}

#[cfg(feature = "x509")]
fn forget_replay(frame: &Frame, replay_guard: &GatewayReplayGuard) {
	if let Some(signer_info) = frame.nonrepudiation.as_ref() {
		replay_guard.forget(signer_info.signature.as_bytes());
	}
}

#[cfg(not(feature = "x509"))]
fn forget_replay(_frame: &Frame, _replay_guard: &GatewayReplayGuard) {}

#[cfg(feature = "x509")]
fn frame_signer_id(frame: &Frame) -> Option<Arc<[u8]>> {
	frame
		.nonrepudiation
		.as_ref()
		.and_then(|info| Encode::to_der(&info.sid).ok())
		.map(Arc::from)
}

#[cfg(not(feature = "x509"))]
fn frame_signer_id(_frame: &Frame) -> Option<Arc<[u8]>> {
	None
}

#[cfg(feature = "x509")]
fn signer_matches_bound_hive(frame: &Frame, registry: &HiveRegistry, hive_id: &[u8]) -> bool {
	match (frame.nonrepudiation.as_ref(), registry.signer_for(hive_id)) {
		(Some(signer_info), Ok(Some(bound))) => match Encode::to_der(&signer_info.sid) {
			Ok(sid) => sid.as_slice() == bound.as_ref(),
			Err(_) => false,
		},
		_ => false,
	}
}

#[cfg(not(feature = "x509"))]
fn signer_matches_bound_hive(_frame: &Frame, _registry: &HiveRegistry, _hive_id: &[u8]) -> bool {
	true
}

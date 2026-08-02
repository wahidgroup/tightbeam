//! Oracle-driven action loop for the colony AFL harness.

use std::sync::Arc;
use std::time::Duration;

use tightbeam::colony::cluster::{
	Cluster, ClusterRequest, ClusterWorkRequest, ServletEntry, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE,
};
use tightbeam::colony::common::type_canonical_bytes;
use tightbeam::compose;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::decode;
use tightbeam::der::Encode;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::client::pool::{ConnectionPool, PoolConfig};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, PooledClient, Protocol};
use tightbeam::utils::urn::Urn;
use tightbeam::{encode, TightBeamError};

use crate::control::{advertise_peer_at, advertise_peer_types, CONTROL_ORDER_BASE};
use crate::csr::{CsrRequest, CsrResponse};
use crate::events;
use crate::fixtures::{colony_urn, servlet_urn, ClusterTestCerts};
use crate::limits::{clamp_nonzero, DEAD_PEER_ADDR, MAX_ACTIONS, MAX_STRESS_BATCH};
use crate::servlets::{PingRequest, PingResponse};
use crate::shadow::AccessAttempt;
use crate::topology::{ColonyTopology, OrgNode};

/// Client I/O budget. Sized above typical local emit latency so allowed
/// work resolves as success/deny rather than timeout races.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_millis(2000);

/// Run oracle-selected actions until bytes or action caps are hit.
pub(crate) async fn run_actions(trace: &TraceCollector, topo: &mut ColonyTopology) -> Result<(), TightBeamError> {
	let mut actions = 0u64;
	let mut order = 1u64;
	let mut control_order = CONTROL_ORDER_BASE;

	loop {
		if actions >= MAX_ACTIONS {
			break;
		}
		if !trace.oracle().fuzz_has_bytes(2).unwrap_or(false) {
			break;
		}

		let Ok(opcode) = trace.oracle().fuzz_u8() else {
			break;
		};
		let Ok(selector) = trace.oracle().fuzz_u8() else {
			break;
		};

		trace.event(events::ACTION_RUN)?;
		actions += 1;

		match opcode % 16 {
			0 => {
				let org = pick_org(topo, selector);
				mutate_export(trace, org, selector)?;
			}
			1 => {
				let org = pick_org(topo, selector);
				mutate_grant(trace, org, selector)?;
			}
			2 => {
				let org = pick_org(topo, selector);
				mutate_gate(trace, org, selector)?;
			}
			3 => {
				let org = pick_org(topo, selector);
				mutate_policy_gate(trace, org, selector)?;
			}
			4 => submit_csr(trace, pick_org(topo, selector), selector, &mut order).await?,
			5 => servlet_lifecycle(trace, pick_org(topo, selector), selector)?,
			6 => stress_burst(trace, pick_org(topo, selector), selector, &mut order).await?,
			7 => advertise_live_peer(trace, topo, selector, &mut control_order).await?,
			8 => cross_org_work(trace, topo, selector, &mut order).await?,
			9 => open_stream_action(trace, pick_org(topo, selector), selector).await?,
			10 => open_duplex_action(trace, pick_org(topo, selector), selector).await?,
			11 => hostile_anon_work(trace, pick_org(topo, selector), selector, &mut order).await?,
			12 => hostile_foreign_work(trace, topo, selector, &mut order).await?,
			13 => failover_probe(trace, topo, selector, &mut order, &mut control_order).await?,
			_ => emit_work(trace, pick_org(topo, selector), selector, &mut order).await?,
		}
	}

	trace.event_with(events::ACTIONS_BALANCE, &["balance"], actions as i64)?;
	Ok(())
}

fn pick_org(topo: &mut ColonyTopology, selector: u8) -> &mut OrgNode {
	match selector % 3 {
		0 => &mut topo.alpha,
		1 => &mut topo.beta,
		_ => &mut topo.gamma,
	}
}

fn org_spki(org: &OrgNode) -> Result<Vec<u8>, TightBeamError> {
	Ok(org.certs.cert.tbs_certificate.subject_public_key_info.to_der()?)
}

fn mutate_export(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let target = target_urn(selector);
	if selector & 1 == 0 {
		org.exports.insert(target);
	} else {
		org.exports.remove(&target);
	}

	trace.event(events::EXPORT_MUTATED)?;
	Ok(())
}

fn mutate_grant(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let spki = org_spki(org)?;
	let target = target_urn(selector);
	if selector & 1 == 0 {
		org.acl.grant(spki, &target);
	} else {
		org.acl.revoke_grant(&spki, &target);
	}

	trace.event(events::GRANT_MUTATED)?;
	Ok(())
}

fn mutate_gate(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let spki = org_spki(org)?;
	if selector & 1 == 0 {
		org.acl.deny(spki);
	} else {
		org.acl.allow(&spki);
	}

	trace.event(events::GATE_MUTATED)?;
	Ok(())
}

fn mutate_policy_gate(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	org.policy_gate.set_reject(selector & 1 == 0);
	trace.event(events::POLICY_GATE_MUTATED)?;
	Ok(())
}

async fn connect_with_identity(
	server_trust: Arc<dyn CertificateTrust>,
	identity: &ClusterTestCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_timeout(CLIENT_IO_TIMEOUT)
		.with_trust_store(server_trust)
		.with_client_identity(
			CertificateSpec::Built(Box::new(identity.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned())),
		)?
		.build()
		.connect(addr)
		.await?)
}

async fn connect_anon(
	server_trust: Arc<dyn CertificateTrust>,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_timeout(CLIENT_IO_TIMEOUT)
		.with_trust_store(server_trust)
		.build()
		.connect(addr)
		.await?)
}

async fn pooled_client(
	trace: &TraceCollector,
	identity: &ClusterTestCerts,
	addr: &<TokioListener as Protocol>::Address,
) -> Result<PooledClient<TokioListener>, TightBeamError> {
	let config = PoolConfig {
		idle_timeout: None,
		max_connections: 1,
		mux_offer: Some(Arc::new(TransportOffer::mux(8))),
	};
	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_timeout(CLIENT_IO_TIMEOUT)
			.with_trust_store(Arc::clone(&identity.trust))
			.with_client_identity(
				CertificateSpec::Built(Box::new(identity.cert.to_owned())),
				Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned())),
			)?
			.with_trace(trace.share())
			.build(),
	);

	Ok(pool.connect(addr.to_owned()).await?)
}

/// One gateway work emit: request, frame id, shadow expectation, and outcome events.
struct ClusterWork<F> {
	request: ClusterWorkRequest,
	frame_id: &'static str,
	allowed: bool,
	ok: Urn<'static>,
	denied: Urn<'static>,
	is_success: F,
}

async fn emit_cluster_work(
	trace: &TraceCollector,
	dial_org: &OrgNode,
	identity: Option<&ClusterTestCerts>,
	order: &mut u64,
	work: ClusterWork<impl FnOnce(&[u8]) -> bool>,
) -> Result<(), TightBeamError> {
	let server_trust = Arc::clone(&dial_org.certs.trust);
	let mut client = match identity {
		Some(id) => connect_with_identity(server_trust, id, dial_org.gateway.addr()).await?,
		None => connect_anon(server_trust, dial_org.gateway.addr()).await?,
	};

	let frame = compose! {
		V0: id: work.frame_id,
		order: *order,
		message: ClusterRequest::Work(work.request)
	}?;
	*order += 1;

	let outcome = tokio::time::timeout(CLIENT_IO_TIMEOUT, client.emit(frame, None)).await;
	match outcome {
		Ok(Ok(Some(response))) if (work.is_success)(&response.message) => {
			if !work.allowed {
				trace.event(events::SHADOW_VIOLATION)?;
			}
			trace.event(work.ok)?;
		}
		_ => {
			trace.event(work.denied)?;
		}
	}
	Ok(())
}

fn shadow_allowed(org: &OrgNode, target: &Urn<'static>, identity: Option<&ClusterTestCerts>, relayed: bool) -> bool {
	let spki = identity.and_then(|id| id.cert.tbs_certificate.subject_public_key_info.to_der().ok());
	org.shadow.allows(&AccessAttempt {
		target,
		caller_cert: identity.map(|id| &id.cert),
		caller_spki: spki.as_deref(),
		relayed,
	})
}

async fn emit_work(trace: &TraceCollector, org: &OrgNode, selector: u8, order: &mut u64) -> Result<(), TightBeamError> {
	let target = target_urn(selector);
	let relayed = selector & 0x80 != 0;
	let allowed = shadow_allowed(org, &target, Some(&org.certs), relayed);

	let mut request = ClusterWorkRequest::new(target.clone(), encode(&PingRequest { value: 21 })?);
	if relayed {
		request = request.into_relayed(1);
	}

	emit_cluster_work(
		trace,
		org,
		Some(&org.certs),
		order,
		ClusterWork {
			request,
			frame_id: "colony-fuzz",
			allowed,
			ok: events::WORK_OK,
			denied: events::WORK_DENIED,
			is_success: |message: &[u8]| match decode::<PingResponse>(&message) {
				Ok(ping) => ping.doubled == 42,
				Err(_) => false,
			},
		},
	)
	.await
}

async fn submit_csr(
	trace: &TraceCollector,
	org: &OrgNode,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	if org.csr_issuer.is_none() {
		return Ok(());
	}

	let target = servlet_urn("csr");
	let allowed = shadow_allowed(org, &target, Some(&org.certs), false);
	let spki = org_spki(org)?;

	let req = CsrRequest {
		spki: spki.clone(),
		colony: colony_urn(org.name).to_string(),
		cn: format!("csr-{}", selector),
	};

	emit_cluster_work(
		trace,
		org,
		Some(&org.certs),
		order,
		ClusterWork {
			request: ClusterWorkRequest::new(target, encode(&req)?),
			frame_id: "colony-fuzz-csr",
			allowed,
			ok: events::CSR_ISSUED,
			denied: events::CSR_REFUSED,
			is_success: |message: &[u8]| match decode::<CsrResponse>(&message) {
				Ok(csr) => csr.status == 0 && !csr.certificate.is_empty(),
				Err(_) => false,
			},
		},
	)
	.await
}

fn servlet_lifecycle(trace: &TraceCollector, org: &mut OrgNode, selector: u8) -> Result<(), TightBeamError> {
	// Post-establish hive.register is refused, so lifecycle actions track
	// soft-state instance counts for the shadow while the live hive keeps
	// its baseline servlets. Stress and export planes still see real work.
	let n = clamp_nonzero(selector, crate::limits::MAX_SERVLET_INSTANCES);
	if selector & 1 == 0 {
		org.soft_instances = org.soft_instances.saturating_add(n);
		trace.event(events::SERVLET_ADDED)?;
	} else {
		org.soft_instances = org.soft_instances.saturating_sub(n);
		trace.event(events::SERVLET_REMOVED)?;
	}

	Ok(())
}

async fn stress_burst(
	trace: &TraceCollector,
	org: &OrgNode,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	let n = clamp_nonzero(selector, MAX_STRESS_BATCH);

	trace.event(events::STRESS_BURST)?;

	for i in 0..n {
		emit_work(trace, org, selector.wrapping_add(i as u8), order).await?;
	}

	Ok(())
}

async fn advertise_live_peer(
	trace: &TraceCollector,
	topo: &mut ColonyTopology,
	selector: u8,
	control_order: &mut u64,
) -> Result<(), TightBeamError> {
	let types = vec![advertised_type(selector)];
	let order = *control_order;
	*control_order += 1;

	let (ok, _) = {
		let advertiser_is_beta = selector & 1 == 0;
		if advertiser_is_beta {
			let ok = advertise_peer_types(trace, &topo.beta, &topo.alpha.gateway, types, order).await?;
			(ok, ())
		} else {
			let ok = advertise_peer_types(trace, &topo.gamma, &topo.alpha.gateway, types, order).await?;
			(ok, ())
		}
	};
	let _ = ok;
	Ok(())
}

async fn cross_org_work(
	trace: &TraceCollector,
	topo: &mut ColonyTopology,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	trace.event(events::CROSS_ORG_WORK)?;

	let target = servlet_urn("peer-ping");
	let relayed = selector & 0x80 != 0;
	let allowed = shadow_allowed(&topo.alpha, &target, Some(&topo.alpha.certs), relayed);

	let mut request = ClusterWorkRequest::new(target, encode(&PingRequest { value: 21 })?);
	if relayed {
		request = request.into_relayed(1);
	}

	emit_cluster_work(
		trace,
		&topo.alpha,
		Some(&topo.alpha.certs),
		order,
		ClusterWork {
			request,
			frame_id: "colony-fuzz-xorg",
			allowed,
			ok: events::WORK_OK,
			denied: events::WORK_DENIED,
			is_success: |message: &[u8]| match decode::<PingResponse>(&message) {
				Ok(ping) => ping.doubled == 42,
				Err(_) => false,
			},
		},
	)
	.await
}

async fn open_stream_action(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let target = servlet_urn("stream-echo");
	let allowed = shadow_allowed(org, &target, Some(&org.certs), false);
	let client = pooled_client(trace, &org.certs, org.gateway.addr()).await?;

	let outcome: Result<bool, TightBeamError> = async {
		let (mut sink, response) = client.open_stream_to(target)?;

		sink.push(b"abcd").await?;
		sink.close_with(b"efgh").await?;

		let reply = tokio::time::timeout(CLIENT_IO_TIMEOUT, response).await;
		match reply {
			Ok(Ok(Some(frame))) => match decode::<PingResponse>(&frame.message) {
				Ok(ping) if ping.doubled == 8 => Ok(true),
				_ => Ok(false),
			},
			_ => Ok(false),
		}
	}
	.await;

	match outcome {
		Ok(true) => {
			if !allowed {
				trace.event(events::SHADOW_VIOLATION)?;
			}
			trace.event(events::STREAM_OK)?;
		}
		_ => {
			let _ = selector;
			trace.event(events::STREAM_DENIED)?;
		}
	}

	Ok(())
}

async fn open_duplex_action(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let target = servlet_urn("stream-echo");
	let allowed = shadow_allowed(org, &target, Some(&org.certs), false);
	let client = pooled_client(trace, &org.certs, org.gateway.addr()).await?;

	let outcome: Result<bool, TightBeamError> = async {
		let (mut sink, mut body) = client.open_duplex_to(target)?;

		sink.push(b"xy").await?;
		sink.close_with(b"z").await?;

		let mut echoed = 0usize;
		let collect = async {
			while let Some(chunk) = body.chunk().await? {
				echoed += chunk.len();
			}
			Ok::<_, TightBeamError>(echoed)
		};
		match tokio::time::timeout(CLIENT_IO_TIMEOUT, collect).await {
			Ok(Ok(n)) if n == 3 => Ok(true),
			_ => Ok(false),
		}
	}
	.await;

	match outcome {
		Ok(true) => {
			if !allowed {
				trace.event(events::SHADOW_VIOLATION)?;
			}
			trace.event(events::DUPLEX_OK)?;
		}
		_ => {
			let _ = selector;
			trace.event(events::DUPLEX_DENIED)?;
		}
	}

	Ok(())
}

async fn hostile_anon_work(
	trace: &TraceCollector,
	org: &OrgNode,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	trace.event(events::HOSTILE_ANON)?;
	let target = target_urn(selector);
	let allowed = shadow_allowed(org, &target, None, false);

	emit_cluster_work(
		trace,
		org,
		None,
		order,
		ClusterWork {
			request: ClusterWorkRequest::new(target, encode(&PingRequest { value: 21 })?),
			frame_id: "colony-fuzz-anon",
			allowed,
			ok: events::WORK_OK,
			denied: events::WORK_DENIED,
			is_success: |message: &[u8]| match decode::<PingResponse>(&message) {
				Ok(ping) => ping.doubled == 42,
				Err(_) => false,
			},
		},
	)
	.await
}

async fn hostile_foreign_work(
	trace: &TraceCollector,
	topo: &mut ColonyTopology,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	trace.event(events::HOSTILE_FOREIGN)?;

	let dial_idx = selector % 3;
	let id_idx = (selector / 3) % 3;
	if dial_idx == id_idx {
		return emit_work(trace, pick_org(topo, selector), selector, order).await;
	}

	let identity = Arc::clone(&pick_org_ref(topo, id_idx).certs);
	let target = target_urn(selector);
	let allowed = shadow_allowed(pick_org_ref(topo, dial_idx), &target, Some(&identity), false);
	let request = ClusterWorkRequest::new(target, encode(&PingRequest { value: 21 })?);

	emit_cluster_work(
		trace,
		pick_org_ref(topo, dial_idx),
		Some(&identity),
		order,
		ClusterWork {
			request,
			frame_id: "colony-fuzz-foreign",
			allowed,
			ok: events::WORK_OK,
			denied: events::WORK_DENIED,
			is_success: |message: &[u8]| match decode::<PingResponse>(&message) {
				Ok(ping) => ping.doubled == 42,
				Err(_) => false,
			},
		},
	)
	.await
}

fn pick_org_ref(topo: &ColonyTopology, idx: u8) -> &OrgNode {
	match idx % 3 {
		0 => &topo.alpha,
		1 => &topo.beta,
		_ => &topo.gamma,
	}
}

async fn failover_probe(
	trace: &TraceCollector,
	topo: &mut ColonyTopology,
	selector: u8,
	order: &mut u64,
	control_order: &mut u64,
) -> Result<(), TightBeamError> {
	trace.event(events::FAILOVER_PROBED)?;

	let types = vec![servlet_urn("peer-ping")];
	let advertiser_is_beta = selector & 1 == 0;

	let dead_order = *control_order;
	*control_order += 1;

	let live_order = *control_order;
	*control_order += 1;

	if advertiser_is_beta {
		let _ = advertise_peer_at(
			trace,
			&topo.beta,
			&topo.alpha.gateway,
			DEAD_PEER_ADDR,
			types.clone(),
			dead_order,
		)
		.await?;

		pin_decoy_for(&topo.alpha.gateway, &topo.decoy_pin, "peer-ping", DEAD_PEER_ADDR);
		let _ = advertise_peer_types(trace, &topo.beta, &topo.alpha.gateway, types, live_order).await?;
	} else {
		let _ = advertise_peer_at(
			trace,
			&topo.gamma,
			&topo.alpha.gateway,
			DEAD_PEER_ADDR,
			types.clone(),
			dead_order,
		)
		.await?;

		pin_decoy_for(&topo.alpha.gateway, &topo.decoy_pin, "peer-ping", DEAD_PEER_ADDR);
		let _ = advertise_peer_types(trace, &topo.gamma, &topo.alpha.gateway, types, live_order).await?;
	}

	cross_org_work(trace, topo, selector, order).await
}

fn pin_decoy_for(
	gateway: &crate::topology::ColonyFuzzGateway,
	pin: &std::sync::Mutex<Option<Vec<u8>>>,
	type_name: &str,
	dial_addr: &[u8],
) {
	let canonical = type_canonical_bytes(&servlet_urn(type_name));
	let key = gateway.peer_routes().into_iter().find_map(|route| {
		if route.dial_addr.as_ref() != dial_addr || route.servlet_type.as_ref() != canonical.as_slice() {
			return None;
		}

		let entry = ServletEntry::peer(
			route.peer_id,
			route.servlet_type,
			route.dial_addr,
			DEFAULT_INITIAL_PHEROMONE,
			DEFAULT_ABANDONMENT_LIMIT,
		);

		Some(entry.route_key().to_vec())
	});

	if let Ok(mut guard) = pin.lock() {
		*guard = key;
	}
}

fn target_urn(selector: u8) -> Urn<'static> {
	match selector % 5 {
		0 => servlet_urn("public"),
		1 => servlet_urn("private"),
		2 => servlet_urn("csr"),
		3 => servlet_urn("stream-echo"),
		_ => servlet_urn("peer-ping"),
	}
}

fn advertised_type(selector: u8) -> Urn<'static> {
	match selector % 3 {
		0 => servlet_urn("peer-ping"),
		1 => servlet_urn("public"),
		_ => servlet_urn("stream-echo"),
	}
}

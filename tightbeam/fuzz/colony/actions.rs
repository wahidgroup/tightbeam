//! Oracle-driven action loop for the colony AFL harness.

use core::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tightbeam::colony::cluster::{
	Cluster, ClusterRequest, ClusterWorkRequest, ClusterWorkResponse, ServletEntry, DEFAULT_ABANDONMENT_LIMIT,
	DEFAULT_INITIAL_PHEROMONE,
};
use tightbeam::colony::common::type_canonical_bytes;
use tightbeam::compose;
use tightbeam::crypto::key::Secp256k1KeyProvider;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::CertificateSpec;
use tightbeam::decode;
use tightbeam::policy::TransitStatus;
use tightbeam::testing::routes::{relayed_to, RoutedOpens};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::client::pool::{ConnectionPool, PoolConfig};
use tightbeam::transport::error::{TransportError, TransportFailure};
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::multiplex::RequestSink;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::{ClientBuilder, ConnectionBuilder, GenericClient, PooledClient, Protocol};
use tightbeam::utils::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use crate::control::{advertise_peer_at, advertise_peer_types, CONTROL_ORDER_BASE};
use crate::csr::{CsrRequest, CsrResponse};
use crate::events;
use crate::fixtures::{colony_urn, servlet_urn, ClusterTestCerts};
use crate::limits::{clamp_nonzero, DEAD_PEER_ADDR, MAX_ACTIONS, MAX_STRESS_BATCH};
use crate::servlets::{PingRequest, PingResponse};
use crate::shadow::{AccessAttempt, Prediction};
use crate::topology::{ColonyTopology, OrgNode};

/// Client I/O budget. Sized above typical local emit latency so allowed
/// work resolves as success/deny rather than timeout races.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_millis(2000);

/// Classified unary/stream outcome for the security oracle.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthzClass {
	/// Authz allowed and application payload succeeded.
	Success = 1,
	/// Explicit authorization refusal from the gateway.
	AuthzDenied = 2,
	/// Timeout, TLS, routing, decode, or other non-authz failure.
	InfraFail = 3,
}

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
			1 => mutate_grant(trace, topo, selector)?,
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
			14 => negative_peer_ad(trace, topo, selector, &mut control_order).await?,
			_ => emit_work(trace, pick_org(topo, selector), selector, &mut order).await?,
		}

		ijon_action(opcode, selector);
	}

	trace.event_with(events::ACTIONS_BALANCE, &["balance"], actions as i64)?;
	Ok(())
}

fn ijon_action(opcode: u8, selector: u8) {
	#[cfg(all(fuzzing, feature = "testing-fuzz-ijon"))]
	{
		afl::ijon_set!(((u32::from(opcode)) << 8) | u32::from(selector));
	}
	#[cfg(not(all(fuzzing, feature = "testing-fuzz-ijon")))]
	{
		let _ = (opcode, selector);
	}
}

/// IJON code for a shadow prediction. `Unmodeled` gets a neutral value
/// so the coverage map does not misattribute those runs to either
/// oracle direction.
fn prediction_code(predicted: Prediction) -> u32 {
	match predicted {
		Prediction::Deny => 0,
		Prediction::Allow => 1,
		Prediction::Unmodeled => 2,
	}
}

fn ijon_authz(predicted: Prediction, class: AuthzClass) {
	#[cfg(all(fuzzing, feature = "testing-fuzz-ijon"))]
	{
		afl::ijon_set!((prediction_code(predicted) << 8) | (class as u32));
	}
	#[cfg(not(all(fuzzing, feature = "testing-fuzz-ijon")))]
	{
		let _ = (prediction_code(predicted), class);
	}
}

fn pick_org(topo: &mut ColonyTopology, selector: u8) -> &mut OrgNode {
	match selector % 3 {
		0 => &mut topo.alpha,
		1 => &mut topo.beta,
		_ => &mut topo.gamma,
	}
}

fn pick_org_ref(topo: &ColonyTopology, idx: u8) -> &OrgNode {
	match idx % 3 {
		0 => &topo.alpha,
		1 => &topo.beta,
		_ => &topo.gamma,
	}
}

/// Fixture-encoded SPKI DER borrowed from the identity bundle. Callers
/// that need ownership (ACL mutation, CSR payloads) copy it themselves.
fn org_spki(org: &OrgNode) -> &[u8] {
	org.certs.spki.as_ref()
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

fn mutate_grant(trace: &TraceCollector, topo: &ColonyTopology, selector: u8) -> Result<(), TightBeamError> {
	let target = target_urn(selector);
	let grantee_spki = org_spki(pick_org_ref(topo, selector >> 2));
	let org = pick_org_ref(topo, selector);
	if selector & 1 == 0 {
		org.acl.grant(grantee_spki, &target);
	} else {
		org.acl.revoke_grant(grantee_spki, &target);
	}

	trace.event(events::GRANT_MUTATED)?;
	Ok(())
}

fn mutate_gate(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let spki = org_spki(org);
	if selector & 1 == 0 {
		org.acl.deny(spki);
	} else {
		org.acl.allow(spki);
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
	let cert = CertificateSpec::Built(Box::new(identity.cert.as_ref().clone()));
	let key = Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned()));

	Ok(ClientBuilder::<TokioListener>::builder()
		.with_timeout(CLIENT_IO_TIMEOUT)
		.with_trust_store(server_trust)
		.with_client_identity(cert, key)?
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
	let offer = Arc::new(TransportOffer::mux(8));
	let config = PoolConfig { idle_timeout: None, max_connections: 1, mux_offer: Some(offer) };

	let cert = CertificateSpec::Built(Box::new(identity.cert.as_ref().clone()));
	let key = Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned()));

	let pool = Arc::new(
		ConnectionPool::<TokioListener>::builder()
			.with_config(config)
			.with_timeout(CLIENT_IO_TIMEOUT)
			.with_trust_store(Arc::clone(&identity.trust))
			.with_client_identity(cert, key)?
			.with_trace(trace.share())
			.build(),
	);

	Ok(pool.connect(addr.to_owned()).await?)
}

pub(crate) fn is_authz_status(status: TransitStatus) -> bool {
	matches!(status, TransitStatus::PermissionDenied | TransitStatus::Unauthenticated)
}

/// Build the client's end-to-end work frame around a typed ping request.
///
/// Gateways deliver this frame to the servlet, so the fuzz harness exercises
/// the same frame-in-frame contract as real clients.
fn inner_ping_frame() -> Result<Frame, TightBeamError> {
	compose! { V0: id: "colony-fuzz-inner", order: 0u64, message: PingRequest { value: 21 } }
}

fn classify_work_message(message: &[u8], payload_ok: impl FnOnce(&[u8]) -> bool) -> AuthzClass {
	match decode::<ClusterWorkResponse>(&message) {
		Ok(response) if response.status == TransitStatus::Ok => match response.into_frame() {
			Ok(Some(frame)) if payload_ok(&frame.message) => AuthzClass::Success,
			Ok(_) | Err(_) => AuthzClass::InfraFail,
		},
		Ok(response) if is_authz_status(response.status) => AuthzClass::AuthzDenied,
		Ok(_) | Err(_) => AuthzClass::InfraFail,
	}
}

/// Compare a shadow prediction against the wire outcome and emit the
/// outcome plus any oracle divergence.
///
/// Only `Allow`/`Deny` participate in the oracle. A predicted `Deny` that
/// the wire allowed is a `SHADOW_VIOLATION`, and a predicted `Allow` that
/// the wire refused is `SHADOW_TOO_CLOSED`. `Unmodeled` skips both
/// directions while the plain outcome event still emits.
fn record_authz_oracle(
	trace: &TraceCollector,
	predicted: Prediction,
	class: AuthzClass,
	ok: Urn<'static>,
	denied: Urn<'static>,
) -> Result<(), TightBeamError> {
	ijon_authz(predicted, class);
	match (predicted, class) {
		(Prediction::Deny, AuthzClass::Success) => {
			trace.event(events::SHADOW_VIOLATION)?;
			trace.event(ok)?;
		}
		(Prediction::Allow, AuthzClass::AuthzDenied) => {
			trace.event(events::SHADOW_TOO_CLOSED)?;
			trace.event(denied)?;
		}
		(_, AuthzClass::Success) => {
			trace.event(ok)?;
		}
		(_, AuthzClass::AuthzDenied) | (_, AuthzClass::InfraFail) => {
			trace.event(denied)?;
		}
	}
	Ok(())
}

fn is_authz_transport(err: &TightBeamError) -> bool {
	match err {
		TightBeamError::TransportError(TransportError::OperationFailed(failure)) => {
			matches!(failure, TransportFailure::PermissionDenied | TransportFailure::Unauthenticated)
		}
		_ => false,
	}
}

fn classify_stream_outcome(outcome: Result<bool, TightBeamError>) -> AuthzClass {
	match outcome {
		Ok(true) => AuthzClass::Success,
		Ok(false) => AuthzClass::InfraFail,
		Err(err) if is_authz_transport(&err) => AuthzClass::AuthzDenied,
		Err(_) => AuthzClass::InfraFail,
	}
}

/// One gateway work emit: request, frame id, shadow expectation, and outcome events.
struct ClusterWork<F> {
	request: ClusterWorkRequest,
	frame_id: &'static str,
	predicted: Prediction,
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
	let client = match identity {
		Some(id) => connect_with_identity(server_trust, id, dial_org.gateway.addr()).await,
		None => connect_anon(server_trust, dial_org.gateway.addr()).await,
	};

	let mut client = match client {
		Ok(client) => client,
		Err(_) => {
			record_authz_oracle(trace, work.predicted, AuthzClass::InfraFail, work.ok, work.denied)?;
			return Ok(());
		}
	};

	let frame = compose! {
		V0: id: work.frame_id,
		order: *order,
		message: ClusterRequest::Work(work.request)
	}?;

	*order += 1;

	let outcome = tokio::time::timeout(CLIENT_IO_TIMEOUT, client.emit(frame, None)).await;
	let class = match outcome {
		Ok(Ok(Some(response))) => classify_work_message(&response.message, work.is_success),
		_ => AuthzClass::InfraFail,
	};

	record_authz_oracle(trace, work.predicted, class, work.ok, work.denied)
}

/// Predict one hop against `org`'s export boundary through its shadow.
///
/// SPKI DER is borrowed from the identity bundle, encoded once in the
/// fixtures rather than re-encoded per prediction.
fn shadow_predict(
	org: &OrgNode,
	target: &Urn<'static>,
	identity: Option<&ClusterTestCerts>,
	relayed: bool,
) -> Prediction {
	org.predict(&AccessAttempt {
		target,
		caller_cert: identity.map(|id| id.cert.as_ref()),
		caller_spki: identity.map(|id| id.spki.as_ref()),
		relayed,
	})
}

/// Compose per-hop predictions along a path.
///
/// The composed prediction is [`Prediction::Allow`] only when every hop
/// allows. It is [`Prediction::Deny`] only when every hop denies. Any mix,
/// or any unmodeled hop, yields [`Prediction::Unmodeled`] so the oracle
/// never fires on a path the shadow cannot fully model.
fn compose_path(hops: impl IntoIterator<Item = Prediction>) -> Prediction {
	let mut all_allow = true;
	let mut all_deny = true;
	for hop in hops {
		match hop {
			Prediction::Allow => all_deny = false,
			Prediction::Deny => all_allow = false,
			Prediction::Unmodeled => {
				all_allow = false;
				all_deny = false;
			}
		}
	}

	if all_allow {
		Prediction::Allow
	} else if all_deny {
		Prediction::Deny
	} else {
		Prediction::Unmodeled
	}
}

async fn emit_work(trace: &TraceCollector, org: &OrgNode, selector: u8, order: &mut u64) -> Result<(), TightBeamError> {
	let target = target_urn(selector);
	let relayed = selector & 0x80 != 0;
	let predicted = shadow_predict(org, &target, Some(&org.certs), relayed);

	let mut request = ClusterWorkRequest::new(target.clone(), &inner_ping_frame()?)?;
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
			predicted,
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
	let predicted = shadow_predict(org, &target, Some(&org.certs), false);
	let spki = org_spki(org);

	let req = CsrRequest {
		spki: spki.to_vec(),
		colony: colony_urn(org.name).to_string(),
		cn: format!("csr-{}", selector),
	};
	let inner = compose! { V0: id: "colony-fuzz-csr-inner", order: 0u64, message: req }?;

	emit_cluster_work(
		trace,
		org,
		Some(&org.certs),
		order,
		ClusterWork {
			request: ClusterWorkRequest::new(target, &inner)?,
			frame_id: "colony-fuzz-csr",
			predicted,
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

	let advertiser_is_beta = selector & 1 == 0;
	let (class, predicted) = if advertiser_is_beta {
		let predicted = topo.alpha.predict_peer_ad(topo.beta.certs.cert.as_ref());
		let class = advertise_peer_types(trace, &topo.beta, &topo.alpha, types, order).await?;
		(class, predicted)
	} else {
		let predicted = topo.alpha.predict_peer_ad(topo.gamma.certs.cert.as_ref());
		let class = advertise_peer_types(trace, &topo.gamma, &topo.alpha, types, order).await?;
		(class, predicted)
	};

	record_authz_oracle(trace, predicted, class, events::PEER_AD_OK, events::PEER_AD_DENIED)
}

/// Drive the peer-advertisement deny path with `Prediction::Deny`.
///
/// The oracle byte selects one of two hostile shapes, either an
/// advertisement signed by an identity outside the receiver's peer-trust
/// set or a replayed `control_order`. The freshness/replay stage is not
/// modeled by the shadow (see [`crate::shadow`]), so the replay case
/// asserts `Deny` only when the priming advertisement landed. Each shape
/// expects the wire to refuse into `PEER_AD_DENIED`, never `SHADOW_VIOLATION`.
async fn negative_peer_ad(
	trace: &TraceCollector,
	topo: &mut ColonyTopology,
	selector: u8,
	control_order: &mut u64,
) -> Result<(), TightBeamError> {
	let types = vec![advertised_type(selector)];

	if selector & 1 == 0 {
		// Untrusted signer shape. Alpha signs an advertisement to its
		// own gateway, but alpha is not in alpha's peer-trust set, so
		// the peer-origin check refuses. The shadow agrees with Deny.
		let order = *control_order;

		*control_order += 1;

		let predicted = topo.alpha.predict_peer_ad(topo.alpha.certs.cert.as_ref());
		let class = advertise_peer_types(trace, &topo.alpha, &topo.alpha, types, order).await?;

		record_authz_oracle(trace, predicted, class, events::PEER_AD_OK, events::PEER_AD_DENIED)
	} else {
		// Replayed control order shape. A first legitimate advertisement
		// primes the replay guard, then the same signer resends at the
		// same order. The replay guard refuses the duplicate signature.
		let order = *control_order;

		*control_order += 1;

		let primed = topo.alpha.predict_peer_ad(topo.beta.certs.cert.as_ref());
		let prime_class = advertise_peer_types(trace, &topo.beta, &topo.alpha, types.clone(), order).await?;

		record_authz_oracle(trace, primed, prime_class, events::PEER_AD_OK, events::PEER_AD_DENIED)?;

		let replay_class = advertise_peer_types(trace, &topo.beta, &topo.alpha, types, order).await?;

		// A prime that did not land leaves the replay guard unprimed,
		// so the resend is fresh on the wire and may legitimately
		// succeed. Only a landed prime makes the duplicate order a
		// modeled `Deny`.
		let replay_predicted = if prime_class == AuthzClass::Success {
			Prediction::Deny
		} else {
			Prediction::Unmodeled
		};

		record_authz_oracle(
			trace,
			replay_predicted,
			replay_class,
			events::PEER_AD_OK,
			events::PEER_AD_DENIED,
		)
	}
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

	// Model the full cross-org path per hop. Alpha is the dial org and
	// does not serve peer-ping locally, so the request relays to the
	// downstream orgs that do (beta and gamma) with the dial org's
	// gateway certificate as caller and relayed = true. A mixed
	// composition yields Unmodeled.
	let dial_hop = shadow_predict(&topo.alpha, &target, Some(&topo.alpha.certs), relayed);
	let beta_hop = shadow_predict(&topo.beta, &target, Some(&topo.alpha.certs), true);
	let gamma_hop = shadow_predict(&topo.gamma, &target, Some(&topo.alpha.certs), true);
	let predicted = compose_path([dial_hop, beta_hop, gamma_hop]);

	let mut request = ClusterWorkRequest::new(target, &inner_ping_frame()?)?;
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
			predicted,
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

async fn stream_echo_roundtrip(
	mut sink: RequestSink,
	response: impl Future<Output = Result<Option<Frame>, TransportError>>,
) -> Result<bool, TightBeamError> {
	sink.push(b"abcd").await?;
	sink.close_with(b"efgh").await?;

	let reply = tokio::time::timeout(CLIENT_IO_TIMEOUT, response).await;
	match reply {
		Ok(Ok(Some(frame))) => match decode::<PingResponse>(&frame.message) {
			Ok(PingResponse { doubled: 8 }) => Ok(true),
			_ => Ok(false),
		},
		Ok(Err(err)) => Err(err.into()),
		Ok(Ok(None)) => Ok(false),
		Err(_) => Ok(false),
	}
}

async fn open_stream_action(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let target = servlet_urn("stream-echo");
	let relayed = selector & 0x80 != 0;
	let predicted = shadow_predict(org, &target, Some(&org.certs), relayed);
	let client = match pooled_client(trace, &org.certs, org.gateway.addr()).await {
		Ok(client) => client,
		Err(_) => {
			record_authz_oracle(
				trace,
				predicted,
				AuthzClass::InfraFail,
				events::STREAM_OK,
				events::STREAM_DENIED,
			)?;
			return Ok(());
		}
	};

	let outcome = if relayed {
		let (sink, response) = client.open_stream_with_route(relayed_to(target, 1))?;
		stream_echo_roundtrip(sink, response).await
	} else {
		let (sink, response) = client.open_stream_to(target)?;
		stream_echo_roundtrip(sink, response).await
	};

	record_authz_oracle(
		trace,
		predicted,
		classify_stream_outcome(outcome),
		events::STREAM_OK,
		events::STREAM_DENIED,
	)
}

async fn open_duplex_action(trace: &TraceCollector, org: &OrgNode, selector: u8) -> Result<(), TightBeamError> {
	let target = servlet_urn("stream-echo");
	let relayed = selector & 0x80 != 0;
	let predicted = shadow_predict(org, &target, Some(&org.certs), relayed);
	let client = match pooled_client(trace, &org.certs, org.gateway.addr()).await {
		Ok(client) => client,
		Err(_) => {
			record_authz_oracle(
				trace,
				predicted,
				AuthzClass::InfraFail,
				events::DUPLEX_OK,
				events::DUPLEX_DENIED,
			)?;
			return Ok(());
		}
	};

	let outcome: Result<bool, TightBeamError> = async {
		let (mut sink, mut body) = if relayed {
			client.open_duplex_with_route(relayed_to(target, 1))?
		} else {
			client.open_duplex_to(target)?
		};

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
			Ok(Ok(3)) => Ok(true),
			Ok(Err(err)) => Err(err),
			_ => Ok(false),
		}
	}
	.await;

	record_authz_oracle(
		trace,
		predicted,
		classify_stream_outcome(outcome),
		events::DUPLEX_OK,
		events::DUPLEX_DENIED,
	)
}

async fn hostile_anon_work(
	trace: &TraceCollector,
	org: &OrgNode,
	selector: u8,
	order: &mut u64,
) -> Result<(), TightBeamError> {
	trace.event(events::HOSTILE_ANON)?;

	let target = target_urn(selector);
	let predicted = shadow_predict(org, &target, None, false);

	emit_cluster_work(
		trace,
		org,
		None,
		order,
		ClusterWork {
			request: ClusterWorkRequest::new(target, &inner_ping_frame()?)?,
			frame_id: "colony-fuzz-anon",
			predicted,
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

	// The accept plane captures the possession-verified foreign identity
	// (validators are configured), so the boundary classifies that
	// certificate, not an anonymous session. Predict with it.
	let predicted = shadow_predict(pick_org_ref(topo, dial_idx), &target, Some(&identity), false);
	let request = ClusterWorkRequest::new(target, &inner_ping_frame()?)?;

	emit_cluster_work(
		trace,
		pick_org_ref(topo, dial_idx),
		Some(&identity),
		order,
		ClusterWork {
			request,
			frame_id: "colony-fuzz-foreign",
			predicted,
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
		let predicted = topo.alpha.predict_peer_ad(topo.beta.certs.cert.as_ref());
		let dead_class =
			advertise_peer_at(trace, &topo.beta, &topo.alpha, DEAD_PEER_ADDR, types.clone(), dead_order).await?;

		record_authz_oracle(trace, predicted, dead_class, events::PEER_AD_OK, events::PEER_AD_DENIED)?;
		pin_decoy_for(&topo.alpha.gateway, &topo.decoy_pin, "peer-ping", DEAD_PEER_ADDR);

		let live_class = advertise_peer_types(trace, &topo.beta, &topo.alpha, types, live_order).await?;
		record_authz_oracle(trace, predicted, live_class, events::PEER_AD_OK, events::PEER_AD_DENIED)?;
	} else {
		let predicted = topo.alpha.predict_peer_ad(topo.gamma.certs.cert.as_ref());
		let dead_class =
			advertise_peer_at(trace, &topo.gamma, &topo.alpha, DEAD_PEER_ADDR, types.clone(), dead_order).await?;

		record_authz_oracle(trace, predicted, dead_class, events::PEER_AD_OK, events::PEER_AD_DENIED)?;
		pin_decoy_for(&topo.alpha.gateway, &topo.decoy_pin, "peer-ping", DEAD_PEER_ADDR);

		let live_class = advertise_peer_types(trace, &topo.gamma, &topo.alpha, types, live_order).await?;
		record_authz_oracle(trace, predicted, live_class, events::PEER_AD_OK, events::PEER_AD_DENIED)?;
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

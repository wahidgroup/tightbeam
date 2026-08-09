//! Servlet export boundary integration tests.
//!
//! These scenarios prove discoverability and enforcement on federated
//! gateways with split trust planes. Gateway A anchors its own identity in
//! `hive_trust` and gateway B only in `peer_trust`, so A classifies B as an
//! external peer and its own certificate as first-party.
//!
//! # Planes
//!
//! - **Discoverability**: the advertise beat filters the slate through
//!   `exported_types`, so an observer never installs a trail for an
//!   unexported type.
//! - **Enforcement**: the fail-closed allowlist refuses unexported targets
//!   for external peers, relayed requests, and anonymous sessions, while
//!   A's own first-party origin traffic and exported targets stay routable.
//! - **Grants**: a positive `ExportGrant` opens one unexported target to a
//!   selected caller identity without advertising it.
//!
//! # Harness
//!
//! First-party recognition needs the inbound mutual-TLS accept plane, so
//! the enforcement scenarios turn on `client_validators` and dial with an
//! explicit client identity. Route claims are injected as direct signed
//! advertisements with the beats off, so every event count is exact.

use super::common::*;
use super::federation::{type_route_count, wait_for_type_routes};
use super::streaming::{pooled_cluster_client, StreamEchoServlet};
use tightbeam::colony::cluster::{ExportGate, ExportGrant, TrustPlanes};
use tightbeam::der::Encode;

/// Two organizations under split trust planes.
///
/// Each `GatewayCerts.trust` anchors only that organization's own identity.
/// A gateway places its own store on `hive_trust` and the other
/// organization's store on `peer_trust`, so a peer session is anchored on
/// exactly one plane.
///
/// # Classification at A
///
/// - A's own certificate is first-party.
/// - B's certificate is an external peer of A.
/// - C's certificate anchors on neither of A's planes: an admitted but
///   unplaced caller for the grant scenario.
struct ExportsCtx {
	a: Arc<ClusterTestCerts>,
	b: Arc<ClusterTestCerts>,
	c: Arc<ClusterTestCerts>,
}

fn exports_ctx() -> ExportsCtx {
	let (cert_a, key_a) = member_identity("Export Org A Gateway");
	let (cert_b, key_b) = member_identity("Export Org B Gateway");
	let (cert_c, key_c) = member_identity("Export Org C Client");
	let trust_a = combined_trust(&[&cert_a]);
	let trust_b = combined_trust(&[&cert_b]);
	let trust_c = combined_trust(&[&cert_c]);

	ExportsCtx {
		a: Arc::new(GatewayCerts { cert: cert_a, key: key_a, trust: trust_a }),
		b: Arc::new(GatewayCerts { cert: cert_b, key: key_b, trust: trust_b }),
		c: Arc::new(GatewayCerts { cert: cert_c, key: key_c, trust: trust_c }),
	}
}

/// Split-plane TLS for export scenarios.
///
/// - `hive_trust` anchors the organization's own identity.
/// - `peer_trust` anchors only the external peer.
fn split_plane_tls(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterTlsConfig {
	ClusterTlsConfig { peer_trust: Some(Arc::clone(&peer.trust)), ..cluster_tls_config(own) }
}

/// [`split_plane_tls`] with the inbound mutual-TLS accept plane on.
///
/// The gateway captures the caller certificate only under mutual TLS, so
/// first-party recognition of unexported origin traffic needs it. Both
/// organizations are admitted at the transport layer, and the export
/// boundary alone decides the verdict.
fn mtls_split_plane_tls(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterTlsConfig {
	let mut tls = split_plane_tls(own, peer);
	tls.client_validators = vec![combined_validator(&[&own.cert, &peer.cert])];
	tls
}

/// Exporter with a static export list and no advertise beat.
///
/// Used by the stream-boundary scenario, which injects route claims directly.
fn exporter_conf(own: &ClusterTestCerts, peer: &ClusterTestCerts, exported: Vec<Urn<'static>>) -> ClusterConfig {
	ClusterConfig::builder(split_plane_tls(own, peer))
		.with_exported_types(exported)
		.build()
}

/// [`exporter_conf`] on the mutual-TLS accept plane.
///
/// The gateway can then recognize a first-party origin session on an
/// unexported target.
fn mtls_exporter_conf(own: &ClusterTestCerts, peer: &ClusterTestCerts, exported: Vec<Urn<'static>>) -> ClusterConfig {
	ClusterConfig::builder(mtls_split_plane_tls(own, peer))
		.with_exported_types(exported)
		.build()
}

/// [`mtls_exporter_conf`] with one custom export gate beside the built-in
/// allowlist.
///
/// Used by the granular identity-rule scenario.
fn exporter_conf_with_gate(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	exported: Vec<Urn<'static>>,
	gate: Arc<dyn ExportGate>,
) -> ClusterConfig {
	ClusterConfig::builder(mtls_split_plane_tls(own, peer))
		.with_exported_types(exported)
		.with_export_gate(gate)
		.build()
}

/// Exporter on a fast beat toward `peer_addr`, carrying one grant.
///
/// Used by the ad-filter scenario, where discoverability itself is under
/// test. The grant proves the slate stays filtered even when a caller is
/// granted an unexported type, because grants are per-session and never
/// enter ads.
fn advertising_exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	peer_addr: String,
	exported: Vec<Urn<'static>>,
	grant: Arc<dyn ExportGrant>,
) -> ClusterConfig {
	ClusterConfig::builder(split_plane_tls(own, peer))
		.with_peers([peer_addr])
		.with_advertise_interval(Duration::from_millis(100))
		.with_rumor_refresh(Duration::from_millis(200))
		.with_exported_types(exported)
		.with_export_grant(grant)
		.build()
}

/// [`mtls_exporter_conf`] with one positive grant and a third admitted
/// client identity.
///
/// The extra identity must pass the transport accept so the export
/// boundary, not TLS, is what refuses it.
fn grant_exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	extra: &ClusterTestCerts,
	exported: Vec<Urn<'static>>,
	grant: Arc<dyn ExportGrant>,
) -> ClusterConfig {
	let mut tls = split_plane_tls(own, peer);
	tls.client_validators = vec![combined_validator(&[&own.cert, &peer.cert, &extra.cert])];

	ClusterConfig::builder(tls)
		.with_exported_types(exported)
		.with_export_grant(grant)
		.build()
}

/// Grant opening one target to one caller public key.
///
/// The granted subject is the adjacent authenticated principal, so on a
/// relayed request the key belongs to the relaying peer gateway.
struct PartnerGrant {
	spki: Vec<u8>,
	target: Urn<'static>,
}

impl ExportGrant for PartnerGrant {
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> bool {
		*target == self.target && session.peer_public_key() == Some(self.spki.as_slice())
	}
}

/// [`PartnerGrant`] for `holder`'s certificate key on `target`.
fn partner_grant(holder: &ClusterTestCerts, target: Urn<'static>) -> Result<Arc<dyn ExportGrant>, TightBeamError> {
	let spki = holder.cert.tbs_certificate.subject_public_key_info.to_der()?;
	Ok(Arc::new(PartnerGrant { spki, target }))
}

/// Edge peer that receives advertisements from the exporter and forwards
/// work to it.
///
/// It runs no beat and carries no export list of its own.
fn edge_peer_conf(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterConfig {
	peering_cluster_conf_with_trust(own, Arc::clone(&peer.trust))
}

/// Hive hosting the echo servlet under two unary types.
///
/// - Exported: `"ping"`.
/// - Private: `"ledger"`.
async fn start_split_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let exported = ClusterTestServlet::start(Arc::new(trace.share()), Some(servlet_tls_config(&certs)?)).await?;
	let hidden = ClusterTestServlet::start(Arc::new(trace.share()), Some(servlet_tls_config(&certs)?)).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("ping"), exported, |t| ClusterTestServlet::start(t, None))?;
	hive.register(servlet_urn("ledger"), hidden, |t| ClusterTestServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Hive hosting the stream-echo servlet under two stream types.
///
/// - Exported: `"stream-echo"`.
/// - Private: `"vault"`.
async fn start_split_stream_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let exported = StreamEchoServlet::start(Arc::new(trace.share()), Some(servlet_tls_config(&certs)?)).await?;
	let hidden = StreamEchoServlet::start(Arc::new(trace.share()), Some(servlet_tls_config(&certs)?)).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("stream-echo"), exported, |t| StreamEchoServlet::start(t, None))?;
	hive.register(servlet_urn("vault"), hidden, |t| StreamEchoServlet::start(t, None))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Emit work and record the doubled echo under `marker`.
async fn record_echo(
	trace: &TraceCollector,
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	type_name: &str,
	id: &[u8],
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	trace.event(WORK_SENT)?;
	let servlet_frame = emit_typed_work(client, key, type_name, id).await?;
	let ping_response = decode_ping_echo(&servlet_frame)?;
	trace.event_with(marker, &[], u64::from(ping_response.doubled))?;
	Ok(())
}

/// Client dialing `server_trust`'s gateway under `identity`, for a
/// mutual-TLS gateway that captures the caller certificate.
async fn connect_with_identity(
	server_trust: Arc<dyn CertificateTrust>,
	identity: &ClusterTestCerts,
	addr: &<TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_trust_store(server_trust)
		.with_client_identity(
			CertificateSpec::Built(Box::new(identity.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned())),
		)?
		.build()
		.connect(addr)
		.await?)
}

tb_assert_spec! {
	pub ClusterExportAdFilterSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(EXPORT_HIDDEN_ROUTES, exactly!(1), equals!(0u64))
		]
	}
}

// # Discoverability
//
// The beat advertises only the exported slate. The exporter serves "ping"
// and "ledger" but exports "ping" alone, while a grant opens "ledger" to
// B's key. Every beat frame (direct ad and slate rumor) carries the filtered
// slate, so the observer installs exactly one ping trail and zero ledger
// trails. The grant never enters ads. One ad carries the whole slate, so
// once ping is installed the ledger absence is decisive, not a race.
tb_scenario! {
	name: cluster_export_list_filters_advertised_slate,
	spec: ClusterExportAdFilterSpec,
	environment Hive {
		context: exports_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_split_hive(trace, Arc::clone(&ctx.a)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let observer = start_cluster(&trace, edge_peer_conf(&ctx.b, &ctx.a)).await?;
			let conf_a = advertising_exporter_conf(
				&ctx.a,
				&ctx.b,
				observer.addr().to_string(),
				vec![servlet_urn("ping")],
				partner_grant(&ctx.b, servlet_urn("ledger"))?,
			);
			let exporter = start_cluster(&trace, conf_a).await?;

			hive.register_with_cluster(exporter.addr()).await?;

			let installed = wait_for_type_routes(&observer, "ping", 1, 100, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], installed as u64)?;
			trace.event_with(EXPORT_HIDDEN_ROUTES, &[], type_route_count(&observer, "ledger") as u64)?;

			exporter.stop();
			observer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterExportUnaryBoundarySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(2u64)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(2)),
			(EXPORT_DENIED_STATUS, exactly!(2), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2)),
			(EXPORT_PEER_ECHOED, exactly!(1), equals!(42u64)),
			(EXPORT_LOCAL_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// # Enforcement (unary)
//
// The boundary refuses what the filter hides. B holds injected trails for
// both of A's types, as if it had learned them before the export list
// narrowed (guessing a name and holding a stale trail are the same attack).
// The scenario drives all four verdicts the fail-closed allowlist
// distinguishes:
//
// 1. B relays "ledger": the request spent relay budget, so the allowlist
//    refuses it (`PermissionDenied`, `CLUSTER_EXPORT_REFUSED`).
// 2. B relays "ping": exported, served, echoed.
// 3. B dials A directly and sends "ledger" at the origin budget: not
//    relayed, but B's certificate is an external peer, so the identity rule
//    refuses it. This is the fail-closed case a default-allow gate would
//    have admitted.
// 4. A's own client dials A directly with A's first-party identity and
//    reaches "ledger": a recognized origin caller crosses the boundary.
tb_scenario! {
	name: cluster_export_boundary_refuses_relayed_unexported_work,
	spec: ClusterExportUnaryBoundarySpec,
	environment Hive {
		context: exports_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_split_hive(trace, Arc::clone(&ctx.a)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let gateway_a = start_cluster(&trace, mtls_exporter_conf(&ctx.a, &ctx.b, vec![servlet_urn("ping")])).await?;
			let gateway_b = start_cluster(&trace, edge_peer_conf(&ctx.b, &ctx.a)).await?;

			hive.register_with_cluster(gateway_a.addr()).await?;

			// The route claim B would hold from before the list
			// narrowed: A's own signature, both types.
			let a_addr = gateway_a.addr().to_string();
			advertise_peer_signed(
				&trace,
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("ping"), servlet_urn("ledger")],
			)
			.await?;

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_typed_work(&mut client_b, &ctx.b.key, "ledger", b"export-relayed-work").await;
			let relayed_denied = work_refusal_status(refused_work)?;
			trace.event_with(EXPORT_DENIED_STATUS, &[], relayed_denied)?;

			record_echo(&trace, &mut client_b, &ctx.b.key, "ping", b"export-peer-work", EXPORT_PEER_ECHOED).await?;

			let mut peer_direct = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.b, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_typed_work(&mut peer_direct, &ctx.b.key, "ledger", b"export-identity-work").await;
			let identity_denied = work_refusal_status(refused_work)?;
			trace.event_with(EXPORT_DENIED_STATUS, &[], identity_denied)?;

			let mut client_a = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.a, gateway_a.addr()).await?;
			record_echo(&trace, &mut client_a, &ctx.a.key, "ledger", b"export-local-work", EXPORT_LOCAL_ECHOED).await?;

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterExportGrantSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(2)),
			(events::CLUSTER_EXPORT_GRANTED, exactly!(1), equals!(true)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(EXPORT_GRANT_ECHOED, exactly!(1), equals!(42u64)),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(1), equals!(false)),
			(EXPORT_DENIED_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// # Grants (positive per-identity widening)
//
// A exports "ping" alone and grants "ledger" to B's gateway key. B holds an
// injected ledger claim (the URN a granted partner knows out of band).
//
// 1. B relays "ledger": the built-in allowlist refuses it, the grant
//    matches B's session key, and the work is served. The audit event
//    carries the relayed flag (`CLUSTER_EXPORT_GRANTED` value `true`).
// 2. C dials A directly with an admitted but ungranted identity and sends
//    "ledger" at the origin budget: no allow source matches, so the
//    boundary refuses (`CLUSTER_EXPORT_REFUSED` value `false`), proving the
//    grant keys on one identity rather than opening the target.
//
// Discoverability of granted types is covered by the ad-filter scenario,
// whose exporter carries this same grant while the slate stays filtered.
tb_scenario! {
	name: cluster_export_grant_opens_private_type_for_partner,
	spec: ClusterExportGrantSpec,
	environment Hive {
		context: exports_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_split_hive(trace, Arc::clone(&ctx.a)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let conf_a = grant_exporter_conf(
				&ctx.a,
				&ctx.b,
				&ctx.c,
				vec![servlet_urn("ping")],
				partner_grant(&ctx.b, servlet_urn("ledger"))?,
			);
			let gateway_a = start_cluster(&trace, conf_a).await?;
			let gateway_b = start_cluster(&trace, edge_peer_conf(&ctx.b, &ctx.a)).await?;

			hive.register_with_cluster(gateway_a.addr()).await?;

			// The ledger claim a granted partner holds out of band.
			let a_addr = gateway_a.addr().to_string();
			advertise_peer_signed(
				&trace,
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("ledger")],
			)
			.await?;

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;
			record_echo(&trace, &mut client_b, &ctx.b.key, "ledger", b"export-grant-work", EXPORT_GRANT_ECHOED).await?;

			let mut client_c = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.c, gateway_a.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_typed_work(&mut client_c, &ctx.c.key, "ledger", b"export-ungranted-work").await;
			let ungranted_denied = work_refusal_status(refused_work)?;
			trace.event_with(EXPORT_DENIED_STATUS, &[], ungranted_denied)?;

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterExportStreamBoundarySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(2u64)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(3)),
			(events::CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, exactly!(1)),
			(events::CLUSTER_EXPORT_UNBOUNDED, exactly!(1)),
			(EXPORT_STREAM_REFUSED, exactly!(1), equals!(true)),
			(EXPORT_DUPLEX_REFUSED, exactly!(1), equals!(true)),
			(EXPORT_ANON_REFUSED, exactly!(1), equals!(true)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(STREAM_SERVLET_HANDLED, exactly!(1)),
			(STREAM_ECHOED, exactly!(1), equals!(8u64))
		]
	}
}

// # Enforcement (stream)
//
// The twin of the unary boundary across both stream openers.
//
// 1. A peer-spliced stream open for the unexported "vault" is refused at
//    A's edge before any route is consulted, and the response future errors.
// 2. A peer-spliced duplex open for "vault" is refused the same way, so
//    neither opener bypasses the boundary.
// 3. An anonymous client dialing A directly is refused on "vault" at the
//    origin budget: without an identity there is no first-party pass.
// 4. The exported "stream-echo" splices through B to A's servlet and echoes
//    the body length, proving the refusal is target-scoped, not plane-wide.
// 5. The posture warnings fire once each: A exports without identity capture
//    and B federates without an export list.
tb_scenario! {
	name: cluster_export_boundary_refuses_unexported_stream_open,
	spec: ClusterExportStreamBoundarySpec,
	environment Hive {
		context: exports_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_split_stream_hive(trace, Arc::clone(&ctx.a)).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let conf_a = with_mux_offer(exporter_conf(&ctx.a, &ctx.b, vec![servlet_urn("stream-echo")]));
			let gateway_a = start_cluster(&trace, conf_a).await?;
			let conf_b = with_mux_offer(edge_peer_conf(&ctx.b, &ctx.a));
			let gateway_b = start_cluster(&trace, conf_b).await?;

			hive.register_with_cluster(gateway_a.addr()).await?;

			let a_addr = gateway_a.addr().to_string();
			advertise_peer_signed(
				&trace,
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("stream-echo"), servlet_urn("vault")],
			)
			.await?;

			let client = pooled_cluster_client(&trace, &ctx.b, gateway_b.addr()).await?;

			trace.event(WORK_SENT)?;

			let (sink, response) = client.open_stream_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let stream_refused = response.await.is_err();
			trace.event_with(EXPORT_STREAM_REFUSED, &[], stream_refused)?;
			trace.event(WORK_SENT)?;

			let (sink, mut body) = client.open_duplex_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let duplex_refused = body.chunk().await.is_err();
			trace.event_with(EXPORT_DUPLEX_REFUSED, &[], duplex_refused)?;
			trace.event(WORK_SENT)?;

			let anon_client = pooled_cluster_client(&trace, &ctx.a, gateway_a.addr()).await?;
			let (sink, response) = anon_client.open_stream_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let anon_refused = response.await.is_err();
			trace.event_with(EXPORT_ANON_REFUSED, &[], anon_refused)?;
			trace.event(WORK_SENT)?;

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = decode(&reply.message)?;
			trace.event_with(STREAM_ECHOED, &[], u64::from(echoed.doubled))?;

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Custom export gate that denies one authenticated peer key on one target.
///
/// This is the granular identity-rule DX the trait exists for.
struct DenyPeerKeyGate {
	denied_spki: Vec<u8>,
	target: Urn<'static>,
}

impl ExportGate for DenyPeerKeyGate {
	fn evaluate(
		&self,
		target: &Urn<'_>,
		session: &SessionContext,
		_planes: &TrustPlanes<'_>,
		_relayed: bool,
	) -> TransitStatus {
		if *target == self.target && session.peer_public_key() == Some(self.denied_spki.as_slice()) {
			return TransitStatus::PermissionDenied;
		}

		TransitStatus::Ok
	}
}

tb_assert_spec! {
	pub ClusterExportCustomGateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(2)),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(1), equals!(true)),
			(EXPORT_DENIED_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(EXPORT_LOCAL_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// # Custom gate
//
// "ping" is exported, so the allowlist passes it for everyone. The custom
// gate then denies exactly B's authenticated session key:
//
// 1. B relays ping work: A's session shows B's certificate from the
//    mutual-TLS handshake, the gate matches its public key, and the work
//    refuses with `CLUSTER_EXPORT_REFUSED`.
// 2. A's own client, presenting A's identity on the same mutual-TLS accept
//    plane, reaches ping untouched: the denial keys on the session identity
//    rather than on the target or the plane.
tb_scenario! {
	name: cluster_custom_export_gate_denies_one_peer_identity,
	spec: ClusterExportCustomGateSpec,
	environment Hive {
		context: exports_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_ping_hive(trace, Arc::clone(&ctx.a), None).await
		},
		client: |HiveEnv { trace, context: ctx, hive }| async move {
			let denied_spki = ctx.b.cert.tbs_certificate.subject_public_key_info.to_der()?;
			let gate = Arc::new(DenyPeerKeyGate { denied_spki, target: servlet_urn("ping") });
			let conf_a = exporter_conf_with_gate(&ctx.a, &ctx.b, vec![servlet_urn("ping")], gate);
			let gateway_a = start_cluster(&trace, conf_a).await?;
			let gateway_b = start_cluster(&trace, edge_peer_conf(&ctx.b, &ctx.a)).await?;

			hive.register_with_cluster(gateway_a.addr()).await?;

			let a_addr = gateway_a.addr().to_string();
			advertise_peer_signed(&trace, &ctx.b, &ctx.a.key, &gateway_b, a_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;
			trace.event(WORK_SENT)?;

			let refused_work = emit_typed_work(&mut client_b, &ctx.b.key, "ping", b"gate-denied-work").await;
			let denied = work_refusal_status(refused_work)?;
			trace.event_with(EXPORT_DENIED_STATUS, &[], denied)?;

			let mut client_a = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.a, gateway_a.addr()).await?;
			record_echo(&trace, &mut client_a, &ctx.a.key, "ping", b"gate-local-work", EXPORT_LOCAL_ECHOED).await?;

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

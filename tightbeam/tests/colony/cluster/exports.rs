//! Integration tests of the servlet export boundary.
//!
//! These scenarios prove discoverability and enforcement on federated
//! gateways with split trust planes. Gateway A anchors its own identity in
//! `hive_trust` and gateway B only in `peer_trust`, so A classifies B as an
//! external peer and its own certificate as first-party.
//!
//! # Planes
//!
//! - **Discoverability**: the advertise beat filters the slate through
//!   `exported_types`, so an observer installs trails for exported types
//!   alone.
//! - **Enforcement**: the fail-closed allowlist refuses unexported targets
//!   for external peers, relayed requests, and anonymous sessions, while
//!   A's own first-party origin traffic and exported targets stay routable.
//! - **Grants**: a positive `ExportGrant` opens one unexported target to a
//!   selected caller identity, while the ads leave that target out.
//!
//! # Harness
//!
//! First-party recognition needs the inbound mutual-TLS accept plane, so
//! the enforcement scenarios turn on `client_authentication` and dial with an
//! explicit client identity. The scenarios inject route claims as direct
//! signed advertisements with the beats off, so every event count is exact.

use super::common::*;
use super::federation::{type_route_count, wait_for_type_routes};
use super::streaming::{pooled_cluster_client, StreamEchoServlet};
use tightbeam::colony::cluster::{ExportGate, ExportGrant, TrustPlanes};
use tightbeam::colony::hive::PeerListGate;
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::der::Encode;

/// Two organizations under split trust planes.
///
/// Each `GatewayCerts.trust` anchors only that organization's own identity.
/// A gateway places its own store on `hive_trust` and the other
/// organization's store on `peer_trust`, so a peer session anchors on
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

/// The split-plane TLS of the export scenarios.
///
/// - `hive_trust` anchors the organization's own identity.
/// - `peer_trust` anchors only the external peer.
fn split_plane_tls(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterTlsConfig {
	cluster_tls_config(own).with_peer_trust(Arc::clone(&peer.trust))
}

/// [`split_plane_tls`] with the inbound mutual-TLS accept plane on.
///
/// The gateway captures the caller certificate only under mutual TLS, so
/// first-party recognition of unexported origin traffic needs it. The
/// transport layer admits both organizations, and the export boundary alone
/// decides the verdict.
fn mtls_split_plane_tls(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterTlsConfig {
	let mut tls = split_plane_tls(own, peer);
	tls.client_authentication = PeerAuthentication::Anonymous.and(combined_validator(&[&own.cert, &peer.cert]));
	tls
}

/// An exporter with a static export list and no advertise beat.
///
/// The stream-boundary scenario uses it and injects route claims directly.
fn exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	exported: impl IntoIterator<Item = Urn<'static>>,
) -> ClusterConfig {
	let exported: Vec<Urn<'static>> = exported.into_iter().collect();
	ClusterConfig::builder(split_plane_tls(own, peer))
		.with_exported_types(exported)
		.build()
}

/// [`exporter_conf`] on the mutual-TLS accept plane.
///
/// The gateway can then recognize a first-party origin session on an
/// unexported target.
fn mtls_exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	exported: impl IntoIterator<Item = Urn<'static>>,
) -> ClusterConfig {
	let exported: Vec<Urn<'static>> = exported.into_iter().collect();
	ClusterConfig::builder(mtls_split_plane_tls(own, peer))
		.with_exported_types(exported)
		.build()
}

/// [`mtls_exporter_conf`] with one custom export gate beside the built-in
/// allowlist.
///
/// The granular identity-rule scenario uses it.
fn exporter_conf_with_gate(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	exported: impl IntoIterator<Item = Urn<'static>>,
	gate: Arc<dyn ExportGate>,
) -> ClusterConfig {
	let exported: Vec<Urn<'static>> = exported.into_iter().collect();
	ClusterConfig::builder(mtls_split_plane_tls(own, peer))
		.with_exported_types(exported)
		.with_export_gate(gate)
		.build()
}

/// An exporter on a fast beat toward `peer_addr`, which carries one grant.
///
/// The ad-filter scenario uses it. The grant proves that the slate stays
/// filtered when a grant opens an unexported type to a caller, because
/// grants are per-session and stay out of ads.
fn advertising_exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	peer_addr: impl Into<String>,
	exported: impl IntoIterator<Item = Urn<'static>>,
	grant: Arc<dyn ExportGrant>,
) -> ClusterConfig {
	let peer_addr: String = peer_addr.into();
	let exported: Vec<Urn<'static>> = exported.into_iter().collect();
	ClusterConfig::builder(split_plane_tls(own, peer))
		.with_peers([peer_addr])
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
		.with_rumor_refresh(Duration::from_millis(200))
		.with_exported_types(exported)
		.with_export_grant(grant)
		.build()
}

/// [`mtls_exporter_conf`] with one positive grant and a third admitted
/// client identity.
///
/// The extra identity must pass the transport accept, so the refusal comes
/// from the export boundary alone.
fn grant_exporter_conf(
	own: &ClusterTestCerts,
	peer: &ClusterTestCerts,
	extra: &ClusterTestCerts,
	exported: impl IntoIterator<Item = Urn<'static>>,
	grant: Arc<dyn ExportGrant>,
) -> ClusterConfig {
	let exported: Vec<Urn<'static>> = exported.into_iter().collect();
	let mut tls = split_plane_tls(own, peer);
	tls.client_authentication =
		PeerAuthentication::Anonymous.and(combined_validator(&[&own.cert, &peer.cert, &extra.cert]));

	ClusterConfig::builder(tls)
		.with_exported_types(exported)
		.with_export_grant(grant)
		.build()
}

/// A grant that opens one target to one caller public key.
///
/// The granted subject is the adjacent authenticated principal, so on a
/// relayed request the key belongs to the relaying peer gateway.
struct PartnerGrant {
	partners: PeerListGate,
	target: Urn<'static>,
}

impl ExportGrant for PartnerGrant {
	fn grants(&self, target: &Urn<'_>, session: &SessionContext, _relayed: bool) -> bool {
		*target == self.target && GatePolicy::evaluate(&self.partners, None, session) == TransitStatus::Ok
	}
}

/// [`PartnerGrant`] for `holder`'s certificate key on `target`.
fn partner_grant(holder: &ClusterTestCerts, target: Urn<'static>) -> Result<Arc<dyn ExportGrant>, TightBeamError> {
	let spki = holder.cert.tbs_certificate.subject_public_key_info.to_der()?;
	let partners = PeerListGate::allow([spki])?;
	Ok(Arc::new(PartnerGrant { partners, target }))
}

/// An edge peer that receives advertisements from the exporter and forwards
/// work to it.
///
/// It keeps the default config, whose beat is off and whose export list is
/// unset.
fn edge_peer_conf(own: &ClusterTestCerts, peer: &ClusterTestCerts) -> ClusterConfig {
	peering_cluster_conf_with_trust(own, Arc::clone(&peer.trust))
}

/// A hive that hosts the echo servlet under two unary types.
///
/// - Exported: `"ping"`.
/// - Private: `"ledger"`.
async fn start_split_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let exported = ClusterTestServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
	let hidden = ClusterTestServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("ping"), exported, |t| {
		ClusterTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.register(servlet_urn("ledger"), hidden, |t| {
		ClusterTestServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// A hive that hosts the stream-echo servlet under two stream types.
///
/// - Exported: `"stream-echo"`.
/// - Private: `"vault"`.
async fn start_split_stream_hive(
	trace: TraceCollector,
	certs: Arc<ClusterTestCerts>,
) -> Result<ClusterTestHive, TightBeamError> {
	let exported = StreamEchoServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;
	let hidden = StreamEchoServlet::start(Arc::new(trace.share()), servlet_tls_config(&certs)?).await?;

	let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
	hive.register(servlet_urn("stream-echo"), exported, |t| {
		StreamEchoServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.register(servlet_urn("vault"), hidden, |t| {
		StreamEchoServlet::start(t, ServletConfig::cleartext())
	})?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Emits work under `type_name`, and returns the servlet's decoded echo.
async fn typed_echo(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	type_name: impl AsRef<str>,
	id: impl AsRef<[u8]>,
) -> Result<PingResponse, TightBeamError> {
	let type_name = type_name.as_ref();
	let id = id.as_ref();
	let servlet_frame = emit_typed_work(client, key, type_name, id).await?;
	decode_ping_echo(&servlet_frame)
}

/// A client that dials `server_trust`'s gateway under `identity`, for a
/// mutual-TLS gateway that captures the caller certificate.
async fn connect_with_identity(
	server_trust: Arc<dyn CertificateTrust>,
	identity: &ClusterTestCerts,
	addr: &<TokioListener as tightbeam::transport::Protocol>::Address,
) -> Result<GenericClient<TokioListener>, TightBeamError> {
	Ok(ClientBuilder::<TokioListener>::builder()
		.with_trust_store(server_trust)
		.with_client_identity(SigningIdentity::from_spec(
			CertificateSpec::Built(Box::new(identity.cert.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(identity.key.to_owned())),
		)?)
		.build()
		.connect(addr.to_owned())
		.await?)
}

tb_assert_spec! {
	pub ClusterExportAdFilterSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// # Discoverability
//
// The exporter serves "ping" and "ledger", exports "ping" alone, and grants
// "ledger" to B's key.
//
// - Every beat frame (direct ad and slate rumor) carries the filtered slate, so
//   the observer installs exactly one ping trail and zero ledger trails.
// - One ad carries the whole slate, so once the ping trail installs, the
//   absent ledger trail is decisive and not a race.
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
			wait_for_direct_advertisement(&trace, 100, Duration::from_millis(100)).await;
			let hidden = type_route_count(&observer, "ledger");
			assert_eq!(installed, 1, "the observer installs the one exported ping trail");
			assert_eq!(hidden, 0, "the export list keeps ledger out of every advertised slate");

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
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(2)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(2))
		]
	}
}

// # Enforcement (unary)
//
// The boundary refuses what the filter hides. B holds injected trails for
// both of A's types, as a guessed name or a trail from before the export list
// narrowed would give it. The fail-closed allowlist gives four verdicts:
//
// 1. B relays "ledger": the request spent relay budget, so the allowlist
//    refuses it (`PermissionDenied`, `CLUSTER_EXPORT_REFUSED`).
// 2. B relays "ping": the target is exported, so A serves it and the echo returns.
// 3. B dials A directly and sends "ledger" at the origin budget. B's
//    certificate is an external peer, so the identity rule refuses it, where
//    a default-allow gate would admit it.
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
			let ad_reply = advertise_peer_signed(
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("ping"), servlet_urn("ledger")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_b.peer_servlets()?.len(), 2, "B holds a claim for both of A's types");

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;

			let refused_work = emit_typed_work(&mut client_b, &ctx.b.key, "ledger", b"export-relayed-work").await;
			let relayed_denied = work_refusal_status(refused_work)?;
			assert_eq!(relayed_denied, TransitStatus::PermissionDenied, "the export boundary refuses the relayed call");

			let echo = typed_echo(&mut client_b, &ctx.b.key, "ping", b"export-peer-work").await?;
			assert_eq!(echo.doubled, 42, "the work echoes");

			let mut peer_direct = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.b, gateway_a.addr()).await?;

			let refused_work = emit_typed_work(&mut peer_direct, &ctx.b.key, "ledger", b"export-identity-work").await;
			let identity_denied = work_refusal_status(refused_work)?;
			assert_eq!(identity_denied, TransitStatus::PermissionDenied, "the export boundary refuses the peer's call");

			let mut client_a = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.a, gateway_a.addr()).await?;
			let echo = typed_echo(&mut client_a, &ctx.a.key, "ledger", b"export-local-work").await?;
			assert_eq!(echo.doubled, 42, "the work echoes");

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
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_EXPORT_GRANTED, exactly!(1), equals!(true)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(1), equals!(false))
		]
	}
}

// # Grants (positive per-identity widening)
//
// A exports "ping" alone and grants "ledger" to B's gateway key. B holds an
// injected ledger claim (the URN a granted partner knows out of band).
//
// 1. B relays "ledger": the built-in allowlist refuses it, the grant
//    matches B's session key, and A serves the work. The audit event
//    carries the relayed flag (`CLUSTER_EXPORT_GRANTED` value `true`).
// 2. C dials A directly with an admitted but ungranted identity and sends
//    "ledger" at the origin budget: no allow source matches, so the
//    boundary refuses (`CLUSTER_EXPORT_REFUSED` value `false`). That proves
//    the grant opens the target to one identity alone.
//
// The ad-filter scenario covers the discoverability of granted types, because
// its exporter carries this same grant while the slate stays filtered.
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
			let ad_reply = advertise_peer_signed(
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("ledger")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_b.peer_servlets()?.len(), 1, "B holds the ledger claim");

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;
			let echo = typed_echo(&mut client_b, &ctx.b.key, "ledger", b"export-grant-work").await?;
			assert_eq!(echo.doubled, 42, "the work echoes");

			let mut client_c = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.c, gateway_a.addr()).await?;

			let refused_work = emit_typed_work(&mut client_c, &ctx.c.key, "ledger", b"export-ungranted-work").await;
			let ungranted_denied = work_refusal_status(refused_work)?;
			assert_eq!(ungranted_denied, TransitStatus::PermissionDenied, "the boundary refuses the ungranted call");

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
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(3)),
			(events::CLUSTER_EXPORT_IDENTITY_UNAVAILABLE, exactly!(1)),
			(events::CLUSTER_EXPORT_UNBOUNDED, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(STREAM_SERVLET_HANDLED, exactly!(1))
		]
	}
}

// # Enforcement (stream)
//
// This scenario is the twin of the unary boundary across both stream openers.
//
// 1. A's edge refuses a peer-spliced stream open for the unexported "vault"
//    before it consults any route, and the response future errors.
// 2. A's edge refuses a peer-spliced duplex open for "vault" the same way, so
//    neither opener bypasses the boundary.
// 3. A refuses "vault" at the origin budget to an anonymous client that dials
//    it directly, because a session with no identity gets no first-party pass.
// 4. The exported "stream-echo" splices through B to A's servlet and echoes
//    the body length. That proves the refusal is target-scoped, not plane-wide.
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
			let ad_reply = advertise_peer_signed(
				&ctx.b,
				&ctx.a.key,
				&gateway_b,
				a_addr.as_bytes(),
				vec![servlet_urn("stream-echo"), servlet_urn("vault")],
			)
			.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_b.peer_servlets()?.len(), 2, "B holds a claim for both of A's types");

			let client = pooled_cluster_client(&trace, &ctx.b, gateway_b.addr()).await?;

			let (sink, response) = client.open_stream_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let stream_refused = response.await.is_err();
			assert!(stream_refused, "the export boundary refuses the spliced stream open");

			let (sink, mut body) = client.open_duplex_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let duplex_refused = body.chunk().await.is_err();
			assert!(duplex_refused, "the export boundary refuses the spliced duplex open");

			let anon_client = pooled_cluster_client(&trace, &ctx.a, gateway_a.addr()).await?;
			let (sink, response) = anon_client.open_stream_to(servlet_urn("vault"))?;
			sink.close_with(b"denied").await?;

			let anon_refused = response.await.is_err();
			assert!(anon_refused, "the export boundary refuses the anonymous stream open");

			let (mut sink, response) = client.open_stream_to(servlet_urn("stream-echo"))?;
			sink.push(b"abcd").await?;
			sink.close_with(b"efgh").await?;

			let reply = response.await?.ok_or(TightBeamError::MissingResponse)?;
			let echoed: PingResponse = reply.decode_message()?;
			assert_eq!(echoed.doubled, 8, "the exported type splices through B to A's servlet");

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A custom export gate that denies one authenticated peer key on one target.
///
/// It is the granular identity rule that the trait exists for.
struct DenyPeerKeyGate {
	denied: PeerListGate,
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
		if *target == self.target {
			return GatePolicy::evaluate(&self.denied, None, session);
		}

		TransitStatus::Ok
	}
}

tb_assert_spec! {
	pub ClusterExportCustomGateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_EXPORT_REFUSED, exactly!(1), equals!(true)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1))
		]
	}
}

// # Custom gate
//
// "ping" is exported, so the allowlist passes it for everyone. The custom
// gate then denies exactly B's authenticated session key:
//
// 1. B relays ping work: A's session shows B's certificate from the
//    mutual-TLS handshake, the gate matches its public key, and A refuses the
//    work with `CLUSTER_EXPORT_REFUSED`.
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
			let denied = PeerListGate::deny([denied_spki])?;
			let gate = Arc::new(DenyPeerKeyGate { denied, target: servlet_urn("ping") });
			let conf_a = exporter_conf_with_gate(&ctx.a, &ctx.b, vec![servlet_urn("ping")], gate);
			let gateway_a = start_cluster(&trace, conf_a).await?;
			let gateway_b = start_cluster(&trace, edge_peer_conf(&ctx.b, &ctx.a)).await?;

			hive.register_with_cluster(gateway_a.addr()).await?;

			let a_addr = gateway_a.addr().to_string();
			let ad_reply = advertise_peer_signed(&ctx.b, &ctx.a.key, &gateway_b, a_addr.as_bytes(), vec![servlet_urn("ping")])
				.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(gateway_b.peer_servlets()?.len(), 1, "B holds the ping claim");

			let mut client_b = connect_cluster(&ctx.b, gateway_b.addr()).await?;

			let refused_work = emit_typed_work(&mut client_b, &ctx.b.key, "ping", b"gate-denied-work").await;
			let denied = work_refusal_status(refused_work)?;
			assert_eq!(denied, TransitStatus::PermissionDenied, "the custom gate refuses B's call");

			let mut client_a = connect_with_identity(Arc::clone(&ctx.a.trust), &ctx.a, gateway_a.addr()).await?;
			let echo = typed_echo(&mut client_a, &ctx.a.key, "ping", b"gate-local-work").await?;
			assert_eq!(echo.doubled, 42, "the work echoes");

			gateway_b.stop();
			gateway_a.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// A federated configuration with no export list, bound at `bind`, that
/// beats toward one peer that never answers.
fn unbounded_federated_conf(certs: &ClusterTestCerts, bind: impl Into<String>) -> ClusterConfig {
	ClusterConfig::builder(cluster_tls_config(certs))
		.with_bind_addr(bind)
		.with_peers(["127.0.0.1:65211"])
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

// A gateway reports its export posture once it decides the address it
// advertises. A federated gateway that refuses its wildcard bind reports no
// posture, and the same gateway on a loopback bind reports it once.
#[tokio::test]
async fn a_gateway_reports_its_export_posture_only_once_it_starts() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let refused_trace = TraceCollector::new();
	let refused = start_cluster(&refused_trace, unbounded_federated_conf(&certs, "0.0.0.0:0")).await;
	let started_trace = TraceCollector::new();
	let started = start_cluster(&started_trace, unbounded_federated_conf(&certs, "127.0.0.1:0")).await?;
	started.stop();

	let refused_posture = refused_trace.recorded(events::CLUSTER_EXPORT_UNBOUNDED);
	let started_posture = started_trace.recorded(events::CLUSTER_EXPORT_UNBOUNDED);
	assert!(refused.is_err(), "a federated gateway refuses its wildcard bind");
	assert_eq!(refused_posture, 0, "a gateway that refuses to start reports no posture");
	assert_eq!(started_posture, 1, "a gateway that starts reports its posture once");
	Ok(())
}

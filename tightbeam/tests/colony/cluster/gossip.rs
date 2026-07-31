//! Gossip flood (rumor plane).

use super::common::*;

// ============================================================================
// Gossip Flood (rumor plane)
// ============================================================================

/// Peering conf that refloods to `peers`.
/// Returns the journal handle so scenarios can poll flood convergence
/// through the public journal trait.
fn gossip_cluster_conf(certs: &ClusterTestCerts, peers: Vec<String>) -> (ClusterConfig, Arc<MemoryGossipJournal>) {
	let journal = Arc::new(MemoryGossipJournal::default());
	let mut conf = peering_cluster_conf_with_peers(certs, peers);
	conf.gossip = GossipConfig {
		journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
		ingress: Some(servlet_urn("ping")),
		..Default::default()
	};

	(conf, journal)
}

/// Payload-only rumor body.
/// The rumor names no destination.
/// Flood scope is the origin certificate's colony URN.
/// Local delivery is the receiving gateway's ingress policy.
/// Hop radius rides the outer frame's `metadata.lifetime`, never the body.
fn rumor_body(payload: Vec<u8>) -> GossipRumor {
	GossipRumor { payload }
}

/// Sign a [`PublishGossip`] control frame with issue-time order and hop radius.
async fn signed_publish_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	body: GossipRumor,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::PublishGossip(body))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Mint an origin-signed rumor [`Frame`] (the nested gossip content).
async fn mint_origin_rumor(key: &Secp256k1SigningKey, id: &[u8], body: GossipRumor) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(body)
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Sign a [`Gossip`] relay frame carrying a verbatim origin rumor.
async fn signed_relay_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	rumor: Frame,
	hop_ttl: u64,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_lifetime(hop_ttl)
		.with_message(ClusterRequest::Gossip(Box::new(rumor)))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Emit one signed gossip frame and record the decoded status on the
/// trace as `GOSSIP_PUBLISH_STATUS`.
async fn send_gossip_frame(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
) -> Result<(), TightBeamError> {
	send_gossip_frame_as(trace, connect_certs, cluster, frame, GOSSIP_PUBLISH_STATUS).await
}

/// Emit one signed gossip frame and record the decoded status under the
/// given marker.
/// One scenario can thereby distinguish per-publish outcomes.
async fn send_gossip_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipResponse = decode(&emit_frame(&mut client, frame).await?.message)?;
	trace.event_with(marker, &[], response.status)?;
	Ok(())
}

/// Sign a [`ReconcileGossip`] control frame listing the sender's held digests.
async fn signed_reconcile_gossip(
	key: &Secp256k1SigningKey,
	id: &[u8],
	held: Vec<Vec<u8>>,
) -> Result<Frame, TightBeamError> {
	let unsigned = frame_compose(Version::V2)
		.with_id(id)
		.with_order(current_timestamp_ms())
		.with_message(ClusterRequest::ReconcileGossip(GossipReconciliation { held }))
		.build()?;

	let provider = Secp256k1KeyProvider::from(key.to_owned());
	unsigned.sign_with_provider::<Sha3_256, _>(&provider).await
}

/// Emit one signed reconcile frame and record the want-list size under
/// the given marker.
/// A refused reconciliation answers an empty want.
async fn send_reconcile_frame_as(
	trace: &TraceCollector,
	connect_certs: &ClusterTestCerts,
	cluster: &ClusterGateway,
	frame: Frame,
	marker: Urn<'static>,
) -> Result<(), TightBeamError> {
	let mut client = connect_cluster(connect_certs, cluster.addr()).await?;
	let response: GossipWant = decode(&emit_frame(&mut client, frame).await?.message)?;
	trace.event_with(marker, &[], response.want.len() as u64)?;
	Ok(())
}

/// One convergence probe over the public journal interface.
/// Every journal holds exactly `held` rumors and none awaits local delivery.
fn gossip_converged(journals: &[Arc<MemoryGossipJournal>], held: usize) -> bool {
	let now = current_timestamp_ms();
	journals.iter().all(|journal| {
		let held_now = journal.held_digests(now).is_ok_and(|digests| digests.len() == held);
		let none_pending = journal.pending_local(now).is_ok_and(|rumors| rumors.is_empty());
		held_now && none_pending
	})
}

/// Poll until every journal converged or attempts exhaust.
/// Refloods run detached from the publish reply.
/// Convergence is therefore only observable by polling.
/// Branching lives here, not in scenarios.
async fn wait_for_gossip_converged(
	journals: &[Arc<MemoryGossipJournal>],
	held: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	for _ in 0..attempts {
		if gossip_converged(journals, held) {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	gossip_converged(journals, held)
}

/// Poll until the journal holds exactly `count` rumors awaiting local
/// delivery. Attempts exhaust if the count never matches.
/// A rumor accepted before the ingress servlet registers stays pending for
/// beat retry. Branching lives here, not in scenarios.
async fn wait_for_pending_local(
	journal: &Arc<MemoryGossipJournal>,
	count: usize,
	attempts: u32,
	interval: Duration,
) -> bool {
	for _ in 0..attempts {
		let pending = journal
			.pending_local(current_timestamp_ms())
			.is_ok_and(|rumors| rumors.len() == count);
		if pending {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	journal
		.pending_local(current_timestamp_ms())
		.is_ok_and(|rumors| rumors.len() == count)
}

tb_assert_spec! {
	pub ClusterGossipFloodSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Fan-out flood.
// A refloods to B and C.
// Every cluster delivers the rumor to its local ping servlet exactly once
// (ACCEPTED = 3). A second publish of the byte-identical rumor is absorbed
// as exactly one DUPLICATE. It is still answered Ok and delivered nowhere
// a second time. The duplicate fires before its reply.
// The count therefore needs no polling.
tb_scenario! {
	name: cluster_gossip_floods_every_cluster_once,
	spec: ClusterGossipFloodSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			// One signed publish frame is resent byte-identical.
			// The origin gateway re-mints the same rumor (same id, order, body).
			// The journal absorbs the second as a Duplicate.
			let frame = signed_publish_gossip(
				&certs.key,
				b"flood-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				4,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame.clone()).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipChainSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(3), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(3)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Partial topology A -> B -> C.
// A is not peered to C.
// The rumor therefore reaches C only through B's reflood.
// The publish starts at ttl 2 and arrives at C with ttl 0.
// The hop budget is exactly consumed.
// The chain still delivers once per cluster with no duplicate.
tb_scenario! {
	name: cluster_gossip_relays_across_partial_topology,
	spec: ClusterGossipChainSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;

			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![gateway_c.addr().to_string()]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"chain-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b, journal_c];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_b.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipHiveTrustOnlySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Hive-trust-only propagation.
// A configures a peer but no peer_trust.
// It therefore builds no peer pool.
// The reflood falls back to the hive pool, the same preference the
// advertise beat applies. The rumor still reaches B.
// B verifies A's relay on its own peer plane.
// The publish starts at ttl 1.
// Each cluster delivers exactly once and B refloods nowhere.
tb_scenario! {
	name: cluster_gossip_refloods_under_hive_trust_only,
	spec: ClusterGossipHiveTrustOnlySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);

			conf_a.tls.peer_trust = None;

			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"hive-only-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let journals = [journal_a, journal_b];
			let converged = wait_for_gossip_converged(&journals, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTtlClampSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(GOSSIP_CLAMP_LEAKED, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// The operator's configured gossip ttl caps the hop radius an origin
// publish may request. With ttl 0 configured, a publish requesting the
// protocol maximum is clamped. It is delivered locally and never refloods
// to the configured peer. A leaked reflood would raise ACCEPTED past one.
tb_scenario! {
	name: cluster_gossip_origin_clamps_configured_ttl,
	spec: ClusterGossipTtlClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_b, journal_b) = gossip_cluster_conf(&certs, vec![]);
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, vec![gateway_b.addr().to_string()]);
			conf_a.gossip.ttl = 0;
			let gateway_a = start_cluster(&trace, conf_a).await?;

			let hive_b = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;
			hive_b.register_with_cluster(gateway_b.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"clamped-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				u64::from(MAX_GOSSIP_TTL),
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_a], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			// A leaked reflood would land within this window.
			// Correct clamping leaves B's journal empty for the whole wait.
			let leaked = wait_for_gossip_converged(&[journal_b], 1, 3, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CLAMP_LEAKED, &[], u64::from(leaked))?;

			gateway_a.stop();
			gateway_b.stop();
			hive_b.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Fixture for the plane-separation scenario.
/// The gateway's own certs anchor the hive plane.
/// A distinct random identity anchors the peer plane.
/// [`GatewayCerts::generate`] cannot serve here.
/// Every generated cert shares the fixed test signing key.
/// Two "identities" would therefore verify interchangeably.
struct GossipPlaneCtx {
	gateway: ClusterTestCerts,
	peer_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn gossip_plane_ctx() -> GossipPlaneCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let peer_cert = create_test_certificate(&raw);
	let peer_key = Secp256k1SigningKey::from(raw);
	let peer_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(peer_cert)
			.expect("peer trust")
			.build(),
	);

	GossipPlaneCtx { gateway: cluster_certs(), peer_key, peer_trust }
}

tb_assert_spec! {
	pub ClusterGossipPlaneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Trust-plane separation and admission bounds.
// A hive-plane signer must not relay peer gossip.
// A peer-plane signer must not publish origin gossip.
// An oversized rumor is refused at admission even on the correct plane.
// Nothing is delivered or recorded for reflood.
tb_scenario! {
	name: cluster_gossip_refuses_wrong_plane_and_oversized,
	spec: ClusterGossipPlaneSpec,
	environment Cluster {
		context: gossip_plane_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			// The oversized rumor exceeds a single-flight envelope.
			// The gateway therefore offers mux.
			// The frame must chunk across the link to reach gossip admission
			// at all.
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pool_config.mux_offer = Some(Arc::new(TransportOffer::mux(8)));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			// Outer frame signed on the hive plane.
			// Peer trust refuses it before the nested rumor is examined.
			let dummy = mint_origin_rumor(
				&ctx.gateway.key,
				b"cross-plane-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.gateway.key, b"cross-plane-relay", dummy, 2).await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			let frame = signed_publish_gossip(
				&ctx.peer_key,
				b"cross-plane-publish",
				rumor_body(encode(&PingRequest { value: 21 })?),
				2,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.gateway, &cluster, frame).await?;

			// A rumor past the gossip bound exceeds what one single-flight
			// envelope carries. It rides a pooled mux link (the same chunked
			// path reflood uses) to reach admission.
			// The payload bound then refuses it on the correct plane.
			let pool_config = PoolConfig {
				mux_offer: Some(Arc::new(TransportOffer::mux(8))),
				..Default::default()
			};
			let pool = Arc::new(
				ConnectionPool::<TokioListener>::builder()
					.with_config(pool_config)
					.with_trust_store(Arc::clone(&ctx.gateway.trust))
					.with_trace(trace.share())
					.build(),
			);
			let mut mux_client = pool.connect(cluster.addr()).await?;

			let frame = signed_publish_gossip(
				&ctx.gateway.key,
				b"oversized-rumor",
				rumor_body(vec![0u8; MAX_GOSSIP_PAYLOAD_BYTES + 1]),
				2,
			)
			.await?;
			let reply = mux_client.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: GossipResponse = decode(&reply.message)?;
			trace.event_with(GOSSIP_PUBLISH_STATUS, &[], response.status)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileRepairSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Anti-entropy repair over the beat.
// Publisher F starts the rumor at ttl 0 so it never floods.
// Receiver R learns the rumor only when F's beat reconciles digests and
// pushes it.
tb_scenario! {
	name: cluster_gossip_repairs_missing_peer_over_beat,
	spec: ClusterGossipReconcileRepairSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			let gateway_r = start_cluster(&trace, conf_r).await?;
			let hive_r = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;

			let (mut conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			conf_f.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive_r.register_with_cluster(gateway_r.addr()).await?;
			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"repair-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipRetrySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PENDING_BEFORE_REGISTER, exactly!(1), equals!(1u64)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Local-delivery retry on the beat.
// The rumor reaches R before R's ping servlet registers.
// It therefore stays pending.
// After registration, R's beat delivers from the pending set and acks.
// R has no peers.
// The beat runs solely for pending_local retry.
tb_scenario! {
	name: cluster_gossip_retries_pending_local_delivery,
	spec: ClusterGossipRetrySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_r, journal_r) = gossip_cluster_conf(&certs, vec![]);
			conf_r.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_r = start_cluster(&trace, conf_r).await?;

			let (conf_f, journal_f) = gossip_cluster_conf(&certs, vec![gateway_r.addr().to_string()]);
			let gateway_f = start_cluster(&trace, conf_f).await?;

			hive.register_with_cluster(gateway_f.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"retry-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				1,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_f, frame).await?;

			let pending = wait_for_pending_local(&journal_r, 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_PENDING_BEFORE_REGISTER, &[], u64::from(pending))?;

			let hive_r = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive_r.register_with_cluster(gateway_r.addr()).await?;

			let converged = wait_for_gossip_converged(&[journal_f, journal_r], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_f.stop();
			gateway_r.stop();
			hive_r.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Counting [`GossipJournal`] wrapping the in-memory default.
/// Counters show the gateway records and acks through the injected trait
/// object. A durable backend swaps in the same way.
#[derive(Default)]
struct CountingJournal {
	inner: MemoryGossipJournal,
	records: AtomicU64,
	acks: AtomicU64,
}

impl GossipJournal for CountingJournal {
	fn record(
		&self,
		signer: &[u8],
		digest: GossipDigest,
		rumor: &Frame,
		now_ms: u64,
	) -> Result<Admission, ClusterError> {
		self.records.fetch_add(1, Ordering::SeqCst);
		self.inner.record(signer, digest, rumor, now_ms)
	}

	fn seen(&self, digest: &GossipDigest, now_ms: u64) -> Result<bool, ClusterError> {
		self.inner.seen(digest, now_ms)
	}

	fn held_digests(&self, now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		self.inner.held_digests(now_ms)
	}

	fn fetch(&self, wanted: &[GossipDigest], now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		self.inner.fetch(wanted, now_ms)
	}

	fn pending_local(&self, now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		self.inner.pending_local(now_ms)
	}

	fn ack_local(&self, digest: &GossipDigest) -> Result<(), ClusterError> {
		self.acks.fetch_add(1, Ordering::SeqCst);
		self.inner.ack_local(digest)
	}

	fn retention_ms(&self) -> u64 {
		self.inner.retention_ms()
	}
}

tb_assert_spec! {
	pub ClusterGossipJournalSeamSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(JOURNAL_RECORDS, exactly!(1), equals!(1u64)),
			(JOURNAL_ACKS, exactly!(1), equals!(1u64))
		]
	}
}

tb_assert_spec! {
	pub ClusterGossipRateLimitSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Per-signer rate admission at the pipeline chokepoint.
// A one-token bucket with a slow refill admits the first publish.
// It refuses the second with ResourceExhausted before it is recorded.
tb_scenario! {
	name: cluster_gossip_rate_limits_signer,
	spec: ClusterGossipRateLimitSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"rate-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"rate-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_LIMITED_STATUS).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipRetentionClampSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_REPLAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// The gateway clamps the freshness window (seen_ttl) to the journal's
// retention horizon at start. The conf here asks for an hour-wide window
// over a one-second journal. After the entry is pruned, a byte-identical
// replay is refused as stale instead of re-admitted as New. Without the
// clamp the replay is still "fresh". It records again and delivers the
// same rumor to local servlets twice (CWE-294).
tb_scenario! {
	name: cluster_gossip_clamps_seen_ttl_to_retention,
	spec: ClusterGossipRetentionClampSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConfig {
				journal: Arc::new(MemoryGossipJournal::new(1_000)) as Arc<dyn GossipJournal>,
				seen_ttl: Duration::from_secs(3_600),
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"clamp-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame.clone()).await?;

			tokio::time::sleep(Duration::from_millis(3_000)).await;
			send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_REPLAY_STATUS).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipDuplicateFreeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(4), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(2)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(0))
		]
	}
}

// Duplicates do not spend rate tokens.
// A two-token bucket with a slow refill admits rumor A.
// It absorbs two byte-identical echoes of A for free.
// It still has the token to admit rumor B.
// If duplicates were charged, the echoes would drain the bucket.
// B would then be refused with ResourceExhausted.
// Relay echo traffic is normal, not abuse.
tb_scenario! {
	name: cluster_gossip_duplicates_spend_no_tokens,
	spec: ClusterGossipDuplicateFreeSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(2, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let first = signed_publish_gossip(
				&certs.key,
				b"dup-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first.clone()).await?;
			send_gossip_frame(&trace, &certs, &gateway, first).await?;

			let second = signed_publish_gossip(
				&certs.key,
				b"dup-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, second).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway drives an injected journal through the trait alone.
// One origin publish records once and acks once on local delivery.
// Counts are final when the publish returns.
// Record and ack precede the reply.
tb_scenario! {
	name: cluster_gossip_uses_injected_journal,
	spec: ClusterGossipJournalSeamSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let journal = Arc::new(CountingJournal::default());
			let mut conf = peering_cluster_conf(&certs);
			conf.gossip = GossipConfig {
				journal: Arc::clone(&journal) as Arc<dyn GossipJournal>,
				ingress: Some(servlet_urn("ping")),
				..Default::default()
			};
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"seam-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			trace.event_with(JOURNAL_RECORDS, &[], journal.records.load(Ordering::SeqCst))?;
			trace.event_with(JOURNAL_ACKS, &[], journal.acks.load(Ordering::SeqCst))?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipInvalidRelaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(4), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(4)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(3)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(0u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(1))
		]
	}
}

// Invalid-relay scoring.
// A trusted peer that relays rumors refused at admission (here an
// over-TTL flood request) weakens its own advertised work routes.
// Weakening is one trial per refusal until the trail is abandoned.
// `peer_routes` then no longer exposes it.
// The weakening stops with the trail (the fourth refusal scores nothing).
// An honest relay from the same signer still delivers.
// Flooding is untouched by work-route abandonment.
tb_scenario! {
	name: cluster_gossip_abandons_invalid_relay_routes,
	spec: ClusterGossipInvalidRelaySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = containment_cluster_conf(&certs);
			conf.gossip.ingress = Some(servlet_urn("ping"));
			let gateway = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(gateway.addr()).await?;
			install_ping_peer(&trace, &certs, &gateway).await?;

			// One more relay than the abandonment budget.
			// The last refusal must find the trail already abandoned and
			// weaken nothing. Each relay carries a valid origin-signed rumor.
			// The refusal is therefore the over-radius hop lifetime, not an
			// unverifiable origin.
			for i in 0..=CONTAINMENT_ABANDON_LIMIT {
				let rumor_id = [b'r', i as u8];
				let rumor = mint_origin_rumor(
					&certs.key,
					&rumor_id,
					rumor_body(encode(&PingRequest { value: i })?),
				)
				.await?;
				let id = [b'b', b'a', b'd', i as u8];
				let frame = signed_relay_gossip(
					&certs.key,
					&id,
					rumor,
					u64::from(MAX_GOSSIP_TTL) + 1,
				)
				.await?;
				send_gossip_frame_as(&trace, &certs, &gateway, frame, GOSSIP_RELAY_STATUS).await?;
			}

			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], gateway.peer_routes().len() as u64)?;

			let honest = mint_origin_rumor(
				&certs.key,
				b"honest-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&certs.key, b"honest-relay", honest, 0).await?;
			send_gossip_frame(&trace, &certs, &gateway, frame).await?;

			gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Grey-hole [`GossipJournal`].
/// Every rumor is recorded as new and retained nowhere.
/// The gateway therefore acknowledges each push with `Ok`.
/// It then re-wants the same digest on every reconciliation round.
#[derive(Default)]
struct AmnesiacJournal;

impl GossipJournal for AmnesiacJournal {
	fn record(
		&self,
		_signer: &[u8],
		_digest: GossipDigest,
		_rumor: &Frame,
		_now_ms: u64,
	) -> Result<Admission, ClusterError> {
		Ok(Admission::New)
	}

	// Retaining nothing, the grey hole never reports a digest as seen.
	// Every repair push therefore reaches record and is re-acknowledged.
	fn seen(&self, _digest: &GossipDigest, _now_ms: u64) -> Result<bool, ClusterError> {
		Ok(false)
	}

	fn held_digests(&self, _now_ms: u64) -> Result<Vec<GossipDigest>, ClusterError> {
		Ok(Vec::new())
	}

	fn fetch(&self, _wanted: &[GossipDigest], _now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		Ok(Vec::new())
	}

	fn pending_local(&self, _now_ms: u64) -> Result<Vec<Frame>, ClusterError> {
		Ok(Vec::new())
	}

	fn ack_local(&self, _digest: &GossipDigest) -> Result<(), ClusterError> {
		Ok(())
	}

	// The grey hole CLAIMS the default retention while retaining nothing.
	// A misbehaving journal lies.
	// The start-time seen-ttl clamp only defends against honest
	// misconfiguration.
	fn retention_ms(&self) -> u64 {
		DEFAULT_GOSSIP_RETENTION_MS
	}
}

tb_assert_spec! {
	pub ClusterGossipGreyHoleSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_DROP_SIGNAL, at_least!(3)),
			(GOSSIP_GREY_HOLE_CONTAINED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(2))
		]
	}
}

// Grey-hole containment over the beat.
// B acknowledges every repair push with `Ok` and retains nothing.
// Each reconciliation round therefore re-wants a digest A already saw
// acknowledged. A's beat reads the reappearance as a drop signal.
// It weakens B's advertised work route once per round and abandons the
// route past the limit. The rumor still converges to honest C through
// the same beat. Flooding to B keeps running off the static peer list.
// Only work routing drops the grey hole.
tb_scenario! {
	name: cluster_gossip_abandons_grey_hole_peer,
	spec: ClusterGossipGreyHoleSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (conf_c, journal_c) = gossip_cluster_conf(&certs, vec![]);
			let gateway_c = start_cluster(&trace, conf_c).await?;
			let hive_c = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive_c.register_with_cluster(gateway_c.addr()).await?;

			let mut conf_b = peering_cluster_conf(&certs);
			conf_b.gossip = GossipConfig {
				journal: Arc::new(AmnesiacJournal) as Arc<dyn GossipJournal>,
				..Default::default()
			};
			let gateway_b = start_cluster(&trace, conf_b).await?;

			let peers_a = vec![gateway_b.addr().to_string(), gateway_c.addr().to_string()];
			let (mut conf_a, journal_a) = gossip_cluster_conf(&certs, peers_a);
			conf_a.peer.advertise_interval = Some(Duration::from_millis(100));
			conf_a.pheromone.abandonment_limit = CONTAINMENT_ABANDON_LIMIT;
			let gateway_a = start_cluster(&trace, conf_a).await?;
			hive.register_with_cluster(gateway_a.addr()).await?;

			// Give the drop signals a trail to weaken.
			// B advertises a ping route dialed at the same address A
			// reconciles with.
			let dial = gateway_b.addr().to_string();
			advertise_peer(&trace, &certs, &gateway_a, dial.as_bytes(), vec![servlet_urn("ping")]).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"grey-hole-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_a, frame).await?;

			// Honest convergence first.
			// A holds its own publish and C is repaired over the beat.
			// B never converges by design.
			let converged =
				wait_for_gossip_converged(&[journal_a, journal_c], 1, 50, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			let contained = wait_for_no_peer_routes(&gateway_a, 100, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_GREY_HOLE_CONTAINED, &[], u64::from(contained))?;

			gateway_a.stop();
			gateway_b.stop();
			gateway_c.stop();
			hive_c.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipTamperedRelaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Tampered-relay scoring.
// A trusted peer forwards an origin-signed rumor whose content it altered.
// That breaks the origin signature.
// The gateway refuses PermissionDenied and weakens the relay's advertised
// routes. An honest relay verifies before forwarding.
tb_scenario! {
	name: cluster_gossip_weakens_tampered_relay,
	spec: ClusterGossipTamperedRelaySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut rumor = mint_origin_rumor(
				&certs.key,
				b"tamper-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			rumor.message = encode(&rumor_body(encode(&PingRequest { value: 99 })?))?;

			let frame = signed_relay_gossip(&certs.key, b"tamper-relay", rumor, 0).await?;
			send_gossip_frame_as(&trace, &certs, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for colony-membership refusals.
/// The gateway belongs to colony "main".
/// One trusted peer identity carries a different colony URN SAN.
/// Another carries no SAN at all.
/// Both use random keys so the three identities never share a subject
/// key id (see [`gossip_plane_ctx`]).
struct ForeignColonyCtx {
	gateway: ClusterTestCerts,
	foreign_key: Secp256k1SigningKey,
	stranger_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

/// Fresh gateway identity in colony "other".
/// A random key keeps its subject key id distinct from every
/// "main"-colony identity. Its own `CN` keeps trust-store issuer
/// resolution unambiguous.
/// One trust store can therefore anchor both identities.
fn foreign_colony_certs() -> ClusterTestCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate_with_cn_and_uri_sans;

	let foreign_urn = colony_ns().colony("other").expect("static colony name");
	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert = create_test_certificate_with_cn_and_uri_sans(&raw, "Foreign Gateway", &[&foreign_urn.to_string()]);
	let trust = combined_trust(&[&cert]);

	GatewayCerts { cert, key: Secp256k1SigningKey::from(raw), trust }
}

fn foreign_colony_ctx() -> ForeignColonyCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let gateway = cluster_certs();
	let foreign = foreign_colony_certs();
	let raw_stranger = k256::ecdsa::SigningKey::random(&mut OsRng);
	let stranger_cert = create_test_certificate(&raw_stranger);
	let peer_trust = combined_trust(&[&gateway.cert, &foreign.cert, &stranger_cert]);

	ForeignColonyCtx {
		gateway,
		foreign_key: foreign.key,
		stranger_key: Secp256k1SigningKey::from(raw_stranger),
		peer_trust,
	}
}

tb_assert_spec! {
	pub ClusterGossipForeignColonySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(GOSSIP_RELAY_STATUS, exactly!(3), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(3)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(GOSSIP_ROUTES_AFTER_SCORING, exactly!(1), equals!(1u64)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// Colony equality on the relay peer is policy, not misbehavior.
// A trusted peer from a different colony federates work routes (the
// advertisement installs). Every gossip relay it drives is refused
// PermissionDenied. Covered cases: a same-colony origin rumor forwarded
// by that peer, a foreign-origin rumor, and a relay from a trusted peer
// with no colony SAN. None of those refusals weaken the advertised route.
// The abandonment limit is 1.
// A single weaken would therefore evict it.
// The route survives.
tb_scenario! {
	name: cluster_gossip_refuses_foreign_colony_without_weakening,
	spec: ClusterGossipForeignColonySpec,
	environment Cluster {
		context: foreign_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.pheromone.abandonment_limit = 1;
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			advertise_peer_signed(
				&trace,
				&ctx.gateway,
				&ctx.foreign_key,
				&cluster,
				PEER_GATEWAY_ADDR,
				vec![servlet_urn("ping")],
			)
			.await?;

			// Same-colony origin, foreign-colony relay.
			// The peer check alone must refuse.
			// Without colony equality on the outer frame, this path would
			// admit, journal, deliver, and reflood.
			let same_colony = mint_origin_rumor(
				&ctx.gateway.key,
				b"same-colony-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame =
				signed_relay_gossip(&ctx.foreign_key, b"foreign-relay-same", same_colony, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let foreign = mint_origin_rumor(
				&ctx.foreign_key,
				b"foreign-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.foreign_key, b"foreign-relay", foreign, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let stranger = mint_origin_rumor(
				&ctx.stranger_key,
				b"stranger-inner",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.stranger_key, b"stranger-relay", stranger, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			trace.event_with(GOSSIP_ROUTES_AFTER_SCORING, &[], cluster.peer_routes().len() as u64)?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for origin-budget keying.
/// One origin identity and two relay identities, all members of the
/// gateway's colony. Every identity uses a random key so no two share a
/// subject key id (see [`gossip_plane_ctx`]).
struct RelayFanoutCtx {
	gateway: ClusterTestCerts,
	origin_key: Secp256k1SigningKey,
	relay_a_key: Secp256k1SigningKey,
	relay_b_key: Secp256k1SigningKey,
	peer_trust: Arc<dyn CertificateTrust>,
}

fn relay_fanout_ctx() -> RelayFanoutCtx {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let gateway = cluster_certs();
	let member_urn = test_colony_urn().to_string();
	let raw_origin = k256::ecdsa::SigningKey::random(&mut OsRng);
	let origin_cert = create_test_certificate_with_uri_sans(&raw_origin, &[&member_urn]);
	let raw_relay_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_a_cert = create_test_certificate_with_uri_sans(&raw_relay_a, &[&member_urn]);
	let raw_relay_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let relay_b_cert = create_test_certificate_with_uri_sans(&raw_relay_b, &[&member_urn]);
	let peer_trust = combined_trust(&[&gateway.cert, &origin_cert, &relay_a_cert, &relay_b_cert]);

	RelayFanoutCtx {
		gateway,
		origin_key: Secp256k1SigningKey::from(raw_origin),
		relay_a_key: Secp256k1SigningKey::from(raw_relay_a),
		relay_b_key: Secp256k1SigningKey::from(raw_relay_b),
		peer_trust,
	}
}

tb_assert_spec! {
	pub ClusterGossipOriginBudgetSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_RELAY_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(GOSSIP_LIMITED_STATUS, exactly!(1), equals!(TransitStatus::ResourceExhausted)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_RELAY_WEAKENED, exactly!(0)),
			(events::CLUSTER_GOSSIP_DUPLICATE, exactly!(0))
		]
	}
}

// Rate admission keys on the rumor's origin, not the relaying peer.
// A one-token bucket admits the origin's first rumor via relay A.
// It then refuses the same origin's second rumor via relay B with
// ResourceExhausted. Fanning one origin's flood through many relays
// grants no extra budget. The refusal is local policy.
// Relay B's routes are therefore never weakened.
tb_scenario! {
	name: cluster_gossip_relays_share_origin_budget,
	spec: ClusterGossipOriginBudgetSpec,
	environment Cluster {
		context: relay_fanout_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			conf.gossip = GossipConfig {
				admission: Arc::new(TokenBucketAdmission::new(1, Duration::from_secs(3_600)))
					as Arc<dyn GossipAdmission>,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let first = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-1",
				rumor_body(encode(&PingRequest { value: 21 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_a_key, b"budget-relay-1", first, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RELAY_STATUS).await?;

			let second = mint_origin_rumor(
				&ctx.origin_key,
				b"budget-rumor-2",
				rumor_body(encode(&PingRequest { value: 22 })?),
			)
			.await?;
			let frame = signed_relay_gossip(&ctx.relay_b_key, b"budget-relay-2", second, 0).await?;
			send_gossip_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_LIMITED_STATUS).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipNonMemberSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(1)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0))
		]
	}
}

// A gateway whose own certificate carries no colony URN SAN is not a
// colony member. It refuses origin publishes PermissionDenied even from
// a trusted hive-plane signer.
// It cannot scope the flood.
tb_scenario! {
	name: cluster_gossip_non_member_gateway_refuses_publish,
	spec: ClusterGossipNonMemberSpec,
	environment Cluster {
		context: GatewayCerts::generate("CN=Non-Member Gateway"),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let frame = signed_publish_gossip(
				&certs.key,
				b"non-member-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &cluster, frame).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterGossipReconcileSameColonySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_RECONCILE_MEMBER_WANT, exactly!(1), equals!(1u64)),
			(GOSSIP_RECONCILE_FOREIGN_WANT, exactly!(1), equals!(0u64)),
			(GOSSIP_RECONCILE_STRANGER_WANT, exactly!(1), equals!(0u64)),
			(events::CLUSTER_GOSSIP_REFUSED, exactly!(2))
		]
	}
}

// Reconciliation is gated on colony EQUALITY, matching the flood scope.
// A want list names local rumor state.
// The follow-up repair push carries rumor bytes.
// Only a same-colony member therefore receives the want-list for a digest
// this gateway lacks. A foreign-colony member and a trusted peer with no
// colony SAN are both refused with an empty want.
// Each fires one REFUSED event.
tb_scenario! {
	name: cluster_gossip_reconcile_requires_same_colony,
	spec: ClusterGossipReconcileSameColonySpec,
	environment Cluster {
		context: foreign_colony_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let conf = peering_cluster_conf_with_trust(&ctx.gateway, Arc::clone(&ctx.peer_trust));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let held = vec![vec![0xABu8; 32]];

			let frame = signed_reconcile_gossip(&ctx.gateway.key, b"member-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_MEMBER_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.foreign_key, b"foreign-reconcile", held.clone()).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_FOREIGN_WANT).await?;

			let frame = signed_reconcile_gossip(&ctx.stranger_key, b"stranger-reconcile", held).await?;
			send_reconcile_frame_as(&trace, &ctx.gateway, &cluster, frame, GOSSIP_RECONCILE_STRANGER_WANT).await?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Fixture for the ingress-None delivery policy.
/// The scenario needs the journal handle to observe retention and the
/// retry set from outside.
struct IngressNoneCtx {
	certs: ClusterTestCerts,
	journal: Arc<MemoryGossipJournal>,
}

fn ingress_none_ctx() -> IngressNoneCtx {
	IngressNoneCtx { certs: cluster_certs(), journal: Arc::new(MemoryGossipJournal::default()) }
}

tb_assert_spec! {
	pub ClusterGossipIngressNoneSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_GOSSIP_ACCEPTED, exactly!(0)),
			(GOSSIP_HELD_NO_INGRESS, exactly!(1), equals!(1u64)),
			(GOSSIP_PENDING_NO_INGRESS, exactly!(1), equals!(1u64))
		]
	}
}

// With no configured ingress the gateway journals and refloods only.
// The publish is answered Ok and retained (held = 1).
// The record is acked immediately, so it never enters the pending retry
// set. No local delivery is reported (ACCEPTED = 0).
// The journal settles before the publish reply returns.
// The probes therefore need no polling.
tb_scenario! {
	name: cluster_gossip_ingress_none_acks_on_record,
	spec: ClusterGossipIngressNoneSpec,
	environment Cluster {
		context: ingress_none_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let mut conf = peering_cluster_conf(&ctx.certs);
			conf.gossip = GossipConfig {
				journal: Arc::clone(&ctx.journal) as Arc<dyn GossipJournal>,
				ingress: None,
				..Default::default()
			};
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let frame = signed_publish_gossip(
				&ctx.certs.key,
				b"ingress-none-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &ctx.certs, &cluster, frame).await?;

			let now = current_timestamp_ms();
			let held_one = ctx.journal.held_digests(now).is_ok_and(|digests| digests.len() == 1);
			let none_pending = ctx.journal.pending_local(now).is_ok_and(|rumors| rumors.is_empty());
			trace.event_with(GOSSIP_HELD_NO_INGRESS, &[], u64::from(held_one))?;
			trace.event_with(GOSSIP_PENDING_NO_INGRESS, &[], u64::from(none_pending))?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerDiscoverySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(2), equals!(1u64)),
			(GOSSIP_PUBLISH_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(events::CLUSTER_PEER_DISCOVERED, at_least!(2)),
			(GOSSIP_CONVERGED, exactly!(1), equals!(1u64))
		]
	}
}

// Seed-bootstrap discovery over the beat (peer exchange).
// X anchors only seed S. S anchors publisher P. P anchors nobody.
// S's beat verifies its anchor P.
// S's reconcile reply therefore shares P over PEX.
// X learns P, feeler-probes it through the colony gate, and promotes it
// (CLUSTER_PEER_DISCOVERED). X's advertisement then teaches P to dial
// back. P promotes X the same way.
// A rumor published at P at ttl 0 never floods.
// It reaches X's ingress only across those two discovered edges.
tb_scenario! {
	name: cluster_peer_discovery_bootstraps_from_seed,
	spec: ClusterPeerDiscoverySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let (mut conf_p, journal_p) = gossip_cluster_conf(&certs, vec![]);
			conf_p.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_p = start_cluster(&trace, conf_p).await?;

			let (mut conf_s, _journal_s) = gossip_cluster_conf(&certs, vec![gateway_p.addr().to_string()]);
			conf_s.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_s = start_cluster(&trace, conf_s).await?;

			let (mut conf_x, journal_x) = gossip_cluster_conf(&certs, vec![gateway_s.addr().to_string()]);
			conf_x.peer.advertise_interval = Some(Duration::from_millis(100));
			let gateway_x = start_cluster(&trace, conf_x).await?;

			let hive_x = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			hive_x.register_with_cluster(gateway_x.addr()).await?;
			hive.register_with_cluster(gateway_p.addr()).await?;

			let frame = signed_publish_gossip(
				&certs.key,
				b"discovery-rumor",
				rumor_body(encode(&PingRequest { value: 21 })?),
				0,
			)
			.await?;
			send_gossip_frame(&trace, &certs, &gateway_p, frame).await?;

			let converged =
				wait_for_gossip_converged(&[journal_p, journal_x], 1, 100, Duration::from_millis(100)).await;
			trace.event_with(GOSSIP_CONVERGED, &[], u64::from(converged))?;

			gateway_p.stop();
			gateway_s.stop();
			gateway_x.stop();
			hive_x.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerEclipseBoundSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_TABLE_FLOOD_ADMITTED, exactly!(1), equals!(MAX_PEER_BUCKET as u64)),
			(PEER_TABLE_ANCHOR_RETAINED, exactly!(1), equals!(true)),
			(PEER_TABLE_TARGETS_BOUNDED, exactly!(1), equals!(true))
		]
	}
}

// Eclipse bound on the discovery table (CWE-770).
// An attacker inside one /16 prefix floods hints past the bucket cap
// and even passes every probe. Admission stops at the per-prefix cap.
// The configured anchor keeps its leading dial slot.
// The target set stays bounded.
// The beat can therefore never be steered wholly onto attacker addresses
// (Heilman et al., USENIX Security 2015).
tb_scenario! {
	name: cluster_peer_table_bounds_eclipse_flood,
	spec: ClusterPeerEclipseBoundSpec,
	environment Bare {
		context: cluster_certs(),
		exec: |SetupEnv { trace, context: certs }| {
			let anchor = "127.0.0.1:9000".to_string();
			let conf = peering_cluster_conf_with_peers(&certs, vec![anchor.clone()]);
			let table = Arc::clone(&conf.peer.table);

			let flood: Vec<PeerHint> = (0..MAX_PEER_BUCKET + 8)
				.map(|host| PeerHint { gateway_addr: format!("10.66.0.{}:9000", host + 1), peer_id: None })
				.collect();
			let admitted = table.learn(flood.clone()).unwrap_or_default();
			trace.event_with(PEER_TABLE_FLOOD_ADMITTED, &[], admitted as u64)?;

			for hint in &flood {
				let _ = table.promote(&hint.gateway_addr, None, current_timestamp_ms());
			}

			let targets = table.target_set().unwrap_or_default();
			trace.event_with(PEER_TABLE_ANCHOR_RETAINED, &[], targets.first() == Some(&anchor))?;
			trace.event_with(PEER_TABLE_TARGETS_BOUNDED, &[], targets.len() <= MAX_PEER_BUCKET + 1)?;
			Ok(())
		}
	}
}

/// Fixture for the feeler-probe colony gate.
/// A gateway from colony "other" is TLS-trusted by the prober.
/// Only the colony gate can therefore tell it apart from a member of
/// colony "main".
struct ForeignGatewayCtx {
	local: ClusterTestCerts,
	foreign: ClusterTestCerts,
	shared_trust: Arc<dyn CertificateTrust>,
}

fn foreign_gateway_ctx() -> ForeignGatewayCtx {
	let local = cluster_certs();
	let foreign = foreign_colony_certs();
	let shared_trust = combined_trust(&[&local.cert, &foreign.cert]);
	ForeignGatewayCtx { local, foreign, shared_trust }
}

/// Running gateway from colony "other", TLS-anchored both ways.
/// A probe against it completes the handshake and fails only the gate.
fn foreign_gateway_conf(ctx: &ForeignGatewayCtx) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		hive_trust: Some(Arc::clone(&ctx.shared_trust)),
		peer_trust: Some(Arc::clone(&ctx.shared_trust)),
		..cluster_tls_config_with_trust(&ctx.foreign, None)
	};
	ClusterConfig::new(tls)
}

/// Prober with no anchors and a fast beat.
/// Discovery runs on feeler probes alone.
/// `shared_trust` anchors both probed identities.
/// Only the colony gate therefore separates them.
fn probing_cluster_conf(ctx: &ForeignGatewayCtx) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		peer_trust: Some(Arc::clone(&ctx.shared_trust)),
		..cluster_tls_config(&ctx.local)
	};

	ClusterConfig::builder(tls)
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

/// Poll until the discovery table holds no new-bucket candidates or
/// attempts exhaust. Feeler probes run on the advertise beat's cadence.
/// Their outcome is therefore only observable by polling.
/// Branching lives here, not in scenarios.
async fn wait_for_new_candidates_drained(table: &PeerTable, attempts: u32, interval: Duration) -> bool {
	let drained = |table: &PeerTable| table.learned().is_ok_and(|(new_count, _)| new_count == 0);
	for _ in 0..attempts {
		if drained(table) {
			return true;
		}

		tokio::time::sleep(interval).await;
	}

	drained(table)
}

tb_assert_spec! {
	pub ClusterPeerForeignProbeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_PROBE_HINTS_ADMITTED, exactly!(1), equals!(2u64)),
			(events::CLUSTER_PEER_DISCOVERED, exactly!(1)),
			(PEER_PROBE_MEMBER_PROMOTED, exactly!(1), equals!(true)),
			(PEER_PROBE_FOREIGN_REFUSED, exactly!(1), equals!(true))
		]
	}
}

// Feeler probes gate on colony equality (CWE-668).
// One learned hint names a same-colony member.
// The other names a TLS-trusted gateway from a foreign colony.
// Both probes complete the handshake.
// Only the member passes the gate (CLUSTER_PEER_DISCOVERED exactly once)
// and joins the beat targets. The foreign candidate leaves the new table
// through discard. A trusted-but-foreign identity can therefore neither
// clog a prefix bucket nor become a dial target.
tb_scenario! {
	name: cluster_feeler_probe_discards_foreign_colony_peer,
	spec: ClusterPeerForeignProbeSpec,
	environment Cluster {
		context: foreign_gateway_ctx(),
		start: |SetupEnv { trace, context: ctx }| async move {
			start_cluster(&trace, foreign_gateway_conf(&ctx)).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			let member_conf = peering_cluster_conf_with_trust(&ctx.local, Arc::clone(&ctx.shared_trust));
			let member = start_cluster(&trace, member_conf).await?;
			let prober_conf = probing_cluster_conf(&ctx);
			let table = Arc::clone(&prober_conf.peer.table);
			let prober = start_cluster(&trace, prober_conf).await?;

			let foreign_addr = cluster.addr().to_string();
			let member_addr = member.addr().to_string();
			let hints = vec![
				PeerHint { gateway_addr: foreign_addr.clone(), peer_id: None },
				PeerHint { gateway_addr: member_addr.clone(), peer_id: None },
			];
			let admitted = table.learn(hints).unwrap_or_default();
			trace.event_with(PEER_PROBE_HINTS_ADMITTED, &[], admitted as u64)?;

			let drained = wait_for_new_candidates_drained(&table, 50, Duration::from_millis(100)).await;
			let targets = table.target_set().unwrap_or_default();
			trace.event_with(PEER_PROBE_MEMBER_PROMOTED, &[], targets.contains(&member_addr))?;
			trace.event_with(PEER_PROBE_FOREIGN_REFUSED, &[], drained && !targets.contains(&foreign_addr))?;

			prober.stop();
			member.stop();
			cluster.stop();
			Ok(())
		}
	}
}

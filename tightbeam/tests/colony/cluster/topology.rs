//! Multi-instance topology and load-balancer wiring.

use super::common::*;

// ============================================================================
// Multi-Instance Topology: Load Balancer Wiring
// ============================================================================

/// Shared fixture for the topology scenarios: gateway certs plus the
/// selection set the [`RecordingBalancer`] populates. The scenario
/// reduces the set to a `BALANCER_SPREAD` boolean event the spec pins.
struct TopologyCtx {
	certs: Arc<GatewayCerts>,
	selected: Arc<Mutex<HashSet<usize>>>,
}

impl TopologyCtx {
	fn new() -> Self {
		Self { certs: Arc::new(cluster_certs()), selected: Arc::new(Mutex::new(HashSet::new())) }
	}

	fn selected_indices(&self) -> HashSet<usize> {
		self.selected.lock().map(|guard| guard.clone()).unwrap_or_default()
	}
}

/// Wraps any strategy to prove the `Arc<dyn LoadBalancer>` is consulted
/// and a custom strategy threads through
/// [`ClusterConfigBuilder::with_load_balancer`]: every offer is recorded as
/// a `BALANCER_OFFERED` event valued with the slate width, and returned
/// indices land in the shared selection set.
struct RecordingBalancer<L: LoadBalancer> {
	inner: L,
	trace: TraceCollector,
	selected: Arc<Mutex<HashSet<usize>>>,
}

impl<L: LoadBalancer> RecordingBalancer<L> {
	fn new(inner: L, trace: &TraceCollector, ctx: &TopologyCtx) -> Self {
		Self { inner, trace: trace.share(), selected: Arc::clone(&ctx.selected) }
	}
}

impl<L: LoadBalancer> LoadBalancer for RecordingBalancer<L> {
	fn select(&self, candidates: &[InstanceMetrics]) -> Option<usize> {
		let value = candidates.len() as u64;
		let _ = self.trace.event_with(BALANCER_OFFERED, &[], value);
		let pick = self.inner.select(candidates);
		if let (Some(index), Ok(mut chosen)) = (pick, self.selected.lock()) {
			chosen.insert(index);
		}
		pick
	}
}

fn topology_cluster_conf(trace: &TraceCollector, ctx: &TopologyCtx, inner: impl LoadBalancer + 'static) -> ClusterConfig {
	let tls = cluster_tls_config(ctx.certs.as_ref());
	let load_balancer = RecordingBalancer::new(inner, trace, ctx);
	ClusterConfig::builder(tls).with_load_balancer(load_balancer).build()
}

/// Register two live ping servlets as instances of one type and route
/// `routes` work requests through the gateway. Every response status is
/// recorded as a valued event the spec asserts against
/// [`TransitStatus::Ok`].
async fn drive_topology_routes(
	trace: &TraceCollector,
	ctx: &TopologyCtx,
	cluster: &ClusterGateway,
	routes: usize,
) -> Result<(), TightBeamError> {
	let trace = Arc::new(trace.share());
	let config = Some(servlet_tls_config(ctx.certs.as_ref())?);
	let servlet_a = ClusterTestServlet::start(Arc::clone(&trace), config).await?;
	let config = Some(servlet_tls_config(ctx.certs.as_ref())?);
	let servlet_b = ClusterTestServlet::start(Arc::clone(&trace), config).await?;
	let addr_a = servlet_a.addr().to_string();
	let addr_b = servlet_b.addr().to_string();
	let hive_addr = b"127.0.0.1:65210".as_slice();

	let mut client = connect_cluster(ctx.certs.as_ref(), cluster.addr()).await?;

	let registered = register_signed_hive(&mut client, &ctx.certs.key, b"topo-reg", hive_addr).await?;
	let value = registered.status;
	trace.event_with(TOPOLOGY_REGISTER_STATUS, &[], value)?;

	let added = vec![servlet_info("ping", addr_a.as_bytes()), servlet_info("ping", addr_b.as_bytes())];
	let removed = vec![];
	let request = servlet_address_update(hive_addr, added, removed);
	let added = emit_servlet_update(&mut client, &ctx.certs.key, b"topo-add", request).await?;
	let value = added.status;
	trace.event_with(TOPOLOGY_ADD_STATUS, &[], value)?;

	for round in 0..routes {
		let id = format!("topo-work-{round}");
		let routed = emit_ping_work(&mut client, id.as_bytes()).await?;
		let value = routed.status;
		trace.event_with(TOPOLOGY_ROUTE_STATUS, &[], value)?;
	}

	servlet_a.stop();
	servlet_b.stop();
	Ok(())
}

/// Drive `routes` requests and record whether the strategy selected both
/// instances as `BALANCER_SPREAD`. Shared by every topology scenario so
/// they differ only in strategy and volume; the offer widths travel as
/// `BALANCER_OFFERED` events the spec value-asserts.
async fn record_topology_spread(
	trace: &TraceCollector,
	ctx: &TopologyCtx,
	cluster: &ClusterGateway,
	routes: usize,
) -> Result<(), TightBeamError> {
	drive_topology_routes(trace, ctx, cluster, routes).await?;

	let spread = ctx.selected_indices() == HashSet::from([0usize, 1usize]);
	trace.event_with(BALANCER_SPREAD, &[], u64::from(spread))?;

	Ok(())
}

tb_assert_spec! {
	pub TopologySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, at_least!(4)),
			(BALANCER_OFFERED, at_least!(4), equals!(2u64)),
			(BALANCER_SPREAD, exactly!(1), equals!(1u64)),
			(TOPOLOGY_REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(TOPOLOGY_ADD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(TOPOLOGY_ROUTE_STATUS, at_least!(4), equals!(TransitStatus::Ok))
		]
	}
}

// A pluggable RoundRobin threads through the builder and deterministically
// spreads work across both registered instances of one type.
tb_scenario! {
	name: cluster_round_robin_spreads_work_across_instances,
	spec: TopologySpec,
	environment Cluster {
		context: TopologyCtx::new(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let inner = RoundRobin::default();
			let conf = topology_cluster_conf(&trace, &ctx, inner);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			record_topology_spread(&trace, &ctx, &cluster, 4).await?;
			cluster.stop();
			Ok(())
		}
	}
}

// The default pheromone forager (via `with_seed` for a reproducible stream)
// explores both instances rather than locking onto one, the stigmergic
// spread the deterministic-argmax predecessor could not provide.
tb_scenario! {
	name: cluster_default_forager_spreads_work_across_instances,
	spec: TopologySpec,
	environment Cluster {
		context: TopologyCtx::new(),
		start: |SetupEnv { trace, context: ctx }| async move {
			let inner = StochasticForager::with_seed(0x7B_EA_11);
			let conf = topology_cluster_conf(&trace, &ctx, inner);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: ctx, cluster }| async move {
			record_topology_spread(&trace, &ctx, &cluster, 12).await?;
			cluster.stop();
			Ok(())
		}
	}
}

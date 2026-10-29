//! The outbound connection pools of a cluster gateway.
//!
//! Hive and peer hops use separate pools, so each trust plane stays
//! attached to the dials it authorizes. The gateway builds its client
//! identity once, and both pools share it by `Arc`.

use std::sync::Arc;

use crate::clock::Clock;
use crate::colony::cluster::ClusterTlsConfig;
use crate::crypto::x509::store::CertificateTrust;
use crate::trace::TraceCollector;
use crate::transport::client::{ConnectionBuilder, ConnectionPool, PoolConfig};
use crate::transport::Protocol;

type ClusterPool<P> = ConnectionPool<P>;

/// The hive pool plus the optional peer-plane pool.
///
/// The fields are named because both pools share one type, so a tuple would
/// let a swap of the two pools compile and cross the two trust planes.
pub struct ClusterPools<P: Protocol> {
	/// The pool of outbound dials to this gateway's own hives, on the
	/// `hive_trust` plane.
	pub hive: Arc<ClusterPool<P>>,
	/// The pool of outbound dials to federated peer gateways, on the
	/// `peer_trust` plane. The value is `None` when `peer_trust` is unset.
	pub peer: Option<Arc<ClusterPool<P>>>,
}

impl ClusterTlsConfig {
	/// Builds one outbound pool from the settings `pool`. The pool dials as
	/// [`Self::outbound`] configures it, validates servers against `trust`
	/// before the server policy of this config, measures time on `clock`, and
	/// records its dials and the sessions they open into `trace`.
	// The `instrument` build alone attaches a trace to a pool, so that build
	// alone reads `trace`.
	#[cfg_attr(not(feature = "instrument"), allow(unused_variables))]
	fn pool<P>(
		&self,
		pool: &PoolConfig,
		clock: &Arc<dyn Clock>,
		trust: Option<Arc<dyn CertificateTrust>>,
		trace: &TraceCollector,
	) -> Arc<ClusterPool<P>>
	where
		P: Protocol + Send + Sync + 'static,
		P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
		P::Transport: Send + Sync,
	{
		// `with_config` takes the config by value, so the copy costs one `Arc`
		// clone of the mux offer.
		let builder = ClusterPool::<P>::builder()
			.with_config(pool.clone())
			.with_clock(Arc::clone(clock));
		#[cfg(feature = "instrument")]
		let builder = builder.with_trace(trace.share());
		let mut builder = self.outbound(builder);

		if let Some(store) = trust {
			builder = builder.with_trust_store(store);
		}

		Arc::new(builder.build())
	}

	/// Builds the hive pool from `pool` and, when `peer_trust` is set, the
	/// peer pool, both under one client identity. Both pools measure time on
	/// the gateway's `clock` and record into the gateway's `trace`.
	///
	/// Each pool reads its trust plane here, on the config that holds both,
	/// because `hive_trust` and `peer_trust` share a type, so a caller that
	/// passed them by position could swap them and cross the trust planes.
	///
	/// # Warning
	///
	/// The trace records each dial of both pools and the session it opens, a
	/// session that the peer fails included. The default `BoundedMemorySink`
	/// drops each event past `max_events`, the gateway's own refusals
	/// included, so a long-lived gateway needs an `EventSink` that forwards
	/// each event, or a reader that drains the trace.
	pub(crate) fn pools<P>(&self, pool: &PoolConfig, clock: &Arc<dyn Clock>, trace: &TraceCollector) -> ClusterPools<P>
	where
		P: Protocol + Send + Sync + 'static,
		P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
		P::Transport: Send + Sync,
	{
		let hive_trust = self.hive_trust.as_ref().map(Arc::clone);
		let hive_pool = self.pool::<P>(pool, clock, hive_trust, trace);
		let peer_trust = self.peer_trust.as_ref().map(Arc::clone);
		let build_peer = |trust| self.pool::<P>(pool, clock, Some(trust), trace);
		let peer_pool = peer_trust.map(build_peer);

		ClusterPools { hive: hive_pool, peer: peer_pool }
	}
}

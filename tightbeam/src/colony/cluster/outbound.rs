//! Outbound connection-pool construction for cluster gateways.
//!
//! Hive and peer hops use separate pools, so each trust plane stays
//! attached to the dials it authorizes. The client identity is materialized
//! once and shared by `Arc` across both pools.

use std::sync::Arc;

use crate::colony::cluster::ClusterTlsConfig;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::store::CertificateTrust;
use crate::transport::client::{ConnectionBuilder, ConnectionPool, PoolConfig};
use crate::transport::Protocol;
use crate::utils::time::Clock;
use crate::TightBeamError;

type ClusterPool<P> = ConnectionPool<P>;

/// The hive pool plus the optional peer-plane pool.
///
/// The fields are named because both pools share one type, so a tuple would
/// let a hive and peer transposition compile and cross the two trust planes.
pub struct ClusterPools<P: Protocol> {
	/// Outbound dials to this gateway's own hives, on the `hive_trust` plane.
	pub hive: Arc<ClusterPool<P>>,
	/// Outbound dials to federated peer gateways, on the `peer_trust` plane.
	/// The value is `None` when federation is disabled.
	pub peer: Option<Arc<ClusterPool<P>>>,
}

impl PoolConfig {
	/// Builds one outbound pool on this configuration. The pool dials as
	/// [`ClusterTlsConfig::outbound`] configures it, validates servers against
	/// `trust` before the server policy of `tls`, and measures time on
	/// `clock`.
	fn build_one<P>(
		&self,
		clock: &Arc<dyn Clock>,
		tls: &ClusterTlsConfig,
		trust: Option<Arc<dyn CertificateTrust>>,
	) -> Arc<ClusterPool<P>>
	where
		P: Protocol<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
		P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
		P::Transport: Send + Sync,
	{
		// `with_config` takes the config by value, so the copy costs a
		// refcount bump on the mux offer.
		let builder = ClusterPool::<P>::builder()
			.with_config(self.clone())
			.with_clock(Arc::clone(clock));
		let mut builder = tls.outbound(builder);

		if let Some(store) = trust {
			builder = builder.with_trust_store(store);
		}

		Arc::new(builder.build())
	}

	/// Builds the hive pool and, when peer trust is configured, the peer
	/// pool from one client identity. Both pools measure time on the
	/// gateway's `clock`.
	///
	/// The method takes the whole TLS config because `hive_trust` and
	/// `peer_trust` share a type, so passing them positionally would let a
	/// swap compile and cross the trust planes.
	pub(crate) fn build_cluster_pools<P>(
		&self,
		tls: &ClusterTlsConfig,
		clock: &Arc<dyn Clock>,
	) -> Result<ClusterPools<P>, TightBeamError>
	where
		P: Protocol<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
		P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
		P::Transport: Send + Sync,
	{
		let hive_trust = tls.hive_trust.as_ref().map(Arc::clone);
		let hive_pool = self.build_one::<P>(clock, tls, hive_trust);
		let peer_trust = tls.peer_trust.as_ref().map(Arc::clone);
		let build_peer = |trust| self.build_one::<P>(clock, tls, Some(trust));
		let peer_pool = peer_trust.map(build_peer);

		Ok(ClusterPools { hive: hive_pool, peer: peer_pool })
	}
}

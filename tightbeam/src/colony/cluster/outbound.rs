//! Outbound connection-pool construction for cluster gateways
//!
//! Hive and peer hops use separate pools so each trust plane stays
//! attached to the dials it authorizes. Client identity is materialized
//! once and shared by `Arc` across both pools.

use std::sync::Arc;

use crate::crypto::key::SigningKeyProvider;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::{Certificate, CertificateSpec};
use crate::transport::client::pool::{ConnectionBuilder, ConnectionPool, PoolConfig};
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::Protocol;
use crate::TightBeamError;

type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;
type ClusterKey = HandshakeKeyManager<DefaultCryptoProvider>;
/// Hive pool plus the optional peer-plane pool
type ClusterPools<P> = (Arc<ClusterPool<P>>, Option<Arc<ClusterPool<P>>>);

/// Build hive and optional peer outbound pools from one client identity
#[cfg(feature = "x509")]
#[doc(hidden)]
pub fn build_cluster_pools<P>(
	pool_config: PoolConfig,
	certificate: CertificateSpec,
	key: Arc<dyn SigningKeyProvider>,
	hive_trust: Option<Arc<dyn CertificateTrust>>,
	peer_trust: Option<Arc<dyn CertificateTrust>>,
) -> Result<ClusterPools<P>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	let certificate = Arc::new(Certificate::try_from(certificate)?);
	let key = Arc::new(ClusterKey::new(key));

	let hive_pool = build_one::<P>(pool_config.clone(), Arc::clone(&certificate), Arc::clone(&key), hive_trust);
	let peer_pool =
		peer_trust.map(|trust| build_one::<P>(pool_config, Arc::clone(&certificate), Arc::clone(&key), Some(trust)));

	Ok((hive_pool, peer_pool))
}

#[cfg(feature = "x509")]
fn build_one<P>(
	pool_config: PoolConfig,
	certificate: Arc<Certificate>,
	key: Arc<ClusterKey>,
	trust: Option<Arc<dyn CertificateTrust>>,
) -> Arc<ClusterPool<P>>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	let mut builder = ClusterPool::<P>::builder()
		.with_config(pool_config)
		.with_shared_client_identity(certificate, key);

	if let Some(store) = trust {
		builder = builder.with_trust_store(store);
	}

	Arc::new(builder.build())
}

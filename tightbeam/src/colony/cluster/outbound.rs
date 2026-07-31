//! Outbound connection-pool construction for cluster gateways
//!
//! Hive and peer hops use separate pools so each trust plane stays
//! attached to the dials it authorizes. Client identity is materialized
//! once and shared by `Arc` across both pools.

use std::sync::Arc;

use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::transport::client::pool::{ConnectionBuilder, ConnectionPool, PoolConfig};
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::Protocol;
use crate::TightBeamError;

#[cfg(feature = "x509")]
use super::ClusterTlsConfig;

type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;
type ClusterKey = HandshakeKeyManager<DefaultCryptoProvider>;

/// Hive pool plus the optional peer-plane pool
///
/// Named fields because both pools share one type: a tuple would let a
/// hive/peer transposition compile, crossing the two trust planes.
pub struct ClusterPools<P: Protocol> {
	/// Outbound dials to this gateway's own hives (`hive_trust` plane)
	pub hive: Arc<ClusterPool<P>>,
	/// Outbound dials to federated peer gateways (`peer_trust` plane);
	/// `None` when federation is disabled
	pub peer: Option<Arc<ClusterPool<P>>>,
}

/// Build hive and optional peer outbound pools from one client identity
///
/// Takes the whole TLS config: `hive_trust` and `peer_trust` share a
/// type, so passing them positionally would let a swap compile and
/// cross the trust planes.
#[cfg(feature = "x509")]
#[doc(hidden)]
pub fn build_cluster_pools<P>(
	pool_config: PoolConfig,
	tls: &ClusterTlsConfig,
) -> Result<ClusterPools<P>, TightBeamError>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync,
	P::Transport: Send + Sync,
{
	let certificate = Arc::new(Certificate::try_from(tls.certificate.clone())?);
	let key = Arc::new(ClusterKey::new(Arc::clone(&tls.key)));

	let hive_pool = build_one::<P>(
		pool_config.clone(),
		Arc::clone(&certificate),
		Arc::clone(&key),
		tls.hive_trust.as_ref().map(Arc::clone),
	);
	let peer_pool = tls
		.peer_trust
		.as_ref()
		.map(|trust| build_one::<P>(pool_config, Arc::clone(&certificate), Arc::clone(&key), Some(Arc::clone(trust))));

	Ok(ClusterPools { hive: hive_pool, peer: peer_pool })
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

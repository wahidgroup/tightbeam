//! Shared pool and digest bounds for cluster gateway runtime.

use std::sync::Arc;

use digest::consts::U32;
use digest::{Digest, OutputSizeUser};

use crate::crypto::profiles::DefaultCryptoProvider;
use crate::der::oid::AssociatedOid;
use crate::transport::client::pool::ConnectionPool;

#[cfg(feature = "x509")]
use crate::colony::hive::ReplayGuard;

pub(crate) type ClusterPool<P> = ConnectionPool<P, DefaultCryptoProvider>;

#[cfg(feature = "x509")]
pub(crate) type GatewayReplayGuard = Arc<ReplayGuard>;
#[cfg(not(feature = "x509"))]
pub(crate) type GatewayReplayGuard = ();

/// Digest bound used by signed cluster control and gossip frames.
pub trait ClusterDigest: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}

impl<D> ClusterDigest for D where D: Digest + OutputSizeUser<OutputSize = U32> + AssociatedOid + Send + Sync + 'static {}

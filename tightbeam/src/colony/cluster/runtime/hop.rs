//! One dial target on a gateway trust plane.
//!
//! Every outbound gateway hop pairs a pool with the address to dial on
//! it. [`Hop`] holds that pair, so the plane a payload travels on is
//! chosen once at construction rather than re-paired at each call.

use core::hash::Hash;
use core::mem;
use core::str::{self, FromStr};
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::ClusterPool;
use crate::colony::cluster::ClusterError;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, PooledClient, Protocol, X509ClientConfig};
use crate::{encode, Frame, Metadata, Version};

/// A pool and the address to dial on it.
pub(crate) struct Hop<'p, P: Protocol> {
	pool: &'p Arc<ClusterPool<P>>,
	addr: Arc<[u8]>,
}

impl<'p, P> Hop<'p, P>
where
	P: Protocol
		+ PersistentConnection
		+ EncryptedProtocol<CryptoProvider = DefaultCryptoProvider>
		+ Send
		+ Sync
		+ 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Targets `addr` on `pool`.
	pub(crate) fn new(pool: &'p Arc<ClusterPool<P>>, addr: Arc<[u8]>) -> Self {
		Self { pool, addr }
	}

	/// Delivers a client's end-to-end frame and returns the peer's
	/// complete reply frame, encoded.
	///
	/// `frame` is the client's frame from [`ClusterWorkRequest::payload`
	/// and re-emitted as-is. DER is canonical, so the emitted bytes match
	/// what the client signed and the servlet can verify the envelope end
	/// to end. The reply frame returns encoded whole so the client can
	/// verify the servlet's envelope the same way.
	///
	/// [`ClusterWorkRequest::payload`]: crate::colony::common::ClusterWorkRequest::payload
	pub(crate) async fn deliver_frame(self, frame: Frame) -> Result<Vec<u8>, ClusterError> {
		let response = self.emit(frame).await?;
		Ok(encode(&response)?)
	}

	/// Delivers hop-local bytes under a fresh transport wrapper and
	/// returns the reply body.
	///
	/// This is the hop plumbing for messages that are not end-to-end frames:
	/// a re-encoded [`ClusterRequest::Work`] envelope toward a peer gateway,
	/// or a gossip application payload toward an ingress servlet.
	///
	/// [`ClusterRequest::Work`]: crate::colony::common::ClusterRequest::Work
	pub(crate) async fn deliver_envelope(self, message: Vec<u8>) -> Result<Vec<u8>, ClusterError> {
		let mut metadata = Metadata::default();
		metadata.id = b"work-forward".to_vec();

		let frame = Frame { version: Version::V0, metadata, message, integrity: None, nonrepudiation: None };
		let mut response = self.emit(frame).await?;
		Ok(mem::take(&mut response.message))
	}

	/// Parses the stored socket and opens a pooled connection to it.
	///
	/// This is the only place dial bytes become a protocol address, so a
	/// stream open and a unary emit reach a peer through one parse.
	pub(crate) async fn connect(self) -> Result<PooledClient<P, DefaultCryptoProvider>, ClusterError> {
		let addr_str = str::from_utf8(&self.addr).map_err(|_| ClusterError::InvalidAddress(self.addr.to_vec()))?;
		let parsed_addr: P::Address = addr_str.parse().map_err(|_| ClusterError::InvalidAddress(self.addr.to_vec()))?;
		self.pool.connect(parsed_addr).await.map_err(|_| ClusterError::ConnectFailed)
	}

	/// Dials the target, emits `frame`, and returns the reply frame.
	async fn emit(self, frame: Frame) -> Result<Frame, ClusterError> {
		let mut client = self.connect().await?;
		match client.emit(frame, None).await {
			Ok(Some(response)) => Ok(response),
			Ok(None) => Err(ClusterError::NoResponse),
			Err(e) => Err(ClusterError::from(e)),
		}
	}
}

//! One dial target on a gateway trust plane.
//!
//! Every outbound gateway hop pairs a pool with the address to dial on
//! it. [`Hop`] holds that pair, so the plane a payload travels on is
//! chosen once at construction rather than re-paired at each call.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::ClusterPool;
use crate::colony::cluster::{ClusterError, DialTarget};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, PooledClient, Protocol};
use crate::{encode, Frame};

/// A pool and the target to dial on it.
pub(crate) struct Hop<'p, P: Protocol> {
	pool: &'p Arc<ClusterPool<P>>,
	dial: DialTarget,
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
		+ MuxConnector
		+ EncryptedProtocolState
		+ Send
		+ Sync
		+ 'static,
{
	/// Targets `dial` on `pool`.
	pub(crate) fn new(pool: &'p Arc<ClusterPool<P>>, dial: DialTarget) -> Self {
		Self { pool, dial }
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
	pub(crate) async fn deliver_envelope(self, message: impl Into<Vec<u8>>) -> Result<Vec<u8>, ClusterError> {
		let message: Vec<u8> = message.into();
		let frame = Frame::v0(b"work-forward", message);
		let response = self.emit(frame).await?;
		Ok(response.into_message())
	}

	/// Opens a pooled connection to the target.
	///
	/// The target becomes a protocol address through
	/// [`DialTarget::protocol_address`], so a stream open and a unary emit
	/// reach a peer through the one conversion every dial uses.
	pub(crate) async fn connect(self) -> Result<PooledClient<P>, ClusterError> {
		let address: P::Address = self.dial.protocol_address()?;
		self.pool.connect(address).await.map_err(|_| ClusterError::ConnectFailed)
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

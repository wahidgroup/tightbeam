//! One dial target on a gateway trust plane.
//!
//! Every outbound gateway hop pairs a plane with the address to dial on
//! it. [`Hop`] holds that pair, so the plane a payload travels on is
//! chosen once at construction rather than re-paired at each call.
//!
//! - A hive hop dials on the hive pool.
//! - A peer hop dials through [`PeerPlane::hop`], which binds the hop to the gateway its route names.
//! - A gossip dial goes through [`PeerPlane::connect_unbound`], which holds an address only.

use core::hash::Hash;
use core::str::FromStr;
use std::sync::Arc;

use crate::colony::cluster::runtime::bounds::ClusterPool;
use crate::colony::cluster::{ClusterConfig, ClusterError, DialTarget};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::state::EncryptedProtocolState;
use crate::transport::{EncryptedProtocol, PersistentConnection, PooledClient, Protocol};
use crate::{encode, Frame};

/// The plane this gateway dials peer gateways on: the peer pool, or the hive
/// pool when no peer trust is configured.
///
/// An advertisement binds its signer to the socket it claims. The pool is
/// private, and the plane offers two ways to it:
///
/// - [`Self::hop`] carries a route and holds the gateway that answers to it before any frame leaves.
/// - [`Self::connect_unbound`] holds an address only, so its client talks to whichever gateway answers.
///
/// A forward dials through [`Self::hop`], so it reaches only the gateway its
/// route names (CWE-668).
pub(crate) struct PeerPlane<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
}

// The impl is manual because a derive would demand `P: Clone`, and both
// fields are reference-counted regardless of `P`.
impl<P: Protocol> Clone for PeerPlane<P> {
	fn clone(&self) -> Self {
		Self { pool: Arc::clone(&self.pool), config: Arc::clone(&self.config) }
	}
}

impl<P: Protocol> PeerPlane<P> {
	/// A plane that dials peer gateways on `pool` and names each gateway that
	/// answers by `config`'s peer trust.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>, config: Arc<ClusterConfig>) -> Self {
		Self { pool, config }
	}

	/// Targets `dial` on this plane, bound to the gateway whose slate key is
	/// `gateway_id`.
	pub(crate) fn hop<'p>(&'p self, dial: DialTarget, gateway_id: &'p (impl AsRef<[u8]> + ?Sized)) -> Hop<'p, P> {
		Hop { plane: Plane::Peer { peers: self, gateway_id: gateway_id.as_ref() }, dial }
	}
}

/// The plane a hop dials on.
enum Plane<'p, P: Protocol> {
	/// The hive pool, which reaches this gateway's own hives and servlets.
	Hive(&'p Arc<ClusterPool<P>>),
	/// The peer plane, bound to the one gateway the route names.
	Peer {
		/// The plane the hop dials on.
		peers: &'p PeerPlane<P>,
		/// The slate key of the gateway that must answer.
		gateway_id: &'p [u8],
	},
}

/// A plane and the target to dial on it.
pub(crate) struct Hop<'p, P: Protocol> {
	plane: Plane<'p, P>,
	dial: DialTarget,
}

impl<'p, P: Protocol> Hop<'p, P> {
	/// Targets `dial` on the hive pool `pool`.
	pub(crate) fn new(pool: &'p Arc<ClusterPool<P>>, dial: DialTarget) -> Self {
		Self { plane: Plane::Hive(pool), dial }
	}
}

impl<P> PeerPlane<P>
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
	/// Connects to `address` and returns a client to the gateway that answers.
	///
	/// Gossip holds each target by address. A reconcile round checks the colony
	/// of the answer. An advertisement and a reflood go to the gateway that
	/// answers.
	///
	/// # Errors
	///
	/// - [`ClusterError::Transport`] -- the dial failed.
	pub(crate) async fn connect_unbound(
		&self,
		address: impl Into<P::Address>,
	) -> Result<PooledClient<P>, ClusterError> {
		let client = self.pool.connect(address).await?;
		Ok(client)
	}

	/// Connects to `address` and returns the client once the gateway that
	/// answered proved to be the one whose slate key is `gateway_id`.
	///
	/// - A cold connection defers its handshake to the first emit, so the
	///   handshake completes here, before the caller can send anything.
	/// - [`ClusterConfig::peer_identity`] names the answer the way an
	///   advertisement names its signer, so a gateway that rotated its
	///   certificate under one key keeps its name.
	/// - An answer with no certificate, or with a key the peer trust store does not hold, fails closed.
	///
	/// # Errors
	///
	/// - [`ClusterError::PeerMismatch`] -- the answer presented another gateway's certificate, or none.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	async fn connect_bound(&self, address: P::Address, gateway_id: &[u8]) -> Result<PooledClient<P>, ClusterError> {
		let connected = self.pool.connect(address).await;
		let mut client = connected.map_err(|_| ClusterError::ConnectFailed)?;
		let handshake = client.complete_handshake().await;
		handshake.map_err(|_| ClusterError::ConnectFailed)?;

		let answered = client.peer_certificate().and_then(|cert| self.config.peer_identity(cert));
		if answered.as_deref() != Some(gateway_id) {
			return Err(ClusterError::PeerMismatch);
		}

		Ok(client)
	}
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
	/// Delivers a client's end-to-end frame and returns the peer's
	/// complete reply frame, encoded.
	///
	/// - `frame` is the client's frame from [`ClusterWorkRequest::payload`],
	///   re-emitted as-is. DER is canonical, so the emitted bytes match what
	///   the client signed and the servlet can verify the envelope end to end.
	/// - The reply frame returns encoded whole so the client can verify the servlet's envelope the same way.
	///
	/// [`ClusterWorkRequest::payload`]: crate::colony::common::ClusterWorkRequest::payload
	pub(crate) async fn deliver_frame(self, frame: Frame) -> Result<Vec<u8>, ClusterError> {
		let response = self.emit(frame).await?;
		Ok(encode(&response)?)
	}

	/// Delivers hop-local bytes under a fresh transport wrapper and
	/// returns the reply body.
	///
	/// This path carries the messages that are not end-to-end frames:
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
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the target does not parse as an address of this protocol.
	/// - [`ClusterError::PeerMismatch`] -- a peer hop was answered by a gateway the route does not name.
	/// - [`ClusterError::ConnectFailed`] -- the dial or the handshake failed.
	pub(crate) async fn connect(self) -> Result<PooledClient<P>, ClusterError> {
		let address: P::Address = self.dial.protocol_address()?;
		match self.plane {
			Plane::Hive(pool) => pool.connect(address).await.map_err(|_| ClusterError::ConnectFailed),
			Plane::Peer { peers, gateway_id } => peers.connect_bound(address, gateway_id).await,
		}
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

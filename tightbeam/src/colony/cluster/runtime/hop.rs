//! One dial target on a gateway trust plane.
//!
//! Every outbound gateway hop pairs a plane with the address to dial on
//! it. [`Hop`] holds that pair, so the plane a payload travels on is
//! chosen once at construction rather than re-paired at each call.
//!
//! - A servlet hop dials through [`HivePlane::servlet`], which binds the hop
//!   to the signer the servlet's registration names.
//! - A heartbeat dials through [`HivePlane::hive`], which binds the hop to the
//!   signer of the hive's registration.
//! - A peer hop dials through [`PeerPlane::hop`], which binds the hop to the gateway its route names.
//! - A gossip dial goes through [`PeerPlane::connect_member`], which proves the answer is a flood member.
//! - A direct advertisement goes through [`PeerPlane::advertiser`], which
//!   hands out the one unbound dial, so its client talks to whichever gateway
//!   answers.

use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::peer::FloodMember;
use crate::colony::cluster::runtime::advertise::Advertiser;
use crate::colony::cluster::runtime::bounds::{ClusterPool, ColonyDialProtocol};
use crate::colony::cluster::{ClusterConfig, ClusterError, DialTarget, HiveEntry};
use crate::crypto::x509::Certificate;
use crate::instrumentation::events::CLUSTER_DIAL_REFUSED;
use crate::trace::TraceCollector;
use crate::transport::TransportResult;
use crate::transport::{PooledClient, Protocol};
use crate::{encode, Frame};

/// The plane this gateway dials its own hives and their servlets on.
///
/// The pool is private, and the plane offers two ways to it, each a
/// [`BoundDial`], so a frame leaves toward a hive or a servlet only under the
/// identity its registration names (CWE-346):
///
/// - [`Self::servlet`] binds a hop to the signer a servlet's registration names.
/// - [`Self::hive`] binds a hop to the signer of a hive's registration.
///
/// A gateway with no peer pool dials its peers on this pool, through the
/// [`PeerPlane`] that [`Self::peers`] lends it to.
pub(crate) struct HivePlane<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	/// The collector that records each refused hop.
	trace: Arc<TraceCollector>,
}

// The impl is manual because a derive would demand `P: Clone`, and every
// field is reference-counted regardless of `P`.
impl<P: Protocol> Clone for HivePlane<P> {
	fn clone(&self) -> Self {
		Self { pool: Arc::clone(&self.pool), trace: Arc::clone(&self.trace) }
	}
}

impl<P: Protocol> HivePlane<P> {
	/// A plane that dials hives and their servlets on `pool`, and records
	/// each refused hop on `trace`.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>, trace: Arc<TraceCollector>) -> Self {
		Self { pool, trace }
	}

	/// Targets the servlet at `dial`, bound to `signer`, the signer its hive's
	/// registration names.
	pub(crate) fn servlet(&self, dial: DialTarget, signer: Arc<SignerIdentifier>) -> Hop<'_, P> {
		let bound = BoundDial::new(dial, ExpectedSigner::Hive(signer));

		Hop { pool: &self.pool, dial: bound, trace: &self.trace }
	}

	/// Targets the control address of `hive`, bound to the signer of its
	/// registration, so a heartbeat admits that identity alone (CWE-346).
	pub(crate) fn hive(&self, hive: &HiveEntry) -> Hop<'_, P> {
		Hop { pool: &self.pool, dial: hive.bound_dial(), trace: &self.trace }
	}

	/// The peer plane over this plane's pool, for a gateway that configures
	/// no peer pool. It names each gateway that answers by `config`'s peer
	/// trust.
	pub(crate) fn peers(&self, config: Arc<ClusterConfig>) -> PeerPlane<P> {
		PeerPlane::new(Arc::clone(&self.pool), config, Arc::clone(&self.trace))
	}
}

/// The plane this gateway dials peer gateways on: the peer pool, or the hive
/// pool when no peer trust is configured.
///
/// An advertisement binds its signer to the socket it claims. The pool is
/// private, and the plane offers three ways to it:
///
/// - [`Self::hop`] carries a route and holds the gateway that answers to it
///   before any frame leaves. A forward dials this way, so it reaches only
///   the gateway its route names (CWE-668).
/// - [`Self::connect_member`] holds an address and proves the answer is a
///   flood member before any frame leaves. A reconcile round and a rumor
///   flood dial this way, so gossip stays inside the flood (CWE-668).
/// - [`Self::advertiser`] hands out the one unbound dial, so its client talks
///   to whichever gateway answers. A direct advertisement dials this way.
pub(crate) struct PeerPlane<P: Protocol> {
	pool: Arc<ClusterPool<P>>,
	config: Arc<ClusterConfig>,
	/// The collector that records each refused hop.
	trace: Arc<TraceCollector>,
}

// The impl is manual because a derive would demand `P: Clone`, and every
// field is reference-counted regardless of `P`.
impl<P: Protocol> Clone for PeerPlane<P> {
	fn clone(&self) -> Self {
		Self {
			pool: Arc::clone(&self.pool),
			config: Arc::clone(&self.config),
			trace: Arc::clone(&self.trace),
		}
	}
}

impl<P: Protocol> PeerPlane<P> {
	/// A plane that dials peer gateways on `pool`, names each gateway that
	/// answers by `config`'s peer trust, and records each refused hop on
	/// `trace`.
	pub(crate) fn new(pool: Arc<ClusterPool<P>>, config: Arc<ClusterConfig>, trace: Arc<TraceCollector>) -> Self {
		Self { pool, config, trace }
	}

	/// Targets `dial` on this plane, bound to the gateway whose slate key is
	/// `gateway_id`.
	pub(crate) fn hop<'p>(&'p self, dial: DialTarget, gateway_id: &'p (impl AsRef<[u8]> + ?Sized)) -> Hop<'p, P> {
		let expected = ExpectedSigner::Gateway { gateway_id: gateway_id.as_ref(), config: &self.config };
		let bound = BoundDial::new(dial, expected);

		Hop { pool: &self.pool, dial: bound, trace: &self.trace }
	}

	/// The one unbound dial on this plane's pool, which a direct
	/// advertisement sends through.
	pub(crate) fn advertiser(&self) -> Advertiser<P> {
		Advertiser::new(Arc::clone(&self.pool))
	}
}

/// A dialed connection whose far end proved it belongs to this gateway's
/// flood.
///
/// [`PeerPlane::connect_member`] is the only constructor, and a gossip frame
/// leaves through [`Self::emit`] alone, so gossip reaches a flood member and
/// no other gateway (CWE-668).
pub(crate) struct FloodClient<P: ColonyDialProtocol> {
	client: PooledClient<P>,
}

impl<P: ColonyDialProtocol> FloodClient<P> {
	/// Wraps `client`, whose far end `_proof` names as a flood member.
	fn new(client: PooledClient<P>, _proof: FloodMember) -> Self {
		Self { client }
	}

	/// Emits `frame` to the member and returns its reply, when it sends one.
	///
	/// # Errors
	///
	/// - [`crate::transport::TransportError`] -- the emit failed on the pooled connection.
	pub(crate) async fn emit(&mut self, frame: Frame, attempt: Option<usize>) -> TransportResult<Option<Frame>> {
		self.client.emit(frame, attempt).await
	}

	/// The certificate the member presented in the handshake.
	pub(crate) fn peer_certificate(&self) -> Option<&Certificate> {
		self.client.peer_certificate()
	}
}

/// A bound dial on the pool of its plane.
///
/// Every hop is a [`BoundDial`], so a frame leaves a hop only toward the party
/// its route names.
pub(crate) struct Hop<'p, P: Protocol> {
	/// The pool the hop dials on: the hive pool for a hive or a servlet, and
	/// the peer plane's pool for a gateway.
	pool: &'p Arc<ClusterPool<P>>,
	/// The target, and the identity its answer must prove.
	dial: BoundDial<'p>,
	/// The collector that records a refused dial.
	trace: &'p TraceCollector,
}

impl<P: ColonyDialProtocol> PeerPlane<P> {
	/// Connects to `address` and returns the client once the gateway that
	/// answered proved it belongs to this gateway's flood.
	///
	/// A reconcile round and a rumor flood dial this way, so gossip bytes
	/// leave only toward a flood member (CWE-668).
	///
	/// - A cold connection defers its handshake to the first emit, so the
	///   handshake completes here, before the caller can send anything.
	/// - `None` means a gateway outside the flood answered. That is an answer
	///   about the address, where an `Err` is a failed dial.
	/// - The proof is asked on every call, so a pooled connection to a gateway
	///   the trust store has since dropped yields `None`.
	///
	/// # Errors
	///
	/// - [`ClusterError::Transport`] -- the dial or the handshake failed.
	pub(crate) async fn connect_member(
		&self,
		address: impl Into<P::Address>,
	) -> Result<Option<FloodClient<P>>, ClusterError> {
		let mut client = self.pool.connect(address).await?;
		client.complete_handshake().await?;

		let Some(flood) = self.config.flood() else {
			return Ok(None);
		};
		let Some(certificate) = client.peer_certificate() else {
			return Ok(None);
		};
		let Ok(member) = flood.member(certificate) else {
			return Ok(None);
		};

		Ok(Some(FloodClient::new(client, member)))
	}
}

impl<P: ColonyDialProtocol> Hop<'_, P> {
	/// Delivers a client's end-to-end frame and returns the peer's
	/// complete reply frame, encoded.
	///
	/// - `frame` is the client's frame from [`ClusterWorkRequest::payload`],
	///   re-emitted as-is. DER is canonical, so the emitted bytes match what
	///   the client signed and the servlet can verify the envelope end to end.
	/// - The reply frame returns encoded whole so the client can verify the servlet's envelope the same way.
	/// - An origin-signed gossip rumor reaches an ingress servlet through this path too, for the same reason.
	///
	/// [`ClusterWorkRequest::payload`]: crate::colony::common::ClusterWorkRequest::payload
	pub(crate) async fn deliver_frame(self, frame: Frame) -> Result<Vec<u8>, ClusterError> {
		let response = self.emit(frame).await?;
		Ok(encode(&response)?)
	}

	/// Delivers hop-local bytes under a fresh transport wrapper and
	/// returns the reply body.
	///
	/// This path carries the one hop-local message, a re-encoded
	/// [`ClusterRequest::Work`] envelope toward a peer gateway. Every other
	/// path carries an end-to-end frame.
	///
	/// [`ClusterRequest::Work`]: crate::colony::common::ClusterRequest::Work
	pub(crate) async fn deliver_envelope(self, message: impl Into<Vec<u8>>) -> Result<Vec<u8>, ClusterError> {
		let message: Vec<u8> = message.into();
		let frame = Frame::v0(b"work-forward", message);

		let response = self.emit(frame).await?;
		Ok(response.into_message())
	}

	/// Opens a pooled connection to the target, with its handshake complete,
	/// so a refused handshake is a refused connect and no frame has left.
	///
	/// - The target becomes a protocol address through
	///   [`DialTarget::protocol_address`], so a stream open and a unary emit
	///   reach a peer through the one conversion every dial uses.
	/// - A refused answer records [`CLUSTER_DIAL_REFUSED`] with the dialed address as its payload.
	///
	/// # Errors
	///
	/// - Every error of [`BoundDial::connect`].
	/// - [`ClusterError::Frame`] -- `trace` refused the refusal event.
	pub(crate) async fn connect(self) -> Result<PooledClient<P>, ClusterError> {
		let target = self.dial.target().clone();
		let connected = self.dial.connect(self.pool).await;
		if matches!(connected, Err(ClusterError::PeerMismatch)) {
			let refused = target.route_bytes();
			self.trace.event(CLUSTER_DIAL_REFUSED)?.with_payload(&refused).emit();
		}

		connected
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

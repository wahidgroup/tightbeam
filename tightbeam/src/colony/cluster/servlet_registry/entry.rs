use core::str::{from_utf8, FromStr};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::MAX_PHEROMONE;
use crate::colony::cluster::{AdmittedDial, ClusterError, NotASocket, PeerAddress, SharedId};
use crate::utils::BasisPoints;

/// The endpoint a route dials, parsed once where the route is built.
///
/// Its representation is private, so every target comes from an address a
/// hive registered or from a socket a peer claimed that the dial policy
/// admitted. Two targets are equal when they name one endpoint, so two
/// spellings of one socket compare equal wherever routes are compared
/// (CWE-706).
///
/// # Examples
///
/// A peer route dials the gateway socket its dial policy admitted:
///
/// ```
/// use core::net::SocketAddr;
/// use std::sync::Arc;
///
/// use tightbeam::colony::cluster::{PeerConfig, PeerRoute, ServletEntry};
///
/// let socket: SocketAddr = "192.0.2.7:9000".parse()?;
/// let dial = PeerConfig::default().admit_dial(socket)?;
/// let route = PeerRoute { peer_id: Arc::from(&b"peer"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
/// let entry = ServletEntry::peer(route, 100, 3);
///
/// let target = entry.dial_target();
/// assert_eq!(target.as_socket().map(|socket| socket.socket()), Some(socket));
/// assert_eq!(target.as_bytes(), b"192.0.2.7:9000");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialTarget(Endpoint);

/// What a [`DialTarget`] names, beside the bytes it renders as.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Endpoint {
	/// A socket that a peer gateway claimed or a hive registered, with its
	/// canonical rendering.
	Socket { address: PeerAddress, rendering: SharedId },
	/// A servlet or control address a hive registered that names no socket,
	/// such as an address of a protocol with its own address scheme. It
	/// compares by its bytes.
	Named(SharedId),
}

impl DialTarget {
	/// Returns the target of an address a hive registered, for one of its
	/// servlets or for its own control plane.
	///
	/// An address that spells a socket becomes that socket, so it compares
	/// with a claimed peer socket. Any other address is a name the protocol
	/// resolves when it dials, kept as the hive wrote it.
	pub(in crate::colony) fn of_registered(address: &SharedId) -> Self {
		match PeerAddress::try_from(address.as_ref()) {
			Ok(socket) => Self::of_socket(socket),
			Err(NotASocket) => Self(Endpoint::Named(Arc::clone(address))),
		}
	}

	/// Returns the target of a socket a peer gateway claimed, which this
	/// gateway's dial policy admitted as `dial`.
	pub(crate) fn of_claimed(dial: AdmittedDial) -> Self {
		Self::of_socket(dial.address())
	}

	/// Returns the target of `dial`, which shares the rendering of this target
	/// when this target names the socket `dial` admitted.
	///
	/// The entries of one slate dial one socket, so they share one rendering
	/// of it. A target of another socket renders `dial` on its own, so an
	/// entry always dials the socket its own proof admitted.
	fn sharing(&self, dial: AdmittedDial) -> Self {
		let address = dial.address();
		if self.as_socket() == Some(&address) {
			return self.clone();
		}

		Self::of_socket(address)
	}

	/// Returns the target of `address`, rendered through
	/// [`PeerAddress::route_bytes`], the one home for the spelling.
	fn of_socket(address: PeerAddress) -> Self {
		let rendering = address.route_bytes();
		Self(Endpoint::Socket { address, rendering })
	}

	/// Returns the socket this target names, when it names one.
	///
	/// # Examples
	///
	/// ```
	/// use core::net::SocketAddr;
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::{PeerConfig, PeerRoute, ServletEntry};
	///
	/// let socket: SocketAddr = "192.0.2.7:9000".parse()?;
	/// let dial = PeerConfig::default().admit_dial(socket)?;
	/// let route = PeerRoute { peer_id: Arc::from(&b"peer"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
	/// let entry = ServletEntry::peer(route, 100, 3);
	///
	/// let named = entry.dial_target().as_socket().ok_or("a peer route dials a socket")?;
	/// assert_eq!(named.socket(), socket);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn as_socket(&self) -> Option<&PeerAddress> {
		match &self.0 {
			Endpoint::Socket { address, .. } => Some(address),
			Endpoint::Named(_) => None,
		}
	}

	/// Returns the bytes a caller gossips or displays this target by.
	///
	/// The target derives them from its endpoint where it is built, so they
	/// agree with the endpoint. A socket renders through
	/// [`PeerAddress::route_bytes`], and a name renders as the hive wrote it.
	///
	/// # Examples
	///
	/// ```
	/// use core::net::SocketAddr;
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::{PeerConfig, PeerRoute, ServletEntry};
	///
	/// let socket: SocketAddr = "[2001:db8::7]:9000".parse()?;
	/// let dial = PeerConfig::default().admit_dial(socket)?;
	/// let route = PeerRoute { peer_id: Arc::from(&b"peer"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
	/// let entry = ServletEntry::peer(route, 100, 3);
	///
	/// assert_eq!(entry.dial_target().as_bytes(), b"[2001:db8::7]:9000");
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	#[must_use]
	pub fn as_bytes(&self) -> &[u8] {
		self.rendering()
	}

	/// Returns the rendering as the shared bytes a route record holds.
	fn rendering(&self) -> &SharedId {
		match &self.0 {
			Endpoint::Socket { rendering, .. } => rendering,
			Endpoint::Named(name) => name,
		}
	}

	/// Returns this target as the address type of the protocol that dials it.
	///
	/// This is the one place a dial becomes a protocol address:
	///
	/// - The protocol's [`FromStr`] is its only constructor, so this method
	///   parses the rendering once per dial, from the same bytes every other
	///   reader of this target sees.
	/// - A protocol may address by something other than a socket, as the laser
	///   test protocol does by airspace slot, and then a socket target does
	///   not parse.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the rendering is not UTF-8, or the
	///   protocol does not address by it.
	///
	/// # Examples
	///
	/// ```
	/// use core::net::SocketAddr;
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::cluster::{PeerConfig, PeerRoute, ServletEntry};
	///
	/// let socket: SocketAddr = "192.0.2.7:9000".parse()?;
	/// let dial = PeerConfig::default().admit_dial(socket)?;
	/// let route = PeerRoute { peer_id: Arc::from(&b"peer"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
	/// let entry = ServletEntry::peer(route, 100, 3);
	///
	/// let address: SocketAddr = entry.dial_target().protocol_address()?;
	/// assert_eq!(address, socket);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn protocol_address<A: FromStr>(&self) -> Result<A, ClusterError> {
		let rendered = self.as_bytes();
		let text = from_utf8(rendered).map_err(|_| ClusterError::InvalidAddress(rendered.to_vec()))?;
		text.parse().map_err(|_| ClusterError::InvalidAddress(rendered.to_vec()))
	}

	/// Whether a connect to `other` reaches the endpoint this target names.
	///
	/// Equal targets do. So do two sockets on one port when either address
	/// is unspecified, because a listener on the wildcard answers a connect
	/// to any of the host's addresses on that port.
	pub(super) fn same_endpoint(&self, other: &Self) -> bool {
		let wildcard_on_one_port = match (self.as_socket(), other.as_socket()) {
			(Some(this), Some(that)) => {
				let either_unspecified = this.is_unspecified() || that.is_unspecified();
				either_unspecified && this.socket().port() == that.socket().port()
			}
			_ => false,
		};

		self == other || wildcard_on_one_port
	}
}

/// How the load balancer reaches an entry.
///
/// All kinds share the same pheromone score tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
	/// The route resolves to a servlet this gateway owns.
	#[default]
	Local,
	/// The route resolves to a peer gateway that owns the servlet, and one
	/// forward reaches it.
	Peer,
	/// The route resolves to a relay peer gateway that must forward once more
	/// to reach the owner, so selection requires a relay budget of at least
	/// two.
	PeerRelay,
}

impl RouteKind {
	/// Whether the request leaves this gateway for a peer gateway.
	#[must_use]
	pub fn is_peer(self) -> bool {
		matches!(self, Self::Peer | Self::PeerRelay)
	}
}

/// The plane a route dials on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoutePlane {
	/// The hive plane, for a servlet of this gateway's own hives.
	Hive {
		/// The signer that names the certificate the servlet must answer
		/// under, from the hive's registration.
		signer: Arc<SignerIdentifier>,
	},
	/// The peer plane, for a route that leaves through a peer gateway.
	Peer {
		/// The slate key of the gateway the route dials.
		gateway_id: SharedId,
	},
}

/// A servlet instance, tracked with its pheromone score and trial count.
///
/// The fields are private, so the route-key discipline holds by
/// construction:
///
/// - A local entry, which a hive's registration builds, keys by the servlet address it dials.
/// - [`ServletEntry::peer`] keys by `peer_id NUL servlet_type`.
/// - [`ServletEntry::peer_relay`] keys by `origin NUL relay NUL type`.
#[derive(Debug)]
pub struct ServletEntry {
	/// The registry map key, which is also the pheromone trail identity.
	route_key: SharedId,
	servlet_type: SharedId,
	/// The reconcile bucket, which is the hive-index key one slate replaces
	/// atomically. Local entries bucket by hive, peer entries by origin, and
	/// relay entries by the composite `origin NUL relay`.
	bucket: SharedId,
	/// The identity that owns the route: the local hive address, or the
	/// certificate fingerprint of the origin gateway that advertised the
	/// type.
	owner_id: SharedId,
	/// The certificate fingerprint of the relay gateway this entry dials,
	/// when the route is a relay trail.
	relay_id: Option<SharedId>,
	/// The endpoint that a forward dials. A local entry dials the endpoint
	/// its `route_key` names, in canonical form.
	dial: DialTarget,
	/// The plane the entry dials on, and the party that must answer there:
	/// the signer a local entry's servlet answers under, or the gateway a
	/// peer-routed entry dials.
	plane: RoutePlane,
	route_kind: RouteKind,
	pheromone: AtomicU64,
	trial_count: AtomicU32,
	abandonment_limit: u32,
}

/// The identity a route belongs to, on the plane that identity lives on.
///
/// A hive control address and a peer certificate fingerprint are different
/// owners even when their bytes agree, so the plane travels with the bytes
/// and two owners are the same only when both agree (CWE-639).
#[derive(Debug, Clone, Copy)]
pub(super) struct Owner<'a> {
	id: &'a [u8],
	kind: RouteKind,
}

impl<'a> Owner<'a> {
	/// Returns the hive at `id`, the owner of the local routes it registered.
	pub(super) fn hive(id: &'a [u8]) -> Self {
		Self { id, kind: RouteKind::Local }
	}

	/// Returns the peer gateway whose certificate fingerprint is `id`.
	pub(super) fn peer(id: &'a [u8]) -> Self {
		Self { id, kind: RouteKind::Peer }
	}

	/// Whether `other` names this owner.
	pub(super) fn same(self, other: Owner<'_>) -> bool {
		self.id == other.id && self.kind.is_peer() == other.kind.is_peer()
	}

	/// Whether this owner lives on the peer plane.
	pub(super) fn is_peer(self) -> bool {
		self.kind.is_peer()
	}
}

/// The operator view of one learned peer route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouteInfo {
	/// The registry key, which is also the pheromone trail identity.
	pub route_key: SharedId,
	/// The canonical bytes of the servlet type this route answers.
	pub servlet_type: SharedId,
	/// The gateway socket this route dials, in its canonical spelling: the
	/// origin's for a direct route and the relay's for a relay trail.
	pub dial_addr: SharedId,
	/// The certificate fingerprint of the peer that advertised the type.
	pub peer_id: SharedId,
}

/// The identity fields one peer-routed constructor hands to
/// [`ServletEntry::peer_kind`].
struct PeerIdentity {
	bucket: SharedId,
	owner_id: SharedId,
	relay_id: Option<SharedId>,
	route_kind: RouteKind,
}

/// The four identities a local route names.
///
/// The fields are named rather than positional because three are
/// [`SharedId`]. A caller that transposed a pair would install a route that
/// dials the wrong place, and no check would refuse it.
///
/// The type is crate-private, so a local route comes from a hive's
/// registration alone, after its signature check.
#[derive(Debug, Clone)]
pub(crate) struct LocalRoute {
	/// The address that reaches the servlet instance.
	pub address: SharedId,
	/// The bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// The hive that owns the instance.
	pub hive_id: SharedId,
	/// The signer that names the certificate the servlet answers under, from
	/// its hive's registration (RFC 5652 §5.3).
	pub signer: SignerIdentifier,
}

/// The three identities a peer route names.
///
/// The fields are named rather than positional because two are
/// [`SharedId`], and a transposed pair would install a route under the wrong
/// peer. The dial is an [`AdmittedDial`], so a peer route exists only for a
/// gateway socket the dial policy admitted (CWE-918).
#[derive(Debug, Clone)]
pub struct PeerRoute {
	/// The peer gateway that advertised the type.
	pub peer_id: SharedId,
	/// The bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// The admitted gateway socket every entry in the slate dials.
	pub dial: AdmittedDial,
}

/// The four identities a relay trail names.
///
/// The fields are named for the same reason as those of [`PeerRoute`], and
/// the dial is admitted for the same reason as that of [`PeerRoute`].
#[derive(Debug, Clone)]
pub struct RelayRoute {
	/// The peer whose type this trail reaches.
	pub origin_id: SharedId,
	/// The peer that forwards the traffic.
	pub relay_id: SharedId,
	/// The bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// The admitted gateway socket at which the trail dials the relay.
	pub dial: AdmittedDial,
}

impl ServletEntry {
	/// Creates the entry of a local servlet reachable at `address`, owned by
	/// `hive_id`, which answers under `signer`.
	///
	/// - This parses the address once, so the entry carries a typed dial target from the moment it exists.
	/// - A dial of the entry admits only the certificate `signer` names, so a
	///   party that answers at the address under another identity receives no
	///   frame (CWE-346).
	pub(crate) fn local(route: LocalRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let LocalRoute { address, servlet_type, hive_id, signer } = route;
		let dial = DialTarget::of_registered(&address);

		Self {
			route_key: address,
			servlet_type,
			bucket: Arc::clone(&hive_id),
			owner_id: hive_id,
			relay_id: None,
			dial,
			plane: RoutePlane::Hive { signer: Arc::new(signer) },
			route_kind: RouteKind::Local,
			pheromone: AtomicU64::new(initial_pheromone),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
		}
	}

	/// Creates a peer route whose key is `peer_id NUL servlet_type`.
	pub fn peer(route: PeerRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let target = DialTarget::of_claimed(route.dial);
		Self::peer_sharing(route, &target, initial_pheromone, abandonment_limit)
	}

	/// Creates the route of [`Self::peer`] for an entry of a slate whose
	/// entries share `target`, the one rendering of the socket they dial.
	pub(crate) fn peer_sharing(
		route: PeerRoute,
		target: &DialTarget,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let PeerRoute { peer_id, servlet_type, dial } = route;
		let identity = PeerIdentity {
			bucket: Arc::clone(&peer_id),
			owner_id: peer_id,
			relay_id: None,
			route_kind: RouteKind::Peer,
		};

		let dial = target.sharing(dial);
		Self::peer_kind(identity, servlet_type, dial, initial_pheromone, abandonment_limit)
	}

	/// Creates a relay trail for `origin_id`'s type. The trail dials the
	/// relay gateway `relay_id` instead of the origin.
	///
	/// The entry buckets under the composite [`Self::relay_bucket`], so the
	/// key is `origin NUL relay NUL servlet_type`. Three rules follow:
	///
	/// - The key is distinct from the direct `origin NUL servlet_type` trail, so the two score independently.
	/// - The trail reconciles under its own bucket, so a replacement of the
	///   origin's direct slate leaves the fallback in place. A withdrawn,
	///   empty direct slate removes it with the direct routes.
	/// - A forward through this trail spends a hop at the relay, so selection
	///   requires a budget that lets the relay forward once more.
	pub fn peer_relay(route: RelayRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let target = DialTarget::of_claimed(route.dial);
		Self::peer_relay_sharing(route, &target, initial_pheromone, abandonment_limit)
	}

	/// Creates the trail of [`Self::peer_relay`] for an entry of a trail whose
	/// entries share `target`, the one rendering of the relay socket they dial.
	pub(crate) fn peer_relay_sharing(
		route: RelayRoute,
		target: &DialTarget,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let RelayRoute { origin_id, relay_id, servlet_type, dial } = route;
		let identity = PeerIdentity {
			bucket: Self::relay_bucket(&origin_id, &relay_id),
			owner_id: origin_id,
			relay_id: Some(relay_id),
			route_kind: RouteKind::PeerRelay,
		};

		let dial = target.sharing(dial);
		Self::peer_kind(identity, servlet_type, dial, initial_pheromone, abandonment_limit)
	}

	/// Builds the composite `origin NUL relay` reconcile bucket for relay
	/// trails.
	///
	/// Entry keys and slate reconciliation share this one construction, so
	/// the two always agree on the bucket.
	#[must_use]
	pub fn relay_bucket(origin_id: impl AsRef<[u8]>, relay_id: impl AsRef<[u8]>) -> SharedId {
		let origin_id = origin_id.as_ref();
		let relay_id = relay_id.as_ref();
		let bucket = origin_id.iter().chain(&[0]).chain(relay_id);

		bucket.copied().collect()
	}

	/// Builds a peer-routed entry. Both peer-routed kinds key as
	/// `bucket NUL type`.
	fn peer_kind(
		identity: PeerIdentity,
		servlet_type: SharedId,
		dial: DialTarget,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let PeerIdentity { bucket, owner_id, relay_id, route_kind } = identity;
		let route_parts = bucket.iter().chain(&[0]).chain(servlet_type.iter());
		let route_key: SharedId = route_parts.copied().collect();

		// A relay trail dials its relay, and a direct route dials the origin
		// that advertised the type.
		let gateway_id = relay_id.as_ref().unwrap_or(&owner_id);
		let plane = RoutePlane::Peer { gateway_id: Arc::clone(gateway_id) };

		Self {
			route_key,
			servlet_type,
			bucket,
			owner_id,
			relay_id,
			dial,
			plane,
			route_kind,
			pheromone: AtomicU64::new(initial_pheromone),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
		}
	}

	/// Returns the registry map key, which is also the pheromone trail
	/// identity.
	#[must_use]
	pub fn route_key(&self) -> &SharedId {
		&self.route_key
	}

	/// Returns the endpoint that a forward through this entry dials.
	#[must_use]
	pub fn dial_target(&self) -> &DialTarget {
		&self.dial
	}

	/// Returns the identity that owns the route: the local hive address, or
	/// the certificate fingerprint of the origin gateway that advertised the
	/// type.
	#[must_use]
	pub fn owner_id(&self) -> &SharedId {
		&self.owner_id
	}

	/// Returns the reconcile bucket this entry lives under in the hive index.
	#[must_use]
	pub fn bucket(&self) -> &SharedId {
		&self.bucket
	}

	/// Returns the identity this route belongs to, on its plane.
	pub(super) fn owner(&self) -> Owner<'_> {
		Owner { id: &self.owner_id, kind: self.route_kind }
	}

	/// Returns the certificate fingerprint of the relay gateway this entry
	/// dials. It is `None` for local and direct peer routes.
	#[must_use]
	pub fn relay_id(&self) -> Option<&SharedId> {
		self.relay_id.as_ref()
	}

	/// Returns the plane this entry dials on, and the party that must answer:
	/// the signer the servlet's registration names for a local route, the
	/// gateway that advertised the type for a direct route, and the relay for a
	/// relay trail.
	pub(crate) fn plane(&self) -> RoutePlane {
		self.plane.clone()
	}

	/// Returns the servlet type's key bytes, which the type index looks up.
	#[must_use]
	pub fn servlet_type(&self) -> &SharedId {
		&self.servlet_type
	}

	/// Returns the kind of this route: local, direct peer, or peer relay.
	#[must_use]
	pub fn route_kind(&self) -> RouteKind {
		self.route_kind
	}

	/// Whether this entry is a peer route that dials `gateway`, either a
	/// direct route to it or a relay trail through it.
	pub(super) fn is_peer_route_to(&self, gateway: PeerAddress) -> bool {
		self.route_kind.is_peer() && self.dial.as_socket() == Some(&gateway)
	}

	/// Returns the count of consecutive failures toward abandonment.
	#[must_use]
	pub fn trial_count(&self) -> u32 {
		self.trial_count.load(Ordering::Relaxed)
	}

	/// Returns the operator view of the peer route fields, when this entry is
	/// peer-routed.
	///
	/// [`PeerRouteInfo::peer_id`] is the origin that advertised the type, for
	/// relay trails too. The relay hop stays on [`ServletEntry::relay_id`].
	#[must_use]
	pub fn peer_route_info(&self) -> Option<PeerRouteInfo> {
		match self.route_kind {
			RouteKind::Local => None,
			RouteKind::Peer | RouteKind::PeerRelay => Some(PeerRouteInfo {
				route_key: Arc::clone(&self.route_key),
				servlet_type: Arc::clone(&self.servlet_type),
				dial_addr: Arc::clone(self.dial.rendering()),
				peer_id: Arc::clone(&self.owner_id),
			}),
		}
	}

	/// Whether consecutive failures reached the abandonment limit.
	#[must_use]
	pub fn is_abandoned(&self) -> bool {
		self.trial_count.load(Ordering::Relaxed) >= self.abandonment_limit
	}

	/// Whether the entry remains selectable for routing.
	#[must_use]
	pub fn is_live(&self) -> bool {
		!self.is_abandoned()
	}

	/// Returns the current pheromone level that weighted selection reads.
	#[must_use]
	pub fn pheromone_level(&self) -> u64 {
		self.pheromone.load(Ordering::Relaxed)
	}

	/// Raises the pheromone after a successful request and clears the
	/// failure streak.
	///
	/// One atomic read-modify-write applies the reinforcement, so it survives
	/// a concurrent evaporation.
	pub fn reinforce(&self, quality: u64) {
		self.update_pheromone(|current| current.saturating_add(quality).min(MAX_PHEROMONE));
		self.trial_count.store(0, Ordering::Relaxed);
	}

	/// Counts one failure toward abandonment.
	pub fn weaken(&self) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
	}

	/// Counts one failure toward abandonment, and reports whether this
	/// failure reached the abandonment limit.
	///
	/// The count rises in one atomic step, so of concurrent failures exactly
	/// one reports that it reached the limit.
	pub(super) fn weaken_to_limit(&self) -> bool {
		let before = self.trial_count.fetch_add(1, Ordering::Relaxed);
		before.saturating_add(1) == self.abandonment_limit
	}

	/// Counts one failure and subtracts `penalty` from the pheromone when the
	/// penalty is nonzero.
	pub fn weaken_with_penalty(&self, penalty: u64) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
		if penalty > 0 {
			self.update_pheromone(|current| current.saturating_sub(penalty));
		}
	}

	/// Decays the pheromone by `rate` basis points.
	pub fn evaporate(&self, rate: BasisPoints) {
		self.update_pheromone(|current| {
			let decay = current.saturating_mul(rate.get() as u64) / 10000;
			current.saturating_sub(decay)
		});
	}

	/// Applies `step` to the pheromone level in one atomic read-modify-write.
	///
	/// A concurrent write fails the exchange and hands back the level it
	/// wrote, so the loop applies `step` again to that level, and each update
	/// lands on the level before it.
	fn update_pheromone(&self, step: impl Fn(u64) -> u64) {
		let pheromone = &self.pheromone;
		let mut current = pheromone.load(Ordering::Relaxed);
		loop {
			let next = step(current);
			match pheromone.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
				Ok(_) => return,
				Err(written) => current = written,
			}
		}
	}

	/// Carries the pheromone and trial state of `prev` across a replacement
	/// when both `prev` and this route are peer-routed.
	///
	/// The install instant stays with the registry's map value, so a
	/// replacement ages from the reconcile that placed it.
	pub fn preserve_peer_trail_from(&mut self, prev: &Self) {
		let both_peer = self.route_kind.is_peer() && prev.route_kind.is_peer();
		if !both_peer {
			return;
		}

		self.pheromone = AtomicU64::new(prev.pheromone.load(Ordering::Relaxed));
		self.trial_count = AtomicU32::new(prev.trial_count.load(Ordering::Relaxed));
	}
}

impl Clone for ServletEntry {
	fn clone(&self) -> Self {
		Self {
			route_key: Arc::clone(&self.route_key),
			servlet_type: Arc::clone(&self.servlet_type),
			bucket: Arc::clone(&self.bucket),
			owner_id: Arc::clone(&self.owner_id),
			relay_id: self.relay_id.as_ref().map(Arc::clone),
			dial: self.dial.clone(),
			plane: self.plane.clone(),
			route_kind: self.route_kind,
			pheromone: AtomicU64::new(self.pheromone.load(Ordering::Relaxed)),
			trial_count: AtomicU32::new(self.trial_count.load(Ordering::Relaxed)),
			abandonment_limit: self.abandonment_limit,
		}
	}
}

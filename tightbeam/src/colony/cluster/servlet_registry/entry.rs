use core::str::{from_utf8, FromStr};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use crate::colony::cluster::{AdmittedDial, ClusterError, NotASocket, PeerAddress, SharedId};
use crate::colony::common::MAX_PHEROMONE;
use crate::utils::BasisPoints;

/// The endpoint a route dials, parsed once where the route is built.
///
/// Two targets are equal when they name one endpoint, so two spellings of
/// one socket compare equal wherever routes are compared (CWE-706). The
/// rendering a dial or a gossip entry carries is derived from the endpoint
/// on demand, so no second field can disagree with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialTarget {
	/// A socket, claimed by a peer gateway or registered by a hive.
	Socket(PeerAddress),
	/// A servlet or control address a hive registered that names no socket,
	/// such as an address of a protocol with its own address scheme. It
	/// compares by its bytes.
	Named(SharedId),
}

impl DialTarget {
	/// An address a hive registered, for one of its servlets or for its own
	/// control plane.
	///
	/// An address that spells a socket is stored as that socket, so it
	/// compares with a claimed peer socket. Any other address is a name the
	/// dialing protocol resolves, kept as the hive wrote it.
	pub(in crate::colony::cluster) fn of_registered(address: &SharedId) -> Self {
		match PeerAddress::try_from(address.as_ref()) {
			Ok(socket) => Self::Socket(socket),
			Err(NotASocket) => Self::Named(Arc::clone(address)),
		}
	}

	/// The bytes a caller gossips or displays this target by.
	///
	/// A socket renders through [`PeerAddress::route_bytes`], the one home
	/// for the spelling, and a name renders as the hive wrote it.
	#[must_use]
	pub fn route_bytes(&self) -> SharedId {
		match self {
			Self::Socket(socket) => socket.route_bytes(),
			Self::Named(name) => Arc::clone(name),
		}
	}

	/// This target as the dialing protocol's address type.
	///
	/// This is the one place a dial becomes a protocol address:
	///
	/// - The protocol's [`FromStr`] is its only constructor, so the rendering is parsed here, once
	///   per dial, from the same bytes every other reader of this target sees.
	/// - A protocol may address by something other than a socket, as the laser test protocol does
	///   by airspace slot, and then a socket target does not parse.
	///
	/// # Errors
	///
	/// - [`ClusterError::InvalidAddress`] -- the protocol does not address by this rendering.
	pub fn protocol_address<A: FromStr>(&self) -> Result<A, ClusterError> {
		let rendered = self.route_bytes();
		let text = from_utf8(&rendered).map_err(|_| ClusterError::InvalidAddress(rendered.to_vec()))?;
		text.parse().map_err(|_| ClusterError::InvalidAddress(rendered.to_vec()))
	}

	/// Whether a connect to `other` reaches the endpoint this target names.
	///
	/// Equal targets do. So do two sockets on one port when either address
	/// is unspecified, because a listener on the wildcard answers a connect
	/// to any of the host's addresses on that port.
	pub(super) fn same_endpoint(&self, other: &Self) -> bool {
		let wildcard_on_one_port = match (self, other) {
			(Self::Socket(this), Self::Socket(that)) => {
				let either_unspecified = this.is_unspecified() || that.is_unspecified();
				either_unspecified && this.socket().port() == that.socket().port()
			}
			_ => false,
		};

		self == other || wildcard_on_one_port
	}

	/// The socket this target names, when it names one.
	#[must_use]
	pub fn socket(&self) -> Option<PeerAddress> {
		match self {
			Self::Socket(socket) => Some(*socket),
			Self::Named(_) => None,
		}
	}
}

impl From<AdmittedDial> for DialTarget {
	fn from(dial: AdmittedDial) -> Self {
		Self::Socket(dial.address())
	}
}

/// How the load balancer reaches an entry.
///
/// All kinds share the same pheromone scoring tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteKind {
	/// The route resolves to a servlet this gateway owns.
	#[default]
	Local,
	/// The route resolves to a peer gateway that owns the servlet, reached
	/// by forwarding.
	Peer,
	/// The route resolves to a relaying peer gateway that must forward once
	/// more to reach the owner, so selection requires a relay budget of at
	/// least two.
	PeerRelay,
}

impl RouteKind {
	/// Whether the request leaves this gateway for a peer gateway.
	#[must_use]
	pub fn is_peer(self) -> bool {
		matches!(self, Self::Peer | Self::PeerRelay)
	}
}

/// A servlet instance tracked with pheromone score and trial count.
///
/// The fields are private, so the route-key discipline holds by
/// construction:
///
/// - [`ServletEntry::local`] keys by the servlet address it dials.
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
	/// The owning identity, which is the local hive address or the
	/// certificate fingerprint of the origin gateway that advertised the
	/// type.
	owner_id: SharedId,
	/// The certificate fingerprint of the relaying gateway this entry dials,
	/// when the route is a relay trail.
	relay_id: Option<SharedId>,
	/// The endpoint dialed when forwarding. A local entry dials the endpoint
	/// its `route_key` names, in canonical form.
	dial: DialTarget,
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
	/// The hive at `id`, owner of the local routes it registered.
	pub(super) fn hive(id: &'a [u8]) -> Self {
		Self { id, kind: RouteKind::Local }
	}

	/// The peer gateway whose certificate fingerprint is `id`.
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

/// Operator view of one learned peer route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouteInfo {
	/// The registry key, which is also the pheromone trail identity.
	pub route_key: SharedId,
	/// Canonical servlet type bytes.
	pub servlet_type: SharedId,
	/// The gateway socket this route dials, in its canonical spelling: the
	/// origin's for a direct route and the relay's for a relay trail.
	pub dial_addr: SharedId,
	/// Advertising peer identity certificate fingerprint.
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

/// The three identities a local route names.
///
/// The fields are named rather than positional because all three are
/// [`SharedId`]. A caller that transposed a pair would install a route that
/// dials the wrong place, and no check would refuse it.
#[derive(Debug, Clone)]
pub struct LocalRoute {
	/// Address the servlet instance is reached at.
	pub address: SharedId,
	/// Bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// Hive that owns the instance.
	pub hive_id: SharedId,
}

/// The three identities a peer route names.
///
/// The fields are named for the same reason as those of [`LocalRoute`].
/// The dial is an [`AdmittedDial`], so a peer route exists only for a
/// gateway socket the dial policy admitted (CWE-918).
#[derive(Debug, Clone)]
pub struct PeerRoute {
	/// Peer gateway that advertised the type.
	pub peer_id: SharedId,
	/// Bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// Admitted gateway socket every entry in the slate dials.
	pub dial: AdmittedDial,
}

/// The four identities a relay trail names.
///
/// The fields are named for the same reason as those of [`LocalRoute`], and
/// the dial is admitted for the same reason as that of [`PeerRoute`].
#[derive(Debug, Clone)]
pub struct RelayRoute {
	/// Peer whose type this trail reaches.
	pub origin_id: SharedId,
	/// Peer the traffic is forwarded through.
	pub relay_id: SharedId,
	/// Bare servlet type this route answers.
	pub servlet_type: SharedId,
	/// Admitted gateway socket the relay is dialed at.
	pub dial: AdmittedDial,
}

impl ServletEntry {
	/// Creates a local servlet reachable at `address`, owned by `hive_id`.
	///
	/// The address is parsed here, once, so the entry carries a typed dial
	/// target from the moment it exists.
	pub fn local(route: LocalRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let LocalRoute { address, servlet_type, hive_id } = route;
		let dial = DialTarget::of_registered(&address);

		Self {
			route_key: address,
			servlet_type,
			bucket: Arc::clone(&hive_id),
			owner_id: hive_id,
			relay_id: None,
			dial,
			route_kind: RouteKind::Local,
			pheromone: AtomicU64::new(initial_pheromone),
			trial_count: AtomicU32::new(0),
			abandonment_limit,
		}
	}

	/// Creates a peer route whose key is `peer_id NUL servlet_type`.
	pub fn peer(route: PeerRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let PeerRoute { peer_id, servlet_type, dial } = route;
		let identity = PeerIdentity {
			bucket: Arc::clone(&peer_id),
			owner_id: peer_id,
			relay_id: None,
			route_kind: RouteKind::Peer,
		};

		Self::peer_kind(identity, servlet_type, dial, initial_pheromone, abandonment_limit)
	}

	/// Creates a relay trail for `origin_id`'s type, dialing the
	/// relaying gateway `relay_id` instead of the origin.
	///
	/// The entry buckets under the composite [`Self::relay_bucket`], so the
	/// key is `origin NUL relay NUL servlet_type`. Three rules follow:
	///
	/// - The key is distinct from the direct `origin NUL servlet_type` trail,
	///   so the two score independently.
	/// - The trail reconciles under its own bucket, so a replacement of the
	///   origin's direct slate leaves the fallback in place. A withdrawn,
	///   empty direct slate removes it with the direct routes.
	/// - Forwarding through this trail spends a hop at the relay, so selection
	///   requires a budget that lets the relay forward once more.
	pub fn peer_relay(route: RelayRoute, initial_pheromone: u64, abandonment_limit: u32) -> Self {
		let RelayRoute { origin_id, relay_id, servlet_type, dial } = route;
		let identity = PeerIdentity {
			bucket: Self::relay_bucket(&origin_id, &relay_id),
			owner_id: origin_id,
			relay_id: Some(relay_id),
			route_kind: RouteKind::PeerRelay,
		};

		Self::peer_kind(identity, servlet_type, dial, initial_pheromone, abandonment_limit)
	}

	/// Builds the composite `origin NUL relay` reconcile bucket for relay
	/// trails.
	///
	/// Entry keys and slate reconciliation share this one construction, so
	/// the two cannot drift apart.
	#[must_use]
	pub fn relay_bucket(origin_id: impl AsRef<[u8]>, relay_id: impl AsRef<[u8]>) -> SharedId {
		let origin_id = origin_id.as_ref();
		let relay_id = relay_id.as_ref();
		let mut bucket = Vec::with_capacity(origin_id.len() + 1 + relay_id.len());
		bucket.extend_from_slice(origin_id);
		bucket.push(0);
		bucket.extend_from_slice(relay_id);

		Arc::from(bucket.as_slice())
	}

	/// Builds a peer-routed entry. Both peer-routed kinds key as
	/// `bucket NUL type`.
	fn peer_kind(
		identity: PeerIdentity,
		servlet_type: SharedId,
		dial: AdmittedDial,
		initial_pheromone: u64,
		abandonment_limit: u32,
	) -> Self {
		let PeerIdentity { bucket, owner_id, relay_id, route_kind } = identity;
		let mut route_key = Vec::with_capacity(bucket.len() + 1 + servlet_type.len());
		route_key.extend_from_slice(&bucket);
		route_key.push(0);
		route_key.extend_from_slice(&servlet_type);

		Self {
			route_key: Arc::from(route_key.as_slice()),
			servlet_type,
			bucket,
			owner_id,
			relay_id,
			dial: DialTarget::from(dial),
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

	/// The endpoint dialed when forwarding through this entry.
	#[must_use]
	pub fn dial_target(&self) -> &DialTarget {
		&self.dial
	}

	/// Returns the owning identity, which is the local hive address or the
	/// certificate fingerprint of the origin gateway that advertised the
	/// type.
	#[must_use]
	pub fn owner_id(&self) -> &SharedId {
		&self.owner_id
	}

	/// Reconcile bucket this entry lives under in the hive index.
	#[must_use]
	pub fn bucket(&self) -> &SharedId {
		&self.bucket
	}

	/// The identity this route belongs to, on its plane.
	pub(super) fn owner(&self) -> Owner<'_> {
		Owner { id: &self.owner_id, kind: self.route_kind }
	}

	/// Returns the certificate fingerprint of the relaying gateway this entry
	/// dials. It is `None` for local and direct peer routes.
	#[must_use]
	pub fn relay_id(&self) -> Option<&SharedId> {
		self.relay_id.as_ref()
	}

	/// Servlet type key bytes used for type-index lookup.
	#[must_use]
	pub fn servlet_type(&self) -> &SharedId {
		&self.servlet_type
	}

	/// Whether this entry is local or peer-routed.
	#[must_use]
	pub fn route_kind(&self) -> RouteKind {
		self.route_kind
	}

	/// Consecutive failures accumulated toward abandonment.
	#[must_use]
	pub fn trial_count(&self) -> u32 {
		self.trial_count.load(Ordering::Relaxed)
	}

	/// Operator view of peer route fields, when this entry is peer-routed.
	///
	/// `peer_id` is the advertising origin for relay trails too. The
	/// relay hop stays on [`ServletEntry::relay_id`].
	#[must_use]
	pub fn peer_route_info(&self) -> Option<PeerRouteInfo> {
		match self.route_kind {
			RouteKind::Local => None,
			RouteKind::Peer | RouteKind::PeerRelay => Some(PeerRouteInfo {
				route_key: Arc::clone(&self.route_key),
				servlet_type: Arc::clone(&self.servlet_type),
				dial_addr: self.dial.route_bytes(),
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

	/// Current pheromone level used by weighted selection.
	#[must_use]
	pub fn pheromone_level(&self) -> u64 {
		self.pheromone.load(Ordering::Relaxed)
	}

	/// Raises the pheromone after a successful request and clears the
	/// failure streak.
	///
	/// One `fetch_update` keeps concurrent evaporation from discarding the
	/// reinforcement.
	pub fn reinforce(&self, quality: u64) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			Some(current.saturating_add(quality).min(MAX_PHEROMONE))
		});
		self.trial_count.store(0, Ordering::Relaxed);
	}

	/// Counts one failure toward abandonment.
	pub fn weaken(&self) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
	}

	/// Counts one failure and subtracts `penalty` from the pheromone when the
	/// penalty is nonzero.
	pub fn weaken_with_penalty(&self, penalty: u64) {
		self.trial_count.fetch_add(1, Ordering::Relaxed);
		if penalty > 0 {
			let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
				Some(current.saturating_sub(penalty))
			});
		}
	}

	/// Decays the pheromone by `rate` basis points.
	pub fn evaporate(&self, rate: BasisPoints) {
		let _ = self.pheromone.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
			let decay = current.saturating_mul(rate.get() as u64) / 10000;
			Some(current.saturating_sub(decay))
		});
	}

	/// Carries pheromone and trial state across a replacement when both the
	/// old and the new route are peer-routed.
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
			route_kind: self.route_kind,
			pheromone: AtomicU64::new(self.pheromone.load(Ordering::Relaxed)),
			trial_count: AtomicU32::new(self.trial_count.load(Ordering::Relaxed)),
			abandonment_limit: self.abandonment_limit,
		}
	}
}

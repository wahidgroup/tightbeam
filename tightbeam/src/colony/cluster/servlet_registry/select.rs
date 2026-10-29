use core::num::NonZeroUsize;
use core::time::Duration;
use std::sync::Arc;

use super::{ClusterError, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry, SharedId};
use crate::colony::cluster::PeerAddress;
use crate::colony::urn::ServletTypeKey;

impl ServletRegistry {
	/// Returns the live routes for a servlet type as shared [`Arc`] handles,
	/// so the call copies the handles and shares each entry.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn entries_for_type(&self, servlet_type: &ServletTypeKey) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let servlet_type = servlet_type.as_ref();
		let routes = self.routes.read()?;
		let addresses = routes.addresses_for_type(servlet_type);
		let result = addresses
			.iter()
			.filter_map(|address| routes.get(address.as_ref()).map(Arc::clone))
			.filter(|entry| entry.is_live())
			.collect();

		Ok(result)
	}

	/// Returns the live local routes for a servlet type.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn local_entries_for_type(
		&self,
		servlet_type: &ServletTypeKey,
	) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.entries_for_type(servlet_type)?;
		let local = routes
			.into_iter()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.collect();

		Ok(local)
	}

	/// Returns the distinct live servlet types this gateway owns, sorted.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn local_servlets(&self) -> Result<Vec<SharedId>, ClusterError> {
		let routes = self.routes.read()?;
		let mut types = routes
			.values()
			.filter(|entry| entry.route_kind() == RouteKind::Local)
			.filter(|entry| entry.is_live())
			.map(|entry| Arc::clone(entry.servlet_type()))
			.collect::<Vec<_>>();

		types.sort_unstable();
		types.dedup();

		Ok(types)
	}

	/// Returns the live routes reached through peer gateways, relay trails
	/// included.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn peer_entries(&self) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let routes = self.routes.read()?;
		let result = routes
			.values()
			.filter(|entry| entry.route_kind().is_peer())
			.filter(|entry| entry.is_live())
			.map(Arc::clone)
			.collect();

		Ok(result)
	}

	/// Reinforces the pheromone of the servlet at `address` after a success,
	/// and reports whether a route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn reinforce(&self, address: impl AsRef<[u8]>, quality: u64) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.reinforce(quality);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Counts one failure for the servlet at `address`, and reports whether a
	/// route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken(&self, address: impl AsRef<[u8]>) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.weaken();
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Counts one failure and applies a pheromone penalty to the servlet at
	/// `address`, and reports whether a route sits at `address`.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn weaken_with_penalty(&self, address: impl AsRef<[u8]>, penalty: u64) -> Result<bool, ClusterError> {
		let address = address.as_ref();
		let routes = self.routes.read()?;
		let result = if let Some(entry) = routes.get(address) {
			entry.weaken_with_penalty(penalty);
			true
		} else {
			false
		};

		Ok(result)
	}

	/// Weakens every live route attributed to a peer identity, and returns
	/// what the weakening did: how many routes it weakened, and how many of
	/// them it drove to their abandonment limit.
	///
	/// A route is attributed to the peer when it is one of these:
	///
	/// - A direct route the peer advertised.
	/// - A relay trail learned for the peer.
	/// - A relay trail that forwards through the peer.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::clock::SystemClock;
	/// use tightbeam::colony::cluster::{PheromoneConfig, ServletRegistry};
	///
	/// let registry = ServletRegistry::new(PheromoneConfig::default(), Arc::new(SystemClock));
	/// let weakened = registry.weaken_peer(b"peer-fingerprint")?;
	///
	/// assert_eq!(weakened.count(), 0);
	/// # Ok::<(), tightbeam::colony::cluster::ClusterError>(())
	/// ```
	pub fn weaken_peer(&self, peer_id: impl AsRef<[u8]>) -> Result<Weakened, ClusterError> {
		let peer_id = peer_id.as_ref();
		let attributed = |entry: &ServletEntry| {
			entry.owner_id().as_ref() == peer_id || entry.relay_id().is_some_and(|relay| relay.as_ref() == peer_id)
		};

		let routes = self.routes.read()?;
		let live = routes
			.values()
			.filter(|entry| entry.route_kind().is_peer())
			.filter(|entry| entry.is_live())
			.filter(|entry| attributed(entry));

		Ok(Weakened::all(live))
	}

	/// Weakens every live peer route that dials `gateway`, relay trails
	/// included, and returns what the weakening did. Misbehavior at one
	/// gateway therefore weakens every trail through it.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::clock::SystemClock;
	/// use tightbeam::colony::cluster::{PeerAddress, PheromoneConfig, ServletRegistry};
	///
	/// let registry = ServletRegistry::new(PheromoneConfig::default(), Arc::new(SystemClock));
	/// let gateway = PeerAddress::from("127.0.0.1:9000".parse::<std::net::SocketAddr>()?);
	/// let weakened = registry.weaken_peer_by_dial(gateway)?;
	///
	/// assert!(weakened.abandoned().is_none());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn weaken_peer_by_dial(&self, gateway: impl Into<PeerAddress>) -> Result<Weakened, ClusterError> {
		let gateway: PeerAddress = gateway.into();
		let routes = self.routes.read()?;
		let live = routes
			.values()
			.filter(|entry| entry.is_peer_route_to(gateway))
			.filter(|entry| entry.is_live());

		Ok(Weakened::all(live))
	}

	/// Evaporates pheromone on every tracked entry at the configured rate.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn evaporate(&self) -> Result<(), ClusterError> {
		let routes = self.routes.read()?;
		let rate = self.config.evaporation_rate;
		for entry in routes.values() {
			entry.evaporate(rate);
		}

		Ok(())
	}

	/// Drops the relay trails whose last reconcile is older than `max_age`.
	///
	/// A relay trail refreshes only when a relayed advertisement rumor
	/// reconciles its bucket, so a trail past `max_age` lost its refresh
	/// path. An unpicked trail accrues no trials, so age is the lifecycle
	/// bound that retires it (CWE-772).
	///
	/// # Sources
	///
	/// - CWE-772, missing release of resource after effective lifetime:
	///   <https://cwe.mitre.org/data/definitions/772.html>
	pub(in crate::colony::cluster) fn prune_stale_relay_trails(
		&self,
		max_age: Duration,
	) -> Result<Option<NonZeroUsize>, ClusterError> {
		let now = self.clock.monotonic();
		let pruned = self.routes.write()?.prune_stale_relay_trails(now, max_age);
		Ok(NonZeroUsize::new(pruned))
	}

	/// Drops every entry that reached its abandonment limit and returns the
	/// count of peer routes among the dropped entries, or [`None`] when it
	/// drops none.
	///
	/// A local route at its limit leaves too. The count names the peer routes
	/// alone, because it is the count the sweep withdraws from the peer plane.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub(in crate::colony::cluster) fn remove_abandoned(&self) -> Result<Option<NonZeroUsize>, ClusterError> {
		let mut routes = self.routes.write()?;
		let abandoned: Vec<(SharedId, bool)> = routes
			.values()
			.filter(|entry| entry.is_abandoned())
			.map(|entry| (Arc::clone(entry.route_key()), entry.route_kind().is_peer()))
			.collect();

		let peers = abandoned.iter().filter(|(_, is_peer)| *is_peer).count();
		for (address, _) in &abandoned {
			routes.remove(address.as_ref());
		}

		Ok(NonZeroUsize::new(peers))
	}

	/// Returns the configuration of the pheromone scores and the lifecycle.
	pub fn config(&self) -> &PheromoneConfig {
		&self.config
	}

	/// Returns the number of tracked servlet routes.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn len(&self) -> Result<usize, ClusterError> {
		let routes = self.routes.read()?;
		Ok(routes.values().count())
	}

	/// Whether the registry holds no routes.
	///
	/// # Errors
	///
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub fn is_empty(&self) -> Result<bool, ClusterError> {
		let is_empty = self.len()? == 0;
		Ok(is_empty)
	}
}

/// What one weakening of a set of live peer routes did, as the weakenings
/// [`ServletRegistry::weaken_peer`] and
/// [`ServletRegistry::weaken_peer_by_dial`] return it.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use tightbeam::clock::SystemClock;
/// use tightbeam::colony::cluster::{PheromoneConfig, ServletRegistry, Weakened};
///
/// let registry = ServletRegistry::new(PheromoneConfig::default(), Arc::new(SystemClock));
/// let weakened: Weakened = registry.weaken_peer(b"peer-fingerprint")?;
///
/// assert_eq!(weakened, Weakened::default());
/// # Ok::<(), tightbeam::colony::cluster::ClusterError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Weakened {
	/// The count of live routes the weakening reached.
	weakened: usize,
	/// The count of those routes that this weakening drove to their
	/// abandonment limit.
	abandoned: usize,
}

impl Weakened {
	/// Counts one failure against each route of `live`, and records what the
	/// failures did.
	fn all(live: impl IntoIterator<Item = impl AsRef<ServletEntry>>) -> Self {
		live.into_iter().fold(Self::default(), |weakened, entry| {
			let reached_limit = entry.as_ref().weaken_to_limit();
			Self {
				weakened: weakened.weakened.saturating_add(1),
				abandoned: weakened.abandoned.saturating_add(usize::from(reached_limit)),
			}
		})
	}

	/// Returns the count of live routes the weakening reached.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::Weakened;
	///
	/// assert_eq!(Weakened::default().count(), 0);
	/// ```
	#[must_use]
	pub fn count(&self) -> usize {
		self.weakened
	}

	/// Returns the count of routes that this weakening drove to their
	/// abandonment limit, or [`None`] when it drove none there.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::colony::cluster::Weakened;
	///
	/// assert!(Weakened::default().abandoned().is_none());
	/// ```
	#[must_use]
	pub fn abandoned(&self) -> Option<NonZeroUsize> {
		NonZeroUsize::new(self.abandoned)
	}
}

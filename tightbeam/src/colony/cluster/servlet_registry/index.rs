use std::sync::Arc;

use super::entry::Owner;
use super::{Bucket, ClusterError, HiveSlate, KindCaps, PeerCaps, RouteKind, ServletEntry, ServletRegistry};
use crate::colony::cluster::peer::{AdmittedPeerAd, RelayTrail};

impl ServletRegistry {
	/// Adds one servlet entry outside any slate, for tests that seed a
	/// registry directly.
	///
	/// Re-registering an address retires its index rows first. Peer route
	/// replacement preserves its pheromone and trial state.
	#[cfg(test)]
	pub(in crate::colony::cluster) fn add(&self, entry: ServletEntry) -> Result<(), ClusterError> {
		let now = self.clock.monotonic();
		self.routes.write()?.insert(entry, now)
	}

	/// Removes one servlet entry by address, for tests that edit a seeded
	/// registry directly.
	#[cfg(test)]
	pub(in crate::colony::cluster) fn remove(
		&self,
		address: impl AsRef<[u8]>,
	) -> Result<Option<Arc<ServletEntry>>, ClusterError> {
		let address = address.as_ref();
		Ok(self.routes.write()?.remove(address))
	}

	/// Replaces one hive's slate atomically.
	///
	/// The hive's own signed registration gates a local slate, so the slate
	/// skips the order ledger. That ledger belongs to the peer
	/// advertisements, which carry an order.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- another owner holds a key or
	///   socket the slate claims, or a route under the hive's bucket.
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub(in crate::colony::cluster) fn reconcile_by_hive(&self, slate: HiveSlate) -> Result<(), ClusterError> {
		let (hive_id, entries) = slate.into_parts();
		let bucket = Bucket { id: hive_id.as_ref(), owner: Owner::hive(hive_id.as_ref()) };
		let now = self.clock.monotonic();
		self.routes.write()?.reconcile(bucket, entries, now)
	}

	/// Reconciles an admitted peer slate after the stale, cap, and ownership
	/// checks.
	///
	/// - The registry refuses an advertisement older than the newest one
	///   applied for the origin, so a replayed ad inside the freshness window
	///   leaves the fresher slate in place (CWE-294).
	/// - An empty slate clears the origin's relay trails with its direct
	///   routes, because a fallback lasts as long as the claim it was learned
	///   from.
	///
	/// # Errors
	///
	/// - [`ClusterError::StalePeerAd`] -- the advertisement is older than the applied one.
	/// - [`ClusterError::PeerCapExceeded`] -- the slate would pass a direct-route cap.
	/// - [`ClusterError::PeerSlateConflict`] -- another owner holds a key or socket.
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub(in crate::colony::cluster) fn reconcile_peer_slate(
		&self,
		ad: AdmittedPeerAd,
		caps: PeerCaps,
	) -> Result<(), ClusterError> {
		let AdmittedPeerAd { peer_hive_id, slate, order, .. } = ad;
		let bucket = Bucket { id: peer_hive_id.as_ref(), owner: Owner::peer(peer_hive_id.as_ref()) };
		let kind_caps = KindCaps {
			kind: RouteKind::Peer,
			max_identities: caps.max_gateways,
			max_routes: caps.max_routes,
		};

		self.routes
			.write()?
			.admit_peer_ad(bucket, slate, kind_caps, order, self.tombstone(), self.clock.monotonic())
	}

	/// Replaces one relay-trail slate atomically under its own bucket.
	///
	/// The bucket is `origin NUL relay`, so an origin's direct slate and its
	/// relay fallback reconcile independently.
	///
	/// # Bounds
	///
	/// - Relay buckets spend the separate budget in
	///   [`PeerCaps::max_relay_buckets`] and [`PeerCaps::max_relay_routes`],
	///   which bounds what a member relaying many origins can claim and
	///   leaves direct-gateway admission its own headroom (CWE-770).
	/// - The relay dial address comes from this registry's recorded value for
	///   the relay, which the direct reconcile's ownership check has already
	///   gated.
	/// - Each bucket refuses stale advertisements on its own order ledger, as
	///   direct slates do (CWE-294).
	pub(in crate::colony::cluster) fn reconcile_relay_trail(
		&self,
		trail: RelayTrail,
		caps: PeerCaps,
	) -> Result<(), ClusterError> {
		let RelayTrail { bucket, origin, slate, order } = trail;
		let bucket = Bucket { id: bucket.as_ref(), owner: Owner::peer(origin.as_ref()) };
		let kind_caps = KindCaps {
			kind: RouteKind::PeerRelay,
			max_identities: caps.max_relay_buckets,
			max_routes: caps.max_relay_routes,
		};

		self.routes
			.write()?
			.admit_peer_ad(bucket, slate, kind_caps, order, self.tombstone(), self.clock.monotonic())
	}

	/// Removes every route a retiring hive owns.
	///
	/// A route another owner landed under the same bucket bytes belongs to
	/// that owner, so it stays in place (CWE-639).
	pub(in crate::colony::cluster) fn remove_by_hive(
		&self,
		hive_id: impl AsRef<[u8]>,
	) -> Result<Vec<Arc<ServletEntry>>, ClusterError> {
		let hive_id = hive_id.as_ref();
		let bucket = Bucket { id: hive_id, owner: Owner::hive(hive_id) };
		Ok(self.routes.write()?.remove_owned(bucket))
	}

	/// Applies a batch of servlet address additions and removals for one hive.
	///
	/// # Errors
	///
	/// - [`ClusterError::ServletNotOwned`] -- an address belongs to another owner.
	/// - [`ClusterError::ServletNotFound`] -- a removal names an absent address.
	/// - [`ClusterError::LockPoisoned`] -- the route lock is poisoned.
	pub(in crate::colony::cluster) fn apply_address_update(
		&self,
		added: HiveSlate,
		removed: &[&[u8]],
	) -> Result<(), ClusterError> {
		let now = self.clock.monotonic();
		self.routes.write()?.apply_address_update(added, removed, now)
	}
}

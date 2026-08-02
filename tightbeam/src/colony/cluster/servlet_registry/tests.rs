use core::time::Duration;
use std::sync::Arc;

use super::{
	ClusterError, PeerCaps, PheromoneConfig, RouteKind, ServletEntry, ServletRegistry, DEFAULT_ABANDONMENT_LIMIT,
	DEFAULT_INITIAL_PHEROMONE,
};
use crate::colony::cluster::peer::{AdmittedPeerAd, RelayTrail};
use crate::colony::common::{current_timestamp_ms, MAX_PHEROMONE};
use crate::utils::BasisPoints;

// =========================================================================
// Test Helpers
// =========================================================================

/// Create a test entry with specified pheromone and abandonment limit
fn test_entry(pheromone: u64, abandonment_limit: u32) -> ServletEntry {
	ServletEntry::new(
		Arc::from(b"addr".as_slice()),
		Arc::from(b"type".as_slice()),
		Arc::from(b"hive".as_slice()),
		pheromone,
		abandonment_limit,
	)
}

/// Create a named test entry for registry tests
fn named_entry(addr: &[u8], servlet_type: &[u8], hive: &[u8]) -> ServletEntry {
	ServletEntry::new(
		Arc::from(addr),
		Arc::from(servlet_type),
		Arc::from(hive),
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)
}

/// Create a named test entry routed through a peer gateway
fn peer_entry(servlet_type: &[u8], peer_id: &[u8]) -> ServletEntry {
	ServletEntry::peer(
		Arc::from(peer_id),
		Arc::from(servlet_type),
		Arc::from(b"127.0.0.1:9000".as_slice()),
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)
}

fn peer_entry_dial(servlet_type: &[u8], peer_id: &[u8], dial: &[u8]) -> ServletEntry {
	ServletEntry::peer(
		Arc::from(peer_id),
		Arc::from(servlet_type),
		Arc::from(dial),
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)
}

// =========================================================================
// ServletEntry Tests - Data-Driven
// =========================================================================

/// Test cases: (initial_pheromone, reinforce_amount, expected_result)
const REINFORCE_CASES: &[(u64, u64, u64)] = &[
	(5000, 1000, 6000),                  // normal add
	(9500, 1000, MAX_PHEROMONE),         // caps at max
	(0, 500, 500),                       // from zero
	(MAX_PHEROMONE, 100, MAX_PHEROMONE), // already at max
];

#[test]
fn entry_reinforce_pheromone() {
	for &(initial, amount, expected) in REINFORCE_CASES {
		let entry = test_entry(initial, 5);
		entry.reinforce(amount);
		assert_eq!(entry.pheromone_level(), expected);
	}
}

/// Test cases: (initial_pheromone, decay_rate_bps, expected_result)
const EVAPORATE_CASES: &[(u64, u16, u64)] = &[
	(10000, 1000, 9000), // 10% decay
	(5000, 2000, 4000),  // 20% decay
	(100, 5000, 50),     // 50% decay
	(0, 1000, 0),        // already zero
];

#[test]
fn entry_evaporate_pheromone() {
	for &(initial, rate, expected) in EVAPORATE_CASES {
		let entry = test_entry(initial, 5);
		entry.evaporate(BasisPoints::new(rate));
		assert_eq!(entry.pheromone_level(), expected);
	}
}

#[test]
fn entry_weaken_increments_trials() {
	let entry = test_entry(5000, 5);
	for expected in 1..=3 {
		entry.weaken();
		assert_eq!(entry.trial_count(), expected);
	}
}

#[test]
fn entry_abandoned_after_limit() {
	let limit = 3;
	let entry = test_entry(5000, limit);

	// Not abandoned until reaching limit
	for _ in 0..limit {
		assert!(!entry.is_abandoned());
		entry.weaken();
	}
	assert!(entry.is_abandoned());
}

#[test]
fn entry_reinforce_resets_trials() {
	let entry = test_entry(5000, 5);
	entry.weaken();
	entry.weaken();
	assert_eq!(entry.trial_count(), 2);

	entry.reinforce(100);
	assert_eq!(entry.trial_count(), 0);
}

// =========================================================================
// ServletRegistry Tests
// =========================================================================

#[test]
fn entry_route_kind_defaults_local() {
	let entry = named_entry(b"addr1", b"calculator", b"hive1");
	assert_eq!(entry.route_kind(), RouteKind::Local);
}

#[test]
fn entry_local_dials_own_address() {
	let entry = named_entry(b"addr1", b"calculator", b"hive1");
	assert_eq!(entry.dial_target().as_ref(), entry.route_key().as_ref());
}

#[test]
fn entry_peer_dials_gateway_not_route_key() {
	let entry = peer_entry(b"calc", b"fp");
	assert_eq!(entry.dial_target().as_ref(), b"127.0.0.1:9000");
	assert_ne!(entry.dial_target().as_ref(), entry.route_key().as_ref());
	assert_eq!(entry.route_key()[0], b'f');
	assert_eq!(entry.route_key()[2], 0);
}

#[test]
fn peer_entries_filters_by_route_kind() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"local", b"calc", b"hive1")).ok();

	let empty = registry.peer_entries().ok().unwrap_or_default();
	assert!(empty.is_empty());

	let peer = peer_entry(b"calc", b"peer-colony");
	let route_key = Arc::clone(peer.route_key());
	registry.add(peer).ok();

	let peers = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(peers.len(), 1);
	assert_eq!(peers[0].route_key().as_ref(), route_key.as_ref());
}

#[test]
fn peer_entries_excludes_abandoned() {
	let limit = 2;
	let config = PheromoneConfig { abandonment_limit: limit, ..Default::default() };
	let registry = ServletRegistry::new(config);

	let peer = ServletEntry::peer(
		Arc::from(b"peer-colony".as_slice()),
		Arc::from(b"calc".as_slice()),
		Arc::from(b"127.0.0.1:9000".as_slice()),
		DEFAULT_INITIAL_PHEROMONE,
		limit,
	);

	let route_key = Arc::clone(peer.route_key());
	registry.add(peer).ok();

	for _ in 0..limit {
		registry.weaken(&route_key).ok();
	}

	let peers = registry.peer_entries().ok().unwrap_or_default();
	assert!(peers.is_empty());
}

#[test]
fn local_entries_for_type_excludes_peer_routes() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"local", b"calc", b"hive1")).ok();
	registry.add(peer_entry(b"calc", b"peer-colony")).ok();

	let local = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
	assert_eq!(local.len(), 1);
	assert_eq!(local[0].route_key().as_ref(), b"local");
}

#[test]
fn local_entries_for_type_empty_when_only_peer_routes() {
	let registry = ServletRegistry::default();
	registry.add(peer_entry(b"calc", b"peer-colony")).ok();

	let local = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
	assert!(local.is_empty());
}

// Non-empty slates install before they prune, so a serialized
// registry is never observably empty once seeded. An empty sighting
// or a final count other than one proves interleaved reconciles
// pruned each other's fresh installs.
#[test]
fn reconcile_by_hive_serializes_concurrent_slates() {
	use core::sync::atomic::{AtomicBool, Ordering};

	let registry = ServletRegistry::default();
	registry.reconcile_by_hive(b"gw", vec![peer_entry(b"urn:t:a", b"gw")]).ok();

	let saw_empty = AtomicBool::new(false);
	std::thread::scope(|scope| {
		scope.spawn(|| {
			for _ in 0..2000 {
				let slate = vec![peer_entry(b"urn:t:a", b"gw")];
				registry.reconcile_by_hive(b"gw", slate).ok();
			}
		});
		scope.spawn(|| {
			for _ in 0..2000 {
				let slate = vec![peer_entry(b"urn:t:b", b"gw")];
				registry.reconcile_by_hive(b"gw", slate).ok();
			}
		});
		scope.spawn(|| {
			for _ in 0..20000 {
				let empty = registry.peer_entries().ok().unwrap_or_default().is_empty();
				saw_empty.fetch_or(empty, Ordering::Relaxed);
			}
		});
	});

	assert!(!saw_empty.load(Ordering::Relaxed));
	assert_eq!(registry.peer_entries().ok().unwrap_or_default().len(), 1);
}

#[test]
fn local_servlets_dedups_and_excludes_peer_routes() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"a1", b"calc", b"hive1")).ok();
	registry.add(named_entry(b"a2", b"calc", b"hive1")).ok();
	registry.add(named_entry(b"a3", b"echo", b"hive1")).ok();
	registry.add(peer_entry(b"urn:t:x", b"gw")).ok();

	let types = registry.local_servlets().ok().unwrap_or_default();
	assert_eq!(types.len(), 2);
}

#[test]
fn local_servlets_tracks_adds_and_removes() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"a1", b"calc", b"hive1")).ok();
	registry.add(named_entry(b"a2", b"echo", b"hive1")).ok();
	registry.remove(b"a2").ok();

	let types = registry.local_servlets().ok().unwrap_or_default();
	assert_eq!(types.len(), 1);
	assert_eq!(types[0].as_ref(), b"calc");
}

#[test]
fn reconcile_by_hive_installs_multi_type_slate() {
	let registry = ServletRegistry::default();
	let slate = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	registry.reconcile_by_hive(b"gw", slate).ok();

	let peers = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(peers.len(), 2);
}

#[test]
fn reconcile_by_hive_prunes_stale_routes() {
	let registry = ServletRegistry::default();
	let full = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	registry.reconcile_by_hive(b"gw", full).ok();
	let shrunk = vec![peer_entry(b"urn:t:a", b"gw")];
	registry.reconcile_by_hive(b"gw", shrunk).ok();

	let peers = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(peers.len(), 1);
	assert_eq!(peers[0].servlet_type().as_ref(), b"urn:t:a");
}

#[test]
fn reconcile_by_hive_leaves_other_hives_untouched() {
	let registry = ServletRegistry::default();
	let peer = peer_entry(b"urn:t:a", b"gw");
	registry.add(named_entry(b"local", b"urn:t:a", b"hive1")).ok();
	registry.reconcile_by_hive(b"gw", vec![peer]).ok();
	registry.reconcile_by_hive(b"gw", vec![]).ok();

	let locals = registry.local_entries_for_type(b"urn:t:a").ok().unwrap_or_default();
	assert_eq!(locals.len(), 1);
	assert!(registry.peer_entries().ok().unwrap_or_default().is_empty());
}

#[test]
fn reconcile_by_hive_preserves_peer_trail_state() {
	let registry = ServletRegistry::default();
	let first = peer_entry(b"urn:t:a", b"fp");
	let route = Arc::clone(first.route_key());
	registry.reconcile_by_hive(b"fp", vec![first]).ok();
	registry.reinforce(&route, 1_000).ok();
	registry.weaken(&route).ok();

	let before = registry.entries_for_type(b"urn:t:a").ok().unwrap_or_default();
	let pheromone_before = before[0].pheromone_level();
	let trials_before = before[0].trial_count();

	registry
		.reconcile_by_hive(b"fp", vec![peer_entry_dial(b"urn:t:a", b"fp", b"127.0.0.1:9001")])
		.ok();

	let after = registry.entries_for_type(b"urn:t:a").ok().unwrap_or_default();
	assert_eq!(after[0].pheromone_level(), pheromone_before);
	assert_eq!(after[0].trial_count(), trials_before);
	assert_eq!(after[0].dial_target().as_ref(), b"127.0.0.1:9001");
}

#[test]
fn peer_dial_conflicts_with_local_servlet_address() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"127.0.0.1:9000", b"calc", b"hive1")).ok();
	assert_eq!(registry.peer_dial_conflicts_local(b"127.0.0.1:9000").ok(), Some(true));
	assert_eq!(registry.peer_dial_conflicts_local(b"127.0.0.1:9001").ok(), Some(false));
}

#[test]
fn slate_exceeds_caps_counts_gateways_and_routes() {
	let registry = ServletRegistry::default();
	registry.reconcile_by_hive(b"fp1", vec![peer_entry(b"a", b"fp1")]).ok();
	registry.reconcile_by_hive(b"fp2", vec![peer_entry(b"a", b"fp2")]).ok();

	assert_eq!(
		registry.slate_exceeds_caps(b"fp3", 1, RouteKind::Peer, 2, 1024).ok(),
		Some(true)
	);
	assert_eq!(
		registry.slate_exceeds_caps(b"fp1", 1, RouteKind::Peer, 2, 1024).ok(),
		Some(false)
	);
	// With fp1 prior=1 and fp2=1, a slate of 5 makes routes_after=6,
	// over the max of 5.
	assert_eq!(registry.slate_exceeds_caps(b"fp1", 5, RouteKind::Peer, 64, 5).ok(), Some(true));
	assert_eq!(registry.slate_exceeds_caps(b"fp1", 0, RouteKind::Peer, 1, 1).ok(), Some(false));
}

fn admitted(hive: &[u8], dial: &[u8], slate: Vec<ServletEntry>) -> AdmittedPeerAd {
	admitted_with_order(hive, dial, slate, 0)
}

fn admitted_with_order(hive: &[u8], dial: &[u8], slate: Vec<ServletEntry>, order: u64) -> AdmittedPeerAd {
	AdmittedPeerAd { peer_hive_id: Arc::from(hive), dial_addr: Arc::from(dial), slate, order }
}

/// Relay trail under the composite `origin NUL relay` bucket.
fn relay_trail(origin: &[u8], relay: &[u8], servlet_type: &[u8], dial: &[u8]) -> RelayTrail {
	let slate = vec![ServletEntry::peer_relay(
		Arc::from(origin),
		Arc::from(relay),
		Arc::from(servlet_type),
		Arc::from(dial),
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)];

	RelayTrail { bucket: ServletEntry::relay_bucket(origin, relay), slate, order: 0 }
}

// The relay bucket lives independently of the origin's direct slate:
// a fresh direct advertisement reconciles only the origin bucket, so
// the fallback trail through the relay survives it.
#[test]
fn direct_reconcile_preserves_relay_bucket() {
	let registry = ServletRegistry::default();
	let first = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(first, PeerCaps::default()).ok();

	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	let installed = registry.reconcile_relay_trail(trail, PeerCaps::default());
	assert!(matches!(installed, Ok(())));

	let refresh = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(refresh, PeerCaps::default()).ok();

	let entries = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(entries.len(), 2);
	assert!(entries.iter().any(|entry| entry.route_kind() == RouteKind::PeerRelay));
}

#[test]
fn relay_reconcile_replaces_only_its_bucket() {
	let registry = ServletRegistry::default();
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(ad, PeerCaps::default()).ok();
	registry
		.reconcile_relay_trail(
			relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
			PeerCaps::default(),
		)
		.ok();

	let replaced = relay_trail(b"origin", b"relay", b"sum", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(replaced, PeerCaps::default()).ok();

	let entries = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(entries.len(), 2);
	assert!(entries.iter().any(|entry| entry.route_kind() == RouteKind::Peer));
	assert!(entries
		.iter()
		.any(|entry| entry.route_kind() == RouteKind::PeerRelay && entry.servlet_type().as_ref() == b"sum"));
}

// Relay buckets spend their own budget: a gateway table at its direct
// cap still admits a relay trail, and a new direct gateway is never
// refused because relay buckets exist.
#[test]
fn relay_buckets_do_not_spend_the_direct_gateway_cap() {
	let registry = ServletRegistry::default();
	let caps = PeerCaps { max_gateways: 1, max_relay_buckets: 1, ..Default::default() };
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(ad, caps).ok();

	let installed = registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps);
	assert!(matches!(installed, Ok(())));
}

// A member relaying many origins mints one bucket per (origin, relay)
// pair, so the relay-bucket cap bounds relay-spam bucket inflation.
#[test]
fn relay_bucket_cap_refuses_extra_buckets() {
	let registry = ServletRegistry::default();
	let caps = PeerCaps { max_relay_buckets: 1, ..Default::default() };
	let first = registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps);
	assert!(matches!(first, Ok(())));

	let refused = registry.reconcile_relay_trail(relay_trail(b"other", b"relay", b"calc", b"127.0.0.1:9001"), caps);
	assert!(matches!(refused, Err(ClusterError::PeerCapExceeded)));
}

// An origin that withdraws its whole direct slate withdraws its relay
// fallbacks with it: a relay trail never outlives every direct claim.
#[test]
fn empty_direct_slate_clears_relay_trails_for_origin() {
	let registry = ServletRegistry::default();
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(ad, PeerCaps::default()).ok();
	registry
		.reconcile_relay_trail(
			relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
			PeerCaps::default(),
		)
		.ok();

	let clearing = admitted(b"origin", b"127.0.0.1:9000", Vec::new());
	registry.reconcile_peer_slate(clearing, PeerCaps::default()).ok();

	assert!(registry.peer_entries().ok().unwrap_or_default().is_empty());
}

// A replayed advertisement older than the newest applied one must not
// regress the slate, for direct buckets and relay buckets alike.
#[test]
fn stale_ad_order_is_refused_per_bucket() {
	let registry = ServletRegistry::default();
	let fresh = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
	assert!(matches!(registry.reconcile_peer_slate(fresh, PeerCaps::default()), Ok(())));

	let replayed = admitted_with_order(b"origin", b"127.0.0.1:9666", vec![peer_entry(b"calc", b"origin")], 10);
	let refused = registry.reconcile_peer_slate(replayed, PeerCaps::default());
	assert!(matches!(refused, Err(ClusterError::StalePeerAd)));

	let mut trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	trail.order = 20;
	assert!(matches!(registry.reconcile_relay_trail(trail, PeerCaps::default()), Ok(())));

	let mut replayed_trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9666");
	replayed_trail.order = 10;

	let refused_trail = registry.reconcile_relay_trail(replayed_trail, PeerCaps::default());
	assert!(matches!(refused_trail, Err(ClusterError::StalePeerAd)));
}

// The order ledger keys per bucket: an equal-order refresh reconciles,
// and the direct bucket's order never gates the relay bucket.
#[test]
fn equal_ad_order_reconciles_idempotently() {
	let registry = ServletRegistry::default();
	let first = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
	registry.reconcile_peer_slate(first, PeerCaps::default()).ok();

	let refresh = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
	assert!(matches!(registry.reconcile_peer_slate(refresh, PeerCaps::default()), Ok(())));

	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	assert!(matches!(registry.reconcile_relay_trail(trail, PeerCaps::default()), Ok(())));
}

// A withdrawal (empty slate) leaves an order tombstone: a replayed
// older advertisement inside the freshness window cannot reinstall
// routes the origin already withdrew.
#[test]
fn withdrawal_tombstone_refuses_older_ad_reinstall() {
	// The unbounded window pins the retain rule itself: the outcome
	// must not depend on how much clock elapses between statements.
	let registry = ServletRegistry::new(PheromoneConfig::default()).with_ad_tombstone_window_ms(u64::MAX);
	let issued = current_timestamp_ms();
	let install = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	registry.reconcile_peer_slate(install, PeerCaps::default()).ok();

	let withdrawal = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![], issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default()).ok();

	let replayed = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	let result = registry.reconcile_peer_slate(replayed, PeerCaps::default());
	assert!(matches!(result, Err(ClusterError::StalePeerAd)));
}

// Past the window the freshness gate refuses the replayed frame
// itself, so the ledger prunes the dead bucket's tombstone and stays
// bounded.
#[test]
fn expired_tombstone_prunes_from_the_ledger() {
	let registry = ServletRegistry::new(PheromoneConfig::default()).with_ad_tombstone_window_ms(0);
	let issued = current_timestamp_ms().saturating_sub(10);
	let install = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	registry.reconcile_peer_slate(install, PeerCaps::default()).ok();

	let withdrawal = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![], issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default()).ok();

	let rows = registry.ad_orders.lock().map(|ledger| ledger.len()).unwrap_or(usize::MAX);
	assert_eq!(rows, 0);
}

// Relay trails refresh only through reconciles, so age past `max_age`
// is the retirement signal. Direct trails are untouched.
#[test]
fn prune_stale_relay_trails_drops_only_aged_relay_buckets() {
	let registry = ServletRegistry::default();
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry.reconcile_peer_slate(ad, PeerCaps::default()).ok();
	registry
		.reconcile_relay_trail(
			relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
			PeerCaps::default(),
		)
		.ok();

	assert_eq!(registry.prune_stale_relay_trails(Duration::from_secs(600)).ok(), Some(0));
	assert_eq!(registry.prune_stale_relay_trails(Duration::ZERO).ok(), Some(1));

	let survivors = registry.peer_entries().ok().unwrap_or_default();
	assert_eq!(survivors.len(), 1);
	assert_eq!(survivors[0].route_kind(), RouteKind::Peer);
}

// weaken_peer scores every trail attributed to an identity: its own
// direct routes and every relay trail that forwards through it.
#[test]
fn weaken_peer_scores_relay_trails_through_the_peer() {
	let registry = ServletRegistry::default();
	registry.add(peer_entry(b"urn:t:a", b"relay")).ok();
	let trail = relay_trail(b"origin", b"relay", b"urn:t:a", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(trail, PeerCaps::default()).ok();

	assert_eq!(registry.weaken_peer(b"relay").ok(), Some(2));
	assert_eq!(registry.weaken_peer(b"origin").ok(), Some(1));
}

#[test]
fn reconcile_peer_slate_refuses_over_gateway_cap() {
	let registry = ServletRegistry::default();
	let caps = PeerCaps { max_gateways: 1, ..Default::default() };
	let first_ad = admitted(b"fp1", b"127.0.0.1:9000", vec![peer_entry(b"a", b"fp1")]);
	let first = registry.reconcile_peer_slate(first_ad, caps);
	assert!(matches!(first, Ok(())));

	let second_ad = admitted(b"fp2", b"127.0.0.1:9001", vec![peer_entry(b"a", b"fp2")]);
	let second = registry.reconcile_peer_slate(second_ad, caps);
	assert!(matches!(second, Err(ClusterError::PeerCapExceeded)));
	assert_eq!(registry.peer_entries().ok().unwrap_or_default().len(), 1);
}

// A local slate and a peer ad race for the same hive-index key. Both
// paths hold the reconcile gate, so the ad either sees the local rows
// and refuses, or completes first and its rows are then replaced. A
// missing local route at the end proves a local install landed inside
// the ad's probe-to-install window and was clobbered by peer rows.
#[test]
fn reconcile_peer_slate_excludes_concurrent_local_install() {
	for _ in 0..500 {
		let registry = ServletRegistry::default();
		std::thread::scope(|scope| {
			scope.spawn(|| {
				let slate = vec![named_entry(b"gw", b"calc", b"gw")];
				registry.reconcile_by_hive(b"gw", slate).ok();
			});
			scope.spawn(|| {
				let ad = admitted(b"gw", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"gw")]);
				registry.reconcile_peer_slate(ad, PeerCaps::default()).ok();
			});
		});

		let locals = registry.local_entries_for_type(b"calc").ok().unwrap_or_default();
		assert_eq!(locals.len(), 1);
	}
}

#[test]
fn peer_key_conflicts_only_with_local_routes() {
	// (seeded entry, probe key, expected conflict)
	let cases: &[(ServletEntry, &[u8], bool)] = &[
		(named_entry(b"gw", b"calc", b"hive1"), b"gw", true),
		(named_entry(b"addr1", b"calc", b"gw"), b"gw", true),
		(peer_entry(b"calc", b"gw"), b"gw", false),
		(peer_entry(b"calc", b"gw"), b"unseen", false),
	];

	for (entry, probe, expected) in cases {
		let registry = ServletRegistry::default();
		registry.add(entry.clone()).ok();

		assert_eq!(registry.peer_key_conflicts_local(probe).ok(), Some(*expected));
	}
}

#[test]
fn registry_add_and_lookup() {
	let registry = ServletRegistry::default();
	let entry = named_entry(b"addr1", b"calculator", b"hive1");
	registry.add(entry).ok();

	let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
	assert_eq!(found.len(), 1);
	assert_eq!(found[0].route_key().as_ref(), b"addr1");
}

fn seed_reregistered_registry() -> ServletRegistry {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
	registry
}

#[test]
fn registry_reregistration_does_not_duplicate_indices() {
	let registry = seed_reregistered_registry();

	let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
	assert_eq!(found.len(), 1);
	assert!(matches!(registry.len().ok(), Some(1)));
}

#[test]
fn registry_reregistration_moves_entry_across_types() {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1")).ok();
	registry.add(named_entry(b"addr1", b"auth", b"hive2")).ok();

	let calculator = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
	let auth = registry.entries_for_type(b"auth").ok().unwrap_or_default();
	assert!(calculator.is_empty());
	assert_eq!(auth.len(), 1);

	// Old hive index rows retired alongside the type rows
	let removed = registry.remove_by_hive(b"hive1").ok().unwrap_or_default();
	assert!(removed.is_empty());
}

#[test]
fn registry_remove_after_reregistration_clears_entry() {
	let registry = seed_reregistered_registry();
	registry.remove(b"addr1").ok();

	let found = registry.entries_for_type(b"calculator").ok().unwrap_or_default();
	assert!(found.is_empty());
}

#[test]
fn registry_remove_abandoned_prunes_entries() {
	let limit = 2;
	let config = PheromoneConfig { abandonment_limit: limit, ..Default::default() };
	let registry = ServletRegistry::new(config);

	let entry = test_entry(5000, limit);
	registry.add(entry).ok();

	// Weaken to abandonment
	for _ in 0..limit {
		registry.weaken(b"addr").ok();
	}

	assert!(matches!(registry.remove_abandoned().ok(), Some(1)));
	assert!(matches!(registry.len().ok(), Some(0)));
}

#[test]
fn weaken_peer_targets_all_routes_of_one_peer() -> Result<(), ClusterError> {
	let registry = ServletRegistry::default();
	registry.add(peer_entry(b"urn:t:a", b"fp-a"))?;
	registry.add(peer_entry(b"urn:t:b", b"fp-a"))?;
	registry.add(peer_entry(b"urn:t:a", b"fp-b"))?;

	let weakened = registry.weaken_peer(b"fp-a")?;

	assert_eq!(weakened, 2);
	Ok(())
}

#[test]
fn weaken_peer_skips_local_routes() -> Result<(), ClusterError> {
	let registry = ServletRegistry::default();
	registry.add(named_entry(b"addr", b"urn:t:a", b"hive-a"))?;

	let weakened = registry.weaken_peer(b"hive-a")?;
	assert_eq!(weakened, 0);
	Ok(())
}

/// Create a peer-routed test entry with a specific abandonment limit
fn peer_entry_limit(servlet_type: &[u8], peer_id: &[u8], limit: u32) -> ServletEntry {
	ServletEntry::peer(
		Arc::from(peer_id),
		Arc::from(servlet_type),
		Arc::from(b"127.0.0.1:9000".as_slice()),
		DEFAULT_INITIAL_PHEROMONE,
		limit,
	)
}

#[test]
fn weaken_peer_abandons_after_limit_leaving_others_live() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = ServletRegistry::default();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-b", limit))?;

	for _ in 0..limit {
		registry.weaken_peer(b"fp-a")?;
	}

	let live = registry.peer_entries()?;
	assert_eq!(live.len(), 1);
	assert_eq!(live[0].owner_id().as_ref(), b"fp-b");
	Ok(())
}

#[test]
fn weaken_peer_skips_already_abandoned_routes() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = ServletRegistry::default();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;

	for _ in 0..limit {
		registry.weaken_peer(b"fp-a")?;
	}

	let weakened = registry.weaken_peer(b"fp-a")?;
	assert_eq!(weakened, 0);
	Ok(())
}

#[test]
fn weaken_peer_by_dial_targets_matching_gateway() -> Result<(), ClusterError> {
	let registry = ServletRegistry::default();
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;
	registry.add(peer_entry_dial(b"urn:t:b", b"fp-a", b"127.0.0.1:9100"))?;
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-b", b"127.0.0.1:9200"))?;

	let weakened = registry.weaken_peer_by_dial(b"127.0.0.1:9100")?;

	assert_eq!(weakened, 2);
	Ok(())
}

#[test]
fn weaken_peer_by_dial_ignores_unknown_gateway() -> Result<(), ClusterError> {
	let registry = ServletRegistry::default();
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;

	let weakened = registry.weaken_peer_by_dial(b"127.0.0.1:9999")?;
	assert_eq!(weakened, 0);
	Ok(())
}

struct ApplyAddressUpdateCase {
	seed: (&'static [u8], &'static [u8], &'static [u8]),
	caller_hive: &'static [u8],
	add: Option<(&'static [u8], &'static [u8], &'static [u8])>,
	remove: &'static [&'static [u8]],
	expect_ok: bool,
	expected_addrs: &'static [&'static [u8]],
}

fn apply_address_update_cases() -> Vec<ApplyAddressUpdateCase> {
	const VICTIM: &[&[u8]] = &[b"victim"];
	const OLD: &[&[u8]] = &[b"old"];
	const NEW: &[&[u8]] = &[b"new"];
	const MISSING: &[&[u8]] = &[b"ghost"];

	vec![
		ApplyAddressUpdateCase {
			seed: (b"victim", b"calc", b"hive-a"),
			caller_hive: b"hive-b",
			add: Some((b"poison", b"calc", b"hive-b")),
			remove: VICTIM,
			expect_ok: false,
			expected_addrs: VICTIM,
		},
		ApplyAddressUpdateCase {
			seed: (b"old", b"calc", b"hive-a"),
			caller_hive: b"hive-a",
			add: Some((b"new", b"calc", b"hive-a")),
			remove: OLD,
			expect_ok: true,
			expected_addrs: NEW,
		},
		// A remove naming an absent locator must refuse: Ok(None) must
		// not report success while the seeded route stays routed.
		ApplyAddressUpdateCase {
			seed: (b"victim", b"calc", b"hive-a"),
			caller_hive: b"hive-a",
			add: None,
			remove: MISSING,
			expect_ok: false,
			expected_addrs: VICTIM,
		},
	]
}

#[test]
fn apply_address_update_ownership_and_atomicity() {
	for case in apply_address_update_cases() {
		let registry = ServletRegistry::default();
		registry.add(named_entry(case.seed.0, case.seed.1, case.seed.2)).ok();

		let added = case.add.map(|(a, t, h)| named_entry(a, t, h)).into_iter().collect();
		let result = registry.apply_address_update(case.caller_hive, added, case.remove);
		assert_eq!(result.is_ok(), case.expect_ok);

		let found = registry.entries_for_type(b"calc").ok().unwrap_or_default();
		assert_eq!(found.len(), case.expected_addrs.len());
		for (entry, addr) in found.iter().zip(case.expected_addrs.iter()) {
			assert_eq!(entry.route_key().as_ref(), *addr);
		}
	}
}

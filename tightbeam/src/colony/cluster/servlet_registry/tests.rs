use core::mem::discriminant;
use core::str::from_utf8;
use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLockReadGuard};
use std::thread;

use super::entry::LocalRoute;
use super::{
	ClusterError, DialTarget, HiveSlate, KindCaps, PeerCaps, PeerRoute, PheromoneConfig, RelayRoute, RouteKind,
	RoutePlane, Routes, ServletEntry, ServletRegistry, SharedId, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE,
};
use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::peer::{AdmittedPeerAd, RelayTrail};
use crate::colony::cluster::MAX_PHEROMONE;
use crate::colony::cluster::{AdmittedDial, PeerAddress};
use crate::colony::protocol::ServletInfo;
use crate::colony::urn::ColonyNamespace;
use crate::colony::urn::ServletTypeKey;
use crate::tb_cases;
use crate::urn::Urn;
use crate::utils::basis_points::BasisPointsOutOfRange;
use crate::utils::time::{Clock, ManualClock, UnixMillis};
use crate::utils::BasisPoints;

/// A clock only the test moves.
fn manual_clock() -> Arc<ManualClock> {
	Arc::new(ManualClock::default())
}

/// A registry on the default pheromone configuration and a manual clock.
fn registry() -> ServletRegistry {
	registry_on(&manual_clock())
}

/// A registry on `clock`, for tests that advance it.
fn registry_on(clock: &Arc<ManualClock>) -> ServletRegistry {
	ServletRegistry::new(PheromoneConfig::default(), Arc::clone(clock) as Arc<dyn Clock>)
}

/// A registry whose routes abandon after `limit` failures.
fn registry_abandoning_after(limit: u32) -> ServletRegistry {
	let config = PheromoneConfig { abandonment_limit: limit, ..Default::default() };
	ServletRegistry::new(config, manual_clock())
}

/// The read guard over the registry's routes, where the admission logic lives.
fn routes(registry: &ServletRegistry) -> RwLockReadGuard<'_, Routes> {
	registry.routes.read().expect("routes lock")
}

/// The owner recorded for the route at `key`, when one is routed there.
fn owner_of(registry: &ServletRegistry, key: impl AsRef<[u8]>) -> Option<SharedId> {
	let key = key.as_ref();
	routes(registry).get(key).map(|entry| Arc::clone(entry.owner_id()))
}

/// The type key the registry indexes `servlet_type` under.
fn type_key(servlet_type: impl AsRef<[u8]>) -> ServletTypeKey {
	let servlet_type = servlet_type.as_ref();
	ServletTypeKey::from_route_bytes(servlet_type)
}

/// The fixture gateway socket spelled as `dial`, which the default dial
/// policy admits as production admits a peer's claim.
fn admitted_dial(dial: impl AsRef<[u8]>) -> AdmittedDial {
	let dial = dial.as_ref();
	AdmittedDial::fixture(from_utf8(dial).expect("fixture dial addresses are UTF-8"))
}

/// One local entry with the given pheromone and abandonment limit.
fn test_entry(pheromone: u64, abandonment_limit: u32) -> ServletEntry {
	ServletEntry::local(
		LocalRoute {
			address: Arc::from(b"addr".as_slice()),
			servlet_type: Arc::from(b"type".as_slice()),
			hive_id: Arc::from(b"hive".as_slice()),
			signer: ServletInfo::fixture_signer(),
		},
		pheromone,
		abandonment_limit,
	)
}

/// A local entry at `addr` that serves `servlet_type` for `hive`.
fn named_entry(addr: impl AsRef<[u8]>, servlet_type: impl AsRef<[u8]>, hive: impl AsRef<[u8]>) -> ServletEntry {
	let addr = addr.as_ref();
	let servlet_type = servlet_type.as_ref();
	let hive = hive.as_ref();
	ServletEntry::local(
		LocalRoute {
			address: Arc::from(addr),
			servlet_type: Arc::from(servlet_type),
			hive_id: Arc::from(hive),
			signer: ServletInfo::fixture_signer(),
		},
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)
}

/// The signer of a fixture servlet's registration.
fn servlet_signer() -> Arc<SignerIdentifier> {
	Arc::new(ServletInfo::fixture_signer())
}

/// The slate `hive` registers, which holds `entries`.
fn hive_slate(hive: impl AsRef<[u8]>, entries: impl IntoIterator<Item = ServletEntry>) -> HiveSlate {
	HiveSlate::of(hive, entries)
}

/// A peer entry for `servlet_type` advertised by `peer_id`, which dials the
/// fixture gateway socket.
fn peer_entry(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>) -> ServletEntry {
	peer_entry_dial(servlet_type, peer_id, b"127.0.0.1:9000")
}

fn peer_entry_dial(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>, dial: impl AsRef<[u8]>) -> ServletEntry {
	let servlet_type = servlet_type.as_ref();
	let peer_id = peer_id.as_ref();
	ServletEntry::peer(
		PeerRoute {
			peer_id: Arc::from(peer_id),
			servlet_type: Arc::from(servlet_type),
			dial: admitted_dial(dial),
		},
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)
}

/// A peer entry with a specific abandonment limit.
fn peer_entry_limit(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>, limit: u32) -> ServletEntry {
	let servlet_type = servlet_type.as_ref();
	let peer_id = peer_id.as_ref();
	ServletEntry::peer(
		PeerRoute {
			peer_id: Arc::from(peer_id),
			servlet_type: Arc::from(servlet_type),
			dial: admitted_dial(b"127.0.0.1:9000"),
		},
		DEFAULT_INITIAL_PHEROMONE,
		limit,
	)
}

/// An admitted advertisement from `hive` at `dial` that carries `slate`, at
/// order zero.
fn admitted(
	hive: impl AsRef<[u8]>,
	dial: impl AsRef<[u8]>,
	slate: impl IntoIterator<Item = ServletEntry>,
) -> AdmittedPeerAd {
	let hive = hive.as_ref();
	let dial = dial.as_ref();
	let slate: Vec<ServletEntry> = slate.into_iter().collect();
	admitted_with_order(hive, dial, slate, 0)
}

fn admitted_with_order(
	hive: impl AsRef<[u8]>,
	dial: impl AsRef<[u8]>,
	slate: impl IntoIterator<Item = ServletEntry>,
	order: u64,
) -> AdmittedPeerAd {
	let hive = hive.as_ref();
	let dial = admitted_dial(dial);
	let slate: Vec<ServletEntry> = slate.into_iter().collect();
	AdmittedPeerAd { peer_hive_id: Arc::from(hive), dial, slate, order: UnixMillis::new(order) }
}

/// Installs one direct peer slate for `peer` that dials the fixture socket.
fn install_peer_slate(
	registry: &ServletRegistry,
	peer: impl AsRef<[u8]>,
	slate: impl IntoIterator<Item = ServletEntry>,
) -> Result<(), ClusterError> {
	let peer = peer.as_ref();
	registry.reconcile_peer_slate(admitted(peer, b"127.0.0.1:9000", slate), PeerCaps::default())
}

/// A relay trail under the composite `origin NUL relay` bucket.
fn relay_trail(
	origin: impl AsRef<[u8]>,
	relay: impl AsRef<[u8]>,
	servlet_type: impl AsRef<[u8]>,
	dial: impl AsRef<[u8]>,
) -> RelayTrail {
	let origin = origin.as_ref();
	let relay = relay.as_ref();
	let servlet_type = servlet_type.as_ref();
	let slate = vec![ServletEntry::peer_relay(
		RelayRoute {
			origin_id: Arc::from(origin),
			relay_id: Arc::from(relay),
			servlet_type: Arc::from(servlet_type),
			dial: admitted_dial(dial),
		},
		DEFAULT_INITIAL_PHEROMONE,
		DEFAULT_ABANDONMENT_LIMIT,
	)];

	RelayTrail {
		bucket: ServletEntry::relay_bucket(origin, relay),
		origin: Arc::from(origin),
		slate,
		order: UnixMillis::new(0),
	}
}

/// The one entry of a relay trail for `origin` through `relay`, which dials
/// the relay at the fixture socket.
fn relay_trail_entry(origin: impl AsRef<[u8]>, relay: impl AsRef<[u8]>) -> ServletEntry {
	let mut slate = relay_trail(origin, relay, b"ping", b"127.0.0.1:9001").slate;
	slate.pop().expect("the fixture trail holds one entry")
}

/// The peer plane bound to the gateway whose slate key is `gateway_id`.
fn peer_plane(gateway_id: impl AsRef<[u8]>) -> RoutePlane {
	RoutePlane::Peer { gateway_id: SharedId::from(gateway_id.as_ref()) }
}

/// The hive plane bound to `signer`.
fn hive_plane(signer: Arc<SignerIdentifier>) -> RoutePlane {
	RoutePlane::Hive { signer }
}

/// Counts `times` failures against the route at `key`.
fn weaken_times(registry: &ServletRegistry, key: impl AsRef<[u8]>, times: u32) -> Result<(), ClusterError> {
	let key = key.as_ref();
	for _ in 0..times {
		registry.weaken(key)?;
	}

	Ok(())
}

/// Counts `times` failures against every route attributed to `peer`.
fn weaken_peer_times(registry: &ServletRegistry, peer: impl AsRef<[u8]>, times: u32) -> Result<(), ClusterError> {
	let peer = peer.as_ref();
	for _ in 0..times {
		registry.weaken_peer(peer)?;
	}

	Ok(())
}

// Reinforcement adds to the level and stops at the ceiling.
tb_cases! {
	fn entry_reinforce_pheromone((initial, amount, expected): (u64, u64, u64)) {
		let entry = test_entry(initial, 5);
		entry.reinforce(amount);

		assert_eq!(entry.pheromone_level(), expected);
	}
	cases {
		normal_add => (5000, 1000, 6000),
		caps_at_max => (9500, 1000, MAX_PHEROMONE),
		from_zero => (0, 500, 500),
		already_at_max => (MAX_PHEROMONE, 100, MAX_PHEROMONE),
	}
}

// Evaporation removes the configured share of the level.
tb_cases! {
	fn entry_evaporate_pheromone((initial, rate, expected): (u64, u16, u64)) -> Result<(), BasisPointsOutOfRange> {
		let entry = test_entry(initial, 5);
		entry.evaporate(BasisPoints::try_from(rate)?);

		assert_eq!(entry.pheromone_level(), expected);

		Ok(())
	}
	cases {
		ten_percent => (10000, 1000, 9000),
		twenty_percent => (5000, 2000, 4000),
		half => (100, 5000, 50),
		already_zero => (0, 1000, 0),
	}
}

/// Counts `times` failures on one entry.
fn weaken_entry_times(entry: &ServletEntry, times: u32) {
	for _ in 0..times {
		entry.weaken();
	}
}

// Every failure counts one trial, and the entry abandons on the failure
// that reaches the limit.
tb_cases! {
	fn entry_trials_count_toward_the_limit((weakened, expected_trials, abandoned): (u32, u32, bool)) {
		let entry = test_entry(5000, 3);
		weaken_entry_times(&entry, weakened);

		assert_eq!(entry.trial_count(), expected_trials);
		assert_eq!(entry.is_abandoned(), abandoned);
	}
	cases {
		none => (0, 0, false),
		one_short => (2, 2, false),
		at_the_limit => (3, 3, true),
	}
}

#[test]
fn entry_reinforce_resets_trials() {
	let entry = test_entry(5000, 5);
	weaken_entry_times(&entry, 2);

	entry.reinforce(100);

	assert_eq!(entry.trial_count(), 0);
}

#[test]
fn entry_route_kind_defaults_local() {
	let entry = named_entry(b"addr1", b"calculator", b"hive1");
	assert_eq!(entry.route_kind(), RouteKind::Local);
}

// A route dials on the hive plane bound to the signer its registration
// names, or on the peer plane bound to one gateway: its advertiser for a
// direct route and the relay for a relay trail.
tb_cases! {
	fn entry_names_the_plane_it_dials_on((entry, plane): (ServletEntry, RoutePlane)) {
		let named = entry.plane();
		assert_eq!(named, plane);
	}

	cases {
		a_local_route_names_its_signer => (named_entry(b"addr1", b"calc", b"hive1"), hive_plane(servlet_signer())),
		a_direct_route_names_its_advertiser => (peer_entry(b"ping", b"peer-a"), peer_plane(b"peer-a")),
		a_relay_trail_names_its_relay => (relay_trail_entry(b"peer-a", b"peer-b"), peer_plane(b"peer-b")),
	}
}

// A local entry dials the endpoint its key names: a name as the hive wrote
// it, and a socket in canonical form however the hive spelled it (CWE-706).
tb_cases! {
	fn entry_local_dials_the_endpoint_its_key_names((address, dialed): (&[u8], &[u8])) {
		let entry = named_entry(address, b"calculator", b"hive1");
		assert_eq!(entry.route_key().as_ref(), address);
		assert_eq!(entry.dial_target().as_bytes(), dialed);
	}
	cases {
		named => (b"addr1", b"addr1"),
		socket => (b"127.0.0.1:9000", b"127.0.0.1:9000"),
		mapped_socket => (b"[::ffff:127.0.0.1]:9000", b"127.0.0.1:9000"),
	}
}

#[test]
fn entry_peer_dials_gateway_not_route_key() {
	let entry = peer_entry(b"calc", b"fp");
	assert_eq!(entry.dial_target().as_bytes(), b"127.0.0.1:9000");
	assert_ne!(entry.dial_target().as_bytes(), entry.route_key().as_ref());
	assert_eq!(entry.route_key().first(), Some(&b'f'));
	assert_eq!(entry.route_key().get(2), Some(&0));
}

#[test]
fn peer_entries_filters_by_route_kind() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"local", b"calc", b"hive1"))?;

	let peer = peer_entry(b"calc", b"peer-colony");
	let route_key = Arc::clone(peer.route_key());

	registry.add(peer)?;

	let peers = registry.peer_entries()?;
	let keys: Vec<SharedId> = peers.iter().map(|entry| Arc::clone(entry.route_key())).collect();
	assert_eq!(keys, vec![route_key]);
	Ok(())
}

#[test]
fn peer_entries_excludes_abandoned() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = registry_abandoning_after(limit);
	let peer = peer_entry_limit(b"calc", b"peer-colony", limit);
	let route_key = Arc::clone(peer.route_key());
	registry.add(peer)?;

	weaken_times(&registry, &route_key, limit)?;

	let peers = registry.peer_entries()?;
	assert!(peers.is_empty());
	Ok(())
}

#[test]
fn local_entries_for_type_excludes_peer_routes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"local", b"calc", b"hive1"))?;
	registry.add(peer_entry(b"calc", b"peer-colony"))?;

	let local = registry.local_entries_for_type(&type_key(b"calc"))?;
	let keys: Vec<SharedId> = local.iter().map(|entry| Arc::clone(entry.route_key())).collect();
	assert_eq!(keys, vec![SharedId::from(b"local".as_slice())]);
	Ok(())
}

#[test]
fn local_entries_for_type_empty_when_only_peer_routes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(peer_entry(b"calc", b"peer-colony"))?;

	let local = registry.local_entries_for_type(&type_key(b"calc"))?;
	assert!(local.is_empty());
	Ok(())
}

/// Races two slates for one peer bucket against a reader, and answers
/// whether the reader ever saw the bucket empty.
///
/// Non-empty slates install before they prune, so a serialized registry
/// holds a seeded slate at every observation. A read that finds the bucket
/// empty proves interleaved reconciles pruned each other's fresh installs.
fn race_peer_slates(registry: &ServletRegistry) -> bool {
	let saw_empty = AtomicBool::new(false);
	thread::scope(|scope| {
		scope.spawn(|| {
			for _ in 0..2000 {
				let slate = vec![peer_entry(b"urn:t:a", b"gw")];
				install_peer_slate(registry, b"gw", slate).expect("the slate is the bucket owner's own");
			}
		});
		scope.spawn(|| {
			for _ in 0..2000 {
				let slate = vec![peer_entry(b"urn:t:b", b"gw")];
				install_peer_slate(registry, b"gw", slate).expect("the slate is the bucket owner's own");
			}
		});
		scope.spawn(|| {
			for _ in 0..20000 {
				let empty = registry.peer_entries().expect("the route lock is live").is_empty();
				saw_empty.fetch_or(empty, Ordering::Relaxed);
			}
		});
	});

	saw_empty.load(Ordering::Relaxed)
}

#[test]
fn reconcile_peer_slate_serializes_concurrent_slates() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;

	let saw_empty = race_peer_slates(&registry);
	assert!(!saw_empty);
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

#[test]
fn local_servlets_dedups_and_excludes_peer_routes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"a1", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a2", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a3", b"echo", b"hive1"))?;
	registry.add(peer_entry(b"urn:t:x", b"gw"))?;

	let types = registry.local_servlets()?;
	assert_eq!(types.len(), 2);
	Ok(())
}

/// Two hives that serve one type both yield routes, and `local_servlets`
/// names the type once. The type index lives in this registry alone, so it
/// answers the fan-out the balancer picks from.
#[test]
fn two_hives_serving_one_type_both_yield_routes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"a1", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a2", b"calc", b"hive2"))?;

	let routes = registry.entries_for_type(&type_key(b"calc"))?;
	assert_eq!(routes.len(), 2);
	assert_eq!(registry.local_servlets()?.len(), 1);
	Ok(())
}

#[test]
fn local_servlets_tracks_adds_and_removes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"a1", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a2", b"echo", b"hive1"))?;
	registry.remove(b"a2")?;

	let types = registry.local_servlets()?;
	assert_eq!(types, vec![SharedId::from(b"calc".as_slice())]);
	Ok(())
}

#[test]
fn reconcile_peer_slate_installs_multi_type_slate() -> Result<(), ClusterError> {
	let registry = registry();
	let slate = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	install_peer_slate(&registry, b"gw", slate)?;

	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

#[test]
fn reconcile_peer_slate_prunes_stale_routes() -> Result<(), ClusterError> {
	let registry = registry();
	let full = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	install_peer_slate(&registry, b"gw", full)?;
	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;

	let peers = registry.peer_entries()?;
	let types: Vec<SharedId> = peers.iter().map(|entry| Arc::clone(entry.servlet_type())).collect();
	assert_eq!(types, vec![SharedId::from(b"urn:t:a".as_slice())]);
	Ok(())
}

#[test]
fn reconcile_peer_slate_leaves_local_routes_untouched() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"local", b"urn:t:a", b"hive1"))?;

	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;
	install_peer_slate(&registry, b"gw", vec![])?;

	assert_eq!(registry.local_entries_for_type(&type_key(b"urn:t:a"))?.len(), 1);
	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

#[test]
fn reconcile_peer_slate_preserves_peer_trail_state() -> Result<(), ClusterError> {
	let registry = registry();
	let first = peer_entry(b"urn:t:a", b"fp");
	let route = Arc::clone(first.route_key());

	install_peer_slate(&registry, b"fp", vec![first])?;
	registry.reinforce(&route, 1_000)?;
	registry.weaken(&route)?;

	let before = registry.entries_for_type(&type_key(b"urn:t:a"))?;
	let scored_before: Vec<(u64, u32)> = before
		.iter()
		.map(|entry| (entry.pheromone_level(), entry.trial_count()))
		.collect();

	let refresh = admitted(
		b"fp",
		b"127.0.0.1:9001",
		vec![peer_entry_dial(b"urn:t:a", b"fp", b"127.0.0.1:9001")],
	);
	registry.reconcile_peer_slate(refresh, PeerCaps::default())?;

	let after = registry.entries_for_type(&type_key(b"urn:t:a"))?;
	let scored_after: Vec<(u64, u32)> = after
		.iter()
		.map(|entry| (entry.pheromone_level(), entry.trial_count()))
		.collect();
	let dials: Vec<&[u8]> = after.iter().map(|entry| entry.dial_target().as_bytes()).collect();
	assert_eq!(scored_after, scored_before);
	assert_eq!(dials, vec![b"127.0.0.1:9001".as_slice()]);
	Ok(())
}

/// The slate `hive1` registers at the fixture gateway socket.
fn local_at_the_gateway_socket() -> HiveSlate {
	hive_slate(b"hive1", vec![named_entry(b"127.0.0.1:9000", b"calc", b"hive1")])
}

/// The advertisement `gw` sends from the fixture gateway socket.
fn peer_at_the_gateway_socket() -> AdmittedPeerAd {
	admitted(b"gw", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"gw")])
}

// A peer may not advertise a socket at which the gateway dials a local servlet.
#[test]
fn a_peer_cannot_dial_a_local_servlets_socket() -> Result<(), ClusterError> {
	let registry = registry();
	registry.reconcile_by_hive(local_at_the_gateway_socket())?;

	let refused = registry.reconcile_peer_slate(peer_at_the_gateway_socket(), PeerCaps::default());
	assert!(matches!(refused, Err(ClusterError::PeerSlateConflict)));
	assert_eq!(registry.len()?, 1);
	Ok(())
}

// A hive may not register a servlet at a socket at which the gateway dials a
// peer gateway. It is the collision of the reverse order, and the one decider
// on the dial axis judges it.
#[test]
fn a_hive_cannot_register_a_peer_gateways_socket() -> Result<(), ClusterError> {
	let registry = registry();
	registry.reconcile_peer_slate(peer_at_the_gateway_socket(), PeerCaps::default())?;

	let refused = registry.reconcile_by_hive(local_at_the_gateway_socket());
	assert!(matches!(refused, Err(ClusterError::ServletNotOwned)));
	assert_eq!(registry.len()?, 1);
	Ok(())
}

/// A second owner's claim on `claimed`, placed against the registry.
type Claim = fn(&ServletRegistry, &[u8]) -> Result<(), ClusterError>;

/// A peer `gw` that claims `claimed` as its gateway socket.
fn claimed_by_a_peer(registry: &ServletRegistry, claimed: &[u8]) -> Result<(), ClusterError> {
	let claim = admitted(b"gw", claimed, vec![peer_entry_dial(b"calc", b"gw", claimed)]);
	registry.reconcile_peer_slate(claim, PeerCaps::default())
}

/// A second hive that registers a servlet at `claimed`.
fn claimed_by_another_hive(registry: &ServletRegistry, claimed: &[u8]) -> Result<(), ClusterError> {
	registry.reconcile_by_hive(hive_slate(b"hive2", vec![named_entry(claimed, b"calc", b"hive2")]))
}

// The registry refuses another owner's socket under any spelling, to a
// second hive as to a peer, because a dual-stack host, a scope id, and a
// wildcard listener each reach one socket by more than one spelling
// (CWE-706, CWE-639).
tb_cases! {
	fn a_socket_another_owner_holds_is_refused_under_any_spelling((local, claimed, claim, expected): (&[u8], &[u8], Claim, ClusterError)) -> Result<(), ClusterError> {
		let registry = registry();
		registry.reconcile_by_hive(hive_slate(b"hive1", vec![named_entry(local, b"calc", b"hive1")]))?;

		let refused = claim(&registry, claimed);
		assert_eq!(refused.map_err(|error| discriminant(&error)), Err(discriminant(&expected)));
		assert_eq!(registry.len()?, 1);
		Ok(())
	}
	cases {
		peer_by_the_mapped_spelling => (b"127.0.0.1:9000", b"[::ffff:127.0.0.1]:9000", claimed_by_a_peer, ClusterError::PeerSlateConflict),
		peer_by_a_scoped_spelling => (b"[::1]:9000", b"[::1%7]:9000", claimed_by_a_peer, ClusterError::PeerSlateConflict),
		peer_at_the_loopback_of_a_wildcard_servlet => (b"0.0.0.0:9000", b"127.0.0.1:9000", claimed_by_a_peer, ClusterError::PeerSlateConflict),
		hive_by_the_mapped_spelling => (b"127.0.0.1:9000", b"[::ffff:127.0.0.1]:9000", claimed_by_another_hive, ClusterError::ServletNotOwned),
		hive_by_a_scoped_spelling => (b"[::1]:9000", b"[::1%7]:9000", claimed_by_another_hive, ClusterError::ServletNotOwned),
	}
}

#[test]
fn a_peer_may_dial_a_socket_no_local_route_holds() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"127.0.0.1:9000", b"calc", b"hive1"))?;

	let admitted_ad = admitted(
		b"gw",
		b"127.0.0.1:9001",
		vec![peer_entry_dial(b"calc", b"gw", b"127.0.0.1:9001")],
	);
	registry.reconcile_peer_slate(admitted_ad, PeerCaps::default())?;

	assert_eq!(registry.len()?, 2);
	Ok(())
}

#[test]
fn slate_exceeds_caps_counts_gateways_and_routes() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"fp1", vec![peer_entry(b"a", b"fp1")])?;
	install_peer_slate(&registry, b"fp2", vec![peer_entry(b"a", b"fp2")])?;

	assert!(routes(&registry).slate_exceeds_caps(
		b"fp3",
		1,
		KindCaps { kind: RouteKind::Peer, max_identities: 2, max_routes: 1024 }
	));
	assert!(!routes(&registry).slate_exceeds_caps(
		b"fp1",
		1,
		KindCaps { kind: RouteKind::Peer, max_identities: 2, max_routes: 1024 }
	));
	// fp1 and fp2 hold one route each, so a five-route slate for fp1 leaves
	// six routes, one over the cap of five.
	assert!(routes(&registry).slate_exceeds_caps(
		b"fp1",
		5,
		KindCaps { kind: RouteKind::Peer, max_identities: 64, max_routes: 5 }
	));
	assert!(!routes(&registry).slate_exceeds_caps(
		b"fp1",
		0,
		KindCaps { kind: RouteKind::Peer, max_identities: 1, max_routes: 1 }
	));
	Ok(())
}

/// Races an older and a newer advertisement for one bucket and answers the
/// servlet types left installed.
fn race_ad_orders(registry: &Arc<ServletRegistry>) -> Vec<SharedId> {
	let older = Arc::clone(registry);
	let newer = Arc::clone(registry);

	let low = thread::spawn(move || {
		let ad = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"echo", b"origin")], 10);
		older.reconcile_peer_slate(ad, PeerCaps::default())
	});
	let high = thread::spawn(move || {
		let ad = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
		newer.reconcile_peer_slate(ad, PeerCaps::default())
	});

	// Whichever lands second may be the stale one, so only the join must
	// succeed.
	let _low = low.join().expect("thread joins");
	let _high = high.join().expect("thread joins");

	routes(registry)
		.values()
		.map(|entry| Arc::clone(entry.servlet_type()))
		.collect()
}

// The order ledger and the installed slate are one decision, so after the last
// ad applies, the ledger names the installed slate. A ledger below the
// installed order would admit a replay older than that slate (CWE-294).
#[test]
fn racing_ads_leave_the_ledger_naming_the_installed_slate() {
	let registry = Arc::new(registry());
	let installed = race_ad_orders(&registry);
	assert_eq!(installed, vec![SharedId::from(b"calc".as_slice())]);
}

// The relay bucket lives independently of the origin's direct slate:
// a fresh direct advertisement reconciles only the origin bucket, so
// the fallback trail through the relay survives it.
#[test]
fn direct_reconcile_preserves_relay_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"origin", vec![peer_entry(b"calc", b"origin")])?;

	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(trail, PeerCaps::default())?;

	install_peer_slate(&registry, b"origin", vec![peer_entry(b"calc", b"origin")])?;

	let entries = registry.peer_entries()?;
	assert_eq!(entries.len(), 2);
	assert!(entries.iter().any(|entry| entry.route_kind() == RouteKind::PeerRelay));
	Ok(())
}

/// A withdrawn socket takes every peer route that dials it: the direct route
/// of the peer that advertised it and the relay trail through it. Another
/// peer's direct route stays.
#[test]
fn withdraw_peer_by_dial_drops_the_routes_that_dial_the_socket() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"peer-a", vec![peer_entry(b"ping", b"peer-a")])?;

	let through = relay_trail(b"peer-c", b"peer-a", b"echo", b"127.0.0.1:9000");
	registry.reconcile_relay_trail(through, PeerCaps::default())?;

	let other_slate = vec![peer_entry_dial(b"pong", b"peer-b", b"127.0.0.1:9001")];
	let other = admitted(b"peer-b", b"127.0.0.1:9001", other_slate);
	registry.reconcile_peer_slate(other, PeerCaps::default())?;
	registry.withdraw_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;

	let live = registry.peer_entries()?;
	let owners: Vec<SharedId> = live.iter().map(|entry| Arc::clone(entry.owner_id())).collect();
	let kinds: Vec<RouteKind> = live.iter().map(|entry| entry.route_kind()).collect();
	assert_eq!(owners, vec![SharedId::from(b"peer-b".as_slice())]);
	assert_eq!(kinds, vec![RouteKind::Peer]);
	Ok(())
}

/// The peer whose socket is withdrawn stays reachable through its fallback
/// trail, because that trail dials the relay.
#[test]
fn withdraw_peer_by_dial_keeps_the_fallback_trail_through_another_relay() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"peer-a", vec![peer_entry(b"ping", b"peer-a")])?;

	let fallback = relay_trail(b"peer-a", b"peer-b", b"ping", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(fallback, PeerCaps::default())?;
	registry.withdraw_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;

	let live = registry.peer_entries()?;
	let relays: Vec<Option<SharedId>> = live.iter().map(|entry| entry.relay_id().cloned()).collect();
	assert_eq!(relays, vec![Some(SharedId::from(b"peer-b".as_slice()))]);
	Ok(())
}

/// A hive route whose address spells the withdrawn socket stays, because the
/// withdrawal acts on the peer plane alone.
#[test]
fn withdraw_peer_by_dial_keeps_a_local_route_at_the_socket() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"127.0.0.1:9000", b"calc", b"hive1"))?;
	registry.withdraw_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;

	let owner = owner_of(&registry, b"127.0.0.1:9000");
	assert_eq!(owner, Some(SharedId::from(b"hive1".as_slice())));
	Ok(())
}

#[test]
fn relay_reconcile_replaces_only_its_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"origin", vec![peer_entry(b"calc", b"origin")])?;
	registry.reconcile_relay_trail(
		relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
		PeerCaps::default(),
	)?;

	let replaced = relay_trail(b"origin", b"relay", b"sum", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(replaced, PeerCaps::default())?;

	let entries = registry.peer_entries()?;
	assert_eq!(entries.len(), 2);
	assert!(entries.iter().any(|entry| entry.route_kind() == RouteKind::Peer));
	assert!(entries
		.iter()
		.any(|entry| entry.route_kind() == RouteKind::PeerRelay && entry.servlet_type().as_ref() == b"sum"));
	Ok(())
}

// A direct gateway at its cap still admits a relay trail, because relay
// buckets spend their own budget.
#[test]
fn relay_buckets_do_not_spend_the_direct_gateway_cap() -> Result<(), ClusterError> {
	let registry = registry();
	let caps = PeerCaps { max_gateways: 1, max_relay_buckets: 1, ..Default::default() };
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);

	registry.reconcile_peer_slate(ad, caps)?;
	registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps)?;

	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

// A member that relays many origins creates one bucket per (origin, relay)
// pair, so the relay-bucket cap bounds how far relay spam inflates buckets.
#[test]
fn relay_bucket_cap_refuses_extra_buckets() -> Result<(), ClusterError> {
	let registry = registry();
	let caps = PeerCaps { max_relay_buckets: 1, ..Default::default() };

	registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps)?;

	let refused = registry.reconcile_relay_trail(relay_trail(b"other", b"relay", b"calc", b"127.0.0.1:9001"), caps);
	assert!(matches!(refused, Err(ClusterError::PeerCapExceeded)));
	Ok(())
}

// An origin that withdraws its whole direct slate withdraws its relay
// fallbacks with it: a relay trail lasts as long as a direct claim.
#[test]
fn empty_direct_slate_clears_relay_trails_for_origin() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"origin", vec![peer_entry(b"calc", b"origin")])?;
	registry.reconcile_relay_trail(
		relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
		PeerCaps::default(),
	)?;

	install_peer_slate(&registry, b"origin", Vec::new())?;

	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

// A replayed advertisement older than the newest applied one must not
// regress a direct bucket.
#[test]
fn stale_ad_order_is_refused_for_a_direct_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	let fresh = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);

	registry.reconcile_peer_slate(fresh, PeerCaps::default())?;

	let replayed = admitted_with_order(b"origin", b"127.0.0.1:9666", vec![peer_entry(b"calc", b"origin")], 10);
	let refused = registry.reconcile_peer_slate(replayed, PeerCaps::default());
	assert!(matches!(refused, Err(ClusterError::StalePeerAd)));
	Ok(())
}

// A replayed advertisement older than the newest applied one must not
// regress a relay bucket either.
#[test]
fn stale_ad_order_is_refused_for_a_relay_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");

	registry.reconcile_relay_trail(RelayTrail { order: UnixMillis::new(20), ..trail }, PeerCaps::default())?;

	let replayed = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9666");
	let refused =
		registry.reconcile_relay_trail(RelayTrail { order: UnixMillis::new(10), ..replayed }, PeerCaps::default());

	assert!(matches!(refused, Err(ClusterError::StalePeerAd)));
	Ok(())
}

// The order ledger keys per bucket: an equal-order refresh reconciles,
// and each bucket's order gates that bucket alone.
#[test]
fn equal_ad_order_reconciles_idempotently() -> Result<(), ClusterError> {
	let registry = registry();
	let first = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
	registry.reconcile_peer_slate(first, PeerCaps::default())?;

	let refresh = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], 20);
	registry.reconcile_peer_slate(refresh, PeerCaps::default())?;
	registry.reconcile_relay_trail(
		relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
		PeerCaps::default(),
	)?;

	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

// A withdrawal leaves a tombstone in the order ledger, so the registry
// refuses a replayed older advertisement inside the freshness window, and the
// routes the origin withdrew stay withdrawn.
#[test]
fn withdrawal_tombstone_refuses_older_ad_reinstall() -> Result<(), ClusterError> {
	// The unbounded window pins the retain rule itself: the outcome
	// must not depend on how much time elapses between statements.
	let clock = manual_clock();
	let registry = registry_on(&clock).with_ad_tombstone_window(Duration::MAX);
	let issued = clock.unix().get();
	let install = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	registry.reconcile_peer_slate(install, PeerCaps::default())?;

	let withdrawal = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![], issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default())?;

	let replayed = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	let result = registry.reconcile_peer_slate(replayed, PeerCaps::default());
	assert!(matches!(result, Err(ClusterError::StalePeerAd)));
	Ok(())
}

// Past the window the freshness gate refuses the replayed frame
// itself, so the ledger prunes the dead bucket's tombstone and stays
// bounded.
#[test]
fn expired_tombstone_prunes_from_the_ledger() -> Result<(), ClusterError> {
	let clock = manual_clock();
	let registry = registry_on(&clock).with_ad_tombstone_window(Duration::ZERO);
	let issued = clock.unix().get().saturating_sub(10);
	let install = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")], issued);
	registry.reconcile_peer_slate(install, PeerCaps::default())?;

	let withdrawal = admitted_with_order(b"origin", b"127.0.0.1:9000", vec![], issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default())?;

	assert_eq!(routes(&registry).ad_order_rows(), 0);
	Ok(())
}

/// A registry on a manual clock with one direct route and one relay trail
/// for `origin`, both installed at the clock's start.
fn registry_with_relay_trail(clock: &Arc<ManualClock>) -> ServletRegistry {
	let registry = registry_on(clock);
	let ad = admitted(b"origin", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"origin")]);
	registry
		.reconcile_peer_slate(ad, PeerCaps::default())
		.expect("the direct slate installs");

	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	registry
		.reconcile_relay_trail(trail, PeerCaps::default())
		.expect("the relay trail installs");
	registry
}

/// The route kinds left in a registry after a prune at `max_age`, and how
/// many routes that prune dropped.
fn kinds_after_prune(registry: &ServletRegistry, max_age: Duration) -> Result<(usize, Vec<RouteKind>), ClusterError> {
	let pruned = registry.prune_stale_relay_trails(max_age)?;
	let mut kinds: Vec<RouteKind> = registry.peer_entries()?.iter().map(|entry| entry.route_kind()).collect();
	kinds.sort_by_key(|kind| match kind {
		RouteKind::Local => 0,
		RouteKind::Peer => 1,
		RouteKind::PeerRelay => 2,
	});

	Ok((pruned, kinds))
}

// Relay trails refresh only through reconciles, so age past `max_age` is
// the retirement signal. A trail exactly at the age stays, so the boundary
// row pins `>` against `>=`. The prune leaves direct trails in place.
tb_cases! {
	fn prune_stale_relay_trails_judges_age((elapsed, pruned, kinds): (Duration, usize, Vec<RouteKind>)) -> Result<(), ClusterError> {
		let clock = manual_clock();
		let registry = registry_with_relay_trail(&clock);

		clock.advance(elapsed);

		let (dropped, remaining) = kinds_after_prune(&registry, Duration::from_secs(600))?;
		assert_eq!(dropped, pruned);
		assert_eq!(remaining, kinds);
		Ok(())
	}
	cases {
		inside_the_age => (Duration::from_secs(1), 0, vec![RouteKind::Peer, RouteKind::PeerRelay]),
		at_the_age => (Duration::from_secs(600), 0, vec![RouteKind::Peer, RouteKind::PeerRelay]),
		past_the_age => (Duration::from_secs(601), 1, vec![RouteKind::Peer]),
	}
}

/// A trail that a reconcile refreshes ages from the refresh, on the
/// registry's clock, so the prune keeps it.
#[test]
fn a_refreshed_relay_trail_survives_the_prune() -> Result<(), ClusterError> {
	let clock = manual_clock();
	let registry = registry_with_relay_trail(&clock);

	clock.advance(Duration::from_secs(601));

	let refresh = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(RelayTrail { order: UnixMillis::new(1), ..refresh }, PeerCaps::default())?;

	let pruned = registry.prune_stale_relay_trails(Duration::from_secs(600))?;
	assert_eq!(pruned, 0);
	Ok(())
}

// `weaken_peer` weakens every trail attributed to an identity: its own
// direct routes, the relay trails learned for it, and every relay trail
// that forwards through it.
#[test]
fn weaken_peer_scores_relay_trails_through_the_peer() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(peer_entry(b"urn:t:a", b"relay"))?;

	let trail = relay_trail(b"origin", b"relay", b"urn:t:a", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(trail, PeerCaps::default())?;

	assert_eq!(registry.weaken_peer(b"relay")?, 2);
	assert_eq!(registry.weaken_peer(b"origin")?, 1);
	Ok(())
}

#[test]
fn reconcile_peer_slate_refuses_over_gateway_cap() -> Result<(), ClusterError> {
	let registry = registry();
	let caps = PeerCaps { max_gateways: 1, ..Default::default() };
	let first_ad = admitted(b"fp1", b"127.0.0.1:9000", vec![peer_entry(b"a", b"fp1")]);
	registry.reconcile_peer_slate(first_ad, caps)?;

	let second_ad = admitted(b"fp2", b"127.0.0.1:9001", vec![peer_entry(b"a", b"fp2")]);
	let second = registry.reconcile_peer_slate(second_ad, caps);
	assert!(matches!(second, Err(ClusterError::PeerCapExceeded)));
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

/// Races one local install against one peer advertisement for the same
/// bucket bytes, `rounds` times, and answers how many rounds ended with the
/// bucket held by exactly one plane.
///
/// Both paths take the route write lock, so a round reads one of two ways:
///
/// - One plane routed: the path that landed first kept the bucket, and the sweep check refused the other.
/// - Both planes routed, or neither: an interleaving slipped past the lock,
///   and one slate clobbered or half-installed the other.
fn rounds_with_one_plane_holding_the_bucket(rounds: usize) -> usize {
	(0..rounds)
		.filter(|_| {
			let registry = registry();
			// Either racer may be the one refused, so the test discards both
			// outcomes and reads what the bucket holds afterwards.
			thread::scope(|scope| {
				scope.spawn(|| {
					let slate = hive_slate(b"gw", vec![named_entry(b"gw", b"calc", b"gw")]);
					let _outcome = registry.reconcile_by_hive(slate);
				});
				scope.spawn(|| {
					let ad = admitted(b"gw", b"127.0.0.1:9000", vec![peer_entry(b"calc", b"gw")]);
					let _outcome = registry.reconcile_peer_slate(ad, PeerCaps::default());
				});
			});

			let locals = registry
				.local_entries_for_type(&type_key(b"calc"))
				.expect("the route lock is live");

			let peers = registry.peer_entries().expect("the route lock is live");
			locals.len() + peers.len() == 1
		})
		.count()
}

#[test]
fn racing_slates_for_one_bucket_leave_it_to_one_plane() {
	let rounds = 500;
	let settled = rounds_with_one_plane_holding_the_bucket(rounds);
	assert_eq!(settled, rounds);
}

// The registry refuses a peer advertisement whose bucket bytes equal a hive
// id once that hive's routes sit under the bucket, because the hive and the
// peer are different owners even when their bytes agree (CWE-639).
#[test]
fn a_peer_cannot_advertise_under_a_hives_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	registry.reconcile_by_hive(hive_slate(b"gw", vec![named_entry(b"addr1", b"calc", b"gw")]))?;

	let refused = install_peer_slate(&registry, b"gw", vec![peer_entry(b"calc", b"gw")]);
	assert!(matches!(refused, Err(ClusterError::PeerSlateConflict)));
	assert_eq!(owner_of(&registry, b"addr1"), Some(SharedId::from(b"gw".as_slice())));
	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

// A hive whose id equals a peer's fingerprint bytes may not register
// under that bucket: the slate swap would sweep the peer's routes, so the
// one decider refuses the sweep before anything moves (CWE-639).
#[test]
fn a_hive_cannot_sweep_a_peers_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"peer", vec![peer_entry(b"calc", b"peer")])?;

	let refused = registry.reconcile_by_hive(hive_slate(b"peer", vec![named_entry(b"local-addr", b"calc", b"peer")]));
	assert!(matches!(refused, Err(ClusterError::ServletNotOwned)));
	assert!(routes(&registry).get(b"local-addr").is_none());
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

// The retirement of a hive takes only the routes it owns, so a peer's routes
// under the same bucket bytes survive it.
#[test]
fn removing_a_hive_leaves_a_peers_routes_under_the_same_bucket() -> Result<(), ClusterError> {
	let registry = registry();
	install_peer_slate(&registry, b"shared", vec![peer_entry(b"calc", b"shared")])?;

	let removed = registry.remove_by_hive(b"shared")?;
	assert!(removed.is_empty());
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

// The registry admits a peer advertisement when a local servlet shares its
// bucket bytes as an address: the keys and sockets differ, so both routes
// stay.
#[test]
fn a_peer_may_share_bytes_with_a_local_address() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"gw", b"calc", b"hive1"))?;

	install_peer_slate(&registry, b"gw", vec![peer_entry(b"calc", b"gw")])?;

	assert_eq!(registry.len()?, 2);
	Ok(())
}

#[test]
fn registry_add_and_lookup() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1"))?;

	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	let keys: Vec<SharedId> = found.iter().map(|entry| Arc::clone(entry.route_key())).collect();
	assert_eq!(keys, vec![SharedId::from(b"addr1".as_slice())]);
	Ok(())
}

fn seed_reregistered_registry() -> Result<ServletRegistry, ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1"))?;
	registry.add(named_entry(b"addr1", b"calculator", b"hive1"))?;
	Ok(registry)
}

#[test]
fn registry_reregistration_does_not_duplicate_indices() -> Result<(), ClusterError> {
	let registry = seed_reregistered_registry()?;
	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	assert_eq!(found.len(), 1);
	assert_eq!(registry.len()?, 1);
	Ok(())
}

#[test]
fn registry_reregistration_moves_entry_across_types() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1"))?;
	registry.add(named_entry(b"addr1", b"auth", b"hive1"))?;

	let calculator = registry.entries_for_type(&type_key(b"calculator"))?;
	let auth = registry.entries_for_type(&type_key(b"auth"))?;
	assert!(calculator.is_empty());
	assert_eq!(auth.len(), 1);
	Ok(())
}

/// One hive cannot take over an address another hive registered. The
/// registry refuses the slate whole, and the first hive keeps its route.
#[test]
fn a_hive_cannot_take_over_another_hives_address() -> Result<(), ClusterError> {
	let registry = registry();
	registry.reconcile_by_hive(hive_slate(b"hive-b", vec![named_entry(b"addr-b", b"calc", b"hive-b")]))?;
	let slate = hive_slate(
		b"hive-a",
		vec![
			named_entry(b"addr-a", b"calc", b"hive-a"),
			named_entry(b"addr-b", b"calc", b"hive-a"),
		],
	);

	let takeover = registry.reconcile_by_hive(slate);
	assert!(matches!(takeover, Err(ClusterError::ServletNotOwned)));
	assert!(routes(&registry).get(b"addr-a").is_none());
	assert_eq!(owner_of(&registry, b"addr-b"), Some(SharedId::from(b"hive-b".as_slice())));
	Ok(())
}

#[test]
fn registry_remove_after_reregistration_clears_entry() -> Result<(), ClusterError> {
	let registry = seed_reregistered_registry()?;
	registry.remove(b"addr1")?;

	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	assert!(found.is_empty());
	Ok(())
}

#[test]
fn registry_remove_abandoned_prunes_entries() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = registry_abandoning_after(limit);
	registry.add(test_entry(5000, limit))?;

	weaken_times(&registry, b"addr", limit)?;

	let removed = registry.remove_abandoned()?;
	assert_eq!(removed, 1);
	assert_eq!(registry.len()?, 0);
	Ok(())
}

#[test]
fn weaken_peer_targets_all_routes_of_one_peer() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(peer_entry(b"urn:t:a", b"fp-a"))?;
	registry.add(peer_entry(b"urn:t:b", b"fp-a"))?;
	registry.add(peer_entry(b"urn:t:a", b"fp-b"))?;

	let weakened = registry.weaken_peer(b"fp-a")?;
	assert_eq!(weakened, 2);
	Ok(())
}

#[test]
fn weaken_peer_skips_local_routes() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(named_entry(b"addr", b"urn:t:a", b"hive-a"))?;

	let weakened = registry.weaken_peer(b"hive-a")?;
	assert_eq!(weakened, 0);
	Ok(())
}

#[test]
fn weaken_peer_abandons_after_limit_leaving_others_live() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = registry();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-b", limit))?;

	weaken_peer_times(&registry, b"fp-a", limit)?;

	let live = registry.peer_entries()?;
	let owners: Vec<SharedId> = live.iter().map(|entry| Arc::clone(entry.owner_id())).collect();
	assert_eq!(owners, vec![SharedId::from(b"fp-b".as_slice())]);
	Ok(())
}

#[test]
fn weaken_peer_skips_already_abandoned_routes() -> Result<(), ClusterError> {
	let limit = 2;
	let registry = registry();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", limit))?;
	weaken_peer_times(&registry, b"fp-a", limit)?;

	let weakened = registry.weaken_peer(b"fp-a")?;
	assert_eq!(weakened, 0);
	Ok(())
}

#[test]
fn weaken_peer_by_dial_targets_matching_gateway() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;
	registry.add(peer_entry_dial(b"urn:t:b", b"fp-a", b"127.0.0.1:9100"))?;
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-b", b"127.0.0.1:9200"))?;

	let weakened = registry.weaken_peer_by_dial(PeerAddress::fixture("127.0.0.1:9100"))?;
	assert_eq!(weakened, 2);
	Ok(())
}

#[test]
fn weaken_peer_by_dial_ignores_unknown_gateway() -> Result<(), ClusterError> {
	let registry = registry();
	registry.add(peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"))?;

	let weakened = registry.weaken_peer_by_dial(PeerAddress::fixture("127.0.0.1:9999"))?;
	assert_eq!(weakened, 0);
	Ok(())
}

/// One address update against a registry seeded with a single route owned
/// by `hive-a`.
struct ApplyAddressUpdateCase {
	/// The seeded route as (address, type, hive).
	seed: (&'static [u8], &'static [u8], &'static [u8]),
	/// The hive whose signed update this is.
	caller_hive: &'static [u8],
	/// The route the update adds, as (address, type, hive), if any.
	add: Option<(&'static [u8], &'static [u8], &'static [u8])>,
	/// The addresses the update removes.
	remove: &'static [&'static [u8]],
	/// The refusal expected, or `None` for an accepted update.
	expected: Option<ClusterError>,
	/// The `calc` routes left afterwards, as (address, owner).
	expected_routes: &'static [(&'static [u8], &'static [u8])],
}

/// The `calc` routes a registry holds, as (address, owner), sorted by address.
fn calc_routes(registry: &ServletRegistry) -> Result<Vec<(SharedId, SharedId)>, ClusterError> {
	let mut found: Vec<(SharedId, SharedId)> = registry
		.entries_for_type(&type_key(b"calc"))?
		.iter()
		.map(|entry| (Arc::clone(entry.route_key()), Arc::clone(entry.owner_id())))
		.collect();
	found.sort();

	Ok(found)
}

// The registry checks every entry before any map moves, so a refused update
// leaves the registry as seeded, and an accepted one lands whole.
tb_cases! {
	fn apply_address_update_ownership_and_atomicity(case: ApplyAddressUpdateCase) -> Result<(), ClusterError> {
		let registry = registry();
		registry.add(named_entry(case.seed.0, case.seed.1, case.seed.2))?;

		let added = hive_slate(case.caller_hive, case.add.map(|(a, t, h)| named_entry(a, t, h)));
		let result = registry.apply_address_update(added, case.remove);
		let outcome = result.as_ref().err().map(core::mem::discriminant);
		assert_eq!(outcome, case.expected.as_ref().map(core::mem::discriminant));

		let expected_routes: Vec<(SharedId, SharedId)> = case
			.expected_routes
			.iter()
			.map(|(address, owner)| (SharedId::from(*address), SharedId::from(*owner)))
			.collect();
		assert_eq!(calc_routes(&registry)?, expected_routes);
		Ok(())
	}
	cases {
		// A removal that names another hive's route refuses the whole update,
		// so the addition beside it fails too.
		removing_another_hives_route => ApplyAddressUpdateCase {
			seed: (b"victim", b"calc", b"hive-a"),
			caller_hive: b"hive-b",
			add: Some((b"poison", b"calc", b"hive-b")),
			remove: &[b"victim"],
			expected: Some(ClusterError::ServletNotOwned),
			expected_routes: &[(b"victim", b"hive-a")],
		},
		// An addition that names a key another hive holds refuses, and the
		// holder keeps its route (CWE-639).
		adding_over_another_hives_route => ApplyAddressUpdateCase {
			seed: (b"victim", b"calc", b"hive-a"),
			caller_hive: b"hive-b",
			add: Some((b"victim", b"calc", b"hive-b")),
			remove: &[],
			expected: Some(ClusterError::ServletNotOwned),
			expected_routes: &[(b"victim", b"hive-a")],
		},
		owner_swaps_its_own_address => ApplyAddressUpdateCase {
			seed: (b"old", b"calc", b"hive-a"),
			caller_hive: b"hive-a",
			add: Some((b"new", b"calc", b"hive-a")),
			remove: &[b"old"],
			expected: None,
			expected_routes: &[(b"new", b"hive-a")],
		},
		// A restart that reuses its listen address removes and re-adds the
		// same locator in one update, and the instance stays routed.
		owner_readds_the_address_it_removes => ApplyAddressUpdateCase {
			seed: (b"reused", b"calc", b"hive-a"),
			caller_hive: b"hive-a",
			add: Some((b"reused", b"calc", b"hive-a")),
			remove: &[b"reused"],
			expected: None,
			expected_routes: &[(b"reused", b"hive-a")],
		},
		// A removal that names an absent locator must refuse, because a success
		// would report a removal that never happened.
		removing_an_absent_locator => ApplyAddressUpdateCase {
			seed: (b"victim", b"calc", b"hive-a"),
			caller_hive: b"hive-a",
			add: None,
			remove: &[b"ghost"],
			expected: Some(ClusterError::ServletNotFound),
			expected_routes: &[(b"victim", b"hive-a")],
		},
	}
}

/// The rendering of the socket `entry` dials, as the operator view of a peer
/// route shares it.
fn dial_rendering(entry: Option<&ServletEntry>) -> SharedId {
	let info = entry.and_then(ServletEntry::peer_route_info);
	info.expect("a slate entry is peer-routed").dial_addr
}

/// A servlet type of the default namespace named `name`.
fn servlet_type_urn(name: &str) -> Urn<'static> {
	let urn = ColonyNamespace::default().servlet(name);
	urn.expect("test names satisfy the mint grammar")
}

/// The entries of one peer slate dial one socket, so they share one rendering
/// of it.
#[test]
fn a_peer_slate_shares_one_rendering_of_its_socket() {
	let types = [servlet_type_urn("ping"), servlet_type_urn("echo")];
	let peer_id = SharedId::from(&b"gw"[..]);
	let slate = PheromoneConfig::default().peer_slate(&peer_id, admitted_dial(b"127.0.0.1:9000"), types);

	let first = dial_rendering(slate.first());
	let last = dial_rendering(slate.last());
	assert!(Arc::ptr_eq(&first, &last));
}

/// The trails through one relay dial one relay socket, so they share one
/// rendering of it.
#[test]
fn a_relay_trail_shares_one_rendering_of_its_relay_socket() -> Result<(), &'static str> {
	let slate = [peer_entry(b"ping", b"origin"), peer_entry(b"echo", b"origin")];
	let advertisement = admitted(b"origin", b"127.0.0.1:9000", slate);
	let relay_id = SharedId::from(&b"relay"[..]);

	let trail = advertisement.relay_trail(&relay_id, admitted_dial(b"127.0.0.1:9001"), &PheromoneConfig::default());
	let trail = trail.ok_or("a relay other than the origin yields a trail")?;

	let first = dial_rendering(trail.slate.first());
	let last = dial_rendering(trail.slate.last());
	assert!(Arc::ptr_eq(&first, &last));
	Ok(())
}

/// A shared target of another socket leaves an entry the socket its own dial
/// admitted, so a shared rendering never redirects an entry.
#[test]
fn a_shared_target_of_another_socket_leaves_an_entry_its_own_dial() {
	let dial = admitted_dial(b"127.0.0.1:9000");
	let route = PeerRoute { peer_id: Arc::from(&b"gw"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
	let other = DialTarget::of_claimed(admitted_dial(b"127.0.0.1:9001"));

	let entry = ServletEntry::peer_sharing(route, &other, DEFAULT_INITIAL_PHEROMONE, DEFAULT_ABANDONMENT_LIMIT);

	assert_eq!(entry.dial_target().as_bytes(), b"127.0.0.1:9000");
}

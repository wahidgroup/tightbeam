use core::mem::discriminant;
use core::num::{NonZeroU32, NonZeroUsize};
use core::str::from_utf8;
use core::time::Duration;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLockReadGuard};
use std::thread;

use super::entry::LocalRoute;
use super::{
	ClusterError, DialTarget, HiveSlate, KindCaps, PeerCaps, PeerRoute, PheromoneConfig, RouteKind, RoutePlane, Routes,
	ServletEntry, ServletRegistry, SharedId, SlateChange, DEFAULT_ABANDONMENT_LIMIT, DEFAULT_INITIAL_PHEROMONE,
};
use crate::basis_points::BasisPoints;
use crate::clock::{Clock, ManualClock, UnixMillis};
use crate::cms::signed_data::SignerIdentifier;
use crate::colony::cluster::peer::{AdmittedPeerAd, RelayTrail};
use crate::colony::cluster::MAX_PHEROMONE;
use crate::colony::cluster::{AdmittedDial, PeerAddress};
use crate::colony::protocol::ServletInfo;
use crate::colony::urn::ColonyNamespace;
use crate::colony::urn::ServletTypeKey;
use crate::tb_cases;
use crate::testing::fixtures::TestClock;
use crate::testing::TestResult;

/// The abandonment limit of the tests that drive a route to it.
const LIMIT: u32 = 2;

/// A registry on `clock`, for tests that advance it.
fn registry_on(clock: &Arc<ManualClock>) -> ServletRegistry {
	ServletRegistry::new(PheromoneConfig::default(), TestClock::erased(clock))
}

/// A registry whose routes abandon after `limit` failures.
fn registry_abandoning_after(limit: u32) -> ServletRegistry {
	let abandonment_limit = NonZeroU32::new(limit).expect("a test limit is at least one");
	let config = PheromoneConfig { abandonment_limit, ..Default::default() };
	ServletRegistry::new(config, TestClock::manual())
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

/// A registry that holds each of `entries`.
fn registry_holding(entries: impl IntoIterator<Item = ServletEntry>) -> ServletRegistry {
	let registry = ServletRegistry::fixture();
	for entry in entries {
		registry.add(entry).expect("a fresh registry takes each fixture route");
	}

	registry
}

/// The route key of each of `entries`, in order.
fn route_keys(entries: &[Arc<ServletEntry>]) -> Vec<SharedId> {
	entries.iter().map(|entry| Arc::clone(entry.route_key())).collect()
}

/// The owner of each of `entries`, in order.
fn owners(entries: &[Arc<ServletEntry>]) -> Vec<SharedId> {
	entries.iter().map(|entry| Arc::clone(entry.owner_id())).collect()
}

/// The route kind of each of `entries`, in order.
fn kinds(entries: &[Arc<ServletEntry>]) -> Vec<RouteKind> {
	entries.iter().map(|entry| entry.route_kind()).collect()
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

/// A local entry at `addr` that serves `servlet_type` for `hive`, under the
/// fixture servlet's signer, at `pheromone` and the abandonment limit
/// `limit`.
fn local_entry(addr: &[u8], servlet_type: &[u8], hive: &[u8], pheromone: u64, limit: NonZeroU32) -> ServletEntry {
	let route = LocalRoute {
		address: Arc::from(addr),
		servlet_type: Arc::from(servlet_type),
		hive_id: Arc::from(hive),
		signer: ServletInfo::fixture_signer(),
	};

	ServletEntry::local(route, pheromone, limit)
}

/// One local entry with the given pheromone and abandonment limit.
fn test_entry(pheromone: u64, abandonment_limit: u32) -> ServletEntry {
	let abandonment_limit = NonZeroU32::new(abandonment_limit).expect("a test limit is at least one");
	local_entry(b"addr", b"type", b"hive", pheromone, abandonment_limit)
}

/// A local entry at `addr` that serves `servlet_type` for `hive`.
fn named_entry(addr: impl AsRef<[u8]>, servlet_type: impl AsRef<[u8]>, hive: impl AsRef<[u8]>) -> ServletEntry {
	let (addr, servlet_type, hive) = (addr.as_ref(), servlet_type.as_ref(), hive.as_ref());
	local_entry(addr, servlet_type, hive, DEFAULT_INITIAL_PHEROMONE, DEFAULT_ABANDONMENT_LIMIT)
}

/// The signer of a fixture servlet's registration.
fn servlet_signer() -> Arc<SignerIdentifier> {
	Arc::new(ServletInfo::fixture_signer())
}

/// A peer entry for `servlet_type` advertised by `peer_id`, which dials the
/// fixture gateway socket.
fn peer_entry(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>) -> ServletEntry {
	peer_entry_dial(servlet_type, peer_id, b"127.0.0.1:9000")
}

/// A peer entry for `servlet_type` advertised by `peer_id`, which dials the
/// fixture socket `dial`.
fn peer_entry_dial(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>, dial: impl AsRef<[u8]>) -> ServletEntry {
	let dial = from_utf8(dial.as_ref()).expect("fixture dial addresses are UTF-8");
	ServletEntry::peer_fixture(servlet_type, peer_id, dial)
}

/// A peer entry with a specific abandonment limit.
fn peer_entry_limit(servlet_type: impl AsRef<[u8]>, peer_id: impl AsRef<[u8]>, limit: u32) -> ServletEntry {
	let limit = NonZeroU32::new(limit).expect("a test limit is at least one");
	peer_entry(servlet_type, peer_id).with_abandonment_limit(limit)
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

/// An admitted advertisement from `hive` at `dial` that carries `slate`,
/// issued at `order`.
fn admitted_with_order(
	hive: impl AsRef<[u8]>,
	dial: impl AsRef<[u8]>,
	slate: impl IntoIterator<Item = ServletEntry>,
	order: u64,
) -> AdmittedPeerAd {
	let dial = from_utf8(dial.as_ref()).expect("fixture dial addresses are UTF-8");
	AdmittedPeerAd::fixture(hive, dial, slate, order)
}

/// The advertisement of `calc` by `origin` at the fixture socket, issued at
/// `order`.
fn origin_ad(order: u64) -> AdmittedPeerAd {
	admitted_with_order(b"origin", b"127.0.0.1:9000", [peer_entry(b"calc", b"origin")], order)
}

/// The advertisement of `origin` at the fixture socket that names no route,
/// issued at `order`.
fn origin_withdrawal(order: u64) -> AdmittedPeerAd {
	admitted_with_order(b"origin", b"127.0.0.1:9000", Vec::new(), order)
}

/// Installs one direct peer slate for `peer` that dials the fixture socket,
/// and returns what the slate changed.
fn install_peer_slate(
	registry: &ServletRegistry,
	peer: impl AsRef<[u8]>,
	slate: impl IntoIterator<Item = ServletEntry>,
) -> Result<SlateChange, ClusterError> {
	let peer = peer.as_ref();
	registry.reconcile_peer_slate(admitted(peer, b"127.0.0.1:9000", slate), PeerCaps::default())
}

/// Installs `trail` with the default caps, and returns what it changed.
fn install_relay_trail(registry: &ServletRegistry, trail: RelayTrail) -> Result<SlateChange, ClusterError> {
	registry.reconcile_relay_trail(trail, PeerCaps::default())
}

/// The installed and the withdrawn counts of `change`, with 0 for none.
fn counts(change: SlateChange) -> (usize, usize) {
	let installed = change.installed().map_or(0, NonZeroUsize::get);
	let withdrawn = change.withdrawn().map_or(0, NonZeroUsize::get);
	(installed, withdrawn)
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
	let dial = from_utf8(dial.as_ref()).expect("fixture dial addresses are UTF-8");
	let slate = vec![ServletEntry::relay_fixture(origin, relay, servlet_type, dial)];

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
	ServletEntry::relay_fixture(origin, relay, b"ping", "127.0.0.1:9001")
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
fn weaken_times(registry: &ServletRegistry, key: impl AsRef<[u8]>, times: u32) {
	let key = key.as_ref();
	for _ in 0..times {
		registry.weaken(key).expect("a live route lock takes a failure");
	}
}

/// Counts `times` failures against every route attributed to `peer`.
fn weaken_peer_times(registry: &ServletRegistry, peer: impl AsRef<[u8]>, times: u32) {
	let peer = peer.as_ref();
	for _ in 0..times {
		registry.weaken_peer(peer).expect("a live route lock takes a failure");
	}
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
	fn entry_evaporate_pheromone((initial, rate, expected): (u64, u16, u64)) -> TestResult {
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

/// Counts `failures` failures on one entry, and answers whether each one
/// reached the limit.
fn limit_reports(entry: &ServletEntry, failures: usize) -> Vec<bool> {
	(0..failures).map(|_| entry.weaken_to_limit()).collect()
}

/// Only the failure that reaches the limit reports it, and a failure past the
/// limit reports nothing.
#[test]
fn entry_reports_the_failure_that_reaches_its_limit() {
	let entry = test_entry(5000, 3);
	let reached = limit_reports(&entry, 4);
	assert_eq!(reached, vec![false, false, true, false]);
	assert!(entry.is_abandoned());
}

/// An entry at the least abandonment limit, one, is live at its creation, so
/// no limit abandons a route before its first failure.
#[test]
fn an_entry_at_the_least_limit_is_live_at_creation() -> TestResult {
	let entry = test_entry(5000, 1);
	assert!(entry.is_live());
	Ok(())
}

/// A failure against a count at `u32::MAX` leaves the count there, so an
/// abandoned route stays abandoned whatever failures follow.
#[test]
fn a_saturated_trial_count_keeps_its_route_abandoned() -> TestResult {
	let entry = test_entry(5000, 3).with_trials(u32::MAX);
	entry.weaken();
	assert!(entry.is_abandoned());
	Ok(())
}

/// A reinforcement resets the trial count of its entry.
#[test]
fn entry_reinforce_resets_trials() {
	let entry = test_entry(5000, 5);
	weaken_entry_times(&entry, 2);
	entry.reinforce(100);
	assert_eq!(entry.trial_count(), 0);
}

/// A local entry routes as a local route.
#[test]
fn a_local_entry_routes_as_local() {
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

/// A peer entry dials the gateway socket of its peer, and its route key names
/// the peer and the type.
#[test]
fn entry_peer_dials_gateway_not_route_key() {
	let entry = peer_entry(b"calc", b"fp");
	assert_eq!(entry.dial_target().as_bytes(), b"127.0.0.1:9000");
	assert_ne!(entry.dial_target().as_bytes(), entry.route_key().as_ref());
	assert_eq!(entry.route_key().first(), Some(&b'f'));
	assert_eq!(entry.route_key().get(2), Some(&0));
}

/// The peer entries hold the peer routes alone.
#[test]
fn peer_entries_filters_by_route_kind() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"local", b"calc", b"hive1"))?;

	let peer = peer_entry(b"calc", b"peer-colony");
	let route_key = Arc::clone(peer.route_key());

	registry.add(peer)?;

	let peers = registry.peer_entries()?;
	assert_eq!(route_keys(&peers), vec![route_key]);
	Ok(())
}

/// The peer entries leave out a route at its abandonment limit.
#[test]
fn peer_entries_excludes_abandoned() -> TestResult {
	let registry = registry_abandoning_after(LIMIT);
	let peer = peer_entry_limit(b"calc", b"peer-colony", LIMIT);
	let route_key = Arc::clone(peer.route_key());
	registry.add(peer)?;

	weaken_times(&registry, &route_key, LIMIT);

	let peers = registry.peer_entries()?;
	assert!(peers.is_empty());
	Ok(())
}

/// A route of `calc` that a peer advertises.
fn calc_peer_route() -> ServletEntry {
	peer_entry(b"calc", b"peer-colony")
}

// The local entries of a type hold its local routes alone, beside a peer
// route of the type or with none but peer routes.
tb_cases! {
	fn local_entries_for_type_holds_only_local_routes((seed, local): (Vec<ServletEntry>, Vec<SharedId>)) -> TestResult {
		let registry = registry_holding(seed);
		let entries = registry.local_entries_for_type(&type_key(b"calc"))?;
		assert_eq!(route_keys(&entries), local);
		Ok(())
	}
	cases {
		beside_a_peer_route => (
			vec![named_entry(b"local", b"calc", b"hive1"), calc_peer_route()],
			vec![SharedId::from(b"local".as_slice())],
		),
		with_only_peer_routes => (vec![calc_peer_route()], Vec::new()),
	}
}

/// Races two slates for one peer bucket against a reader, and answers
/// whether the reader ever saw the bucket empty.
///
/// Non-empty slates install before they prune, so a serialized registry
/// always holds a seeded slate. An empty read proves that interleaved
/// reconciles pruned each other's fresh installs.
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

/// Two slates for one bucket reconcile one at a time, so a reader sees the
/// bucket held.
#[test]
fn reconcile_peer_slate_serializes_concurrent_slates() -> TestResult {
	let registry = ServletRegistry::fixture();
	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;

	let saw_empty = race_peer_slates(&registry);
	assert!(!saw_empty);
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

/// The local servlets name each type of a local route once, and leave out a
/// type that a peer route alone serves.
#[test]
fn local_servlets_dedups_and_excludes_peer_routes() -> TestResult {
	let registry = ServletRegistry::fixture();
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
fn two_hives_serving_one_type_both_yield_routes() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"a1", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a2", b"calc", b"hive2"))?;

	let routes = registry.entries_for_type(&type_key(b"calc"))?;
	assert_eq!(routes.len(), 2);
	assert_eq!(registry.local_servlets()?.len(), 1);
	Ok(())
}

/// The local servlets follow each add and each removal of a local route.
#[test]
fn local_servlets_tracks_adds_and_removes() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"a1", b"calc", b"hive1"))?;
	registry.add(named_entry(b"a2", b"echo", b"hive1"))?;
	registry.remove(b"a2")?;

	let types = registry.local_servlets()?;
	assert_eq!(types, vec![SharedId::from(b"calc".as_slice())]);
	Ok(())
}

/// A peer slate installs a route for each type it names.
#[test]
fn reconcile_peer_slate_installs_multi_type_slate() -> TestResult {
	let registry = ServletRegistry::fixture();
	let slate = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];
	install_peer_slate(&registry, b"gw", slate)?;
	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

/// A peer slate prunes each route of its bucket that it leaves out.
#[test]
fn reconcile_peer_slate_prunes_stale_routes() -> TestResult {
	let registry = ServletRegistry::fixture();
	let full = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	install_peer_slate(&registry, b"gw", full)?;
	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;

	let peers = registry.peer_entries()?;
	let types: Vec<SharedId> = peers.iter().map(|entry| Arc::clone(entry.servlet_type())).collect();
	assert_eq!(types, vec![SharedId::from(b"urn:t:a".as_slice())]);
	Ok(())
}

/// The servlet types that one slate names.
type SlateTypes = &'static [&'static [u8]];

// A second slate for one bucket counts the routes it adds and the routes it
// leaves out, and a route both slates name counts as neither.
tb_cases! {
	fn reconcile_peer_slate_counts_what_the_slate_changed(
		(first, second, expected): (SlateTypes, SlateTypes, (usize, usize))
	) -> TestResult {
		let registry = ServletRegistry::fixture();
		let slate = |types: SlateTypes| types.iter().map(|servlet| peer_entry(servlet, b"gw")).collect::<Vec<_>>();
		install_peer_slate(&registry, b"gw", slate(first))?;

		let change = install_peer_slate(&registry, b"gw", slate(second))?;
		assert_eq!(counts(change), expected);
		Ok(())
	}
	cases {
		a_refresh_changes_nothing => (&[b"urn:t:a", b"urn:t:b"], &[b"urn:t:a", b"urn:t:b"], (0, 0)),
		a_growth_installs_the_new_route => (&[b"urn:t:a"], &[b"urn:t:a", b"urn:t:b"], (1, 0)),
		a_shrink_withdraws_the_dropped_route => (&[b"urn:t:a", b"urn:t:b"], &[b"urn:t:a"], (0, 1)),
		a_swap_installs_and_withdraws => (&[b"urn:t:a"], &[b"urn:t:b"], (1, 1)),
		an_empty_slate_withdraws_every_route => (&[b"urn:t:a", b"urn:t:b"], &[], (0, 2)),
	}
}

/// A first slate for a bucket counts each of its routes as installed.
#[test]
fn reconcile_peer_slate_counts_a_first_slate_as_installed() -> TestResult {
	let registry = ServletRegistry::fixture();
	let slate = vec![peer_entry(b"urn:t:a", b"gw"), peer_entry(b"urn:t:b", b"gw")];

	let change = install_peer_slate(&registry, b"gw", slate)?;
	assert_eq!(counts(change), (2, 0));
	assert!(change.opens_bucket());
	Ok(())
}

/// A peer slate and its withdrawal leave the local routes of a type in place.
#[test]
fn reconcile_peer_slate_leaves_local_routes_untouched() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"local", b"urn:t:a", b"hive1"))?;

	install_peer_slate(&registry, b"gw", vec![peer_entry(b"urn:t:a", b"gw")])?;
	install_peer_slate(&registry, b"gw", vec![])?;

	assert_eq!(registry.local_entries_for_type(&type_key(b"urn:t:a"))?.len(), 1);
	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

/// A refreshed slate keeps the pheromone and the trials of each route it
/// carries over, and takes the dial it names.
#[test]
fn reconcile_peer_slate_preserves_peer_trail_state() -> TestResult {
	let registry = ServletRegistry::fixture();
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

/// One owner's claim on `claimed`, placed against the registry.
type Claim = fn(&ServletRegistry, &[u8]) -> Result<(), ClusterError>;

/// The hive `hive1` that registers a servlet at `claimed`.
fn claimed_by_the_hive(registry: &ServletRegistry, claimed: &[u8]) -> Result<(), ClusterError> {
	registry.reconcile_by_hive(HiveSlate::of(b"hive1", vec![named_entry(claimed, b"calc", b"hive1")]))
}

/// A peer `gw` that claims `claimed` as its gateway socket.
fn claimed_by_a_peer(registry: &ServletRegistry, claimed: &[u8]) -> Result<(), ClusterError> {
	let claim = admitted(b"gw", claimed, vec![peer_entry_dial(b"calc", b"gw", claimed)]);
	registry.reconcile_peer_slate(claim, PeerCaps::default())?;
	Ok(())
}

/// A second hive that registers a servlet at `claimed`.
fn claimed_by_another_hive(registry: &ServletRegistry, claimed: &[u8]) -> Result<(), ClusterError> {
	registry.reconcile_by_hive(HiveSlate::of(b"hive2", vec![named_entry(claimed, b"calc", b"hive2")]))
}

/// The first owner's claim and its socket, the second owner's claim and its
/// spelling of the socket, and the refusal of the second claim.
type Collision = (Claim, &'static [u8], Claim, &'static [u8], ClusterError);

// The registry refuses a socket that another owner holds, under any
// spelling, to a second hive as to a peer, because a dual-stack host, a
// scope id, and a wildcard listener each reach one socket by more than one
// spelling (CWE-706, CWE-639). A peer may not advertise a socket at which
// the gateway dials a local servlet, and the one decider on the dial axis
// judges the reverse collision too: a hive may not register a servlet at a
// socket where the gateway dials a peer gateway.
tb_cases! {
	fn a_socket_another_owner_holds_is_refused_under_any_spelling(
		(held, socket, claim, claimed, expected): Collision
	) -> TestResult {
		let registry = ServletRegistry::fixture();
		held(&registry, socket)?;

		let refused = claim(&registry, claimed);
		assert_eq!(ClusterError::variant_of(&refused), Some(discriminant(&expected)));
		assert_eq!(registry.len()?, 1);
		Ok(())
	}
	cases {
		peer_by_the_same_spelling => (
			claimed_by_the_hive,
			b"127.0.0.1:9000",
			claimed_by_a_peer,
			b"127.0.0.1:9000",
			ClusterError::PeerSlateConflict,
		),
		hive_after_a_peer_holds_it => (
			claimed_by_a_peer,
			b"127.0.0.1:9000",
			claimed_by_another_hive,
			b"127.0.0.1:9000",
			ClusterError::ServletNotOwned,
		),
		peer_by_the_mapped_spelling => (
			claimed_by_the_hive,
			b"127.0.0.1:9000",
			claimed_by_a_peer,
			b"[::ffff:127.0.0.1]:9000",
			ClusterError::PeerSlateConflict,
		),
		peer_by_a_scoped_spelling => (
			claimed_by_the_hive,
			b"[::1]:9000",
			claimed_by_a_peer,
			b"[::1%7]:9000",
			ClusterError::PeerSlateConflict,
		),
		peer_at_the_loopback_of_a_wildcard_servlet => (
			claimed_by_the_hive,
			b"0.0.0.0:9000",
			claimed_by_a_peer,
			b"127.0.0.1:9000",
			ClusterError::PeerSlateConflict,
		),
		hive_by_the_mapped_spelling => (
			claimed_by_the_hive,
			b"127.0.0.1:9000",
			claimed_by_another_hive,
			b"[::ffff:127.0.0.1]:9000",
			ClusterError::ServletNotOwned,
		),
		hive_by_a_scoped_spelling => (
			claimed_by_the_hive,
			b"[::1]:9000",
			claimed_by_another_hive,
			b"[::1%7]:9000",
			ClusterError::ServletNotOwned,
		),
	}
}

/// A peer may claim a socket at which no local route dials.
#[test]
fn a_peer_may_dial_a_socket_no_local_route_holds() -> TestResult {
	let registry = ServletRegistry::fixture();
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

/// The caps of the peer plane at `max_identities` gateways and
/// `max_routes` routes.
fn peer_caps(max_identities: usize, max_routes: usize) -> KindCaps {
	KindCaps { kind: RouteKind::Peer, max_identities, max_routes }
}

// A slate past the cap of gateways or of routes exceeds the caps, and a
// slate of a known gateway inside them does not. The gateways `fp1` and
// `fp2` hold one route each, so a five-route slate for `fp1` leaves six
// routes, one over a cap of five.
tb_cases! {
	fn slate_exceeds_caps((bucket, routes_after, caps, exceeds): (&[u8], usize, KindCaps, bool)) {
		let registry = registry_holding([peer_entry(b"a", b"fp1"), peer_entry(b"a", b"fp2")]);
		assert_eq!(routes(&registry).slate_exceeds_caps(bucket, routes_after, caps), exceeds);
	}
	cases {
		a_new_gateway_past_the_identity_cap => (b"fp3", 1, peer_caps(2, 1024), true),
		a_known_gateway_inside_the_identity_cap => (b"fp1", 1, peer_caps(2, 1024), false),
		a_slate_past_the_route_cap => (b"fp1", 5, peer_caps(64, 5), true),
		an_empty_slate_inside_any_cap => (b"fp1", 0, peer_caps(1, 1), false),
	}
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

/// The order ledger and the installed slate are one decision, so after the last
/// ad applies, the ledger names the installed slate. A ledger below the
/// installed order would admit a replay older than that slate (CWE-294).
#[test]
fn racing_ads_leave_the_ledger_naming_the_installed_slate() {
	let registry = Arc::new(ServletRegistry::fixture());
	let installed = race_ad_orders(&registry);
	assert_eq!(installed, vec![SharedId::from(b"calc".as_slice())]);
}

/// A fresh direct advertisement reconciles only the origin bucket, so the
/// fallback trail through the relay survives it.
#[test]
fn direct_reconcile_preserves_relay_bucket() -> TestResult {
	let registry = registry_with_a_relay_trail();

	install_peer_slate(&registry, b"origin", vec![peer_entry(b"calc", b"origin")])?;

	let entries = registry.peer_entries()?;
	let calc = SharedId::from(b"calc".as_slice());
	let expected = vec![(RouteKind::Peer, calc.clone()), (RouteKind::PeerRelay, calc)];
	assert_eq!(kinds_and_types(&entries), expected);
	Ok(())
}

/// A withdrawn socket takes every peer route that dials it: the direct route
/// of the peer that advertised it and the relay trail through it. Another
/// peer's direct route stays.
#[test]
fn withdraw_peer_by_dial_drops_the_routes_that_dial_the_socket() -> TestResult {
	let registry = ServletRegistry::fixture();
	install_peer_slate(&registry, b"peer-a", vec![peer_entry(b"ping", b"peer-a")])?;

	let through = relay_trail(b"peer-c", b"peer-a", b"echo", b"127.0.0.1:9000");
	registry.reconcile_relay_trail(through, PeerCaps::default())?;

	let other_slate = vec![peer_entry_dial(b"pong", b"peer-b", b"127.0.0.1:9001")];
	let other = admitted(b"peer-b", b"127.0.0.1:9001", other_slate);

	registry.reconcile_peer_slate(other, PeerCaps::default())?;

	let withdrawn = registry.withdraw_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;
	let live = registry.peer_entries()?;
	assert_eq!(withdrawn, NonZeroUsize::new(2));
	assert_eq!(owners(&live), vec![SharedId::from(b"peer-b".as_slice())]);
	assert_eq!(kinds(&live), vec![RouteKind::Peer]);
	Ok(())
}

/// The peer whose socket is withdrawn stays reachable through its fallback
/// trail, because that trail dials the relay.
#[test]
fn withdraw_peer_by_dial_keeps_the_fallback_trail_through_another_relay() -> TestResult {
	let registry = ServletRegistry::fixture();
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
fn withdraw_peer_by_dial_keeps_a_local_route_at_the_socket() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"127.0.0.1:9000", b"calc", b"hive1"))?;

	let withdrawn = registry.withdraw_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;
	let owner = owner_of(&registry, b"127.0.0.1:9000");
	assert_eq!(withdrawn, None);
	assert_eq!(owner, Some(SharedId::from(b"hive1".as_slice())));
	Ok(())
}

/// A relay trail replaces the routes of its own bucket alone, so the direct
/// route of its origin stays.
#[test]
fn relay_reconcile_replaces_only_its_bucket() -> TestResult {
	let registry = registry_with_a_relay_trail();

	install_relay_trail(&registry, relay_trail(b"origin", b"relay", b"sum", b"127.0.0.1:9001"))?;

	let entries = registry.peer_entries()?;
	let (calc, sum) = (SharedId::from(b"calc".as_slice()), SharedId::from(b"sum".as_slice()));
	let expected = vec![(RouteKind::Peer, calc), (RouteKind::PeerRelay, sum)];
	assert_eq!(kinds_and_types(&entries), expected);
	Ok(())
}

/// A gateway at its direct cap admits a relay trail, because relay buckets
/// spend their own budget.
#[test]
fn relay_buckets_do_not_spend_the_direct_gateway_cap() -> TestResult {
	let registry = ServletRegistry::fixture();
	let caps = PeerCaps { max_gateways: 1, max_relay_buckets: 1, ..Default::default() };
	let ad = origin_ad(0);

	registry.reconcile_peer_slate(ad, caps)?;
	registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps)?;

	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

/// A member that relays many origins creates one bucket per (origin, relay)
/// pair, so the relay-bucket cap bounds how far relay spam inflates buckets.
#[test]
fn relay_bucket_cap_refuses_extra_buckets() -> TestResult {
	let registry = ServletRegistry::fixture();
	let caps = PeerCaps { max_relay_buckets: 1, ..Default::default() };

	registry.reconcile_relay_trail(relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"), caps)?;

	let refused = registry.reconcile_relay_trail(relay_trail(b"other", b"relay", b"calc", b"127.0.0.1:9001"), caps);
	assert!(matches!(refused, Err(ClusterError::PeerCapExceeded)));
	Ok(())
}

/// An origin that withdraws its whole direct slate withdraws its relay
/// fallbacks with it: a relay trail lasts as long as a direct claim.
#[test]
fn empty_direct_slate_clears_relay_trails_for_origin() -> TestResult {
	let registry = registry_with_a_relay_trail();
	install_peer_slate(&registry, b"origin", Vec::new())?;
	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

/// An emptied direct slate counts the relay trails it withdraws with the
/// direct routes, because both leave in the one step.
#[test]
fn empty_direct_slate_counts_the_relay_trails_it_withdraws() -> TestResult {
	let registry = registry_with_a_relay_trail();
	let change = install_peer_slate(&registry, b"origin", Vec::new())?;
	assert_eq!(counts(change), (0, 2));
	Ok(())
}

/// A relay trail is new when its bucket held no route. A refresh of the
/// trail, or a trail that replaces its type, finds the bucket held.
#[test]
fn a_relay_trail_opens_its_bucket_once() -> TestResult {
	let registry = ServletRegistry::fixture();
	let trail = |servlet_type: &[u8]| relay_trail(b"origin", b"relay", servlet_type, b"127.0.0.1:9001");
	let first = registry.reconcile_relay_trail(trail(b"calc"), PeerCaps::default())?;
	let refreshed = registry.reconcile_relay_trail(trail(b"calc"), PeerCaps::default())?;
	let replaced = registry.reconcile_relay_trail(trail(b"sum"), PeerCaps::default())?;

	let opened = [first.opens_bucket(), refreshed.opens_bucket(), replaced.opens_bucket()];
	assert_eq!(opened, [true, false, false]);
	Ok(())
}

/// An install of the route of `calc` that `origin` dials at `dial`, issued
/// at `order`, on one plane.
type Install = fn(&ServletRegistry, &[u8], u64) -> Result<(), ClusterError>;

/// Installs the direct slate of `origin` at `dial`, issued at `order`.
fn direct_at(registry: &ServletRegistry, dial: &[u8], order: u64) -> Result<(), ClusterError> {
	let ad = admitted_with_order(b"origin", dial, vec![peer_entry_dial(b"calc", b"origin", dial)], order);
	registry.reconcile_peer_slate(ad, PeerCaps::default()).map(drop)
}

/// Installs the relay trail of `origin` through `relay` at `dial`, issued at
/// `order`.
fn relay_at(registry: &ServletRegistry, dial: &[u8], order: u64) -> Result<(), ClusterError> {
	let trail = RelayTrail { order: UnixMillis::new(order), ..relay_trail(b"origin", b"relay", b"calc", dial) };
	registry.reconcile_relay_trail(trail, PeerCaps::default()).map(drop)
}

// A replayed advertisement older than the newest applied one regresses no
// bucket, direct or relay.
tb_cases! {
	fn a_stale_ad_order_is_refused(install: Install) -> TestResult {
		let registry = ServletRegistry::fixture();
		install(&registry, b"127.0.0.1:9001", 20)?;

		let refused = install(&registry, b"127.0.0.1:9666", 10);
		assert!(matches!(refused, Err(ClusterError::StalePeerAd)));
		Ok(())
	}
	cases {
		for_a_direct_bucket => direct_at,
		for_a_relay_bucket => relay_at,
	}
}

/// The order ledger keys per bucket: an equal-order refresh reconciles,
/// and each bucket's order gates that bucket alone.
#[test]
fn equal_ad_order_reconciles_idempotently() -> TestResult {
	let registry = ServletRegistry::fixture();
	let first = origin_ad(20);
	registry.reconcile_peer_slate(first, PeerCaps::default())?;

	let refresh = origin_ad(20);
	registry.reconcile_peer_slate(refresh, PeerCaps::default())?;
	registry.reconcile_relay_trail(
		relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001"),
		PeerCaps::default(),
	)?;

	assert_eq!(registry.peer_entries()?.len(), 2);
	Ok(())
}

/// A withdrawal leaves a tombstone in the order ledger, so the registry
/// refuses a replayed older advertisement inside the freshness window, and the
/// routes the origin withdrew stay withdrawn.
#[test]
fn withdrawal_tombstone_refuses_older_ad_reinstall() -> TestResult {
	// The unbounded window pins the retain rule itself: the outcome
	// must not depend on how much time elapses between statements.
	let clock = TestClock::manual();
	let registry = registry_on(&clock).with_ad_tombstone_window(Duration::MAX);
	let issued = clock.unix().get();
	let install = origin_ad(issued);
	registry.reconcile_peer_slate(install, PeerCaps::default())?;

	let withdrawal = origin_withdrawal(issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default())?;

	let replayed = origin_ad(issued);
	let result = registry.reconcile_peer_slate(replayed, PeerCaps::default());
	assert!(matches!(result, Err(ClusterError::StalePeerAd)));
	Ok(())
}

/// Past the window the freshness gate refuses the replayed frame
/// itself, so the ledger prunes the dead bucket's tombstone and stays
/// bounded.
#[test]
fn expired_tombstone_prunes_from_the_ledger() -> TestResult {
	let clock = TestClock::manual();
	let registry = registry_on(&clock).with_ad_tombstone_window(Duration::ZERO);
	let issued = clock.unix().get().saturating_sub(10);
	let install = origin_ad(issued);
	registry.reconcile_peer_slate(install, PeerCaps::default())?;

	let withdrawal = origin_withdrawal(issued + 1);
	registry.reconcile_peer_slate(withdrawal, PeerCaps::default())?;

	assert_eq!(routes(&registry).ad_order_rows(), 0);
	Ok(())
}

/// A registry on a manual clock with one direct route and one relay trail
/// for `origin`, both installed at the clock's start.
fn registry_with_relay_trail(clock: &Arc<ManualClock>) -> ServletRegistry {
	let registry = registry_on(clock);
	let ad = origin_ad(0);
	registry
		.reconcile_peer_slate(ad, PeerCaps::default())
		.expect("the direct slate installs");

	let trail = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	registry
		.reconcile_relay_trail(trail, PeerCaps::default())
		.expect("the relay trail installs");
	registry
}

/// The registry of [`registry_with_relay_trail`] on a clock that the test
/// leaves still.
fn registry_with_a_relay_trail() -> ServletRegistry {
	registry_with_relay_trail(&TestClock::manual())
}

/// The rank of `kind` in the order local, peer, relay, which sorts the
/// route kinds a test reads.
fn rank(kind: RouteKind) -> u8 {
	match kind {
		RouteKind::Local => 0,
		RouteKind::Peer => 1,
		RouteKind::PeerRelay => 2,
	}
}

/// The route kind and the servlet type of each of `entries`, sorted by
/// kind.
fn kinds_and_types(entries: &[Arc<ServletEntry>]) -> Vec<(RouteKind, SharedId)> {
	let mut read: Vec<(RouteKind, SharedId)> = entries
		.iter()
		.map(|entry| (entry.route_kind(), Arc::clone(entry.servlet_type())))
		.collect();
	read.sort_by_key(|(kind, _)| rank(*kind));
	read
}

/// The route kinds left in a registry after a prune at `max_age`, and how
/// many routes that prune dropped.
fn kinds_after_prune(registry: &ServletRegistry, max_age: Duration) -> Result<(usize, Vec<RouteKind>), ClusterError> {
	let pruned = registry.prune_stale_relay_trails(max_age)?.map_or(0, NonZeroUsize::get);
	let mut kinds = kinds(&registry.peer_entries()?);
	kinds.sort_by_key(|kind| rank(*kind));

	Ok((pruned, kinds))
}

// Relay trails refresh only through reconciles, so age past `max_age` is
// the retirement signal. A trail exactly at the age stays, so the boundary
// row pins `>` against `>=`. The prune leaves direct trails in place.
tb_cases! {
	fn prune_stale_relay_trails_judges_age((elapsed, pruned, kinds): (Duration, usize, Vec<RouteKind>)) -> TestResult {
		let clock = TestClock::manual();
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
fn a_refreshed_relay_trail_survives_the_prune() -> TestResult {
	let clock = TestClock::manual();
	let registry = registry_with_relay_trail(&clock);

	clock.advance(Duration::from_secs(601));

	let refresh = relay_trail(b"origin", b"relay", b"calc", b"127.0.0.1:9001");
	registry.reconcile_relay_trail(RelayTrail { order: UnixMillis::new(1), ..refresh }, PeerCaps::default())?;

	let pruned = registry.prune_stale_relay_trails(Duration::from_secs(600))?;
	assert_eq!(pruned, None);
	Ok(())
}

// `weaken_peer` weakens every trail attributed to an identity: its own
// direct routes, the relay trails learned for it, and every relay trail
// that forwards through it.
tb_cases! {
	fn weaken_peer_scores_every_trail_of_the_identity((peer, weakened): (&[u8], usize)) -> TestResult {
		let registry = registry_holding([peer_entry(b"urn:t:a", b"relay")]);
		install_relay_trail(&registry, relay_trail(b"origin", b"relay", b"urn:t:a", b"127.0.0.1:9001"))?;

		let reached = registry.weaken_peer(peer)?;
		assert_eq!(reached.count(), weakened);
		Ok(())
	}
	cases {
		through_the_relay => (b"relay", 2),
		learned_for_the_origin => (b"origin", 1),
	}
}

/// A slate of a new gateway past the cap of gateways is refused, and the routes
/// held stay.
#[test]
fn reconcile_peer_slate_refuses_over_gateway_cap() -> TestResult {
	let registry = ServletRegistry::fixture();
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
			let registry = ServletRegistry::fixture();
			// Either racer may be the one refused, so the test discards both
			// outcomes and reads what the bucket holds afterwards.
			thread::scope(|scope| {
				scope.spawn(|| {
					let slate = HiveSlate::of(b"gw", vec![named_entry(b"gw", b"calc", b"gw")]);
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

/// A local install and a peer slate that race for one bucket leave it to one
/// plane.
#[test]
fn racing_slates_for_one_bucket_leave_it_to_one_plane() {
	let rounds = 500;
	let settled = rounds_with_one_plane_holding_the_bucket(rounds);
	assert_eq!(settled, rounds);
}

/// The registry refuses a peer advertisement whose bucket bytes equal a hive
/// id once that hive's routes sit under the bucket, because the hive and the
/// peer are different owners even when their bytes agree (CWE-639).
#[test]
fn a_peer_cannot_advertise_under_a_hives_bucket() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.reconcile_by_hive(HiveSlate::of(b"gw", vec![named_entry(b"addr1", b"calc", b"gw")]))?;

	let refused = install_peer_slate(&registry, b"gw", vec![peer_entry(b"calc", b"gw")]);
	assert!(matches!(refused, Err(ClusterError::PeerSlateConflict)));
	assert_eq!(owner_of(&registry, b"addr1"), Some(SharedId::from(b"gw".as_slice())));
	assert!(registry.peer_entries()?.is_empty());
	Ok(())
}

/// A hive whose id equals a peer's fingerprint bytes may not register
/// under that bucket: the slate swap would sweep the peer's routes, so the
/// one decider refuses the sweep before anything moves (CWE-639).
#[test]
fn a_hive_cannot_sweep_a_peers_bucket() -> TestResult {
	let registry = ServletRegistry::fixture();
	install_peer_slate(&registry, b"peer", vec![peer_entry(b"calc", b"peer")])?;

	let refused =
		registry.reconcile_by_hive(HiveSlate::of(b"peer", vec![named_entry(b"local-addr", b"calc", b"peer")]));
	assert!(matches!(refused, Err(ClusterError::ServletNotOwned)));
	assert!(routes(&registry).get(b"local-addr").is_none());
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

/// The retirement of a hive takes only the routes it owns, so a peer's routes
/// under the same bucket bytes survive it.
#[test]
fn removing_a_hive_leaves_a_peers_routes_under_the_same_bucket() -> TestResult {
	let registry = ServletRegistry::fixture();
	install_peer_slate(&registry, b"shared", vec![peer_entry(b"calc", b"shared")])?;

	let removed = registry.remove_by_hive(b"shared")?;
	assert!(removed.is_empty());
	assert_eq!(registry.peer_entries()?.len(), 1);
	Ok(())
}

/// The registry admits a peer advertisement when a local servlet shares its
/// bucket bytes as an address: the keys and sockets differ, so both routes
/// stay.
#[test]
fn a_peer_may_share_bytes_with_a_local_address() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"gw", b"calc", b"hive1"))?;
	install_peer_slate(&registry, b"gw", vec![peer_entry(b"calc", b"gw")])?;
	assert_eq!(registry.len()?, 2);
	Ok(())
}

/// An added route resolves by its servlet type.
#[test]
fn an_added_route_resolves_by_its_type() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(named_entry(b"addr1", b"calculator", b"hive1"))?;

	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	assert_eq!(route_keys(&found), vec![SharedId::from(b"addr1".as_slice())]);
	Ok(())
}

/// A registry that registered one route twice at one address.
fn seed_reregistered_registry() -> ServletRegistry {
	let route = || named_entry(b"addr1", b"calculator", b"hive1");
	registry_holding([route(), route()])
}

/// A route registered twice at one address keeps one row in the type index.
#[test]
fn a_reregistration_keeps_one_index_row() -> TestResult {
	let registry = seed_reregistered_registry();
	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	assert_eq!(found.len(), 1);
	assert_eq!(registry.len()?, 1);
	Ok(())
}

/// A route registered again under another type moves to that type.
#[test]
fn a_reregistration_moves_the_route_to_its_new_type() -> TestResult {
	let registry = ServletRegistry::fixture();
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
fn a_hive_cannot_take_over_another_hives_address() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.reconcile_by_hive(HiveSlate::of(b"hive-b", vec![named_entry(b"addr-b", b"calc", b"hive-b")]))?;
	let slate = HiveSlate::of(
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

/// A removal of a route registered twice clears it from its type.
#[test]
fn a_removal_after_a_reregistration_clears_the_route() -> TestResult {
	let registry = seed_reregistered_registry();
	registry.remove(b"addr1")?;

	let found = registry.entries_for_type(&type_key(b"calculator"))?;
	assert!(found.is_empty());
	Ok(())
}

/// The sweep drops a local route and a peer route at their limit, and counts
/// the peer route alone.
#[test]
fn remove_abandoned_drops_routes_at_their_limit() -> TestResult {
	let registry = registry_abandoning_after(LIMIT);
	registry.add(test_entry(5000, LIMIT))?;
	let peer = peer_entry_limit(b"urn:t:a", b"fp-a", LIMIT);
	let peer_key = Arc::clone(peer.route_key());
	registry.add(peer)?;

	weaken_times(&registry, b"addr", LIMIT);
	weaken_times(&registry, &peer_key, LIMIT);

	let removed = registry.remove_abandoned()?;
	assert_eq!(removed, NonZeroUsize::new(1));
	assert_eq!(registry.len()?, 0);
	Ok(())
}

// A weakening of a peer reaches every route that peer advertised and no
// route of another peer, and no local route of a hive of the same name.
tb_cases! {
	fn weaken_peer_reaches_the_routes_of_one_peer(
		(seed, peer, weakened): (Vec<ServletEntry>, &[u8], usize)
	) -> TestResult {
		let registry = registry_holding(seed);

		let reached = registry.weaken_peer(peer)?;
		assert_eq!(reached.count(), weakened);
		Ok(())
	}
	cases {
		all_routes_of_one_peer => (
			vec![peer_entry(b"urn:t:a", b"fp-a"), peer_entry(b"urn:t:b", b"fp-a"), peer_entry(b"urn:t:a", b"fp-b")],
			b"fp-a",
			2,
		),
		no_local_route => (vec![named_entry(b"addr", b"urn:t:a", b"hive-a")], b"hive-a", 0),
	}
}

/// A peer weakened to its limit abandons its routes, and the routes of another
/// peer stay live.
#[test]
fn weaken_peer_abandons_after_limit_leaving_others_live() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", LIMIT))?;
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-b", LIMIT))?;

	weaken_peer_times(&registry, b"fp-a", LIMIT);

	let live = registry.peer_entries()?;
	assert_eq!(owners(&live), vec![SharedId::from(b"fp-b".as_slice())]);
	Ok(())
}

/// A weakening of a peer reaches none of its routes that are already abandoned.
#[test]
fn weaken_peer_skips_already_abandoned_routes() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", LIMIT))?;
	weaken_peer_times(&registry, b"fp-a", LIMIT);

	let weakened = registry.weaken_peer(b"fp-a")?;
	assert_eq!(weakened.count(), 0);
	Ok(())
}

/// The three peer routes of the weakening by socket: two of `fp-a` at
/// `127.0.0.1:9100` and one of `fp-b` at `127.0.0.1:9200`.
fn routes_at_two_sockets() -> Vec<ServletEntry> {
	vec![
		peer_entry_dial(b"urn:t:a", b"fp-a", b"127.0.0.1:9100"),
		peer_entry_dial(b"urn:t:b", b"fp-a", b"127.0.0.1:9100"),
		peer_entry_dial(b"urn:t:a", b"fp-b", b"127.0.0.1:9200"),
	]
}

// A weakening by socket reaches the routes that dial the matching gateway
// alone, and none for a gateway the registry does not know.
tb_cases! {
	fn weaken_peer_by_dial_reaches_the_routes_at_the_socket((dial, weakened): (&str, usize)) -> TestResult {
		let registry = registry_holding(routes_at_two_sockets());
		let reached = registry.weaken_peer_by_dial(PeerAddress::fixture(dial))?;
		assert_eq!(reached.count(), weakened);
		Ok(())
	}
	cases {
		a_matching_gateway => ("127.0.0.1:9100", 2),
		an_unknown_gateway => ("127.0.0.1:9999", 0),
	}
}

/// The count of routes that one weakening of `peer` reaches, beside the
/// count it abandons.
fn weakening(registry: &ServletRegistry, peer: &[u8]) -> (usize, usize) {
	let weakened = registry.weaken_peer(peer).expect("a live route lock takes a weakening");
	(weakened.count(), weakened.abandoned().map_or(0, NonZeroUsize::get))
}

/// Each weakening counts the routes it reached, and the one that drives them
/// to their limit counts them as abandoned. A weakening past the limit
/// reaches no live route.
#[test]
fn weaken_peer_counts_the_routes_it_abandons() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", LIMIT))?;
	registry.add(peer_entry_limit(b"urn:t:b", b"fp-a", LIMIT))?;
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-b", LIMIT))?;

	let rounds = [
		weakening(&registry, b"fp-a"),
		weakening(&registry, b"fp-a"),
		weakening(&registry, b"fp-a"),
	];
	assert_eq!(rounds, [(2, 0), (2, 2), (0, 0)]);
	Ok(())
}

/// A weakening by socket counts the routes it reached and the routes it
/// abandoned.
#[test]
fn weaken_peer_by_dial_counts_the_routes_it_abandons() -> TestResult {
	let registry = ServletRegistry::fixture();
	registry.add(peer_entry_limit(b"urn:t:a", b"fp-a", 1))?;
	registry.add(peer_entry(b"urn:t:b", b"fp-a"))?;

	let weakened = registry.weaken_peer_by_dial(PeerAddress::fixture("127.0.0.1:9000"))?;
	assert_eq!(weakened.count(), 2);
	assert_eq!(weakened.abandoned().map(NonZeroUsize::get), Some(1));
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
fn calc_routes(registry: &ServletRegistry) -> Vec<(SharedId, SharedId)> {
	let entries = registry.entries_for_type(&type_key(b"calc")).expect("a live route lock reads");
	let mut found: Vec<(SharedId, SharedId)> = route_keys(&entries).into_iter().zip(owners(&entries)).collect();
	found.sort();
	found
}

// The registry checks every entry before any map moves, so a refused update
// leaves the registry as seeded, and an accepted one lands whole.
tb_cases! {
	fn apply_address_update_ownership_and_atomicity(case: ApplyAddressUpdateCase) -> TestResult {
		let registry = ServletRegistry::fixture();
		registry.add(named_entry(case.seed.0, case.seed.1, case.seed.2))?;

		let added = HiveSlate::of(case.caller_hive, case.add.map(|(a, t, h)| named_entry(a, t, h)));
		let result = registry.apply_address_update(added, case.remove);
		assert_eq!(ClusterError::variant_of(&result), case.expected.as_ref().map(discriminant));

		let expected_routes: Vec<(SharedId, SharedId)> = case
			.expected_routes
			.iter()
			.map(|(address, owner)| (SharedId::from(*address), SharedId::from(*owner)))
			.collect();
		assert_eq!(calc_routes(&registry), expected_routes);
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

/// The slate of the trail of `advertisement` through `relay`, which dials
/// the relay at the fixture socket `127.0.0.1:9001`.
fn relay_slate_of(advertisement: &AdmittedPeerAd, relay: &[u8]) -> Vec<ServletEntry> {
	let trail = advertisement.relay_trail(
		&SharedId::from(relay),
		admitted_dial(b"127.0.0.1:9001"),
		&PheromoneConfig::default(),
	);
	trail.expect("a relay other than the origin yields a trail").slate
}

/// The entries of one peer slate dial one socket, so they share one rendering
/// of it.
#[test]
fn a_peer_slate_shares_one_rendering_of_its_socket() {
	let types = [
		ColonyNamespace::servlet_fixture("ping"),
		ColonyNamespace::servlet_fixture("echo"),
	];

	let peer_id = SharedId::from(&b"gw"[..]);
	let slate = PheromoneConfig::default().peer_slate(&peer_id, admitted_dial(b"127.0.0.1:9000"), types);

	let first = dial_rendering(slate.first());
	let last = dial_rendering(slate.last());
	assert!(Arc::ptr_eq(&first, &last));
}

/// The trails through one relay dial one relay socket, so they share one
/// rendering of it.
#[test]
fn a_relay_trail_shares_one_rendering_of_its_relay_socket() {
	let slate = [peer_entry(b"ping", b"origin"), peer_entry(b"echo", b"origin")];
	let advertisement = admitted(b"origin", b"127.0.0.1:9000", slate);

	let slate = relay_slate_of(&advertisement, b"relay");
	let (first, last) = (dial_rendering(slate.first()), dial_rendering(slate.last()));
	assert!(Arc::ptr_eq(&first, &last));
}

/// A shared target of another socket leaves each entry on the socket its own
/// dial admitted, so a shared rendering never redirects an entry.
#[test]
fn a_shared_target_of_another_socket_leaves_an_entry_its_own_dial() {
	let dial = admitted_dial(b"127.0.0.1:9000");
	let route = PeerRoute { peer_id: Arc::from(&b"gw"[..]), servlet_type: Arc::from(&b"ping"[..]), dial };
	let other = DialTarget::of_claimed(admitted_dial(b"127.0.0.1:9001"));

	let entry = ServletEntry::peer_sharing(route, &other, DEFAULT_INITIAL_PHEROMONE, DEFAULT_ABANDONMENT_LIMIT);
	assert_eq!(entry.dial_target().as_bytes(), b"127.0.0.1:9000");
}

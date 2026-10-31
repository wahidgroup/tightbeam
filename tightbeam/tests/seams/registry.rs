//! A hive runs on an outside [`ServletRegistry`] over a [`BTreeMap`], which
//! has no `Default`. The hive registers, replaces, stops, and refuses servlets
//! through it, and refuses the registry when it holds a registration. The
//! registry answers the type of an instance through the provided
//! [`ServletRegistry::servlet_type`].

#![cfg(all(feature = "colony", feature = "tcp"))]

use core::future::{ready, Ready};
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tightbeam::colony::hive::{
	Hive, HiveConfig, HiveError, HiveRuntime, RefusedRegistration, ReplacedServlet, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

use super::StopProbe;
use crate::common::hive::servlet_urn;
use crate::common::result::TestResult;

/// The instance key under which a hive registers a [`StopProbe`].
const INSTANCE_KEY: &[u8] = b"urn:tightbeam::servlet:outside/127.0.0.1:7100";

/// A hive that stores its servlets in an [`OutsideRegistry`].
type OutsideHive = HiveRuntime<TokioListener, OutsideRegistry>;

/// The registrations of an [`OutsideRegistry`], which each clone of the
/// registry shares.
type Shelf = Arc<Mutex<BTreeMap<Vec<u8>, ServletRegistration>>>;

/// A [`ServletRegistry`] an outside crate writes, over a [`BTreeMap`].
///
/// The registry holds at most `capacity` instances. Each clone shares the
/// map, so the test reads what the hive stored through a clone of its own.
#[derive(Clone)]
struct OutsideRegistry {
	shelf: Shelf,
	capacity: usize,
}

impl OutsideRegistry {
	/// A registry that holds at most `capacity` instances.
	fn holding(capacity: usize) -> Self {
		Self { shelf: Shelf::default(), capacity }
	}

	/// Locks the map, and recovers a poisoned lock, because each write
	/// under the guard is one map insert, remove, or drain.
	fn map(&self) -> MutexGuard<'_, BTreeMap<Vec<u8>, ServletRegistration>> {
		self.shelf.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

impl ServletRegistry for OutsideRegistry {
	/// Refuses a new key once the registry holds `capacity` instances, with
	/// [`TransitStatus::ResourceExhausted`].
	fn insert(
		&self,
		key: impl Into<Vec<u8>>,
		registration: ServletRegistration,
	) -> Result<Option<ReplacedServlet>, Box<RefusedRegistration>> {
		let key: Vec<u8> = key.into();
		let mut map = self.map();
		let full = map.len() >= self.capacity && !map.contains_key(&key);
		if full {
			let error = TightBeamError::WorkRefused(TransitStatus::ResourceExhausted);
			return Err(Box::new(RefusedRegistration { error, registration }));
		}

		let replaced = map.insert(key, registration);
		Ok(replaced.map(ReplacedServlet::new))
	}

	fn remove(&self, key: impl AsRef<[u8]>) -> Option<ServletRegistration> {
		self.map().remove(key.as_ref())
	}

	fn for_each<F>(&self, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		self.map().iter().for_each(|(key, registration)| f(key, registration));
	}

	fn for_each_by_type<F>(&self, prefix: impl AsRef<[u8]>, mut f: F)
	where
		F: FnMut(&Vec<u8>, &ServletRegistration),
	{
		let prefix = prefix.as_ref();
		let map = self.map();
		let typed = map.iter().filter(|(key, _)| key.starts_with(prefix));
		typed.for_each(|(key, registration)| f(key, registration));
	}

	fn count(&self) -> usize {
		self.map().len()
	}

	fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)> {
		let map = self.map();
		let address_of = |registration: &ServletRegistration| {
			let address = registration.servlet.addr_bytes().to_vec();
			(registration.servlet_type.clone(), address)
		};

		map.values().map(address_of).collect()
	}

	fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)> {
		core::mem::take(&mut *self.map()).into_iter().collect()
	}

	fn keys(&self) -> Vec<Vec<u8>> {
		self.map().keys().cloned().collect()
	}
}

/// The spawner of a [`StopProbe`], which a test never calls.
fn no_spawn(_trace: Arc<TraceCollector>) -> Ready<Result<StopProbe, TightBeamError>> {
	ready(Err(TightBeamError::NotEstablished))
}

/// The type URN that a [`StopProbe`] registers under.
fn outside_type() -> Urn<'static> {
	servlet_urn("outside")
}

/// A provisional hive that stores its servlets in `registry`, which shares its
/// map with the caller's clone.
fn outside_hive(registry: &OutsideRegistry) -> OutsideHive {
	let hive = OutsideHive::with_registry(HiveConfig::default(), registry.clone());
	hive.expect("a registry that holds no registration takes a hive")
}

/// A provisional hive on an outside registry of no bound, beside a clone of
/// that registry.
fn unbounded_hive() -> (OutsideRegistry, OutsideHive) {
	let registry = OutsideRegistry::holding(usize::MAX);
	let hive = outside_hive(&registry);
	(registry, hive)
}

/// An [`unbounded_hive`] that holds one registered [`StopProbe`], beside the
/// flag that the probe sets when it stops.
fn hive_holding_a_probe() -> (OutsideRegistry, OutsideHive, Arc<AtomicBool>) {
	let (registry, mut hive) = unbounded_hive();
	let (servlet, stopped) = StopProbe::new();
	let registered = hive.register(outside_type(), servlet, no_spawn);
	registered.expect("a registry of no bound takes the probe");
	(registry, hive, stopped)
}

/// A hive stores each servlet it registers in the outside registry it runs on.
#[test]
fn a_hive_registers_its_servlet_in_an_outside_registry() -> TestResult {
	let (registry, mut hive) = unbounded_hive();
	let (servlet, _stopped) = StopProbe::new();

	hive.register(outside_type(), servlet, no_spawn)?;

	assert_eq!(registry.keys(), [INSTANCE_KEY]);
	Ok(())
}

/// An outside registry on the provided `servlet_type` answers the type of each
/// instance through the default walk of its registrations.
#[test]
fn an_outside_registry_answers_the_type_of_an_instance_through_the_provided_walk() {
	let (registry, _hive, _stopped) = hive_holding_a_probe();
	let servlet_type = registry.servlet_type(INSTANCE_KEY);
	assert_eq!(servlet_type, Some(outside_type()));
}

/// A registration under an instance the outside registry holds replaces it,
/// and the hive stops the replaced servlet while the replacing one runs.
#[test]
fn a_hive_stops_the_servlet_that_an_outside_registry_replaces() -> TestResult {
	let (_registry, mut hive) = unbounded_hive();
	let (replaced, replaced_stopped) = StopProbe::new();
	let (replacing, replacing_stopped) = StopProbe::new();

	hive.register(outside_type(), replaced, no_spawn)?;
	hive.register(outside_type(), replacing, no_spawn)?;

	let replaced_stop = replaced_stopped.load(Ordering::SeqCst);
	let replacing_stop = replacing_stopped.load(Ordering::SeqCst);
	assert_eq!((replaced_stop, replacing_stop), (true, false));
	Ok(())
}

/// A running hive drains the outside registry as it stops, and stops each
/// servlet that the registry held.
#[tokio::test]
async fn a_running_hive_stops_each_servlet_its_outside_registry_holds() -> TestResult {
	let (registry, mut hive, stopped) = hive_holding_a_probe();

	hive.establish(Arc::new(TraceCollector::new())).await?;
	hive.stop();

	assert_eq!((stopped.load(Ordering::SeqCst), registry.count()), (true, 0));
	Ok(())
}

/// An outside registry that refuses a registration fails the hive's register
/// with the registry's own error, and the hive stops the refused servlet.
#[test]
fn a_hive_stops_the_servlet_that_an_outside_registry_refuses() {
	let registry = OutsideRegistry::holding(0);
	let mut hive = outside_hive(&registry);
	let (servlet, stopped) = StopProbe::new();

	let registered = hive.register(outside_type(), servlet, no_spawn);
	assert!(matches!(
		registered,
		Err(TightBeamError::WorkRefused(TransitStatus::ResourceExhausted))
	));
	assert!(stopped.load(Ordering::SeqCst));
}

/// A hive refuses an occupied outside registry and stops its servlet.
#[test]
fn a_hive_refuses_an_outside_registry_that_holds_a_registration() -> TestResult {
	let registry = OutsideRegistry::holding(usize::MAX);
	let (servlet, stopped) = StopProbe::new();
	let spawner: SpawnerFn = Arc::new(|_| Box::pin(async { Err(TightBeamError::NotEstablished) }));
	let registration = ServletRegistration { servlet: Box::new(servlet), spawner, servlet_type: outside_type() };
	let inserted = registry.insert(INSTANCE_KEY, registration);
	// An empty registry replaces no servlet, so the insert answers `None`.
	let _replaced = inserted.map_err(|refused| refused.stop_servlet())?;

	let refused = OutsideHive::with_registry(HiveConfig::default(), registry.clone()).err();
	assert!(matches!(refused, Some(TightBeamError::HiveError(HiveError::OccupiedRegistry))));
	assert!(stopped.load(Ordering::SeqCst));
	Ok(())
}

//! A hive runs on an outside [`ServletRegistry`] over a [`BTreeMap`], which
//! has no `Default`. The hive registers, replaces, stops, and refuses servlets
//! through it, and refuses the registry when it holds a registration. The
//! registry answers the type of an instance through the provided
//! [`ServletRegistry::servlet_type`].

#![cfg(all(feature = "std", feature = "colony", feature = "tcp"))]

use core::future::{ready, Ready};
use core::sync::atomic::{AtomicBool, Ordering};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::colony::hive::{
	Hive, HiveConfig, HiveError, HiveRuntime, RefusedRegistration, ReplacedServlet, ServletBox, ServletRegistration,
	ServletRegistry, SpawnerFn,
};
use tightbeam::colony::urn::ColonyNamespace;
use tightbeam::policy::TransitStatus;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

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

/// A [`ServletBox`] whose stop the test reads, because a hive stops a servlet
/// through [`ServletBox::stop_boxed`] alone.
struct StopProbe {
	stopped: Arc<AtomicBool>,
}

impl ServletBox for StopProbe {
	fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::from(b"127.0.0.1:7100".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {
		self.stopped.store(true, Ordering::SeqCst);
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}
}

/// A [`StopProbe`] and the flag it sets when it stops.
fn probe() -> (StopProbe, Arc<AtomicBool>) {
	let stopped = Arc::new(AtomicBool::new(false));
	let probe = StopProbe { stopped: Arc::clone(&stopped) };
	(probe, stopped)
}

/// The spawner of a [`StopProbe`], which a test never calls.
fn no_spawn(_trace: Arc<TraceCollector>) -> Ready<Result<StopProbe, TightBeamError>> {
	ready(Err(TightBeamError::NotEstablished))
}

/// The type URN that a [`StopProbe`] registers under.
fn outside_type() -> Urn<'static> {
	let servlet_type = ColonyNamespace::default().servlet("outside");
	servlet_type.expect("test names satisfy the mint grammar")
}

/// A provisional hive that stores its servlets in `registry`, which shares its
/// map with the caller's clone.
fn outside_hive(registry: &OutsideRegistry) -> Result<OutsideHive, TightBeamError> {
	OutsideHive::with_registry(HiveConfig::default(), registry.clone())
}

/// A hive stores each servlet it registers in the outside registry it runs on.
#[test]
fn a_hive_registers_its_servlet_in_an_outside_registry() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(usize::MAX);
	let mut hive = outside_hive(&registry)?;
	let (servlet, _stopped) = probe();

	hive.register(outside_type(), servlet, no_spawn)?;

	assert_eq!(registry.keys(), [INSTANCE_KEY]);
	Ok(())
}

/// An outside registry on the provided `servlet_type` answers the type of each
/// instance through the default walk of its registrations.
#[test]
fn an_outside_registry_answers_the_type_of_an_instance_through_the_provided_walk() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(usize::MAX);
	let mut hive = outside_hive(&registry)?;
	let (servlet, _stopped) = probe();

	hive.register(outside_type(), servlet, no_spawn)?;

	assert_eq!(registry.servlet_type(INSTANCE_KEY), Some(outside_type()));
	Ok(())
}

/// A registration under an instance the outside registry holds replaces it,
/// and the hive stops the replaced servlet while the replacing one runs.
#[test]
fn a_hive_stops_the_servlet_that_an_outside_registry_replaces() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(usize::MAX);
	let mut hive = outside_hive(&registry)?;
	let (replaced, replaced_stopped) = probe();
	let (replacing, replacing_stopped) = probe();

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
async fn a_running_hive_stops_each_servlet_its_outside_registry_holds() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(usize::MAX);
	let mut hive = outside_hive(&registry)?;
	let (servlet, stopped) = probe();

	hive.register(outside_type(), servlet, no_spawn)?;
	hive.establish(Arc::new(TraceCollector::new())).await?;
	hive.stop();

	assert_eq!((stopped.load(Ordering::SeqCst), registry.count()), (true, 0));
	Ok(())
}

/// An outside registry that refuses a registration fails the hive's register
/// with the registry's own error, and the hive stops the refused servlet.
#[test]
fn a_hive_stops_the_servlet_that_an_outside_registry_refuses() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(0);
	let mut hive = outside_hive(&registry)?;
	let (servlet, stopped) = probe();

	let registered = hive.register(outside_type(), servlet, no_spawn);
	let refused = matches!(registered, Err(TightBeamError::WorkRefused(TransitStatus::ResourceExhausted)));
	assert_eq!((refused, stopped.load(Ordering::SeqCst)), (true, true));
	Ok(())
}

/// A hive refuses an occupied outside registry and stops its servlet.
#[test]
fn a_hive_refuses_an_outside_registry_that_holds_a_registration() -> Result<(), TightBeamError> {
	let registry = OutsideRegistry::holding(usize::MAX);
	let (servlet, stopped) = probe();
	let spawner: SpawnerFn = Arc::new(|_| Box::pin(async { Err(TightBeamError::NotEstablished) }));
	let registration = ServletRegistration { servlet: Box::new(servlet), spawner, servlet_type: outside_type() };
	let _replaced = registry
		.insert(INSTANCE_KEY, registration)
		.map_err(|refused| refused.stop_servlet())?;

	let refused = outside_hive(&registry).err();
	let occupied = matches!(refused, Some(TightBeamError::HiveError(HiveError::OccupiedRegistry)));
	assert_eq!((occupied, stopped.load(Ordering::SeqCst)), (true, true));
	Ok(())
}

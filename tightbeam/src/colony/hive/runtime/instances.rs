//! Keeps a hive's servlet registry and its routing context in agreement for
//! every servlet instance.

use std::sync::{Arc, Mutex, PoisonError};

use crate::colony::hive::runtime::{DrainMode, HiveContextImpl};
use crate::colony::hive::{
	HiveScalingConfig, RefusedRegistration, ServletBox, ServletPlacement, ServletRegistration, ServletRegistry,
};
use crate::transport::Protocol;
use crate::urn::Urn;
use crate::{Errorizable, TightBeamError};

/// Why [`HiveInstances::insert`] registered no servlet.
///
/// Whatever the cause, the insert stops the servlet through
/// [`ServletBox::stop_boxed`] before it returns, so the caller only chooses its
/// answer. A refusal of the address or of the registry carries its cause as
/// the error's source.
#[derive(Debug, Errorizable)]
pub enum InsertRefusal {
	/// The hive is draining, so it takes no instance (CWE-362).
	#[error("the hive is draining")]
	Draining,
	/// The type holds the most instances its bounds admit (CWE-770).
	#[error("the servlet type holds the most instances its bounds admit")]
	AtCapacity,
	/// The servlet's address is not a valid instance locator, so no URN
	/// names it. The servlet keeps that address, so a retry changes
	/// nothing.
	#[error("the servlet's address is not a valid instance locator: {0}")]
	#[source]
	Unnameable(TightBeamError),
	/// The registry refused the registration.
	#[error("the servlet registry refused the registration: {0}")]
	#[source]
	Registry(TightBeamError),
}

/// Why [`HiveInstances::remove`] removed no instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Errorizable)]
pub(crate) enum RemoveRefusal {
	/// The key names no instance that the registry holds.
	#[error("the registry holds no instance under the key")]
	Absent,
	/// The servlet type holds the fewest instances its bounds admit.
	#[error("the servlet type holds the fewest instances its bounds admit")]
	AtFloor,
}

/// An instance that [`HiveInstances::remove`] took out, which the caller
/// reports to the cluster.
pub(crate) struct Removed {
	/// The type URN of the removed instance.
	pub(crate) servlet_type: Urn<'static>,
	/// The address the removed instance answered at.
	pub(crate) address: Arc<[u8]>,
}

/// The outcome of one move of the instance set, and the servlet it took out,
/// which stops once the admission lock drops.
struct Settled<T> {
	outcome: T,
	retired: Option<Box<dyn ServletBox>>,
}

impl<T> Settled<T> {
	/// Stops the servlet the move took out, and returns the outcome.
	fn stop_retired(self) -> T {
		if let Some(servlet) = self.retired {
			servlet.stop_boxed();
		}

		self.outcome
	}
}

/// One hive's servlet instances and the routes that reach them.
///
/// Each move touches the registry first, then the routes, so a route names
/// only a live instance. The two sit behind separate locks, so the pair is
/// eventually consistent: each step commits on its own lock and stays
/// committed.
///
/// # Admission
///
/// Every insert, removal, and drain holds the hive's admission lock, so the
/// drain read, the bound check, and the write are one step (CWE-362,
/// CWE-367). The locks always go in one order: admission, registry, routes.
pub struct HiveInstances<'a, R: ServletRegistry, P: Protocol> {
	servlets: &'a R,
	routes: &'a HiveContextImpl<P>,
	/// The lock that every move of the instance set holds.
	admission: &'a Mutex<()>,
	/// The drain state, which a drain enters and an insert reads.
	drain: &'a DrainMode,
	/// The instance bounds of each servlet type.
	scaling: &'a HiveScalingConfig,
}

impl<'a, R: ServletRegistry, P: Protocol> HiveInstances<'a, R, P> {
	/// Views `servlets` and the `routes` that reach them as one instance set.
	pub fn new(
		servlets: &'a R,
		routes: &'a HiveContextImpl<P>,
		admission: &'a Mutex<()>,
		drain: &'a DrainMode,
		scaling: &'a HiveScalingConfig,
	) -> Self {
		Self { servlets, routes, admission, drain, scaling }
	}

	/// Runs `step`, one whole move of the instance set, under the admission
	/// lock, then stops the servlet the step took out.
	///
	/// The stop runs after the lock drops, because a servlet's stop is outside
	/// code and every move of the hive waits on the lock. The lock guards `()`,
	/// so a poisoned lock holds no damaged state, and the guard recovers it.
	fn under_admission<T>(&self, step: impl FnOnce() -> Settled<T>) -> T {
		let settled = {
			let _admission = self.admission.lock().unwrap_or_else(PoisonError::into_inner);
			step()
		};

		settled.stop_retired()
	}

	/// Registers one servlet and its route, and returns where the servlet
	/// sits, which the caller reports to the cluster.
	///
	/// - A servlet that names no signer gets no route, because a sibling admits
	///   a servlet's answer by that signer alone (CWE-346).
	/// - A replaced instance retires as in [`Self::remove`]: its route leaves before the new one lands.
	/// - Each servlet the insert refuses or replaces stops through
	///   [`ServletBox::stop_boxed`] once the admission lock drops.
	///
	/// # Errors
	///
	/// - [`InsertRefusal::Draining`] -- the hive is draining, so a late spawn adds no instance.
	/// - [`InsertRefusal::AtCapacity`] -- the type is at its bound, less any instance at the same address.
	/// - [`InsertRefusal::Unnameable`] -- the servlet's address is not a valid instance locator.
	/// - [`InsertRefusal::Registry`] -- the registry refused the registration, so the insert adds no route.
	pub(crate) fn insert(&self, registration: ServletRegistration) -> Result<ServletPlacement, InsertRefusal> {
		self.under_admission(|| self.place(registration))
	}

	/// Places one servlet and its route under the lock [`Self::insert`] holds,
	/// and hands out each servlet the move stops.
	fn place(&self, registration: ServletRegistration) -> Settled<Result<ServletPlacement, InsertRefusal>> {
		if self.drain.is_draining() {
			return Settled { outcome: Err(InsertRefusal::Draining), retired: Some(registration.servlet) };
		}

		let placement = match registration.placement() {
			Ok(placement) => placement,
			Err(error) => {
				let outcome = Err(InsertRefusal::Unnameable(error));
				return Settled { outcome, retired: Some(registration.servlet) };
			}
		};

		let key_bytes = placement.instance.canonical_bytes();
		let current = self.instances_of(&registration.servlet_type, Some(&key_bytes));
		let bounds = self.scaling.scale_config(&registration.servlet_type);
		if !bounds.admits_instance(current) {
			return Settled { outcome: Err(InsertRefusal::AtCapacity), retired: Some(registration.servlet) };
		}

		let type_key = registration.servlet_type.canonical_bytes();
		// The route map and the registry each own a key, so the bytes clone.
		let route_key = key_bytes.clone();

		// The registry takes the instance first, so a route exists only for a
		// registered instance.
		let replaced = match self.servlets.insert(key_bytes, registration) {
			Ok(replaced) => replaced,
			Err(refused) => {
				let RefusedRegistration { error, registration } = *refused;
				let outcome = Err(InsertRefusal::Registry(error));
				return Settled { outcome, retired: Some(registration.servlet) };
			}
		};
		// A replaced instance shares its key, its type, and its address with
		// its replacement, so the slate entry of that address stands. Its route
		// leaves here, and its servlet stops once the admission lock drops.
		let retired = replaced.and_then(|replaced| {
			replaced.retire(|registration| {
				let address = registration.servlet.addr_bytes();
				self.leave(&route_key, &registration.servlet_type, &address);
			})
		});

		if let Some(signer) = &placement.signer {
			let address = Arc::clone(&placement.address);
			self.routes.add_route(route_key, address, Arc::clone(signer), &type_key);
		}

		Settled { outcome: Ok(placement), retired }
	}

	/// Removes one instance: its registry entry, then its route, then the
	/// servlet itself, which stops once the admission lock drops.
	///
	/// Returns the removed type URN and address, which callers notify the
	/// cluster with. A type that holds the fewest instances its bounds admit
	/// keeps its instance.
	///
	/// # Errors
	///
	/// - [`RemoveRefusal::Absent`] -- `key` names no instance.
	/// - [`RemoveRefusal::AtFloor`] -- the servlet type holds the fewest instances its bounds admit.
	pub(crate) fn remove(&self, key: impl AsRef<[u8]>) -> Result<Removed, RemoveRefusal> {
		let key = key.as_ref();
		self.under_admission(|| self.take(key))
	}

	/// Takes the instance under `key` and its route out of the hive under the
	/// admission lock that [`Self::remove`] holds, and hands out its servlet.
	fn take(&self, key: &[u8]) -> Settled<Result<Removed, RemoveRefusal>> {
		let Some(servlet_type) = self.servlets.servlet_type(key) else {
			return Settled { outcome: Err(RemoveRefusal::Absent), retired: None };
		};

		let current = self.instances_of(&servlet_type, None);
		let bounds = self.scaling.scale_config(&servlet_type);
		if !bounds.spares_instance(current) {
			return Settled { outcome: Err(RemoveRefusal::AtFloor), retired: None };
		}

		// 1. The registry gives the instance up first, so a registration that
		//    lands on the key while it leaves replaces nothing.
		let Some(ServletRegistration { servlet, servlet_type, .. }) = self.servlets.remove(key) else {
			return Settled { outcome: Err(RemoveRefusal::Absent), retired: None };
		};
		let address = servlet.addr_bytes();

		// 2. The route leaves before the servlet stops, so a sibling call in
		//    this window resolves another instance or no route.
		self.leave(key, &servlet_type, &address);

		// 3. The servlet stops once nothing routes to it and the admission
		//    lock drops.
		Settled { outcome: Ok(Removed { servlet_type, address }), retired: Some(servlet) }
	}

	/// Enters drain and takes every instance out of the registry under one
	/// hold of the admission lock, and returns each registration, so its
	/// caller stops the servlets after the lock drops.
	///
	/// An insert reads the drain state under the same lock, so a spawn that
	/// outlives the drain adds no instance, whichever path drains the hive.
	pub(crate) fn drain_all(&self) -> Vec<ServletRegistration> {
		self.under_admission(|| {
			self.drain.begin();
			let drained = self.servlets.drain_all().into_iter();
			let registrations = drained.map(|(_, registration)| registration).collect();

			Settled { outcome: registrations, retired: None }
		})
	}

	/// Counts the instances of `servlet_type` that the registry holds, less
	/// the one under `besides`.
	fn instances_of(&self, servlet_type: &Urn<'_>, besides: Option<&[u8]>) -> usize {
		let mut count = 0usize;
		let type_prefix = servlet_type.type_prefix_bytes();
		self.servlets.for_each_by_type(type_prefix, |held, _| {
			if besides != Some(held.as_slice()) {
				count = count.saturating_add(1);
			}
		});

		count
	}

	/// Takes the route of the instance of `servlet_type` at `address` under
	/// `key` away, ahead of the stop of its servlet.
	fn leave(&self, key: &[u8], servlet_type: &Urn<'static>, address: &Arc<[u8]>) {
		let removed_type = servlet_type.canonical_bytes();
		self.routes.remove_route(key, servlet_type, &removed_type, address);
	}
}

#[cfg(test)]
mod tests {
	use core::error::Error;
	use core::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::hive::{HashMapRegistry, HiveContext, ReplacedServlet, ServletScaleConfig, SpawnerFn};
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::router::RouterError;
	use crate::testing::TestMessage;
	use crate::transport::client::{ConnectionBuilder, ConnectionPool};
	use crate::transport::TokioListener;
	use crate::{encode, Frame};

	/// A [`ServletBox`] whose stop is observable.
	///
	/// The shipped servlet runtime stops by aborting its accept task, which
	/// leaves a test nothing to read, so this probe records the call.
	struct StopProbe {
		stopped: Arc<AtomicBool>,
		signer: Option<SignerIdentifier>,
	}

	impl ServletBox for StopProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7001".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {
			self.stopped.store(true, Ordering::SeqCst);
		}

		fn signer(&self) -> Option<&SignerIdentifier> {
			self.signer.as_ref()
		}
	}

	/// A [`ServletBox`] that reads the hive's routes for its own type at the
	/// instant the hive stops it.
	///
	/// The order of a removal is observable only from inside the stop, so
	/// this probe records whether a route names its type at that instant.
	struct RouteProbe {
		routes: Arc<HiveContextImpl<TokioListener>>,
		servlet_type: Urn<'static>,
		routed_at_stop: Arc<AtomicBool>,
		signer: SignerIdentifier,
	}

	impl ServletBox for RouteProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7002".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {
			let routed = self.routes.resolves(&self.servlet_type);
			self.routed_at_stop.store(routed, Ordering::SeqCst);
		}

		fn signer(&self) -> Option<&SignerIdentifier> {
			Some(&self.signer)
		}
	}

	/// A [`ServletBox`] that reads, at the instant the hive stops it, whether
	/// the admission lock is free.
	///
	/// A stop is code an outside crate writes, and every move of the hive
	/// waits on that lock, so this probe records whether its stop ran with
	/// the lock free.
	struct LockProbe {
		admission: Arc<Mutex<()>>,
		free_at_stop: Arc<AtomicBool>,
	}

	impl ServletBox for LockProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7003".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {
			let free = self.admission.try_lock().is_ok();
			self.free_at_stop.store(free, Ordering::SeqCst);
		}

		fn signer(&self) -> Option<&SignerIdentifier> {
			None
		}
	}

	/// A [`ServletRegistry`] that refuses every insert.
	///
	/// The shipped registry takes every registration, so only a double reaches
	/// the trait's refusal arm, which a consumer registry may reach. It refuses
	/// with [`TightBeamError::NonceExhausted`], which nothing else on the
	/// insert path produces, so the test can tell that refusal apart.
	#[derive(Default)]
	struct RefusingRegistry;

	impl ServletRegistry for RefusingRegistry {
		fn insert(
			&self,
			_key: impl Into<Vec<u8>>,
			registration: ServletRegistration,
		) -> Result<Option<ReplacedServlet>, Box<RefusedRegistration>> {
			Err(Box::new(RefusedRegistration {
				error: TightBeamError::NonceExhausted,
				registration,
			}))
		}

		fn remove(&self, _key: impl AsRef<[u8]>) -> Option<ServletRegistration> {
			None
		}

		fn for_each<F>(&self, _f: F)
		where
			F: FnMut(&Vec<u8>, &ServletRegistration),
		{
		}

		fn for_each_by_type<F>(&self, _prefix: impl AsRef<[u8]>, _f: F)
		where
			F: FnMut(&Vec<u8>, &ServletRegistration),
		{
		}

		fn slate(&self) -> Vec<ServletInfo> {
			Vec::new()
		}

		fn count(&self) -> usize {
			0
		}

		fn addresses(&self) -> Vec<(Urn<'static>, Vec<u8>)> {
			Vec::new()
		}

		fn drain_all(&self) -> Vec<(Vec<u8>, ServletRegistration)> {
			Vec::new()
		}

		fn keys(&self) -> Vec<Vec<u8>> {
			Vec::new()
		}
	}

	/// Returns the spawner every probe registration carries. The insert under
	/// test reads no spawner, so this one spawns a plain [`StopProbe`].
	fn probe_spawner() -> SpawnerFn {
		Arc::new(|_| {
			let probe = StopProbe { stopped: Arc::default(), signer: None };
			Box::pin(async move { Ok(Box::new(probe) as Box<dyn ServletBox>) })
		})
	}

	/// Builds a registration of one [`StopProbe`] under `servlet_type` that
	/// names `signer`.
	fn probe_registration(
		servlet_type: Urn<'static>,
		stopped: &Arc<AtomicBool>,
		signer: Option<SignerIdentifier>,
	) -> ServletRegistration {
		let probe = StopProbe { stopped: Arc::clone(stopped), signer };
		ServletRegistration { servlet: Box::new(probe), spawner: probe_spawner(), servlet_type }
	}

	/// Builds a registration of one [`RouteProbe`] under `servlet_type`. The
	/// probe reads `routes` for that type when it stops.
	fn route_probe_registration(
		routes: &Arc<HiveContextImpl<TokioListener>>,
		servlet_type: &Urn<'static>,
		routed_at_stop: &Arc<AtomicBool>,
	) -> ServletRegistration {
		let probe = RouteProbe {
			routes: Arc::clone(routes),
			servlet_type: servlet_type.clone(),
			routed_at_stop: Arc::clone(routed_at_stop),
			signer: ServletInfo::fixture_signer(),
		};
		let spawner = probe_spawner();

		ServletRegistration { servlet: Box::new(probe), spawner, servlet_type: servlet_type.clone() }
	}

	/// Builds empty routes over a fresh pool, which the tests leave idle.
	fn routes() -> HiveContextImpl<TokioListener> {
		HiveContextImpl::new(Arc::new(ConnectionPool::<TokioListener>::builder().build()))
	}

	/// The admission lock, the drain state, and the type bounds that the
	/// instance set of a test reads.
	#[derive(Default)]
	struct Admission {
		hold: Arc<Mutex<()>>,
		drain: DrainMode,
		scaling: HiveScalingConfig,
	}

	impl Admission {
		/// An admission that bounds the `echo` type to one instance.
		fn single_instance() -> Self {
			let bounds = ServletScaleConfig::new(1, 1, crate::bps!(8000), crate::bps!(2000));
			let bounds = bounds.expect("one instance is a legal range");
			let mut admission = Self::default();
			admission.scaling.overrides.insert(echo_type(), bounds);
			admission
		}

		/// Views `servlets` and `routes` as one instance set.
		fn instances<'a, R: ServletRegistry>(
			&'a self,
			servlets: &'a R,
			routes: &'a HiveContextImpl<TokioListener>,
		) -> HiveInstances<'a, R, TokioListener> {
			HiveInstances::new(servlets, routes, &self.hold, &self.drain, &self.scaling)
		}

		/// Builds a registration of one [`LockProbe`] under the `echo` type,
		/// which reads this admission's lock as it stops and sets
		/// `free_at_stop` to what it found.
		fn lock_probe(&self, free_at_stop: &Arc<AtomicBool>) -> ServletRegistration {
			let probe = LockProbe { admission: Arc::clone(&self.hold), free_at_stop: Arc::clone(free_at_stop) };
			let spawner = probe_spawner();

			ServletRegistration { servlet: Box::new(probe), spawner, servlet_type: echo_type() }
		}
	}

	/// The servlet type of every probe.
	fn echo_type() -> Urn<'static> {
		let servlet_type = ColonyNamespace::default().servlet("echo");
		servlet_type.expect("test names satisfy the mint grammar")
	}

	/// Builds a frame to call a sibling with.
	fn call_frame() -> Frame {
		let message = encode(&TestMessage { content: "ping".into() }).expect("a test message encodes");

		Frame::v0(b"call", message)
	}

	/// A refused registry insert adds no route and stops the servlet the one
	/// way the trait names.
	#[tokio::test]
	async fn a_refused_registry_insert_leaves_no_route() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = RefusingRegistry;
		let routes = routes();
		let stopped = Arc::new(AtomicBool::new(false));
		let registration = probe_registration(servlet_type.clone(), &stopped, Some(ServletInfo::fixture_signer()));

		let admission = Admission::default();
		let inserted = admission.instances(&servlets, &routes).insert(registration);
		assert!(matches!(inserted, Err(InsertRefusal::Registry(TightBeamError::NonceExhausted))));

		let unrouted = routes.call(&servlet_type, call_frame()).await;
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		assert!(stopped.load(Ordering::SeqCst));
		Ok(())
	}

	/// The map registry hands back the registration it replaces as a value
	/// whose drop stops the servlet, so a caller that drops it leaves no
	/// servlet running.
	#[test]
	fn a_replaced_registration_that_its_caller_drops_stops_its_servlet() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let replaced = Arc::new(AtomicBool::new(false));
		let first = servlets.insert(b"echo".to_vec(), probe_registration(servlet_type.clone(), &replaced, None));
		first.map_err(|refused| refused.stop_servlet())?;

		let second = servlets.insert(b"echo".to_vec(), probe_registration(servlet_type, &Arc::default(), None));
		drop(second.map_err(|refused| refused.stop_servlet())?);

		assert!(replaced.load(Ordering::SeqCst));
		Ok(())
	}

	/// A registration of an instance the hive holds replaces it, and the
	/// replaced servlet stops the one way the trait names.
	#[test]
	fn a_replaced_registration_stops_its_servlet() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		let instances = admission.instances(&servlets, &routes);
		let replaced = Arc::new(AtomicBool::new(false));
		let replacing = Arc::new(AtomicBool::new(false));

		instances.insert(probe_registration(servlet_type.clone(), &replaced, None))?;
		instances.insert(probe_registration(servlet_type, &replacing, None))?;

		assert!(replaced.load(Ordering::SeqCst));
		assert!(!replacing.load(Ordering::SeqCst));
		assert_eq!(servlets.count(), 1);
		Ok(())
	}

	/// A removal drops the route before it stops the servlet, so no call in
	/// the removal window resolves a stopped instance.
	#[tokio::test]
	async fn a_removed_instance_loses_its_route_before_it_stops() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let routes = Arc::new(routes());
		let routed_at_stop = Arc::new(AtomicBool::new(true));
		let registration = route_probe_registration(&routes, &servlet_type, &routed_at_stop);
		let admission = Admission::default();
		let instances = admission.instances(&servlets, &routes);
		let placed = instances.insert(registration)?;

		instances.insert(probe_registration(servlet_type, &Arc::default(), None))?;
		instances.remove(placed.instance.canonical_bytes())?;

		assert!(!routed_at_stop.load(Ordering::SeqCst));
		Ok(())
	}

	/// A servlet that names no signer registers and gets no route, because a
	/// sibling's dial admits a servlet's answer by that signer alone
	/// (CWE-346).
	#[tokio::test]
	async fn an_unsigned_servlet_registers_with_no_route() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let registration = probe_registration(servlet_type.clone(), &Arc::default(), None);

		Admission::default().instances(&servlets, &routes).insert(registration)?;

		let unrouted = routes.call(&servlet_type, call_frame()).await;
		assert_eq!(servlets.count(), 1);
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		Ok(())
	}

	/// A draining hive refuses an insert and stops the servlet it refused,
	/// so a spawn that outlived the drain leaves nothing running.
	#[test]
	fn a_draining_hive_refuses_an_insert_and_stops_its_servlet() {
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		admission.drain.begin();

		let stopped = Arc::new(AtomicBool::new(false));
		let registration = probe_registration(echo_type(), &stopped, None);

		let inserted = admission.instances(&servlets, &routes).insert(registration);
		assert!(matches!(inserted, Err(InsertRefusal::Draining)));
		assert!(stopped.load(Ordering::SeqCst));
	}

	/// A registration that replaces the instance at its own address takes no
	/// place of its own, so a type at its bound admits it.
	#[test]
	fn a_replacement_at_the_bound_is_admitted() -> Result<(), Box<dyn Error>> {
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::single_instance();
		let instances = admission.instances(&servlets, &routes);
		instances.insert(probe_registration(echo_type(), &Arc::default(), None))?;
		instances.insert(probe_registration(echo_type(), &Arc::default(), None))?;

		assert_eq!(servlets.count(), 1);
		Ok(())
	}

	/// A drain enters the drain state under the hold that empties the set, so
	/// an insert that lands after it adds no instance, whichever path drained
	/// the hive (CWE-362).
	#[test]
	fn a_drained_instance_set_refuses_a_later_insert() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		let instances = admission.instances(&servlets, &routes);
		instances.drain_all();

		let inserted = instances.insert(probe_registration(servlet_type, &Arc::default(), None));
		assert!(matches!(inserted, Err(InsertRefusal::Draining)));
		Ok(())
	}

	/// A removed servlet stops once the admission lock drops, so a stop that
	/// blocks holds up no other move of the hive.
	#[test]
	fn a_removed_servlet_stops_once_the_admission_lock_drops() -> Result<(), Box<dyn Error>> {
		let servlet_type = ColonyNamespace::default().servlet("echo")?;
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		let instances = admission.instances(&servlets, &routes);
		let free_at_stop = Arc::new(AtomicBool::new(false));
		let placed = instances.insert(admission.lock_probe(&free_at_stop))?;

		instances.insert(probe_registration(servlet_type, &Arc::default(), None))?;
		instances.remove(placed.instance.canonical_bytes())?;

		assert!(free_at_stop.load(Ordering::SeqCst));
		Ok(())
	}

	/// A servlet that the hive refuses stops once the admission lock drops.
	#[test]
	fn a_refused_servlet_stops_once_the_admission_lock_drops() -> Result<(), Box<dyn Error>> {
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		admission.drain.begin();

		let instances = admission.instances(&servlets, &routes);
		let free_at_stop = Arc::new(AtomicBool::new(false));

		let refused = instances.insert(admission.lock_probe(&free_at_stop)).is_err();
		assert_eq!((refused, free_at_stop.load(Ordering::SeqCst)), (true, true));
		Ok(())
	}

	/// A servlet that a registration at its own address replaces stops once
	/// the admission lock drops.
	#[test]
	fn a_replaced_servlet_stops_once_the_admission_lock_drops() -> Result<(), Box<dyn Error>> {
		let servlets = HashMapRegistry::default();
		let routes = routes();
		let admission = Admission::default();
		let instances = admission.instances(&servlets, &routes);
		let free_at_stop = Arc::new(AtomicBool::new(false));

		instances.insert(admission.lock_probe(&free_at_stop))?;
		instances.insert(admission.lock_probe(&Arc::default()))?;

		assert!(free_at_stop.load(Ordering::SeqCst));
		Ok(())
	}
}

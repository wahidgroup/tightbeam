//! Keeps a hive's servlet registry and its routing context in agreement for
//! every servlet instance.

use std::sync::{Arc, Mutex, PoisonError};

use crate::colony::hive::gates::CommandRefusal;
use crate::colony::hive::runtime::{DrainMode, HiveContextImpl};
use crate::colony::hive::{
	HiveScalingConfig, RefusedRegistration, ReplacedServlet, ServletBox, ServletPlacement, ServletRegistration,
	ServletRegistry,
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

impl InsertRefusal {
	/// The name of this refusal, the label of the scale record it draws.
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Draining => "Draining",
			Self::AtCapacity => "AtCapacity",
			Self::Unnameable(_) => "Unnameable",
			Self::Registry(_) => "Registry",
		}
	}
}

impl From<InsertRefusal> for TightBeamError {
	/// The error of a registration that the instance set refused: the cause
	/// of a refused address or registry, and the status a command answers for
	/// a type at its bound or a hive that drains.
	fn from(refusal: InsertRefusal) -> Self {
		match refusal {
			InsertRefusal::Unnameable(error) | InsertRefusal::Registry(error) => error,
			InsertRefusal::Draining | InsertRefusal::AtCapacity => {
				let status = CommandRefusal::from(refusal).status();
				Self::WorkRefused(status)
			}
		}
	}
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

impl RemoveRefusal {
	/// The name of this refusal, the label of the scale record it draws.
	pub(crate) fn as_str(&self) -> &'static str {
		match self {
			Self::Absent => "Absent",
			Self::AtFloor => "AtFloor",
		}
	}
}

/// An instance that [`HiveInstances::remove`] took out, which the caller
/// reports to the cluster.
pub(crate) struct Removed {
	/// The type URN of the removed instance.
	pub(crate) servlet_type: Urn<'static>,
	/// The address the removed instance answered at.
	pub(crate) address: Arc<[u8]>,
}

/// A servlet that one move of the instance set took out, which stops once
/// the admission lock drops.
enum Retired {
	/// A servlet that the move refused or removed, which stops through
	/// [`ServletBox::stop_boxed`].
	Servlet(Box<dyn ServletBox>),
	/// A registration that the registry gave up for its replacement, which
	/// stops its servlet as it drops.
	Replaced(ReplacedServlet),
}

impl Retired {
	/// Stops the servlet this value holds.
	fn stop(self) {
		match self {
			Self::Servlet(servlet) => servlet.stop_boxed(),
			Self::Replaced(replaced) => drop(replaced),
		}
	}
}

/// The outcome of one move of the instance set, and the servlet it took out,
/// which stops once the admission lock drops.
struct Settled<T> {
	outcome: T,
	retired: Option<Retired>,
}

impl<T> Settled<T> {
	/// The outcome of a move that takes `servlet` out of the hive.
	fn retiring(outcome: T, servlet: Box<dyn ServletBox>) -> Self {
		Self { outcome, retired: Some(Retired::Servlet(servlet)) }
	}

	/// Stops the servlet the move took out, and returns the outcome.
	fn stop_retired(self) -> T {
		if let Some(retired) = self.retired {
			retired.stop();
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
	/// - A replacement's route takes over the route of the instance it
	///   replaces in place, so its type keeps a route.
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
			return Settled::retiring(Err(InsertRefusal::Draining), registration.servlet);
		}

		let placement = match registration.placement() {
			Ok(placement) => placement,
			Err(error) => {
				let outcome = Err(InsertRefusal::Unnameable(error));
				return Settled::retiring(outcome, registration.servlet);
			}
		};

		let key_bytes = placement.instance.canonical_bytes();
		let current = self.instances_of(&registration.servlet_type, Some(&key_bytes));
		let bounds = self.scaling.scale_config(&registration.servlet_type);
		if !bounds.admits_instance(current) {
			return Settled::retiring(Err(InsertRefusal::AtCapacity), registration.servlet);
		}

		// The registry takes the registration, so the route step keeps its own
		// copy of the key and of the type key.
		let type_key = registration.servlet_type.canonical_bytes();
		let route_key = key_bytes.clone();

		// The registry takes the instance first, so a route exists only for a
		// registered instance.
		let replaced = match self.servlets.insert(key_bytes, registration) {
			Ok(replaced) => replaced,
			Err(refused) => {
				let RefusedRegistration { error, registration } = *refused;
				let outcome = Err(InsertRefusal::Registry(error));
				return Settled::retiring(outcome, registration.servlet);
			}
		};

		// A replaced instance shares its key, its type, and its address with
		// its replacement, so the slate entry of that address stands, and its
		// servlet stops once the admission lock drops.
		let previous = replaced.as_ref().and_then(ReplacedServlet::registration);
		match (&placement.signer, previous) {
			// The new route takes the key and the type index over in place,
			// so the type keeps a route throughout the replacement.
			(Some(signer), _) => {
				let address = Arc::clone(&placement.address);
				self.routes.add_route(route_key, address, Arc::clone(signer), &type_key);
			}
			// A servlet that names no signer has no route, so the route of the
			// instance it replaces leaves, under the type that instance names.
			(None, Some(previous)) => self.leave(&route_key, &previous.servlet_type, &placement.address),
			(None, None) => {}
		}

		let retired = replaced.map(Retired::Replaced);
		Settled { outcome: Ok(placement), retired }
	}

	/// Removes one instance: its registry entry, then its route, then the
	/// servlet itself, which stops once the admission lock drops.
	///
	/// Returns the removed type URN and address, which callers notify the
	/// cluster with.
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
		Settled::retiring(Ok(Removed { servlet_type, address }), servlet)
	}

	/// Enters drain and takes every instance out of the registry under one
	/// hold of the admission lock, and returns each registration, so its
	/// caller drains or stops the servlets after the lock drops.
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
	use core::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::colony::hive::fixtures::{echo_type, Probe};
	use crate::colony::hive::{HashMapRegistry, HiveContext, ReplacedServlet, ServletScaleConfig};
	use crate::colony::protocol::ServletInfo;
	use crate::router::RouterError;
	use crate::testing::{TestMessage, TestResult};
	use crate::transport::client::{ConnectionBuilder, ConnectionPool};
	use crate::transport::TokioListener;
	use crate::{encode, Frame};

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

	/// The address of the probe that each instance test registers.
	const PROBE: &[u8] = b"127.0.0.1:7001";

	/// A registration of the probe under the `echo` type, which sets
	/// `stopped` as it stops and names `signer`.
	fn probe(stopped: &Arc<AtomicBool>, signer: Option<SignerIdentifier>) -> ServletRegistration {
		Probe::at(PROBE).flagging(stopped).signed(signer).registration(echo_type())
	}

	/// A registration of the probe under the `echo` type, which names no
	/// signer and runs no step as it stops.
	fn idle() -> ServletRegistration {
		Probe::at(PROBE).registration(echo_type())
	}

	/// A hive's registry and its routes over an idle pool, with the admission
	/// lock, the drain state, and the type bounds that its instance set reads.
	struct Hive<R = HashMapRegistry> {
		servlets: R,
		routes: Arc<HiveContextImpl<TokioListener>>,
		hold: Arc<Mutex<()>>,
		drain: DrainMode,
		scaling: HiveScalingConfig,
	}

	impl<R: ServletRegistry + Default> Default for Hive<R> {
		fn default() -> Self {
			let pool = Arc::new(ConnectionPool::<TokioListener>::builder().build());
			let routes = Arc::new(HiveContextImpl::new(pool));
			let (hold, drain, scaling) = Default::default();
			Self { servlets: R::default(), routes, hold, drain, scaling }
		}
	}

	impl Hive {
		/// A hive over a map registry that holds no instance, has begun no
		/// drain, and bounds no type.
		fn new() -> Self {
			Self::default()
		}

		/// A hive that bounds the `echo` type to one instance.
		fn single_instance() -> Self {
			let mut hive = Self::default();
			let bounds = ServletScaleConfig::single_instance();
			hive.scaling.overrides.insert(echo_type(), bounds);
			hive
		}

		/// A hive whose drain has begun.
		fn draining() -> Self {
			let hive = Self::default();
			hive.drain.begin();
			hive
		}
	}

	impl<R: ServletRegistry> Hive<R> {
		/// The registry and the routes of this hive as one instance set.
		fn instances(&self) -> HiveInstances<'_, R, TokioListener> {
			HiveInstances::new(&self.servlets, &self.routes, &self.hold, &self.drain, &self.scaling)
		}

		/// A registration of the probe under the `echo` type, which reads the
		/// admission lock of this hive as it stops and sets `free_at_stop` to
		/// what it found.
		fn lock_probe(&self, free_at_stop: &Arc<AtomicBool>) -> ServletRegistration {
			let (hold, free) = (Arc::clone(&self.hold), Arc::clone(free_at_stop));
			let read = move || free.store(hold.try_lock().is_ok(), Ordering::SeqCst);

			Probe::at(b"127.0.0.1:7003").on_stop(read).registration(echo_type())
		}

		/// A registration of the probe under the `echo` type, which reads the
		/// routes of this hive for that type as it stops and sets
		/// `routed_at_stop` to what it found.
		fn route_probe(&self, routed_at_stop: &Arc<AtomicBool>) -> ServletRegistration {
			let (routes, routed) = (Arc::clone(&self.routes), Arc::clone(routed_at_stop));
			let read = move || routed.store(routes.resolves(&echo_type()), Ordering::SeqCst);
			let probe = Probe::at(b"127.0.0.1:7002").signed(ServletInfo::fixture_signer());
			probe.on_stop(read).registration(echo_type())
		}
	}

	/// Builds a frame to call a sibling with.
	fn call_frame() -> Frame {
		let message = encode(&TestMessage { content: "ping".into() }).expect("a test message encodes");
		Frame::v0(b"call", message)
	}

	/// A refused registry insert adds no route and stops the servlet the one
	/// way the trait names.
	#[tokio::test]
	async fn a_refused_registry_insert_leaves_no_route() {
		let hive = Hive::<RefusingRegistry>::default();
		let stopped = Arc::new(AtomicBool::new(false));

		let inserted = hive.instances().insert(probe(&stopped, Some(ServletInfo::fixture_signer())));
		let unrouted = hive.routes.call(&echo_type(), call_frame()).await;
		assert!(matches!(inserted, Err(InsertRefusal::Registry(TightBeamError::NonceExhausted))));
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		assert!(stopped.load(Ordering::SeqCst));
	}

	/// The map registry hands back the registration it replaces as a value
	/// whose drop stops the servlet, so a caller that drops it leaves no
	/// servlet running.
	#[test]
	fn a_replaced_registration_that_its_caller_drops_stops_its_servlet() {
		let replaced = Arc::new(AtomicBool::new(false));
		let servlets = HashMapRegistry::holding(b"echo".to_vec(), probe(&replaced, None));

		let second = servlets.insert(b"echo".to_vec(), idle());
		drop(second);

		assert!(replaced.load(Ordering::SeqCst));
	}

	/// A registration of an instance the hive holds replaces it, and the
	/// replaced servlet stops the one way the trait names.
	#[test]
	fn a_replaced_registration_stops_its_servlet() -> TestResult {
		let hive = Hive::new();
		let (replaced, replacing) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
		hive.instances().insert(probe(&replaced, None))?;
		hive.instances().insert(probe(&replacing, None))?;

		let stops = (replaced.load(Ordering::SeqCst), replacing.load(Ordering::SeqCst));
		assert_eq!((stops, hive.servlets.count()), ((true, false), 1));
		Ok(())
	}

	/// A removal drops the route before it stops the servlet, so no call in
	/// the removal window resolves a stopped instance.
	#[test]
	fn a_removed_instance_loses_its_route_before_it_stops() -> TestResult {
		let hive = Hive::new();
		let routed_at_stop = Arc::new(AtomicBool::new(true));
		let placed = hive.instances().insert(hive.route_probe(&routed_at_stop))?;

		hive.instances().insert(idle())?;
		hive.instances().remove(placed.instance.canonical_bytes())?;

		assert!(!routed_at_stop.load(Ordering::SeqCst));
		Ok(())
	}

	/// A servlet that names no signer registers and gets no route, because a
	/// sibling's dial admits a servlet's answer by that signer alone
	/// (CWE-346).
	#[tokio::test]
	async fn an_unsigned_servlet_registers_with_no_route() -> TestResult {
		let hive = Hive::new();
		hive.instances().insert(idle())?;

		let unrouted = hive.routes.call(&echo_type(), call_frame()).await;
		assert_eq!(hive.servlets.count(), 1);
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		Ok(())
	}

	/// A draining hive refuses an insert and stops the servlet it refused,
	/// so a spawn that outlived the drain leaves nothing running.
	#[test]
	fn a_draining_hive_refuses_an_insert_and_stops_its_servlet() {
		let hive = Hive::draining();
		let stopped = Arc::new(AtomicBool::new(false));

		let inserted = hive.instances().insert(probe(&stopped, None));
		assert!(matches!(inserted, Err(InsertRefusal::Draining)));
		assert!(stopped.load(Ordering::SeqCst));
	}

	/// A replacement that names no signer has no route, so the route of the
	/// signed instance it replaces leaves with it (CWE-346).
	#[test]
	fn an_unsigned_replacement_takes_the_route_of_the_instance_it_replaces_away() -> TestResult {
		let hive = Hive::new();
		let signed = probe(&Arc::default(), Some(ServletInfo::fixture_signer()));

		hive.instances().insert(signed)?;
		hive.instances().insert(idle())?;

		assert!(!hive.routes.resolves(&echo_type()));
		Ok(())
	}

	/// A registration that replaces the instance at its own address takes no
	/// place of its own, so a type at its bound admits it.
	#[test]
	fn a_replacement_at_the_bound_is_admitted() -> TestResult {
		let hive = Hive::single_instance();
		hive.instances().insert(idle())?;
		hive.instances().insert(idle())?;
		assert_eq!(hive.servlets.count(), 1);
		Ok(())
	}

	/// A drain enters the drain state under the hold that empties the set, so
	/// an insert that lands after it adds no instance, whichever path drained
	/// the hive (CWE-362).
	#[test]
	fn a_drained_instance_set_refuses_a_later_insert() {
		let hive = Hive::new();
		hive.instances().drain_all();

		let inserted = hive.instances().insert(idle());
		assert!(matches!(inserted, Err(InsertRefusal::Draining)));
	}

	/// A removed servlet stops once the admission lock drops, so a stop that
	/// blocks holds up no other move of the hive.
	#[test]
	fn a_removed_servlet_stops_once_the_admission_lock_drops() -> TestResult {
		let hive = Hive::new();
		let free_at_stop = Arc::new(AtomicBool::new(false));
		let placed = hive.instances().insert(hive.lock_probe(&free_at_stop))?;

		hive.instances().insert(probe(&Arc::default(), None))?;
		hive.instances().remove(placed.instance.canonical_bytes())?;

		assert!(free_at_stop.load(Ordering::SeqCst));
		Ok(())
	}

	/// A servlet that the hive refuses stops once the admission lock drops.
	#[test]
	fn a_refused_servlet_stops_once_the_admission_lock_drops() {
		let hive = Hive::draining();
		let free_at_stop = Arc::new(AtomicBool::new(false));

		let refused = hive.instances().insert(hive.lock_probe(&free_at_stop));
		assert!(matches!(refused, Err(InsertRefusal::Draining)));
		assert!(free_at_stop.load(Ordering::SeqCst));
	}

	/// A servlet that a registration at its own address replaces stops once
	/// the admission lock drops.
	#[test]
	fn a_replaced_servlet_stops_once_the_admission_lock_drops() -> TestResult {
		let hive = Hive::new();
		let free_at_stop = Arc::new(AtomicBool::new(false));

		hive.instances().insert(hive.lock_probe(&free_at_stop))?;
		hive.instances().insert(hive.lock_probe(&Arc::default()))?;

		assert!(free_at_stop.load(Ordering::SeqCst));
		Ok(())
	}
}

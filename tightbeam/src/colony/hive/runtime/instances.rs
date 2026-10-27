//! Keeps a hive's servlet registry and its routing context in agreement for
//! every servlet instance.

use std::sync::Arc;

use crate::colony::hive::runtime::HiveContextImpl;
use crate::colony::hive::{RefusedRegistration, ServletPlacement, ServletRegistration, ServletRegistry};
use crate::transport::Protocol;
use crate::urn::Urn;
use crate::{Errorizable, TightBeamError};

/// Why [`HiveInstances::insert`] registered no servlet.
///
/// Either way, the insert stops the servlet through
/// [`ServletBox::stop_boxed`] before it returns, so the caller only chooses its
/// answer. The cause travels as the error's source.
///
/// [`ServletBox::stop_boxed`]: crate::colony::hive::ServletBox::stop_boxed
#[derive(Debug, Errorizable)]
pub enum InsertRefusal {
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

/// One hive's servlet instances together with the routes that reach them.
///
/// An instance exists in the registry and in the routing context. An insert
/// or a removal through this view touches both in one fixed order, so a route
/// names only a live instance. The two sit behind separate locks, so the pair
/// is eventually consistent: each step commits on its own lock and stays
/// committed whatever a later step does.
pub struct HiveInstances<'a, R: ServletRegistry, P: Protocol> {
	servlets: &'a R,
	routes: &'a HiveContextImpl<P>,
}

impl<'a, R: ServletRegistry, P: Protocol> HiveInstances<'a, R, P> {
	/// Views `servlets` and the routes that reach them as one instance set.
	pub fn new(servlets: &'a R, routes: &'a HiveContextImpl<P>) -> Self {
		Self { servlets, routes }
	}

	/// Registers one servlet and the route that reaches it.
	///
	/// Returns where the servlet sits, which callers notify the cluster with.
	///
	/// - A servlet that names no signer gets no route, because a sibling's
	///   dial admits a servlet's answer by that signer alone (CWE-346).
	/// - A refused registration stops its servlet through
	///   [`ServletBox::stop_boxed`], whichever step refused it.
	/// - A registration that replaces an instance the registry holds retires
	///   that instance as [`Self::remove`] does, before the route of the
	///   replacement lands: its route leaves, then its servlet stops.
	///
	/// [`ServletBox::stop_boxed`]: crate::colony::hive::ServletBox::stop_boxed
	///
	/// # Errors
	///
	/// - [`InsertRefusal::Unnameable`] -- the servlet's address is not a valid instance locator.
	/// - [`InsertRefusal::Registry`] -- the registry refused the registration, so the insert adds no route.
	pub(crate) fn insert(&self, registration: ServletRegistration) -> Result<ServletPlacement, InsertRefusal> {
		let placement = match registration.placement() {
			Ok(placement) => placement,
			Err(error) => {
				let refused = RefusedRegistration { error, registration };
				return Err(InsertRefusal::Unnameable(refused.stop_servlet()));
			}
		};

		let key_bytes = placement.instance.canonical_bytes();
		let type_key = registration.servlet_type.canonical_bytes();
		// The route map and the registry each own a key, so the bytes clone.
		let route_key = key_bytes.clone();

		// The registry takes the instance first, so a route exists only for a
		// registered instance.
		let replaced = self
			.servlets
			.insert(key_bytes, registration)
			.map_err(|refused| InsertRefusal::Registry(refused.stop_servlet()))?;
		// A replaced instance shares its key, its type, and its address with
		// its replacement, so the slate entry of that address stands. Its route
		// leaves, and its servlet stops as the replaced value drops.
		if let Some(replaced) = replaced {
			replaced.retire(|registration| {
				let address = registration.servlet.addr_bytes();
				self.leave(&route_key, &registration.servlet_type, &address);
			});
		}

		if let Some(signer) = &placement.signer {
			let address = Arc::clone(&placement.address);
			self.routes.add_route(route_key, address, Arc::clone(signer), &type_key);
		}

		Ok(placement)
	}

	/// Removes one instance: its registry entry, then its route, then the
	/// servlet itself.
	///
	/// Returns the removed type URN and address, which callers notify the
	/// cluster with. [`None`] means `key` named no instance.
	pub fn remove(&self, key: impl AsRef<[u8]>) -> Option<(Urn<'static>, Arc<[u8]>)> {
		let key = key.as_ref();

		// 1. The registry gives the instance up first, so a registration that
		//    lands on the key while it leaves replaces nothing.
		let ServletRegistration { servlet, servlet_type, .. } = self.servlets.remove(key)?;
		let removed_addr = servlet.addr_bytes();

		// 2. The route leaves before the servlet stops, so a sibling call in
		//    this window resolves another instance or no route.
		self.leave(key, &servlet_type, &removed_addr);

		// 3. The servlet stops once nothing routes to it.
		servlet.stop_boxed();

		Some((servlet_type, removed_addr))
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
	use crate::colony::hive::{HashMapRegistry, HiveContext, ReplacedServlet, ServletBox, SpawnerFn};
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

		let inserted = HiveInstances::new(&servlets, &routes).insert(registration);
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
		let instances = HiveInstances::new(&servlets, &routes);
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
		let instances = HiveInstances::new(&servlets, &routes);
		let placed = instances.insert(registration)?;

		let removed = instances.remove(placed.instance.canonical_bytes());
		assert!(removed.is_some());
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

		HiveInstances::new(&servlets, &routes).insert(registration)?;

		let unrouted = routes.call(&servlet_type, call_frame()).await;
		assert_eq!(servlets.count(), 1);
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		Ok(())
	}
}

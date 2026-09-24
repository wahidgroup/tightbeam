//! Keeps a hive's servlet registry and its routing context in agreement for
//! every servlet instance.

use std::sync::Arc;

use crate::colony::hive::runtime::HiveContextImpl;
use crate::colony::hive::{RefusedRegistration, ServletRegistration, ServletRegistry};
use crate::transport::Protocol;
use crate::utils::urn::Urn;
use crate::{Errorizable, TightBeamError};

/// Why [`HiveInstances::insert`] registered no servlet.
///
/// Either way the servlet has already been stopped through
/// [`ServletBox::stop_boxed`], so the caller only chooses its answer. The
/// cause travels as the error's source.
///
/// [`ServletBox::stop_boxed`]: crate::colony::hive::ServletBox::stop_boxed
#[derive(Debug, Errorizable)]
pub enum InsertRefusal {
	/// The servlet's address is not a valid instance locator, so no URN
	/// names it. The servlet keeps producing that address, so a retry
	/// changes nothing.
	#[error("the servlet's address is not a valid instance locator: {0}")]
	#[source]
	Unnameable(TightBeamError),
	/// The registry did not take the registration.
	#[error("the servlet registry refused the registration: {0}")]
	#[source]
	Registry(TightBeamError),
}

/// One hive's servlet instances together with the routes that reach them.
///
/// An instance exists in the registry and in the routing context, and the
/// two MUST agree. Binding them in one view means an insert or a removal
/// touches both, so neither can be updated on its own.
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
	/// Returns the instance URN and shared address bytes, which callers
	/// notify the cluster with. A registration that does not land stops
	/// its servlet through [`ServletBox::stop_boxed`], whichever step
	/// refused it.
	///
	/// [`ServletBox::stop_boxed`]: crate::colony::hive::ServletBox::stop_boxed
	///
	/// # Errors
	///
	/// - [`InsertRefusal::Unnameable`] -- the servlet's address is not a
	///   valid instance locator.
	/// - [`InsertRefusal::Registry`] -- the registry did not take the
	///   registration. No route is added.
	pub fn insert(&self, registration: ServletRegistration) -> Result<(Urn<'static>, Arc<[u8]>), InsertRefusal> {
		let addr_bytes = registration.servlet.addr_bytes();
		let instance = match registration.servlet_type.instance_urn(addr_bytes.as_ref()) {
			Ok(instance) => instance,
			Err(error) => {
				let refused = RefusedRegistration { error, registration };

				return Err(InsertRefusal::Unnameable(refused.stop_servlet()));
			}
		};

		let key_bytes = instance.canonical_bytes();
		let type_key = registration.servlet_type.canonical_bytes();
		// The route map and the registry each own a key, so the bytes clone.
		let route_key = key_bytes.clone();

		// The registry takes the instance first, so a route exists only for a
		// registered instance.
		self.servlets
			.insert(key_bytes, registration)
			.map_err(|refused| InsertRefusal::Registry(refused.stop_servlet()))?;
		self.routes.add_route(route_key, Arc::clone(&addr_bytes), &type_key);

		Ok((instance, addr_bytes))
	}

	/// Stops one instance and drops the route that reached it.
	///
	/// Returns the removed type URN and address, which callers notify the
	/// cluster with. [`None`] means `key` named no instance.
	pub fn remove(&self, key: impl AsRef<[u8]>) -> Option<(Urn<'static>, Arc<[u8]>)> {
		let key = key.as_ref();
		let ServletRegistration { servlet, servlet_type, .. } = self.servlets.remove(key)?;
		let removed_type = servlet_type.canonical_bytes();
		let removed_addr = servlet.addr_bytes();

		servlet.stop_boxed();
		self.routes.remove_route(key, &servlet_type, &removed_type, &removed_addr);

		Some((servlet_type, removed_addr))
	}
}

#[cfg(test)]
mod tests {
	use core::error::Error;
	use core::sync::atomic::{AtomicBool, Ordering};

	use super::*;
	use crate::colony::common::ColonyNamespace;
	use crate::colony::hive::{HiveContext, ServletBox, ServletInfo, SpawnerFn};
	use crate::router::RouterError;
	use crate::testing::TestMessage;
	use crate::transport::client::pool::{ConnectionBuilder, ConnectionPool};
	use crate::transport::TokioListener;
	use crate::{encode, Frame};

	/// A [`ServletBox`] whose stop is observable.
	///
	/// The shipped servlet runtime stops by aborting its accept task, which
	/// gives a test nothing to read, so no real servlet can prove that the
	/// stop call was made. This probe records the call instead.
	struct StopProbe {
		stopped: Arc<AtomicBool>,
	}

	impl ServletBox for StopProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7001".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {
			self.stopped.store(true, Ordering::SeqCst);
		}
	}

	/// A [`ServletRegistry`] that refuses every insert.
	///
	/// The shipped registry takes every registration, so only a double reaches
	/// the refusal arm of the trait contract that a consumer registry may
	/// reach. It refuses with [`TightBeamError::NonceExhausted`], which nothing
	/// else on the insert path produces, so the test can tell that refusal
	/// from any other failure.
	#[derive(Default)]
	struct RefusingRegistry;

	impl ServletRegistry for RefusingRegistry {
		fn insert(
			&self,
			_key: impl Into<Vec<u8>>,
			registration: ServletRegistration,
		) -> Result<(), Box<RefusedRegistration>> {
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

	/// A registration of one [`StopProbe`] under `servlet_type`.
	///
	/// The insert under test reads no spawner, so the one it carries is
	/// the registered type's own probe factory.
	fn probe_registration(servlet_type: Urn<'static>, stopped: &Arc<AtomicBool>) -> ServletRegistration {
		let probe = StopProbe { stopped: Arc::clone(stopped) };
		let spawner: SpawnerFn = Arc::new(|_| {
			Box::pin(async { Ok(Box::new(StopProbe { stopped: Arc::default() }) as Box<dyn ServletBox>) })
		});

		ServletRegistration { servlet: Box::new(probe), spawner, servlet_type }
	}

	/// Empty routes over a pool nothing dials.
	fn routes() -> HiveContextImpl<TokioListener> {
		HiveContextImpl::new(Arc::new(ConnectionPool::<TokioListener>::builder().build()))
	}

	/// A frame to call a sibling with.
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
		let registration = probe_registration(servlet_type.clone(), &stopped);

		let inserted = HiveInstances::new(&servlets, &routes).insert(registration);

		assert!(matches!(inserted, Err(InsertRefusal::Registry(TightBeamError::NonceExhausted))));
		let unrouted = routes.call(&servlet_type, call_frame()).await;
		assert!(matches!(unrouted, Err(TightBeamError::RouterError(RouterError::UnknownRoute))));
		assert!(stopped.load(Ordering::SeqCst));
		Ok(())
	}
}

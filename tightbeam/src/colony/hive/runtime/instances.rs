//! Registry and context coherence for servlet instances.

use std::sync::Arc;

use crate::colony::hive::runtime::HiveContextImpl;
use crate::colony::hive::{HashMapRegistry, ServletRegistration, ServletRegistry};
use crate::transport::Protocol;
use crate::utils::urn::Urn;
use crate::TightBeamError;

/// One hive's servlet instances together with the routes that reach them.
///
/// An instance exists in the registry and in the routing context, and the
/// two MUST agree. Binding them in one view means an insert or a removal
/// touches both, so neither can be updated on its own.
pub struct HiveInstances<'a, P: Protocol> {
	servlets: &'a HashMapRegistry,
	routes: &'a HiveContextImpl<P>,
}

impl<'a, P: Protocol> HiveInstances<'a, P> {
	/// Views `servlets` and the routes that reach them as one instance set.
	pub fn new(servlets: &'a HashMapRegistry, routes: &'a HiveContextImpl<P>) -> Self {
		Self { servlets, routes }
	}

	/// Registers one servlet and the route that reaches it.
	///
	/// Returns the instance URN and shared address bytes, which callers
	/// notify the cluster with.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UrnValidationError`] -- the servlet's address is
	///   not a valid instance locator. The servlet is stopped, so an
	///   unnameable registration ends with its servlet.
	pub fn insert(&self, registration: ServletRegistration) -> Result<(Urn<'static>, Arc<[u8]>), TightBeamError> {
		let addr_bytes = registration.servlet.addr_bytes();
		let instance = match registration.servlet_type.instance_urn(addr_bytes.as_ref()) {
			Ok(instance) => instance,
			Err(err) => {
				let ServletRegistration { servlet, .. } = registration;
				servlet.stop_boxed();
				return Err(err);
			}
		};

		let key_bytes = instance.canonical_bytes();
		let type_key = registration.servlet_type.canonical_bytes();
		// Vec clone: route map and registry each must own a key.
		let route_key = key_bytes.clone();

		self.routes.add_route(route_key, Arc::clone(&addr_bytes), &type_key);

		let _ = self.servlets.insert(key_bytes, registration);

		Ok((instance, addr_bytes))
	}

	/// Stops one instance and drops the route that reached it.
	///
	/// Returns the removed type URN and address, which callers notify the
	/// cluster with. [`None`] means `key` named no instance.
	pub fn remove(&self, key: &[u8]) -> Option<(Urn<'static>, Arc<[u8]>)> {
		let ServletRegistration { servlet, servlet_type, .. } = self.servlets.remove(key)?;
		let removed_type = servlet_type.canonical_bytes();
		let removed_addr = servlet.addr_bytes();

		servlet.stop_boxed();
		self.routes.remove_route(key, &servlet_type, &removed_type, &removed_addr);

		Some((servlet_type, removed_addr))
	}
}

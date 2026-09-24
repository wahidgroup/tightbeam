//! Intra-hive routing context backed by a servlet connection pool.

use core::hash::Hash;
use core::str::{from_utf8, FromStr};
use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::colony::hive::{
	CallFuture, DuplexOpenFuture, HashMapRegistry, HiveContext, ServletRegistry, StreamOpenFuture, StreamResponseFuture,
};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::router::RouterError;
use crate::transport::client::pool::ConnectionPool;
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::{MessageCollector, MessageEmitter, PersistentConnection, Protocol};
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// Maps an instance key or a type key to shared servlet address bytes.
type AddressMap = HashMap<Vec<u8>, Arc<[u8]>>;

/// Instance routes and the type index they produce.
///
/// # One lock
///
/// The index is derived from the instances, so both live behind one lock
/// and under one owner. A reader sees an index that names an address the
/// instance map still holds, and no caller can order two acquisitions
/// against another caller (CWE-362).
///
/// # Poison recovery
///
/// Every write under the lock is a `HashMap` insert or remove, which
/// completes or aborts the process, so a thread that panicked while
/// holding the guard left whole maps behind it. The owner therefore
/// recovers a poisoned lock and keeps routing.
#[derive(Default)]
struct Routes {
	instances: AddressMap,
	by_type: AddressMap,
}

impl Routes {
	/// The first instance registered for a type owns the index entry.
	///
	/// `addr` moves into the instance map. The index takes an extra [`Arc`]
	/// handle only for a new type, so it shares the address bytes.
	fn insert(&mut self, key: impl Into<Vec<u8>>, addr: Arc<[u8]>, type_bytes: impl AsRef<[u8]>) {
		let key: Vec<u8> = key.into();
		let type_bytes = type_bytes.as_ref();
		self.by_type.entry(type_bytes.to_vec()).or_insert_with(|| Arc::clone(&addr));
		self.instances.insert(key, addr);
	}

	/// Drops an instance and promotes a sibling of the same type into the
	/// index when the departing instance held it.
	fn remove(
		&mut self,
		key: impl AsRef<[u8]>,
		type_prefix: impl AsRef<[u8]>,
		type_bytes: impl AsRef<[u8]>,
		removed: &Arc<[u8]>,
	) {
		let key = key.as_ref();
		let type_prefix = type_prefix.as_ref();
		let type_bytes = type_bytes.as_ref();
		self.instances.remove(key);

		if self.by_type.get(type_bytes) != Some(removed) {
			return;
		}

		let replacement = self
			.instances
			.iter()
			.find(|(instance, _)| instance.starts_with(type_prefix))
			.map(|(_, addr)| Arc::clone(addr));

		match replacement {
			Some(addr) => self.by_type.insert(type_bytes.to_vec(), addr),
			None => self.by_type.remove(type_bytes),
		};
	}

	fn resolve(&self, type_key: impl AsRef<[u8]>) -> Option<Arc<[u8]>> {
		let type_key = type_key.as_ref();
		self.by_type.get(type_key).cloned()
	}
}

/// The routes and the connection pool that a servlet uses to call its sibling
/// servlets in the same hive.
pub struct HiveContextImpl<P: Protocol> {
	routes: Arc<RwLock<Routes>>,
	pool: Arc<ConnectionPool<P>>,
}

impl<P: Protocol> HiveContextImpl<P> {
	/// Creates empty routes bound to the hive servlet pool.
	pub fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		Self { routes: Arc::new(RwLock::new(Routes::default())), pool }
	}

	/// The routes for writing, recovered from a poisoned lock because every
	/// write under the guard leaves whole maps.
	fn routes_mut(&self) -> RwLockWriteGuard<'_, Routes> {
		self.routes.write().unwrap_or_else(PoisonError::into_inner)
	}

	/// The routes for reading, recovered the same way.
	fn routes(&self) -> RwLockReadGuard<'_, Routes> {
		self.routes.read().unwrap_or_else(PoisonError::into_inner)
	}

	/// Routes `key` to `addr` and indexes `type_bytes` on it when the type
	/// has no route yet.
	pub fn add_route(&self, key: impl Into<Vec<u8>>, addr: Arc<[u8]>, type_bytes: impl AsRef<[u8]>) {
		let key: Vec<u8> = key.into();
		let type_bytes = type_bytes.as_ref();
		self.routes_mut().insert(key, addr, type_bytes);
	}

	/// Drops the route under `key` and re-indexes `type_urn` on a sibling
	/// when the departing instance held the index.
	pub fn remove_route(
		&self,
		key: impl AsRef<[u8]>,
		type_urn: &Urn<'_>,
		type_bytes: impl AsRef<[u8]>,
		removed_addr: &Arc<[u8]>,
	) {
		let key = key.as_ref();
		let type_bytes = type_bytes.as_ref();
		let type_prefix = type_urn.type_prefix_bytes();
		self.routes_mut().remove(key, &type_prefix, type_bytes, removed_addr);
	}

	/// Adds a route to every instance already in `servlets`.
	///
	/// Registration fills the registry before the hive starts, so the
	/// routes catch up in one pass at start rather than per registration.
	pub(crate) fn seed_routes(&self, servlets: &HashMapRegistry) {
		servlets.for_each(|key, reg| {
			let addr_bytes = reg.servlet.addr_bytes();
			let type_key = reg.servlet_type.canonical_bytes();
			// `for_each` lends the key, and `add_route` needs an owned copy.
			self.add_route(key.clone(), addr_bytes, &type_key);
		});
	}

	/// The address this hive dials for `servlet_type`.
	///
	/// # Errors
	///
	/// - [`RouterError::UnknownRoute`] -- no instance of the type is routed,
	///   or the routed address is not a locator `P` can parse.
	fn resolve_addr(&self, servlet_type: &Urn<'_>) -> Result<P::Address, TightBeamError>
	where
		P::Address: FromStr,
	{
		let route_err = || TightBeamError::RouterError(RouterError::UnknownRoute);
		let type_key = servlet_type.canonical_bytes();
		let addr_bytes = self.routes().resolve(&type_key).ok_or_else(route_err)?;
		let addr_str = from_utf8(addr_bytes.as_ref()).map_err(|_| route_err())?;

		let parsed = addr_str.parse().map_err(|_| route_err())?;
		Ok(parsed)
	}
}

impl<P> HiveContext for HiveContextImpl<P>
where
	P: Protocol<CryptoProvider = DefaultCryptoProvider>,
	P: Protocol + PersistentConnection + Send + Sync + 'static,
	P::Address: Hash + Eq + Clone + Send + Sync + FromStr + 'static,
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig + MuxConnector + Send + Sync + 'static,
{
	fn call<'a>(&'a self, servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a> {
		Box::pin(async move {
			let addr = self.resolve_addr(servlet_type)?;
			let mut pooled_conn = self.pool.connect(addr).await?;
			// The caller's frame emits as-is so an applied nonrepudiation
			// signature stays verifiable at the servlet.
			let response = pooled_conn.emit(frame, None).await?;
			response.ok_or(TightBeamError::MissingResponse)
		})
	}

	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		Box::pin(async move {
			let addr = self.resolve_addr(servlet_type)?;
			let pooled_conn = self.pool.connect(addr).await?;
			let (sink, response) = pooled_conn.open_stream()?;

			// The lease returns to the pool here, and the sink and the response
			// live on the shared mux plane independently of it. The pool-level
			// future already yields the complete trailer frame of the reply.
			let response: StreamResponseFuture = Box::pin(async move {
				let reply = response.await?;
				reply.ok_or(TightBeamError::MissingResponse)
			});

			Ok((sink, response))
		})
	}

	fn open_duplex<'a>(&'a self, servlet_type: &'a Urn<'a>) -> DuplexOpenFuture<'a> {
		Box::pin(async move {
			let addr = self.resolve_addr(servlet_type)?;
			let pooled_conn = self.pool.connect(addr).await?;

			let duplex = pooled_conn.open_duplex()?;
			Ok(duplex)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::mpsc;
	use std::thread;
	use std::time::Duration;

	const TYPE: &[u8] = b"urn:tb:servlet:echo";
	const PREFIX: &[u8] = b"urn:tb:servlet:echo/";

	fn addr(bytes: &'static str) -> Arc<[u8]> {
		Arc::from(bytes.as_bytes())
	}

	fn instance(tail: impl AsRef<str>) -> Vec<u8> {
		let tail = tail.as_ref();
		format!("urn:tb:servlet:echo/{tail}").into_bytes()
	}

	#[test]
	fn first_instance_of_a_type_owns_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.insert(instance("b"), addr("10.0.0.2"), TYPE);
		assert_eq!(routes.resolve(TYPE), Some(addr("10.0.0.1")));
	}

	#[test]
	fn removing_the_indexed_instance_promotes_a_sibling() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.insert(instance("b"), addr("10.0.0.2"), TYPE);
		routes.remove(instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), Some(addr("10.0.0.2")));
	}

	#[test]
	fn removing_the_last_instance_clears_the_type() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.remove(instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), None);
	}

	#[test]
	fn removing_a_sibling_leaves_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.insert(instance("b"), addr("10.0.0.2"), TYPE);
		routes.remove(instance("b"), PREFIX, TYPE, &addr("10.0.0.2"));
		assert_eq!(routes.resolve(TYPE), Some(addr("10.0.0.1")));
	}

	/// Insert and remove run concurrently against one lock. Two locks
	/// acquired in opposite orders wedge both threads, so the bounded wait
	/// reports that as a failure within the wait (CWE-362).
	#[test]
	fn concurrent_insert_and_remove_finish() {
		let routes = Arc::new(RwLock::new(Routes::default()));
		let (done, finished) = mpsc::channel();

		let inserter = Arc::clone(&routes);
		let insert_done = done.clone();
		thread::spawn(move || {
			for _ in 0..20_000 {
				inserter
					.write()
					.expect("routes lock")
					.insert(instance("a"), addr("10.0.0.1"), TYPE);
			}

			insert_done.send(()).expect("receiver alive");
		});

		let remover = Arc::clone(&routes);
		thread::spawn(move || {
			for _ in 0..20_000 {
				remover
					.write()
					.expect("routes lock")
					.remove(instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
			}

			done.send(()).expect("receiver alive");
		});

		for _ in 0..2 {
			assert!(finished.recv_timeout(Duration::from_secs(10)).is_ok());
		}
	}
}

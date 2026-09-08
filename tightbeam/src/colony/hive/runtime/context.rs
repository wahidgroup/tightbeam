//! Intra-hive routing context backed by a servlet connection pool.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::colony::hive::{
	CallFuture, DuplexOpenFuture, HashMapRegistry, HiveContext, ServletRegistry, StreamOpenFuture, StreamResponseFuture,
};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::router::RouterError;
use crate::transport::client::pool::ConnectionPool;
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::{MessageCollector, MessageEmitter, PersistentConnection, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::{Frame, TightBeamError};

/// Instance or type key to shared servlet address bytes.
type AddressMap = HashMap<Vec<u8>, Arc<[u8]>>;

/// Instance routes and the type index they produce.
///
/// The index is derived from the instances, so both live behind one lock
/// and under one owner. A reader sees an index that names an address the
/// instance map still holds, and no caller can order two acquisitions
/// against another caller (CWE-362).
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
	fn insert(&mut self, key: Vec<u8>, addr: Arc<[u8]>, type_bytes: &[u8]) {
		self.by_type.entry(type_bytes.to_vec()).or_insert_with(|| Arc::clone(&addr));
		self.instances.insert(key, addr);
	}

	/// Drops an instance and promotes a sibling of the same type into the
	/// index when the departing instance held it.
	fn remove(&mut self, key: &[u8], type_prefix: &[u8], type_bytes: &[u8], removed: &Arc<[u8]>) {
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

	fn resolve(&self, type_key: &[u8]) -> Option<Arc<[u8]>> {
		self.by_type.get(type_key).cloned()
	}
}

/// Shared routes and pool used for sibling servlet calls.
pub struct HiveContextImpl<P: Protocol> {
	routes: Arc<RwLock<Routes>>,
	pool: Arc<ConnectionPool<P>>,
}

impl<P: Protocol> HiveContextImpl<P> {
	/// Creates empty routes bound to the hive servlet pool.
	pub fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		Self { routes: Arc::new(RwLock::new(Routes::default())), pool }
	}

	pub fn add_route(&self, key: Vec<u8>, addr: Arc<[u8]>, type_bytes: &[u8]) {
		let Ok(mut routes) = self.routes.write() else {
			return;
		};

		routes.insert(key, addr, type_bytes);
	}

	pub fn remove_route(&self, key: &[u8], type_urn: &Urn<'_>, type_bytes: &[u8], removed_addr: &Arc<[u8]>) {
		let type_prefix = type_urn.type_prefix_bytes();
		let Ok(mut routes) = self.routes.write() else {
			return;
		};

		routes.remove(key, &type_prefix, type_bytes, removed_addr);
	}

	/// Adds a route to every instance already in `servlets`.
	///
	/// Registration fills the registry before the hive starts, so the
	/// routes catch up in one pass at start rather than per registration.
	pub(crate) fn seed_routes(&self, servlets: &HashMapRegistry) {
		servlets.for_each(|key, reg| {
			let addr_bytes = reg.servlet.addr_bytes();
			let type_key = reg.servlet_type.canonical_bytes();
			// for_each borrows the registry key, and add_route needs an owned copy.
			self.add_route(key.clone(), addr_bytes, &type_key);
		});
	}

	fn resolve_addr(&self, servlet_type: &Urn<'_>) -> Result<P::Address, TightBeamError>
	where
		P::Address: core::str::FromStr,
	{
		let route_err = || TightBeamError::RouterError(RouterError::UnknownRoute);
		let routes = self.routes.read().map_err(|_| TightBeamError::LockPoisoned)?;
		let type_key = servlet_type.canonical_bytes();
		let addr_bytes = routes.resolve(&type_key).ok_or_else(route_err)?;
		let addr_str = core::str::from_utf8(addr_bytes.as_ref()).map_err(|_| route_err())?;

		let parsed = addr_str.parse().map_err(|_| route_err())?;
		Ok(parsed)
	}
}

impl<P> HiveContext for HiveContextImpl<P>
where
	P: Protocol + PersistentConnection + Send + Sync + 'static,
	P::Address: core::hash::Hash + Eq + Clone + Send + Sync + core::str::FromStr + 'static,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = DefaultCryptoProvider>
		+ MuxConnector
		+ Send
		+ Sync
		+ 'static,
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

			// The lease returns to the pool here. The sink and response live
			// on the shared mux plane independently. The pool-level future
			// already yields the servlet's complete trailer reply frame.
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

	fn instance(tail: &str) -> Vec<u8> {
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
		routes.remove(&instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), Some(addr("10.0.0.2")));
	}

	#[test]
	fn removing_the_last_instance_clears_the_type() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.remove(&instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), None);
	}

	#[test]
	fn removing_a_sibling_leaves_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), addr("10.0.0.1"), TYPE);
		routes.insert(instance("b"), addr("10.0.0.2"), TYPE);
		routes.remove(&instance("b"), PREFIX, TYPE, &addr("10.0.0.2"));
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
					.remove(&instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
			}

			done.send(()).expect("receiver alive");
		});

		for _ in 0..2 {
			assert!(finished.recv_timeout(Duration::from_secs(10)).is_ok());
		}
	}
}

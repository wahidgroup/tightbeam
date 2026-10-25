//! The intra-hive routing context, backed by a servlet connection pool.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::{ColonyDialProtocol, DialTarget};
use crate::colony::hive::{
	CallFuture, DuplexOpenFuture, HashMapRegistry, HiveContext, ServletRegistry, StreamOpenFuture, StreamResponseFuture,
};
use crate::router::RouterError;
use crate::transport::client::ConnectionPool;
use crate::transport::{PooledClient, Protocol};
use crate::urn::Urn;
use crate::{Frame, TightBeamError};

/// One sibling instance: the address that reaches it, and the signer of the
/// certificate it answers under.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Sibling {
	address: Arc<[u8]>,
	signer: Arc<SignerIdentifier>,
}

impl Sibling {
	/// Connects to this sibling on `pool`, once the party that answers proves
	/// it holds the certificate [`Self::signer`] names (CWE-346).
	///
	/// # Errors
	///
	/// - The errors of [`BoundDial::connect`], as [`TightBeamError::ClusterError`].
	async fn connect<P: ColonyDialProtocol>(
		self,
		pool: &Arc<ConnectionPool<P>>,
	) -> Result<PooledClient<P>, TightBeamError> {
		let target = DialTarget::of_registered(&self.address);
		let dial = BoundDial::new(target, ExpectedSigner::Hive(self.signer));

		Ok(dial.connect(pool).await?)
	}
}

/// Maps an instance key or a type key to the sibling it routes to.
type SiblingMap = HashMap<Vec<u8>, Sibling>;

/// Instance routes and the type index they produce.
///
/// # One lock
///
/// The index derives from the instances, so both live behind one lock and
/// under one owner. A reader sees an index that names an address the
/// instance map still holds, and every caller takes the same single lock,
/// which rules out a lock-order deadlock between two callers (CWE-362).
///
/// # Poison recovery
///
/// Every write under the lock is a `HashMap` insert or remove, which
/// completes or aborts the process, so a thread that panicked while it held
/// the guard left whole maps behind it. The owner therefore recovers a
/// poisoned lock, and the routes stay in service.
#[derive(Default)]
struct Routes {
	instances: SiblingMap,
	by_type: SiblingMap,
}

impl Routes {
	/// Inserts `sibling` under `key`. The first instance registered for a type
	/// owns the index entry.
	///
	/// `sibling` moves into the instance map. The index takes extra [`Arc`]
	/// handles only for a new type, so it shares the address and the signer.
	fn insert(&mut self, key: impl Into<Vec<u8>>, sibling: Sibling, type_bytes: impl AsRef<[u8]>) {
		let key: Vec<u8> = key.into();
		let type_bytes = type_bytes.as_ref();
		self.by_type.entry(type_bytes.to_vec()).or_insert_with(|| sibling.clone());
		self.instances.insert(key, sibling);
	}

	/// Drops an instance and promotes a sibling of the same type into the
	/// index when the dropped instance held it.
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

		let indexed = self.by_type.get(type_bytes).map(|sibling| &sibling.address);
		if indexed != Some(removed) {
			return;
		}

		let replacement = self
			.instances
			.iter()
			.find(|(instance, _)| instance.starts_with(type_prefix))
			.map(|(_, sibling)| sibling.clone());

		match replacement {
			Some(sibling) => self.by_type.insert(type_bytes.to_vec(), sibling),
			None => self.by_type.remove(type_bytes),
		};
	}

	fn resolve(&self, type_key: impl AsRef<[u8]>) -> Option<Sibling> {
		let type_key = type_key.as_ref();
		self.by_type.get(type_key).cloned()
	}
}

/// The routes and the connection pool that a servlet uses to call its sibling
/// servlets in the same hive.
///
/// Each route names the signer its sibling answers under, and every call
/// dials bound to that signer, so a party that answers at a sibling's address
/// under another identity receives no frame (CWE-346). A route exists only
/// for a servlet that names a signer.
pub struct HiveContextImpl<P: Protocol> {
	routes: Arc<RwLock<Routes>>,
	pool: Arc<ConnectionPool<P>>,
}

impl<P: Protocol> HiveContextImpl<P> {
	/// Creates empty routes bound to the hive servlet pool.
	pub fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		Self { routes: Arc::new(RwLock::new(Routes::default())), pool }
	}

	/// Takes the write lock of the routes. It recovers a poisoned lock,
	/// because every write under the guard leaves whole maps.
	fn routes_mut(&self) -> RwLockWriteGuard<'_, Routes> {
		self.routes.write().unwrap_or_else(PoisonError::into_inner)
	}

	/// Takes the read lock of the routes and recovers a poisoned lock the
	/// same way.
	fn routes(&self) -> RwLockReadGuard<'_, Routes> {
		self.routes.read().unwrap_or_else(PoisonError::into_inner)
	}

	/// Routes `key` to the sibling at `addr` that answers under `signer`, and
	/// indexes `type_bytes` on it when the type has no route yet.
	///
	/// A call through the route admits only the certificate `signer` names
	/// (RFC 5652 §5.3).
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::hive::HiveContextImpl;
	/// use tightbeam::crypto::x509::utils::CertificateExt;
	/// use tightbeam::testing::{TestCertificate, TestKey};
	/// use tightbeam::transport::client::{ConnectionBuilder, ConnectionPool};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let key = TestKey::insecure_fixed_signing();
	/// let signer = TestCertificate::self_signed(&key).signer_identifier()?;
	/// let pool = Arc::new(ConnectionPool::<TokioListener>::builder().build());
	/// let routes = HiveContextImpl::new(pool);
	///
	/// let address: Arc<[u8]> = Arc::from(b"127.0.0.1:7000".as_slice());
	/// let instance = b"urn:tightbeam:servlet:echo/127.0.0.1:7000";
	/// routes.add_route(instance, address, signer, b"urn:tightbeam:servlet:echo");
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn add_route(
		&self,
		key: impl Into<Vec<u8>>,
		addr: Arc<[u8]>,
		signer: impl Into<Arc<SignerIdentifier>>,
		type_bytes: impl AsRef<[u8]>,
	) {
		let key: Vec<u8> = key.into();
		let sibling = Sibling { address: addr, signer: signer.into() };
		let type_bytes = type_bytes.as_ref();
		self.routes_mut().insert(key, sibling, type_bytes);
	}

	/// Drops the route under `key` and re-indexes `type_urn` on a sibling
	/// when the dropped instance held the index.
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

	/// Returns whether a route for `servlet_type` exists, for a test that
	/// reads the routes at an instant the hive picks.
	#[cfg(test)]
	pub(crate) fn resolves(&self, servlet_type: &Urn<'_>) -> bool {
		let type_key = servlet_type.canonical_bytes();
		self.routes().resolve(&type_key).is_some()
	}

	/// Adds a route to every instance already in `servlets` that names a
	/// signer.
	///
	/// Registration fills the registry before the hive starts, so the
	/// routes catch up in one pass at start rather than per registration.
	pub(crate) fn seed_routes(&self, servlets: &HashMapRegistry) {
		servlets.for_each(|key, reg| {
			// A sibling's dial admits a servlet's answer by its signer alone,
			// so a servlet that names none gets no route (CWE-346).
			let Some(signer) = reg.servlet.signer() else {
				return;
			};

			let addr_bytes = reg.servlet.addr_bytes();
			let type_key = reg.servlet_type.canonical_bytes();
			// `for_each` lends the key, and `add_route` needs an owned copy.
			self.add_route(key.clone(), addr_bytes, signer.clone(), &type_key);
		});
	}

	/// Returns the sibling this hive routes `servlet_type` to.
	///
	/// # Errors
	///
	/// - [`RouterError::UnknownRoute`] -- the hive routes no instance of the type.
	fn sibling(&self, servlet_type: &Urn<'_>) -> Result<Sibling, TightBeamError> {
		let type_key = servlet_type.canonical_bytes();
		let routed = self.routes().resolve(&type_key);

		routed.ok_or(TightBeamError::RouterError(RouterError::UnknownRoute))
	}
}

impl<P: ColonyDialProtocol> HiveContext for HiveContextImpl<P> {
	fn call<'a>(&'a self, servlet_type: &'a Urn<'a>, frame: Frame) -> CallFuture<'a> {
		Box::pin(async move {
			let sibling = self.sibling(servlet_type)?;
			let mut pooled_conn = sibling.connect(&self.pool).await?;
			// The context emits the caller's frame as-is, so an applied
			// nonrepudiation signature stays verifiable at the servlet.
			let response = pooled_conn.emit(frame, None).await?;
			response.ok_or(TightBeamError::MissingResponse)
		})
	}

	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		Box::pin(async move {
			let sibling = self.sibling(servlet_type)?;
			let pooled_conn = sibling.connect(&self.pool).await?;
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
			let sibling = self.sibling(servlet_type)?;
			let pooled_conn = sibling.connect(&self.pool).await?;

			let duplex = pooled_conn.open_duplex()?;
			Ok(duplex)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::hive::{ServletBox, ServletRegistration, SpawnerFn};
	use crate::colony::protocol::ServletInfo;
	use crate::colony::urn::ColonyNamespace;
	use crate::tb_cases;
	use crate::transport::client::ConnectionBuilder;
	use crate::transport::TokioListener;
	use std::sync::mpsc;
	use std::thread;
	use std::time::Duration;

	const TYPE: &[u8] = b"urn:tb:servlet:echo";
	const PREFIX: &[u8] = b"urn:tb:servlet:echo/";

	fn addr(bytes: &'static str) -> Arc<[u8]> {
		Arc::from(bytes.as_bytes())
	}

	/// Builds the sibling at `bytes`, which answers under the fixture
	/// servlet's signer.
	fn sibling(bytes: &'static str) -> Sibling {
		Sibling { address: addr(bytes), signer: Arc::new(ServletInfo::fixture_signer()) }
	}

	fn instance(tail: impl AsRef<str>) -> Vec<u8> {
		let tail = tail.as_ref();
		format!("urn:tb:servlet:echo/{tail}").into_bytes()
	}

	#[test]
	fn first_instance_of_a_type_owns_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), sibling("10.0.0.1"), TYPE);
		routes.insert(instance("b"), sibling("10.0.0.2"), TYPE);
		assert_eq!(routes.resolve(TYPE), Some(sibling("10.0.0.1")));
	}

	#[test]
	fn removing_the_indexed_instance_promotes_a_sibling() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), sibling("10.0.0.1"), TYPE);
		routes.insert(instance("b"), sibling("10.0.0.2"), TYPE);
		routes.remove(instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), Some(sibling("10.0.0.2")));
	}

	#[test]
	fn removing_the_last_instance_clears_the_type() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), sibling("10.0.0.1"), TYPE);
		routes.remove(instance("a"), PREFIX, TYPE, &addr("10.0.0.1"));
		assert_eq!(routes.resolve(TYPE), None);
	}

	#[test]
	fn removing_a_sibling_leaves_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), sibling("10.0.0.1"), TYPE);
		routes.insert(instance("b"), sibling("10.0.0.2"), TYPE);
		routes.remove(instance("b"), PREFIX, TYPE, &addr("10.0.0.2"));
		assert_eq!(routes.resolve(TYPE), Some(sibling("10.0.0.1")));
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
		let inserted = sibling("10.0.0.1");
		thread::spawn(move || {
			for _ in 0..20_000 {
				inserter
					.write()
					.expect("routes lock")
					.insert(instance("a"), inserted.clone(), TYPE);
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

	/// A servlet at a fixed locator that names `signer` as the identity it
	/// answers under.
	struct SignerProbe {
		signer: Option<SignerIdentifier>,
	}

	impl ServletBox for SignerProbe {
		fn addr_bytes(&self) -> Arc<[u8]> {
			Arc::from(b"127.0.0.1:7005".as_slice())
		}

		fn stop_boxed(self: Box<Self>) {}

		fn signer(&self) -> Option<&SignerIdentifier> {
			self.signer.as_ref()
		}
	}

	/// Returns the type the seeded registry holds.
	fn echo_type() -> Urn<'static> {
		let namespace = ColonyNamespace::default();
		namespace.servlet("echo").expect("test names satisfy the mint grammar")
	}

	/// Returns the spawner of a [`SignerProbe`] that names no signer.
	fn probe_spawner() -> SpawnerFn {
		Arc::new(|_| Box::pin(async { Ok(Box::new(SignerProbe { signer: None }) as Box<dyn ServletBox>) }))
	}

	/// Builds a registry that holds one [`SignerProbe`] of [`echo_type`] that
	/// names `signer`.
	fn registry_holding(signer: Option<SignerIdentifier>) -> HashMapRegistry {
		let servlet_type = echo_type();
		let key = servlet_type.instance_urn(b"127.0.0.1:7005");
		let key = key.expect("the probe locator names an instance");
		let spawner = probe_spawner();
		let registration = ServletRegistration { servlet: Box::new(SignerProbe { signer }), spawner, servlet_type };

		let registry = HashMapRegistry::default();
		let inserted = registry.insert(key.canonical_bytes(), registration);
		assert!(inserted.is_ok(), "the map registry takes every registration");

		registry
	}

	// A sibling's dial admits a servlet's answer by its signer alone, so the
	// routes a hive seeds at start route a servlet that names its signer and
	// leave out one that names none.
	tb_cases! {
		fn seed_routes_route_a_servlet_by_its_signer((signer, routed): (Option<SignerIdentifier>, bool)) {
			let servlets = registry_holding(signer);
			let routes = HiveContextImpl::new(Arc::new(ConnectionPool::<TokioListener>::builder().build()));

			routes.seed_routes(&servlets);

			assert_eq!(routes.resolves(&echo_type()), routed);
		}
		cases {
			a_signed_servlet_is_routed => (Some(ServletInfo::fixture_signer()), true),
			an_unsigned_servlet_is_left_out => (None, false),
		}
	}
}

//! The intra-hive routing context, backed by a servlet connection pool.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::cms::signed_data::SignerIdentifier;
use crate::colony::bound_dial::{BoundDial, ExpectedSigner};
use crate::colony::cluster::{ColonyDialProtocol, DialTarget};
use crate::colony::hive::{CallFuture, DuplexOpenFuture, HiveContext, StreamOpenFuture, StreamResponseFuture};
use crate::router::RouterError;
use crate::trace::TraceCollector;
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
	/// Connects to this sibling on the pool of `plane`, once the party that
	/// answers proves it holds the certificate [`Self::signer`] names
	/// (CWE-346). A refused answer records its refusal on the trace of `plane`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::ClusterError`] -- an error of [`BoundDial::connect`].
	async fn connect<P: ColonyDialProtocol>(self, plane: &SiblingPlane<P>) -> Result<PooledClient<P>, TightBeamError> {
		let target = DialTarget::of_registered(&self.address);
		let dial = BoundDial::new(target, ExpectedSigner::Hive(self.signer));
		Ok(dial.connect(&plane.pool, &plane.trace).await?)
	}
}

/// The pool that sibling calls dial on, beside the trace that records each
/// dial it refuses.
///
/// A hive sets a whole plane when it establishes, so a call reads the pool
/// and the trace of one hive state.
struct SiblingPlane<P: Protocol> {
	pool: Arc<ConnectionPool<P>>,
	trace: Arc<TraceCollector>,
}

/// Maps an instance key or a type key to the sibling it routes to.
type SiblingMap = HashMap<Vec<u8>, Sibling>;

/// The instance routes and the type index they produce.
///
/// # One lock
///
/// The index derives from the instances, so both live behind one lock and
/// under one owner. A reader sees an index that names only addresses the
/// instance map holds, and with one lock no two callers can deadlock on lock
/// order (CWE-362).
///
/// # Poison recovery
///
/// Every write under the lock is a `HashMap` insert or remove, which
/// completes or aborts the process, so a thread that panicked under the guard
/// left whole maps. The owner recovers a poisoned lock, and the routes stay in
/// service.
#[derive(Default)]
struct Routes {
	instances: SiblingMap,
	by_type: SiblingMap,
}

impl Routes {
	/// Inserts `sibling` under `key`.
	///
	/// - The first instance registered for a type owns the index entry.
	/// - A sibling that replaces the indexed instance takes the entry over.
	///   An instance key names the type and the address, so within one type
	///   the indexed instance is the one at the indexed address.
	///
	/// `sibling` moves into the instance map. The index takes extra [`Arc`]
	/// handles only for an entry it takes, so it shares the address and the
	/// signer.
	fn insert(&mut self, key: impl Into<Vec<u8>>, sibling: Sibling, type_bytes: impl AsRef<[u8]>) {
		let key: Vec<u8> = key.into();
		let type_bytes = type_bytes.as_ref();
		match self.by_type.get_mut(type_bytes) {
			Some(indexed) if indexed.address == sibling.address => *indexed = sibling.clone(),
			Some(_) => {}
			None => {
				self.by_type.insert(type_bytes.to_vec(), sibling.clone());
			}
		}
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
///
/// # Planes
///
/// A call dials on the provisional plane, the pool that [`Self::new`] takes
/// and the trace that [`Self::with_trace`] names, until the hive that holds
/// the context establishes. The established hive sets a plane of its own
/// once, and each later call dials on it. A call reads its plane with no
/// lock, and a call already in flight finishes on the plane it started on.
pub struct HiveContextImpl<P: Protocol> {
	routes: Arc<RwLock<Routes>>,
	/// The pool and the trace that each sibling call uses until the hive
	/// establishes.
	provisional: SiblingPlane<P>,
	/// The pool and the trace of the established hive. A hive establishes
	/// once, so the slot takes its value once.
	established: OnceLock<SiblingPlane<P>>,
}

impl<P: Protocol> HiveContextImpl<P> {
	/// Creates empty routes bound to the hive servlet pool.
	///
	/// The context records each refused dial on a trace of its own until
	/// [`Self::with_trace`] names another, or the hive that holds it
	/// establishes.
	pub fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		let trace = Arc::new(TraceCollector::default());
		let provisional = SiblingPlane { pool, trace };

		Self {
			routes: Arc::new(RwLock::new(Routes::default())),
			provisional,
			established: OnceLock::new(),
		}
	}

	/// Records each sibling dial that this context refuses into `trace`, until
	/// the hive that holds the context establishes with a trace of its own.
	///
	/// A builder of the context gives it the trace it reads, so the pool and
	/// the refusals of one plane can record into one trace.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::colony::hive::HiveContextImpl;
	/// use tightbeam::trace::TraceCollector;
	/// use tightbeam::transport::client::{ConnectionBuilder, ConnectionPool};
	/// use tightbeam::transport::tcp::r#async::TokioListener;
	///
	/// let trace = TraceCollector::default();
	/// let pool = Arc::new(ConnectionPool::<TokioListener>::builder().build());
	/// let routes = HiveContextImpl::new(pool).with_trace(trace.share());
	/// ```
	#[must_use]
	pub fn with_trace(mut self, trace: impl Into<Arc<TraceCollector>>) -> Self {
		self.provisional.trace = trace.into();
		self
	}

	/// The plane that a sibling call starts on: the established one once the
	/// hive establishes, and the provisional one before.
	fn plane(&self) -> &SiblingPlane<P> {
		self.established.get().unwrap_or(&self.provisional)
	}

	/// Sets the plane that each later sibling call dials on to `pool` and
	/// `trace`, for the hive that establishes.
	///
	/// A call already in flight finishes on the plane it started on.
	///
	/// # Errors
	///
	/// - [`TightBeamError::AlreadyEstablished`] -- the hive set its plane already.
	pub(crate) fn establish_plane(
		&self,
		pool: Arc<ConnectionPool<P>>,
		trace: Arc<TraceCollector>,
	) -> Result<(), TightBeamError> {
		let plane = SiblingPlane { pool, trace };
		self.established.set(plane).map_err(|_| TightBeamError::AlreadyEstablished)
	}

	/// Takes the write lock of the routes, and recovers a poisoned lock.
	fn routes_mut(&self) -> RwLockWriteGuard<'_, Routes> {
		self.routes.write().unwrap_or_else(PoisonError::into_inner)
	}

	/// Takes the read lock of the routes, and recovers a poisoned lock.
	fn routes(&self) -> RwLockReadGuard<'_, Routes> {
		self.routes.read().unwrap_or_else(PoisonError::into_inner)
	}

	/// Routes `key` to the sibling at `addr` that answers under `signer`, and
	/// indexes `type_bytes` on it when the type has no route yet or its route
	/// names `addr`.
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
			let mut pooled_conn = sibling.connect(self.plane()).await?;
			// The context emits the caller's frame as-is, so an applied
			// nonrepudiation signature stays verifiable at the servlet.
			let response = pooled_conn.emit(frame, None).await?;
			response.ok_or(TightBeamError::MissingResponse)
		})
	}

	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		Box::pin(async move {
			let sibling = self.sibling(servlet_type)?;
			let pooled_conn = sibling.connect(self.plane()).await?;
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
			let pooled_conn = sibling.connect(self.plane()).await?;

			let duplex = pooled_conn.open_duplex()?;
			Ok(duplex)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::colony::protocol::ServletInfo;
	use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
	use crate::crypto::x509::utils::CertificateExt;
	use crate::testing::TestCertificate;
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

	/// A sibling that answers under a second key, at `bytes`.
	fn resigned_sibling(bytes: &'static str) -> Sibling {
		let key = Secp256k1SigningKey::from_bytes(&[7; 32].into()).expect("the fixture scalar is a valid key");
		let certificate = TestCertificate::self_signed(&key);
		let signer = certificate.signer_identifier().expect("the fixture certificate names its key");

		Sibling { address: addr(bytes), signer: Arc::new(signer) }
	}

	// An instance that replaces the indexed one at its address takes the type
	// over, so a call dials bound to the signer that answers there.
	#[test]
	fn a_replacement_of_the_indexed_instance_takes_the_index() {
		let mut routes = Routes::default();
		routes.insert(instance("a"), sibling("10.0.0.1"), TYPE);
		routes.insert(instance("a"), resigned_sibling("10.0.0.1"), TYPE);
		assert_eq!(routes.resolve(TYPE), Some(resigned_sibling("10.0.0.1")));
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
}

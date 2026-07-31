//! Intra-hive routing context backed by a servlet connection pool.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::colony::common::{canonical_bytes, type_prefix_bytes};
use crate::colony::hive::{CallFuture, DuplexOpenFuture, HiveContext, StreamOpenFuture, StreamResponseFuture};
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::router::RouterError;
use crate::transport::client::pool::ConnectionPool;
use crate::transport::multiplex::MuxConnector;
use crate::transport::policy::PolicyConfig;
use crate::transport::{MessageCollector, MessageEmitter, PersistentConnection, Protocol, X509ClientConfig};
use crate::utils::urn::Urn;
use crate::{Frame, Metadata, TightBeamError, Version};

/// Instance or type key to shared servlet address bytes.
type AddressMap = HashMap<Vec<u8>, Arc<[u8]>>;
/// Shared, lockable address map for concurrent route updates.
type SharedAddressMap = Arc<RwLock<AddressMap>>;

/// Shared address maps and pool used for sibling servlet calls.
pub struct HiveContextImpl<P: Protocol> {
	servlet_addresses: SharedAddressMap,
	type_index: SharedAddressMap,
	pool: Arc<ConnectionPool<P>>,
}

impl<P: Protocol> HiveContextImpl<P> {
	/// Empty maps bound to the hive servlet pool.
	pub fn new(pool: Arc<ConnectionPool<P>>) -> Self {
		Self {
			servlet_addresses: Arc::new(RwLock::new(HashMap::new())),
			type_index: Arc::new(RwLock::new(HashMap::new())),
			pool,
		}
	}

	/// Record an instance route; first registration per type wins the index.
	///
	/// `addr` moves into the instance map. The type index takes an extra
	/// [`Arc`] handle only when the type is new (refcount bump, not a byte
	/// copy). `type_bytes.to_vec()` is a real key copy for the type index.
	pub fn add_route(&self, key: Vec<u8>, addr: Arc<[u8]>, type_bytes: &[u8]) {
		let Ok(mut addrs) = self.servlet_addresses.write() else {
			return;
		};

		if let Ok(mut type_idx) = self.type_index.write() {
			// Arc::clone: share the same address bytes in the type index.
			type_idx.entry(type_bytes.to_vec()).or_insert_with(|| Arc::clone(&addr));
		}

		addrs.insert(key, addr);
	}

	/// Drop an instance route and repair the type index when needed.
	pub fn remove_route(&self, key: &[u8], type_urn: &Urn<'_>, type_bytes: &[u8], removed_addr: &Arc<[u8]>) {
		if let Ok(mut addrs) = self.servlet_addresses.write() {
			addrs.remove(key);
		}

		let Ok(mut type_idx) = self.type_index.write() else {
			return;
		};

		if type_idx.get(type_bytes) != Some(removed_addr) {
			return;
		}

		let type_prefix = type_prefix_bytes(type_urn);
		let Ok(addrs) = self.servlet_addresses.read() else {
			return;
		};

		let replacement = addrs
			.iter()
			.find(|(k, _)| k.starts_with(&type_prefix))
			.map(|(_, a)| Arc::clone(a));
		match replacement {
			Some(new_addr) => {
				type_idx.insert(type_bytes.to_vec(), new_addr);
			}
			None => {
				type_idx.remove(type_bytes);
			}
		}
	}

	fn build_frame(id: &[u8], message: Vec<u8>) -> Frame {
		Frame {
			version: Version::V0,
			metadata: Metadata {
				id: id.to_vec(),
				order: 0,
				compactness: None,
				integrity: None,
				confidentiality: None,
				priority: None,
				lifetime: None,
				previous_frame: None,
				matrix: None,
			},
			message,
			integrity: None,
			nonrepudiation: None,
		}
	}

	fn resolve_addr(&self, servlet_type: &Urn<'_>) -> Result<P::Address, TightBeamError>
	where
		P::Address: core::str::FromStr,
	{
		let route_err = || TightBeamError::RouterError(RouterError::UnknownRoute);
		let type_idx = self.type_index.read().map_err(|_| TightBeamError::LockPoisoned)?;
		let type_key = canonical_bytes(servlet_type);
		let addr_bytes = type_idx.get(&type_key).cloned().ok_or_else(route_err)?;
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
	fn call<'a>(&'a self, servlet_type: &'a Urn<'a>, request: Vec<u8>) -> CallFuture<'a> {
		Box::pin(async move {
			let addr = self.resolve_addr(servlet_type)?;
			let mut pooled_conn = self.pool.connect(addr).await?;
			let frame = Self::build_frame(b"hive-call", request);
			let response = pooled_conn.emit(frame, None).await?;
			let message = match response {
				Some(mut frame) => core::mem::take(&mut frame.message),
				None => return Err(TightBeamError::MissingResponse),
			};

			Ok(message)
		})
	}

	fn open_stream<'a>(&'a self, servlet_type: &'a Urn<'a>) -> StreamOpenFuture<'a> {
		Box::pin(async move {
			let addr = self.resolve_addr(servlet_type)?;
			let pooled_conn = self.pool.connect(addr).await?;
			let (sink, response) = pooled_conn.open_stream()?;

			// The lease returns to the pool here; the sink and response live
			// on the shared mux plane independently.
			let response: StreamResponseFuture = Box::pin(async move {
				let reply = response.await?;
				let message = match reply {
					Some(mut frame) => core::mem::take(&mut frame.message),
					None => return Err(TightBeamError::MissingResponse),
				};

				Ok(message)
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

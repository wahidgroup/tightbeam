//! The hive's client for the cluster control plane.
//!
//! [`ClusterLink`] carries registration, the anti-entropy re-announce, and
//! the scaling fan-out. All three share one signed control frame shape and
//! the same transport identity rules.

use core::time::Duration;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::builder::TypeBuilder;
use crate::colony::common::{ClusterRequest, ServletChange, TaskGroup};
use crate::colony::hive::{
	HashMapRegistry, HiveConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdateResponse,
	ServletRegistry,
};
use crate::crypto::hash::Sha3_256;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::decode;
use crate::instrumentation::events::HIVE_REREGISTERED;
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::trace::TraceCollector;
use crate::transport::state::{DialableEncryption, EncryptionConfig};
use crate::transport::{EndpointConfig, MessageEmitter, Protocol, TransportResult};
use crate::utils::urn::Urn;
use crate::{Frame, Message, TightBeamError, Version};

/// This hive's link to the gateways it registered with.
///
/// # Shared state
///
/// Registration, the anti-entropy re-announce, and the scaling fan-out read
/// the same slate, gateway list, control address, and configuration. One
/// owner holds those four, so a caller names the operation and the link
/// supplies the state.
///
/// # Poison recovery
///
/// The gateway list changes by one push at a time, so a thread that
/// panicked while holding its lock left a whole list behind it. The link
/// therefore recovers a poisoned lock and keeps announcing.
pub struct ClusterLink<P: Protocol> {
	servlets: Arc<HashMapRegistry>,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	config: Arc<HiveConfig>,
}

impl<P: Protocol> Clone for ClusterLink<P>
where
	P::Address: Clone,
{
	fn clone(&self) -> Self {
		Self {
			servlets: Arc::clone(&self.servlets),
			cluster_addrs: Arc::clone(&self.cluster_addrs),
			hive_addr: self.hive_addr.clone(),
			config: Arc::clone(&self.config),
		}
	}
}

impl<P> ClusterLink<P>
where
	P: Protocol<CryptoProvider = DefaultCryptoProvider> + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + Send + 'static,
	TightBeamError: From<P::Error>,
{
	/// Binds the hive's slate and control address to its gateway list.
	pub fn new(
		servlets: Arc<HashMapRegistry>,
		cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
		hive_addr: P::Address,
		config: Arc<HiveConfig>,
	) -> Self {
		Self { servlets, cluster_addrs, hive_addr, config }
	}

	/// The gateway list for reading, recovered from a poisoned lock because
	/// every write under the guard leaves a whole list.
	fn addrs(&self) -> RwLockReadGuard<'_, Vec<P::Address>> {
		self.cluster_addrs.read().unwrap_or_else(PoisonError::into_inner)
	}

	/// The gateway list for writing, recovered the same way.
	fn addrs_mut(&self) -> RwLockWriteGuard<'_, Vec<P::Address>> {
		self.cluster_addrs.write().unwrap_or_else(PoisonError::into_inner)
	}

	/// The gateways this hive has registered with.
	pub fn gateways(&self) -> Vec<P::Address> {
		self.addrs().clone()
	}

	/// Whether any gateway has accepted this hive.
	pub fn has_gateways(&self) -> bool {
		!self.addrs().is_empty()
	}

	/// Records `gateway` as one this hive is registered with.
	///
	/// Registration is idempotent, so the list holds one row per gateway and
	/// each beat of [`ClusterLink::spawn_reregister`] dials each gateway once.
	pub fn remember(&self, gateway: P::Address) {
		let mut addrs = self.addrs_mut();
		let incoming: Vec<u8> = gateway.into();
		let known = addrs.iter().any(|addr| {
			let bytes: Vec<u8> = (*addr).into();
			bytes == incoming
		});
		if !known {
			addrs.push(gateway);
		}
	}

	/// Sends one signed registration of the current slate to `gateway`.
	pub async fn register(&self, gateway: P::Address) -> Result<RegisterHiveResponse, TightBeamError> {
		let servlet_addresses = self.servlets.slate();
		let request = ClusterRequest::RegisterHive(RegisterHiveRequest {
			hive_addr: self.hive_addr.into(),
			servlet_addresses,
			metadata: Some(b"hive".to_vec()),
		});

		let mut transport = self.dial(gateway).await?;
		let frame = self.control_frame(b"hive-registration", request).await?;
		let response_frame = transport.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
		decode::<RegisterHiveResponse>(response_frame.message())
	}

	/// Re-announces the current slate to every registered gateway.
	///
	/// Gateway registries are soft state, so a gateway that misses this
	/// announcement stays divergent until the next beat re-announces.
	pub async fn announce_slate(&self) {
		for gateway in self.gateways() {
			let _ = self.register(gateway).await;
		}
	}

	/// Runs the anti-entropy beat that re-announces the slate on an interval.
	///
	/// The beat ends once the hive drains: a hive that is going away stops
	/// advertising itself, and the drain announces its emptied slate once.
	pub fn spawn_reregister(&self, trace: Arc<TraceCollector>) -> rt::JoinHandle {
		let link = self.clone();
		rt::spawn(async move {
			let Some(interval) = link.config.control.reregister_interval else {
				return;
			};

			let clock = Arc::clone(&link.config.clock);
			let beat: Result<(), TightBeamError> = async move {
				loop {
					clock.sleep(interval).await;

					for gateway in link.gateways() {
						let outcome = link.register(gateway).await;
						let status = outcome.map(|response| response.status).unwrap_or(TransitStatus::Unavailable);
						trace.event_with(HIVE_REREGISTERED, &[], status)?;
					}
				}
			}
			.await;

			// A trace fault ends the beat, which is the effect a
			// `testing-fault` injection observes.
			drop(beat);
		})
	}

	/// Fans out one scaling add/remove update to every registered gateway.
	///
	/// A hive whose URN could not be created withholds the update, because
	/// the change needs an identity to attribute it to.
	///
	/// The fan-out runs under `tasks`, so stopping the hive stops an update
	/// still retrying against an unreachable gateway. Exhausted retries fall
	/// back to a full-slate announcement.
	pub(crate) fn notify_scaling(
		&self,
		tasks: &TaskGroup,
		hive_urn: Option<&Arc<Urn<'static>>>,
		change: ServletChange,
	) {
		let Some(hive_urn) = hive_urn.map(Arc::clone) else {
			return;
		};

		let link = self.clone();
		tasks.spawn(async move {
			let gateways = link.gateways();
			if gateways.is_empty() {
				return;
			}

			let update = ClusterRequest::ServletAddressUpdate(change.into_update(hive_urn.as_ref().clone()));
			let Ok(frame) = link.control_frame(b"scaling-update", update).await else {
				return;
			};

			let any_failed = link.fanout_scaling_update(&gateways, &frame).await;
			if any_failed {
				link.announce_slate().await;
			}
		});
	}

	/// Everything a cluster dial is built from.
	///
	/// A hive dials the cluster, so it answers the dialer's question here
	/// rather than at the first frame it tries to write. A hive identity with
	/// no trust store would present that identity to whoever answered the
	/// cluster address (CWE-295). A TLS-registered hive therefore never falls
	/// back to cleartext for a scaling update (CWE-319).
	fn endpoint(&self) -> TransportResult<EndpointConfig<DefaultCryptoProvider>> {
		let mut encryption = EncryptionConfig::unconfigured();
		if let Some(store) = &self.config.trust_store {
			encryption.trust_store = Some(Arc::clone(store));
		}
		if let Some(hive_tls) = &self.config.hive_tls {
			hive_tls.identity().install(&mut encryption);
		}

		let encryption = DialableEncryption::new(encryption)?;
		Ok(EndpointConfig::new(encryption, Arc::clone(&self.config.clock)))
	}

	/// One transport to `gateway` under this hive's identity.
	async fn dial(&self, gateway: P::Address) -> Result<P::Transport, TightBeamError> {
		let endpoint = self.endpoint()?;
		let stream = P::connect(gateway).await?;
		Ok(P::create_transport(stream, endpoint))
	}

	/// A hive-to-cluster control frame, signed when hive TLS is configured.
	async fn control_frame(&self, id: impl AsRef<[u8]>, message: impl Message) -> Result<Frame, TightBeamError> {
		let id = id.as_ref();
		// `metadata.order` is the control freshness binding (CWE-294).
		let order = self.config.clock.unix();

		match self.config.hive_tls.as_ref() {
			Some(hive_tls) => {
				// Signatures are a V1 field (§5.6), so a signed frame is V1.
				let mut signed = Version::V1
					.compose()
					.with_id(id)
					.with_order(order.get())
					.with_message(message)
					.build()?;
				signed
					.sign_with_provider::<Sha3_256, _>(hive_tls.identity().signing_provider())
					.await?;
				Ok(signed)
			}
			None => {
				let frame = Version::V0
					.compose()
					.with_id(id)
					.with_order(order.get())
					.with_message(message)
					.build()?;
				Ok(frame)
			}
		}
	}

	/// Sends `frame` to every gateway, returning whether any refused it.
	async fn fanout_scaling_update(&self, gateways: impl AsRef<[P::Address]>, frame: &Frame) -> bool {
		let gateways = gateways.as_ref();
		let mut any_failed = false;

		for gateway in gateways.iter().copied() {
			let accepted = self.emit_scaling_update_with_retry(gateway, frame).await;
			if !accepted {
				any_failed = true;
			}
		}

		any_failed
	}

	/// Sends `frame` to `gateway` under the notify retry policy, returning
	/// whether the gateway accepted it.
	async fn emit_scaling_update_with_retry(&self, gateway: P::Address, frame: &Frame) -> bool {
		// The provisioning does not change between attempts, and a refused
		// dial is a configuration this loop cannot retry its way out of.
		let Ok(endpoint) = self.endpoint() else {
			return false;
		};

		let max_attempts = self.config.control.notify_retry.max_attempts();
		for attempt in 0..=max_attempts {
			let Ok(stream) = P::connect(gateway).await else {
				self.retry_delay(attempt).await;
				continue;
			};

			// A transport-level answer is not acceptance, so the body MUST
			// carry `TransitStatus::Ok`.
			let mut transport = P::create_transport(stream, endpoint.clone());
			match transport.emit(frame.clone(), None).await {
				Ok(Some(response)) => {
					let decoded = decode::<ServletAddressUpdateResponse>(response.message());
					if matches!(decoded, Ok(body) if body.status == TransitStatus::Ok) {
						return true;
					}

					self.retry_delay(attempt).await;
				}
				Ok(None) | Err(_) => {
					self.retry_delay(attempt).await;
				}
			}
		}

		false
	}

	/// Waits out the notify retry policy's delay before `attempt`'s retry,
	/// on the hive clock. The last attempt has no retry to wait for.
	async fn retry_delay(&self, attempt: usize) {
		let policy = &self.config.control.notify_retry;
		if attempt < policy.max_attempts() {
			let delay = Duration::from_millis(policy.delay_ms(attempt));
			self.config.clock.sleep(delay).await;
		}
	}
}

//! Hive-to-cluster control-plane client helpers.
//!
//! Registration, anti-entropy re-announce, and scaling fan-out share one
//! signed control frame shape and the same transport identity rules.

use std::sync::{Arc, RwLock};

use crate::builder::TypeBuilder;
use crate::colony::common::{current_timestamp_ms, ClusterRequest, DrainMode, TaskGroup};
use crate::colony::hive::{
	HashMapRegistry, HiveConfig, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
	ServletAddressUpdateResponse, ServletInfo, ServletRegistry,
};
use crate::crypto::hash::Sha3_256;
use crate::crypto::profiles::DefaultCryptoProvider;
use crate::crypto::x509::store::CertificateTrust;
use crate::crypto::x509::Certificate;
use crate::decode;
use crate::instrumentation::events::HIVE_REREGISTERED;
use crate::policy::TransitStatus;
use crate::runtime::rt;
use crate::trace::TraceCollector;
use crate::transport::handshake::HandshakeKeyManager;
use crate::transport::policy::CoreRetryPolicy;
use crate::transport::{MessageEmitter, Protocol, X509ClientConfig};
use crate::utils::compose;
use crate::utils::urn::Urn;
use crate::{Frame, Message, TightBeamError, Version};

type ClientIdentity = (Arc<Certificate>, Arc<HandshakeKeyManager<DefaultCryptoProvider>>);

/// Build a hive-to-cluster control frame, signed when hive TLS is configured.
async fn build_control_frame(
	id: &[u8],
	message: impl Message,
	hive_tls: Option<Arc<HiveTlsConfig>>,
) -> Result<Frame, TightBeamError> {
	// `metadata.order` is the control freshness binding (CWE-294).
	let order = current_timestamp_ms();

	match hive_tls.as_ref() {
		Some(hive_tls) => {
			let unsigned = compose(Version::V0)
				.with_id(id)
				.with_order(order)
				.with_message(message)
				.build()?;
			let signed = unsigned.sign_with_provider::<Sha3_256, _>(hive_tls.key.as_ref()).await?;
			Ok(signed)
		}
		None => {
			let frame = compose(Version::V0)
				.with_id(id)
				.with_order(order)
				.with_message(message)
				.build()?;
			Ok(frame)
		}
	}
}

/// This hive's link to the gateways it registered with.
///
/// Registration, the anti-entropy re-announce, and the scaling fan-out read
/// the same slate, gateway list, control address, and configuration. One
/// owner holds those four, so a caller names the operation and the link
/// supplies the state.
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
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + 'static,
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

	/// Gateways this hive has registered with.
	///
	/// A poisoned list reads as empty, which is the same refusal every
	/// other reader of this list makes: a known gateway is what gives the
	/// hive something to announce to and something to scale for.
	pub fn gateways(&self) -> Vec<P::Address> {
		self.cluster_addrs.read().map(|addrs| addrs.clone()).unwrap_or_default()
	}

	/// Whether any gateway has accepted this hive.
	pub fn has_gateways(&self) -> bool {
		self.cluster_addrs.read().is_ok_and(|addrs| !addrs.is_empty())
	}

	/// Records `gateway` as one this hive is registered with.
	///
	/// Registration is idempotent, so the list holds one row per gateway and
	/// the beat below dials each once.
	pub fn remember(&self, gateway: P::Address) {
		let Ok(mut addrs) = self.cluster_addrs.write() else {
			return;
		};

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

		let trust_store = self.config.trust_store.as_ref();
		let hive_tls = self.config.hive_tls.as_ref();
		let mut transport = dial_cluster::<P>(gateway, trust_store, hive_tls).await?;
		let hive_tls_for_frame = self.config.hive_tls.as_ref().map(Arc::clone);

		let frame = build_control_frame(b"hive-registration", request, hive_tls_for_frame).await?;
		let response_frame = transport.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;
		decode::<RegisterHiveResponse>(&response_frame.message)
	}

	/// Re-announces the current slate to every registered gateway.
	///
	/// Soft state: exhausted retries leave a gateway divergent until the
	/// next beat re-announces.
	pub async fn announce_slate(&self) {
		for gateway in self.gateways() {
			let _ = self.register(gateway).await;
		}
	}

	/// Runs the anti-entropy beat that re-announces the slate on an interval.
	///
	/// The beat ends once the hive drains: a hive that is going away stops
	/// advertising itself, and the drain announces its emptied slate once.
	pub fn spawn_reregister(&self, trace: Arc<TraceCollector>, drain: DrainMode) -> rt::JoinHandle {
		let link = self.clone();
		rt::spawn(async move {
			let Some(interval) = link.config.control.reregister_interval else {
				return;
			};

			loop {
				tokio::time::sleep(interval).await;

				if drain.is_draining() {
					return;
				}

				for gateway in link.gateways() {
					let outcome = link.register(gateway).await;
					let status = outcome.map(|response| response.status).unwrap_or(TransitStatus::Unavailable);
					let _ = trace.event_with(HIVE_REREGISTERED, &[], status);
				}
			}
		})
	}

	/// Fans out one scaling add/remove update to every registered gateway.
	///
	/// A hive whose URN could not be minted holds its announcement, because
	/// the change needs an identity to attribute it to.
	///
	/// The fan-out runs under `tasks`, so stopping the hive stops an update
	/// still retrying against an unreachable gateway. Exhausted retries fall
	/// back to a full-slate announcement.
	pub fn notify_scaling(
		&self,
		tasks: &TaskGroup,
		hive_urn: Option<&Arc<Urn<'static>>>,
		servlet_info: ServletInfo,
		is_added: bool,
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

			let update = scaling_update_request(&hive_urn, servlet_info, is_added);
			let hive_tls = link.config.hive_tls.as_ref().map(Arc::clone);
			let trust_store = link.config.trust_store.as_ref().map(Arc::clone);

			let Ok(frame) = build_control_frame(b"scaling-update", update, hive_tls.clone()).await else {
				return;
			};

			// A TLS-registered hive must not fall back to cleartext for scaling updates (CWE-319).
			let Some(client_identity) = resolve_client_identity(hive_tls.as_ref()) else {
				return;
			};

			let any_failed = fanout_scaling_update::<P>(
				&gateways,
				&frame,
				trust_store.as_ref(),
				client_identity.as_ref(),
				link.config.control.notify_retry.as_ref(),
			)
			.await;

			if any_failed {
				link.announce_slate().await;
			}
		});
	}
}

fn scaling_update_request(hive_urn: &Urn<'static>, servlet_info: ServletInfo, is_added: bool) -> ClusterRequest {
	if is_added {
		return ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
			hive_id: hive_urn.clone(),
			added: vec![servlet_info],
			removed: vec![],
		});
	}

	ClusterRequest::ServletAddressUpdate(ServletAddressUpdate {
		hive_id: hive_urn.clone(),
		added: vec![],
		removed: vec![servlet_info.servlet_id],
	})
}

/// `None` aborts the notify task (TLS configured but identity unusable).
/// `Some(None)` is cleartext. `Some(Some(_))` is a client identity.
fn resolve_client_identity(hive_tls: Option<&Arc<HiveTlsConfig>>) -> Option<Option<ClientIdentity>> {
	match hive_tls {
		Some(hive_tls) => {
			let cert = Certificate::try_from(hive_tls.certificate.clone()).ok()?;
			let key_mgr = HandshakeKeyManager::new(Arc::clone(&hive_tls.key));
			Some(Some((Arc::new(cert), Arc::new(key_mgr))))
		}
		None => Some(None),
	}
}

async fn dial_cluster<P>(
	cluster_addr: P::Address,
	trust_store: Option<&Arc<dyn CertificateTrust>>,
	hive_tls: Option<&Arc<HiveTlsConfig>>,
) -> Result<P::Transport, TightBeamError>
where
	P: Protocol + Send + Sync,
	P::Address: Clone + Send + Sync,
	P::Stream: Send,
	P::Error: Send,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send,
	TightBeamError: From<P::Error>,
{
	let stream = P::connect(cluster_addr).await?;
	let mut transport = P::create_transport(stream);
	if let Some(store) = trust_store {
		transport = transport.with_trust_store(Arc::clone(store));
	}
	if let Some(hive_tls) = hive_tls {
		let cert = Certificate::try_from(hive_tls.certificate.clone())?;
		let key_mgr = HandshakeKeyManager::new(Arc::clone(&hive_tls.key));
		transport = transport.with_client_identity(Arc::new(cert), Arc::new(key_mgr));
	}

	Ok(transport)
}

async fn fanout_scaling_update<P>(
	gateways: &[P::Address],
	frame: &Frame,
	trust_store: Option<&Arc<dyn CertificateTrust>>,
	client_identity: Option<&ClientIdentity>,
	retry_policy: &dyn CoreRetryPolicy,
) -> bool
where
	P: Protocol + Send + Sync,
	P::Address: Clone + Copy + Send + Sync,
	P::Stream: Send,
	P::Error: Send,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send,
{
	let max_attempts = retry_policy.max_attempts();
	let mut any_failed = false;

	for gateway in gateways.iter().copied() {
		let accepted = emit_scaling_update_with_retry::<P>(
			gateway,
			frame,
			trust_store,
			client_identity,
			retry_policy,
			max_attempts,
		)
		.await;
		if !accepted {
			any_failed = true;
		}
	}

	any_failed
}

async fn emit_scaling_update_with_retry<P>(
	gateway: P::Address,
	frame: &Frame,
	trust_store: Option<&Arc<dyn CertificateTrust>>,
	client_identity: Option<&ClientIdentity>,
	retry_policy: &dyn CoreRetryPolicy,
	max_attempts: usize,
) -> bool
where
	P: Protocol + Send + Sync,
	P::Address: Clone + Copy + Send + Sync,
	P::Stream: Send,
	P::Error: Send,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send,
{
	for attempt in 0..=max_attempts {
		let Ok(stream) = P::connect(gateway).await else {
			retry_delay(attempt, max_attempts, retry_policy).await;
			continue;
		};

		let mut transport = P::create_transport(stream);
		if let Some(store) = trust_store {
			transport = transport.with_trust_store(Arc::clone(store));
		}
		if let Some((cert, key_mgr)) = client_identity {
			transport = transport.with_client_identity(Arc::clone(cert), Arc::clone(key_mgr));
		}

		// Transport Ok is not acceptance: require TransitStatus::Ok in the body.
		match transport.emit(frame.clone(), None).await {
			Ok(Some(response)) => {
				let decoded = decode::<ServletAddressUpdateResponse>(&response.message);
				if matches!(decoded, Ok(body) if body.status == TransitStatus::Ok) {
					return true;
				}

				retry_delay(attempt, max_attempts, retry_policy).await;
			}
			Ok(None) | Err(_) => {
				retry_delay(attempt, max_attempts, retry_policy).await;
			}
		}
	}

	false
}

async fn retry_delay(attempt: usize, max: usize, policy: &dyn CoreRetryPolicy) {
	if attempt < max {
		let delay = core::time::Duration::from_millis(policy.delay_ms(attempt));
		tokio::time::sleep(delay).await;
	}
}

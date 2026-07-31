//! Hive-to-cluster control-plane client helpers.
//!
//! Registration, anti-entropy re-announce, and scaling fan-out share one
//! signed control frame shape and the same transport identity rules.

use std::sync::{Arc, RwLock};

use crate::builder::TypeBuilder;
use crate::colony::common::{current_timestamp_ms, ClusterRequest};
use crate::colony::hive::runtime::servlet_slate;
use crate::colony::hive::{
	HiveConfig, HiveTlsConfig, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdate,
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
pub async fn build_control_frame(
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

/// One signed registration of the hive's current servlet slate to one gateway.
pub async fn register_once<P>(
	servlets: &impl ServletRegistry,
	hive_addr: P::Address,
	cluster_addr: P::Address,
	config: &HiveConfig,
) -> Result<RegisterHiveResponse, TightBeamError>
where
	P: Protocol + Send + Sync,
	P::Address: Clone + Send + Sync,
	P::Stream: Send,
	P::Error: Send,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send,
	TightBeamError: From<P::Error>,
{
	let servlet_addresses = servlet_slate(servlets);
	let request = ClusterRequest::RegisterHive(RegisterHiveRequest {
		hive_addr: hive_addr.into(),
		servlet_addresses,
		metadata: Some(b"hive".to_vec()),
	});

	let mut transport = dial_cluster::<P>(cluster_addr, config.trust_store.as_ref(), config.hive_tls.as_ref()).await?;
	let hive_tls_for_frame = config.hive_tls.as_ref().map(Arc::clone);
	let frame = build_control_frame(b"hive-registration", request, hive_tls_for_frame).await?;

	let response_frame = transport.emit(frame, None).await?.ok_or(TightBeamError::MissingResponse)?;

	decode::<RegisterHiveResponse>(&response_frame.message)
}

/// Anti-entropy beat: re-announce the full slate to every registered gateway.
pub fn spawn_reregister_task<P>(
	servlets: Arc<impl ServletRegistry + 'static>,
	trace: Arc<TraceCollector>,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	config: HiveConfig,
) -> rt::JoinHandle
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + 'static,
	TightBeamError: From<P::Error>,
{
	rt::spawn(async move {
		let Some(interval) = config.control.reregister_interval else {
			return;
		};

		loop {
			tokio::time::sleep(interval).await;

			let Some(gateways) = snapshot_gateways(&cluster_addrs) else {
				return;
			};

			for gateway in gateways {
				let outcome = register_once::<P>(&*servlets, hive_addr.clone(), gateway, &config).await;
				let status = outcome.map(|response| response.status).unwrap_or(TransitStatus::Unavailable);
				let _ = trace.event_with(HIVE_REREGISTERED, &[], status);
			}
		}
	})
}

/// Fan out a scaling add/remove update to every registered gateway.
///
/// Exhausted retries trigger an immediate full-slate reconcile to every peer.
pub fn notify_cluster<P>(
	servlets: Arc<impl ServletRegistry + 'static>,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	hive_urn: Arc<Urn<'static>>,
	servlet_info: ServletInfo,
	is_added: bool,
	config: Arc<HiveConfig>,
) where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send + 'static,
	TightBeamError: From<P::Error>,
{
	rt::spawn(async move {
		let Some(gateways) = snapshot_gateways(&cluster_addrs) else {
			return;
		};
		if gateways.is_empty() {
			return;
		}

		let update = scaling_update_request(&hive_urn, servlet_info, is_added);
		let hive_tls = config.hive_tls.as_ref().map(Arc::clone);
		let trust_store = config.trust_store.as_ref().map(Arc::clone);

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
			config.control.notify_retry.as_ref(),
		)
		.await;

		if any_failed {
			reconcile_all::<P>(&*servlets, hive_addr, &gateways, &config).await;
		}
	});
}

fn snapshot_gateways<A: Clone>(cluster_addrs: &RwLock<Vec<A>>) -> Option<Vec<A>> {
	let guard = cluster_addrs.read().ok()?;
	Some(guard.clone())
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

async fn reconcile_all<P>(
	servlets: &impl ServletRegistry,
	hive_addr: P::Address,
	gateways: &[P::Address],
	config: &HiveConfig,
) where
	P: Protocol + Send + Sync,
	P::Address: Clone + Send + Sync,
	P::Stream: Send,
	P::Error: Send,
	P::Transport: MessageEmitter + X509ClientConfig<CryptoProvider = DefaultCryptoProvider> + Send,
	TightBeamError: From<P::Error>,
{
	// Soft-state reconcile: exhausted retries leave peers divergent until the next beat.
	for gateway in gateways {
		let _ = register_once::<P>(servlets, hive_addr.clone(), gateway.clone(), config).await;
	}
}

async fn retry_delay(attempt: usize, max: usize, policy: &dyn CoreRetryPolicy) {
	if attempt < max {
		let delay = core::time::Duration::from_millis(policy.delay_ms(attempt));
		tokio::time::sleep(delay).await;
	}
}

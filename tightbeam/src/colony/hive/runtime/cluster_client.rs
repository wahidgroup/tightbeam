//! The hive's client for the cluster control plane.
//!
//! [`ClusterLink`] carries registration, the anti-entropy re-announce, and
//! the scaling fan-out. All three share one control frame shape, signed when
//! hive TLS is configured, the same transport identity rules, and the hive's
//! trace.

use core::time::Duration;
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::builder::TypeBuilder;
use crate::colony::hive::{HiveConfig, ServletRegistry};
use crate::colony::protocol::{
	ClusterRequest, IssueClock, RegisterHiveRequest, RegisterHiveResponse, ServletAddressUpdateResponse, ServletChange,
};
use crate::instrumentation::events::HIVE_REREGISTERED;
use crate::policy::TransitStatus;
use crate::runtime::{rt, TaskGroup};
use crate::trace::{TraceCollector, TraceHandle};
use crate::transport::accept::ConnectionTerms;
use crate::transport::multiplex::MuxCapable;
use crate::transport::state::{DialableEncryption, EncryptedProtocolState};
use crate::transport::{EndpointConfig, MessageEmitter, Protocol, TransportResult};
use crate::urn::Urn;
use crate::{Frame, Message, TightBeamError, Version};

/// This hive's link to the gateways it registered with.
///
/// # Shared state
///
/// Registration, the anti-entropy re-announce, and the scaling fan-out read
/// one slate, gateway list, control address, and configuration. The link
/// holds all four, so a caller names the operation and the link supplies the
/// state.
///
/// # Poison recovery
///
/// The gateway list changes by one push at a time, so a thread that panicked
/// under the lock left a whole list. The link recovers a poisoned lock, and
/// the announcements go on.
///
/// # Warning
///
/// Each transport the link dials records into the hive's trace, so the trace
/// holds the session of each dial, a failed one included. The default
/// `BoundedMemorySink` drops each event past `max_events`, the hive's own
/// included, so a long-lived hive needs an `EventSink` that forwards each
/// event, or a reader that drains the trace.
pub struct ClusterLink<P: Protocol, R: ServletRegistry> {
	servlets: Arc<R>,
	cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
	hive_addr: P::Address,
	config: Arc<HiveConfig>,
	/// The hive's trace, which each announcement records into.
	trace: Arc<TraceCollector>,
	/// The terms the link sets on each transport it dials: the hive's trace,
	/// and no mux offer, because each control exchange is one request.
	terms: ConnectionTerms,
	/// The issue times of the hive's control frames, which the hive shares
	/// with every link it builds.
	issue_clock: Arc<IssueClock>,
}

impl<P: Protocol, R: ServletRegistry> Clone for ClusterLink<P, R>
where
	P::Address: Clone,
{
	fn clone(&self) -> Self {
		Self {
			servlets: Arc::clone(&self.servlets),
			cluster_addrs: Arc::clone(&self.cluster_addrs),
			hive_addr: self.hive_addr.clone(),
			config: Arc::clone(&self.config),
			trace: Arc::clone(&self.trace),
			terms: self.terms.clone(),
			issue_clock: Arc::clone(&self.issue_clock),
		}
	}
}

impl<P, R> ClusterLink<P, R>
where
	P: Protocol + Send + Sync + 'static,
	P::Address: Clone + Copy + Send + Sync + 'static,
	P::Stream: Send + 'static,
	P::Error: Send + 'static,
	P::Transport: MessageEmitter + MuxCapable + EncryptedProtocolState + Send + 'static,
	R: ServletRegistry + 'static,
	TightBeamError: From<P::Error>,
{
	/// Binds the hive's slate, control address, configuration, trace, and
	/// issue clock to its gateway list.
	pub(crate) fn new(
		servlets: Arc<R>,
		cluster_addrs: Arc<RwLock<Vec<P::Address>>>,
		hive_addr: P::Address,
		config: Arc<HiveConfig>,
		trace: Arc<TraceCollector>,
		issue_clock: Arc<IssueClock>,
	) -> Self {
		let handle = TraceHandle::new(Arc::clone(&trace));
		let terms = ConnectionTerms::new(handle, None);

		Self { servlets, cluster_addrs, hive_addr, config, trace, terms, issue_clock }
	}

	/// Takes the read lock of the gateway list, and recovers a poisoned lock.
	fn addrs(&self) -> RwLockReadGuard<'_, Vec<P::Address>> {
		self.cluster_addrs.read().unwrap_or_else(PoisonError::into_inner)
	}

	/// Takes the write lock of the gateway list, and recovers a poisoned lock.
	fn addrs_mut(&self) -> RwLockWriteGuard<'_, Vec<P::Address>> {
		self.cluster_addrs.write().unwrap_or_else(PoisonError::into_inner)
	}

	/// Returns a copy of the list of gateways that accepted this hive.
	pub fn gateways(&self) -> Vec<P::Address> {
		self.addrs().clone()
	}

	/// Returns whether any gateway accepted this hive.
	pub fn has_gateways(&self) -> bool {
		!self.addrs().is_empty()
	}

	/// Records `gateway` as a gateway that accepted this hive.
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

	/// Sends one registration of the current slate to `gateway`, signed when
	/// hive TLS is configured.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingResponse`] -- the gateway answers with no frame.
	/// - [`TightBeamError`] -- the dial, the frame's build or signature, the
	///   exchange, or the decode of the answer fails.
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
		response_frame.decode_message::<RegisterHiveResponse>()
	}

	/// Announces the current slate to `gateway`, and records its answer as
	/// [`HIVE_REREGISTERED`]: the status it replies, or `Unavailable` for a
	/// registration that failed.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the event, the fault the `testing-fault` feature injects.
	async fn announce_to(&self, gateway: P::Address) -> Result<(), TightBeamError> {
		let outcome = self.register(gateway).await;
		let status = outcome.map(|response| response.status).unwrap_or(TransitStatus::Unavailable);
		let label = status.as_str();
		let evidence = || -> Option<Vec<u8>> { Some(gateway.into()) };
		let trace = &self.trace;
		trace.emit_event_with_value_and_rendered_evidence(HIVE_REREGISTERED, label, status, evidence)
	}

	/// Re-announces the current slate to every registered gateway, and
	/// records the answer of each one.
	///
	/// Gateway registries are soft state, so a gateway that misses this
	/// announcement stays divergent until the next beat re-announces.
	///
	/// # Errors
	///
	/// - [`TightBeamError`] -- the trace refused the record of an answer, the
	///   fault the `testing-fault` feature injects. The gateways after it hear
	///   no announcement.
	pub(crate) async fn announce_slate(&self) -> Result<(), TightBeamError> {
		for gateway in self.gateways() {
			self.announce_to(gateway).await?;
		}

		Ok(())
	}

	/// Runs the anti-entropy beat that re-announces the slate on an interval.
	///
	/// The beat ends once the hive drains, so the hive stops its
	/// advertisements, and the drain announces its emptied slate once.
	pub fn spawn_reregister(&self) -> rt::JoinHandle {
		let link = self.clone();
		rt::spawn(async move {
			let Some(interval) = link.config.control.reregister_interval else {
				return;
			};

			let clock = Arc::clone(&link.config.clock);
			let beat: Result<(), TightBeamError> = async move {
				loop {
					clock.sleep(interval).await;
					link.announce_slate().await?;
				}
			}
			.await;

			// A trace fault ends the beat, which is the effect a
			// `testing-fault` injection observes.
			drop(beat);
		})
	}

	/// Fans out one scaling update, an add or a removal, to every registered
	/// gateway.
	///
	/// - A hive whose URN failed to derive withholds the update, because the update names the hive.
	/// - The fan-out runs under `tasks`, so a hive stop also stops its retries.
	/// - A spent retry or an unbuilt frame falls back to the full slate, which records each gateway's answer.
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
			let any_failed = match link.control_frame(b"scaling-update", update).await {
				Ok(frame) => link.fanout_scaling_update(&gateways, &frame).await,
				// A frame that fails to build reaches no gateway, so the slate
				// announcement takes its place.
				Err(_unbuilt) => true,
			};
			if !any_failed {
				return;
			}

			// A trace fault ends the fallback, which is the effect a
			// `testing-fault` injection observes.
			let announced = link.announce_slate().await;
			drop(announced);
		});
	}

	/// The endpoint configuration of a cluster dial.
	///
	/// A hive dials the cluster, so [`DialableEncryption::new`] checks the
	/// dialer rule here, before the dial writes a frame. A hive identity with
	/// no trust store would present itself to whoever answers the cluster
	/// address (CWE-295). A TLS-registered hive never falls back to cleartext
	/// for a scaling update (CWE-319).
	fn endpoint(&self) -> TransportResult<EndpointConfig<P::CryptoProvider>> {
		let encryption = DialableEncryption::new(self.config.gateway_dial())?;
		Ok(EndpointConfig::new(encryption, Arc::clone(&self.config.clock)))
	}

	/// Opens one transport to `gateway` under this hive's identity.
	async fn dial(&self, gateway: P::Address) -> Result<P::Transport, TightBeamError> {
		let endpoint = self.endpoint()?;
		let transport = self.connect(gateway, endpoint).await?;
		Ok(transport)
	}

	/// Connects to `gateway` under `endpoint`, within its operation timeout,
	/// and sets the link's terms on the transport before its handshake. Every
	/// dial of the link connects here.
	async fn connect(
		&self,
		gateway: P::Address,
		endpoint: EndpointConfig<P::CryptoProvider>,
	) -> TransportResult<P::Transport> {
		let stream = endpoint.dial::<P>(gateway).await?;
		let transport = P::create_transport(stream, endpoint);
		Ok(self.terms.apply(transport))
	}

	/// Builds a hive-to-cluster control frame, signed when hive TLS is
	/// configured.
	async fn control_frame(&self, id: impl AsRef<[u8]>, message: impl Message) -> Result<Frame, TightBeamError> {
		let id = id.as_ref();
		// `metadata.order` is the control freshness binding (CWE-294), and the
		// orders of the hive increase strictly (README §5.7.1).
		let order = self.issue_clock.issue();
		match self.config.hive_tls.as_ref() {
			Some(hive_tls) => {
				// Signatures are a V1 field (§5.6), so a signed frame is V1.
				let mut signed = Version::V1
					.compose()
					.with_id(id)
					.with_order(order.instant().get())
					.with_message(message)
					.build()?;
				signed.sign_with_provider(hive_tls.identity()).await?;
				Ok(signed)
			}
			None => {
				let frame = Version::V0
					.compose()
					.with_id(id)
					.with_order(order.instant().get())
					.with_message(message)
					.build()?;
				Ok(frame)
			}
		}
	}

	/// Sends `frame` to every gateway and returns whether any gateway failed
	/// to accept it.
	async fn fanout_scaling_update(&self, gateways: impl AsRef<[P::Address]>, frame: &Frame) -> bool {
		let mut any_failed = false;

		let gateways = gateways.as_ref();
		for gateway in gateways.iter().copied() {
			let accepted = self.emit_scaling_update_with_retry(gateway, frame).await;
			if !accepted {
				any_failed = true;
			}
		}

		any_failed
	}

	/// Sends `frame` to `gateway` under the notify retry policy and returns
	/// whether the gateway accepted it.
	async fn emit_scaling_update_with_retry(&self, gateway: P::Address, frame: &Frame) -> bool {
		// The provisioning holds across attempts, so a refused endpoint is a
		// configuration fault that no retry of this loop repairs.
		let Ok(endpoint) = self.endpoint() else {
			return false;
		};

		let max_attempts = self.config.control.notify_retry.max_attempts();
		for attempt in 0..=max_attempts {
			let Ok(mut transport) = self.connect(gateway, endpoint.clone()).await else {
				self.retry_delay(attempt).await;
				continue;
			};

			// A transport-level answer is not acceptance, so the body MUST
			// carry `TransitStatus::Ok`.
			match transport.emit(frame.clone(), None).await {
				Ok(Some(response)) => {
					let decoded = response.decode_message::<ServletAddressUpdateResponse>();
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
	/// on the hive clock. After the last attempt it returns at once, because
	/// no retry follows.
	async fn retry_delay(&self, attempt: usize) {
		let policy = &self.config.control.notify_retry;
		if attempt < policy.max_attempts() {
			let delay = Duration::from_millis(policy.delay_ms(attempt));
			self.config.clock.sleep(delay).await;
		}
	}
}

//! Cluster macros for generating cluster gateway servers

/// Macro for creating clusters with pre-configured settings
///
/// The runtime configuration is supplied to `Cluster::start`, not to the
/// macro.
///
/// # Syntax
///
/// ```ignore
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener
/// }
///
/// // With custom digest:
/// cluster! {
///     pub MyCluster,
///     protocol: TokioListener,
///     digest: Blake3
/// }
/// ```
#[macro_export]
macro_rules! cluster {
	// Public with custom digest
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $digest, [pub], [$(#[$meta])*]);
	};

	// Public with default digest (Sha3_256)
	(
		$(#[$meta:meta])*
		pub $cluster_name:ident,
		protocol: $protocol:path
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $crate::crypto::hash::Sha3_256, [pub], [$(#[$meta])*]);
	};

	// Private with custom digest
	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path,
		digest: $digest:path
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $digest, [], [$(#[$meta])*]);
	};

	// Private with default digest (Sha3_256)
	(
		$(#[$meta:meta])*
		$cluster_name:ident,
		protocol: $protocol:path
	) => {
		$crate::cluster!(@impl_cluster $cluster_name, $protocol, $crate::crypto::hash::Sha3_256, [], [$(#[$meta])*]);
	};

	// Generate cluster struct
	(@impl_cluster $cluster_name:ident, $protocol:path, $digest:path, [$($vis:tt)*], [$(#[$meta:meta])*]) => {
		$(#[$meta])*
		$($vis)* struct $cluster_name {
			registry: ::std::sync::Arc<$crate::colony::cluster::HiveRegistry>,
			servlet_registry: ::std::sync::Arc<$crate::colony::cluster::ServletRegistry>,
			config: ::std::sync::Arc<$crate::colony::cluster::ClusterConf>,
			pool: ::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>,
			peer_pool: ::core::option::Option<::std::sync::Arc<$crate::transport::client::pool::ConnectionPool<$protocol>>>,
			server_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			heartbeat_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			evaporation_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			advertise_handle: Option<$crate::colony::servlet::servlet_runtime::rt::JoinHandle>,
			addr: <$protocol as $crate::transport::Protocol>::Address,
			trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
		}

		$crate::cluster!(@impl_cluster_trait $cluster_name, $protocol, $digest);
		$crate::cluster!(@impl_drop $cluster_name);
	};

	// Implement Cluster trait
	(@impl_cluster_trait $cluster_name:ident, $protocol:path, $digest:path) => {
		impl $crate::colony::cluster::Cluster for $cluster_name {
			type Protocol = $protocol;
			type Address = <$protocol as $crate::transport::Protocol>::Address;

			async fn start(
				trace: ::std::sync::Arc<$crate::trace::TraceCollector>,
				config: $crate::colony::cluster::ClusterConf,
			) -> Result<Self, $crate::TightBeamError> {
				use $crate::transport::Protocol;

				// The admission freshness window MUST NOT outlive journal
				// retention: a rumor older than retention has no digest
				// left to deduplicate against, so a wider window would
				// re-admit a replayed rumor as new (CWE-294). Clamped
				// here, where the config becomes immutable, so mutation
				// after the builder cannot widen the window.
				#[cfg(feature = "x509")]
				let config = {
					let mut config = config;
					let retention =
						::core::time::Duration::from_millis(config.gossip.journal.retention_ms());
					if config.gossip.seen_ttl > retention {
						config.gossip.seen_ttl = retention;
					}
					config
				};

				let config = ::std::sync::Arc::new(config);

				// The gateway always serves TLS when x509 is enabled;
				// an empty client_validators list means server-auth only
				let bind_addr = match config.bind_addr.as_deref() {
					Some(raw) => raw
						.parse()
						.map_err(|_| $crate::transport::TransportError::InvalidMessage)?,
					None => <$protocol>::default_bind_address()?,
				};

				#[cfg(feature = "x509")]
				let (listener, addr) = {
					// Spec cloned because try_from consumes and config is shared
					let cert_obj = $crate::crypto::x509::Certificate::try_from(config.tls.certificate.clone())?;
					let key_mgr = $crate::transport::handshake::HandshakeKeyManager::new(
						::std::sync::Arc::clone(&config.tls.key)
					);
					let mut encryption_config = $crate::transport::TransportEncryptionConfig::new(cert_obj, key_mgr);
					if !config.tls.client_validators.is_empty() {
						let validators: Vec<_> = config.tls.client_validators.iter().map(::std::sync::Arc::clone).collect();
						encryption_config = encryption_config.with_client_validators(validators);
					}
					<$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, encryption_config).await?
				};

				#[cfg(not(feature = "x509"))]
				let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await?;

				let registry = ::std::sync::Arc::new(
					$crate::colony::cluster::HiveRegistry::new(config.heartbeat.timeout)
				);

				let servlet_registry = ::std::sync::Arc::new(
					$crate::colony::cluster::ServletRegistry::new(config.pheromone.clone())
				);

				let pools = $crate::colony::cluster::outbound::build_cluster_pools::<$protocol>(
					config.pool_config.clone(),
					&config.tls,
				)?;
				let pool = pools.hive;
				let peer_pool = pools.peer;

				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let servlet_registry_for_server = ::std::sync::Arc::clone(&servlet_registry);
				let config_for_server = ::std::sync::Arc::clone(&config);
				let pool_for_server = ::std::sync::Arc::clone(&pool);
				let peer_pool_for_server = peer_pool.as_ref().map(::std::sync::Arc::clone);
				let trace_for_server = ::std::sync::Arc::clone(&trace);

				// Freshness window + replay set for signed hive control frames
				// (registration, address updates). Shared across all gateway
				// requests (CWE-294)
				#[cfg(feature = "x509")]
				let replay_guard_for_server = ::std::sync::Arc::new(
					$crate::colony::hive::ReplayGuard::new(config.control_freshness_window_ms)
				);
				#[cfg(not(feature = "x509"))]
				let replay_guard_for_server = ();

				let server_handle = $crate::cluster!(
					@build_gateway_server $protocol,
					listener,
					registry_for_server,
					servlet_registry_for_server,
					config_for_server,
					pool_for_server,
					peer_pool_for_server,
					trace_for_server,
					replay_guard_for_server,
					$digest
				);

				// Start the heartbeat loop (colony requires tokio):
				// JoinSet gives bounded concurrency per cycle.
				let heartbeat_handle = {
					let registry = ::std::sync::Arc::clone(&registry);
					let servlet_registry_for_hb = ::std::sync::Arc::clone(&servlet_registry);
					let config = ::std::sync::Arc::clone(&config);
					let pool = ::std::sync::Arc::clone(&pool);
					let trace_for_hb = ::std::sync::Arc::clone(&trace);

					$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
						loop {
							let hives = registry.all_hives().unwrap_or_default();
							let max_concurrent = config.heartbeat.max_concurrent;
							let mut set = ::tokio::task::JoinSet::new();

							let tasks: Vec<_> = hives
								.into_iter()
								.filter_map(|hive| $crate::cluster!(@parse_hive_addr hive))
								.collect();

							for (hive_addr, addr) in tasks {
								// Bounded: wait if at capacity
								while set.len() >= max_concurrent {
									let _ = set.join_next().await;
								}

								let registry = ::std::sync::Arc::clone(&registry);
								let servlet_registry = ::std::sync::Arc::clone(&servlet_registry_for_hb);
								let config = ::std::sync::Arc::clone(&config);
								let pool = ::std::sync::Arc::clone(&pool);
								let trace = ::std::sync::Arc::clone(&trace_for_hb);
								let max_failures = config.heartbeat.max_failures;

								set.spawn(async move {
									let result = $crate::cluster!(@send_heartbeat_async pool, config, addr, $digest);
									$crate::cluster!(@process_heartbeat_result registry, servlet_registry, hive_addr, result, max_failures, config, trace);
								});
							}

							// Drain remaining tasks
							while set.join_next().await.is_some() {}

							// Evict hives that exceeded the heartbeat timeout
							// (covers hives that were never reachable and thus
							// never accumulated per-send failures) and retire
							// their servlet routing entries with them.
							if let Ok(evicted) = registry.evict_stale() {
								for entry in evicted {
									let _ = servlet_registry_for_hb.remove_by_hive(&entry.address);
									let _ = trace_for_hb.event($crate::instrumentation::events::CLUSTER_HIVE_EVICTED);
								}
							}

							$crate::colony::servlet::servlet_runtime::rt::sleep(config.heartbeat.interval).await;
						}
					})
				};

				// Start the evaporation loop for bio-inspired routing
				let evaporation_handle = {
					let servlet_registry = ::std::sync::Arc::clone(&servlet_registry);
					let evaporation_interval = config.pheromone.evaporation_interval;

					$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
						loop {
							$crate::colony::servlet::servlet_runtime::rt::sleep(evaporation_interval).await;
							let _ = servlet_registry.evaporate();
							let _ = servlet_registry.remove_abandoned();
						}
					})
				};

				// Anti-entropy advertise beat: re-announce exported types to
				// every peer gateway each interval. Peer registries are soft
				// state, exactly like hive registration; signing needs the
				// key store, so the beat only exists with x509.
				#[cfg(feature = "x509")]
				let advertise_handle = {
					let advertise_pool = $crate::cluster!(@peer_dial_pool peer_pool, pool);
					let local_pool = ::std::sync::Arc::clone(&pool);
					let servlet_registry = ::std::sync::Arc::clone(&servlet_registry);
					let config = ::std::sync::Arc::clone(&config);
					let trace = ::std::sync::Arc::clone(&trace);
					let gateway_addr: Vec<u8> = addr.clone().into();

					::core::option::Option::Some($crate::cluster!(
						@build_advertise_task $protocol, servlet_registry, advertise_pool, local_pool, config, gateway_addr, trace, $digest
					))
				};
				#[cfg(not(feature = "x509"))]
				let advertise_handle = ::std::option::Option::None;

				Ok(Self {
					registry,
					servlet_registry,
					config,
					pool,
					peer_pool,
					server_handle: Some(server_handle),
					heartbeat_handle: Some(heartbeat_handle),
					evaporation_handle: Some(evaporation_handle),
					advertise_handle,
					addr,
					trace,
				})
			}

			fn addr(&self) -> Self::Address {
				self.addr
			}

			fn available_servlets(&self) -> Vec<Vec<u8>> {
				self.registry.to_available_servlets().unwrap_or_default()
			}

			fn peer_servlets(&self) -> Vec<Vec<u8>> {
				let mut types: Vec<Vec<u8>> = self
					.servlet_registry
					.peer_entries()
					.unwrap_or_default()
					.into_iter()
					.map(|entry| entry.servlet_type().to_vec())
					.collect();
				types.sort_unstable();
				types.dedup();
				types
			}

			fn peer_routes(&self) -> Vec<$crate::colony::cluster::PeerRouteInfo> {
				self.servlet_registry
					.peer_entries()
					.unwrap_or_default()
					.into_iter()
					.filter_map(|entry| entry.peer_route_info())
					.collect()
			}

			fn hive_count(&self) -> usize {
				self.registry.len().unwrap_or(0)
			}

			fn trace(&self) -> ::std::sync::Arc<$crate::trace::TraceCollector> {
				::std::sync::Arc::clone(&self.trace)
			}

			fn stop(mut self) {
				if let Some(handle) = self.advertise_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.evaporation_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
			}

			async fn join(mut self) -> Result<(), $crate::colony::servlet::servlet_runtime::rt::JoinError> {
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::join(handle).await
				} else {
					Ok(())
				}
			}

		}

		impl $crate::colony::cluster::ClusterHeartbeat for $cluster_name {
			fn registry(&self) -> &::std::sync::Arc<$crate::colony::cluster::HiveRegistry> {
				&self.registry
			}

			fn heartbeat_config(&self) -> &$crate::colony::cluster::HeartbeatConf {
				&self.config.heartbeat
			}

			async fn send_heartbeat(
				&self,
				addr: Self::Address,
			) -> Result<$crate::colony::common::HeartbeatResult, $crate::colony::cluster::ClusterError> {
				$crate::cluster!(@send_heartbeat_async self.pool, self.config, addr, $digest)
			}
		}
	};

	// Build gateway server
	(@build_gateway_server $protocol:path, $listener:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident, $peer_pool:ident, $trace:ident, $replay_guard:ident, $digest:path) => {{
		// Must be copied out before the handler closure captures the config.
		let __mux_offer = $config.pool_config.mux_offer.to_owned();
		$crate::server! {
			protocol $protocol: $listener,
			policies: { with_mux_offer: [ __mux_offer.to_owned() ] },
			handle: move |frame: $crate::Frame, session: $crate::policy::SessionContext| {
				let registry = ::std::sync::Arc::clone(&$registry);
				let servlet_registry = ::std::sync::Arc::clone(&$servlet_registry);
				let config = ::std::sync::Arc::clone(&$config);
				let pool = ::std::sync::Arc::clone(&$pool);
				let peer_pool = $peer_pool.as_ref().map(::std::sync::Arc::clone);
				let trace = ::std::sync::Arc::clone(&$trace);
				let _replay_guard = ::core::clone::Clone::clone(&$replay_guard);
				async move {
					$crate::cluster!(@handle_gateway_request frame, session, registry, servlet_registry, config, pool, peer_pool, trace, _replay_guard, $digest)
				}
			}
		}
	}};

	// Helper: Build response frame (DRY)
	(@reply $frame:ident, $message:expr) => {
		$crate::colony::common::reply_frame($frame.metadata.id.clone(), $message)
	};

	// Handle gateway requests (registration + work)
	(@handle_gateway_request $frame:ident, $session:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident, $peer_pool:ident, $trace:ident, $replay_guard:ident, $digest:path) => {{
		// Gate policies run before ANY decoding: an unevaluated policy
		// list is indistinguishable from an open gateway. Each gate sees
		// the connection's authenticated peer context.
		for policy in $config.policies.iter() {
			let status = $crate::policy::GatePolicy::evaluate(
				policy.as_ref(),
				::core::option::Option::Some(&$frame),
				&$session,
			);
			if status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_GATE_BLOCKED);
				return $crate::cluster!(@reply $frame,
					$crate::colony::cluster::ClusterWorkResponse::err(status)
				);
			}
		}

		// Hive-origin control frames (registration, address updates) must
		// carry a signature verifiable against `tls.hive_trust`. A gateway
		// without a trust store fails closed because accepting unauthenticated
		// control frames lets any network peer poison routing state (CWE-306).
		#[cfg(feature = "x509")]
		let verify_hive_origin = || match $config.tls.hive_trust.as_ref() {
			Some(trust) => match $crate::colony::hive::verify_frame_signature(trust.as_ref(), &$frame) {
				$crate::colony::hive::TrustVerification::Verified => $crate::policy::TransitStatus::Ok,
				$crate::colony::hive::TrustVerification::MissingSignature => $crate::policy::TransitStatus::Unauthenticated,
				_ => $crate::policy::TransitStatus::PermissionDenied,
			},
			None => $crate::policy::TransitStatus::PermissionDenied,
		};
		#[cfg(not(feature = "x509"))]
		let verify_hive_origin = || $crate::policy::TransitStatus::Ok;

		// Peer-origin control frames (advertisements) verify against a
		// SEPARATE trust anchor, `tls.peer_trust`: a hive certificate must
		// not forge a peer advertisement and vice versa. A gateway without
		// a peer trust store has federation disabled and refuses (CWE-306).
		#[cfg(feature = "x509")]
		let verify_peer_origin = || match $config.tls.peer_trust.as_ref() {
			Some(trust) => match $crate::colony::hive::verify_frame_signature(trust.as_ref(), &$frame) {
				$crate::colony::hive::TrustVerification::Verified => $crate::policy::TransitStatus::Ok,
				$crate::colony::hive::TrustVerification::MissingSignature => $crate::policy::TransitStatus::Unauthenticated,
				_ => $crate::policy::TransitStatus::PermissionDenied,
			},
			None => $crate::policy::TransitStatus::PermissionDenied,
		};

		#[cfg(not(feature = "x509"))]
		let verify_peer_origin = || $crate::policy::TransitStatus::Ok;

		// Signed control frames must additionally be fresh and unseen: a
		// captured registration or address update carries a valid signature,
		// so signature verification alone cannot stop replay (CWE-294).
		// Freshness binds to `metadata.order` (unix milliseconds), not a
		// body timestamp: the order field is already covered by the
		// nonrepudiation signature (§5.7.5).
		#[cfg(feature = "x509")]
		let verify_control_freshness = || {
			let now = $crate::colony::common::current_timestamp_ms();
			if !$replay_guard.is_fresh($frame.metadata.order, now) {
				return $crate::policy::TransitStatus::PermissionDenied;
			}

			let Some(signer_info) = $frame.nonrepudiation.as_ref() else {
				return $crate::policy::TransitStatus::Unauthenticated;
			};

			// Signer identifier keys the replay partition. An unencodable
			// identifier cannot be attributed.
			let Ok(signer_id) = $crate::der::Encode::to_der(&signer_info.sid) else {
				return $crate::policy::TransitStatus::PermissionDenied;
			};
			if !$replay_guard.check_and_insert(&signer_id, signer_info.signature.as_bytes(), now) {
				return $crate::policy::TransitStatus::PermissionDenied;
			}

			$crate::policy::TransitStatus::Ok
		};
		#[cfg(not(feature = "x509"))]
		let verify_control_freshness = || $crate::policy::TransitStatus::Ok;

		// Single decode of the CHOICE envelope: the tag discriminates
		// the request type. Undecodable input is rejected fail-closed.
		let cluster_request = match $crate::decode::<$crate::colony::common::ClusterRequest>(&$frame.message) {
			Ok(request) => request,
			Err(_) => {
				return $crate::cluster!(@reply $frame,
					$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::PermissionDenied)
				);
			}
		};

		match cluster_request {
		$crate::colony::common::ClusterRequest::RegisterHive(request) => {
			let origin_status = verify_hive_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_REGISTER_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::RegisterHiveResponse {
					status: origin_status,
					hive_id: None,
				});
			}

			let freshness_status = verify_control_freshness();
			if freshness_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_REGISTER_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::RegisterHiveResponse {
					status: freshness_status,
					hive_id: None,
				});
			}

			// Every announced identity must be an instance-narrowed
			// servlet URN in this gateway's namespace whose locator
			// bytes equal the route address: routes key by address,
			// removes key by URN locator, so a mismatch creates
			// unremovable ghost routes (CWE-639).
			let urns_valid = request.servlet_addresses.iter().all(|info| {
				match $config.namespace.validate(&info.servlet_id) {
					Ok($crate::colony::common::ColonyResource::Servlet {
						instance: ::std::option::Option::Some(locator),
						..
					}) => locator.as_bytes() == info.address.as_slice(),
					_ => false,
				}
			});
			if !urns_valid {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_REGISTER_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::RegisterHiveResponse {
					status: $crate::policy::TransitStatus::PermissionDenied,
					hive_id: None,
				});
			}

			// The hive's identity URN is minted from its control address.
			// An address that cannot mint an exact identity (non-UTF-8 or
			// empty) is refused up front: lossy minting would hand out an
			// identity whose bytes never match the registry key on later
			// updates.
			let hive_identity = core::str::from_utf8(&request.hive_addr)
				.ok()
				.and_then(|addr| $config.namespace.hive(addr).ok());
			let ::std::option::Option::Some(hive_identity) = hive_identity else {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_REGISTER_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::RegisterHiveResponse {
					status: $crate::policy::TransitStatus::PermissionDenied,
					hive_id: None,
				});
			};

			// One Arc allocation, shared by every route entry below;
			// copied out here because the registry consumes `request`.
			let hive_addr: ::std::sync::Arc<[u8]> = request.hive_addr.clone().into();

			// Route keys are the canonical TYPE bytes (instance tails
			// stripped): work targets types, never single instances.
			let servlet_info: Vec<(::std::sync::Arc<[u8]>, ::std::sync::Arc<[u8]>)> = request
				.servlet_addresses
				.iter()
				.map(|info| (
					::std::sync::Arc::from($crate::colony::common::type_canonical_bytes(&info.servlet_id).as_slice()),
					::std::sync::Arc::from(info.address.as_slice()),
				))
				.collect();

			#[cfg(feature = "x509")]
			let signer_id: ::std::option::Option<::std::sync::Arc<[u8]>> = $frame
				.nonrepudiation
				.as_ref()
				.and_then(|info| $crate::der::Encode::to_der(&info.sid).ok())
				.map(::std::sync::Arc::from);
			#[cfg(not(feature = "x509"))]
			let signer_id: ::std::option::Option<::std::sync::Arc<[u8]>> = ::std::option::Option::None;

			// Registration is complete only when the hive entry AND its
			// servlet routes are all installed: reporting success on a
			// partial install leaves the hive believing it is routable
			// while the cluster's tables are incomplete. A route failure
			// rolls the hive entry back so no half-registered state lingers.
			//
			// The announced slate REPLACES any prior rows for this hive:
			// re-registration is the reconciliation primitive.
			let registered = $registry.register_with_signer(request, signer_id).and_then(|()| {
				let _ = $servlet_registry.remove_by_hive(&hive_addr);
				servlet_info
					.iter()
					.try_for_each(|(servlet_type, servlet_addr)| {
						let entry = $crate::colony::cluster::ServletEntry::new(
							::std::sync::Arc::clone(servlet_addr),  // Actual servlet address!
							::std::sync::Arc::clone(servlet_type),
							::std::sync::Arc::clone(&hive_addr),
							$config.pheromone.initial_pheromone,
							$config.pheromone.abandonment_limit,
						);
						$servlet_registry.add(entry)
					})
					.inspect_err(|_| {
						let _ = $registry.unregister(&hive_addr);
						let _ = $servlet_registry.remove_by_hive(&hive_addr);
					})
			});

			let response = match registered {
				Ok(()) => {
					let hive_count = $registry.len().unwrap_or_default() as u64;
					let _ = $trace.event_with(
						$crate::instrumentation::events::CLUSTER_HIVE_REGISTERED,
						&[],
						hive_count,
					);

					$crate::colony::hive::RegisterHiveResponse {
						status: $crate::policy::TransitStatus::Ok,
						hive_id: Some(hive_identity),
					}
				}
				Err(_) => {
					// The signature was recorded before the registry ran.
					// Forget it so a legitimate retry of the same signed
					// frame is not rejected as a replay. A failed
					// registration must not hand out an identity either.
					#[cfg(feature = "x509")]
					if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
						$replay_guard.forget(signer_info.signature.as_bytes());
					}

					let _ = $trace.event($crate::instrumentation::events::CLUSTER_REGISTER_REFUSED);
					$crate::colony::hive::RegisterHiveResponse {
						status: $crate::policy::TransitStatus::PermissionDenied,
						hive_id: None,
					}
				}
			};

			return $crate::cluster!(@reply $frame, response);
		}

		$crate::colony::common::ClusterRequest::ServletAddressUpdate(update) => {
			let origin_status = verify_hive_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse {
					status: origin_status,
				});
			}

			let freshness_status = verify_control_freshness();
			if freshness_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse {
					status: freshness_status,
				});
			}

			// The claimed identity must be a hive URN in this gateway's
			// namespace - the registry key is the locator it was minted from.
			// Added identities must be instance-narrowed servlet URNs
			// whose locator equals the route address (same alignment
			// rule as registration). Removed identities must be
			// instance-narrowed servlet URNs: the registry unroutes by
			// the locator in the instance tail.
			let claimed_hive = $config.namespace.validate(&update.hive_id);
			let added_valid = update.added.iter().all(|info| {
				match $config.namespace.validate(&info.servlet_id) {
					Ok($crate::colony::common::ColonyResource::Servlet {
						instance: ::std::option::Option::Some(locator),
						..
					}) => locator.as_bytes() == info.address.as_slice(),
					_ => false,
				}
			});
			let removed_locators: ::std::option::Option<Vec<&[u8]>> = update
				.removed
				.iter()
				.map(|urn| match $config.namespace.validate(urn) {
					Ok($crate::colony::common::ColonyResource::Servlet {
						instance: ::std::option::Option::Some(locator),
						..
					}) => ::std::option::Option::Some(locator.as_bytes()),
					_ => ::std::option::Option::None,
				})
				.collect();
			let (hive_id, removed): (::std::sync::Arc<[u8]>, Vec<&[u8]>) =
				match (claimed_hive, added_valid, removed_locators) {
					(
						Ok($crate::colony::common::ColonyResource::Hive { addr }),
						true,
						::std::option::Option::Some(removed),
					) => (::std::sync::Arc::from(addr.as_bytes()), removed),
					_ => {
						let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_REFUSED);
						return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse {
							status: $crate::policy::TransitStatus::PermissionDenied,
						});
					}
				};

			// Bind the authenticated signer to the claimed hive_id. A trusted
			// certificate must not update another hive's routes (CWE-639).
			#[cfg(feature = "x509")]
			{
				let bound_ok = match (
					$frame.nonrepudiation.as_ref(),
					$registry.signer_for(&hive_id),
				) {
					(Some(signer_info), Ok(Some(bound))) => {
						match $crate::der::Encode::to_der(&signer_info.sid) {
							Ok(sid) => sid.as_slice() == bound.as_ref(),
							Err(_) => false,
						}
					}
					_ => false,
				};
				if !bound_ok {
					if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
						$replay_guard.forget(signer_info.signature.as_bytes());
					}

					let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_REFUSED);
					return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse {
						status: $crate::policy::TransitStatus::PermissionDenied,
					});
				}
			}

			let added: Vec<$crate::colony::cluster::ServletEntry> = update
				.added
				.iter()
				.map(|info| {
					$crate::colony::cluster::ServletEntry::new(
						::std::sync::Arc::from(info.address.as_slice()),
						::std::sync::Arc::from($crate::colony::common::type_canonical_bytes(&info.servlet_id).as_slice()),
						::std::sync::Arc::clone(&hive_id),
						$config.pheromone.initial_pheromone,
						$config.pheromone.abandonment_limit,
					)
				})
				.collect();

			let updated = $servlet_registry.apply_address_update(&hive_id, added, &removed);
			let status = match updated {
				Ok(()) => {
					let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_ACCEPTED);
					$crate::policy::TransitStatus::Ok
				}
				Err(_) => {
					// Release the replay record so the hive can resend the
					// same signed update after the failure clears.
					#[cfg(feature = "x509")]
					if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
						$replay_guard.forget(signer_info.signature.as_bytes());
					}

					let _ = $trace.event($crate::instrumentation::events::CLUSTER_UPDATE_REFUSED);
					$crate::policy::TransitStatus::PermissionDenied
				}
			};

			return $crate::cluster!(@reply $frame, $crate::colony::hive::ServletAddressUpdateResponse { status });
		}

		$crate::colony::common::ClusterRequest::Work(request) => {
			// A work target must be a servlet URN in this gateway's
			// namespace; foreign authorities and realms are refused
			// before the registry is consulted.
			if !$crate::colony::common::is_bare_servlet_type(&$config.namespace, &request.servlet_type) {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_REFUSED);
				return $crate::cluster!(@reply $frame,
					$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::PermissionDenied)
				);
			}

			let type_key = $crate::colony::common::canonical_bytes(&request.servlet_type);
			let forwarded = request.forwarded;
			let servlet_type = request.servlet_type;
			let payload = request.payload;

			// One-hop loop guard: already-forwarded work selects Local only.
			// Origin work selects Local and Peer so pheromone can prefer
			// nearby nests while still failing over across the colony.
			let entries = if forwarded {
				$servlet_registry.local_entries_for_type(&type_key)
			} else {
				$servlet_registry.entries_for_type(&type_key)
			};
			let entries = match entries {
				Ok(e) if !e.is_empty() => e,
				_ => {
					let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_UNAVAILABLE);
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Unavailable)
					);
				}
			};

			let metrics: Vec<$crate::colony::common::InstanceMetrics> = entries
				.iter()
				.map(|e| $crate::colony::common::InstanceMetrics {
					instance_key: e.route_key().to_vec(),
					pheromone: e.pheromone_level(),
				})
				.collect();

			let selected_idx = match $config.load_balancer.select(&metrics) {
				Some(idx) => idx,
				None => {
					let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_UNAVAILABLE);
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::Unavailable)
					);
				}
			};

			let selected_entry = &entries[selected_idx];
			let route_key = ::std::sync::Arc::clone(selected_entry.route_key());
			let dial_addr = ::std::sync::Arc::clone(selected_entry.dial_target());
			let route_kind = selected_entry.route_kind();

			// Local hops carry bare app payload on the hive trust plane.
			// Peer hops re-enter the peer gateway as Work{forwarded:true}
			// on the peer trust plane.
			let forward_result = match route_kind {
				$crate::colony::cluster::RouteKind::Local => {
					$crate::cluster!(@forward_work $pool, dial_addr, payload)
				}
				$crate::colony::cluster::RouteKind::Peer => {
					match $peer_pool.as_ref() {
						Some(peer_pool) => match $crate::encode(&$crate::colony::common::ClusterRequest::Work(
							$crate::colony::common::ClusterWorkRequest::new(servlet_type, payload).into_forwarded(),
						)) {
							Ok(envelope) => $crate::cluster!(@forward_work peer_pool, dial_addr, envelope),
							Err(error) => Err($crate::colony::cluster::ClusterError::from(error)),
						},
						None => Err($crate::colony::cluster::ClusterError::ConnectFailed),
					}
				}
			};

			// Pheromone feedback: the outcome steers future selection
			// toward instances that answer and away from ones that fail
			match forward_result {
				Ok(response_payload) => match route_kind {
					$crate::colony::cluster::RouteKind::Local => {
						$crate::cluster!(@work_trail_ok $servlet_registry, &route_key, $config, $trace);
						return $crate::cluster!(@reply $frame,
							$crate::colony::cluster::ClusterWorkResponse::ok(response_payload)
						);
					}
					$crate::colony::cluster::RouteKind::Peer => {
						// Peer gateways reply with ClusterWorkResponse; unwrap
						// and relay so the client sees one envelope.
						match $crate::decode::<$crate::colony::cluster::ClusterWorkResponse>(&response_payload) {
							Ok(peer_response) => {
								let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_FORWARDED);
								if peer_response.status == $crate::policy::TransitStatus::Ok {
									$crate::cluster!(@work_trail_ok $servlet_registry, &route_key, $config, $trace);
								} else {
									$crate::cluster!(@work_trail_weaken $servlet_registry, &route_key, $config, $trace);
								}

								return $crate::cluster!(@reply $frame, peer_response);
							}
							Err(_) => {
								$crate::cluster!(@work_trail_fail $servlet_registry, &route_key, $config, $trace,
									$frame, $crate::policy::TransitStatus::Unavailable);
							}
						}
					}
				},
				Err(error) => {
					// A servlet refusal relays verbatim so the caller keeps
					// its retryability contract.
					let status = match error {
						$crate::colony::cluster::ClusterError::Transport(
							$crate::transport::error::TransportError::OperationFailed(failure),
						) => $crate::policy::TransitStatus::try_from(failure)
							.unwrap_or($crate::policy::TransitStatus::Unavailable),
						_ => $crate::policy::TransitStatus::Unavailable,
					};
					$crate::cluster!(@work_trail_fail $servlet_registry, &route_key, $config, $trace, $frame, status);
				}
			}
		}

		$crate::colony::common::ClusterRequest::AdvertisePeer(advertisement) => {
			let origin_status = verify_peer_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				$crate::cluster!(@refuse_peer_ad $frame, $trace, origin_status);
			}

			let freshness_status = verify_control_freshness();
			if freshness_status != $crate::policy::TransitStatus::Ok {
				$crate::cluster!(@refuse_peer_ad $frame, $trace, freshness_status);
			}

			// Signer resolution + wire checks live in `admit`: the
			// signer key and claimed dial address cannot be transposed.
			let admitted = match $crate::colony::cluster::peer::AdmittedPeerAd::admit(
				&$frame,
				&advertisement,
				&$config,
			) {
				::core::result::Result::Ok(admitted) => admitted,
				::core::result::Result::Err(status) => {
					return $crate::cluster!(@refuse_peer_ad $frame, $trace, $replay_guard, status);
				}
			};

			if let Err(error) = $servlet_registry.reconcile_peer_slate(
				admitted,
				$crate::colony::cluster::PeerCaps::default(),
			) {
				let status = match error {
					$crate::colony::cluster::ClusterError::PeerSlateConflict
					| $crate::colony::cluster::ClusterError::PeerCapExceeded => {
						$crate::policy::TransitStatus::PermissionDenied
					}
					_ => $crate::policy::TransitStatus::Unavailable,
				};
				return $crate::cluster!(@refuse_peer_ad $frame, $trace, $replay_guard, status);
			}

			let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISED);
			return $crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse {
				status: $crate::policy::TransitStatus::Ok,
			});
		}

		// A relayed rumor arrives as a complete origin-signed frame inside
		// an outer relay frame. The OUTER frame verifies on the peer trust
		// plane, exactly like an advertisement: a hive certificate must not
		// forge a peer relay. The INNER rumor frame then verifies its own
		// origin signature on the same plane, so a relay that tampered with
		// the rumor content is caught here and scored, before the shared
		// gossip pipeline (dedup + one local delivery) runs.
		#[cfg(feature = "x509")]
		$crate::colony::common::ClusterRequest::Gossip(rumor) => {
			let rumor = *rumor;
			let origin_status = verify_peer_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				return $crate::cluster!(@refuse_gossip $frame, $trace, origin_status);
			}

			// Gossip flood is colony-scoped (CWE-668): this gateway and
			// the relaying peer must prove the SAME colony URN. A peer
			// from another federated colony may advertise work routes,
			// but MUST NOT drive admission, journaling, delivery, or
			// reflood of a same-colony origin rumor. Matches the
			// ReconcileGossip equality gate. A mismatch is policy, not
			// relay misbehavior, so no trail is weakened.
			let ::core::option::Option::Some(local_colony) = $config.colony_urn() else {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::PermissionDenied);
			};
			let peer_colony = $crate::colony::cluster::frame_colony_urn(
				&$config.namespace,
				$config.tls.peer_trust.as_deref(),
				&$frame,
			);
			if peer_colony.as_ref() != ::core::option::Option::Some(local_colony) {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::PermissionDenied);
			}

			// The remaining hop radius rides the outer relay frame's
			// `metadata.lifetime`, which the relay rebuilt and re-signed,
			// so it is hop-authenticated. An honest relay always sets it;
			// a missing lifetime is relay misbehavior and is scored.
			let hop_ttl = match $frame.metadata.lifetime {
				::core::option::Option::Some(hop_ttl) => hop_ttl,
				::core::option::Option::None => {
					$crate::cluster!(@weaken_invalid_relay relay, $frame, $servlet_registry, $config, $trace);
					return $crate::cluster!(@refuse_gossip $frame, $trace,
						$crate::policy::TransitStatus::PermissionDenied);
				}
			};

			// The rumor's own signature proves the origin gateway on the
			// peer trust plane and covers its id, issue time, and payload
			// (§5.7.5). An honest relay verified before forwarding,
			// so an unverifiable rumor is relay misbehavior and is scored.
			let rumor_status = match $config.tls.peer_trust.as_ref() {
				::core::option::Option::Some(trust) => {
					match $crate::colony::hive::verify_frame_signature(trust.as_ref(), &rumor) {
						$crate::colony::hive::TrustVerification::Verified => $crate::policy::TransitStatus::Ok,
						$crate::colony::hive::TrustVerification::MissingSignature => {
							$crate::policy::TransitStatus::Unauthenticated
						}
						_ => $crate::policy::TransitStatus::PermissionDenied,
					}
				}
				::core::option::Option::None => $crate::policy::TransitStatus::PermissionDenied,
			};
			if rumor_status != $crate::policy::TransitStatus::Ok {
				$crate::cluster!(@weaken_invalid_relay relay, $frame, $servlet_registry, $config, $trace);
				return $crate::cluster!(@refuse_gossip $frame, $trace, rumor_status);
			}

			// Flood scope: a rumor admits only into the origin's own
			// colony. The compare binds the full colony URN from the
			// origin certificate resolved on the peer trust plane; rumor
			// bytes carry no scope, because unsigned scope bytes would be
			// weaker than the certificate binding (CWE-345). A foreign or
			// missing colony URN is a policy refusal, never scored.
			let origin_colony = $crate::colony::cluster::frame_colony_urn(
				&$config.namespace,
				$config.tls.peer_trust.as_deref(),
				&rumor,
			);
			if origin_colony.as_ref() != ::core::option::Option::Some(local_colony) {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::PermissionDenied);
			}

			// Gossip freshness is the seen-ttl window checked in `admit`
			// against the rumor's hop-invariant signed issue time, not the
			// shorter control window: a rumor relayed across several hops
			// is legitimately older than a one-shot control frame. Replay
			// is subsumed by that window plus journal digest dedup, so the
			// relay takes no replay record here.
			$crate::cluster!(@gossip_pipeline relay,
				$frame, $servlet_registry, $config, $pool, $peer_pool, $trace, $digest, rumor, hop_ttl);
		}

		// An origin rumor from a local publisher verifies on the hive trust
		// plane, like a registration: a peer certificate must not inject
		// origin gossip. This gateway is the FIRST GATEWAY that accepted
		// the publish: it mints the rumor frame and signs it with its
		// cluster key, so every gateway on the peer trust plane can verify
		// the origin end to end.
		#[cfg(feature = "x509")]
		$crate::colony::common::ClusterRequest::PublishGossip(body) => {
			let origin_status = verify_hive_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				return $crate::cluster!(@refuse_gossip $frame, $trace, origin_status);
			}

			// Publishing starts a colony flood, so the accepting gateway
			// itself must be a colony member: the rumor it mints is
			// scoped by the colony URN in its own certificate, which
			// every receiving gateway resolves and compares.
			if $config.colony_urn().is_none() {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::PermissionDenied);
			}

			// The publish frame's `metadata.lifetime` is the publisher's
			// requested hop radius; absent, the operator default applies.
			// The origin gateway caps it at the operator's configured
			// radius (itself bounded by the protocol cap) while honoring a
			// smaller request, such as 0 for local-only delivery. The hop
			// radius lives outside the rumor, so the clamp does not change
			// the rumor's identity.
			let radius_cap = u64::from($config.gossip.ttl.min($crate::constants::MAX_GOSSIP_TTL));
			let hop_ttl = $frame.metadata.lifetime.unwrap_or(radius_cap).min(radius_cap);

			// The rumor's id and issue-time order are copied from the
			// publish frame, so a replayed publish re-mints a bit-identical
			// rumor whose digest dedups as a journal Duplicate rather than
			// minting a fresh deliverable rumor (CWE-294).
			let rumor = {
				use $crate::builder::TypeBuilder;
				$crate::builder::frame::FrameBuilder::from($crate::Version::V2)
					.with_id(&$frame.metadata.id)
					.with_order($frame.metadata.order)
					.with_message(body)
					.with_witness_hasher::<$digest>()
					.build()
			};
			let rumor = match rumor {
				::core::result::Result::Ok(rumor) => rumor,
				::core::result::Result::Err(_) => {
					return $crate::cluster!(@refuse_gossip $frame, $trace,
						$crate::policy::TransitStatus::Unavailable);
				}
			};
			let rumor = match rumor.sign_with_provider::<$digest, _>($config.tls.key.as_ref()).await {
				::core::result::Result::Ok(rumor) => rumor,
				::core::result::Result::Err(_) => {
					return $crate::cluster!(@refuse_gossip $frame, $trace,
						$crate::policy::TransitStatus::Unavailable);
				}
			};

			$crate::cluster!(@gossip_pipeline origin,
				$frame, $servlet_registry, $config, $pool, $peer_pool, $trace, $digest, rumor, hop_ttl);
		}

		// A reconciliation summary verifies on the peer trust plane, like an
		// advertisement. Admission is the peer-plane signature plus the control
		// freshness window. Digests only travel here; rumor content does not.
		// The reply lists digests this gateway lacks so the peer can push them.
		#[cfg(feature = "x509")]
		$crate::colony::common::ClusterRequest::ReconcileGossip(reconciliation) => {
			let origin_status = verify_peer_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				$crate::cluster!(@refuse_reconcile $frame, $trace);
			}

			// Reconciliation exchanges colony gossip state: the want list
			// names local rumors and the follow-up repair push carries
			// rumor bytes. The requester's certificate must prove the SAME
			// colony as this gateway, or colony-scoped state leaks across
			// the federation boundary (CWE-668). Checked before freshness
			// so a policy refusal never takes a replay record (CWE-772).
			let requester_colony = $crate::colony::cluster::frame_colony_urn(
				&$config.namespace,
				$config.tls.peer_trust.as_deref(),
				&$frame,
			);
			if $config.colony_urn().is_none() || requester_colony.as_ref() != $config.colony_urn() {
				$crate::cluster!(@refuse_reconcile $frame, $trace);
			}

			let freshness_status = verify_control_freshness();
			if freshness_status != $crate::policy::TransitStatus::Ok {
				$crate::cluster!(@refuse_reconcile $frame, $trace);
			}

			// Digest lists share the journal capacity bound so a peer cannot
			// force an unbounded set-difference work unit (CWE-770).
			if reconciliation.held.len() > $crate::constants::MAX_GOSSIP_LOG {
				$crate::cluster!(@refuse_reconcile $frame, $trace);
			}

			// A journal read failure yields an empty want.
			// Repair defers to a later beat instead of refusing the peer.
			let want = match $config.gossip.journal.held_digests(
				$crate::colony::common::current_timestamp_ms(),
			) {
				::core::result::Result::Ok(held) => {
					$crate::colony::cluster::gossip_want(&reconciliation.held, &held)
				}
				::core::result::Result::Err(_) => ::std::vec::Vec::new(),
			};

			return $crate::cluster!(@reply $frame, $crate::colony::common::GossipWant { want });
		}
		}
	}};

	// Shared gossip pipeline: admit, dedup via the journal, and deliver once
	// through the operator's ingress policy. A duplicate is dropped.
	// `$rumor` is the origin-signed rumor frame (already verified on the
	// relay path); `$ttl` is the remaining hop radius from the OUTER frame.
	// The `$origin` marker is `relay` for peer-relayed rumors and `origin`
	// for local publishes: only a relay scores its sender on admit failure.
	(@gossip_pipeline $origin:tt, $frame:ident, $servlet_registry:ident, $config:ident, $pool:ident, $peer_pool:ident, $trace:ident, $digest:path, $rumor:expr, $ttl:expr) => {{
		let rumor = $rumor;
		let hop_ttl = $ttl;

		let admitted = match $crate::colony::cluster::AdmittedGossip::admit::<$digest>(
			&rumor,
			hop_ttl,
			$config.gossip.seen_ttl.as_millis() as u64,
			$crate::colony::common::current_timestamp_ms(),
		) {
			::core::result::Result::Ok(admitted) => admitted,
			::core::result::Result::Err(status) => {
				$crate::cluster!(@weaken_invalid_relay $origin, $frame, $servlet_registry, $config, $trace);
				return $crate::cluster!(@refuse_gossip $frame, $trace, status);
			}
		};

		// Rate admission and the journal partition key on the identity
		// whose signature this handler verified: the local publisher on a
		// publish, the rumor's origin gateway on a relay. Keying a relayed
		// rumor on the relaying peer would grant the origin a fresh budget
		// at every relay, so one origin could exceed its limits by fanning
		// the same flood through many gateways (CWE-770). An unsigned or
		// unencodable signer cannot be attributed, so its rumor is refused.
		let attributed = $crate::cluster!(@gossip_attribution $origin, $frame, rumor);
		let signer_id = match attributed.nonrepudiation.as_ref() {
			::core::option::Option::Some(signer_info) => match $crate::der::Encode::to_der(&signer_info.sid) {
				::core::result::Result::Ok(signer_id) => signer_id,
				::core::result::Result::Err(_) => {
					return $crate::cluster!(@refuse_gossip $frame, $trace,
						$crate::policy::TransitStatus::PermissionDenied)
				}
			},
			::core::option::Option::None => {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::Unauthenticated)
			}
		};

		let now = $crate::colony::common::current_timestamp_ms();

		// Relay echoes are normal traffic: the reflood does not skip the
		// sender, so every flooded rumor comes back at least once. A known
		// duplicate is dropped before rate admission so echoes cannot drain
		// a signer's bucket. The probe is advisory; the journal record
		// below stays the atomic dedup step for a racing duplicate.
		match $config.gossip.journal.seen(&admitted.digest(), now) {
			::core::result::Result::Ok(true) => {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_DUPLICATE);
				return $crate::cluster!(@reply $frame, $crate::colony::common::GossipResponse {
					status: $crate::policy::TransitStatus::Ok,
				});
			}
			::core::result::Result::Ok(false) => {}
			::core::result::Result::Err(_) => {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::Unavailable)
			}
		}

		// Per-signer rate admission runs before the journal records or refloods.
		// An over-limit signer cannot grow retained state or amplify traffic (CWE-770).
		// An admission backend fault refuses the rumor rather than admitting it.
		match $config.gossip.admission.allow(&signer_id, now) {
			::core::result::Result::Ok(true) => {}
			::core::result::Result::Ok(false) => {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::ResourceExhausted)
			}
			::core::result::Result::Err(_) => {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::Unavailable)
			}
		}

		match $config.gossip.journal.record(&signer_id, admitted.digest(), &rumor, now) {
			::core::result::Result::Ok($crate::colony::cluster::Admission::Duplicate) => {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_DUPLICATE);
				return $crate::cluster!(@reply $frame, $crate::colony::common::GossipResponse {
					status: $crate::policy::TransitStatus::Ok,
				});
			}
			::core::result::Result::Ok($crate::colony::cluster::Admission::New) => {}
			::core::result::Result::Err(_) => {
				return $crate::cluster!(@refuse_gossip $frame, $trace,
					$crate::policy::TransitStatus::Unavailable)
			}
		}

		// A New rumor is already recorded for dedup and reflood.
		// Local delivery is confirmed separately.
		// Only a delivered rumor is acked and reported as CLUSTER_GOSSIP_ACCEPTED.
		$crate::cluster!(@gossip_deliver_local
			$servlet_registry, $config, $pool, $trace,
			admitted.payload().to_vec(), admitted.digest());

		// Reflood a still-live rumor to the peer graph on a detached task so
		// the reply is not blocked on the flood cascade. The rumor bytes are
		// forwarded verbatim; only the outer hop frame is rebuilt with the
		// decremented radius. Loop-freedom holds without skipping the
		// sender: the sender drops the echo as a duplicate, and the digest
		// plus decremented radius bound propagation. A gateway with no
		// peers skips the task entirely: the reflood signature is the
		// costly step and would fan out to nobody.
		if hop_ttl > 0 && !$config.peers.is_empty() {
			let reflood_pool = $crate::cluster!(@peer_dial_pool $peer_pool, $pool);
			let config = ::std::sync::Arc::clone(&$config);
			let reflood_rumor = rumor.clone();
			let next_ttl = hop_ttl - 1;
			let _ = $crate::colony::servlet::servlet_runtime::rt::spawn(
				$crate::cluster!(@reflood_gossip reflood_pool, config, reflood_rumor, next_ttl, $digest)
			);
		}

		return $crate::cluster!(@reply $frame, $crate::colony::common::GossipResponse {
			status: $crate::policy::TransitStatus::Ok,
		});
	}};

	// Deliver one recorded rumor to a load-balanced local instance of the
	// operator's configured ingress type. Ack the journal only after that
	// hop succeeds. The inbound pipeline and the beat retry share this
	// step. Delivery is receiving-gateway policy, never rumor content: no
	// configured ingress means journal-and-reflood only, so the record is
	// acked immediately and never enters the pending retry set. With an
	// ingress, a rumor with no reachable instance stays pending for a
	// later beat.
	(@gossip_deliver_local $servlet_registry:expr, $config:expr, $pool:expr, $trace:expr, $payload:expr, $digest_value:expr) => {{
		match $config.gossip.ingress.as_ref() {
			::core::option::Option::None => {
				let _ = $config.gossip.journal.ack_local(&$digest_value);
			}
			::core::option::Option::Some(ingress) => {
				let type_key = $crate::colony::common::canonical_bytes(ingress);
				let entries = match $servlet_registry.local_entries_for_type(&type_key) {
					::core::result::Result::Ok(entries) => entries,
					::core::result::Result::Err(_) => ::std::vec::Vec::new(),
				};

				let metrics: ::std::vec::Vec<$crate::colony::common::InstanceMetrics> = entries
					.iter()
					.map(|entry| $crate::colony::common::InstanceMetrics {
						instance_key: entry.route_key().to_vec(),
						pheromone: entry.pheromone_level(),
					})
					.collect();

				if let ::core::option::Option::Some(selected_idx) = $config.load_balancer.select(&metrics) {
					let dial_addr = ::std::sync::Arc::clone(entries[selected_idx].dial_target());
					if let ::core::result::Result::Ok(_response) =
						$crate::cluster!(@forward_work $pool, dial_addr, $payload)
					{
						let _ = $config.gossip.journal.ack_local(&$digest_value);
						let _ = $trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_ACCEPTED);
					}
				}
			}
		}
	}};

	// Select the pool for dialing peer gateways: prefer the peer trust
	// plane when present. Gateways that only dial peers under hive_trust
	// keep the hive pool. The advertise beat and the gossip reflood share
	// this preference so both planes reach configured peers identically.
	(@peer_dial_pool $peer_pool:expr, $pool:expr) => {
		$peer_pool
			.as_ref()
			.map(::std::sync::Arc::clone)
			.unwrap_or_else(|| ::std::sync::Arc::clone(&$pool))
	};

	// Reflood one rumor to every configured peer. Expands to a future for
	// `rt::spawn`. The rumor travels verbatim inside a fresh outer hop
	// frame whose `metadata.lifetime` carries the decremented radius. The
	// outer frame is built and signed once (signing is the costly step)
	// and the identical signed frame is fanned out concurrently over the
	// pooled peer connections, so a wide peer list costs one signature and
	// one round of mux streams.
	(@reflood_gossip $peer_pool:expr, $config:expr, $rumor:expr, $ttl:expr, $digest:path) => {
		async move {
			use $crate::builder::TypeBuilder;

			let request = $crate::colony::common::ClusterRequest::Gossip(::std::boxed::Box::new($rumor));

			let frame = match $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"gossip-reflood")
				.with_message(request)
				.with_priority($crate::MessagePriority::NetworkControl)
				.with_lifetime($ttl)
				.with_witness_hasher::<$digest>()
				.build()
			{
				::core::result::Result::Ok(frame) => frame,
				::core::result::Result::Err(_) => return,
			};

			let signed_frame = match frame.sign_with_provider::<$digest, _>($config.tls.key.as_ref()).await {
				::core::result::Result::Ok(signed) => signed,
				::core::result::Result::Err(_) => return,
			};

			let mut fanout = ::tokio::task::JoinSet::new();
			for peer in $config.peers.iter() {
				let ::core::result::Result::Ok(peer_addr) = peer.parse() else {
					continue;
				};

				let peer_pool = ::std::sync::Arc::clone(&$peer_pool);
				let frame = signed_frame.clone();
				fanout.spawn(async move {
					if let ::core::result::Result::Ok(mut client) = peer_pool.connect(peer_addr).await {
						let _ = client.emit(frame, None).await;
					}
				});
			}

			while fanout.join_next().await.is_some() {}
		}
	};

	// Invalid-relay scoring: a trusted peer that relayed a rumor this
	// gateway refuses has misbehaved. That covers a missing hop radius, a
	// rumor whose origin signature does not verify (the relay forwarded
	// tampered or forged content it should itself have refused), and any
	// admission failure (an oversized, over-radius, stale, or undecodable
	// rumor passed ITS admission unchecked). Every live route the relay
	// advertised is weakened by one trial. Attribution is the signer
	// fingerprint, which `verify_peer_origin` already proved before these
	// checks ran. Rate-limit, journal-capacity, and colony-membership
	// refusals never reach this arm: those refusals reflect local
	// policy, not peer misbehavior.
	(@weaken_invalid_relay relay, $frame:ident, $servlet_registry:ident, $config:ident, $trace:ident) => {{
		#[cfg(feature = "x509")]
		if let ::core::option::Option::Some(peer_id) =
			$crate::colony::cluster::peer_signer_fingerprint($config.tls.peer_trust.as_deref(), &$frame)
		{
			if let ::core::result::Result::Ok(weakened) = $servlet_registry.weaken_peer(&peer_id) {
				if weakened > 0 {
					// The weaken event carries the verified relay
					// fingerprint so the audit record names which peer
					// was scored, not only that scoring happened.
					if let ::core::result::Result::Ok(event) =
						$trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_RELAY_WEAKENED)
					{
						event.with_payload(peer_id.as_ref()).emit();
					}
				}
			}
		}
	}};

	// Origin variant: a locally published rumor has no relaying peer to
	// score, so admission failure refuses without touching any trail.
	(@weaken_invalid_relay origin, $frame:ident, $servlet_registry:ident, $config:ident, $trace:ident) => {{}};

	// Frame carrying the signature that attributes a rumor for rate
	// admission and the journal partition. A publish is attributed to the
	// outer frame's hive-plane publisher; a relay is attributed to the
	// nested rumor's origin gateway, whose signature the relay arm
	// verified. The relaying peer's own signature never keys the budget.
	(@gossip_attribution origin, $frame:ident, $rumor:ident) => {
		&$frame
	};
	(@gossip_attribution relay, $frame:ident, $rumor:ident) => {
		&$rumor
	};

	// Gossip refuse: fire the refused event and build the reply. Gossip
	// takes no replay record (seen-ttl plus journal digest dedup subsume
	// replay), so there is nothing to release. Callers prefix `return`.
	(@refuse_gossip $frame:ident, $trace:expr, $status:expr) => {{
		$crate::cluster!(@gossip_refused_event $frame, $trace);
		$crate::cluster!(@reply $frame, $crate::colony::common::GossipResponse { status: $status })
	}};

	// Refuse reconciliation with an empty want set.
	// The peer treats the round as a well-formed no-op rather than a decode failure.
	(@refuse_reconcile $frame:ident, $trace:expr) => {{
		$crate::cluster!(@gossip_refused_event $frame, $trace);
		return $crate::cluster!(@reply $frame, $crate::colony::common::GossipWant {
			want: ::std::vec::Vec::new(),
		});
	}};

	// Fire the refused event with the CLAIMED signer attached as evidence:
	// most refusals fire because the claim does not resolve or verify, so
	// the claim is the only attribution the audit record can carry.
	(@gossip_refused_event $frame:ident, $trace:expr) => {{
		if let ::core::result::Result::Ok(event) =
			$trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_REFUSED)
		{
			match $crate::colony::cluster::signer_attribution(&$frame) {
				::core::option::Option::Some(signer) => event.with_payload(&signer).emit(),
				::core::option::Option::None => event.emit(),
			}
		}
	}};

	// Helper: refuse a peer advertisement whose replay record already
	// exists. The refusal is deterministic on local state, so the record
	// is released: the peer must be able to resend the same signed frame
	// once that state clears (CWE-772). Refusals BEFORE the freshness
	// check use the plain arm instead: no record exists yet, or the
	// record IS the protection being enforced.
	(@refuse_peer_ad $frame:ident, $trace:ident, $replay_guard:ident, $status:expr) => {{
		#[cfg(feature = "x509")]
		if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
			$replay_guard.forget(signer_info.signature.as_bytes());
		}

		let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED);
		$crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse { status: $status })
	}};

	// Peer advertisement refuse: fire event and reply with status
	(@refuse_peer_ad $frame:ident, $trace:expr, $status:expr) => {{
		let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED);
		return $crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse {
			status: $status,
		});
	}};

	// Work trail: reinforce + routed event (no return)
	(@work_trail_ok $servlet_registry:expr, $route_key:expr, $config:expr, $trace:expr) => {{
		let _ = $servlet_registry.reinforce($route_key, $config.pheromone.reinforcement_boost);
		let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_ROUTED);
	}};

	// Work trail: weaken + failed event (no return)
	(@work_trail_weaken $servlet_registry:expr, $route_key:expr, $config:expr, $trace:expr) => {{
		let _ = $servlet_registry.weaken_with_penalty($route_key, $config.pheromone.weakening_penalty);
		let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_FAILED);
	}};

	// Work trail: weaken + failed + error reply
	(@work_trail_fail $servlet_registry:expr, $route_key:expr, $config:expr, $trace:expr, $frame:ident, $status:expr) => {{
		$crate::cluster!(@work_trail_weaken $servlet_registry, $route_key, $config, $trace);
		return $crate::cluster!(@reply $frame,
			$crate::colony::cluster::ClusterWorkResponse::err($status)
		);
	}};

	// Helper: Forward work to a servlet
	(@forward_work $pool:expr, $addr:expr, $payload:expr) => {{
		async {
			let addr_str = core::str::from_utf8(&$addr)
				.map_err(|_| $crate::colony::cluster::ClusterError::InvalidAddress($addr.to_vec()))?;
			let parsed_addr = addr_str.parse()
				.map_err(|_| $crate::colony::cluster::ClusterError::InvalidAddress($addr.to_vec()))?;

			let mut metadata = $crate::Metadata::default();
			metadata.id = b"work-forward".to_vec();

			let frame = $crate::Frame {
				version: $crate::Version::V0,
				metadata,
				message: $payload,
				integrity: None,
				nonrepudiation: None,
			};

			let mut client = $pool.connect(parsed_addr).await
				.map_err(|_| $crate::colony::cluster::ClusterError::ConnectFailed)?;

			let mut response = match client.emit(frame, None).await {
				Ok(Some(r)) => r,
				Ok(None) => {
					return Err($crate::colony::cluster::ClusterError::NoResponse);
				}
				Err(e) => {
					return Err($crate::colony::cluster::ClusterError::from(e));
				}
			};

			Ok::<_, $crate::colony::cluster::ClusterError>(::core::mem::take(&mut response.message))
		}.await
	}};

	// Implement Drop
	(@impl_drop $cluster_name:ident) => {
		impl Drop for $cluster_name {
			fn drop(&mut self) {
				if let Some(handle) = self.advertise_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.evaporation_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.heartbeat_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
				if let Some(handle) = self.server_handle.take() {
					$crate::colony::servlet::servlet_runtime::rt::abort(&handle);
				}
			}
		}
	};

	// =========================================================================
	// Helpers
	// =========================================================================

	// Helper: Send heartbeat async - builds, signs, and sends heartbeat frame
	(@send_heartbeat_async $pool:expr, $config:expr, $addr:expr, $digest:path) => {
		async {
			use $crate::builder::TypeBuilder;

			let cmd = $crate::colony::common::ClusterCommand {
				heartbeat: Some($crate::colony::common::HeartbeatParams {
					cluster_status: $crate::colony::common::ClusterStatus::Healthy,
				}),
				manage: None,
			};

			// Priority is a V2+ metadata field. Composing it on V1 fails at
			// build time and every heartbeat would count as a send failure.
			// `metadata.order` is the command freshness binding (CWE-294).
			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"heartbeat")
				.with_order($crate::colony::common::current_timestamp_ms())
				.with_message(cmd)
				.with_priority($crate::MessagePriority::NetworkControl)
				.with_witness_hasher::<$digest>()
				.build()?;

			let signed_frame = frame
				.sign_with_provider::<$digest, _>($config.tls.key.as_ref())
				.await?;

			let mut client = $pool.connect($addr).await?;

			let response = client.emit(signed_frame, None).await?
				.ok_or($crate::colony::cluster::ClusterError::NoResponse)?;

			let cmd_response: $crate::colony::common::ClusterCommandResponse =
				$crate::decode(&response.message)?;
			cmd_response.heartbeat.ok_or($crate::colony::cluster::ClusterError::MalformedResponse)
		}.await
	};

	// Helper: Send one signed advertisement of the exported type slate to one
	// peer gateway. Signs with the gateway key. Only invoked under x509: `tls`
	// access here is expansion-checked, never reached without the feature.
	(@send_advertisement_async $pool:expr, $config:expr, $peer_addr:expr, $gateway_addr:expr, $types:expr, $digest:path) => {
		async {
			use $crate::builder::TypeBuilder;

			let request = $crate::colony::common::ClusterRequest::AdvertisePeer(
				$crate::colony::common::PeerAdvertisement {
					gateway_addr: $gateway_addr,
					advertised_types: $types,
				}
			);

			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"peer-advertise")
				.with_order($crate::colony::common::current_timestamp_ms())
				.with_message(request)
				.with_priority($crate::MessagePriority::NetworkControl)
				.with_witness_hasher::<$digest>()
				.build()?;

			let signed_frame = frame
				.sign_with_provider::<$digest, _>($config.tls.key.as_ref())
				.await?;

			let mut client = $pool.connect($peer_addr).await?;

			let response = client.emit(signed_frame, None).await?
				.ok_or($crate::colony::cluster::ClusterError::NoResponse)?;

			let decoded: $crate::colony::common::PeerAdvertisementResponse =
				$crate::decode(&response.message)?;
			Ok::<_, $crate::colony::cluster::ClusterError>(decoded.status)
		}.await
	};

	// Run one anti-entropy reconciliation round against one peer.
	// This gateway advertises retained digests. The peer answers with digests it lacks.
	// Missing rumors are fetched and pushed back as `Gossip` frames.
	//
	// `$acked` is this peer's push ledger: digests the peer previously
	// acknowledged with `Ok`. A previously acknowledged digest reappearing
	// in the peer's want set means the peer accepted the rumor and then
	// dropped it (grey hole), so the round weakens every route dialed
	// through that peer once and fires the drop-signal event. Attribution
	// is by dial address because reconciliation replies are unsigned; the
	// peer pool's pinned trust authenticates the endpoint at that address.
	(@reconcile_gossip_async $pool:expr, $config:expr, $peer_addr:expr, $servlet_registry:expr, $trace:expr, $acked:expr, $peer_bytes:expr, $digest:path) => {
		async {
			use $crate::builder::TypeBuilder;

			let now = $crate::colony::common::current_timestamp_ms();
			let held: ::std::vec::Vec<::std::vec::Vec<u8>> = $config
				.gossip
				.journal
				.held_digests(now)?
				.iter()
				.map(|digest| digest.to_vec())
				.collect();

			let mut client = $pool.connect($peer_addr).await?;

			// Colony scope gate (CWE-668): reconciliation carries colony
			// gossip state in both directions, held digests out and rumor
			// bytes on the repair push. The dialed endpoint's handshake
			// certificate must prove the same colony as this gateway
			// before any state flows. `None` fails closed: no validated
			// peer certificate means no reconciliation round.
			let peer_colony = client
				.peer_certificate()
				.and_then(|cert| $crate::colony::cluster::cert_colony_urn(&$config.namespace, cert));
			if peer_colony.as_ref() != $config.colony_urn() {
				return Ok::<_, $crate::colony::cluster::ClusterError>(());
			}

			let request = $crate::colony::common::ClusterRequest::ReconcileGossip(
				$crate::colony::common::GossipReconciliation { held }
			);

			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"gossip-reconcile")
				.with_order(now)
				.with_message(request)
				.with_priority($crate::MessagePriority::NetworkControl)
				.with_witness_hasher::<$digest>()
				.build()?;

			let signed_frame = frame
				.sign_with_provider::<$digest, _>($config.tls.key.as_ref())
				.await?;

			let response = client.emit(signed_frame, None).await?
				.ok_or($crate::colony::cluster::ClusterError::NoResponse)?;

			let reply: $crate::colony::common::GossipWant =
				$crate::decode(&response.message)?;

			// A peer want-list above the journal bound is policy abuse, not
			// a repair signal: drop the round rather than allocate work.
			if reply.want.len() > $crate::constants::MAX_GOSSIP_LOG {
				return Ok::<_, $crate::colony::cluster::ClusterError>(());
			}

			let wanted = $crate::colony::cluster::wanted_digests(&reply.want);

			// Grey-hole check: a digest this peer already acknowledged with
			// `Ok` cannot legitimately be wanted again while retention holds,
			// so its reappearance is a drop signal. One weaken per round
			// regardless of how many digests reappeared: consecutive
			// dropping rounds accumulate trials toward abandonment, while a
			// transient loss (peer restart) costs at most one trial and
			// heals on the next clean round.
			let acked = $acked;
			let dropped = wanted.iter().any(|digest| acked.contains(digest));
			if dropped {
				let _ = $servlet_registry.weaken_peer_by_dial($peer_bytes);
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_GOSSIP_DROP_SIGNAL);
			}
			for digest in &wanted {
				acked.remove(digest);
			}

			let now = $crate::colony::common::current_timestamp_ms();
			let seen_ttl_ms = $config.gossip.seen_ttl.as_millis() as u64;
			let missing = $config.gossip.journal.fetch(&wanted, now)?;

			// Push each retained rumor verbatim inside a fresh outer frame,
			// so the origin signature survives anti-entropy repair intact.
			// Only rumors whose signed issue time is still inside the
			// freshness window are pushed. The outer `lifetime` is 0: a
			// repair push is pure delivery to one peer, never a reflood.
			// The peer admits each through the same path as a live relay.
			let admissible = missing.into_iter().filter(|rumor| {
				$crate::colony::cluster::gossip_fresh(rumor.metadata.order, seen_ttl_ms, now)
			});

			for rumor in admissible {
				let ::core::result::Result::Ok(pushed_digest) =
					$crate::colony::cluster::gossip_digest::<$digest>(&rumor)
				else {
					continue;
				};
				let push = $crate::colony::common::ClusterRequest::Gossip(::std::boxed::Box::new(rumor));

				let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
					.with_id(b"gossip-repair")
					.with_message(push)
					.with_priority($crate::MessagePriority::NetworkControl)
					.with_lifetime(0)
					.with_witness_hasher::<$digest>()
					.build()?;

				let signed = frame
					.sign_with_provider::<$digest, _>($config.tls.key.as_ref())
					.await?;

				// Record the digest only on an explicit `Ok`: a refused or
				// unanswered push proves nothing about later retention, so
				// it must not arm the grey-hole check.
				if let ::core::option::Option::Some(push_reply) = client.emit(signed, None).await? {
					let decoded: ::core::result::Result<$crate::colony::common::GossipResponse, _> =
						$crate::decode(&push_reply.message);
					if let ::core::result::Result::Ok(gossip_reply) = decoded {
						if ::core::matches!(gossip_reply.status, $crate::policy::TransitStatus::Ok) {
							acked.insert(pushed_digest);
						}
					}
				}
			}

			Ok::<_, $crate::colony::cluster::ClusterError>(())
		}.await
	};

	// Build the advertise beat task. Inert unless an interval is configured.
	// Each tick retries local delivery of any rumor still pending.
	// When peers are configured, the same beat advertises live local routes
	// (capped at MAX_ADVERTISED_TYPES) and reconciles gossip with each peer.
	// An empty slate is still sent. Local retry does not require peers: a
	// lone gateway still delivers rumors that arrived before its ingress
	// servlet registered.
	//
	// Two pools are threaded. `$pool` dials peer gateways on the peer trust plane when present.
	// `$local_pool` is the hive pool used for local servlet delivery retries.
	(@build_advertise_task $protocol:path, $servlet_registry:expr, $pool:expr, $local_pool:expr, $config:expr, $gateway_addr:expr, $trace:expr, $digest:path) => {{
		let servlet_registry = $servlet_registry;
		let pool = $pool;
		let local_pool = $local_pool;
		let config = $config;
		let gateway_addr = $gateway_addr;
		let trace = $trace;

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			let Some(interval) = config.advertise_interval else { return };

			// Per-peer push ledger for grey-hole detection: digests each
			// peer acknowledged with `Ok` during anti-entropy repair. Loop
			// local because only this task reads or writes it. Growth is
			// bounded by journal capacity times the static peer list, so
			// no unbounded resource is consumed (CWE-770).
			let mut push_ledger: ::std::collections::HashMap<
				::std::string::String,
				::std::collections::HashSet<$crate::colony::cluster::GossipDigest>,
			> = ::std::collections::HashMap::new();

			loop {
				$crate::colony::servlet::servlet_runtime::rt::sleep(interval).await;

				// Retry local delivery for journaled rumors not yet delivered.
				// A common case is a rumor that arrived before the ingress servlet registered.
				// A delivered rumor is acked and stops being retried.
				if let ::core::result::Result::Ok(pending) = config
					.gossip
					.journal
					.pending_local($crate::colony::common::current_timestamp_ms())
				{
					// A journal only records rumors that passed admission,
					// so a body or digest failure here means the backend
					// returned something it never admitted; the entry is
					// skipped rather than delivered unvalidated.
					for rumor in pending {
						let ::core::result::Result::Ok(body) =
							$crate::decode::<$crate::colony::common::GossipRumor>(&rumor.message)
						else {
							continue;
						};
						let ::core::result::Result::Ok(digest) =
							$crate::colony::cluster::gossip_digest::<$digest>(&rumor)
						else {
							continue;
						};
						$crate::cluster!(@gossip_deliver_local
							servlet_registry, config, local_pool, trace,
							body.payload, digest);
					}
				}

				if config.peers.is_empty() {
					continue;
				}

				let slate: Vec<$crate::utils::urn::Urn<'static>> = servlet_registry
					.local_servlets()
					.unwrap_or_default()
					.iter()
					.filter_map(|bytes| core::str::from_utf8(bytes).ok())
					.filter_map(|canonical| canonical.parse().ok())
					.take($crate::constants::MAX_ADVERTISED_TYPES)
					.collect();

				for peer in config.peers.iter() {
					let Ok(peer_addr) = peer.parse() else { continue };
					let _ = $crate::cluster!(
						@send_advertisement_async pool, config, peer_addr, gateway_addr.clone(), slate.clone(), $digest
					);
					// Anti-entropy backstop on the same beat.
					// Repair any rumor this peer is missing so flooding gaps do not persist.
					// Reconciliation is a colony operation: a non-member
					// gateway skips it, as its requests would be refused.
					if config.colony_urn().is_some() {
						let acked = push_ledger.entry(peer.clone()).or_default();
						let _ = $crate::cluster!(
							@reconcile_gossip_async pool, config, peer_addr,
							servlet_registry, trace, acked, peer.as_bytes(), $digest
						);
					}
				}
			}
		})
	}};

	// Helper: Process heartbeat result - updates registry based on success/failure
	(@process_heartbeat_result $registry:expr, $servlet_registry:expr, $hive_addr:expr, $result:expr, $max_failures:expr, $config:expr, $trace:expr) => {
		// A decoded heartbeat only proves the hive answered, not that it is
		// healthy: gate rejections (PermissionDenied/Unauthenticated) come back
		// heartbeat-shaped and must count as failures.
		let alive = matches!(
			&$result,
			Ok(hb) if matches!(
				hb.status,
				$crate::policy::TransitStatus::Ok | $crate::policy::TransitStatus::ResourceExhausted
			)
		);

		// Fire callback if configured
		$crate::cluster!(@fire_heartbeat_callback $config, $hive_addr, $result, alive);

		match (alive, $result) {
			(true, Ok(hb)) => {
				let _ = $registry.touch(&$hive_addr, hb.utilization);
			}
			_ => {
				if let Ok(failures) = $registry.increment_failure(&$hive_addr) {
					if failures >= $max_failures {
						// Remove from HiveRegistry
						let _ = $registry.unregister(&$hive_addr);
						// Also remove all servlet entries for this hive
						let _ = $servlet_registry.remove_by_hive(&$hive_addr);
						let _ = $trace.event($crate::instrumentation::events::CLUSTER_HIVE_EVICTED);
					}
				}
			}
		}
	};

	// Helper: Fire heartbeat callback if configured
	(@fire_heartbeat_callback $config:expr, $hive_addr:expr, $result:expr, $alive:expr) => {
		if let Some(ref callback) = $config.heartbeat.on_heartbeat {
			let event = $crate::colony::cluster::HeartbeatEvent {
				hive_addr: ::std::sync::Arc::clone(&$hive_addr),
				success: $alive,
				utilization: $result.as_ref().ok().map(|r| r.utilization),
			};
			callback(event);
		}
	};

	// Helper: Parse hive address from bytes to protocol address
	(@parse_hive_addr $hive:expr) => {
		{
			let hive_addr = ::std::sync::Arc::clone(&$hive.address);
			core::str::from_utf8(&hive_addr)
				.ok()
				.and_then(|s| s.parse().ok())
				.map(|addr| (hive_addr, addr))
		}
	};
}

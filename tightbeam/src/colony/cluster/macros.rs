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

				let pool = {
					use $crate::transport::client::pool::ConnectionBuilder;
					let mut builder = $crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
						.with_config(config.pool_config.clone())
						.with_client_identity(config.tls.certificate.clone(), ::std::sync::Arc::clone(&config.tls.key))?;

					if let Some(ref trust) = config.tls.hive_trust {
						builder = builder.with_trust_store(::std::sync::Arc::clone(trust));
					}

					::std::sync::Arc::new(builder.build())
				};

				let registry_for_server = ::std::sync::Arc::clone(&registry);
				let servlet_registry_for_server = ::std::sync::Arc::clone(&servlet_registry);
				let config_for_server = ::std::sync::Arc::clone(&config);
				let pool_for_server = ::std::sync::Arc::clone(&pool);
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
					trace_for_server,
					replay_guard_for_server
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
					let registry = ::std::sync::Arc::clone(&registry);
					let config = ::std::sync::Arc::clone(&config);

					// Federation crosses trust planes: a peer gateway's TLS
					// identity is anchored in `peer_trust`, not `hive_trust`,
					// so the beat dials on its own peer-plane pool. Without
					// `peer_trust` the hive pool is the only plane available.
					// TODO(zero-copy): `ConnectionBuilder::with_client_identity`
					// and `with_config` take `CertificateSpec`/`PoolConfig` by
					// value, forcing clones here and in the hive pool build
					// above. Rework the trait to borrow or take `Arc` so pool
					// construction is zero-copy.
					let advertise_pool = match config.tls.peer_trust {
						Some(ref trust) => {
							use $crate::transport::client::pool::ConnectionBuilder;
							::std::sync::Arc::new(
								$crate::transport::client::pool::ConnectionPool::<$protocol>::builder()
									.with_config(config.pool_config.clone())
									.with_client_identity(
										config.tls.certificate.clone(),
										::std::sync::Arc::clone(&config.tls.key),
									)?
									.with_trust_store(::std::sync::Arc::clone(trust))
									.build(),
							)
						}
						None => ::std::sync::Arc::clone(&pool),
					};
					let gateway_addr: Vec<u8> = addr.clone().into();

					Some($crate::cluster!(@build_advertise_task $protocol, registry, advertise_pool, config, gateway_addr, $digest))
				};
				#[cfg(not(feature = "x509"))]
				let advertise_handle = ::std::option::Option::None;

				Ok(Self {
					registry,
					servlet_registry,
					config,
					pool,
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
					.peer_servlets()
					.unwrap_or_default()
					.into_iter()
					.map(|entry| entry.servlet_type.to_vec())
					.collect();
				types.sort_unstable();
				types.dedup();
				types
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

			// =====================================================================
			// Heartbeat Methods
			// =====================================================================

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
	(@build_gateway_server $protocol:path, $listener:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident, $trace:ident, $replay_guard:ident) => {{
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
				let trace = ::std::sync::Arc::clone(&$trace);
				let _replay_guard = ::core::clone::Clone::clone(&$replay_guard);
				async move {
					$crate::cluster!(@handle_gateway_request frame, session, registry, servlet_registry, config, pool, trace, _replay_guard)
				}
			}
		}
	}};

	// Helper: Build response frame (DRY)
	(@reply $frame:ident, $message:expr) => {
		$crate::colony::common::reply_frame($frame.metadata.id.clone(), $message)
	};

	// Handle gateway requests (registration + work)
	(@handle_gateway_request $frame:ident, $session:ident, $registry:ident, $servlet_registry:ident, $config:ident, $pool:ident, $trace:ident, $replay_guard:ident) => {{
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
		#[cfg(feature = "x509")]
		let verify_control_freshness = |issued_at_ms: u64| {
			let now = $crate::colony::common::current_timestamp_ms();
			if !$replay_guard.is_fresh(issued_at_ms, now) {
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
		let verify_control_freshness = |_issued_at_ms: u64| $crate::policy::TransitStatus::Ok;

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

			let freshness_status = verify_control_freshness(request.issued_at_ms);
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

			let freshness_status = verify_control_freshness(update.issued_at_ms);
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
			if !matches!(
				$config.namespace.validate(&request.servlet_type),
				Ok($crate::colony::common::ColonyResource::Servlet { instance: None, .. })
			) {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_REFUSED);
				return $crate::cluster!(@reply $frame,
					$crate::colony::cluster::ClusterWorkResponse::err($crate::policy::TransitStatus::PermissionDenied)
				);
			}

			let type_key = $crate::colony::common::canonical_bytes(&request.servlet_type);
			let entries = match $servlet_registry.local_entries_for_type(&type_key) {
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
				.map(|e| {
					use core::sync::atomic::Ordering;
					$crate::colony::common::InstanceMetrics {
						instance_key: e.address.to_vec(),
						pheromone: e.pheromone.load(Ordering::Relaxed),
					}
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
			let selected_addr = ::std::sync::Arc::clone(&selected_entry.address);

			let forward_result = $crate::cluster!(@forward_work $pool, selected_addr, request.payload);

			// Pheromone feedback: the outcome steers future selection
			// toward instances that answer and away from ones that fail
			match forward_result {
				Ok(response_payload) => {
					let _ = $servlet_registry.reinforce(&selected_entry.address, $config.pheromone.reinforcement_boost);
					let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_ROUTED);
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::ok(response_payload)
					);
				}
				Err(error) => {
					let _ = $servlet_registry.weaken_with_penalty(&selected_entry.address, $config.pheromone.weakening_penalty);
					let _ = $trace.event($crate::instrumentation::events::CLUSTER_WORK_FAILED);

					// A servlet refusal relays verbatim so the caller keeps
					// its retryability contract.
					let status = match error {
						$crate::colony::cluster::ClusterError::Transport(
							$crate::transport::error::TransportError::OperationFailed(failure),
						) => $crate::policy::TransitStatus::try_from(failure)
							.unwrap_or($crate::policy::TransitStatus::Unavailable),
						_ => $crate::policy::TransitStatus::Unavailable,
					};
					return $crate::cluster!(@reply $frame,
						$crate::colony::cluster::ClusterWorkResponse::err(status)
					);
				}
			}
		}

		$crate::colony::common::ClusterRequest::AdvertisePeer(advertisement) => {
			let origin_status = verify_peer_origin();
			if origin_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse {
					status: origin_status,
				});
			}

			let freshness_status = verify_control_freshness(advertisement.issued_at_ms);
			if freshness_status != $crate::policy::TransitStatus::Ok {
				let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED);
				return $crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse {
					status: freshness_status,
				});
			}

			// Slate ownership binds to the AUTHENTICATED signer certificate,
			// never the claimed gateway_addr: any trusted peer could
			// otherwise claim another peer's address and clobber or withdraw
			// that peer's slate (CWE-290).
			#[cfg(feature = "x509")]
			let peer_hive_id: ::std::option::Option<Vec<u8>> =
				$frame.nonrepudiation.as_ref().and_then(|signer_info| {
					$config.tls.peer_trust.as_ref().and_then(|trust| {
						trust.find_by_signer_info(signer_info).and_then(|cert| {
							$crate::crypto::x509::store::CertificateTrustStore::to_fingerprint(cert)
								.ok()
								.map(|fingerprint| fingerprint.to_vec())
						})
					})
				});

			// Without x509 there is no signer identity to bind: the claimed
			// address is the only available slate key.
			#[cfg(not(feature = "x509"))]
			let peer_hive_id: ::std::option::Option<Vec<u8>> =
				::std::option::Option::Some(advertisement.gateway_addr.to_vec());

			let ::std::option::Option::Some(peer_hive_id) = peer_hive_id else {
				return $crate::cluster!(@refuse_peer_ad $frame, $trace, $replay_guard,
					$crate::policy::TransitStatus::PermissionDenied);
			};

			// Nestmate recognition (structural CHC half): every advertised
			// identity must be a bare servlet type URN in this gateway's
			// realm/NID. A foreign authority or realm is refused before any
			// route installs. The count is bounded fail-closed (CWE-770).
			let gateway_addr_nonempty = !advertisement.gateway_addr.is_empty();
			let gateway_addr_utf8 = core::str::from_utf8(&advertisement.gateway_addr).is_ok();
			let gateway_addr_no_nul = !advertisement.gateway_addr.contains(&0);
			let gateway_addr_valid = gateway_addr_nonempty && gateway_addr_utf8 && gateway_addr_no_nul;
			let types_valid = advertisement.advertised_types.iter().all(|urn| matches!(
				$config.namespace.validate(urn),
				Ok($crate::colony::common::ColonyResource::Servlet { instance: ::std::option::Option::None, .. })
			));

			let within_cap = advertisement.advertised_types.len() <= $crate::constants::MAX_ADVERTISED_TYPES;

			// A peer slate replaces only prior Peer state: a gateway_addr or
			// signer fingerprint that collides with a local servlet address
			// or local hive key would let a trusted peer clobber routes the
			// hive trust plane installed, so it is refused (CWE-284).
			let no_local_conflict = matches!(
				$servlet_registry.peer_key_conflicts_local(&advertisement.gateway_addr),
				Ok(false)
			) && matches!(
				$servlet_registry.peer_key_conflicts_local(&peer_hive_id),
				Ok(false)
			);

			if !gateway_addr_valid || !types_valid || !within_cap || !no_local_conflict {
				return $crate::cluster!(@refuse_peer_ad $frame, $trace, $replay_guard,
					$crate::policy::TransitStatus::PermissionDenied);
			}

			// Peer routes live only in the servlet registry, reconciled by
			// the signer identity as the hive key. Entries are keyed by a
			// per-type route key (signer NUL type) because the entry map is
			// one-entry-per-address: keying every type by the bare signer
			// identity would keep only the last type in the slate.
			let gateway_id: ::std::sync::Arc<[u8]> = peer_hive_id.as_slice().into();
			let slate: Vec<$crate::colony::cluster::ServletEntry> = advertisement
				.advertised_types
				.iter()
				.map(|urn| {
					let type_bytes = $crate::colony::common::type_canonical_bytes(urn);
					let mut route_key = Vec::with_capacity(gateway_id.len() + 1 + type_bytes.len());
					route_key.extend_from_slice(&gateway_id);
					route_key.push(0);
					route_key.extend_from_slice(&type_bytes);

					$crate::colony::cluster::ServletEntry::new(
						::std::sync::Arc::from(route_key.as_slice()),
						::std::sync::Arc::from(type_bytes.as_slice()),
						::std::sync::Arc::clone(&gateway_id),
						$config.pheromone.initial_pheromone,
						$config.pheromone.abandonment_limit,
					).with_route_kind($crate::colony::cluster::RouteKind::Peer)
				})
				.collect();

			if $servlet_registry.reconcile_by_hive(&gateway_id, slate).is_err() {
				return $crate::cluster!(@refuse_peer_ad $frame, $trace, $replay_guard,
					$crate::policy::TransitStatus::PermissionDenied);
			}

			let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISED);
			return $crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse {
				status: $crate::policy::TransitStatus::Ok,
			});
		}
		}
	}};

	// Helper: refuse a peer advertisement whose replay record already
	// exists. The refusal is deterministic on local state, so the record
	// is released: the peer must be able to resend the same signed frame
	// once that state clears (CWE-772). Refusals BEFORE the freshness
	// check reply plain instead: no record exists yet, or the record IS
	// the protection being enforced.
	(@refuse_peer_ad $frame:ident, $trace:ident, $replay_guard:ident, $status:expr) => {{
		#[cfg(feature = "x509")]
		if let Some(signer_info) = $frame.nonrepudiation.as_ref() {
			$replay_guard.forget(signer_info.signature.as_bytes());
		}
		let _ = $trace.event($crate::instrumentation::events::CLUSTER_PEER_ADVERTISE_REFUSED);
		$crate::cluster!(@reply $frame, $crate::colony::common::PeerAdvertisementResponse { status: $status })
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
				issued_at_ms: $crate::colony::common::current_timestamp_ms(),
				heartbeat: Some($crate::colony::common::HeartbeatParams {
					cluster_status: $crate::colony::common::ClusterStatus::Healthy,
				}),
				manage: None,
			};

			// Priority is a V2+ metadata field. Composing it on V1 fails at
			// build time and every heartbeat would count as a send failure.
			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"heartbeat")
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
					issued_at_ms: $crate::colony::common::current_timestamp_ms(),
					gateway_addr: $gateway_addr,
					advertised_types: $types,
				}
			);

			let frame = $crate::builder::frame::FrameBuilder::from($crate::Version::V2)
				.with_id(b"peer-advertise")
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

	// Helper: Build the advertise beat task. Inert unless an interval and
	// peers are configured. Each tick snapshots the hive registry: the
	// slate is point-in-time truth, so types appear as hives register and
	// disappear as they leave. An empty slate is still sent.
	(@build_advertise_task $protocol:path, $registry:expr, $pool:expr, $config:expr, $gateway_addr:expr, $digest:path) => {{
		let registry = $registry;
		let pool = $pool;
		let config = $config;
		let gateway_addr = $gateway_addr;

		$crate::colony::servlet::servlet_runtime::rt::spawn(async move {
			let Some(interval) = config.advertise_interval else { return };
			if config.peers.is_empty() {
				return;
			}

			loop {
				$crate::colony::servlet::servlet_runtime::rt::sleep(interval).await;

				let slate: Vec<$crate::utils::urn::Urn<'static>> = registry
					.to_available_servlets()
					.unwrap_or_default()
					.iter()
					.filter_map(|bytes| core::str::from_utf8(bytes).ok())
					.filter_map(|canonical| canonical.parse().ok())
					.collect();

				for peer in config.peers.iter() {
					let Ok(peer_addr) = peer.parse() else { continue };
					let _ = $crate::cluster!(
						@send_advertisement_async pool, config, peer_addr, gateway_addr.clone(), slate.clone(), $digest
					);
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

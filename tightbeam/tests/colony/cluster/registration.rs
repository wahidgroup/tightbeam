//! Registration, control-plane refusal, and hive lifecycle.

use super::common::*;

tb_assert_spec! {
	pub ClusterTeardownSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

/// Records the teardown call instead of serving traffic: `stop_boxed` is
/// the observable under test.
struct StopProbeServlet {
	trace: TraceCollector,
}

impl ServletBox for StopProbeServlet {
	fn addr_bytes(&self) -> std::sync::Arc<[u8]> {
		std::sync::Arc::from(b"127.0.0.1:0".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {
		let _ = self.trace.event(SERVLET_STOPPED);
	}
}

// Environment teardown must run `Hive::stop`, which drains registered
// servlets through `stop_boxed`. Plain drop only aborts control tasks.
tb_scenario! {
	name: cluster_env_teardown_stops_hive_servlets,
	spec: ClusterTeardownSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![async move {
			let mut hive = ClusterTestHive::new(Some(hive_tls_config(&certs)))?;
			hive.register(servlet_urn("probe"), StopProbeServlet { trace: trace.share() }, |t| async move {
				Ok(StopProbeServlet { trace: t.share() })
			})?;
			hive.establish(Arc::new(trace.share())).await?;

			Ok::<_, TightBeamError>(hive)
		}],
		client: |ClusterEnv { cluster, .. }| async move {
			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPolicySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_GATE_BLOCKED, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

tb_scenario! {
	name: cluster_policy_gate_blocks,
	spec: ClusterPolicySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let cluster_conf = ClusterConfig::builder(cluster_tls_config(&certs))
				.with_gate_policy(Arc::new(RejectAllPolicy))
				.build();

			start_cluster(&trace, cluster_conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let inner = signed_work_frame(&certs.key, b"policy-test").await?;

			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;

			trace.event(WORK_SENT)?;

			let refused_work = client.submit_work_to(servlet_urn("ping"), &inner).await;
			record_work_refusal(&trace, refused_work)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterUnsignedRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_unsigned_registration,
	spec: ClusterUnsignedRegistrationSpec,
	environment Cluster {
		context: cluster_certs(),
		// Registration itself is under test, so no `hives:` key.
		// The client drives it, and the spec asserts the rejection.
		start: |SetupEnv { trace, context: certs }| async move {
			// The cluster requires signed hive-origin frames (hive_trust set).
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			// The hive validates the cluster's TLS certificate but has no
			// signing identity of its own, so control frames go out unsigned.
			let hive_conf = HiveConfig {
				trust_store: Some(Arc::clone(&certs.trust)),
				..Default::default()
			};

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(trace.share())).await?;

			trace.event(REGISTRATION_SENT)?;

			let cluster_addr = cluster.addr();
			let response = hive.register_with_cluster(cluster_addr).await?;
			record_register_response(&trace, &response, &cluster)?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRefusedRegNotQueuedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::HIVE_REREGISTERED, exactly!(0)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Unauthenticated)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
		]
	}
}

// A refused RegisterHiveResponse must not enqueue the gateway: the
// anti-entropy beat would otherwise keep calling a peer that already
// rejected the hive, and scaling updates would fan out there too.
tb_scenario! {
	name: cluster_refused_registration_does_not_queue_gateway,
	spec: ClusterRefusedRegNotQueuedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let mut hive_conf = HiveConfig {
				trust_store: Some(Arc::clone(&certs.trust)),
				..Default::default()
			};
			hive_conf.control.reregister_interval = Some(Duration::from_millis(50));

			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(trace.share())).await?;

			trace.event(REGISTRATION_SENT)?;

			let cluster_addr = cluster.addr();
			let response = hive.register_with_cluster(cluster_addr).await?;
			record_register_response(&trace, &response, &cluster)?;

			// Wait several anti-entropy intervals. A queued gateway would
			// emit HIVE_REREGISTERED, and an unqueued one stays silent.
			tokio::time::sleep(Duration::from_millis(250)).await;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterNoTrustStoreSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(REGISTRATION_SENT, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(REGISTRY_HIVES, exactly!(1), equals!(0u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(0u64))
		]
	}
}

tb_scenario! {
	name: cluster_without_hive_trust_rejects_control_frames,
	spec: ClusterNoTrustStoreSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			// A gateway without hive_trust cannot authenticate control
			// frames and must fail closed, so even a validly signed
			// registration is rejected.
			let tls = ClusterTlsConfig {
				certificate: CertificateSpec::Built(Box::new(certs.cert.to_owned())),
				key: Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())),
				validators: vec![],
				client_validators: vec![],
				hive_trust: None,
				peer_trust: None,
			};
			start_cluster(&trace, ClusterConfig::new(tls)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;
			let signed = signed_control_frame(
				&certs,
				b"no-trust-reg",
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;

			trace.event(REGISTRATION_SENT)?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			record_register_response(&trace, &response, &cluster)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterServletLocatorAlignSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Alignment ordering: the mismatched registration is refused before the
// clean one lands, and the mismatched update is refused only after the
// hive registered. Counting cannot prove which registration was refused.
tb_process_spec! {
	pub ClusterLocatorAlignProcess,
	events {
		observable {
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_REFUSED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_REGISTER_REFUSED => MisalignRefused },
		MisalignRefused => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_UPDATE_REFUSED => UpdateRefused },
		UpdateRefused => { }
	}
	terminal { UpdateRefused }
}

// Register and update must refuse ServletInfo whose instance locator
// disagrees with the announced address: routes key by address, remove
// by URN locator (CWE-639 ghost / orphan routes).
tb_scenario! {
	name: cluster_rejects_mismatched_servlet_locator,
	config: ScenarioConfig::builder()
		.with_spec(ClusterServletLocatorAlignSpec::latest())
		.with_csp(ClusterLocatorAlignProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;
			let hive_addr = b"127.0.0.1:65100";

			let mismatch = servlet_info_mismatched("ping", b"127.0.0.1:65101", b"127.0.0.1:65199");
			let refused_reg = signed_control_frame(
				&certs,
				b"misalign-reg",
				ClusterRequest::RegisterHive(RegisterHiveRequest {
					hive_addr: hive_addr.to_vec(),
					servlet_addresses: vec![mismatch],
					metadata: None,
				}),
			)
			.await?;

			let response_frame = emit_frame(&mut client, refused_reg).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// A clean registration lands, then a mismatched add must refuse.
			let ok_reg = signed_control_frame(
				&certs,
				b"align-reg",
				registration_request(hive_addr),
			)
			.await?;

			let response_frame = emit_frame(&mut client, ok_reg).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			let bad_add = servlet_address_update(
				hive_addr,
				vec![servlet_info_mismatched("ping", b"127.0.0.1:65102", b"127.0.0.1:65198")],
				vec![],
			);

			let refused_update = signed_control_frame(&certs, b"misalign-update", bad_add).await?;
			let response_frame = emit_frame(&mut client, refused_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterReplaySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(2)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Anti-replay ordering: only after a registration lands can its replay
// (then a stale resend) be refused, and only after a fresh update lands
// can its replay be refused. Counting alone cannot prove the refusals
// follow the acceptances.
tb_process_spec! {
	pub ClusterReplayProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED,
			events::CLUSTER_UPDATE_REFUSED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_REGISTER_REFUSED => ReplayRefused },
		ReplayRefused => { events::CLUSTER_REGISTER_REFUSED => StaleRefused },
		StaleRefused => { events::CLUSTER_UPDATE_ACCEPTED => UpdateAccepted },
		UpdateAccepted => { events::CLUSTER_UPDATE_REFUSED => Done },
		Done => { }
	}
	terminal { Done }
}

tb_scenario! {
	name: cluster_rejects_replayed_and_stale_control_frames,
	config: ScenarioConfig::builder()
		.with_spec(ClusterReplaySpec::latest())
		.with_csp(ClusterReplayProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;

			// A fresh signed registration is accepted.
			let fresh = signed_control_frame(
				&certs,
				b"replay-reg",
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;
			let replayed = fresh.to_owned();

			let response_frame = emit_frame(&mut client, fresh).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// A byte-identical resend carries an already-seen signature.
			let response_frame = emit_frame(&mut client, replayed).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// The signature is valid but the order lies outside the
			// freshness window.
			let stale_ts = current_timestamp_ms() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame_with_order(
				&certs.key,
				b"stale-reg",
				registration_request(b"127.0.0.1:65000"),
				stale_ts,
			)
			.await?;

			let response_frame = emit_frame(&mut client, stale).await?;
			let _: RegisterHiveResponse = decode(&response_frame.message)?;

			// The same enforcement applies to servlet address updates.
			let update = servlet_address_update(
				b"127.0.0.1:65000",
				vec![servlet_info("ping", b"127.0.0.1:65001")],
				vec![],
			);
			let fresh_update = signed_control_frame(&certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.to_owned();

			let response_frame = emit_frame(&mut client, fresh_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

			let response_frame = emit_frame(&mut client, replayed_update).await?;
			let _: ServletAddressUpdateResponse = decode(&response_frame.message)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterHeartbeatRejectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(REGISTER_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(REGISTRY_HIVES, exactly!(1), equals!(1u64)),
			(REGISTER_ASSIGNED_ID, exactly!(1), equals!(1u64)),
			(REGISTRY_EMPTIED, exactly!(1), equals!(1u64)),
			(REJECTED_HEARTBEAT_DECODED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_HIVE_EVICTED, exactly!(1))
		]
	}
}

// Eviction ordering: a hive can only be evicted after it registered.
// The client-side REJECTED_HEARTBEAT_DECODED marker stays out of the
// alphabet because the heartbeat task fires the eviction event after the
// registry empties, racing the client's poll.
tb_process_spec! {
	pub ClusterEvictionProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_HIVE_EVICTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_HIVE_EVICTED => Evicted },
		Evicted => { }
	}
	terminal { Evicted }
}

/// Heartbeat-eviction fixture. The heartbeat callback (set in `start`)
/// records whether a decoded rejected heartbeat was observed. The client
/// surfaces that flag as a valued event the spec pins after eviction.
struct HeartbeatRejectionContext {
	certs: ClusterTestCerts,
	rejected_decoded: AtomicBool,
}

tb_scenario! {
	name: cluster_evicts_hive_on_rejected_heartbeats,
	config: ScenarioConfig::builder()
		.with_spec(ClusterHeartbeatRejectionSpec::latest())
		.with_csp(ClusterEvictionProcess)
		.build(),
	environment Cluster {
		context: HeartbeatRejectionContext {
			certs: cluster_certs(),
			rejected_decoded: AtomicBool::new(false),
		},
		start: |SetupEnv { trace, context: rejection }| async move {
			let callback_rejection = Arc::clone(&rejection);
			let heartbeat = HeartbeatConfig::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.with_callback(Arc::new(move |event| {
					// utilization is only Some when the heartbeat response
					// decoded, proving the failure came from the rejected
					// status rather than a transport error.
					let decoded_reject = !event.success && event.utilization.is_some();
					callback_rejection
						.rejected_decoded
						.fetch_or(decoded_reject, Ordering::SeqCst);
				}))
				.build();

			let cluster_conf = ClusterConfig::builder(cluster_tls_config(&rejection.certs))
				.with_heartbeat_config(heartbeat)
				.build();
			start_cluster(&trace, cluster_conf).await
		},
		client: |ClusterEnv { trace, context: rejection, cluster }| async move {
			let certs = &rejection.certs;
			let cluster_addr = cluster.addr();

			// The hive serves the shared cert (the cluster trusts it for
			// TLS) but configures no trust store for inbound commands.
			let mut hive = ClusterTestHive::new(Some(hive_tls_config_no_trust(certs)))?;
			hive.establish(Arc::new(trace.share())).await?;

			// Register the hive out-of-band with a validly signed frame.
			let hive_addr_bytes = hive.addr().to_string().into_bytes();
			let registration = signed_control_frame(
				certs,
				b"hb-reject-reg",
				registration_request(&hive_addr_bytes),
			)
			.await?;

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let response_frame = emit_frame(&mut client, registration).await?;
			let response: RegisterHiveResponse = decode(&response_frame.message)?;
			record_register_response(&trace, &response, &cluster)?;

			// Heartbeats run every 100ms with max_failures = 1, so the
			// first PermissionDenied heartbeat must evict the hive.
			let emptied = wait_for_empty_registry(&cluster, 50, Duration::from_millis(100)).await;
			trace.event_with(REGISTRY_EMPTIED, &[], u64::from(emptied))?;

			let decoded = rejection.rejected_decoded.load(Ordering::SeqCst);
			trace.event_with(REJECTED_HEARTBEAT_DECODED, &[], u64::from(decoded))?;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

// Two hive identities under one gateway prove ServletAddressUpdate is
// signer-bound, so one hive cannot tamper with another's routes.
struct DualHiveCerts {
	gateway: ClusterTestCerts,
	hive_a: (Certificate, Secp256k1SigningKey),
	hive_b: (Certificate, Secp256k1SigningKey),
	hive_trust: Arc<dyn CertificateTrust>,
}

fn dual_hive_certs() -> DualHiveCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate;

	let gateway = cluster_certs();
	let raw_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_a = create_test_certificate(&raw_a);
	let cert_b = create_test_certificate(&raw_b);
	let key_a = Secp256k1SigningKey::from(raw_a);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::<Sha3_256>::from(Secp256k1Policy)
			.with_certificate(cert_a.to_owned())
			.expect("hive A trust")
			.with_certificate(cert_b.to_owned())
			.expect("hive B trust")
			.build(),
	);

	DualHiveCerts { gateway, hive_a: (cert_a, key_a), hive_b: (cert_b, key_b), hive_trust }
}

tb_assert_spec! {
	pub ClusterCrossHiveUpdateSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2)),
			(REGISTER_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(REGISTRY_HIVES, exactly!(1), equals!(2u64)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

// Tamper ordering: the cross-hive poison update is refused before the
// owner's update lands. Counting cannot prove the refusal hit the
// poison rather than the owner's own update.
tb_process_spec! {
	pub ClusterCrossUpdateProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => OneRegistered },
		OneRegistered => { events::CLUSTER_HIVE_REGISTERED => TwoRegistered },
		TwoRegistered => { events::CLUSTER_UPDATE_REFUSED => CrossRefused },
		CrossRefused => { events::CLUSTER_UPDATE_ACCEPTED => OwnerLanded },
		OwnerLanded => { }
	}
	terminal { OwnerLanded }
}

tb_scenario! {
	name: cluster_rejects_cross_hive_servlet_address_update,
	config: ScenarioConfig::builder()
		.with_spec(ClusterCrossHiveUpdateSpec::latest())
		.with_csp(ClusterCrossUpdateProcess)
		.build(),
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config_with_trust(
				&certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs.gateway, cluster_addr).await?;

			let hive_a_addr = b"127.0.0.1:65010".as_slice();
			let hive_b_addr = b"127.0.0.1:65011".as_slice();

			let response_a = register_signed_hive(&mut client, &certs.hive_a.1, b"reg-a", hive_a_addr).await?;
			let response_b = register_signed_hive(&mut client, &certs.hive_b.1, b"reg-b", hive_b_addr).await?;
			trace.event_with(REGISTER_STATUS, &[], response_a.status)?;
			trace.event_with(REGISTER_STATUS, &[], response_b.status)?;
			trace.event_with(REGISTRY_HIVES, &[], cluster.hive_count() as u64)?;

			let update_cases = [
				(
					&certs.hive_b.1,
					b"cross-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("poison", b"127.0.0.1:65099")], vec![]),
				),
				(
					&certs.hive_a.1,
					b"owner-update".as_slice(),
					servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65012")], vec![]),
				),
			];

			for (key, id, request) in update_cases {
				emit_servlet_update(&mut client, key, id, request).await?;
			}

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRegistrationHijackSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(REGISTRY_HIVES, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

tb_process_spec! {
	// Hijack ordering: the owner registers first, the hijacker's registration
	// is refused, and only then does the owner's update land.
	pub ClusterHijackProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_REGISTER_REFUSED,
			events::CLUSTER_UPDATE_ACCEPTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => OwnerRegistered },
		OwnerRegistered => { events::CLUSTER_REGISTER_REFUSED => HijackRefused },
		HijackRefused => { events::CLUSTER_UPDATE_ACCEPTED => OwnerBindIntact },
		OwnerBindIntact => { }
	}
	terminal { OwnerBindIntact }
}

tb_scenario! {
	name: cluster_rejects_cross_hive_registration_hijack,
	config: ScenarioConfig::builder()
		.with_spec(ClusterRegistrationHijackSpec::latest())
		.with_csp(ClusterHijackProcess)
		.build(),
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config_with_trust(
				&certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;
			let hive_a_addr = b"127.0.0.1:65020".as_slice();

			register_signed_hive(&mut client, &certs.hive_a.1, b"owner-reg", hive_a_addr).await?;
			register_signed_hive(&mut client, &certs.hive_b.1, b"hijack-reg", hive_a_addr).await?;

			// The registry after the refused hijack still holds exactly
			// the owner: the failed takeover must not disturb the binding.
			trace.event_with(REGISTRY_HIVES, &[], cluster.hive_count() as u64)?;

			// The owner's update still lands: the failed hijack must not
			// have disturbed the signer binding.
			emit_servlet_update(
				&mut client,
				&certs.hive_a.1,
				b"owner-still-bound",
				servlet_address_update(hive_a_addr, vec![servlet_info("ping", b"127.0.0.1:65021")], vec![]),
			)
			.await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRemovalSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(2)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

tb_process_spec! {
	// Removal ordering: work routes only between the add and the removal,
	// the foreign-realm refusal lands between them, and unavailability
	// follows the accepted removal. Counting cannot distinguish "routed
	// then removed" from "removed then routed".
	pub ClusterRemovalProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_UPDATE_ACCEPTED,
			events::CLUSTER_UPDATE_REFUSED,
			events::CLUSTER_WORK_ROUTED,
			events::CLUSTER_WORK_UNAVAILABLE
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_UPDATE_ACCEPTED => InstanceAdded },
		InstanceAdded => { events::CLUSTER_WORK_ROUTED => Routed },
		Routed => { events::CLUSTER_UPDATE_REFUSED => ForeignRefused },
		ForeignRefused => { events::CLUSTER_UPDATE_ACCEPTED => InstanceRemoved },
		InstanceRemoved => { events::CLUSTER_WORK_UNAVAILABLE => Unrouted },
		Unrouted => { }
	}
	terminal { Unrouted }
}

// A signed update that removes an instance URN unroutes it: work for
// the type routed before the removal and is Unavailable after. A
// removal naming a foreign realm is refused wholesale.
tb_scenario! {
	name: cluster_removal_update_unroutes_instance,
	config: ScenarioConfig::builder()
		.with_spec(ClusterRemovalSpec::latest())
		.with_csp(ClusterRemovalProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let conf = routing_cluster_conf(&certs, None);
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let trace = Arc::new(trace.share());
			let config = Some(servlet_tls_config(&certs)?);
			let servlet = ClusterTestServlet::start(trace, config).await?;
			let servlet_addr = servlet.addr().to_string();
			let hive_addr = b"127.0.0.1:65200".as_slice();

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			register_signed_hive(&mut client, &certs.key, b"removal-reg", hive_addr).await?;

			let added = vec![servlet_info("ping", servlet_addr.as_bytes())];
			let request = servlet_address_update(hive_addr, added, vec![]);
			emit_servlet_update(&mut client, &certs.key, b"removal-add", request).await?;

			emit_ping_work(&mut client, &certs.key, b"pre-removal-work").await?;

			let removed = vec![foreign_realm_instance(&servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-foreign", request).await?;

			let removed = vec![servlet_instance(&servlet_urn("ping"), &servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-remove", request).await?;

			// The removed instance no longer routes, so the submission
			// must resolve to a refusal.
			let refused_work = emit_ping_work(&mut client, &certs.key, b"post-removal-work").await;
			work_refusal_status(refused_work)?;

			servlet.stop();
			cluster.stop();
			Ok(())
		}
	}
}

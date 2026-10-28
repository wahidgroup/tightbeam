//! The tests of registration, control-plane refusal, and the hive lifecycle.

use tokio::sync::Notify;

use tightbeam::colony::cluster::ClusterHeartbeat;
use tightbeam::colony::hive::ServletDrainFuture;
use tightbeam::crypto::x509::store::TrustVerification;
use tightbeam::testing::TestFrame;
use tightbeam::trace::AssertionValue;
use tightbeam::transport::{TransportError, TransportFailure};

#[cfg(feature = "instrument")]
use tightbeam::testing::fixtures::TestTrace;

use super::common::*;

tb_assert_spec! {
	pub ClusterTeardownSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(SERVLET_STOPPED, exactly!(1))
		]
	}
}

/// A servlet that records its teardown call and serves no traffic, because
/// `stop_boxed` is the observable under test.
struct StopProbeServlet {
	trace: TraceCollector,
}

impl ServletBox for StopProbeServlet {
	fn addr_bytes(&self) -> std::sync::Arc<[u8]> {
		std::sync::Arc::from(b"127.0.0.1:0".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {
		self.trace
			.event(SERVLET_STOPPED)
			.expect("recording the servlet stop is what this probe exists to do");
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}
}

// Environment teardown must run `Hive::stop`, which drains registered
// servlets through `stop_boxed`. A plain drop only aborts control tasks.
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
		assertions: [
			(events::CLUSTER_GATE_BLOCKED, exactly!(1), equals!(TransitStatus::PermissionDenied))
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let inner = signed_work_frame(&certs.key, b"policy-test").await?;

			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;

			let refused_work = client.submit_work_to(servlet_urn("ping"), &inner).await;
			check_work_refusal(refused_work, TransitStatus::PermissionDenied)?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterUnsignedRegistrationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::Unauthenticated))
		]
	}
}

tb_scenario! {
	name: cluster_rejects_unsigned_registration,
	spec: ClusterUnsignedRegistrationSpec,
	environment Cluster {
		context: cluster_certs(),
		// Registration itself is under test, so the environment has no
		// `hives:` key. The client drives it, and the spec asserts the
		// rejection.
		start: |SetupEnv { trace, context: certs }| async move {
			// The cluster requires signed hive-origin frames because
			// `hive_trust` is set.
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;

			// The frame is unsigned by construction. A hive cannot drive this
			// case: with no signing identity it binds no control plane, so it
			// has no address to register and refuses before it dials.
			let unsigned = Version::V0
				.compose()
				.with_id(b"unsigned-reg")
				.with_order(UnixMillis::now().get())
				.with_message(registration_request(b"127.0.0.1:65200"))
				.build()?;

			let response_frame = emit_frame(&mut client, unsigned).await?;
			let response: RegisterHiveResponse = decode(response_frame.message())?;
			assert!(response.hive_id.is_none(), "a refused registration assigns no hive id");
			assert_eq!(cluster.hive_count()?, 0, "a refused registration installs no hive");

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRefusedRegNotQueuedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2)),
			(events::HIVE_REREGISTERED, exactly!(1), equals!(TransitStatus::Ok))
		]
	}
}

/// The hive's own signing identity and the trust store that admits it.
///
/// The identity is absent from the shared gateway trust, so the refusing
/// gateway turns it away, and present here, so the accepting gateway
/// admits it.
fn untrusted_hive_identity() -> (Arc<HiveTlsConfig>, Arc<dyn CertificateTrust>) {
	let (hive_cert, hive_key) = colony_identity("CN=Untrusted Hive", &test_colony_urn());
	let admits_hive: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
			.with_certificate(hive_cert.to_owned())
			.expect("the hive certificate builds a trust store")
			.build(),
	);
	let hive_tls = HiveTlsConfig::new(
		CertificateSpec::Built(Box::new(hive_cert)),
		Arc::new(Secp256k1KeyProvider::from(hive_key)),
		PeerAuthentication::Anonymous,
	)
	.expect("the hive TLS material must decode");

	(Arc::new(hive_tls), admits_hive)
}

// A refused registration must not queue the gateway, or the hive's beat
// calls a peer that refused it. A second gateway admits the hive, so its beat
// re-registers once with `Ok`, and the refusal count stays at one.
tb_scenario! {
	name: cluster_refused_registration_does_not_queue_gateway,
	spec: ClusterRefusedRegNotQueuedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let clock = Arc::new(ManualClock::default());
			let (hive_tls, admits_hive) = untrusted_hive_identity();

			// The accepting gateway's own heartbeat never fires inside this
			// run, because it reads the clock the test advances.
			let mut accepting_conf = ClusterConfig::new(cluster_tls_config_with_trust(&certs, Some(admits_hive)));
			accepting_conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;

			let accepting = start_cluster(&trace, accepting_conf).await?;
			let mut hive_conf = HiveConfig {
				trust_store: Some(Arc::clone(&certs.trust)),
				hive_tls: Some(hive_tls),
				clock: Arc::clone(&clock) as Arc<dyn Clock>,
				..Default::default()
			};
			hive_conf.control.reregister_interval = Some(Duration::from_millis(50));
			let mut hive = ClusterTestHive::new(Some(hive_conf))?;
			hive.establish(Arc::new(trace.share())).await?;

			let response = hive.register_with_cluster(cluster.addr()).await?;
			assert!(response.hive_id.is_none(), "a refused registration assigns no hive id");
			assert_eq!(cluster.hive_count()?, 0, "a refused registration installs no hive");

			hive.register_with_cluster(accepting.addr()).await?;

			// The hive's beat re-announces to every gateway it queued, and
			// records the answer of each one.
			clock.advance(Duration::from_millis(50));
			let reregistered = || trace.recorded(events::HIVE_REREGISTERED) >= 1;
			poll_until(50, Duration::from_millis(20), reregistered).await;

			hive.stop();
			accepting.stop();
			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterNoTrustStoreSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

tb_scenario! {
	name: cluster_without_hive_trust_rejects_control_frames,
	spec: ClusterNoTrustStoreSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			// A gateway without `hive_trust` cannot authenticate control
			// frames and must fail closed, so it rejects even a validly
			// signed registration.
			let tls = ClusterTlsConfig::new(CertificateSpec::Built(Box::new(certs.cert.to_owned())), Arc::new(Secp256k1KeyProvider::from(certs.key.to_owned())))
				.expect("the test certificate must decode");
			start_cluster(&trace, ClusterConfig::new(tls)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs, cluster_addr).await?;
			let signed = signed_control_frame(
				&certs,
				b"no-trust-reg",
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;

			let response_frame = emit_frame(&mut client, signed).await?;
			let response: RegisterHiveResponse = decode(response_frame.message())?;
			assert!(response.hive_id.is_none(), "a refused registration assigns no hive id");
			assert_eq!(cluster.hive_count()?, 0, "a refused registration installs no hive");

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterServletLocatorAlignSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Alignment ordering: the gateway refuses the mismatched registration before
// the clean one lands, and refuses the mismatched update only after the hive
// registered. A count cannot prove which registration the gateway refused.
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

// Register and update must refuse a `ServletInfo` whose instance locator
// disagrees with the announced address. Routes key by address and remove by
// URN locator, so a mismatch leaves ghost or orphan routes (CWE-639).
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

			let mismatch = servlet_info_mismatched(&certs, "ping", b"127.0.0.1:65101", b"127.0.0.1:65199");
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
			let _: RegisterHiveResponse = decode(response_frame.message())?;

			// After a clean registration lands, a mismatched add must refuse.
			let ok_reg = signed_control_frame(
				&certs,
				b"align-reg",
				registration_request(hive_addr),
			)
			.await?;

			let response_frame = emit_frame(&mut client, ok_reg).await?;
			let _: RegisterHiveResponse = decode(response_frame.message())?;

			let bad_add = servlet_address_update(
				hive_addr,
				vec![servlet_info_mismatched(&certs, "ping", b"127.0.0.1:65102", b"127.0.0.1:65198")],
				vec![],
			);

			let refused_update = signed_control_frame(&certs, b"misalign-update", bad_add).await?;
			let response_frame = emit_frame(&mut client, refused_update).await?;
			let _: ServletAddressUpdateResponse = decode(response_frame.message())?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterReplaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(2)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1))
		]
	}
}

// Anti-replay ordering: the gateway can refuse a registration's replay (then
// a stale resend) only after the registration lands, and an update's replay
// only after the fresh update lands. A count alone cannot prove that the
// refusals follow the acceptances.
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

			// The gateway accepts a fresh signed registration.
			let fresh = signed_control_frame(
				&certs,
				b"replay-reg",
				registration_request(b"127.0.0.1:65000"),
			)
			.await?;
			let replayed = fresh.to_owned();

			let response_frame = emit_frame(&mut client, fresh).await?;
			let _: RegisterHiveResponse = decode(response_frame.message())?;

			// A byte-identical resend carries an already-seen signature.
			let response_frame = emit_frame(&mut client, replayed).await?;
			let _: RegisterHiveResponse = decode(response_frame.message())?;

			// The signature is valid but the order lies outside the
			// freshness window.
			let stale_ts = UnixMillis::now().get() - 2 * DEFAULT_COMMAND_FRESHNESS_WINDOW_MS;
			let stale = signed_control_frame_with_order(
				&certs.key,
				b"stale-reg",
				registration_request(b"127.0.0.1:65000"),
				stale_ts,
			)
			.await?;

			let response_frame = emit_frame(&mut client, stale).await?;
			let _: RegisterHiveResponse = decode(response_frame.message())?;

			// The same enforcement applies to servlet address updates.
			let update = servlet_address_update(
				b"127.0.0.1:65000",
				vec![servlet_info(&certs, "ping", b"127.0.0.1:65001")],
				vec![],
			);
			let fresh_update = signed_control_frame(&certs, b"replay-update", update).await?;
			let replayed_update = fresh_update.to_owned();

			let response_frame = emit_frame(&mut client, fresh_update).await?;
			let _: ServletAddressUpdateResponse = decode(response_frame.message())?;

			let response_frame = emit_frame(&mut client, replayed_update).await?;
			let _: ServletAddressUpdateResponse = decode(response_frame.message())?;

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterFlippedReplaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// A capture with `s` flipped to `n - s` verifies to the value of its original
// (SEC 1 v2.0 §4.1.4). The replay ledger keys on that value, so the gateway
// refuses the capture as a replay of the spent slot, not a forgery (CWE-294).
tb_scenario! {
	name: cluster_refuses_registration_replayed_with_its_s_flipped,
	spec: ClusterFlippedReplaySpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			let request = registration_request(b"127.0.0.1:65000");
			let fresh = signed_control_frame(&certs, b"flipped-reg", request).await?;
			let flipped = TestFrame::with_flipped_s(&fresh);
			let original = certs.trust.verify_frame(&fresh);
			let twin = certs.trust.verify_frame(&flipped);
			let verified = (original, twin);
			let twin_verifies =
				matches!(verified, (TrustVerification::Verified(_, a), TrustVerification::Verified(_, b)) if a == b);
			assert!(twin_verifies, "the s-flipped capture verifies under the hive trust to the value of its original");

			// The gateway counts the accepted registration as
			// CLUSTER_HIVE_REGISTERED, so its reply needs no record here.
			let accepted_frame = emit_frame(&mut client, fresh).await?;
			decode::<RegisterHiveResponse>(accepted_frame.message())?;

			let response_frame = emit_frame(&mut client, flipped).await?;
			let response: RegisterHiveResponse = decode(response_frame.message())?;
			assert!(response.hive_id.is_none(), "a refused registration assigns no hive id");
			assert_eq!(cluster.hive_count()?, 1, "the replay refusal keeps the one registration");

			cluster.stop();

			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterHeartbeatRejectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_HEARTBEAT_FAILED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_HIVE_EVICTED, exactly!(1), equals!(0u64))
		]
	}
}

// Eviction ordering: the gateway can evict a hive only after it registered,
// and only after it counted the failed heartbeat that reached
// `max_failures`.
tb_process_spec! {
	pub ClusterEvictionProcess,
	events {
		observable {
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_HEARTBEAT_FAILED,
			events::CLUSTER_HIVE_EVICTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_HIVE_REGISTERED => Registered },
		Registered => { events::CLUSTER_HEARTBEAT_FAILED => Failed },
		Failed => { events::CLUSTER_HIVE_EVICTED => Evicted },
		Evicted => { }
	}
	terminal { Evicted }
}

/// Polls until the gateway records an eviction or the attempts run out. The
/// eviction empties the registry, so the wait ends on that decision, and the
/// spec judges the count.
async fn wait_for_eviction(trace: &TraceCollector) {
	let evicted = || trace.recorded(events::CLUSTER_HIVE_EVICTED) >= 1;
	poll_until(50, Duration::from_millis(100), evicted).await;
}

// The hive answers the heartbeat with `PermissionDenied`, so the failure
// carries the status the hive answered, which a transport fault would not.
tb_scenario! {
	name: cluster_evicts_hive_on_rejected_heartbeats,
	config: ScenarioConfig::builder()
		.with_spec(ClusterHeartbeatRejectionSpec::latest())
		.with_csp(ClusterEvictionProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let heartbeat = HeartbeatConfig::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.build();

			let cluster_conf = ClusterConfig::builder(cluster_tls_config(&certs))
				.with_heartbeat_config(heartbeat)
				.build();
			start_cluster(&trace, cluster_conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let certs = certs.as_ref();
			let cluster_addr = cluster.addr();

			// The hive serves the shared certificate (the cluster trusts it
			// for TLS) but configures no trust store for inbound commands.
			let mut hive = ClusterTestHive::new(Some(hive_tls_config_no_trust(certs)))?;
			hive.establish(Arc::new(trace.share())).await?;

			// Register the hive out-of-band with a validly signed frame.
			let hive_addr_bytes = hive
				.addr()
				.ok_or(TightBeamError::NotEstablished)?
				.to_string()
				.into_bytes();
			let registration = signed_control_frame(
				certs,
				b"hb-reject-reg",
				registration_request(&hive_addr_bytes),
			)
			.await?;

			let mut client = connect_cluster(certs, cluster_addr).await?;
			let response_frame = emit_frame(&mut client, registration).await?;
			let response: RegisterHiveResponse = decode(response_frame.message())?;
			assert!(response.hive_id.is_some(), "an accepted registration names the hive");

			// Heartbeats run every 100ms with `max_failures = 1`, so the
			// first PermissionDenied heartbeat must evict the hive.
			wait_for_eviction(&trace).await;

			hive.stop();
			cluster.stop();

			Ok(())
		}
	}
}

// Two hive identities under one gateway prove `ServletAddressUpdate` is
// signer-bound, so one hive cannot tamper with another's routes.
struct DualHiveCerts {
	gateway: ClusterTestCerts,
	hive_a: (Certificate, Secp256k1SigningKey),
	hive_b: (Certificate, Secp256k1SigningKey),
	hive_trust: Arc<dyn CertificateTrust>,
}

fn dual_hive_certs() -> DualHiveCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let gateway = cluster_certs();
	let raw_a = k256::ecdsa::SigningKey::random(&mut OsRng);
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_a = TestCertificate::self_signed(&raw_a);
	let cert_b = TestCertificate::self_signed(&raw_b);
	let key_a = Secp256k1SigningKey::from(raw_a);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let hive_trust: Arc<dyn CertificateTrust> = Arc::new(
		CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation)
			.with_certificate(cert_a.to_owned())
			.expect("hive A trust")
			.with_certificate(cert_b.to_owned())
			.expect("hive B trust")
			.build(),
	);

	DualHiveCerts { gateway, hive_a: (cert_a, key_a), hive_b: (cert_b, key_b), hive_trust }
}

/// Starts a hive whose control plane answers under hive B's identity and
/// admits the gateway's commands, so it answers a heartbeat that reaches it.
async fn start_hive_b(certs: &DualHiveCerts, trace: &TraceCollector) -> Result<ClusterTestHive, TightBeamError> {
	let (cert, key) = &certs.hive_b;
	let spec = CertificateSpec::Built(Box::new(cert.to_owned()));
	let provider = Arc::new(Secp256k1KeyProvider::from(key.to_owned()));
	let hive_tls = HiveTlsConfig::new(spec, provider, PeerAuthentication::Anonymous)?;
	let trust_store = Some(Arc::clone(&certs.gateway.trust));
	let conf = HiveConfig { hive_tls: Some(Arc::new(hive_tls)), trust_store, ..Default::default() };

	let mut hive = ClusterTestHive::new(Some(conf))?;
	hive.establish(Arc::new(trace.share())).await?;
	Ok(hive)
}

/// Registers the control address of `hive` under hive A's signature, so the
/// registration names an identity other than the one that answers there.
async fn register_under_hive_a(
	certs: &DualHiveCerts,
	cluster: &ClusterGateway,
	hive: &ClusterTestHive,
) -> Result<RegisterHiveResponse, TightBeamError> {
	let hive_addr = hive.addr().ok_or(TightBeamError::NotEstablished)?.to_string();
	let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;

	register_signed_hive(&mut client, &certs.hive_a.1, b"reg-b-as-a", hive_addr).await
}

tb_assert_spec! {
	pub ClusterHeartbeatBindingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1))
		]
	}
}

// A heartbeat binds to the identity that signed the hive's registration
// (CWE-346). Hive A registers the address where hive B answers, so the
// heartbeat finds another identity and ends before its command leaves.
tb_scenario! {
	name: cluster_heartbeat_refuses_a_hive_answering_under_another_identity,
	spec: ClusterHeartbeatBindingSpec,
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let tls = cluster_tls_config_with_trust(&certs.gateway, Some(Arc::clone(&certs.hive_trust)));
			start_cluster(&trace, ClusterConfig::new(tls)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let hive = start_hive_b(&certs, &trace).await?;
			let hive_addr = *hive.addr().ok_or(TightBeamError::NotEstablished)?;
			register_under_hive_a(&certs, &cluster, &hive).await?;

			let refused = cluster.send_heartbeat(hive_addr).await;
			let mismatched = matches!(refused, Err(ClusterError::PeerMismatch));
			assert!(mismatched, "the heartbeat refuses a hive that answers under another identity");

			hive.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterHeartbeatUnregisteredSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_DIAL_REFUSED, exactly!(0))
		]
	}
}

// A heartbeat names the hive by its registration, so one to an unregistered
// address refuses before any dial. The registered hive proves the trace
// reaches the gateway, so the dial count of 0 is the gateway's own record.
tb_scenario! {
	name: cluster_heartbeat_refuses_an_address_no_hive_registered,
	spec: ClusterHeartbeatUnregisteredSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		hives: |SetupEnv { trace, context: certs }| vec![start_ping_hive(trace, certs, None)],
		client: |ClusterEnv { cluster, .. }| async move {
			let unregistered = *cluster.addr();

			let refused = cluster.send_heartbeat(unregistered).await;
			let unregistered_refused = matches!(refused, Err(ClusterError::InvalidAddress(_)));
			assert!(unregistered_refused, "a heartbeat to an address no hive registered refuses before any dial");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterHeartbeatBindingEvictionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_HEARTBEAT_FAILED, exactly!(1), equals!(TransitStatus::Unavailable)),
			(events::CLUSTER_DIAL_REFUSED, at_least!(1)),
			(events::CLUSTER_HIVE_EVICTED, exactly!(1), equals!(0u64))
		]
	}
}

// The background beat keeps a hive alive on its own identity's answer alone.
// Hive B admits the heartbeat, but the beat ends each dial before the command
// leaves, so the hive leaves at its first failed beat. The failure carries
// `Unavailable`, the status of a beat that never reached the hive.
tb_scenario! {
	name: cluster_heartbeat_keeps_no_hive_alive_on_another_identity,
	spec: ClusterHeartbeatBindingEvictionSpec,
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let heartbeat = HeartbeatConfig::builder()
				.with_interval(Duration::from_millis(100))
				.with_max_failures(1)
				.build();

			let hive_trust = Some(Arc::clone(&certs.hive_trust));
			let tls = cluster_tls_config_with_trust(&certs.gateway, hive_trust);
			let conf = ClusterConfig::builder(tls).with_heartbeat_config(heartbeat).build();
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let hive = start_hive_b(&certs, &trace).await?;
			register_under_hive_a(&certs, &cluster, &hive).await?;

			wait_for_eviction(&trace).await;

			hive.stop();
			cluster.stop();
			Ok(())
		}
	}
}

/// A gateway whose leases lapse 10 ms after the last live beat, on a clock
/// only the test moves. No count of failed beats evicts a hive, so a lease
/// alone retires one.
fn lease_sweep_conf(certs: &ClusterTestCerts, clock: &Arc<ManualClock>) -> ClusterConfig {
	let heartbeat = HeartbeatConfig::builder()
		.with_interval(Duration::from_millis(100))
		.with_timeout(Duration::from_millis(10))
		.with_max_failures(u32::MAX)
		.build();
	let clock = Arc::clone(clock) as Arc<dyn Clock>;

	ClusterConfig::builder(cluster_tls_config(certs))
		.with_heartbeat_config(heartbeat)
		.with_clock(clock)
		.build()
}

// One lease sweep retires two hives whose leases lapsed together. Each
// eviction names the count of hives that its own retire left, so the two
// counts step down to 0.
#[tokio::test]
async fn a_lease_sweep_names_the_count_each_retire_leaves() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let clock = Arc::new(ManualClock::default());
	let trace = TraceCollector::default();
	let cluster = start_cluster(&trace, lease_sweep_conf(&certs, &clock)).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;
	register_signed_hive(&mut client, &certs.key, b"lease-a", b"127.0.0.1:1").await?;
	register_signed_hive(&mut client, &certs.key, b"lease-b", b"127.0.0.1:2").await?;

	clock.advance(Duration::from_millis(100));
	poll_until(50, Duration::from_millis(100), || {
		trace.recorded(events::CLUSTER_HIVE_EVICTED) >= 2
	})
	.await;
	cluster.stop();

	let evicted = recorded_values(&trace, events::CLUSTER_HIVE_EVICTED);
	assert_eq!(evicted, [Some(AssertionValue::U64(1)), Some(AssertionValue::U64(0))]);
	Ok(())
}

/// A gateway that dials at most `max_concurrent` hives at once in each beat,
/// beats every 100 ms, and evicts a hive at its first failed beat.
fn capped_beat_conf(certs: &ClusterTestCerts, max_concurrent: NonZeroUsize) -> ClusterConfig {
	let heartbeat = HeartbeatConfig::builder()
		.with_interval(Duration::from_millis(100))
		.with_max_failures(1)
		.with_max_concurrent(max_concurrent)
		.build();

	ClusterConfig::builder(cluster_tls_config(certs))
		.with_heartbeat_config(heartbeat)
		.build()
}

/// The count of the hives that a gateway under a beat capped at one dial
/// evicts within 5 s, from two hives at addresses where no party answers.
async fn evictions_of_a_beat_capped_at_one_dial() -> Result<usize, TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::default();
	let cluster = start_cluster(&trace, capped_beat_conf(&certs, NonZeroUsize::MIN)).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;
	register_signed_hive(&mut client, &certs.key, b"capped-a", b"127.0.0.1:1").await?;
	register_signed_hive(&mut client, &certs.key, b"capped-b", b"127.0.0.1:2").await?;

	poll_until(50, Duration::from_millis(100), || {
		trace.recorded(events::CLUSTER_HIVE_EVICTED) >= 2
	})
	.await;
	cluster.stop();

	Ok(trace.recorded(events::CLUSTER_HIVE_EVICTED))
}

// A beat that dials one hive at a time reaches every hive of its cycle. No
// party answers at either registered address, so each hive leaves at its
// first beat (CWE-835).
//
// The gateway runs on a runtime of its own, with two workers, which the test
// shuts down in the background. A beat that spins with no yield holds one
// worker alone, so the poll fails at its own deadline and the run goes on.
#[test]
fn a_beat_capped_at_one_dial_reaches_every_hive() -> Result<(), TightBeamError> {
	let mut builder = tokio::runtime::Builder::new_multi_thread();
	let runtime = builder.worker_threads(2).enable_all().build()?;
	let evicted = runtime.block_on(evictions_of_a_beat_capped_at_one_dial());

	runtime.shutdown_background();

	assert_eq!(evicted?, 2);
	Ok(())
}

// An admitted registration names the signer whose signature the gateway
// verified, so the audit trail answers who registered the hive (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn an_admitted_registration_names_its_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;

	register_signed_hive(&mut client, &certs.key, b"named-reg", b"127.0.0.1:65210").await?;
	cluster.stop();

	let principals = payload_digests(&trace, events::CLUSTER_HIVE_REGISTERED);
	assert_eq!(principals, [Some(signer_digest(&certs.cert))]);
	Ok(())
}

// An admitted address update names the signer whose signature the gateway
// verified, so the audit trail answers who moved a servlet route (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn an_admitted_update_names_its_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;

	register_signed_hive(&mut client, &certs.key, b"update-reg", b"127.0.0.1:65211").await?;

	let added = servlet_info(&certs, "ping", b"127.0.0.1:65212");
	let update = servlet_address_update(b"127.0.0.1:65211", vec![added], vec![]);

	emit_servlet_update(&mut client, &certs.key, b"named-update", update).await?;
	cluster.stop();

	let principals = payload_digests(&trace, events::CLUSTER_UPDATE_ACCEPTED);
	assert_eq!(principals, [Some(signer_digest(&certs.cert))]);
	Ok(())
}

// A registration that the gateway refuses after the signature verifies names
// its signer, so the audit trail answers who sent it (CWE-778). Its hive
// address is not UTF-8, so the gateway refuses it as `PermissionDenied`.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_refused_registration_names_its_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;

	register_signed_hive(&mut client, &certs.key, b"named-refusal", [0xff, 0xfe, 0xfd]).await?;
	cluster.stop();

	let principals = payload_digests(&trace, events::CLUSTER_REGISTER_REFUSED);
	assert_eq!(principals, [Some(signer_digest(&certs.cert))]);
	Ok(())
}

// An address update that the gateway refuses after the signature verifies
// names its signer (CWE-778). It removes a bare servlet type where an
// instance belongs, so the gateway refuses it as `PermissionDenied`.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_refused_update_names_its_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;
	let update = servlet_address_update(b"127.0.0.1:65214", vec![], vec![servlet_urn("ping")]);

	emit_servlet_update(&mut client, &certs.key, b"named-update-refusal", update).await?;
	cluster.stop();

	let principals = payload_digests(&trace, events::CLUSTER_UPDATE_REFUSED);
	assert_eq!(principals, [Some(signer_digest(&certs.cert))]);
	Ok(())
}

// A replayed registration names the signer whose signature the gateway
// verified before its freshness gate refused the replay (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_replayed_registration_names_its_signer() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = payload_trace();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;
	let fresh = signed_control_frame(&certs, b"named-replay", registration_request(b"127.0.0.1:65215")).await?;

	emit_frame(&mut client, fresh.to_owned()).await?;
	emit_frame(&mut client, fresh).await?;
	cluster.stop();

	let principals = payload_digests(&trace, events::CLUSTER_REGISTER_REFUSED);
	assert_eq!(principals, [Some(signer_digest(&certs.cert))]);
	Ok(())
}

tb_assert_spec! {
	pub ClusterCrossHiveUpdateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2)),
			(events::CLUSTER_REGISTER_REFUSED, absent!()),
			(events::CLUSTER_UPDATE_REFUSED, exactly!(1)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

// Tamper ordering: the gateway refuses the cross-hive poison update before the
// owner's update lands. A count cannot prove that the refusal hit the poison
// rather than the owner's own update.
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let cluster_addr = cluster.addr();
			let mut client = connect_cluster(&certs.gateway, cluster_addr).await?;

			let hive_a_addr = b"127.0.0.1:65010".as_slice();
			let hive_b_addr = b"127.0.0.1:65011".as_slice();

			register_signed_hive(&mut client, &certs.hive_a.1, b"reg-a", hive_a_addr).await?;
			register_signed_hive(&mut client, &certs.hive_b.1, b"reg-b", hive_b_addr).await?;
			assert_eq!(cluster.hive_count()?, 2, "both hives register");

			// The process pins the order: hive B's update of hive A's routes
			// refuses, and then the owner's own update lands.
			let poison = vec![servlet_info(&certs.gateway, "poison", b"127.0.0.1:65099")];
			let cross_update = servlet_address_update(hive_a_addr, poison, vec![]);
			emit_servlet_update(&mut client, &certs.hive_b.1, b"cross-update", cross_update).await?;

			let owned = vec![servlet_info(&certs.gateway, "ping", b"127.0.0.1:65012")];
			let owner_update = servlet_address_update(hive_a_addr, owned, vec![]);
			emit_servlet_update(&mut client, &certs.hive_a.1, b"owner-update", owner_update).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterServletTakeoverSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

// A second hive that registers a servlet address the first hive serves meets
// a whole refusal, so the first keeps its route (CWE-639). Only the route's
// owner may remove it, so the accepted removal proves the first hive kept it.
tb_scenario! {
	name: cluster_rejects_a_registration_that_takes_another_hives_servlet,
	spec: ClusterServletTakeoverSpec,
	environment Cluster {
		context: dual_hive_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config_with_trust(
				&certs.gateway,
				Some(Arc::clone(&certs.hive_trust)),
			)))
			.await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;
			let servlet_addr = b"127.0.0.1:65020".as_slice();

			let owner = [servlet_info(&certs.gateway, "calc", servlet_addr)];
			register_signed_hive_serving(&mut client, &certs.hive_a.1, b"reg-a", b"127.0.0.1:65021", owner).await?;

			let takeover = [servlet_info(&certs.gateway, "calc", servlet_addr)];
			register_signed_hive_serving(&mut client, &certs.hive_b.1, b"reg-b", b"127.0.0.1:65022", takeover).await?;
			assert_eq!(cluster.hive_count()?, 1, "a refused takeover installs no second hive");

			let owned_instance = servlet_info(&certs.gateway, "calc", servlet_addr).servlet_id;
			let removal = servlet_address_update(b"127.0.0.1:65021", vec![], vec![owned_instance]);
			emit_servlet_update(&mut client, &certs.hive_a.1, b"owner-removes", removal).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterRegistrationHijackSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1))
		]
	}
}

tb_process_spec! {
	// Hijack ordering: the owner registers first, the gateway refuses the
	// hijacker's registration, and only then does the owner's update land.
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
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs.gateway, cluster.addr()).await?;
			let hive_a_addr = b"127.0.0.1:65020".as_slice();

			register_signed_hive(&mut client, &certs.hive_a.1, b"owner-reg", hive_a_addr).await?;
			register_signed_hive(&mut client, &certs.hive_b.1, b"hijack-reg", hive_a_addr).await?;

			// After the refused hijack, the registry holds the owner alone,
			// because the failed takeover must not disturb the binding.
			assert_eq!(cluster.hive_count()?, 1, "a refused hijack keeps the owner alone");

			// The owner's update lands afterward, so the failed hijack left
			// the signer binding intact.
			emit_servlet_update(
				&mut client,
				&certs.hive_a.1,
				b"owner-still-bound",
				servlet_address_update(hive_a_addr, vec![servlet_info(&certs.gateway, "ping", b"127.0.0.1:65021")], vec![]),
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
	// follows the accepted removal. A count cannot tell "routed then
	// removed" from "removed then routed".
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
// the type routed before the removal and is Unavailable after. The
// gateway refuses the whole of a removal that names a foreign realm.
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
			let config = servlet_tls_config(&certs)?;
			let servlet = ClusterTestServlet::start(trace, config).await?;
			let servlet_addr = servlet.addr().to_string();
			let hive_addr = b"127.0.0.1:65200".as_slice();

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			register_signed_hive(&mut client, &certs.key, b"removal-reg", hive_addr).await?;

			let added = vec![servlet_info(&certs, "ping", servlet_addr.as_bytes())];
			let request = servlet_address_update(hive_addr, added, vec![]);
			emit_servlet_update(&mut client, &certs.key, b"removal-add", request).await?;

			emit_ping_work(&mut client, &certs.key, b"pre-removal-work").await?;

			let removed = vec![foreign_realm_instance(&servlet_addr)];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-foreign", request).await?;

			let removed = vec![servlet_urn("ping").servlet_instance(&servlet_addr).expect("a servlet type URN yields an instance URN")];
			let request = servlet_address_update(hive_addr, vec![], removed);
			emit_servlet_update(&mut client, &certs.key, b"removal-remove", request).await?;

			// The removed instance has stopped routing, so the submission must
			// resolve to a refusal.
			let refused_work = emit_ping_work(&mut client, &certs.key, b"post-removal-work").await;
			work_refusal_status(refused_work)?;

			servlet.stop();
			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterUndialableHiveSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_REGISTER_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// The gateway refuses a hive whose control address the heartbeat cannot
// dial, because an admitted one would expire at the lease timeout with no
// refusal to show for it.
tb_scenario! {
	name: cluster_refuses_a_hive_whose_control_address_the_protocol_cannot_dial,
	spec: ClusterUndialableHiveSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			register_signed_hive(&mut client, &certs.key, b"reg-undialable", b"hive.example:9000").await?;
			assert_eq!(cluster.hive_count()?, 0, "an undialable hive registers no entry");

			cluster.stop();
			Ok(())
		}
	}
}

/// The session events that a hive's own trace records as it registers with a
/// gateway. The gateway's heartbeat waits an hour, so no gateway dials the
/// hive, and the hive's trace holds the session of its own dial alone.
#[cfg(feature = "instrument")]
async fn hive_registration_sessions() -> Result<Vec<Urn<'static>>, TightBeamError> {
	let certs = Arc::new(cluster_certs());
	let mut conf = routing_cluster_conf(&certs, None);
	conf.heartbeat.interval = Duration::from_secs(3_600);
	let cluster = start_cluster(&TraceCollector::new(), conf).await?;
	let hive_trace = TraceCollector::new();
	let hive = start_ping_hive(hive_trace.share(), certs, None).await?;

	hive.register_with_cluster(cluster.addr()).await?;
	hive.stop();
	cluster.stop();

	Ok(TestTrace::trail(&hive_trace, &[events::SESSION_HANDSHAKE_COMPLETE]))
}

/// A hive records the session of each dial to a gateway on its own trace.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_hive_records_its_cluster_dials_on_its_own_trace() -> Result<(), TightBeamError> {
	assert_eq!(hive_registration_sessions().await?, [events::SESSION_HANDSHAKE_COMPLETE]);
	Ok(())
}

/// The audit records of the colony events that a gateway's own trace files as
/// one hive registers with it. The gateway's heartbeat waits an hour, so the
/// registration is the one colony decision on the trace.
#[cfg(feature = "instrument")]
async fn gateway_registration_records() -> Result<Vec<Urn<'static>>, TightBeamError> {
	let certs = Arc::new(cluster_certs());
	let mut conf = routing_cluster_conf(&certs, None);
	conf.heartbeat.interval = Duration::from_secs(3_600);
	let gateway_trace = TraceCollector::new();
	let cluster = start_cluster(&gateway_trace, conf).await?;
	let hive = start_ping_hive(TraceCollector::new(), certs, None).await?;

	hive.register_with_cluster(cluster.addr()).await?;
	hive.stop();
	cluster.stop();

	Ok(TestTrace::trail(&gateway_trace, &[events::CLUSTER_HIVE_REGISTERED]))
}

/// A gateway files a registration in its audit sink under the URN of the
/// event, not as a test assertion.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_gateway_files_a_registration_under_the_urn_of_its_event() -> Result<(), TightBeamError> {
	assert_eq!(gateway_registration_records().await?, [events::CLUSTER_HIVE_REGISTERED]);
	Ok(())
}

/// The count of strangers that fail the handshake of a gateway's colony
/// plane, and the bound of the gateway's trace, in the test of that bound.
#[cfg(feature = "instrument")]
const REFUSED_STRANGERS: usize = 4;

/// Dials `gateway` as `stranger`, whose certificate the client validator of
/// the gateway leaves out, and sends one frame. The client trusts the
/// certificate of `certs`, which the gateway presents.
#[cfg(feature = "instrument")]
async fn dial_as_stranger(
	certs: &ClusterTestCerts,
	stranger: &ClusterTestCerts,
	gateway: &ClusterGateway,
) -> Result<Frame, TightBeamError> {
	let identity = signing_identity(stranger.cert.to_owned(), stranger.key.to_owned());
	let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::clone(&certs.trust));
	let client = builder.with_client_identity(identity).build();
	let mut client = client.connect(gateway.addr().to_owned()).await?;

	emit_frame(&mut client, TestFrame::v0(Some("stranger"), None)).await
}

/// What a gateway records after [`REFUSED_STRANGERS`] strangers fail the
/// handshake of its colony plane, then one event of its own: its own events in
/// its trace, that trace's overflow latch, and the refused certificates on its
/// connection trace. Each trace holds [`REFUSED_STRANGERS`] events.
#[cfg(feature = "instrument")]
async fn gateway_traces_after_refused_strangers() -> Result<(Vec<Urn<'static>>, bool, usize), TightBeamError> {
	use tightbeam::instrumentation::TbInstrumentationConfig;
	use tightbeam::trace::TraceConfig;

	let config = TbInstrumentationConfig { max_events: REFUSED_STRANGERS as u32, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let certs = cluster_certs();
	let stranger = cluster_certs();
	let mut tls = cluster_tls_config(&certs);
	tls.client_authentication = PeerAuthentication::Anonymous.and(combined_validator(&[&certs.cert]));
	let mut conf = ClusterConfig::new(tls);
	conf.heartbeat.interval = Duration::from_secs(3_600);
	let gateway = start_cluster(&trace, conf).await?;
	let connections = gateway.connection_trace();
	// The start records into the trace, so a drain gives every slot to the
	// strangers. A drain keeps the latch.
	let _started = trace.drain_events();

	for _ in 0..REFUSED_STRANGERS {
		// The gateway refuses the certificate of the stranger, so the frame
		// fails, and the test reads the refusal from the trace instead.
		let _refused = dial_as_stranger(&certs, &stranger, &gateway).await;
	}

	// A wait that runs out leaves the connection trace short of the
	// strangers, which the count of refused certificates then shows.
	let refused = || connections.recorded(events::SESSION_CERT_REJECTED) >= REFUSED_STRANGERS;
	poll_until(50, Duration::from_millis(100), refused).await;
	trace.emit_event(events::CLUSTER_HIVE_EVICTED)?;
	gateway.stop();

	let kept = TestTrace::trail(&trace, &[events::CLUSTER_HIVE_EVICTED]);
	Ok((kept, trace.overflowed(), connections.recorded(events::SESSION_CERT_REJECTED)))
}

/// Strangers that never authenticate record on a gateway's connection trace,
/// so the gateway's own bounded trace keeps its next event and sets no
/// overflow latch.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn refused_strangers_leave_the_trace_of_a_gateway_to_its_own_events() -> Result<(), TightBeamError> {
	let recorded = gateway_traces_after_refused_strangers().await?;
	assert_eq!(recorded, (vec![events::CLUSTER_HIVE_EVICTED], false, REFUSED_STRANGERS));
	Ok(())
}

/// The count of work requests that a client with no certificate sends, and the
/// bound of the gateway's trace, in the test of that bound.
#[cfg(feature = "instrument")]
const ANONYMOUS_REQUESTS: usize = 4;

/// What a gateway keeps after [`ANONYMOUS_REQUESTS`] anonymous work requests
/// for a type no hive serves, then one event of its own: its own events in the
/// sink of its trace, the overflow latch, and the refused requests.
#[cfg(feature = "instrument")]
async fn gateway_traces_after_anonymous_work() -> Result<(Vec<Urn<'static>>, bool, usize), TightBeamError> {
	use tightbeam::instrumentation::TbInstrumentationConfig;
	use tightbeam::trace::TraceConfig;

	let config = TbInstrumentationConfig { max_events: ANONYMOUS_REQUESTS as u32, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let certs = cluster_certs();
	let mut conf = ClusterConfig::new(cluster_tls_config(&certs));
	conf.heartbeat.interval = Duration::from_secs(3_600);
	let gateway = start_cluster(&trace, conf).await?;
	let connections = gateway.connection_trace();
	// The start records into the trace, so a drain gives every slot to the
	// requests. A drain keeps the latch.
	let _started = trace.drain_events();

	let mut client = connect_cluster(&certs, gateway.addr()).await?;
	let work = TestFrame::v0(Some("anonymous"), Some("work"));
	for _ in 0..ANONYMOUS_REQUESTS {
		// No hive serves the type, so the gateway refuses each request.
		let _refused = client.submit_work_to(servlet_urn("nobody"), &work).await;
	}

	trace.emit_event(events::CLUSTER_HIVE_EVICTED)?;
	gateway.stop();

	let kept = TestTrace::trail(&trace, &[events::CLUSTER_HIVE_EVICTED]);
	Ok((kept, trace.overflowed(), connections.recorded(events::CLUSTER_WORK_UNAVAILABLE)))
}

/// Anonymous work leaves the bounded trace of a gateway to its own events.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn anonymous_work_leaves_the_trace_of_a_gateway_to_its_own_events() -> Result<(), TightBeamError> {
	let recorded = gateway_traces_after_anonymous_work().await?;
	assert_eq!(recorded, (vec![events::CLUSTER_HIVE_EVICTED], false, ANONYMOUS_REQUESTS));
	Ok(())
}

/// The records of one work request for a type no hive serves, from a client
/// whose certificate the gateway validates: the count in the sink of the
/// gateway's trace, then the count in the sink of its connection trace.
#[cfg(feature = "instrument")]
async fn records_of_certified_work() -> Result<(usize, usize), TightBeamError> {
	let trace = TraceCollector::new();
	let certs = cluster_certs();
	let mut tls = cluster_tls_config(&certs);
	tls.client_authentication = PeerAuthentication::Anonymous.and(combined_validator(&[&certs.cert]));

	let gateway = start_cluster(&trace, ClusterConfig::new(tls)).await?;
	let connections = gateway.connection_trace();
	let identity = signing_identity(certs.cert.to_owned(), certs.key.to_owned());
	let builder = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::clone(&certs.trust));
	let client = builder.with_client_identity(identity).build();
	let mut client = client.connect(gateway.addr().to_owned()).await?;

	let work = TestFrame::v0(Some("certified"), Some("work"));
	let _refused = client.submit_work_to(servlet_urn("nobody"), &work).await;
	gateway.stop();

	let unavailable = [events::CLUSTER_WORK_UNAVAILABLE];
	let audited = TestTrace::trail(&trace, &unavailable).len();
	let connected = TestTrace::trail(&connections, &unavailable).len();
	Ok((audited, connected))
}

/// Work from a certified client records on the trace of the gateway.
#[cfg(feature = "instrument")]
#[tokio::test]
async fn certified_work_records_on_the_trace_of_a_gateway() -> Result<(), TightBeamError> {
	assert_eq!(records_of_certified_work().await?, (1, 0));
	Ok(())
}

/// A sink that forwards each event, and names itself for each trace that
/// splits from its own.
#[cfg(feature = "instrument")]
#[derive(Clone, Default)]
struct Forwarded(Arc<Mutex<Vec<Urn<'static>>>>);

#[cfg(feature = "instrument")]
impl Forwarded {
	/// The count of the forwarded events that record `event`.
	fn count(&self, event: Urn<'static>) -> usize {
		let seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		seen.iter().filter(|urn| **urn == event).count()
	}
}

#[cfg(feature = "instrument")]
impl tightbeam::instrumentation::EventSink for Forwarded {
	fn emit(&self, event: tightbeam::instrumentation::TbEvent) {
		let mut seen = self.0.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
		seen.push(event.urn);
	}

	fn drain(&self) -> Vec<tightbeam::instrumentation::TbEvent> {
		Vec::new()
	}

	fn overflowed(&self) -> bool {
		false
	}

	fn sibling(&self) -> Option<Arc<dyn tightbeam::instrumentation::EventSink>> {
		Some(Arc::new(self.clone()))
	}
}

/// The refused certificates that reach the sink of a gateway's trace after
/// [`REFUSED_STRANGERS`] strangers fail the handshake of its colony plane.
#[cfg(feature = "instrument")]
async fn forwarded_refusals_of_strangers() -> Result<usize, TightBeamError> {
	use tightbeam::trace::TraceConfig;

	let forwarded = Forwarded::default();
	let config = TraceConfig::default().with_sink(forwarded.clone());
	let trace = TraceCollector::from(config);
	let certs = cluster_certs();
	let stranger = cluster_certs();
	let mut tls = cluster_tls_config(&certs);
	tls.client_authentication = PeerAuthentication::Anonymous.and(combined_validator(&[&certs.cert]));

	let gateway = start_cluster(&trace, ClusterConfig::new(tls)).await?;
	let connections = gateway.connection_trace();

	for _ in 0..REFUSED_STRANGERS {
		// The gateway refuses the certificate of the stranger, so the frame
		// fails, and the test reads the refusal from the sink instead.
		let _refused = dial_as_stranger(&certs, &stranger, &gateway).await;
	}

	let refused = || connections.recorded(events::SESSION_CERT_REJECTED) >= REFUSED_STRANGERS;
	poll_until(50, Duration::from_millis(100), refused).await;
	gateway.stop();

	Ok(forwarded.count(events::SESSION_CERT_REJECTED))
}

/// A refused handshake reaches the sink of a gateway's trace (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn a_refused_handshake_reaches_the_sink_of_the_trace_of_a_gateway() -> Result<(), TightBeamError> {
	assert_eq!(forwarded_refusals_of_strangers().await?, REFUSED_STRANGERS);
	Ok(())
}

// A drain announces the emptied slate to each gateway, and records the answer
// of each one, so a gateway that refuses it leaves a record (CWE-778). The
// gateway's hive trust turns to a store that holds a stranger alone, so it
// refuses the drain's registration.
#[tokio::test]
async fn a_drain_whose_gateway_refuses_the_emptied_slate_records_it() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let switch = SwitchTrust::new(Arc::clone(&certs.trust), stranger_gateway_certs().trust);
	let hive_trust: Arc<dyn CertificateTrust> = switch.clone();
	let gateway_conf = ClusterConfig::new(cluster_tls_config_with_trust(&certs, Some(hive_trust)));
	let cluster = start_cluster(&TraceCollector::new(), gateway_conf).await?;

	let trace = TraceCollector::new();
	let mut hive_conf = hive_tls_config(&certs);
	hive_conf.control.reregister_interval = None;
	let mut hive = ClusterTestHive::new(Some(hive_conf))?;
	hive.establish(Arc::new(trace.share())).await?;
	hive.register_with_cluster(cluster.addr()).await?;

	switch.switch();
	hive.drain().await?;
	hive.stop();
	cluster.stop();

	let answers = recorded_values(&trace, events::HIVE_REREGISTERED);
	assert_eq!(answers, [Some(AssertionValue::TransitStatus(TransitStatus::PermissionDenied))]);
	Ok(())
}

/// The drain timeout of the hive whose servlet never ends its drain, on the
/// hive's manual clock. The gateway reads the system clock, so a short timeout
/// keeps the hive's signed slate inside the freshness window of the gateway.
const STALLED_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// A [`ServletBox`] whose drain never ends. Its drain wakes `entered` once the
/// hive calls it.
struct StalledDrain {
	entered: Arc<Notify>,
}

impl ServletBox for StalledDrain {
	fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::from(b"127.0.0.1:7090".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {}

	fn drain_boxed(self: Box<Self>) -> ServletDrainFuture {
		Box::pin(async move {
			self.entered.notify_one();
			core::future::pending::<Result<(), TightBeamError>>().await
		})
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}
}

// A drain past its timeout still announces the emptied slate, so each gateway
// retires the routes of the hive at once. The one servlet of the hive never
// ends its drain, and the hive clock moves past the timeout once that drain
// begins.
#[tokio::test]
async fn a_drain_past_its_timeout_still_announces_the_emptied_slate() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let cluster = start_cluster(&TraceCollector::new(), ClusterConfig::new(cluster_tls_config(&certs))).await?;

	let trace = TraceCollector::new();
	let clock = Arc::new(ManualClock::default());
	let entered = Arc::new(Notify::new());
	let mut hive_conf = hive_tls_config(&certs);
	hive_conf.clock = Arc::clone(&clock) as Arc<dyn Clock>;
	hive_conf.control.drain_timeout = STALLED_DRAIN_TIMEOUT;
	let mut hive = ClusterTestHive::new(Some(hive_conf))?;
	let servlet = StalledDrain { entered: Arc::clone(&entered) };
	let spawner = |_| async { Ok(StalledDrain { entered: Arc::default() }) };
	hive.register(servlet_urn("stalled"), servlet, spawner)?;
	hive.establish(Arc::new(trace.share())).await?;
	hive.register_with_cluster(cluster.addr()).await?;

	let expire = async {
		entered.notified().await;
		clock.advance(STALLED_DRAIN_TIMEOUT);
	};
	let (drained, ()) = tokio::join!(hive.drain(), expire);
	hive.stop();
	cluster.stop();

	let expired = matches!(
		drained,
		Err(TightBeamError::TransportError(TransportError::OperationFailed(
			TransportFailure::DeadlineExceeded
		)))
	);
	let answers = recorded_values(&trace, events::HIVE_REREGISTERED);
	let announced = (true, vec![Some(AssertionValue::TransitStatus(TransitStatus::Ok))]);
	assert_eq!((expired, answers), announced);
	Ok(())
}

// An address update that names a hive outside the namespace refuses with its
// cause in the label, so the trail tells a foreign identity from a refused
// route (CWE-778).
#[cfg(feature = "instrument")]
#[tokio::test]
async fn an_address_update_outside_the_namespace_refuses_with_its_cause() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let trace = TraceCollector::new();
	let cluster = start_cluster(&trace, ClusterConfig::new(cluster_tls_config(&certs))).await?;
	let mut client = connect_cluster(&certs, cluster.addr()).await?;
	let hive_id = ColonyNamespace::new("tightbeam", "elsewhere")?.hive("127.0.0.1:65216")?;
	let update = ServletAddressUpdate { hive_id, added: Vec::new(), removed: Vec::new() };

	let request = ClusterRequest::ServletAddressUpdate(update);
	emit_servlet_update(&mut client, &certs.key, b"foreign-update", request).await?;
	cluster.stop();

	let labels = recorded_labels(&trace, events::CLUSTER_UPDATE_REFUSED);
	assert_eq!(labels, [Some(String::from("PermissionDenied/invalid-urn"))]);
	Ok(())
}

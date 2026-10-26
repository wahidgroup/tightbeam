//! The tests of registration, control-plane refusal, and the hive lifecycle.

use super::common::*;
use tightbeam::colony::cluster::ClusterHeartbeat;
use tightbeam::crypto::x509::store::TrustVerification;
#[cfg(feature = "instrument")]
use tightbeam::testing::fixtures::TestTrace;
use tightbeam::testing::TestFrame;
use tightbeam::trace::{AssertionLabel, AssertionValue, IntoEventLabel};

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

/// Records the teardown call and serves no traffic, because `stop_boxed` is
/// the observable under test.
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
		CertificateTrustBuilder::from(Secp256k1Policy::default())
			.with_certificate(hive_cert.to_owned())
			.expect("the hive certificate builds a trust store")
			.build(),
	);
	let hive_tls = HiveTlsConfig::new(
		CertificateSpec::Built(Box::new(hive_cert)),
		Arc::new(Secp256k1KeyProvider::from(hive_key)),
		vec![],
	)
	.expect("the hive TLS material must decode");

	(Arc::new(hive_tls), admits_hive)
}

// A refused RegisterHiveResponse must not enqueue the gateway: the
// anti-entropy beat would otherwise keep calling a peer that already
// rejected the hive, and scaling updates would fan out there too.
//
// The beat that does run proves the claim:
//
// - A second gateway admits the hive, and the hive's beat re-registers with the gateways it queued.
// - The hive records each re-registration with the status of the gateway's
//   answer, so the one `Ok` is the beat's footprint.
// - The hive dials queued gateways in the order it queued them, so a
//   refusing gateway that it wrongly queued would refuse again, and both the
//   refusal count and the re-registration count pin that.
// - The hive and the accepting gateway read the one clock the test advances,
//   so the beat fires when the test says and the frames they sign for each
//   other stay fresh.
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

			// A clean registration lands, then a mismatched add must refuse.
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

// A capture with `s` flipped to `n - s` verifies under the hive trust the
// gateway holds (SEC 1 v2.0 §4.1.4), to the value of its original. The replay
// ledger keys on the canonical signature, so the rewritten capture finds the
// slot its original spent (CWE-294), and the gateway refuses it as a replay and
// not as a forgery.
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

/// Polls until the gateway records an eviction or the attempts run out.
///
/// The eviction is the decision that empties the registry, so the wait
/// ends on the decision itself, and the spec judges the count.
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
		CertificateTrustBuilder::from(Secp256k1Policy::default())
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
	let hive_tls = HiveTlsConfig::new(spec, Arc::new(Secp256k1KeyProvider::from(key.to_owned())), vec![])?;
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

// A heartbeat is bound to the identity that signed the hive's registration
// (CWE-346). Hive A registers the control address where hive B answers, so
// the heartbeat finds another identity there and ends before its command
// leaves.
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

// A heartbeat names the hive by its registration, so the gateway refuses a
// heartbeat to an address with no registration before any dial. A registered
// hive proves that the trace reaches the gateway, so the dial count of 0 reads
// the gateway's own record.
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
// Hive B admits the gateway's heartbeat, and the beat ends each dial to it
// before the command leaves, so the hive leaves at its first failed beat. The
// failure carries `Unavailable`, the status of a beat that never reached the
// hive, where an answered rejection would carry the hive's own status.
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

/// Drains the assertions of `trace`, and returns the value of each one that
/// records `event`, in the order the trace recorded them.
fn recorded_values(trace: &TraceCollector, event: Urn<'static>) -> Vec<Option<AssertionValue>> {
	let label = AssertionLabel::Custom(event.into_label());
	let drained = trace.drain_assertions().into_iter();

	drained
		.filter(|recorded| recorded.label == label)
		.map(|recorded| recorded.value)
		.collect()
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

// A second hive that registers a servlet address the first hive already
// serves meets a whole refusal, so the first hive keeps its route (CWE-639).
// The first hive then removes that address under its own signature, which
// only the route's owner may do, so the accepted removal is the proof it
// kept the route.
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

// A gateway that admitted a hive the heartbeat cannot dial would leave it to
// expire at the lease timeout with no refusal to show for it.
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

//! The peer federation tests of the advertisement control plane.

use std::net::{Ipv4Addr, TcpListener};

use super::common::*;
use tightbeam::colony::cluster::ClusterConfigBuilder;
use tightbeam::transport::Protocol;

tb_assert_spec! {
	pub ClusterPeerAdvertisedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1))
		]
	},
	// Version 1.1.0 adds the refusal event to the contract, so a scenario that
	// accepts proves that the gateway refused nothing.
	V(1,1,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!())
		]
	}
}

tb_assert_spec! {
	pub ClusterPeerRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1))
		]
	},
	// Version 1.1.0 pins the status that the peer receives.
	V(1,1,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied))
		]
	}
}

// The gateway refuses a claimed dial outside the optional allowlist before it
// installs a route.
tb_scenario! {
	name: cluster_refuses_peer_dial_outside_allowlist,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![String::from("10.0.0.1:9000")])).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "a refused advertisement installs no peer route");

			cluster.stop();
			Ok(())
		}
	}
}

// A dial on the allowlist installs its peer route.
tb_scenario! {
	name: cluster_accepts_peer_dial_on_allowlist,
	spec: ClusterPeerAdvertisedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let allowed = String::from_utf8_lossy(PEER_GATEWAY_ADDR).into_owned();
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![allowed])).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "one advertised type installs one peer route");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerRouteIntrospectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!())
		]
	}
}

// A trusted peer advertisement installs peer routes: the advertised type
// surfaces in `peer_servlets` (learned), never in `available_servlets`
// (local hives only). This scenario stops at the install, before any forward.
tb_scenario! {
	name: cluster_accepts_peer_advertisement,
	spec: ClusterPeerRouteIntrospectionSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			assert_eq!(cluster.peer_servlets()?.len(), 1, "one advertised type installs one peer route");
			assert!(cluster.available_servlets()?.is_empty(), "a peer route never lists as a local servlet");

			// Exactly one learned route is keyed by the advertised type, and
			// it exposes the claimed dial path and the signer fingerprint.
			let ping_canonical = servlet_urn("ping").type_canonical_bytes();
			let routes = cluster.peer_routes()?;
			let exposed = routes.len() == 1
				&& routes.first().is_some_and(|route| {
					let servlet_type: &[u8] = route.servlet_type.as_ref();
					let dial_addr: &[u8] = route.dial_addr.as_ref();
					servlet_type == ping_canonical.as_slice() && dial_addr == PEER_GATEWAY_ADDR && !route.peer_id.is_empty()
				});

			assert!(
				exposed,
				"the learned route exposes the advertised type, the claimed dial path, and the signer fingerprint"
			);

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerMultiTypeSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!())
		]
	}
}

// Every advertised type in a slate installs its own peer route, so a
// two-type advertisement surfaces both types.
tb_scenario! {
	name: cluster_multi_type_advertisement_installs_all,
	spec: ClusterPeerMultiTypeSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let slate = vec![servlet_urn("ping"), servlet_urn("echo")];
			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, slate).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut peers = cluster.peer_servlets()?;
			peers.sort_unstable();

			let mut expected: Vec<std::sync::Arc<[u8]>> = vec![
				std::sync::Arc::from(servlet_urn("ping").type_canonical_bytes()),
				std::sync::Arc::from(servlet_urn("echo").type_canonical_bytes()),
			];
			expected.sort_unstable();

			assert_eq!(peers, expected, "a two-type slate installs a route for each type");

			cluster.stop();
			Ok(())
		}
	}
}

/// The receiver identity plus a second, independently trusted peer signer.
struct PeerPairCerts {
	gateway: GatewayCerts,
	peer_b: (Certificate, Secp256k1SigningKey),
	peer_trust: Arc<dyn CertificateTrust>,
}

fn peer_pair_certs() -> PeerPairCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let gateway = cluster_certs();
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_b = TestCertificate::with_uri_sans(&raw_b, &[&test_colony_urn().to_string()]);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let peer_trust = combined_trust(&[&gateway.cert, &cert_b]);

	PeerPairCerts { gateway, peer_b: (cert_b, key_b), peer_trust }
}

/// Returns the receiver configuration that anchors both pair identities in
/// `peer_trust`.
fn peering_pair_conf(certs: &PeerPairCerts) -> ClusterConfig {
	let tls = cluster_tls_config(&certs.gateway).with_peer_trust(Arc::clone(&certs.peer_trust));
	ClusterConfig::new(tls)
}

tb_assert_spec! {
	pub ClusterPeerSignerKeyedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(3)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64))
		]
	}
}

// Slates belong to the authenticated signer, not the claimed gateway address:
// - Two trusted peers under the same address keep independent slates, so two routes exist after both install.
// - One peer's withdrawal evicts only its own routes, so ping survives echo's exit.
tb_scenario! {
	name: cluster_peer_slates_keyed_by_signer,
	spec: ClusterPeerSignerKeyedSpec,
	environment Cluster {
		context: peer_pair_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_pair_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let gateway = &certs.gateway;
			let ad_reply = advertise_peer_signed(gateway, &gateway.key, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")])
				.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let ad_reply = advertise_peer_signed(gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")])
				.await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			assert_eq!(cluster.peer_servlets()?.len(), 2, "two signers under one address keep a route each");

			let ad_reply = advertise_peer_signed(gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let survivors = cluster.peer_servlets()?;
			let ping_type = servlet_urn("ping").type_canonical_bytes();
			assert!(
				survivors.iter().any(|servlet_type| servlet_type.as_ref() == ping_type.as_slice()),
				"the withdrawal of B leaves the ping route of A"
			);

			cluster.stop();
			Ok(())
		}
	}
}

// Federation is default-off: a gateway without `peer_trust` refuses every
// advertisement fail-closed and installs no peer routes.
tb_scenario! {
	name: cluster_refuses_advertisement_without_peer_trust,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "a refused advertisement installs no peer route");

			cluster.stop();
			Ok(())
		}
	}
}

// Each scenario draws its own gateway identity, so a gateway answers an
// advertisement signed under the key of another scenario as one from an
// unknown signer, and installs no route.
tb_scenario! {
	name: cluster_refuses_the_identity_of_another_scenario,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let other_scenario = cluster_certs();
			let ping = vec![servlet_urn("ping")];
			let ad_reply = advertise_peer_signed(&certs, &other_scenario.key, &cluster, PEER_GATEWAY_ADDR, ping).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "a refused advertisement installs no peer route");

			cluster.stop();
			Ok(())
		}
	}
}

// Nestmate recognition: an advertised type from a foreign namespace fails the
// structural CHC half, and the gateway refuses it even under a valid peer
// certificate.
tb_scenario! {
	name: cluster_refuses_foreign_realm_advertisement,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let foreign_ns = ColonyNamespace::new("tightbeam", "other-realm")?;
			let foreign = foreign_ns.servlet("ping")?;

			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![foreign]).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "a refused advertisement installs no peer route");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerReplayReleasedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1))
		]
	}
}

// Retry ordering: the gateway refuses the conflicted advertisement before the
// byte-identical resend installs. A count alone cannot prove that the refusal
// preceded the install.
tb_process_spec! {
	pub ClusterAdRetryProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISE_REFUSED,
			events::CLUSTER_PEER_ADVERTISED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISE_REFUSED => ConflictRefused },
		ConflictRefused => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { }
	}
	terminal { Installed }
}

// An advertisement refused on local state (address conflict) releases its
// replay record, so the peer can resend the byte-identical signed frame and
// install once the conflict clears.
tb_scenario! {
	name: cluster_advertisement_retryable_after_refusal,
	config: ScenarioConfig::builder()
		.with_spec(ClusterPeerReplayReleasedSpec::latest())
		.with_csp(ClusterAdRetryProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			// Hive-plane frames below sign with the hive-plane identity,
			// which the split trust holds beside the gateway identity.
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));
			start_cluster(&trace, conf).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let hive_addr = b"127.0.0.1:65031".as_slice();
			let locator = String::from_utf8_lossy(PEER_GATEWAY_ADDR);
			let hive_id = hive_plane_certs(&certs);
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			register_signed_hive(&mut client, &hive_id.key, b"reg-conflict", hive_addr).await?;
			emit_servlet_update(
				&mut client,
				&hive_id.key,
				b"add-conflict",
				servlet_address_update(hive_addr, vec![servlet_info(&certs, "ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
				gateway_addr: PEER_GATEWAY_ADDR.to_vec(),
				advertised_types: vec![servlet_urn("ping")],
			});

			let frame = signed_control_frame(&certs, b"peer-advertise", request).await?;
			let ad_reply = send_advertisement_frame(&certs, &cluster, frame.to_owned()).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");

			let held = servlet_urn("ping").servlet_instance(locator.as_ref())?;
			emit_servlet_update(
				&mut client,
				&hive_id.key,
				b"del-conflict",
				servlet_address_update(hive_addr, vec![], vec![held]),
			)
			.await?;

			let ad_reply = send_advertisement_frame(&certs, &cluster, frame).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "the resend installs once the conflict clears");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerForwardLoopGuardSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

// Work with a spent relay budget serves locally only, so a peer-only type
// stays Unavailable once the hop budget reaches zero.
tb_scenario! {
	name: cluster_refuses_reforward_of_peer_work,
	spec: ClusterPeerForwardLoopGuardSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			let work_response = emit_relayed_ping_work(&mut client, &certs.key, b"reforward-guard").await?;
			assert_eq!(
				work_response.status,
				TransitStatus::Unavailable,
				"a spent hop budget leaves a peer-only type unavailable"
			);
			assert!(work_response.payload.is_none(), "a refused work reply carries no payload");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerForwardEchoSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2))
		]
	}
}

// Unary cross-cluster forward: ping lives only on the advertiser. The client
// asks the receiver, the receiver re-emits Work with the budget spent, the
// advertiser serves locally, and the echo returns.
tb_scenario! {
	name: cluster_forwards_work_to_peer_gateway,
	spec: ClusterPeerForwardEchoSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			let receiver_addr = receiver.addr();
			let config = advertising_cluster_conf(&certs, receiver_addr.to_string());
			let advertiser = start_cluster(&trace, config).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the receiver learns the one type the advertiser serves");

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let servlet_frame = emit_ping_work(&mut client, &certs.key, b"forward-echo").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

// Peer hops dial on `peer_trust`, so an importer with `hive_trust = None`
// forwards when only `peer_trust` anchors the peer gateway's certificate.
tb_scenario! {
	name: cluster_forwards_on_peer_trust_plane,
	spec: ClusterPeerForwardEchoSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_peer_trust_only(&certs)).await?;
			let receiver_addr = receiver.addr();
			let config = advertising_cluster_conf(&certs, receiver_addr.to_string());
			let advertiser = start_cluster(&trace, config).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the receiver learns the one type the advertiser serves");

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let servlet_frame = emit_ping_work(&mut client, &certs.key, b"peer-plane").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerCollideSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(events::CLUSTER_PEER_HINTS_LEARNED, exactly!(1), equals!(1u64))
		]
	}
}

// The gateway refuses a claimed `gateway_addr` that matches a local servlet
// address, and the refusal gates routing state only:
// - The admitted identity lands in the discovery new table, where the probe gate decides its fate.
// - A slate refusal therefore leaves graph connectivity intact.
tb_scenario! {
	name: cluster_refuses_peer_dial_colliding_local_servlet,
	spec: ClusterPeerCollideSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, hive_plane_certs(&certs), None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = peering_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));

			let cluster = start_cluster(&trace, conf).await?;
			hive.register_with_cluster(cluster.addr()).await?;

			// The update must present the registered signer, so it signs
			// with the hive-plane identity.
			let hive_addr = hive
				.addr()
				.ok_or(TightBeamError::NotEstablished)?
				.to_string()
				.into_bytes();

			let hive_id = hive_plane_certs(&certs);
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			emit_servlet_update(
				&mut client,
				&hive_id.key,
				b"collide-local",
				servlet_address_update(&hive_addr, vec![servlet_info(&certs, "ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")]).await?;
			assert_eq!(ad_reply, TransitStatus::PermissionDenied, "the gateway refuses the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "a refused advertisement installs no peer route");

			cluster.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The scenario sends CONTAINMENT_ABANDON_LIMIT failed forwards and one probe
// after abandonment. CLUSTER_WORK_FAILED counts the failed forwards, and
// CLUSTER_WORK_UNAVAILABLE counts the probe.
tb_assert_spec! {
	pub ClusterPeerContainmentSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

/// Submits `count` ping requests through `client`, each under the id of
/// `prefix` and its index, and returns the refusal status of each one. A
/// request that the gateway serves fails the scenario.
async fn refused_pings(
	client: &mut GenericClient<TokioListener>,
	key: &Secp256k1SigningKey,
	prefix: u8,
	count: u32,
) -> Result<Vec<TransitStatus>, TightBeamError> {
	let mut statuses = Vec::new();
	for index in 0..count {
		let id = [prefix, u8::try_from(index).expect("a fixture count fits a u8")];
		let refused_work = emit_ping_work(client, key, &id).await;
		statuses.push(work_refusal_status(refused_work)?);
	}

	Ok(statuses)
}

/// Submits `count` ping requests to `gateway`, each on a client of its own
/// and under the id of `prefix` and its index, and returns the value that
/// each echo carries.
async fn pinged_echoes(
	certs: &ClusterTestCerts,
	gateway: &ClusterGateway,
	prefix: &[u8],
	count: u8,
) -> Result<Vec<u32>, TightBeamError> {
	let mut doubled = Vec::new();
	for index in 0..count {
		let mut client = connect_cluster(certs, gateway.addr()).await?;
		let id = [prefix, &[index]].concat();

		let servlet_frame = emit_ping_work(&mut client, &certs.key, &id).await?;
		doubled.push(decode_ping_echo(&servlet_frame)?.doubled);
	}

	Ok(doubled)
}

// Abandonment ordering: unavailability must follow exactly
// CONTAINMENT_ABANDON_LIMIT failed forwards on the installed route. A count
// cannot prove that the trail failed before selection dropped it.
tb_process_spec! {
	pub ClusterContainmentProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISED,
			events::CLUSTER_WORK_FAILED,
			events::CLUSTER_WORK_UNAVAILABLE
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { events::CLUSTER_WORK_FAILED => FailedOnce },
		FailedOnce => { events::CLUSTER_WORK_FAILED => FailedTwice },
		FailedTwice => { events::CLUSTER_WORK_FAILED => Abandoned },
		Abandoned => { events::CLUSTER_WORK_UNAVAILABLE => Contained },
		Contained => { }
	}
	terminal { Contained }
}

// Infection containment: each failed forward weakens a peer route to a silent
// gateway. Past the abandonment limit the route drops out of selection, so
// the peer-only type reports Unavailable with no further forward attempt.
tb_scenario! {
	name: cluster_abandons_failing_peer_trail,
	config: ScenarioConfig::builder()
		.with_spec(ClusterPeerContainmentSpec::latest())
		.with_csp(ClusterContainmentProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, containment_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			// Each forward dials the dead peer, weakens the trail, and
			// resolves to a refusal at the client.
			let statuses = refused_pings(&mut client, &certs.key, b'f', CONTAINMENT_ABANDON_LIMIT.get()).await?;
			assert_eq!(statuses, [TransitStatus::Unavailable; CONTAINMENT_ABANDON_LIMIT.get() as usize], "each forward to the dead peer is refused");

			// Once the trail reaches abandonment, selection drops it, so the
			// peer-only type is Unavailable and the gateway attempts no
			// further forward.
			let refused_work = emit_ping_work(&mut client, &certs.key, b"gone").await;
			let status = work_refusal_status(refused_work)?;
			assert_eq!(status, TransitStatus::Unavailable, "an abandoned trail leaves the peer-only type unavailable");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1))
		]
	}
}

// Healing ordering: the local hive joins only after the dead trail has
// absorbed its full failure budget, and the successful route follows the
// join. A count cannot prove that work failed before the colony healed.
tb_process_spec! {
	pub ClusterIsolationProcess,
	events {
		observable {
			events::CLUSTER_PEER_ADVERTISED,
			events::CLUSTER_WORK_FAILED,
			events::CLUSTER_HIVE_REGISTERED,
			events::CLUSTER_WORK_ROUTED
		}
		hidden { }
	}
	states {
		Idle => { events::CLUSTER_PEER_ADVERTISED => Installed },
		Installed => { events::CLUSTER_WORK_FAILED => FailedOnce },
		FailedOnce => { events::CLUSTER_WORK_FAILED => FailedTwice },
		FailedTwice => { events::CLUSTER_WORK_FAILED => Abandoned },
		Abandoned => { events::CLUSTER_HIVE_REGISTERED => Healed },
		Healed => { events::CLUSTER_WORK_ROUTED => Served },
		Served => { }
	}
	terminal { Served }
}

// Containment isolates only the bad nest: after the dead peer trail reaches
// abandonment, a local ping hive joins and serves the same type, so work
// flows on-colony while the peer stays dropped.
tb_scenario! {
	name: cluster_isolates_abandoned_peer_and_serves_local,
	config: ScenarioConfig::builder()
		.with_spec(ClusterPeerIsolationSpec::latest())
		.with_csp(ClusterIsolationProcess)
		.build(),
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, hive_plane_certs(&certs), None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut conf = containment_cluster_conf(&certs);
			conf.tls.hive_trust = Some(split_hive_trust(&certs));

			let importer = start_cluster(&trace, conf).await?;

			let ad_reply = install_ping_peer(&certs, &importer).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");

			let mut client = connect_cluster(&certs, importer.addr()).await?;

			// Fail the peer trail into abandonment before any local route.
			// Every submission resolves to a refusal at the client.
			let statuses = refused_pings(&mut client, &certs.key, b'x', CONTAINMENT_ABANDON_LIMIT.get()).await?;
			assert_eq!(statuses, [TransitStatus::Unavailable; CONTAINMENT_ABANDON_LIMIT.get() as usize], "each forward to the dead peer is refused");

			// Heal the colony: a local ping hive joins after the bad nest
			// reaches abandonment, which leaves one live route for the type.
			hive.register_with_cluster(importer.addr()).await?;

			let servlet_frame = emit_ping_work(&mut client, &certs.key, b"local").await?;
			let ping_response = decode_ping_echo(&servlet_frame)?;
			assert_eq!(ping_response.doubled, 42, "the ping servlet doubles the request");

			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

// The gateway that serves a request records CLUSTER_WORK_ROUTED, and a gateway
// that forwards it records one more on the peer's Ok. The count is therefore
// the 36 requests plus the forwards.
tb_assert_spec! {
	pub ClusterPeerLocalitySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(events::CLUSTER_WORK_ROUTED, at_least!(36)),
			(events::CLUSTER_WORK_FORWARDED, at_most!(6))
		]
	}
}

// Local and peer both serve ping: warm local trails first, then admit the
// peer route. The seeded forager keeps the roulette stream reproducible so
// the reinforced local trail claims most later work on-colony.
tb_scenario! {
	name: cluster_locality_prefers_local_over_peer,
	spec: ClusterPeerLocalitySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, hive_plane_certs(&certs), None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut local_conf = peering_cluster_conf(&certs);
			local_conf.tls.hive_trust = Some(split_hive_trust(&certs));
			local_conf.load_balancer = Arc::new(StochasticForager::with_seed(0x7F0));
			let local_gateway = start_cluster(&trace, local_conf).await?;

			hive.register_with_cluster(local_gateway.addr()).await?;

			let warmed = pinged_echoes(&certs, &local_gateway, b"war", 12).await?;
			assert_eq!(warmed, [42; 12], "the ping servlet doubles each warming request");

			let config = advertising_cluster_conf(&certs, local_gateway.addr().to_string());
			let peer_gateway = start_cluster(&trace, config).await?;
			let peer_hive = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			peer_hive.register_with_cluster(peer_gateway.addr()).await?;

			let learned = wait_for_peer_types(&trace, &local_gateway, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the local gateway learns the peer's one type");

			let served = pinged_echoes(&certs, &local_gateway, b"loc", 24).await?;
			assert_eq!(served, [42; 24], "the ping servlet doubles each request");

			peer_hive.stop();
			peer_gateway.stop();
			local_gateway.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerSlateShrinkSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_PEER_ADVERTISED, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, absent!()),
			(events::CLUSTER_PEER_ROUTES_WITHDRAWN, exactly!(1), equals!(1u64))
		]
	}
}

// Reconciliation is by replacement: a later advertisement that carries an
// empty slate retires every route of the peer's earlier slate.
tb_scenario! {
	name: cluster_empty_advertisement_clears_peer_routes,
	spec: ClusterPeerSlateShrinkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { context: certs, cluster, .. }| async move {
			let ad_reply = install_ping_peer(&certs, &cluster).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert_eq!(cluster.peer_servlets()?.len(), 1, "one advertised type installs one peer route");

			let ad_reply = advertise_peer(&certs, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			assert_eq!(ad_reply, TransitStatus::Ok, "the gateway admits the advertisement");
			assert!(cluster.peer_servlets()?.is_empty(), "an empty slate retires every route of the earlier slate");

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerBeatSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// The advertised slate follows the registry: a hive that registers after
// both gateways are up surfaces at the peer within a beat, which the
// advertiser runs on its own.
tb_scenario! {
	name: cluster_beat_advertises_registered_hive_types,
	spec: ClusterPeerBeatSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			let receiver_addr = receiver.addr();
			let advertiser = start_cluster(&trace, advertising_cluster_conf(&certs, receiver_addr.to_string())).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the receiver learns the one type the hive serves");

			let ping_canonical = servlet_urn("ping").type_canonical_bytes();
			let keyed = learned
				.first()
				.is_some_and(|learned_type| learned_type.as_ref() == ping_canonical.as_slice());
			assert!(keyed, "the beat advertises the ping type of the hive");

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBeatUpdatedSlateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// The advertised slate follows the live routes: a type that joins through a
// servlet address update surfaces at the peer on the next beat, as a
// registration-time type does.
tb_scenario! {
	name: cluster_beat_slate_tracks_servlet_updates,
	spec: ClusterBeatUpdatedSlateSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster: receiver }| async move {

			let config = advertising_cluster_conf(&certs, receiver.addr().to_string());
			let advertiser = start_cluster(&trace, config).await?;
			let hive_addr = b"127.0.0.1:65041".as_slice();
			let mut client = connect_cluster(&certs, advertiser.addr()).await?;
			register_signed_hive(&mut client, &certs.key, b"reg-beat-update", hive_addr).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-beat-echo",
				servlet_address_update(hive_addr, vec![servlet_info(&certs, "echo", b"127.0.0.1:65042")], vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the type an address update adds surfaces at the peer");

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterBeatCapSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// The beat honors the receiver's advertisement cap, so a colony past
// MAX_ADVERTISED_TYPES advertises a deterministic capped subset. Every
// receiver refuses an oversized slate, which would silently wedge federation.
tb_scenario! {
	name: cluster_beat_bounds_slate_to_advertised_cap,
	spec: ClusterBeatCapSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster: receiver }| async move {
			let config = advertising_cluster_conf(&certs, receiver.addr().to_string());
			let advertiser = start_cluster(&trace, config).await?;

			let hive_addr = b"127.0.0.1:65043".as_slice();
			let mut client = connect_cluster(&certs, advertiser.addr()).await?;
			register_signed_hive(&mut client, &certs.key, b"reg-beat-cap", hive_addr).await?;

			let over_cap: Vec<ServletInfo> = (0..=MAX_ADVERTISED_TYPES)
				.map(|i| {
					let addr = format!("127.0.0.1:{}", 20000 + i);
					servlet_info(&certs, format!("t{i}"), addr.as_bytes())
				})
				.collect();
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-beat-cap",
				servlet_address_update(hive_addr, over_cap, vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), MAX_ADVERTISED_TYPES, "the beat advertises the capped subset of the slate");

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

/// The exporter identity, which serves the advertiser and the hive, sits on
/// one trust plane, and the receiver sits on another. Only `peer_trust` can
/// validate the receiver's TLS identity, so the advertise beat must dial on
/// the peer plane, never the hive one.
struct SplitPlaneCerts {
	exporter: ClusterTestCerts,
	receiver: (Certificate, Secp256k1SigningKey),
	receiver_trust: Arc<dyn CertificateTrust>,
}

fn split_plane_certs() -> SplitPlaneCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::fixtures::TestCertificate;

	let exporter = cluster_certs();
	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let receiver_cert = TestCertificate::with_uri_sans(&raw, &[&test_colony_urn().to_string()]);
	let receiver_key = Secp256k1SigningKey::from(raw);
	let receiver_trust = combined_trust(&[&receiver_cert]);
	SplitPlaneCerts { exporter, receiver: (receiver_cert, receiver_key), receiver_trust }
}

fn share_certs(certs: &ClusterTestCerts) -> Arc<ClusterTestCerts> {
	Arc::new(GatewayCerts {
		cert: certs.cert.to_owned(),
		key: certs.key.to_owned(),
		trust: Arc::clone(&certs.trust),
	})
}

/// Returns the configuration of a receiver with its own identity, whose
/// `peer_trust` anchors the exporter's certificate so its signed
/// advertisements verify.
fn receiving_peer_conf(certs: &SplitPlaneCerts) -> ClusterConfig {
	ClusterConfig::new(
		ClusterTlsConfig::new(
			CertificateSpec::Built(Box::new(certs.receiver.0.to_owned())),
			Arc::new(Secp256k1KeyProvider::from(certs.receiver.1.to_owned())),
		)
		.expect("the test certificate must decode")
		.with_hive_trust(Some(Arc::clone(&certs.exporter.trust)))
		.with_peer_trust(Some(Arc::clone(&certs.exporter.trust))),
	)
}

/// Returns the configuration of an advertiser whose hive plane cannot
/// validate the receiver, because only `peer_trust` anchors the receiver's
/// identity.
fn cross_plane_advertising_conf(certs: &SplitPlaneCerts, peer: impl Into<String>) -> ClusterConfig {
	let peer: String = peer.into();
	let tls = cluster_tls_config(&certs.exporter).with_peer_trust(Arc::clone(&certs.receiver_trust));

	ClusterConfig::builder(tls)
		.with_peers([peer])
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
		.build()
}

tb_assert_spec! {
	pub ClusterPeerPlaneBeatSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

// Federation crosses trust planes: only the advertiser's `peer_trust` anchors
// the receiver's TLS identity, so the beat must dial on the peer plane. A beat
// on the hive-trust pool fails to connect.
tb_scenario! {
	name: cluster_beat_dials_on_peer_trust_plane,
	spec: ClusterPeerPlaneBeatSpec,
	environment Hive {
		context: split_plane_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, share_certs(&certs.exporter), None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let receiver = start_cluster(&trace, receiving_peer_conf(&certs)).await?;
			let receiver_addr = receiver.addr().to_string();
			let advertiser = start_cluster(&trace, cross_plane_advertising_conf(&certs, receiver_addr)).await?;

			hive.register_with_cluster(advertiser.addr()).await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			assert_eq!(learned.len(), 1, "the beat on the peer plane reaches the receiver");

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

/// Returns a federating builder bound to the IPv4 wildcard, which a scenario
/// finishes with or without an advertise address.
fn wildcard_advertising_builder(certs: &ClusterTestCerts, peer: impl Into<String>) -> ClusterConfigBuilder {
	let peer: String = peer.into();
	ClusterConfig::builder(cluster_tls_config(certs))
		.with_bind_addr("0.0.0.0:0")
		.with_peers([peer])
		.expect("fixture peers name sockets")
		.with_advertise_interval(Duration::from_millis(100))
}

/// A port on the IPv4 wildcard that this value reserves for the scenario's
/// own listener, against a concurrent test that binds a port of its own.
///
/// - The socket holds the port in the bound state with `SO_REUSEADDR` set.
/// - A listener that names the port and sets `SO_REUSEADDR` binds beside the reservation.
/// - A bind that asks the kernel for any port passes over the reserved one.
struct ReservedWildcardPort {
	_held: HeldPort,
	port: u16,
}

impl ReservedWildcardPort {
	/// Reserves a fresh port on the IPv4 wildcard.
	fn hold() -> Self {
		let held = HeldPort::hold(Ipv4Addr::UNSPECIFIED, PortSharing::Shared);
		let port = held.address().port();

		Self { _held: held, port }
	}

	/// Returns the reserved port.
	fn port(&self) -> u16 {
		self.port
	}
}

/// Whether a fresh listener can take `port` on the IPv4 wildcard, which
/// fails while another listener holds it.
fn wildcard_port_is_free(port: u16) -> bool {
	TcpListener::bind(("0.0.0.0", port)).is_ok()
}

// A gateway bound to the wildcard address would advertise `0.0.0.0`, which
// every peer refuses as unspecified. A federating gateway with no advertise
// address therefore refuses to start, and releases the port it bound.
#[tokio::test]
async fn cluster_refuses_to_federate_from_a_wildcard_bind_without_an_advertise_address() -> Result<(), TightBeamError> {
	let certs = cluster_certs();
	let reserved = ReservedWildcardPort::hold();
	let port = reserved.port();
	let conf = wildcard_advertising_builder(&certs, "127.0.0.1:65210")
		.with_bind_addr(format!("0.0.0.0:{port}"))
		.build();

	let refused = start_cluster(&TraceCollector::new(), conf).await;
	let advertise_required = matches!(
		refused,
		Err(TightBeamError::ClusterError(error)) if matches!(*error, ClusterError::AdvertiseAddressRequired)
	);

	assert!(
		advertise_required,
		"a wildcard bind without an advertise address refuses to start"
	);
	assert!(wildcard_port_is_free(port), "a refused start releases the port it bound");
	Ok(())
}

tb_assert_spec! {
	pub ClusterAdvertiseAddrSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1))
		]
	}
}

/// The socket a wildcard-bound advertiser tells its peers to dial.
const ADVERTISED_GATEWAY_ADDR: &[u8] = b"127.0.0.1:65211";

/// Returns the loopback spelling of a gateway's bound socket, for a client on
/// the same host to dial a wildcard-bound gateway.
fn loopback_of(cluster: &ClusterGateway) -> <TokioListener as Protocol>::Address {
	let spelling = format!("127.0.0.1:{}", cluster.addr().port());
	spelling.parse().expect("a loopback socket spelling parses")
}

// A wildcard-bound gateway advertises the address the operator configured,
// so the peer's learned route dials that address and never the bound one.
tb_scenario! {
	name: cluster_advertises_the_configured_address_over_a_wildcard_bind,
	spec: ClusterAdvertiseAddrSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster: receiver }| async move {
			let advertised = String::from_utf8_lossy(ADVERTISED_GATEWAY_ADDR).into_owned();
			let conf = wildcard_advertising_builder(&certs, receiver.addr().to_string())
				.with_advertise_addr(advertised)?
				.build();
			let advertiser = start_cluster(&trace, conf).await?;

			let mut client = connect_cluster(&certs, &loopback_of(&advertiser)).await?;
			let hive_addr = b"127.0.0.1:65212";
			let servlets = vec![servlet_info(&certs, "ping", hive_addr)];
			register_signed_hive_serving(&mut client, &certs.key, b"reg-wildcard", hive_addr, servlets).await?;

			let learned = wait_for_peer_types(&trace, &receiver, 50, Duration::from_millis(100)).await;
			let routes = receiver.peer_routes()?;
			let learned_any = !learned.is_empty();
			let all_dial_advertised = routes.iter().all(|route| route.dial_addr.as_ref() == ADVERTISED_GATEWAY_ADDR);
			assert!(learned_any && all_dial_advertised, "the learned route dials the configured advertise address");

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

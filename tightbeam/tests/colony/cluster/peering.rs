//! Peer federation (advertisement control plane).

use super::common::*;

// ============================================================================
// Peer Federation (advertisement control plane)
// ============================================================================

tb_assert_spec! {
	pub ClusterPeerAdvertisedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1))
		]
	},
	// 1.1.0: the wire outcome joins the contract so accepting scenarios
	// prove the peer saw Ok, not merely that the install event fired.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok))
		]
	},
	// 1.2.0: the surviving route count joins the contract: one advertised
	// type must leave exactly one installed peer route.
	V(1,2,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64))
		]
	}
}

tb_assert_spec! {
	pub ClusterPeerRefusedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1))
		]
	},
	// 1.1.0: refusal contract pins the wire status AND the security
	// property refuse => zero installed peer routes.
	V(1,1,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// Claimed dial outside the optional allowlist is refused before install.
tb_scenario! {
	name: cluster_refuses_peer_dial_outside_allowlist,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![String::from("10.0.0.1:9000")])).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;

			cluster.stop();
			Ok(())
		}
	}
}

// Allowlisted dial installs normally.
tb_scenario! {
	name: cluster_accepts_peer_dial_on_allowlist,
	spec: ClusterPeerAdvertisedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			let allowed = String::from_utf8_lossy(PEER_GATEWAY_ADDR).into_owned();
			start_cluster(&trace, peering_with_dial_allowlist(&certs, vec![allowed])).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerRouteIntrospectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(1u64)),
			(LOCAL_SERVLETS_AFTER_INSTALLS, exactly!(1), equals!(0u64)),
			(PEER_ROUTE_EXPOSED, exactly!(1), equals!(1u64))
		]
	}
}

// A trusted peer advertisement installs peer routes: the advertised type
// surfaces in `peer_servlets` (learned), never in `available_servlets`
// (local hives only). No forwarding happens in this stage.
tb_scenario! {
	name: cluster_accepts_peer_advertisement,
	spec: ClusterPeerRouteIntrospectionSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			trace.event_with(LOCAL_SERVLETS_AFTER_INSTALLS, &[], cluster.available_servlets().len() as u64)?;

			// One learned route keyed by the advertised type, exposing the
			// claimed dial path and the signer fingerprint.
			let ping_canonical = type_canonical_bytes(&servlet_urn("ping"));
			let routes = cluster.peer_routes();
			let exposed = routes.len() == 1
				&& routes.first().is_some_and(|route| {
					route.servlet_type == ping_canonical
						&& route.dial_addr == PEER_GATEWAY_ADDR && !route.peer_id.is_empty()
				});

			trace.event_with(PEER_ROUTE_EXPOSED, &[], u64::from(exposed))?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerMultiTypeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(2u64)),
			(PEER_SLATE_MATCHES, exactly!(1), equals!(1u64))
		]
	}
}

// A slate is not one type: every advertised type installs its own peer
// route, so a two-type advertisement surfaces both types.
tb_scenario! {
	name: cluster_multi_type_advertisement_installs_all,
	spec: ClusterPeerMultiTypeSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let slate = vec![servlet_urn("ping"), servlet_urn("echo")];
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, slate).await?;

			let mut peers = cluster.peer_servlets();
			peers.sort_unstable();

			let mut expected = vec![
				type_canonical_bytes(&servlet_urn("ping")),
				type_canonical_bytes(&servlet_urn("echo")),
			];
			expected.sort_unstable();

			trace.event_with(PEER_SLATE_MATCHES, &[], u64::from(peers == expected))?;

			cluster.stop();
			Ok(())
		}
	}
}

/// Receiver identity plus a second, independently trusted peer signer.
struct PeerPairCerts {
	gateway: GatewayCerts,
	peer_b: (Certificate, Secp256k1SigningKey),
	peer_trust: Arc<dyn CertificateTrust>,
}

fn peer_pair_certs() -> PeerPairCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let gateway = cluster_certs();
	let raw_b = k256::ecdsa::SigningKey::random(&mut OsRng);
	let cert_b = create_test_certificate_with_uri_sans(&raw_b, &[&test_colony_urn().to_string()]);
	let key_b = Secp256k1SigningKey::from(raw_b);
	let peer_trust = combined_trust(&[&gateway.cert, &cert_b]);

	PeerPairCerts { gateway, peer_b: (cert_b, key_b), peer_trust }
}

/// Receiver conf anchoring both pair identities in `peer_trust`.
fn peering_pair_conf(certs: &PeerPairCerts) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		peer_trust: Some(Arc::clone(&certs.peer_trust)),
		..cluster_tls_config(&certs.gateway)
	};
	ClusterConfig::new(tls)
}

tb_assert_spec! {
	pub ClusterPeerSignerKeyedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(3)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(3)),
			(PEER_AD_STATUS, exactly!(3), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(2u64)),
			(PEER_ROUTES_AFTER_WITHDRAWAL, exactly!(1), equals!(1u64)),
			(PEER_PING_LIVE_AFTER_WITHDRAWAL, exactly!(1), equals!(1u64))
		]
	}
}

// Slates belong to the authenticated signer, not the claimed gateway
// address: two trusted peers advertising under the same address keep
// independent slates (two routes after both install), and one peer's
// withdrawal only evicts its own routes (ping survives echo's exit).
tb_scenario! {
	name: cluster_peer_slates_keyed_by_signer,
	spec: ClusterPeerSignerKeyedSpec,
	environment Cluster {
		context: peer_pair_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_pair_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let gateway = &certs.gateway;
			advertise_peer_signed(&trace, gateway, &gateway.key, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")])
				.await?;
			advertise_peer_signed(&trace, gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")])
				.await?;

			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			advertise_peer_signed(&trace, gateway, &certs.peer_b.1, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;

			let survivors = cluster.peer_servlets();
			trace.event_with(PEER_ROUTES_AFTER_WITHDRAWAL, &[], survivors.len() as u64)?;
			trace.event_with(
				PEER_PING_LIVE_AFTER_WITHDRAWAL,
				&[],
				u64::from(survivors.contains(&type_canonical_bytes(&servlet_urn("ping")))),
			)?;

			cluster.stop();
			Ok(())
		}
	}
}

// Federation is default-off: a gateway without `peer_trust` refuses every
// advertisement fail-closed, installing no peer routes.
tb_scenario! {
	name: cluster_refuses_advertisement_without_peer_trust,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, routing_cluster_conf(&certs, None)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("ping")]).await?;

			cluster.stop();
			Ok(())
		}
	}
}

// Nestmate recognition: an advertised type from a foreign realm fails the
// structural CHC half and is refused even under a valid peer certificate.
tb_scenario! {
	name: cluster_refuses_foreign_realm_advertisement,
	spec: ClusterPeerRefusedSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let foreign_ns =
				ColonyNamespace::new("tightbeam", "other-realm").map_err(|_| TightBeamError::MissingResponse)?;
			let foreign = foreign_ns.servlet("ping").map_err(|_| TightBeamError::MissingResponse)?;

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![foreign]).await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerReplayReleasedSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// Retry ordering: the conflicted advertisement is refused before the
// byte-identical resend installs. Counting alone cannot prove the
// refusal preceded the install.
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

// A refusal is not a penalty box: an advertisement refused on local state
// (address conflict) releases its replay record, so the peer can resend
// the byte-identical signed frame once the conflict clears and install.
tb_scenario! {
	name: cluster_advertisement_retryable_after_refusal,
	config: ScenarioConfig::builder()
		.with_spec(ClusterPeerReplayReleasedSpec::latest())
		.with_csp(ClusterAdRetryProcess)
		.build(),
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			let hive_addr = b"127.0.0.1:65031".as_slice();
			let locator = String::from_utf8_lossy(PEER_GATEWAY_ADDR);
			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			register_signed_hive(&mut client, &certs.key, b"reg-conflict", hive_addr).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-conflict",
				servlet_address_update(hive_addr, vec![servlet_info("ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			let request = ClusterRequest::AdvertisePeer(PeerAdvertisement {
				gateway_addr: PEER_GATEWAY_ADDR.to_vec(),
				advertised_types: vec![servlet_urn("ping")],
			});

			let frame = signed_control_frame(&certs, b"peer-advertise", request).await?;

			send_advertisement_frame(&trace, &certs, &cluster, frame.to_owned()).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"del-conflict",
				servlet_address_update(hive_addr, vec![], vec![servlet_instance(&servlet_urn("ping"), locator.as_ref())]),
			)
			.await?;

			send_advertisement_frame(&trace, &certs, &cluster, frame).await?;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerForwardLoopGuardSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1)),
			(WORK_STATUS, exactly!(1), equals!(TransitStatus::Unavailable)),
			(WORK_PAYLOAD, exactly!(1), equals!(0u64))
		]
	}
}

// Already-forwarded work never re-forwards: peer-only types stay
// Unavailable under the one-hop loop guard.
tb_scenario! {
	name: cluster_refuses_reforward_of_peer_work,
	spec: ClusterPeerForwardLoopGuardSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			trace.event(WORK_SENT)?;

			let work_response = emit_forwarded_ping_work(&mut client, b"reforward-guard").await?;
			record_work_status(&trace, &work_response)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerForwardEchoSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(1)),
			(events::CLUSTER_WORK_FORWARDED, exactly!(1)),
			(events::CLUSTER_WORK_ROUTED, exactly!(2)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Unary cross-cluster forward: ping lives only on B; client asks A; A
// wraps Work{forwarded:true}, B serves locally, echo returns.
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

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			trace.event(WORK_SENT)?;

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let work_response = emit_ping_work(&mut client, b"forward-echo").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;

			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

// Peer hops dial on peer_trust: importer with hive_trust=None still forwards
// when the peer gateway cert is anchored only in peer_trust.
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

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			trace.event(WORK_SENT)?;

			let mut client = connect_cluster(&certs, receiver.addr()).await?;
			let work_response = emit_ping_work(&mut client, b"peer-plane").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

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
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(PEER_ADVERTISE_SENT, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISE_REFUSED, exactly!(1)),
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::PermissionDenied)),
			(PEER_ROUTES_AFTER, exactly!(1), equals!(0u64))
		]
	}
}

// Claimed gateway_addr that matches a local servlet address is refused.
tb_scenario! {
	name: cluster_refuses_peer_dial_colliding_local_servlet,
	spec: ClusterPeerCollideSpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let cluster = start_cluster(&trace, peering_cluster_conf(&certs)).await?;
			hive.register_with_cluster(cluster.addr()).await?;

			let hive_addr = hive.addr().to_string().into_bytes();
			let mut client = connect_cluster(&certs, cluster.addr()).await?;
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"collide-local",
				servlet_address_update(&hive_addr, vec![servlet_info("ping", PEER_GATEWAY_ADDR)], vec![]),
			)
			.await?;

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![servlet_urn("echo")]).await?;

			cluster.stop();
			hive.stop();
			Ok(())
		}
	}
}

// WORK_SENT = CONTAINMENT_ABANDON_LIMIT failing forwards + 1 probe after
// abandonment; CLUSTER_WORK_FAILED = CONTAINMENT_ABANDON_LIMIT.
tb_assert_spec! {
	pub ClusterPeerContainmentSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_WORK_UNAVAILABLE, exactly!(1))
		]
	}
}

// Abandonment ordering: unavailability must follow exactly
// CONTAINMENT_ABANDON_LIMIT failed forwards on the installed route.
// Counting cannot prove the trail failed before selection dropped it.
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

// Infection containment: a peer route to a gateway that never answers is
// weakened on each failed forward and, past the abandonment limit, drops
// out of selection so the peer-only type reports Unavailable with no
// further forward attempt.
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
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;

			let mut client = connect_cluster(&certs, cluster.addr()).await?;

			// Each forward reaches the dead peer and weakens the trail.
			for i in 0..CONTAINMENT_ABANDON_LIMIT {
				trace.event(WORK_SENT)?;
				let id = [b'f', i as u8];
				let _ = emit_ping_work(&mut client, &id).await?;
			}

			// Trail abandoned: selection drops it, so the peer-only type
			// is Unavailable and no further forward is attempted.
			trace.event(WORK_SENT)?;
			let _ = emit_ping_work(&mut client, b"gone").await?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerIsolationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(PEER_AD_STATUS, exactly!(1), equals!(TransitStatus::Ok)),
			(WORK_SENT, exactly!(4)),
			(events::CLUSTER_WORK_FAILED, exactly!(3)),
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_WORK_ROUTED, exactly!(1)),
			(WORK_ECHOED, exactly!(1), equals!(42u64))
		]
	}
}

// Healing ordering: the local hive joins only after the dead trail has
// absorbed its full failure budget, and the successful route follows the
// join. Counting cannot prove work failed before the colony healed.
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

// Containment isolates only the bad nest: after the dead peer trail is
// abandoned, a local ping hive joins and serves the same type, so work
// keeps flowing on-colony while the peer stays dropped.
tb_scenario! {
	name: cluster_isolates_abandoned_peer_and_serves_local,
	config: ScenarioConfig::builder()
		.with_spec(ClusterPeerIsolationSpec::latest())
		.with_csp(ClusterIsolationProcess)
		.build(),
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let importer = start_cluster(&trace, containment_cluster_conf(&certs)).await?;

			install_ping_peer(&trace, &certs, &importer).await?;

			let mut client = connect_cluster(&certs, importer.addr()).await?;

			// Fail the peer trail into abandonment before any local route.
			for i in 0..CONTAINMENT_ABANDON_LIMIT {
				trace.event(WORK_SENT)?;
				let id = [b'x', i as u8];
				let _ = emit_ping_work(&mut client, &id).await?;
			}

			// Heal the colony: a local ping hive joins after the bad nest
			// is abandoned, leaving one live route for the type.
			hive.register_with_cluster(importer.addr()).await?;

			trace.event(WORK_SENT)?;
			let work_response = emit_ping_work(&mut client, b"local").await?;
			let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
			let ping_response: PingResponse = decode(&payload)?;
			trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;

			importer.stop();
			hive.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerLocalitySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(2), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(WORK_SENT, exactly!(36)),
			(events::CLUSTER_WORK_FORWARDED, at_most!(6)),
			(WORK_ECHOED, exactly!(36), equals!(42u64))
		]
	}
}

// Local and peer both serve ping: warm local trails first, then admit the
// peer route. Seeded forager keeps the roulette stream reproducible so the
// reinforced local trail claims most later work on-colony.
tb_scenario! {
	name: cluster_locality_prefers_local_over_peer,
	spec: ClusterPeerLocalitySpec,
	environment Hive {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| start_ping_hive(trace, certs, None),
		client: |HiveEnv { trace, context: certs, hive }| async move {
			let mut local_conf = peering_cluster_conf(&certs);
			local_conf.load_balancer = Arc::new(StochasticForager::with_seed(0x7F0));
			let local_gateway = start_cluster(&trace, local_conf).await?;

			hive.register_with_cluster(local_gateway.addr()).await?;

			for i in 0..12u8 {
				trace.event(WORK_SENT)?;

				let mut client = connect_cluster(&certs, local_gateway.addr()).await?;
				let id = [b'w', b'a', b'r', i];

				let work_response = emit_ping_work(&mut client, &id).await?;
				let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
				let ping_response: PingResponse = decode(&payload)?;
				trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
			}

			let config = advertising_cluster_conf(&certs, local_gateway.addr().to_string());
			let peer_gateway = start_cluster(&trace, config).await?;
			let peer_hive = start_ping_hive(trace.share(), Arc::clone(&certs), None).await?;
			peer_hive.register_with_cluster(peer_gateway.addr()).await?;

			let learned = wait_for_peer_types(&local_gateway, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			for i in 0..24u8 {
				trace.event(WORK_SENT)?;
				let mut client = connect_cluster(&certs, local_gateway.addr()).await?;
				let id = [b'l', b'o', b'c', i];

				let work_response = emit_ping_work(&mut client, &id).await?;
				let payload = work_response.payload.ok_or(TightBeamError::MissingResponse)?;
				let ping_response: PingResponse = decode(&payload)?;
				trace.event_with(WORK_ECHOED, &[], u64::from(ping_response.doubled))?;
			}

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
		gate: Ok,
		assertions: [
			(PEER_ADVERTISE_SENT, exactly!(2)),
			(events::CLUSTER_PEER_ADVERTISED, exactly!(2)),
			(PEER_AD_STATUS, exactly!(2), equals!(TransitStatus::Ok)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(PEER_ROUTES_AFTER_WITHDRAWAL, exactly!(1), equals!(0u64))
		]
	}
}

// Reconciliation is by replacement: a later advertisement carrying an
// empty slate retires every route the peer previously advertised.
tb_scenario! {
	name: cluster_empty_advertisement_clears_peer_routes,
	spec: ClusterPeerSlateShrinkSpec,
	environment Cluster {
		context: cluster_certs(),
		start: |SetupEnv { trace, context: certs }| async move {
			start_cluster(&trace, peering_cluster_conf(&certs)).await
		},
		client: |ClusterEnv { trace, context: certs, cluster }| async move {
			install_ping_peer(&trace, &certs, &cluster).await?;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], cluster.peer_servlets().len() as u64)?;

			advertise_peer(&trace, &certs, &cluster, PEER_GATEWAY_ADDR, vec![]).await?;
			trace.event_with(PEER_ROUTES_AFTER_WITHDRAWAL, &[], cluster.peer_servlets().len() as u64)?;

			cluster.stop();
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub ClusterPeerBeatSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64)),
			(PEER_PING_TYPE_LEARNED, exactly!(1), equals!(1u64))
		]
	}
}

// The advertised slate is registry truth, not configuration: a hive that
// registers AFTER both gateways are up surfaces at the peer within a
// beat, with no operator involvement.
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

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			let ping_canonical = type_canonical_bytes(&servlet_urn("ping"));
			let keyed = learned.first().is_some_and(|learned_type| *learned_type == ping_canonical);
			trace.event_with(PEER_PING_TYPE_LEARNED, &[], u64::from(keyed))?;

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
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// The advertised slate is route truth, not registration history: a type
// that joins through a servlet address update surfaces at the peer on
// the next beat, exactly like a registration-time type.
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
				servlet_address_update(hive_addr, vec![servlet_info("echo", b"127.0.0.1:65042")], vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

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
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, exactly!(1), equals!(1u64)),
			(events::CLUSTER_UPDATE_ACCEPTED, exactly!(1)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(MAX_ADVERTISED_TYPES as u64))
		]
	}
}

// The beat honors the receiver's advertisement cap: a colony exporting
// more types than MAX_ADVERTISED_TYPES advertises a deterministic capped
// subset instead of an oversized slate every receiver refuses, which
// would silently wedge federation.
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
					servlet_info(&format!("t{i}"), addr.as_bytes())
				})
				.collect();
			emit_servlet_update(
				&mut client,
				&certs.key,
				b"add-beat-cap",
				servlet_address_update(hive_addr, over_cap, vec![]),
			)
			.await?;

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			advertiser.stop();
			receiver.stop();
			Ok(())
		}
	}
}

/// Exporter (advertiser + hive) identity on one trust plane, receiver on
/// another: only `peer_trust` can validate the receiver's TLS identity,
/// so the advertise beat must dial on the peer plane, never the hive one.
struct SplitPlaneCerts {
	exporter: ClusterTestCerts,
	receiver: (Certificate, Secp256k1SigningKey),
	receiver_trust: Arc<dyn CertificateTrust>,
}

fn split_plane_certs() -> SplitPlaneCerts {
	use tightbeam::random::OsRng;
	use tightbeam::testing::utils::create_test_certificate_with_uri_sans;

	let exporter = cluster_certs();
	let raw = k256::ecdsa::SigningKey::random(&mut OsRng);
	let receiver_cert = create_test_certificate_with_uri_sans(&raw, &[&test_colony_urn().to_string()]);
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

/// Receiver with its own identity: `peer_trust` anchors the exporter's
/// certificate so its signed advertisements verify.
fn receiving_peer_conf(certs: &SplitPlaneCerts) -> ClusterConfig {
	ClusterConfig::new(ClusterTlsConfig {
		certificate: CertificateSpec::Built(Box::new(certs.receiver.0.to_owned())),
		key: Arc::new(Secp256k1KeyProvider::from(certs.receiver.1.to_owned())),
		validators: vec![],
		client_validators: vec![],
		hive_trust: Some(Arc::clone(&certs.exporter.trust)),
		peer_trust: Some(Arc::clone(&certs.exporter.trust)),
	})
}

/// Advertiser whose hive plane cannot validate the receiver: only
/// `peer_trust` anchors the receiver's identity.
fn cross_plane_advertising_conf(certs: &SplitPlaneCerts, peer: String) -> ClusterConfig {
	let tls = ClusterTlsConfig {
		peer_trust: Some(Arc::clone(&certs.receiver_trust)),
		..cluster_tls_config(&certs.exporter)
	};

	let mut conf = ClusterConfig::new(tls);
	conf.peer.peers = vec![peer];
	conf.peer.advertise_interval = Some(Duration::from_millis(100));
	conf
}

tb_assert_spec! {
	pub ClusterPeerPlaneBeatSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::CLUSTER_HIVE_REGISTERED, at_least!(1), equals!(1u64)),
			(events::CLUSTER_PEER_ADVERTISED, at_least!(1)),
			(PEER_ROUTES_AFTER_INSTALLS, exactly!(1), equals!(1u64))
		]
	}
}

// Federation crosses trust planes: the receiver's TLS identity is only
// anchored in the advertiser's `peer_trust`, so the beat must dial on the
// peer plane. A beat riding the hive-trust pool never connects.
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

			let learned = wait_for_peer_types(&receiver, 50, Duration::from_millis(100)).await;
			trace.event_with(PEER_ROUTES_AFTER_INSTALLS, &[], learned.len() as u64)?;

			advertiser.stop();
			receiver.stop();
			hive.stop();
			Ok(())
		}
	}
}

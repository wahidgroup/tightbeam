//! Three-org live topology for the colony AFL harness.
//!
//! Alpha is the federation seed: beta and gamma peer to alpha's gateway
//! address. The Cluster scenario `start` returns this topology as the
//! owned program; the client dials any org gateway for work and CSR.
//! Advertise beats stay disabled; routes install only via one-shot
//! [`tightbeam::colony::cluster::ClusterRequest::AdvertisePeer`] actions.

use std::sync::{Arc, Mutex};

use tightbeam::cluster;
use tightbeam::colony::cluster::{Cluster, ClusterConfig, DynamicExportList, ExportAllowlist};
use tightbeam::colony::hive::Hive;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::store::CertificateTrust;
use tightbeam::crypto::x509::Certificate;
use tightbeam::hive;
use tightbeam::policy::GatePolicy;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::client::pool::PoolConfig;
use tightbeam::transport::handshake::negotiation::TransportOffer;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::TightBeamError;

use crate::acl::{DynamicAclState, DynamicDenyGate, DynamicGrant};
use crate::csr::{csr_servlet_config, CsrIssuer, CsrServlet};
use crate::fixtures::{
	cluster_tls_config, colony_identity, colony_urn, combined_trust, combined_validator, hive_tls_config, servlet_urn,
	ClusterTestCerts, GatewayCerts,
};
use crate::policy::{DecoyFirstBalancer, DynamicPolicyGate, StableRoundRobin};
use crate::servlets::{ping_servlet_config, ColonyPingServlet};
use crate::shadow::GatewayShadow;

hive! {
	pub ColonyFuzzHive,
	protocol: TokioListener
}

cluster! {
	pub ColonyFuzzGateway,
	protocol: TokioListener
}

/// One organization's gateway, hive, and mutable ACL handles.
pub(crate) struct OrgNode {
	pub name: &'static str,
	pub certs: Arc<ClusterTestCerts>,
	pub exports: Arc<DynamicExportList>,
	pub acl: Arc<DynamicAclState>,
	pub policy_gate: Arc<DynamicPolicyGate>,
	pub shadow: GatewayShadow,
	pub gateway: ColonyFuzzGateway,
	pub hive: ColonyFuzzHive,
	pub csr_issuer: Option<Arc<CsrIssuer>>,
	/// Soft-state instance counter for lifecycle opcodes after establish.
	pub soft_instances: usize,
}

/// Full multi-org program under test.
///
/// Owned by `ClusterEnv.cluster` for the colony AFL target. `alpha` is
/// the seed gateway; peer orgs dial it during [`ColonyTopology::boot`].
pub(crate) struct ColonyTopology {
	/// Federation entry / peer seed.
	pub alpha: OrgNode,
	pub beta: OrgNode,
	pub gamma: OrgNode,
	/// Shared decoy pin for alpha's failover balancer.
	pub decoy_pin: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ColonyTopology {
	pub async fn boot(trace: &TraceCollector) -> Result<Self, TightBeamError> {
		let alpha_urn = colony_urn("alpha");
		let beta_urn = colony_urn("beta");
		let gamma_urn = colony_urn("gamma");

		// Fixed distinct seeds: identical inputs MUST mint identical SPKIs.
		let (cert_a, key_a) = colony_identity("Alpha Gateway", &alpha_urn, 1);
		let (cert_b, key_b) = colony_identity("Beta Gateway", &beta_urn, 2);
		let (cert_c, key_c) = colony_identity("Gamma Gateway", &gamma_urn, 3);

		let alpha_certs = Arc::new(gateway_bundle(cert_a, key_a));
		let beta_certs = Arc::new(gateway_bundle(cert_b, key_b));
		let gamma_certs = Arc::new(gateway_bundle(cert_c, key_c));

		let decoy_pin = Arc::new(Mutex::new(None));
		// Full-mesh peer trust so one-shot ads and foreign-identity dials
		// reach the export/gate planes instead of dying at TLS.
		let alpha_peers = combined_trust(&[&beta_certs.cert, &gamma_certs.cert]);
		let beta_peers = combined_trust(&[&alpha_certs.cert, &gamma_certs.cert]);
		let gamma_peers = combined_trust(&[&alpha_certs.cert, &beta_certs.cert]);
		let federation = [&alpha_certs.cert, &beta_certs.cert, &gamma_certs.cert];

		let alpha = boot_org(
			trace,
			BootOrg {
				name: "alpha",
				own: Arc::clone(&alpha_certs),
				peer_trust: alpha_peers,
				federation_certs: &federation,
				with_csr: true,
				max_hops: 2,
				peers: vec![],
				with_peer_ping: false,
				decoy_pin: Some(Arc::clone(&decoy_pin)),
			},
		)
		.await?;
		let alpha_addr = alpha.gateway.addr().to_string();
		let beta = boot_org(
			trace,
			BootOrg {
				name: "beta",
				own: Arc::clone(&beta_certs),
				peer_trust: beta_peers,
				federation_certs: &federation,
				with_csr: false,
				max_hops: 1,
				peers: vec![alpha_addr.clone()],
				with_peer_ping: true,
				decoy_pin: None,
			},
		)
		.await?;
		let gamma = boot_org(
			trace,
			BootOrg {
				name: "gamma",
				own: Arc::clone(&gamma_certs),
				peer_trust: gamma_peers,
				federation_certs: &federation,
				with_csr: false,
				max_hops: 0,
				peers: vec![alpha_addr],
				with_peer_ping: true,
				decoy_pin: None,
			},
		)
		.await?;

		Ok(Self { alpha, beta, gamma, decoy_pin })
	}

	pub fn stop(self) {
		self.alpha.hive.stop();
		self.beta.hive.stop();
		self.gamma.hive.stop();
		self.alpha.gateway.stop();
		self.beta.gateway.stop();
		self.gamma.gateway.stop();
	}
}

pub(crate) fn gateway_bundle(cert: Certificate, key: Secp256k1SigningKey) -> GatewayCerts {
	let trust = combined_trust(&[&cert]);
	GatewayCerts { cert, key, trust }
}

/// Per-org boot knobs for [`boot_org`].
struct BootOrg<'a> {
	name: &'static str,
	own: Arc<ClusterTestCerts>,
	peer_trust: Arc<dyn CertificateTrust>,
	federation_certs: &'a [&'a Certificate],
	with_csr: bool,
	max_hops: u8,
	peers: Vec<String>,
	with_peer_ping: bool,
	decoy_pin: Option<Arc<Mutex<Option<Vec<u8>>>>>,
}

async fn boot_org(trace: &TraceCollector, cfg: BootOrg<'_>) -> Result<OrgNode, TightBeamError> {
	let BootOrg {
		name,
		own,
		peer_trust,
		federation_certs,
		with_csr,
		max_hops,
		peers,
		with_peer_ping,
		decoy_pin,
	} = cfg;

	let mut exported = vec![servlet_urn("public"), servlet_urn("stream-echo")];
	if with_peer_ping {
		exported.push(servlet_urn("peer-ping"));
	}
	let exports = Arc::new(DynamicExportList::new(exported));
	let acl = Arc::new(DynamicAclState::default());
	let policy_gate = DynamicPolicyGate::new();

	let mut tls = cluster_tls_config(&own);
	tls.peer_trust = Some(Arc::clone(&peer_trust));
	tls.client_validators = vec![combined_validator(federation_certs)];

	let pool = PoolConfig {
		idle_timeout: None,
		max_connections: 32,
		mux_offer: Some(Arc::new(TransportOffer::mux(8))),
	};

	// Leave advertise_interval at None so the gossip beat never races the
	// action loop. Local export/ACL enforcement still covers the boundary;
	// live discovery races belong in integration tests.
	let mut builder = ClusterConfig::builder(tls)
		.with_export_allowlist(Arc::clone(&exports) as Arc<dyn ExportAllowlist>)
		.with_export_grant(Arc::new(DynamicGrant { state: Arc::clone(&acl) }))
		.with_export_gate(Arc::new(DynamicDenyGate { state: Arc::clone(&acl) }))
		.with_gate_policy(Arc::clone(&policy_gate) as Arc<dyn GatePolicy + Send + Sync>)
		.with_max_hops(max_hops)
		.with_pool_config(pool)
		.with_control_freshness_window_ms(u64::MAX / 4);

	if let Some(pin) = decoy_pin {
		builder = builder.with_load_balancer(DecoyFirstBalancer { preferred: pin });
	} else {
		builder = builder.with_load_balancer(StableRoundRobin::new());
	}

	if !peers.is_empty() {
		builder = builder.with_peers(peers);
	}

	let conf = builder.build();
	let gateway = ColonyFuzzGateway::start(Arc::new(trace.share()), conf).await?;

	let mut hive = ColonyFuzzHive::new(Some(hive_tls_config(&own)))?;
	let ping = ColonyPingServlet::start(Arc::new(trace.share()), Some(ping_servlet_config()?)).await?;
	hive.register(servlet_urn("public"), ping, |t| ColonyPingServlet::start(t, None))?;

	let private = ColonyPingServlet::start(Arc::new(trace.share()), Some(ping_servlet_config()?)).await?;
	hive.register(servlet_urn("private"), private, |t| ColonyPingServlet::start(t, None))?;

	let stream = ColonyPingServlet::start(Arc::new(trace.share()), Some(ping_servlet_config()?)).await?;
	hive.register(servlet_urn("stream-echo"), stream, |t| ColonyPingServlet::start(t, None))?;

	if with_peer_ping {
		let peer_ping = ColonyPingServlet::start(Arc::new(trace.share()), Some(ping_servlet_config()?)).await?;
		hive.register(servlet_urn("peer-ping"), peer_ping, |t| ColonyPingServlet::start(t, None))?;
	}

	let mut csr_issuer = None;
	if with_csr {
		let issuer = Arc::new(CsrIssuer::new(colony_urn(name).to_string()));
		let csr = CsrServlet::start(Arc::new(trace.share()), Some(csr_servlet_config(Arc::clone(&issuer))?)).await?;
		let issuer_spawn = Arc::clone(&issuer);
		hive.register(servlet_urn("csr"), csr, move |t| {
			let issuer = Arc::clone(&issuer_spawn);
			async move {
				let conf = csr_servlet_config(issuer)?;
				CsrServlet::start(t, Some(conf)).await
			}
		})?;
		csr_issuer = Some(issuer);
	}

	hive.establish(Arc::new(trace.share())).await?;
	hive.register_with_cluster(gateway.addr()).await?;

	let shadow = GatewayShadow {
		exports: Arc::clone(&exports),
		acl: Arc::clone(&acl),
		policy_gate: Arc::clone(&policy_gate),
		hive_trust: Arc::clone(&own.trust),
		peer_trust,
	};

	Ok(OrgNode {
		name,
		certs: own,
		exports,
		acl,
		policy_gate,
		shadow,
		gateway,
		hive,
		csr_issuer,
		soft_instances: 2 + usize::from(with_peer_ping),
	})
}

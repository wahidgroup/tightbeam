//! Three-org live topology for the colony AFL harness.
//!
//! Alpha is the federation seed: beta and gamma peer to alpha's gateway
//! address. The Cluster scenario `start` returns this topology as the
//! owned program; the client dials any org gateway for work and CSR.
//! Advertise beats stay disabled; routes install only via one-shot
//! [`tightbeam::colony::cluster::ClusterRequest::AdvertisePeer`] actions.

use std::sync::{Arc, Mutex};

use tightbeam::cluster;
use tightbeam::colony::cluster::{Cluster, ClusterConfig, DynamicExportList, ExportAllowlist, ExportGate, ExportGrant};
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
use tightbeam::utils::urn::Urn;
use tightbeam::TightBeamError;

use crate::acl::{DynamicAclState, DynamicDenyGate, DynamicGrant};
use crate::csr::{csr_servlet_config, CsrIssuer, CsrServlet};
use crate::fixtures::{
	cluster_tls_config, colony_identity, colony_urn, combined_trust, hive_tls_config, servlet_urn, ClusterTestCerts,
	GatewayCerts,
};
use crate::policy::{DecoyFirstBalancer, DynamicPolicyGate, StableRoundRobin};
use crate::servlets::{ping_servlet_config, ColonyPingServlet};
use crate::shadow::{AccessAttempt, GatewayShadow, Prediction};

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
	/// Short org label used in traces and CSR issuer naming.
	pub name: &'static str,
	/// Deterministic gateway identity for this organization.
	pub certs: Arc<ClusterTestCerts>,
	/// Live export allowlist mutated by oracle actions.
	pub exports: Arc<DynamicExportList>,
	/// Shared grant and deny tables for this gateway.
	pub acl: Arc<DynamicAclState>,
	/// Pre-decode gate the oracle can arm or disarm.
	pub policy_gate: Arc<DynamicPolicyGate>,
	/// Live cluster gateway under test.
	pub gateway: ColonyFuzzGateway,
	/// Local hive registered to the gateway.
	pub hive: ColonyFuzzHive,
	/// Optional CSR issuer handle when this org serves CSR.
	pub csr_issuer: Option<Arc<CsrIssuer>>,
	/// Independent oracle over harness-owned state. Drift against the
	/// live wire is the detection mechanism, never a source of truth.
	pub shadow: GatewayShadow,
	/// Soft-state instance counter for lifecycle opcodes after establish.
	pub soft_instances: usize,
}

impl OrgNode {
	/// Predict against this org's export boundary through the shadow.
	pub fn predict(&self, attempt: &AccessAttempt<'_>) -> Prediction {
		self.shadow.predict(attempt)
	}

	/// Predict whether a signed peer advertisement from `signer` admits.
	pub fn predict_peer_ad(&self, signer: &Certificate) -> Prediction {
		self.shadow.predict_peer_ad(signer)
	}
}

/// Full multi-org program under test.
///
/// Owned by `ClusterEnv.cluster` for the colony AFL target. `alpha` is
/// the seed gateway; peer orgs dial it during [`ColonyTopology::boot`].
pub(crate) struct ColonyTopology {
	/// Federation entry / peer seed.
	pub alpha: OrgNode,
	/// Peer organization that dials the federation seed.
	pub beta: OrgNode,
	/// Second peer organization in the three-org mesh.
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
		let alpha_peers = combined_trust(&[beta_certs.cert.as_ref(), gamma_certs.cert.as_ref()]);
		let beta_peers = combined_trust(&[alpha_certs.cert.as_ref(), gamma_certs.cert.as_ref()]);
		let gamma_peers = combined_trust(&[alpha_certs.cert.as_ref(), beta_certs.cert.as_ref()]);

		let alpha = boot_org(
			trace,
			BootOrg {
				name: "alpha",
				own: Arc::clone(&alpha_certs),
				peer_trust: alpha_peers,
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
	let cert = Arc::new(cert);
	let trust = combined_trust(&[cert.as_ref()]);
	GatewayCerts::new(cert, key, trust)
}

/// Per-org boot knobs for [`boot_org`].
struct BootOrg {
	name: &'static str,
	own: Arc<ClusterTestCerts>,
	peer_trust: Arc<dyn CertificateTrust>,
	with_csr: bool,
	max_hops: u8,
	peers: Vec<String>,
	with_peer_ping: bool,
	decoy_pin: Option<Arc<Mutex<Option<Vec<u8>>>>>,
}

async fn boot_org(trace: &TraceCollector, cfg: BootOrg) -> Result<OrgNode, TightBeamError> {
	let BootOrg { name, own, peer_trust, with_csr, max_hops, peers, with_peer_ping, decoy_pin } = cfg;

	let mut exported = vec![servlet_urn("public"), servlet_urn("stream-echo")];
	if with_peer_ping {
		exported.push(servlet_urn("peer-ping"));
	}

	let data = DynamicExportList::new(exported);
	let exports = Arc::new(data);
	let acl = Arc::new(DynamicAclState::default());
	let policy_gate = DynamicPolicyGate::new();

	let export_grant: Arc<dyn ExportGrant> = Arc::new(DynamicGrant { state: Arc::clone(&acl) });
	let export_gate: Arc<dyn ExportGate> = Arc::new(DynamicDenyGate { state: Arc::clone(&acl) });

	let mut tls = cluster_tls_config(&own);
	tls.peer_trust = Some(Arc::clone(&peer_trust));
	// With empty client_validators, the ECIES server admits anonymous
	// dials and opportunistically captures any offered identity whose
	// proof-of-possession signature verifies. Mutual-TLS chain
	// validation is covered by integration tests.
	tls.client_validators = vec![];

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
		.with_export_grant(Arc::clone(&export_grant))
		.with_export_gate(Arc::clone(&export_gate))
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
	let gateway = ColonyFuzzGateway::start(share_trace(trace), conf).await?;
	let mut hive = ColonyFuzzHive::new(Some(hive_tls_config(&own)))?;

	// Local work surfaces. peer-ping is only on orgs that advertise it.
	let mut local_types = vec![servlet_urn("public"), servlet_urn("private"), servlet_urn("stream-echo")];
	if with_peer_ping {
		local_types.push(servlet_urn("peer-ping"));
	}

	for servlet_type in local_types {
		register_ping(&mut hive, trace, servlet_type).await?;
	}

	let csr_issuer = match with_csr {
		true => Some(register_csr(&mut hive, trace, name).await?),
		false => None,
	};

	hive.establish(share_trace(trace)).await?;
	hive.register_with_cluster(gateway.addr()).await?;

	// The shadow reads the same handles the gateway config holds: the
	// dynamic export list, ACL, and policy gate, plus this org's own
	// trust as hive_trust and the fixed peer set as peer_trust.
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
		gateway,
		hive,
		csr_issuer,
		shadow,
		soft_instances: 2 + usize::from(with_peer_ping),
	})
}

fn share_trace(trace: &TraceCollector) -> Arc<TraceCollector> {
	Arc::new(trace.share())
}

/// Boot a ping servlet and register it; the spawner rebuilds a fresh instance on scale-out.
async fn register_ping(
	hive: &mut ColonyFuzzHive,
	trace: &TraceCollector,
	servlet_type: Urn<'static>,
) -> Result<(), TightBeamError> {
	let trace = share_trace(trace);
	let config = ping_servlet_config()?;
	let servlet = ColonyPingServlet::start(trace, Some(config)).await?;
	// Scale-out rebuilds a fresh ping instance with default config.
	let respawn = |t| ColonyPingServlet::start(t, None);

	hive.register(servlet_type, servlet, respawn)
}

/// Boot the CSR servlet. Returns the issuer so the org node can observe mint counts.
async fn register_csr(
	hive: &mut ColonyFuzzHive,
	trace: &TraceCollector,
	org_name: &str,
) -> Result<Arc<CsrIssuer>, TightBeamError> {
	let allowed_colony = colony_urn(org_name).to_string();
	let issuer = Arc::new(CsrIssuer::new(allowed_colony));
	let csr_type = servlet_urn("csr");
	let trace = share_trace(trace);
	let config = csr_servlet_config(Arc::clone(&issuer))?;
	let servlet = CsrServlet::start(trace, Some(config)).await?;

	// Spawner owns its issuer clone; OrgNode keeps the returned handle.
	let spawn_issuer = Arc::clone(&issuer);
	let respawn = move |t| {
		let issuer = Arc::clone(&spawn_issuer);

		async move {
			let config = csr_servlet_config(issuer)?;
			CsrServlet::start(t, Some(config)).await
		}
	};

	hive.register(csr_type, servlet, respawn)?;
	Ok(issuer)
}

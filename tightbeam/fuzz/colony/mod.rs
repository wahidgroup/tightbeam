//! Multi-org colony AFL fuzz (export, work, CSR, routing, streams, trust).
//!
//! One Cluster AFL target that boots a three-organization federation,
//! mutates live export/ACL/GatePolicy state, installs peer routes through
//! one-shot advertisements, and drives work/CSR/stream/hostile/failover
//! actions from oracle bytes. The scenario owns [`ColonyTopology`] as the
//! ClusterEnv program under test.

#![cfg(all(feature = "std", feature = "full"))]
// The AFL arm expands `cfg(fuzzing)`, which cargo does not know as a
// check-cfg name (same allowance as the other fuzz targets).
#![allow(unexpected_cfgs)]

mod acl;
mod actions;
mod control;
mod csr;
mod events;
mod fixtures;
mod limits;
mod policy;
mod servlets;
mod shadow;
mod topology;

use tightbeam::testing::{ClusterEnv, ScenarioConfig, SetupEnv};
use tightbeam::{at_least, exactly, tb_assert_spec, tb_process_spec, tb_scenario};

use crate::actions::run_actions;
use crate::topology::ColonyTopology;

tb_assert_spec! {
	/// Colony cooperation assertion specification.
	pub ColonyAssertSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(events::ACTION_RUN, at_least!(0)),
			(events::SHADOW_VIOLATION, exactly!(0)),
			(events::ACTIONS_BALANCE, exactly!(1), tags: ["balance"]),
		]
	},
	annotations { description: "Multi-org colony AFL assertion specification" }
}

tb_process_spec! {
	pub ColonyCoopFlow,
	events {
		observable {
			events::ACTION_RUN, events::SHADOW_VIOLATION, events::WORK_OK, events::WORK_DENIED,
			events::CSR_ISSUED, events::CSR_REFUSED, events::SERVLET_ADDED, events::SERVLET_REMOVED,
			events::STRESS_BURST, events::EXPORT_MUTATED, events::GRANT_MUTATED, events::GATE_MUTATED,
			events::POLICY_GATE_MUTATED, events::PEER_ADVERTISE_SENT, events::PEER_AD_OK, events::PEER_AD_DENIED,
			events::PEER_ROUTES_AFTER, events::CROSS_ORG_WORK, events::STREAM_OK, events::STREAM_DENIED,
			events::DUPLEX_OK, events::DUPLEX_DENIED, events::HOSTILE_ANON, events::HOSTILE_FOREIGN,
			events::FAILOVER_PROBED, events::ACTIONS_BALANCE
		}
		hidden { }
	}
	states {
		Idle => {
			events::ACTION_RUN => Acting,
			events::ACTIONS_BALANCE => Idle,
		},
		Acting => {
			events::ACTION_RUN => Acting,
			events::WORK_OK => Acting,
			events::WORK_DENIED => Acting,
			events::CSR_ISSUED => Acting,
			events::CSR_REFUSED => Acting,
			events::SERVLET_ADDED => Acting,
			events::SERVLET_REMOVED => Acting,
			events::STRESS_BURST => Acting,
			events::EXPORT_MUTATED => Acting,
			events::GRANT_MUTATED => Acting,
			events::GATE_MUTATED => Acting,
			events::POLICY_GATE_MUTATED => Acting,
			events::PEER_ADVERTISE_SENT => Acting,
			events::PEER_AD_OK => Acting,
			events::PEER_AD_DENIED => Acting,
			events::PEER_ROUTES_AFTER => Acting,
			events::CROSS_ORG_WORK => Acting,
			events::STREAM_OK => Acting,
			events::STREAM_DENIED => Acting,
			events::DUPLEX_OK => Acting,
			events::DUPLEX_DENIED => Acting,
			events::HOSTILE_ANON => Acting,
			events::HOSTILE_FOREIGN => Acting,
			events::FAILOVER_PROBED => Acting,
			events::SHADOW_VIOLATION => Acting,
			events::ACTIONS_BALANCE => Idle,
		}
	}
	annotations { description: "High-level multi-org colony cooperation flow" }
}

tb_scenario! {
	fuzz: afl,
	csp: ColonyCoopFlow,
	config: ScenarioConfig::builder()
		.with_spec(ColonyAssertSpec::latest())
		.with_csp(ColonyCoopFlow)
		.build(),
	environment Cluster {
		context: (),
		start: |SetupEnv { trace, .. }| async move {
			ColonyTopology::boot(&trace).await
		},
		client: |ClusterEnv { trace, cluster: mut topo, .. }| async move {
			run_actions(&trace, &mut topo).await?;
			topo.stop();
			Ok(())
		}
	}
}

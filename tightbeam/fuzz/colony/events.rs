//! Colony fuzz scenario event inventory.
//!
//! One URN per emit site, domain-scoped under `event:colony/` so trace
//! assertions stay local to this harness.

use tightbeam::utils::urn::Urn;

const FUZZ_NID: &str = "fuzz";

pub(crate) const ACTION_RUN: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/action-run");
pub(crate) const SHADOW_VIOLATION: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/shadow-violation");
pub(crate) const WORK_OK: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/work-ok");
pub(crate) const WORK_DENIED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/work-denied");
pub(crate) const CSR_ISSUED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/csr-issued");
pub(crate) const CSR_REFUSED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/csr-refused");
pub(crate) const SERVLET_ADDED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/servlet-added");
pub(crate) const SERVLET_REMOVED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/servlet-removed");
pub(crate) const STRESS_BURST: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/stress-burst");
pub(crate) const EXPORT_MUTATED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/export-mutated");
pub(crate) const GRANT_MUTATED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/grant-mutated");
pub(crate) const GATE_MUTATED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/gate-mutated");
pub(crate) const POLICY_GATE_MUTATED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/policy-gate-mutated");
pub(crate) const PEER_ADVERTISE_SENT: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/peer-advertise-sent");
pub(crate) const PEER_AD_OK: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/peer-ad-ok");
pub(crate) const PEER_AD_DENIED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/peer-ad-denied");
pub(crate) const PEER_ROUTES_AFTER: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/peer-routes-after");
pub(crate) const CROSS_ORG_WORK: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/cross-org-work");
pub(crate) const STREAM_OK: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/stream-ok");
pub(crate) const STREAM_DENIED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/stream-denied");
pub(crate) const DUPLEX_OK: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/duplex-ok");
pub(crate) const DUPLEX_DENIED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/duplex-denied");
pub(crate) const HOSTILE_ANON: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/hostile-anon");
pub(crate) const HOSTILE_FOREIGN: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/hostile-foreign");
pub(crate) const FAILOVER_PROBED: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/failover-probed");
pub(crate) const ACTIONS_BALANCE: Urn<'static> = Urn::new(FUZZ_NID, "event:colony/actions-balance");

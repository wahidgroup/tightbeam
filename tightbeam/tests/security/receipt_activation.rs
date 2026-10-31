//! # Receipt-activation threat
//!
//! ## Weakness
//! A budget-bearing session is only accountable if the dual-signed receipt
//! is completed:
//!
//! 1. The server issues and signs the receipt.
//! 2. The client countersigns it.
//! 3. The server verifies the countersignature and settles.
//!
//! The server runs step 3 inside the step that processes the client
//! Finished. That step consumes the issued receipt whether settlement
//! succeeds or fails.
//!
//! Suppose a second client Finished, after a refused settlement, finds no
//! receipt left to settle and passes. The metered session then activates
//! with a budget nobody settled, which defeats non-repudiation.
//!
//! ## Attack
//! A client countersigns a receipt whose settlement the authorizer refuses,
//! and the server aborts the step. The client replays the same Finished,
//! and the server integration then asks for the session. The session
//! carries budgets, but no `StoredReceipt` exists.
//!
//! ## Expected control
//! A refused settlement MUST leave the server with nothing to complete
//! from. The replayed Finished and the completion MUST both fail closed.
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-306: Missing Authentication for Critical Function <https://cwe.mitre.org/data/definitions/306.html>

#![cfg(feature = "transport-multiplex")]

use std::sync::Arc;

use tightbeam::absent;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::negotiation::SETTLEMENT_UNSUPPORTED_CODE;
use tightbeam::transport::handshake::{HandshakeError, HandshakeMessage, ServerHandshakeProtocol};
use tightbeam::TightBeamError;

use crate::common::result::TestResult;
use crate::common::security::{
	expectation_failure, ClientMaterials, GrantingAuthorizer, PayingApprover, ServerMaterials,
};
use crate::security::common::{BudgetPair, HandshakeBackendKind};
use crate::security::live::{LiveHandshake, ReceiptHooks, SMALL_BUDGETS};

const CHALLENGE: &[u8] = b"activation-invoice";
const RESPONSE: &[u8] = b"activation-preimage";

/// The hooks of a client that pays and a server whose authorizer issues a
/// challenge and keeps the default settlement, which refuses a challenged
/// receipt.
fn refusing_settlement() -> Result<ReceiptHooks, TightBeamError> {
	Ok(ReceiptHooks {
		authorizer: Some(Arc::new(GrantingAuthorizer::challenging(CHALLENGE)?)),
		approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
		observer: None,
	})
}

tb_assert_spec! {
	pub ReceiptActivationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_RECEIPT_REFUSED, exactly!(1), equals!(SETTLEMENT_UNSUPPORTED_CODE)),
			(events::SESSION_HANDSHAKE_COMPLETE, absent!())
		]
	}
}

/// A live handshake of `kind` whose settlement the authorizer refuses MUST NOT
/// activate the budget-bearing session: the server records the refused
/// settlement, and its session never reaches the encrypted phase.
async fn a_refused_settlement_leaves_the_session_inactive(
	trace: &TraceCollector,
	kind: HandshakeBackendKind,
) -> Result<(), TightBeamError> {
	let materials = ServerMaterials::fixed();
	let identity = ClientMaterials::generate().identity();
	let handshake = LiveHandshake::budget_bearing(kind, materials, identity, SMALL_BUDGETS, refusing_settlement()?);

	let outcome = handshake.audit_server(trace).run().await?;
	outcome.refused_by_server("server activated a session whose settlement its authorizer refused")
}

tb_scenario! {
	name: an_hpke_session_requires_a_settled_receipt,
	spec: ReceiptActivationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_refused_settlement_leaves_the_session_inactive(&trace, HandshakeBackendKind::Hpke).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: complete_requires_settled_receipt,
	spec: ReceiptActivationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_refused_settlement_leaves_the_session_inactive(&trace, HandshakeBackendKind::Cms).await
		}
	}
}

/// Spends `server` on `finished`, a client Finished whose settlement the
/// authorizer refuses. A server that settled would refuse a replay too, so
/// the helper checks the refusal.
async fn spent_by_a_refused_settlement(server: &mut dyn ServerHandshakeProtocol, finished: HandshakeMessage) {
	let closing = server.handle_request(finished).await;
	assert!(matches!(closing, Err(HandshakeError::SettlementRejected { .. })));
}

/// A refused settlement leaves the server handshake of `kind` spent and drops
/// the issued receipt with it, so the server refuses a replayed client
/// Finished before it reads it.
async fn a_spent_server_refuses_a_replayed_finished(kind: HandshakeBackendKind) -> TestResult {
	let materials = ServerMaterials::fixed();
	let BudgetPair { mut client, mut server } = materials.budget_pair(kind, SMALL_BUDGETS, refusing_settlement()?);
	let opening = client.start().await?;
	let reply = server.handle_request(opening).await?;
	let reply = reply.ok_or_else(|| expectation_failure("the server owes a reply to the opening"))?;
	let finished = client.handle_response(reply).await?;
	let finished = finished.ok_or_else(|| expectation_failure("the client owes a closing to the reply"))?;
	spent_by_a_refused_settlement(server.as_mut(), finished.to_owned()).await;

	let replay = server.handle_request(finished).await;
	assert!(matches!(replay, Err(HandshakeError::InvalidState)));
	Ok(())
}

/// An HPKE server spent by a refused settlement refuses a replayed Finished.
#[tokio::test]
async fn an_hpke_server_spent_by_a_refused_settlement_refuses_a_replayed_finished() -> TestResult {
	a_spent_server_refuses_a_replayed_finished(HandshakeBackendKind::Hpke).await
}

/// A CMS server spent by a refused settlement refuses a replayed Finished.
#[cfg(feature = "transport-cms")]
#[tokio::test]
async fn a_cms_server_spent_by_a_refused_settlement_refuses_a_replayed_finished() -> TestResult {
	a_spent_server_refuses_a_replayed_finished(HandshakeBackendKind::Cms).await
}

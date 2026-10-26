//! # Receipt-activation threat (CMS)
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

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::absent;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, SETTLEMENT_UNSUPPORTED_CODE};
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::TightBeamError;

use crate::common::security::{
	cms_mutual_budget_pair, ClientMaterials, CmsSessionHooks, GrantingAuthorizer, PayingApprover, ServerMaterials,
};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{LiveHandshake, ReceiptHooks};

const CHALLENGE: &[u8] = b"activation-invoice";
const RESPONSE: &[u8] = b"activation-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

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

// A CMS handshake whose settlement the authorizer refuses MUST NOT activate
// the budget-bearing session: the server records the refused settlement, and
// its session never reaches the encrypted phase.
tb_scenario! {
	name: complete_requires_settled_receipt,
	spec: ReceiptActivationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let identity = ClientMaterials::generate().identity();

			// The authorizer issues a challenge and keeps the default
			// settlement, which refuses a challenged receipt.
			let hooks = ReceiptHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenging(CHALLENGE)?)),
				approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
				observer: None,
			};

			let kind = HandshakeBackendKind::Cms;
			let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
			let outcome = handshake.audit_server(&trace).run().await?;

			outcome.refused_by_server("server activated a session whose settlement its authorizer refused")
		}
	}
}

/// A refused settlement leaves the server handshake spent and drops the
/// issued receipt with it, so the server refuses a replayed client Finished
/// before it reads it.
#[tokio::test]
async fn a_spent_server_refuses_a_replayed_finished() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let hooks = CmsSessionHooks {
		authorizer: Some(Arc::new(GrantingAuthorizer::challenging(CHALLENGE)?)),
		approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
		..CmsSessionHooks::default()
	};

	let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
	let (mut client, mut server) = (pair.client, pair.server);
	let reply = server.reply(client.start()?).await?;
	let client_finished = client.respond(reply).await?;
	let closing = server.finish(client_finished.to_owned()).await;
	assert!(
		matches!(closing, Err(HandshakeError::SettlementRejected { .. })),
		"the authorizer settled a challenged receipt"
	);

	let replay = server.finish(client_finished).await;

	assert!(
		matches!(replay, Err(HandshakeError::InvalidState)),
		"a spent server read a replayed client Finished"
	);
	Ok(())
}

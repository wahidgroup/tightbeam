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

use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::utils::urn::Urn;
use tightbeam::TightBeamError;

use crate::common::security::{
	cms_mutual_budget_pair, CmsSessionHooks, GrantingAuthorizer, PayingApprover, ServerMaterials,
};

pub(crate) const COMPLETE_FAILS_WITHOUT_SETTLEMENT: Urn<'static> =
	tightbeam::urn!("test", "event:receipt-activation/complete-fails-without-settlement");
pub(crate) const REPLAY_FAILS_WITHOUT_SETTLEMENT: Urn<'static> =
	tightbeam::urn!("test", "event:receipt-activation/replay-fails-without-settlement");
pub(crate) const SETTLEMENT_REFUSED: Urn<'static> =
	tightbeam::urn!("test", "event:receipt-activation/settlement-refused");

const CHALLENGE: &[u8] = b"activation-invoice";
const RESPONSE: &[u8] = b"activation-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

tb_assert_spec! {
	pub ReceiptActivationSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(SETTLEMENT_REFUSED, exactly!(1), equals!(true)),
			(REPLAY_FAILS_WITHOUT_SETTLEMENT, exactly!(1), equals!(true)),
			(COMPLETE_FAILS_WITHOUT_SETTLEMENT, exactly!(1), equals!(true))
		]
	}
}

// A CMS handshake whose settlement the authorizer refuses MUST NOT activate
// the budget-bearing session: the replayed client Finished and the
// completion both fail closed.
tb_scenario! {
	name: complete_requires_settled_receipt,
	spec: ReceiptActivationSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let hooks = CmsSessionHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenging(CHALLENGE)?)),
				approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
				..CmsSessionHooks::default()
			};

			let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
			let (mut client, mut server) = (pair.client, pair.server);

			// The authorizer issues a challenge and keeps the default
			// settlement, which refuses a challenged receipt.
			let reply = server.reply(client.start()?).await?;

			let client_finished = client.respond(reply).await?;
			let closing = server.finish(client_finished.to_owned()).await;
			let settlement_refused = matches!(closing, Err(HandshakeError::SettlementRejected { .. }));
			trace.event_with(SETTLEMENT_REFUSED, &[], settlement_refused)?;

			// The refused settlement left the handshake spent and dropped the
			// issued receipt with it, so the server refuses the replayed
			// Finished before it reads it.
			let replay = server.finish(client_finished).await;
			let replay_refused = matches!(replay, Err(HandshakeError::InvalidState));
			trace.event_with(REPLAY_FAILS_WITHOUT_SETTLEMENT, &[], replay_refused)?;

			let completion = server.complete();
			let completion_refused = matches!(completion, Err(HandshakeError::InvalidState));
			trace.event_with(COMPLETE_FAILS_WITHOUT_SETTLEMENT, &[], completion_refused)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

//! # Receipt-activation threat (CMS)
//!
//! ## Weakness
//! A budget-bearing session is only accountable if the dual-signed receipt
//! is completed: the server issues and signs it, the client countersigns,
//! and the server verifies the countersignature and settles. The trait
//! driver runs that acknowledgement automatically, but the orchestrator
//! also exposes an inherent `complete()` for manual drivers. If
//! `complete()` activates a metered session whenever the client Finished
//! merely verified, without confirming the countersigned receipt settled,
//! a driver that forgets the acknowledgement step activates a budget the
//! client never countersigned, defeating non-repudiation.
//!
//! ## Attack
//! A server integration processes the client Finished and calls
//! `complete()` directly, skipping `process_receipt_ack`. The session
//! carries budgets, but no `StoredReceipt` exists: there is no client
//! countersignature and no settlement. The metered session is live, yet
//! the accountable artifact the whole feature exists to produce is absent.
//!
//! ## Expected control
//! `complete()` MUST fail closed for a budget-bearing session whose
//! countersigned receipt has not been settled: a session receipt was
//! issued but no stored (dual-signed, settled) receipt was retained.
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order
//!   <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-306: Missing Authentication for Critical Function
//!   <https://cwe.mitre.org/data/definitions/306.html>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::TightBeamError;

use crate::common::security::{
	cms_mutual_budget_pair, CmsSessionHooks, GrantingAuthorizer, PayingApprover, ServerMaterials,
};

const CHALLENGE: &[u8] = b"activation-invoice";
const RESPONSE: &[u8] = b"activation-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

tb_assert_spec! {
	pub ReceiptActivationSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(complete_fails_without_settlement, exactly!(1), equals!(true))
		]
	}
}

// A manual driver that runs the CMS handshake through the client Finished
// but skips the receipt acknowledgement MUST NOT be able to activate the
// budget-bearing session: complete() fails closed.
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

			// Drive the handshake manually through the client Finished, then
			// deliberately skip process_receipt_ack.
			let key_exchange = client.build_key_exchange(vec![0xA5; 32], None)?;
			server.process_key_exchange(&key_exchange).await?;
			let server_finished = server.build_server_finished().await?;
			client.process_server_finished(&server_finished)?;
			let client_finished = client.build_client_finished().await?;
			server.process_client_finished(&client_finished)?;

			// The countersigned receipt was never acknowledged, so the
			// metered session must not activate.
			let complete_result = server.complete();
			let activation_refused = matches!(complete_result, Err(HandshakeError::CountersignatureMissing));
			trace.event_with(
				ReceiptActivationSpec::complete_fails_without_settlement,
				&[],
				activation_refused,
			)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

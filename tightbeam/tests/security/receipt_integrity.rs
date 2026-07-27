//! # Session-receipt integrity threats
//!
//! ## Weakness
//! A [`SessionReceipt`] is a dual-signed, third-party-verifiable artifact
//! attesting the budgets granted for a metered session. If the value the
//! server signs into the receipt is the raw wire request rather than the
//! value the transport actually enforces, the artifact attests a fact the
//! system does not implement: enforcement clamps every direction to
//! [`MAX_MUX_SESSION_BUDGET`] (CWE-770), but the signed receipt would carry
//! the unclamped request. Both parties then countersign a budget neither
//! endpoint will honour.
//!
//! ## Attack
//! A client offers `requested_budgets` far above the enforcement ceiling
//! against a server with no local budget ceiling configured. The server
//! grants the request verbatim, signs a receipt over the raw figure, and
//! the client countersigns. The resulting third-party-verifiable artifact
//! states a credit volume the session will never admit.
//!
//! ## Expected control
//! The budgets and credit unit bound into the receipt MUST be the same
//! values the transport enforces: the grant is clamped once, at the choke
//! point, before it enters both the transcript and the receipt, so wire
//! accept, receipt body, and enforced budget are byte-identical (SSOT).
//!
//! ## References
//! - CWE-770: Allocation of Resources Without Limits or Throttling
//!   <https://cwe.mitre.org/data/definitions/770.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use tightbeam::constants::MAX_MUX_SESSION_BUDGET;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
use tightbeam::utils::urn::Urn;
use tightbeam::TightBeamError;

use crate::common::security::expectation_failure;
use crate::transport::support::{establish_mutual_transports, MutualSessionHooks};

pub(crate) const RECEIPT_BUDGETS_WITHIN_CEILING: Urn<'static> =
	Urn::new("test", "event:receipt-integrity/receipt-budgets-within-ceiling");
pub(crate) const RECEIPT_MATCHES_ENFORCED_BUDGET: Urn<'static> =
	Urn::new("test", "event:receipt-integrity/receipt-matches-enforced-budget");

/// Client request that overshoots the enforcement ceiling in both
/// directions, so a faithful receipt must reflect the clamp.
const OVER_MAX: MuxBudgets = MuxBudgets {
	client_to_server: MAX_MUX_SESSION_BUDGET + 1000,
	server_to_client: MAX_MUX_SESSION_BUDGET + 5000,
};

tb_assert_spec! {
	pub ReceiptBudgetClampSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(RECEIPT_BUDGETS_WITHIN_CEILING, exactly!(1), equals!(true)),
			(RECEIPT_MATCHES_ENFORCED_BUDGET, exactly!(1), equals!(true))
		]
	}
}

// A budget request above the enforcement ceiling must yield a receipt
// whose budgets equal the values the transport actually enforces, not the
// raw request: the signed artifact is the single source of truth.
tb_scenario! {
	name: receipt_budgets_bound_to_enforcement,
	spec: ReceiptBudgetClampSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let client_offer = TransportOffer::mux(4).with_budgets(OVER_MAX);
			let server_offer = TransportOffer::mux(4).with_budgets(OVER_MAX);
			let hooks = MutualSessionHooks::default();
			let session = establish_mutual_transports(client_offer, server_offer, hooks).await?;

			let stored = session
				.client
				.session_receipt()
				.ok_or_else(|| expectation_failure("client must retain the receipt"))?;
			let settings = session
				.client
				.negotiated_mux()
				.ok_or_else(|| expectation_failure("client must negotiate multiplexing"))?;

			let is_client_to_server_within_ceiling = stored.receipt().budgets.client_to_server <= MAX_MUX_SESSION_BUDGET;
			let is_server_to_client_within_ceiling = stored.receipt().budgets.server_to_client <= MAX_MUX_SESSION_BUDGET;

			trace.event_with(RECEIPT_BUDGETS_WITHIN_CEILING, &[], is_client_to_server_within_ceiling && is_server_to_client_within_ceiling)?;

			// The client's send budget is the client-to-server direction;
			// its receive budget is the server-to-client direction.
			let is_budget_matched = Some(stored.receipt().budgets.client_to_server) == settings.send_budget
				&& Some(stored.receipt().budgets.server_to_client) == settings.recv_budget;
			trace.event_with(RECEIPT_MATCHES_ENFORCED_BUDGET, &[], is_budget_matched)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

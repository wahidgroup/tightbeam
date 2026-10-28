//! # Session-receipt integrity threats
//!
//! ## Weakness
//! A [`SessionReceipt`] is a dual-signed artifact that a third party can
//! verify, and it attests the budgets granted for a metered session.
//! Enforcement clamps each direction to [`MAX_MUX_SESSION_BUDGET`] (CWE-770).
//! A server that signs the raw request instead of the enforced value makes
//! both parties countersign a budget that neither endpoint honours.
//!
//! ## Attack
//! A client offers `requested_budgets` far above the enforcement ceiling to a
//! server with no local budget ceiling. The server signs a receipt over the
//! raw figure, and the client countersigns an artifact that states a credit
//! volume the session never admits.
//!
//! ## Expected control
//! The receipt MUST bind the budgets and credit unit the transport enforces.
//! Enforcement clamps the grant once, before it enters the transcript and the
//! receipt, so the transport accept, the receipt body, and the enforced
//! budget are byte-identical.
//!
//! ## References
//! - CWE-770: Allocation of Resources Without Limits or Throttling
//!   <https://cwe.mitre.org/data/definitions/770.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "transport-multiplex",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use tightbeam::constants::MAX_MUX_SESSION_BUDGET;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};
use tightbeam::TightBeamError;

use crate::common::security::expectation_failure;
use crate::transport::support::{establish_mutual_transports, MutualSessionHooks};

/// The client request that overshoots the enforcement ceiling in both
/// directions, so a faithful receipt must reflect the clamp.
const OVER_MAX: MuxBudgets = MuxBudgets {
	client_to_server: MAX_MUX_SESSION_BUDGET + 1000,
	server_to_client: MAX_MUX_SESSION_BUDGET + 5000,
};

/// A budget request above the enforcement ceiling must yield a receipt whose
/// budgets equal the values that the transport enforces. The signed artifact
/// is the single source of truth.
#[tokio::test]
async fn receipt_budgets_bound_to_enforcement() -> Result<(), TightBeamError> {
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
	let budgets = stored.receipt().budgets;

	assert!(
		budgets.client_to_server <= MAX_MUX_SESSION_BUDGET && budgets.server_to_client <= MAX_MUX_SESSION_BUDGET,
		"the receipt binds a budget above the ceiling"
	);

	// The client's send budget is the client-to-server direction. Its receive
	// budget is the server-to-client direction.
	assert_eq!(
		(Some(budgets.client_to_server), Some(budgets.server_to_client)),
		(settings.send_budget(), settings.recv_budget()),
		"the receipt and the enforced budgets differ"
	);
	Ok(())
}

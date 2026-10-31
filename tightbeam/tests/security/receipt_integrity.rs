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

#![cfg(feature = "transport-multiplex")]

use tightbeam::constants::MAX_MUX_SESSION_BUDGET;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, TransportOffer};

use crate::common::transport::{establish_mutual_transports, MutualSessionHooks, MutualTransports};

/// The client request that overshoots the enforcement ceiling in both
/// directions, so a faithful receipt must reflect the clamp.
const OVER_MAX: MuxBudgets = MuxBudgets {
	client_to_server: MAX_MUX_SESSION_BUDGET + 1000,
	server_to_client: MAX_MUX_SESSION_BUDGET + 5000,
};

/// The budgets that enforcement clamps [`OVER_MAX`] to: the ceiling in each
/// direction.
const CLAMPED: MuxBudgets = MuxBudgets {
	client_to_server: MAX_MUX_SESSION_BUDGET,
	server_to_client: MAX_MUX_SESSION_BUDGET,
};

/// A session whose client and server both request [`OVER_MAX`].
async fn over_ceiling_session() -> MutualTransports {
	let client_offer = TransportOffer::mux(4).with_budgets(OVER_MAX);
	let server_offer = TransportOffer::mux(4).with_budgets(OVER_MAX);
	let hooks = MutualSessionHooks::default();

	let session = establish_mutual_transports(client_offer, server_offer, hooks).await;
	session.expect("a session over the ceiling establishes")
}

/// A budget request above the enforcement ceiling yields a receipt that binds
/// the ceiling in each direction.
#[tokio::test]
async fn a_receipt_binds_the_clamped_budgets() {
	let session = over_ceiling_session().await;
	let budgets = session.client.session_receipt().map(|stored| stored.receipt().budgets);
	assert_eq!(budgets, Some(CLAMPED));
}

/// The transport of a session over the ceiling negotiates the clamped budgets
/// that its receipt binds. The client's send budget is the client-to-server
/// direction, and its receive budget is the server-to-client direction.
#[tokio::test]
async fn the_transport_negotiates_the_budgets_its_receipt_binds() {
	let session = over_ceiling_session().await;

	let settings = session.client.negotiated_mux();
	let negotiated = settings.map(|settings| (settings.send_budget(), settings.recv_budget()));
	assert_eq!(negotiated, Some((Some(MAX_MUX_SESSION_BUDGET), Some(MAX_MUX_SESSION_BUDGET))));
}

//! # Settlement-answer confidentiality threat (CMS)
//!
//! ## Weakness
//! The settlement answer a client attaches to its receipt
//! countersignature is a bearer secret (for example a payment preimage):
//! whoever observes it can claim the settlement. If the answer travels in
//! the cleartext client Finished, a passive network observer steals it.
//!
//! ## Attack
//! An observer captures the client Finished `SignedData` and scans it for
//! the settlement answer.
//!
//! ## Expected control
//! The answer MUST travel in an `EnvelopedData` encrypted to the server
//! certificate (RFC 5652 s6), never the cleartext wire. The server MUST
//! decrypt it, verify the countersignature over the plaintext, settle,
//! and retain the identical dual-signed receipt on both endpoints.
//!
//! ## References
//! - CWE-311: Missing Encryption of Sensitive Data
//!   <https://cwe.mitre.org/data/definitions/311.html>
//! - RFC 5652 s6: EnvelopedData provides data confidentiality
//!   <https://datatracker.ietf.org/doc/html/rfc5652#section-6>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tightbeam::asn1::OctetString;
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::SessionReceipt;
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::TightBeamError;

use crate::common::security::{
	cms_mutual_budget_pair, contains_window, CmsSessionHooks, PayingApprover, ServerMaterials,
};

const CHALLENGE: &[u8] = b"cms-conf-invoice";
const RESPONSE: &[u8] = b"cms-conf-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// Grants budgets with a settlement challenge and accepts settlement only
/// for the expected plaintext answer, counting invocations.
struct SettlingAuthorizer {
	challenge: OctetString,
	expected_response: OctetString,
	settle_calls: AtomicU32,
}

impl TransportAuthorizer for SettlingAuthorizer {
	fn authorize<'a>(
		&'a self,
		offer: &'a TransportOffer,
	) -> MaybeSendFuture<'a, Result<AuthorizationGrant, AuthorizationRefusal>> {
		Box::pin(async move {
			let challenge = self.challenge.clone();
			Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(challenge) })
		})
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
	) -> MaybeSendFuture<'a, Result<(), AuthorizationRefusal>> {
		Box::pin(async move {
			self.settle_calls.fetch_add(1, Ordering::SeqCst);

			if response == Some(self.expected_response.as_bytes()) {
				return Ok(());
			}

			Err(AuthorizationRefusal { code: u32::MAX })
		})
	}
}

tb_assert_spec! {
	pub ReceiptConfidentialitySpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(response_confidential_on_wire, exactly!(1), equals!(true)),
			(settled_with_plaintext_once, exactly!(1), equals!(true)),
			(server_recovers_plaintext_answer, exactly!(1), equals!(true)),
			(receipts_match_across_endpoints, exactly!(1), equals!(true)),
			(settled_session_activates, exactly!(1), equals!(true))
		]
	}
}

// The settlement answer must survive the CMS EnvelopedData round trip
// (client encrypts to the server certificate, server decrypts, verifies
// the countersignature over the plaintext, and settles) while never
// appearing in the cleartext client Finished bytes.
tb_scenario! {
	name: cms_response_confidential_round_trip,
	spec: ReceiptConfidentialitySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let authorizer = Arc::new(SettlingAuthorizer {
				challenge: OctetString::new(CHALLENGE)?,
				expected_response: OctetString::new(RESPONSE)?,
				settle_calls: AtomicU32::new(0),
			});
			let hooks = CmsSessionHooks {
				authorizer: Some(Arc::clone(&authorizer) as Arc<dyn TransportAuthorizer>),
				approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
				..CmsSessionHooks::default()
			};
			let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
			let (mut client, mut server) = (pair.client, pair.server);

			// Full budget-bearing handshake including the receipt
			// acknowledgement.
			let key_exchange = client.build_key_exchange(vec![0xA5; 32], None)?;
			server.process_key_exchange(&key_exchange).await?;
			let server_finished = server.build_server_finished().await?;
			client.process_server_finished(&server_finished)?;
			let client_finished = client.build_client_finished().await?;
			server.process_client_finished(&client_finished)?;
			server.process_receipt_ack(&client_finished).await?;

			// The plaintext answer must never appear in the cleartext
			// client Finished bytes: it travels in an EnvelopedData encrypted
			// to the server certificate.
			let response_leaked = contains_window(&client_finished, RESPONSE);
			trace.event_with(
				ReceiptConfidentialitySpec::response_confidential_on_wire,
				&[],
				!response_leaked,
			)?;

			// Settlement fired exactly once and saw the decrypted
			// plaintext (the settle hook refuses anything else).
			let settle_calls = authorizer.settle_calls.load(Ordering::SeqCst);
			trace.event_with(
				ReceiptConfidentialitySpec::settled_with_plaintext_once,
				&[],
				settle_calls == 1,
			)?;

			// Both endpoints retain the identical dual-signed receipt,
			// including the plaintext answer recovered from the envelope.
			let client_receipt = client.session_receipt();
			let server_receipt = server.session_receipt();
			let expected_answer = Some(OctetString::new(RESPONSE)?);
			let answer_recovered =
				server_receipt.is_some_and(|stored| stored.ancillary_response == expected_answer);
			trace.event_with(
				ReceiptConfidentialitySpec::server_recovers_plaintext_answer,
				&[],
				answer_recovered,
			)?;

			let receipts_match = client_receipt.is_some() && client_receipt == server_receipt;
			trace.event_with(
				ReceiptConfidentialitySpec::receipts_match_across_endpoints,
				&[],
				receipts_match,
			)?;

			let activated = server.complete().is_ok();
			trace.event_with(ReceiptConfidentialitySpec::settled_session_activates, &[], activated)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

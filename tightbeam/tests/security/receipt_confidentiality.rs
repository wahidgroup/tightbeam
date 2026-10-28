//! # Settlement-answer confidentiality threat (CMS)
//!
//! ## Weakness
//! The settlement answer a client attaches to its receipt
//! countersignature is a bearer secret (for example a payment preimage):
//! whoever observes it can claim the settlement. If the answer travels in
//! the client Finished in the clear, a passive network observer steals it.
//!
//! ## Attack
//! An observer captures the sealed client Finished and scans it for the
//! settlement answer.
//!
//! ## Expected control
//! The answer MUST travel sealed under the handshake secret's acknowledgement
//! key, as the `RECEIPT_ACK` attribute of the client Finished, which itself
//! travels sealed under the identity key of the same secret. The server MUST
//! open both seals, verify the countersignature over the plaintext, and
//! settle. Both endpoints MUST retain the identical dual-signed receipt.
//!
//! ## References
//! - CWE-311: Missing Encryption of Sensitive Data <https://cwe.mitre.org/data/definitions/311.html>
//! - RFC 5116 § 3.1: a nonce used once per key <https://datatracker.ietf.org/doc/html/rfc5116#section-3.1>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tightbeam::asn1::OctetString;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{
	AuthorizationGrant, AuthorizationRefusal, MuxBudgets, TransportAuthorizer, TransportOffer,
};
use tightbeam::transport::handshake::receipt::SessionReceipt;
use tightbeam::utils::marker::MaybeSendFuture;
use tightbeam::x509::Certificate;
use tightbeam::TightBeamError;

use crate::common::security::{contains_window, ClientMaterials, PayingApprover, ServerMaterials};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{LiveHandshake, ReceiptHooks, CLOSING_FRAME};

const CHALLENGE: &[u8] = b"cms-conf-invoice";
const RESPONSE: &[u8] = b"cms-conf-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// An authorizer that grants budgets with a settlement challenge, settles only
/// the expected plaintext answer, and counts the `settle` calls.
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
			let challenge = self.challenge.to_owned();
			Ok(AuthorizationGrant { budgets: offer.requested_budgets, challenge: Some(challenge) })
		})
	}

	fn settle<'a>(
		&'a self,
		_receipt: &'a SessionReceipt,
		response: Option<&'a [u8]>,
		_client: &'a Certificate,
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
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(1))
		]
	}
}

// The settlement answer must survive the sealed acknowledgement round trip
// (client seals, server opens, verifies the countersignature, and settles)
// while staying out of the client Finished bytes on the wire.
tb_scenario! {
	name: cms_response_confidential_round_trip,
	spec: ReceiptConfidentialitySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let identity = ClientMaterials::generate().identity();
			let authorizer = Arc::new(SettlingAuthorizer {
				challenge: OctetString::new(CHALLENGE)?,
				expected_response: OctetString::new(RESPONSE)?,
				settle_calls: AtomicU32::new(0),
			});
			let hooks = ReceiptHooks {
				authorizer: Some(Arc::clone(&authorizer) as Arc<dyn TransportAuthorizer>),
				approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
				observer: None,
			};

			let kind = HandshakeBackendKind::Cms;
			let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
			let outcome = handshake.audit_server(&trace).run().await?;

			// The plaintext answer MUST stay out of the client Finished bytes
			// on the wire, because it travels sealed under the handshake
			// secret.
			let client_finished = outcome.relay.frame(CLOSING_FRAME)?;
			assert!(
				!contains_window(&client_finished, RESPONSE),
				"the settlement answer crossed the wire in the clear"
			);

			// Settlement fires exactly once and sees the decrypted
			// plaintext, because the settle hook refuses anything else.
			let settle_calls = authorizer.settle_calls.load(Ordering::SeqCst);
			assert_eq!(settle_calls, 1, "settle ran other than once");

			// Both endpoints retain the identical dual-signed receipt,
			// including the plaintext answer recovered from the sealed
			// acknowledgement.
			let (client, server) = outcome.established()?;
			let client_receipt = client.session_receipt();
			let server_receipt = server.session_receipt();

			let expected_answer = OctetString::new(RESPONSE)?;
			let answer_recovered =
				server_receipt.is_some_and(|stored| stored.ancillary_response() == Some(&expected_answer));
			assert!(answer_recovered, "the server receipt lost the settlement answer");
			assert!(
				client_receipt.is_some() && client_receipt == server_receipt,
				"the endpoints hold different receipts"
			);

			Ok::<(), TightBeamError>(())
		}
	}
}

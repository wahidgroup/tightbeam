//! # Settlement-ordering threat (HPKE)
//!
//! ## Weakness
//! `TransportAuthorizer::settle` is the hook where an application performs
//! an irreversible external side effect (crediting an account, releasing a
//! good, marking an invoice paid).
//!
//! A server that settles before it finishes checking the closing spends that
//! side effect on a closing it then refuses, and the session never activates.
//!
//! ## Attack
//! A network attacker captures a victim's budget-bearing closing, an
//! `AuthEnvelopedData` whose encrypted content carries the client Finished and,
//! inside it, the sealed receipt countersignature. The countersignature covers
//! only the receipt body and the settlement answer. The attacker corrupts the
//! encrypted content and sends the closing on.
//!
//! The attack succeeds when the server settles on the corrupted closing
//! before it refuses that closing.
//!
//! ## Expected control
//! Two layers give defense in depth:
//!
//! 1. Primary: the closing is authenticated encryption under the closing key
//!    of the handshake secret, so corrupted content fails its tag. The sealed
//!    countersignature that settlement verifies is inside that content, so the
//!    server reaches the countersignature only through a successful open.
//! 2. Ordering: settlement is the last step of the server's closing, after
//!    every cheaper refusal, so `settle` fires only for a closing that passed
//!    every earlier check.
//!
//! [`Handshake::finish`] runs the server's closing in this order:
//!
//! 1. Refuse an abort alert, and decode the closing.
//! 2. Open the closing under the closing key of the handshake secret the reply derived.
//! 3. Read the key-confirmation tag and the acknowledgement, and build the offer of the client Finished.
//! 4. Verify the key-confirmation tag.
//! 5. Admit the client identity.
//! 6. Open the countersignature under the handshake secret, verify it, and call `settle`.
//!
//! The scenario proves the observable end-to-end property with three checks:
//!
//! - The plaintext settlement answer is absent from the frame of the closing.
//! - The server refuses the corrupted closing at step 2 with
//!   [`HandshakeError::SealedClosing`] of `EnvelopeError::Authentication`,
//!   which its audit trail records.
//! - The authorizer's `settle` hook records zero calls.
//!
//! Layer 1 catches the corruption, so the property holds independent of the
//! ordering. The ordering stays as hygiene, because settlement is
//! irreversible and so runs as the final validation step.
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-345: Insufficient Verification of Data Authenticity
//!   <https://cwe.mitre.org/data/definitions/345.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>

#![cfg(all(feature = "transport-hpke", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::TightBeamError;

use crate::common::security::{contains_window, ClientMaterials, PayingApprover, ServerMaterials, SettleSpyAuthorizer};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, ReceiptHooks, CLOSING_FRAME};

const CHALLENGE: &[u8] = b"settle-ordering-invoice";
const RESPONSE: &[u8] = b"settle-ordering-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

tb_assert_spec! {
	pub SettlementOrderingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("sealed-closing/authentication"))
		]
	}
}

// Before settlement runs, the server MUST reject a budget-bearing closing
// whose encrypted content is corrupted, so the authorizer's settle hook
// records zero calls.
tb_scenario! {
	name: settlement_runs_after_decrypt,
	spec: SettlementOrderingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let identity = ClientMaterials::deterministic().identity();
			let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
			let hooks = ReceiptHooks {
				authorizer: Some(Arc::clone(&authorizer) as _),
				approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
				observer: None,
			};

			// The relay corrupts the middle byte of the encrypted content,
			// which carries the sealed receipt countersignature. The tag of the
			// closing then fails, so `finish` refuses the closing before the
			// key confirmation, the admission, and the settlement side effect.
			let corrupt = AttackStep::new(CLOSING_FRAME, FrameEdit::flip_sealed_content());
			let kind = HandshakeBackendKind::Hpke;
			let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
			let outcome = handshake.audit_server(&trace).with_step(corrupt).run().await?;

			outcome.refused_by_server("server accepted a corrupted closing")?;
			assert_eq!(authorizer.settle_calls(), 0, "settle ran before the server refused the closing");

			// The paying party's settlement answer travels sealed inside the
			// closing, so for confidentiality the plaintext RESPONSE must never
			// appear in the frame of the closing.
			let closing = outcome.relay.frame(CLOSING_FRAME)?;
			assert!(!contains_window(&closing, RESPONSE), "the settlement answer crossed the wire in the clear");

			Ok::<(), TightBeamError>(())
		}
	}
}

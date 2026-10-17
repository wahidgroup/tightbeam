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
//! A network attacker captures a victim's budget-bearing [`ClientKeyExchange`],
//! whose HPKE ciphertext (`sealed_payload`) carries the sealed receipt
//! countersignature. The countersignature covers only the receipt body and the
//! settlement answer. The attacker corrupts the ciphertext and sends the key
//! exchange on.
//!
//! The attack succeeds when the server settles on the corrupted closing
//! before it refuses that closing.
//!
//! ## Expected control
//! Two layers give defense in depth:
//!
//! 1. Primary: the HPKE payload is authenticated encryption, so a corrupted
//!    `sealed_payload` fails to open under the static key. The sealed
//!    countersignature that settlement verifies is inside that payload, so
//!    the server reaches the countersignature only through a successful open.
//! 2. Ordering: settlement is the last step of the server's closing, after
//!    every cheaper refusal, so `settle` fires only for a closing that passed
//!    every earlier check.
//!
//! [`Handshake::finish`] runs the server's closing in this order:
//!
//! 1. Refuse an abort alert, and decode the [`ClientKeyExchange`] and the HPKE message it carries.
//! 2. Open the HPKE payload under the static key and the domain tag.
//! 3. Check that the payload echoes the client random of the hello, which refuses a replay.
//! 4. Derive the handshake secret, and open the sealed client identity under it.
//! 5. Verify the key-confirmation tag.
//! 6. Admit the client identity.
//! 7. Open the countersignature under the handshake secret, verify it, and call `settle`.
//!
//! The scenario proves the observable end-to-end property with three events:
//!
//! - The plaintext settlement answer is absent from the cleartext DER of the key exchange.
//! - The server refuses the corrupted closing at step 2 with [`HandshakeError::HpkeError`].
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

use tightbeam::asn1::OctetString;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, SecurityOffer, TransportOffer};
use tightbeam::transport::handshake::{ClientKeyExchange, Handshake, HandshakeError, PeerAuthentication};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

pub(crate) const CORRUPTED_KEY_EXCHANGE_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/corrupted-key-exchange-rejected");
pub(crate) const RESPONSE_CONFIDENTIAL_ON_WIRE: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/response-confidential-on-wire");
pub(crate) const SETTLE_NEVER_FIRED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/settle-never-fired");

use crate::common::security::{
	carried_closing, carried_key_exchange, contains_window, default_security_profile, expectation_failure,
	hpke_client_config, hpke_server_config, pinning_validator, ClientMaterials, PayingApprover, ServerMaterials,
	SettleSpyAuthorizer,
};

const CHALLENGE: &[u8] = b"settle-ordering-invoice";
const RESPONSE: &[u8] = b"settle-ordering-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

tb_assert_spec! {
	pub SettlementOrderingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(RESPONSE_CONFIDENTIAL_ON_WIRE, exactly!(1), equals!(true)),
			(CORRUPTED_KEY_EXCHANGE_REJECTED, exactly!(1), equals!(true)),
			(SETTLE_NEVER_FIRED, exactly!(1), equals!(true))
		]
	}
}

// Before settlement runs, the server MUST reject a budget-bearing
// ClientKeyExchange whose HPKE ciphertext is corrupted, so the authorizer's
// settle hook records zero calls.
tb_scenario! {
	name: settlement_runs_after_decrypt,
	spec: SettlementOrderingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let profile = default_security_profile();
			let client_materials = ClientMaterials::deterministic();
			let client_identity = client_materials.identity();

			let mut config = hpke_client_config(pinning_validator(&materials.certificate));
			config.flow.identity = Some(client_identity);
			config.security_offer = Some(SecurityOffer::new(vec![profile]));
			config.transport_offer = Some(TransportOffer::mux(4).with_budgets(REQUEST));
			config.receipt_approver = Some(Arc::new(PayingApprover::answering(RESPONSE)?));

			let mut client = Handshake::client(config);
			let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
			let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
			let mut server_config = hpke_server_config::<DefaultCryptoProvider>(&materials, [profile]);
			server_config.peer_authentication = PeerAuthentication::mutual([validator]);
			server_config.transport = Some(TransportOffer::mux(4));
			server_config.transport_authorizer = Some(Arc::clone(&authorizer) as _);

			let mut server = Handshake::server(server_config);
			let reply = server.reply(client.start()?).await?;
			let closing = client.respond(reply).await?;
			let client_kex_der = carried_key_exchange(closing).to_der()?;

			// The paying party's settlement answer travels inside the HPKE
			// payload sealed to the server, so for confidentiality the
			// plaintext RESPONSE must never appear in the cleartext DER of the
			// key exchange.
			let response_leaked = contains_window(&client_kex_der, RESPONSE);
			trace.event_with(
				RESPONSE_CONFIDENTIAL_ON_WIRE,
				&[],
				!response_leaked,
			)?;

			// Corrupt the last byte of the HPKE ciphertext, which sits in the
			// AEAD tag. The ciphertext carries the sealed receipt
			// countersignature, so the server must open it before it can
			// settle, and that open must fail.
			let mut kex = ClientKeyExchange::from_der(&client_kex_der)?;
			let mut ciphertext = kex.sealed_payload.as_bytes().to_vec();
			let last = ciphertext.len().checked_sub(1).ok_or_else(|| expectation_failure("empty ciphertext"))?;

			ciphertext[last] ^= 0xFF;
			kex.sealed_payload = OctetString::new(ciphertext)?;

			// The payload is authenticated encryption, so the static key fails
			// to open it, and `finish` refuses the closing before the key
			// confirmation, the admission, and the settlement side effect.
			let kex_result = server.finish(carried_closing(&kex)).await;
			let rejected = matches!(kex_result, Err(HandshakeError::HpkeError(_)));

			trace.event_with(CORRUPTED_KEY_EXCHANGE_REJECTED, &[], rejected)?;
			trace.event_with(SETTLE_NEVER_FIRED, &[], authorizer.settle_calls() == 0)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

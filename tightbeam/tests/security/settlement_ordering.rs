//! # Settlement-ordering threat (ECIES)
//!
//! ## Weakness
//! `TransportAuthorizer::settle` is the hook where an application performs
//! an irreversible external side effect (crediting an account, releasing a
//! good, marking an invoice paid).
//!
//! Suppose the server verifies the client's receipt countersignature and
//! settles *before* it has decrypted the key exchange and confirmed the
//! client random. An attacker can then drive settlement with a key exchange
//! the server will reject. The payload never establishes a session, but the
//! side effect already fired.
//!
//! ## Attack
//! A network attacker captures a victim's budget-bearing `ClientKeyExchange`:
//! the certificate, the transcript-bound auth signature, and the ECIES
//! ciphertext (`encrypted_data`). The ciphertext carries the sealed receipt
//! countersignature, which covers only the receipt body and the settlement
//! answer. The attacker corrupts the ciphertext and keeps the rest.
//!
//! If the server settles before decrypting, the corrupted payload triggers
//! settlement and only afterwards fails the AEAD check. The attacker has
//! forced a settlement against a session that never activates.
//!
//! ## Expected control
//! Two layers give defense in depth:
//!
//! 1. Primary: the ECIES client auth signature covers
//!    `Digest(transcript_hash || encrypted_data || cert_der)`, so a corrupted
//!    `encrypted_data` fails the proof of possession when the server admits
//!    the client, before decryption and before settlement.
//! 2. Ordering: `settle` runs strictly after decryption and the client random
//!    replay check, so it is the last gate and no external side effect can be
//!    provoked by a key exchange the server will reject.
//!
//! This test proves the observable end-to-end property: a corrupted
//! budget-bearing key exchange is rejected and the authorizer's `settle`
//! hook never fires. Layer 1 catches the corruption, so the property holds
//! independent of the ordering. The ordering stays as hygiene, because
//! settlement is irreversible and so is the final validation step.
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-multiplex",
	feature = "testing"
))]

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
use tightbeam::utils::urn::Urn;
use tightbeam::TightBeamError;

pub(crate) const CORRUPTED_KEY_EXCHANGE_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/corrupted-key-exchange-rejected");
pub(crate) const RESPONSE_CONFIDENTIAL_ON_WIRE: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/response-confidential-on-wire");
pub(crate) const SETTLE_NEVER_FIRED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/settle-never-fired");

use crate::common::security::{
	carried_closing, carried_key_exchange, contains_window, default_security_profile, ecies_client_config,
	ecies_server_config, expectation_failure, pinning_validator, ClientMaterials, PayingApprover, ServerMaterials,
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

// A budget-bearing ClientKeyExchange whose ECIES ciphertext is corrupted MUST
// be rejected before settlement runs: the authorizer's settle hook records
// zero calls.
tb_scenario! {
	name: settlement_runs_after_decrypt,
	spec: SettlementOrderingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let profile = default_security_profile();
			let client_materials = ClientMaterials::deterministic();
			let client_identity = client_materials.identity();

			let mut config = ecies_client_config(pinning_validator(&materials.certificate));
			config.flow.identity = Some(client_identity);
			config.security_offer = Some(SecurityOffer::new(vec![profile]));
			config.transport_offer = Some(TransportOffer::mux(4).with_budgets(REQUEST));
			config.receipt_approver = Some(Arc::new(PayingApprover::answering(RESPONSE)?));

			let mut client = Handshake::client(config);
			let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
			let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
			let mut server_config = ecies_server_config::<DefaultCryptoProvider>(&materials, [profile]);
			server_config.peer_authentication = PeerAuthentication::mutual([validator]);
			server_config.transport = Some(TransportOffer::mux(4));
			server_config.transport_authorizer = Some(Arc::clone(&authorizer) as _);

			let mut server = Handshake::server(server_config);
			let reply = server.reply(client.start()?).await?;
			let closing = client.respond(reply).await?;
			let client_kex_der = carried_key_exchange(closing).to_der()?;

			// Confidentiality: the paying party's settlement answer is
			// folded into the ECIES payload encrypted to the server, so the
			// plaintext RESPONSE must never appear in the cleartext key
			// exchange wire bytes.
			let response_leaked = contains_window(&client_kex_der, RESPONSE);
			trace.event_with(
				RESPONSE_CONFIDENTIAL_ON_WIRE,
				&[],
				!response_leaked,
			)?;

			// Corrupt the ECIES ciphertext and keep the certificate and the
			// auth signature. The ciphertext carries the sealed receipt
			// countersignature, so the server must refuse the key exchange
			// before it opens the payload or settles.
			let mut kex = ClientKeyExchange::from_der(&client_kex_der)?;
			let mut ciphertext = kex.encrypted_data.as_bytes().to_vec();
			let last = ciphertext.len().checked_sub(1).ok_or_else(|| expectation_failure("empty ciphertext"))?;

			ciphertext[last] ^= 0xFF;
			kex.encrypted_data = OctetString::new(ciphertext)?;

			// The mutual-auth signature commits to the exact ciphertext
			// (the anti-splice control), so the corruption is caught as a
			// signature failure before any decrypt or settlement side effect.
			let kex_result = server.finish(carried_closing(&kex)).await;
			let rejected = matches!(kex_result, Err(HandshakeError::SignatureError(_)));

			trace.event_with(CORRUPTED_KEY_EXCHANGE_REJECTED, &[], rejected)?;
			trace.event_with(SETTLE_NEVER_FIRED, &[], authorizer.settle_calls() == 0)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

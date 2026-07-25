//! # Settlement-ordering threat (ECIES)
//!
//! ## Weakness
//! `TransportAuthorizer::settle` is the hook where an application performs
//! an irreversible external side effect (crediting an account, releasing a
//! good, marking an invoice paid). If the server verifies the client's
//! receipt countersignature and settles *before* it has decrypted the key
//! exchange and confirmed the client random, an attacker can drive
//! settlement with a key exchange the server will then reject: the payload
//! never establishes a session, but the side effect already fired.
//!
//! ## Attack
//! A network attacker captures a victim's budget-bearing
//! `ClientKeyExchange` (certificate, transcript-bound auth signature, and
//! the receipt countersignature). The countersignature covers only the
//! receipt body and settlement answer, not the ECIES `encrypted_data`, so
//! the attacker splices in a corrupted ciphertext. If the server settles
//! before decrypting, the corrupted payload triggers settlement and only
//! afterwards fails the AEAD check. The attacker has forced a settlement
//! against a session that never activates.
//!
//! ## Expected control
//! Two layers, defense in depth:
//! 1. Primary: the ECIES client auth signature covers
//!    `Digest(transcript_hash || encrypted_data || cert_der)`, so any
//!    corruption of `encrypted_data` is rejected at certificate validation
//!    before decryption and before settlement.
//! 2. Ordering: `settle` runs strictly after decryption and the client
//!    random replay check, so it is the last gate and no external side
//!    effect can be provoked by a key exchange the server will reject.
//!
//! This test proves the observable end-to-end property: a corrupted
//! budget-bearing key exchange is rejected and the authorizer's `settle`
//! hook never fires. The corruption is caught by layer 1, so the property
//! holds independent of the ordering. The ordering is retained as hygiene
//! (settlement, being irreversible, is the final validation step).
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order
//!   <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-94: Adversary in the Middle (AiTM)
//!   <https://capec.mitre.org/data/definitions/94.html>

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-multiplex",
	feature = "testing"
))]

use std::sync::Arc;

use tightbeam::asn1::OctetString;
use tightbeam::crypto::ecies::Secp256k1EciesMessage;
use tightbeam::crypto::key::{Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::Secp256k1SigningKey;
use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::utils::{create_test_certificate, create_test_signing_key};
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, SecurityOffer, TransportOffer};
use tightbeam::transport::handshake::{
	client::EciesHandshakeClient, server::EciesHandshakeServer, ClientKeyExchange, HandshakeError,
};
use tightbeam::TightBeamError;

use crate::common::security::{
	contains_window, default_security_profile, expectation_failure, pinning_validator, PayingApprover, ServerMaterials,
	SettleSpyAuthorizer,
};

const CHALLENGE: &[u8] = b"settle-ordering-invoice";
const RESPONSE: &[u8] = b"settle-ordering-preimage";
const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

tb_assert_spec! {
	pub SettlementOrderingSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(response_confidential_on_wire, exactly!(1), equals!(true)),
			(corrupted_key_exchange_rejected, exactly!(1), equals!(true)),
			(settle_never_fired, exactly!(1), equals!(true))
		]
	}
}

// A budget-bearing ClientKeyExchange whose ECIES ciphertext is corrupted
// (countersignature still valid, since it never covered the ciphertext)
// MUST be rejected before settlement runs: the authorizer's settle hook
// records zero calls.
tb_scenario! {
	name: settlement_runs_after_decrypt,
	spec: SettlementOrderingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let profile = default_security_profile();

			let client_signing = create_test_signing_key();
			let client_cert = Arc::new(create_test_certificate(&client_signing));
			let signing_key = Secp256k1SigningKey::from(client_signing);
			let client_provider: Arc<dyn SigningKeyProvider> = Arc::new(Secp256k1KeyProvider::from(signing_key));

			let mut client = EciesHandshakeClient::<DefaultCryptoProvider, Secp256k1EciesMessage>::new(None)
				.with_security_offer(SecurityOffer::new(vec![profile]))
				.with_certificate_validator(pinning_validator(&materials.certificate))
				.with_client_identity(Arc::clone(&client_cert), client_provider)
				.with_transport_offer(TransportOffer::mux(4).with_budgets(REQUEST))
				.with_receipt_approver(Arc::new(PayingApprover::answering(RESPONSE)?));

			let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
			let validators: Arc<Vec<Arc<dyn CertificateValidation>>> = Arc::new(vec![Arc::new(ExpiryValidator)]);
			let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
				Arc::clone(&materials.key_provider),
				Arc::clone(&materials.certificate),
				None,
				Some(validators),
			)
			.with_supported_profiles(vec![profile])
			.with_transport_config(TransportOffer::mux(4))
			.with_transport_authorizer(Arc::clone(&authorizer) as _);

			let client_hello = client.build_client_hello()?;
			let server_handshake = server.process_client_hello(&client_hello).await?;
			let client_kex_der = client.process_server_handshake(&server_handshake).await?;

			// Confidentiality: the paying party's settlement answer is
			// folded into the ECIES payload encrypted to the server, so the
			// plaintext RESPONSE must never appear in the cleartext key
			// exchange wire bytes.
			let response_leaked = contains_window(&client_kex_der, RESPONSE);
			trace.event_with(
				SettlementOrderingSpec::response_confidential_on_wire,
				&[],
				!response_leaked,
			)?;

			// Corrupt the ECIES ciphertext while preserving the certificate,
			// auth signature, and receipt countersignature: decrypt must fail,
			// but the countersignature (which never covered the ciphertext)
			// stays valid.
			let mut kex = ClientKeyExchange::from_der(&client_kex_der)?;
			let mut ciphertext = kex.encrypted_data.as_bytes().to_vec();
			let last = ciphertext.len().checked_sub(1).ok_or_else(|| expectation_failure("empty ciphertext"))?;

			ciphertext[last] ^= 0xFF;
			kex.encrypted_data = OctetString::new(ciphertext)?;

			// The mutual-auth signature commits to the exact ciphertext
			// (the anti-splice control), so the corruption is caught as a
			// signature failure before any decrypt or settlement side effect.
			let corrupted = kex.to_der()?;
			let kex_result = server.process_client_key_exchange(&corrupted).await;
			let rejected = matches!(kex_result, Err(HandshakeError::SignatureError(_)));
			trace.event_with(SettlementOrderingSpec::corrupted_key_exchange_rejected, &[], rejected)?;

			trace.event_with(SettlementOrderingSpec::settle_never_fired, &[], authorizer.settle_calls() == 0)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

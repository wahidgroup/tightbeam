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
//! The scenario proves the observable end-to-end property with three events:
//!
//! - The plaintext settlement answer is absent from the DER of the closing.
//! - The server refuses the corrupted closing at step 2 with [`HandshakeError::SealedClosing`].
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

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
use tightbeam::exactly;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::{MuxBudgets, SecurityOffer, TransportOffer};
use tightbeam::transport::handshake::{Handshake, HandshakeError, HandshakeMessage, PeerAuthentication};
use tightbeam::urn::Urn;
use tightbeam::TightBeamError;

pub(crate) const CORRUPTED_CLOSING_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/corrupted-closing-rejected");
pub(crate) const RESPONSE_CONFIDENTIAL_ON_WIRE: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/response-confidential-on-wire");
pub(crate) const SETTLE_NEVER_FIRED: Urn<'static> =
	tightbeam::urn!("test", "event:settlement-ordering/settle-never-fired");

use crate::common::security::{
	contains_window, default_security_profile, flip_sealed_content, hpke_client_config_presenting, hpke_server_config,
	pinning_validator, ClientMaterials, PayingApprover, ServerMaterials, SettleSpyAuthorizer,
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
			(CORRUPTED_CLOSING_REJECTED, exactly!(1), equals!(true)),
			(SETTLE_NEVER_FIRED, exactly!(1), equals!(true))
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
			let profile = default_security_profile();
			let client_materials = ClientMaterials::deterministic();
			let client_identity = client_materials.identity();

			let validator = pinning_validator(&materials.certificate);
			let mut config = hpke_client_config_presenting::<DefaultCryptoProvider>(validator, client_identity);
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

			// The paying party's settlement answer travels sealed inside the
			// closing, so for confidentiality the plaintext RESPONSE must never
			// appear in the DER of the closing.
			let response_leaked = contains_window(closing.der(), RESPONSE);
			trace.event_with(
				RESPONSE_CONFIDENTIAL_ON_WIRE,
				&[],
				!response_leaked,
			)?;

			// Corrupt the middle byte of the encrypted content. The content
			// carries the sealed receipt countersignature, so the server must
			// open it before it can settle, and that open must fail.
			let sealed = closing.auth_enveloped()?;
			let corrupted = flip_sealed_content(sealed.value())?;

			// The closing is authenticated encryption, so its tag fails, and
			// `finish` refuses the closing before the key confirmation, the
			// admission, and the settlement side effect.
			let closing_result = server.finish(HandshakeMessage::try_from(corrupted)?).await;
			let rejected = matches!(closing_result, Err(HandshakeError::SealedClosing(_)));

			trace.event_with(CORRUPTED_CLOSING_REJECTED, &[], rejected)?;
			trace.event_with(SETTLE_NEVER_FIRED, &[], authorizer.settle_calls() == 0)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

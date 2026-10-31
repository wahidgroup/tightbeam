//! # Settlement-ordering threat (HPKE)
//!
//! ## Weakness
//! `TransportAuthorizer::settle` is the hook where an application performs an
//! irreversible external side effect (crediting an account, releasing a good,
//! marking an invoice paid). A server that settles before it admits the client
//! spends that side effect on a session it then refuses.
//!
//! ## Attack
//! A client holds the handshake secret, so its key-confirmation tag verifies,
//! and it countersigns the receipt with a valid settlement answer. Its
//! certificate fails the server policy. The attack succeeds when the server
//! settles before that policy refuses the client.
//!
//! ## Expected control
//! [`Handshake::finish`] runs the server's closing in this order:
//!
//! 1. Refuse an abort alert, and decode the closing.
//! 2. Open the closing under the closing key of the handshake secret the reply derived.
//! 3. Verify the key-confirmation tag, and read the acknowledgement and the offer.
//! 4. Admit the client identity under every validator.
//! 5. Open the countersignature under the handshake secret, verify it, and call `settle`.
//!
//! Settlement is the last step, so a client that fails step 4 reaches no
//! settlement: the server refuses with `CertificateDenied`, which its audit
//! trail records, the authorizer's `settle` hook records zero calls, and the
//! observer records no outcome, because the exchange never concluded.
//!
//! ## References
//! - CWE-696: Incorrect Behavior Order <https://cwe.mitre.org/data/definitions/696.html>
//! - CWE-285: Improper Authorization <https://cwe.mitre.org/data/definitions/285.html>

#![cfg(all(feature = "transport-hpke", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::absent;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::TightBeamError;

use crate::common::security::{ClientMaterials, ServerMaterials};
use crate::security::common::{HandshakeBackendKind, RejectAllValidator};
use crate::security::live::{LiveHandshake, PayingHooks, ReceiptHooks, SMALL_BUDGETS};

const CHALLENGE: &[u8] = b"settle-ordering-invoice";
const RESPONSE: &[u8] = b"settle-ordering-preimage";

tb_assert_spec! {
	pub SettlementOrderingSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/certificate-denied")),
			(events::SESSION_RECEIPT_SETTLED, absent!())
		]
	}
}

// The server MUST admit the client before it settles, so a client that its
// policy refuses reaches no settlement and leaves no outcome.
tb_scenario! {
	name: settlement_waits_for_the_admission_of_the_client,
	spec: SettlementOrderingSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let identity = ClientMaterials::fixed().identity();
			let PayingHooks { authorizer, observer, hooks } = ReceiptHooks::paying(CHALLENGE, RESPONSE)?;

			// The server policy refuses every certificate, so the admission of
			// the client is the check that stops the closing, after the tag and
			// before the settlement side effect.
			let refusing: Arc<dyn CertificateValidation> = Arc::new(RejectAllValidator);
			let kind = HandshakeBackendKind::Hpke;
			let handshake = LiveHandshake::budget_bearing(kind, materials, identity, SMALL_BUDGETS, hooks);
			let outcome = handshake.with_client_validators([refusing]).audit_server(&trace).run().await?;

			outcome.refused_by_server("server activated a session of a client its policy refuses")?;
			assert_eq!(authorizer.settle_calls(), 0);
			assert!(observer.recorded().is_empty());

			Ok::<(), TightBeamError>(())
		}
	}
}

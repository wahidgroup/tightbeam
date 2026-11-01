//! # Countersignature-evidence threat (audit-trail completeness)
//!
//! ## Weakness
//! The [`SessionObserver`] contract promises the server a record of every
//! budget-bearing session whose receipt exchange concluded.
//!
//! A countersignature can fail verification, or a client can withhold it. If
//! either case aborts the handshake before the observer fires, the most
//! suspicious terminal states are invisible to the application ledger. Those
//! states are forged-countersignature probes and withheld countersignatures.
//!
//! ## Attack
//! An attacker tampers with the carriage of a budget-bearing receipt
//! acknowledgement, which travels sealed in both protocols, or a client
//! withholds its acknowledgement. The handshake aborts as it should, but the
//! operator's ledger stays silent: repeated probes leave no evidence.
//!
//! ## Expected control
//! Every concluded receipt exchange MUST reach the observer before the
//! abort:
//!
//! - An absent acknowledgement records `SessionVerdict::CountersignatureMissing`.
//! - A failing acknowledgement records `SessionVerdict::CountersignatureInvalid`.
//! - Settlement MUST stay unfired and the session MUST stay inactive.
//!
//! The observer records a concluded exchange. A flipped byte of the sealed
//! closing stops the exchange, so the ledger stays empty. A countersignature
//! that fails to verify under the true secret concludes it, so the observer
//! records `CountersignatureInvalid`. The CMS flow tests cover a withheld
//! acknowledgement, which sits inside the sealed closing of its client.
//!
//! ## References
//! - CWE-778: Insufficient Logging <https://cwe.mitre.org/data/definitions/778.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(feature = "transport-multiplex", feature = "testing"))]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tightbeam::absent;
use tightbeam::crypto::key::{KeyBackend, KeyError, SigningKeyProvider};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::spki::AlgorithmIdentifierOwned;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::handshake::receipt::SessionVerdict;
use tightbeam::TightBeamError;

use crate::common::security::{ClientMaterials, ServerMaterials};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{
	AttackStep, FrameEdit, LiveHandshake, PayingHooks, ReceiptHooks, CLOSING_FRAME, SMALL_BUDGETS,
};

const CHALLENGE: &[u8] = b"evidence-invoice";
const RESPONSE: &[u8] = b"evidence-preimage";

tb_assert_spec! {
	pub CountersignatureTamperSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("sealed-closing/authentication")),
			(events::SESSION_HANDSHAKE_COMPLETE, absent!())
		]
	}
}

tb_assert_spec! {
	pub CountersignatureForgedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("signature")),
			(events::SESSION_HANDSHAKE_COMPLETE, absent!())
		]
	}
}

/// A client key that signs another prehash on its first call, the
/// countersignature, and the prehash it receives on each later call. So the
/// client Finished verifies, and the countersignature alone fails.
#[derive(Debug)]
struct ForgedCountersignature {
	/// The key of the client certificate.
	key: Arc<dyn SigningKeyProvider>,
	/// Whether the key has made the forged signature.
	forged: AtomicBool,
}

impl KeyBackend for ForgedCountersignature {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.key.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.key.to_public_key_bytes()
	}
}

impl SigningKeyProvider for ForgedCountersignature {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let first = !self.forged.swap(true, Ordering::SeqCst);
		let mut signed = prehash.to_vec();
		if let Some(octet) = signed.first_mut().filter(|_| first) {
			*octet ^= 0xFF;
		}

		Box::pin(async move { self.key.sign_prehash(&signed).await })
	}
}

/// A budget-bearing handshake of `kind` whose client seals a countersignature
/// that fails to verify. The server refuses, settles nothing, and records the
/// concluded exchange.
async fn a_forged_countersignature_reaches_the_observer(
	trace: &TraceCollector,
	kind: HandshakeBackendKind,
) -> Result<(), TightBeamError> {
	let client = ClientMaterials::fixed();
	let key = ForgedCountersignature { key: client.key_provider, forged: AtomicBool::new(false) };
	let identity = SigningIdentity::new(client.certificate, Arc::new(key))?;
	let PayingHooks { authorizer, observer, hooks } = ReceiptHooks::paying(CHALLENGE, RESPONSE)?;

	let materials = ServerMaterials::fixed();
	let handshake = LiveHandshake::budget_bearing(kind, materials, identity, SMALL_BUDGETS, hooks);

	let outcome = handshake.audit_server(trace).run().await?;
	outcome.refused_by_server("server accepted a forged countersignature")?;
	assert_eq!(authorizer.settle_calls(), 0);

	let verdicts: Vec<SessionVerdict> = observer.recorded().into_iter().map(|outcome| outcome.verdict).collect();
	assert_eq!(verdicts, [SessionVerdict::CountersignatureInvalid]);
	Ok(())
}

/// A budget-bearing handshake of `kind` whose closing a MITM corrupts in
/// transit. The closing is authenticated encryption, and a flipped content
/// byte is the one wire handle a MITM has on the sealed acknowledgement, so
/// the server refuses the closing, settles nothing, and the receipt exchange
/// reaches no verdict for the observer to record.
async fn a_tampered_closing_leaves_no_evidence(
	trace: &TraceCollector,
	kind: HandshakeBackendKind,
) -> Result<(), TightBeamError> {
	let identity = ClientMaterials::fixed().identity();
	let PayingHooks { authorizer, observer, hooks } = ReceiptHooks::paying(CHALLENGE, RESPONSE)?;
	let tamper = AttackStep::new(CLOSING_FRAME, FrameEdit::flip_sealed_content());
	let materials = ServerMaterials::fixed();
	let handshake = LiveHandshake::budget_bearing(kind, materials, identity, SMALL_BUDGETS, hooks);

	let outcome = handshake.audit_server(trace).with_step(tamper).run().await?;
	outcome.refused_by_server("server accepted a tampered closing")?;
	assert_eq!(authorizer.settle_calls(), 0);
	assert!(observer.recorded().is_empty());
	Ok(())
}

#[cfg(feature = "transport-hpke")]
tb_scenario! {
	name: hpke_tampered_countersignature_carriage_rejected,
	spec: CountersignatureTamperSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_tampered_closing_leaves_no_evidence(&trace, HandshakeBackendKind::Hpke).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: cms_tampered_countersignature_carriage_rejected,
	spec: CountersignatureTamperSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_tampered_closing_leaves_no_evidence(&trace, HandshakeBackendKind::Cms).await
		}
	}
}

#[cfg(feature = "transport-hpke")]
tb_scenario! {
	name: hpke_forged_countersignature_reaches_the_observer,
	spec: CountersignatureForgedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_forged_countersignature_reaches_the_observer(&trace, HandshakeBackendKind::Hpke).await
		}
	}
}

#[cfg(feature = "transport-cms")]
tb_scenario! {
	name: cms_forged_countersignature_reaches_the_observer,
	spec: CountersignatureForgedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			a_forged_countersignature_reaches_the_observer(&trace, HandshakeBackendKind::Cms).await
		}
	}
}

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
//! The observer records a concluded exchange, so a tamper rejected before the
//! exchange concludes leaves the ledger unchanged.
//!
//! These scenarios tamper with the sealed closing of each protocol. A client
//! withholds its acknowledgement inside its own sealed closing, so the CMS flow
//! tests cover that case.
//!
//! ## References
//! - CWE-778: Insufficient Logging <https://cwe.mitre.org/data/definitions/778.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(feature = "transport-multiplex", feature = "testing"))]

use tightbeam::absent;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::tb_assert_spec;

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

#[cfg(feature = "transport-hpke")]
mod hpke {
	use std::sync::Arc;

	use super::CountersignatureTamperSpec;

	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::TightBeamError;

	use crate::common::security::{
		ClientMaterials, PayingApprover, RecordingObserver, ServerMaterials, SettleSpyAuthorizer,
	};
	use crate::security::common::HandshakeBackendKind;
	use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, ReceiptHooks, CLOSING_FRAME};

	const CHALLENGE: &[u8] = b"evidence-invoice";
	const RESPONSE: &[u8] = b"evidence-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	tb_scenario! {
		name: hpke_tampered_countersignature_carriage_rejected,
		spec: CountersignatureTamperSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let materials = ServerMaterials::generate();
				let identity = ClientMaterials::deterministic().identity();
				let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
				let observer = Arc::new(RecordingObserver::default());
				let hooks = ReceiptHooks {
					authorizer: Some(Arc::clone(&authorizer) as _),
					approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
					observer: Some(Arc::clone(&observer) as Arc<dyn SessionObserver>),
				};

				// The closing is authenticated encryption, and a flipped
				// content byte is the only wire handle a MITM has on the
				// sealed acknowledgement.
				let tamper = AttackStep::new(CLOSING_FRAME, FrameEdit::flip_sealed_content());
				let kind = HandshakeBackendKind::Hpke;
				let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
				let outcome = handshake.audit_server(&trace).with_step(tamper).run().await?;

				outcome.refused_by_server("server accepted a tampered closing")?;
				assert_eq!(authorizer.settle_calls(), 0, "settle ran for a closing the server refused");

				// The receipt exchange reaches no verdict, so the observer
				// ledger stays empty.
				assert!(
					observer.recorded().is_empty(),
					"the observer ledger holds an outcome for an exchange that never concluded"
				);

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

#[cfg(feature = "transport-cms")]
mod cms {
	use std::sync::Arc;

	use super::CountersignatureTamperSpec;

	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::TightBeamError;

	use crate::common::security::{
		ClientMaterials, PayingApprover, RecordingObserver, ServerMaterials, SettleSpyAuthorizer,
	};
	use crate::security::common::HandshakeBackendKind;
	use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, ReceiptHooks, CLOSING_FRAME};

	const CHALLENGE: &[u8] = b"evidence-cms-invoice";
	const RESPONSE: &[u8] = b"evidence-cms-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	tb_scenario! {
		name: cms_tampered_countersignature_carriage_rejected,
		spec: CountersignatureTamperSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let materials = ServerMaterials::generate();
				let identity = ClientMaterials::generate().identity();
				let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
				let observer = Arc::new(RecordingObserver::default());
				let hooks = ReceiptHooks {
					authorizer: Some(Arc::clone(&authorizer) as _),
					approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
					observer: Some(Arc::clone(&observer) as Arc<dyn SessionObserver>),
				};

				let tamper = AttackStep::new(CLOSING_FRAME, FrameEdit::flip_sealed_content());
				let kind = HandshakeBackendKind::Cms;
				let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
				let outcome = handshake.audit_server(&trace).with_step(tamper).run().await?;

				outcome.refused_by_server("server accepted a tampered client Finished")?;
				assert_eq!(authorizer.settle_calls(), 0, "settle ran for a closing the server refused");

				// The receipt exchange reaches no verdict, so the observer
				// ledger stays empty.
				assert!(
					observer.recorded().is_empty(),
					"the observer ledger holds an outcome for an exchange that never concluded"
				);

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

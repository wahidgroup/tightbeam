//! # Countersignature-evidence threat (audit-trail completeness)
//!
//! ## Weakness
//! The [`SessionObserver`] contract promises the server a record of every
//! budget-bearing session whose receipt exchange concluded.
//!
//! A countersignature can fail verification or be withheld. If either case
//! aborts the handshake before the observer fires, the most suspicious
//! terminal states are invisible to the application ledger. Those states are
//! forged-countersignature probes and withheld countersignatures.
//!
//! ## Attack
//! An attacker tampers with the carriage of a budget-bearing receipt
//! acknowledgement, which travels sealed in both protocols, or a client
//! withholds its acknowledgement. The handshake correctly aborts, but the
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

use tightbeam::urn::Urn;

pub(crate) const NO_OUTCOME_BEFORE_CONCLUSION: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/no-outcome-before-conclusion");
pub(crate) const SESSION_NEVER_ACTIVATES: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/session-never-activates");
pub(crate) const SETTLE_NEVER_FIRED: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/settle-never-fired");
pub(crate) const TAMPERED_CIPHERTEXT_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/tampered-ciphertext-rejected");

#[cfg(feature = "transport-hpke")]
mod hpke {
	use std::sync::Arc;

	use super::{
		NO_OUTCOME_BEFORE_CONCLUSION, SESSION_NEVER_ACTIVATES, SETTLE_NEVER_FIRED, TAMPERED_CIPHERTEXT_REJECTED,
	};

	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use tightbeam::exactly;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, SecurityOffer, TransportOffer};
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::transport::handshake::{Handshake, HandshakeError, HandshakeMessage, PeerAuthentication};
	use tightbeam::TightBeamError;

	use crate::common::security::{
		default_security_profile, flip_sealed_content, hpke_client_config_presenting, hpke_server_config,
		pinning_validator, ClientMaterials, PayingApprover, RecordingObserver, ServerMaterials, SettleSpyAuthorizer,
	};

	const CHALLENGE: &[u8] = b"evidence-invoice";
	const RESPONSE: &[u8] = b"evidence-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	tb_assert_spec! {
		pub CountersignatureTamperSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(TAMPERED_CIPHERTEXT_REJECTED, exactly!(1), equals!(true)),
				(SETTLE_NEVER_FIRED, exactly!(1), equals!(true)),
				(NO_OUTCOME_BEFORE_CONCLUSION, exactly!(1), equals!(true)),
				(SESSION_NEVER_ACTIVATES, exactly!(1), equals!(true))
			]
		}
	}

	tb_scenario! {
		name: hpke_tampered_countersignature_carriage_rejected,
		spec: CountersignatureTamperSpec,
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
				let observer = Arc::new(RecordingObserver::default());
				let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
				let mut server_config = hpke_server_config::<DefaultCryptoProvider>(&materials, [profile]);
				server_config.peer_authentication = PeerAuthentication::mutual([validator]);
				server_config.transport = Some(TransportOffer::mux(4));
				server_config.transport_authorizer = Some(Arc::clone(&authorizer) as _);
				server_config.session_observer = Some(Arc::clone(&observer) as Arc<dyn SessionObserver>);

				let mut server = Handshake::server(server_config);
				let reply = server.reply(client.start()?).await?;
				let sealed_closing = client.respond(reply).await?.auth_enveloped()?;

				// The closing is authenticated encryption, and a flipped
				// content byte is the only wire handle a MITM has on the
				// sealed acknowledgement.
				let tampered = flip_sealed_content(sealed_closing.value())?;

				let closing = server.finish(HandshakeMessage::try_from(tampered)?).await;
				let rejected = matches!(closing, Err(HandshakeError::SealedClosing(_)));
				trace.event_with(TAMPERED_CIPHERTEXT_REJECTED, &[], rejected)?;

				let unsettled = authorizer.settle_calls() == 0;
				trace.event_with(SETTLE_NEVER_FIRED, &[], unsettled)?;

				// The receipt exchange reached no verdict, so the observer
				// ledger stays empty.
				let outcomes = observer.recorded();
				trace.event_with(NO_OUTCOME_BEFORE_CONCLUSION, &[], outcomes.is_empty())?;

				let inactive = matches!(server.complete(), Err(HandshakeError::InvalidState));
				trace.event_with(SESSION_NEVER_ACTIVATES, &[], inactive)?;

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

#[cfg(feature = "transport-cms")]
mod cms {
	use std::sync::Arc;

	use super::{
		NO_OUTCOME_BEFORE_CONCLUSION, SESSION_NEVER_ACTIVATES, SETTLE_NEVER_FIRED, TAMPERED_CIPHERTEXT_REJECTED,
	};

	use tightbeam::exactly;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::transport::handshake::{HandshakeError, HandshakeMessage};
	use tightbeam::TightBeamError;

	use crate::common::security::{
		cms_mutual_budget_pair, flip_sealed_content, CmsSessionHooks, PayingApprover, RecordingObserver,
		ServerMaterials, SettleSpyAuthorizer,
	};

	const CHALLENGE: &[u8] = b"evidence-cms-invoice";
	const RESPONSE: &[u8] = b"evidence-cms-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	tb_assert_spec! {
		pub CmsCountersignatureTamperSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(TAMPERED_CIPHERTEXT_REJECTED, exactly!(1), equals!(true)),
				(SETTLE_NEVER_FIRED, exactly!(1), equals!(true)),
				(NO_OUTCOME_BEFORE_CONCLUSION, exactly!(1), equals!(true)),
				(SESSION_NEVER_ACTIVATES, exactly!(1), equals!(true))
			]
		}
	}

	tb_scenario! {
		name: cms_tampered_countersignature_carriage_rejected,
		spec: CmsCountersignatureTamperSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let materials = ServerMaterials::generate();
				let authorizer = Arc::new(SettleSpyAuthorizer::challenging(CHALLENGE)?);
				let observer = Arc::new(RecordingObserver::default());
				let hooks = CmsSessionHooks {
					authorizer: Some(Arc::clone(&authorizer) as _),
					approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
					observer: Some(Arc::clone(&observer) as Arc<dyn SessionObserver>),
				};

				let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
				let (mut client, mut server) = (pair.client, pair.server);

				let reply = server.reply(client.start()?).await?;
				let sealed_finished = client.respond(reply).await?.auth_enveloped()?;
				let tampered = flip_sealed_content(sealed_finished.value())?;

				let closing = server.finish(HandshakeMessage::try_from(tampered)?).await;
				let rejected = matches!(closing, Err(HandshakeError::SealedClosing(_)));
				trace.event_with(TAMPERED_CIPHERTEXT_REJECTED, &[], rejected)?;

				let unsettled = authorizer.settle_calls() == 0;
				trace.event_with(SETTLE_NEVER_FIRED, &[], unsettled)?;

				// The receipt exchange reached no verdict, so the observer
				// ledger stays empty.
				let outcomes = observer.recorded();
				trace.event_with(NO_OUTCOME_BEFORE_CONCLUSION, &[], outcomes.is_empty())?;

				let inactive = matches!(server.complete(), Err(HandshakeError::InvalidState));
				trace.event_with(SESSION_NEVER_ACTIVATES, &[], inactive)?;

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

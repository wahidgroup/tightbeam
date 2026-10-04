//! # Countersignature-evidence threat (audit-trail completeness)
//!
//! ## Weakness
//! The [`SessionObserver`] contract promises the server a record of every
//! budget-bearing session whose receipt exchange concluded.
//!
//! A countersignature can fail verification or be withheld. If either case
//! aborts the handshake before the observer fires, the most suspicious
//! terminal states, forged-countersignature probes and withheld
//! countersignatures, are invisible to the application ledger.
//!
//! ## Attack
//! An attacker tampers with the carriage of a budget-bearing receipt
//! acknowledgement, or strips the acknowledgement attribute from the
//! client Finished. The handshake correctly aborts, but the operator's
//! ledger stays silent: repeated probes leave no evidence.
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
//! ## References
//! - CWE-778: Insufficient Logging <https://cwe.mitre.org/data/definitions/778.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(feature = "transport-multiplex", feature = "testing"))]

use tightbeam::utils::urn::Urn;

pub(crate) const MISSING_COUNTERSIGNATURE_FAILS_CLOSED: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/missing-countersignature-fails-closed");
pub(crate) const NO_OUTCOME_BEFORE_CONCLUSION: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/no-outcome-before-conclusion");
pub(crate) const OUTCOME_RECORDS_MISSING_COUNTERSIGNATURE: Urn<'static> = tightbeam::urn!(
	"test",
	"event:countersignature-evidence/outcome-records-missing-countersignature",
);
pub(crate) const SESSION_NEVER_ACTIVATES: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/session-never-activates");
pub(crate) const SETTLE_NEVER_FIRED: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/settle-never-fired");
pub(crate) const TAMPERED_CIPHERTEXT_REJECTED: Urn<'static> =
	tightbeam::urn!("test", "event:countersignature-evidence/tampered-ciphertext-rejected");

#[cfg(feature = "transport-ecies")]
mod ecies {
	use std::sync::Arc;

	use super::{NO_OUTCOME_BEFORE_CONCLUSION, SETTLE_NEVER_FIRED, TAMPERED_CIPHERTEXT_REJECTED};

	use tightbeam::asn1::OctetString;
	use tightbeam::crypto::profiles::DefaultCryptoProvider;
	use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	use tightbeam::exactly;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::{MuxBudgets, SecurityOffer, TransportOffer};
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::transport::handshake::{Handshake, PeerAuthentication};
	use tightbeam::TightBeamError;

	use crate::common::security::{
		carried_closing, carried_key_exchange, default_security_profile, ecies_client_config, ecies_server_config,
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
				(NO_OUTCOME_BEFORE_CONCLUSION, exactly!(1), equals!(true))
			]
		}
	}

	tb_scenario! {
		name: ecies_tampered_countersignature_carriage_rejected,
		spec: CountersignatureTamperSpec,
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
				let observer = Arc::new(RecordingObserver::default());
				let validator: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator);
				let mut server_config = ecies_server_config::<DefaultCryptoProvider>(&materials, [profile]);
				server_config.peer_authentication = PeerAuthentication::mutual([validator]);
				server_config.transport = Some(TransportOffer::mux(4));
				server_config.transport_authorizer = Some(Arc::clone(&authorizer) as _);
				server_config.session_observer = Some(Arc::clone(&observer) as Arc<dyn SessionObserver>);

				let mut server = Handshake::server(server_config);
				let reply = server.reply(client.start()?).await?;
				let closing = client.respond(reply).await?;

				// The auth signature covers `encrypted_data`, and a flipped
				// ciphertext byte is the only wire handle a MITM has on the
				// sealed ack.
				let mut kex = carried_key_exchange(closing);
				let mut forged = kex.encrypted_data.as_bytes().to_vec();
				let middle = forged.len() / 2;
				forged[middle] ^= 0xFF;
				kex.encrypted_data = OctetString::new(forged)?;

				let kex_result = server.finish(carried_closing(&kex)).await;
				trace.event_with(
					TAMPERED_CIPHERTEXT_REJECTED,
					&[],
					kex_result.is_err(),
				)?;
				trace.event_with(
					SETTLE_NEVER_FIRED,
					&[],
					authorizer.settle_calls() == 0,
				)?;

				// The receipt exchange reached no verdict, so the observer
				// ledger stays empty.
				let outcomes = observer.recorded();
				trace.event_with(
					NO_OUTCOME_BEFORE_CONCLUSION,
					&[],
					outcomes.is_empty(),
				)?;

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

#[cfg(feature = "transport-cms")]
mod cms {
	use std::sync::Arc;

	use super::{
		MISSING_COUNTERSIGNATURE_FAILS_CLOSED, OUTCOME_RECORDS_MISSING_COUNTERSIGNATURE, SESSION_NEVER_ACTIVATES,
	};

	use tightbeam::cms::signed_data::SignedData;
	use tightbeam::exactly;
	use tightbeam::oids::RECEIPT_ACK;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::{SessionObserver, SessionVerdict};
	use tightbeam::transport::handshake::{HandshakeError, HandshakeMessage};
	use tightbeam::TightBeamError;

	use crate::common::security::{
		cms_mutual_budget_pair, expectation_failure, CmsSessionHooks, GrantingAuthorizer, PayingApprover,
		RecordingObserver, ServerMaterials,
	};

	const CHALLENGE: &[u8] = b"evidence-cms-invoice";
	const RESPONSE: &[u8] = b"evidence-cms-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	/// The client Finished without its `RECEIPT_ACK` unsigned attribute. No
	/// signature covers unsigned attributes, so the stripped message stays
	/// signature-valid.
	fn strip_receipt_ack(client_finished: &SignedData) -> Result<SignedData, TightBeamError> {
		let mut signed_data = client_finished.to_owned();
		let mut signer_info = signed_data
			.signer_infos
			.0
			.iter()
			.next()
			.cloned()
			.ok_or_else(|| expectation_failure("client Finished must carry a SignerInfo"))?;

		let attrs = signer_info
			.unsigned_attrs
			.take()
			.ok_or_else(|| expectation_failure("client Finished must carry unsigned attributes"))?;

		let retained: Vec<_> = attrs.iter().filter(|attribute| attribute.oid != RECEIPT_ACK).cloned().collect();
		signer_info.unsigned_attrs = Some(retained.try_into()?);
		signed_data.signer_infos = vec![signer_info].try_into()?;
		Ok(signed_data)
	}

	tb_assert_spec! {
		pub CountersignatureMissingSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(MISSING_COUNTERSIGNATURE_FAILS_CLOSED, exactly!(1), equals!(true)),
				(OUTCOME_RECORDS_MISSING_COUNTERSIGNATURE, exactly!(1), equals!(true)),
				(SESSION_NEVER_ACTIVATES, exactly!(1), equals!(true))
			]
		}
	}

	tb_scenario! {
		name: cms_missing_countersignature_recorded,
		spec: CountersignatureMissingSpec,
		environment Bare {
			exec: |SetupEnv { trace, .. }| async move {
				let materials = ServerMaterials::generate();
				let observer = Arc::new(RecordingObserver::default());
				let hooks = CmsSessionHooks {
					authorizer: Some(Arc::new(GrantingAuthorizer::challenging(CHALLENGE)?)),
					approver: Some(Arc::new(PayingApprover::answering(RESPONSE)?)),
					observer: Some(Arc::clone(&observer) as Arc<dyn SessionObserver>),
				};
				let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
				let (mut client, mut server) = (pair.client, pair.server);

				let reply = server.reply(client.start()?).await?;

				let client_finished = client.respond(reply).await?.signed()?;
				// The MITM strips the acknowledgement on the wire.
				let stripped = strip_receipt_ack(client_finished.value())?;

				// The Finished signature covers no unsigned attribute, so the
				// stripped Finished passes it, and the missing
				// countersignature is what refuses the step.
				let closing = server.finish(HandshakeMessage::try_from(stripped)?).await;
				let ack_refused = matches!(closing, Err(HandshakeError::CountersignatureMissing));
				trace.event_with(
					MISSING_COUNTERSIGNATURE_FAILS_CLOSED,
					&[],
					ack_refused,
				)?;

				let outcomes = observer.recorded();
				let missing_recorded = outcomes.len() == 1
					&& outcomes[0].verdict == SessionVerdict::CountersignatureMissing
					&& outcomes[0].countersignature.is_none()
					&& outcomes[0].ancillary_response.is_none();
				trace.event_with(
					OUTCOME_RECORDS_MISSING_COUNTERSIGNATURE,
					&[],
					missing_recorded,
				)?;

				let activation = server.complete();
				let activation_refused = matches!(activation, Err(HandshakeError::InvalidState));
				trace.event_with(SESSION_NEVER_ACTIVATES, &[], activation_refused)?;

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

//! # Countersignature-evidence threat (audit-trail completeness)
//!
//! ## Weakness
//! The [`SessionObserver`] contract promises the server a record of every
//! budget-bearing session whose receipt exchange concluded. If a
//! countersignature that arrived but failed verification (or never
//! arrived at all) aborts the handshake before the observer fires, the
//! most suspicious terminal states, forged-countersignature probes and
//! withheld countersignatures, are invisible to the application ledger.
//!
//! ## Attack
//! An attacker tampers with the carriage of a budget-bearing receipt
//! acknowledgement, or strips the acknowledgement attribute from the
//! client Finished. The handshake correctly aborts, but the operator's
//! ledger shows nothing: repeated probes leave no evidence.
//!
//! ## Expected control
//! Every concluded receipt exchange MUST reach the observer before the
//! abort: an absent acknowledgement records
//! `SessionVerdict::CountersignatureMissing` (a failing one records
//! `SessionVerdict::CountersignatureInvalid`). Settlement MUST never
//! fire and the session MUST never activate. A tamper rejected before
//! the exchange concludes is not a concluded exchange and records
//! nothing.
//!
//! ## References
//! - CWE-778: Insufficient Logging
//!   <https://cwe.mitre.org/data/definitions/778.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>

#![cfg(all(feature = "transport-multiplex", feature = "testing"))]

#[cfg(feature = "transport-ecies")]
mod ecies {
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
	use tightbeam::transport::handshake::receipt::SessionObserver;
	use tightbeam::transport::handshake::{
		client::EciesHandshakeClient, server::EciesHandshakeServer, ClientKeyExchange,
	};
	use tightbeam::TightBeamError;

	use crate::common::security::{
		default_security_profile, pinning_validator, PayingApprover, RecordingObserver, ServerMaterials,
		SettleSpyAuthorizer,
	};

	const CHALLENGE: &[u8] = b"evidence-invoice";
	const RESPONSE: &[u8] = b"evidence-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	tb_assert_spec! {
		pub CountersignatureTamperSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Ok,
			assertions: [
				(tampered_ciphertext_rejected, exactly!(1), equals!(true)),
				(settle_never_fired, exactly!(1), equals!(true)),
				(no_outcome_before_conclusion, exactly!(1), equals!(true))
			]
		}
	}

	// The ECIES countersignature rides inside the key-exchange
	// ciphertext, covered by the client auth signature: any wire tamper
	// that could reach it MUST be rejected before the receipt exchange
	// concludes, settlement MUST never fire, and no outcome is recorded
	// (the observer contract covers concluded exchanges only).
	tb_scenario! {
		name: ecies_tampered_countersignature_carriage_rejected,
		spec: CountersignatureTamperSpec,
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
				let observer = Arc::new(RecordingObserver::default());
				let validators: Arc<Vec<Arc<dyn CertificateValidation>>> = Arc::new(vec![Arc::new(ExpiryValidator)]);
				let mut server = EciesHandshakeServer::<DefaultCryptoProvider>::new(
					Arc::clone(&materials.key_provider),
					Arc::clone(&materials.certificate),
					None,
					Some(validators),
				)
				.with_supported_profiles(vec![profile])
				.with_transport_config(TransportOffer::mux(4))
				.with_transport_authorizer(Arc::clone(&authorizer) as _)
				.with_session_observer(Arc::clone(&observer) as Arc<dyn SessionObserver>);

				let client_hello = client.build_client_hello()?;
				let server_handshake = server.process_client_hello(&client_hello).await?;
				let client_kex_der = client.process_server_handshake(&server_handshake).await?;

				// The countersignature travels only inside the ECIES
				// ciphertext, and the client auth signature covers that
				// ciphertext: the closest a MITM can get is flipping a
				// ciphertext byte, which the auth binding rejects.
				let mut kex = ClientKeyExchange::from_der(&client_kex_der)?;
				let mut forged = kex.encrypted_data.as_bytes().to_vec();
				let middle = forged.len() / 2;
				forged[middle] ^= 0xFF;
				kex.encrypted_data = OctetString::new(forged)?;
				let tampered = kex.to_der()?;

				let kex_result = server.process_client_key_exchange(&tampered).await;
				trace.event_with(
					CountersignatureTamperSpec::tampered_ciphertext_rejected,
					&[],
					kex_result.is_err(),
				)?;
				trace.event_with(
					CountersignatureTamperSpec::settle_never_fired,
					&[],
					authorizer.settle_calls() == 0,
				)?;

				// Nothing concluded: the receipt exchange never reached a
				// verdict, so the observer records nothing.
				let outcomes = observer.recorded();
				trace.event_with(
					CountersignatureTamperSpec::no_outcome_before_conclusion,
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

	use tightbeam::cms::signed_data::SignedData;
	use tightbeam::der::{Decode, Encode};
	use tightbeam::exactly;
	use tightbeam::oids::RECEIPT_ACK;
	use tightbeam::tb_assert_spec;
	use tightbeam::tb_scenario;
	use tightbeam::testing::SetupEnv;
	use tightbeam::transport::handshake::negotiation::MuxBudgets;
	use tightbeam::transport::handshake::receipt::{SessionObserver, SessionVerdict};
	use tightbeam::transport::handshake::HandshakeError;
	use tightbeam::TightBeamError;

	use crate::common::security::{
		cms_mutual_budget_pair, expectation_failure, CmsSessionHooks, GrantingAuthorizer, PayingApprover,
		RecordingObserver, ServerMaterials,
	};

	const CHALLENGE: &[u8] = b"evidence-cms-invoice";
	const RESPONSE: &[u8] = b"evidence-cms-preimage";
	const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

	/// Re-encode the client Finished without its `RECEIPT_ACK` unsigned
	/// attribute. No signature covers unsigned attributes, so the
	/// stripped message stays signature-valid.
	fn strip_receipt_ack(client_finished: &[u8]) -> Result<Vec<u8>, TightBeamError> {
		let mut signed_data = SignedData::from_der(client_finished)?;
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
		Ok(signed_data.to_der()?)
	}

	tb_assert_spec! {
		pub CountersignatureMissingSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Ok,
			assertions: [
				(stripped_finished_still_authenticates, exactly!(1), equals!(true)),
				(missing_countersignature_fails_closed, exactly!(1), equals!(true)),
				(outcome_records_missing_countersignature, exactly!(1), equals!(true)),
				(session_never_activates, exactly!(1), equals!(true))
			]
		}
	}

	// A client Finished stripped of its acknowledgement attribute MUST
	// abort the receipt acknowledgement, MUST reach the observer as
	// CountersignatureMissing evidence, and MUST NOT activate the
	// session. The settlement answer rides inside the stripped envelope,
	// so nothing of it survives either.
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

				let key_exchange = client.build_key_exchange(vec![0xA5; 32], None)?;
				server.process_key_exchange(&key_exchange).await?;

				let server_finished = server.build_server_finished().await?;
				client.process_server_finished(&server_finished)?;

				let client_finished = client.build_client_finished().await?;
				// The MITM strips the acknowledgement on the wire.
				let stripped = strip_receipt_ack(&client_finished)?;

				let finished_accepted = server.process_client_finished(&stripped).is_ok();
				trace.event_with(
					CountersignatureMissingSpec::stripped_finished_still_authenticates,
					&[],
					finished_accepted,
				)?;

				let ack = server.process_receipt_ack(&stripped).await;
				let ack_refused = matches!(ack, Err(HandshakeError::CountersignatureMissing));
				trace.event_with(
					CountersignatureMissingSpec::missing_countersignature_fails_closed,
					&[],
					ack_refused,
				)?;

				// The withheld acknowledgement is evidence: one outcome,
				// the missing verdict, no countersignature bytes, and no
				// answer (it rode inside the stripped envelope).
				let outcomes = observer.recorded();
				let missing_recorded = outcomes.len() == 1
					&& outcomes[0].verdict == SessionVerdict::CountersignatureMissing
					&& outcomes[0].countersignature.is_none()
					&& outcomes[0].ancillary_response.is_none();
				trace.event_with(
					CountersignatureMissingSpec::outcome_records_missing_countersignature,
					&[],
					missing_recorded,
				)?;

				let activation = server.complete();
				let activation_refused = matches!(activation, Err(HandshakeError::CountersignatureMissing));
				trace.event_with(CountersignatureMissingSpec::session_never_activates, &[], activation_refused)?;

				Ok::<(), TightBeamError>(())
			}
		}
	}
}

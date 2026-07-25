//! # Unsigned-attribute injection threat (CMS)
//!
//! ## Weakness
//! RFC 5652 s11.4 places the receipt countersignature among the
//! *unsigned* attributes of the client Finished: no signature covers
//! them, so an intermediary can add attributes without invalidating the
//! message. If the server picks "the first" matching attribute, an
//! injected duplicate lets an attacker steer which value is consumed.
//!
//! ## Attack
//! A MITM captures the client Finished `SignedData` and inserts a second
//! `RECEIPT_SIGNATURE` unsigned attribute carrying a forged value. Every
//! signature on the message still verifies.
//!
//! ## Expected control
//! Every TightBeam handshake attribute is single-use: the server MUST
//! parse the SignedData once, and a duplicate unsigned attribute MUST
//! fail closed before any value is consumed. The budget-bearing session
//! MUST never activate.
//!
//! ## References
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CWE-694: Use of Multiple Resources with Duplicate Identifier
//!   <https://cwe.mitre.org/data/definitions/694.html>
//! - RFC 5652 s11.4: countersignature travels in unsigned attributes
//!   <https://datatracker.ietf.org/doc/html/rfc5652#section-11.4>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::asn1::{Any, OctetString};
use tightbeam::cms::signed_data::SignedData;
use tightbeam::der::asn1::SetOfVec;
use tightbeam::der::{Decode, Encode};
use tightbeam::exactly;
use tightbeam::oids::RECEIPT_SIGNATURE;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::x509::attr::Attribute;
use tightbeam::TightBeamError;

use crate::common::security::{
	cms_mutual_budget_pair, expectation_failure, CmsSessionHooks, GrantingAuthorizer, ServerMaterials,
};

const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// Re-encode the client Finished with a second `RECEIPT_SIGNATURE`
/// unsigned attribute carrying a forged value. No signature covers
/// unsigned attributes, so the result stays signature-valid.
fn inject_duplicate_receipt_signature(client_finished: &[u8]) -> Result<Vec<u8>, TightBeamError> {
	let mut signed_data = SignedData::from_der(client_finished)?;
	let mut signer_info = signed_data
		.signer_infos
		.0
		.iter()
		.next()
		.cloned()
		.ok_or_else(|| expectation_failure("client Finished must carry a SignerInfo"))?;

	let forged_value = Any::encode_from(&OctetString::new(*b"forged-countersignature")?)?;
	let mut values = SetOfVec::new();
	values.insert(forged_value)?;
	let mut attrs = signer_info
		.unsigned_attrs
		.take()
		.ok_or_else(|| expectation_failure("client Finished must carry unsigned attributes"))?;
	attrs.insert(Attribute { oid: RECEIPT_SIGNATURE, values })?;
	signer_info.unsigned_attrs = Some(attrs);

	signed_data.signer_infos = vec![signer_info].try_into()?;
	Ok(signed_data.to_der()?)
}

tb_assert_spec! {
	pub AttributeInjectionSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(injection_invisible_to_signatures, exactly!(1), equals!(true)),
			(duplicate_attribute_fails_closed, exactly!(1), equals!(true)),
			(session_never_activates, exactly!(1), equals!(true))
		]
	}
}

// A duplicate RECEIPT_SIGNATURE unsigned attribute passes every
// signature check (nothing signs unsigned attributes), so the server's
// single-use attribute rule is the only control: the receipt
// acknowledgement must fail closed and the session must never activate.
tb_scenario! {
	name: cms_duplicate_receipt_attribute_fails_closed,
	spec: AttributeInjectionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let hooks = CmsSessionHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenge_free())),
				..CmsSessionHooks::default()
			};
			let pair = cms_mutual_budget_pair(&materials, REQUEST, hooks)?;
			let (mut client, mut server) = (pair.client, pair.server);

			let key_exchange = client.build_key_exchange(vec![0xA5; 32], None)?;
			server.process_key_exchange(&key_exchange).await?;
			let server_finished = server.build_server_finished().await?;
			client.process_server_finished(&server_finished)?;
			let client_finished = client.build_client_finished().await?;

			// The MITM injects the duplicate on the wire.
			let tampered = inject_duplicate_receipt_signature(&client_finished)?;

			// Signature verification cannot see the injection: the
			// tampered Finished still authenticates.
			let finished_accepted = server.process_client_finished(&tampered).is_ok();
			trace.event_with(
				AttributeInjectionSpec::injection_invisible_to_signatures,
				&[],
				finished_accepted,
			)?;

			// The single-use attribute rule is the control that holds.
			let ack = server.process_receipt_ack(&tampered).await;
			let duplicate_rejected = matches!(ack, Err(HandshakeError::DuplicateAttribute));
			trace.event_with(
				AttributeInjectionSpec::duplicate_attribute_fails_closed,
				&[],
				duplicate_rejected,
			)?;

			let activation = server.complete();
			let activation_refused = matches!(activation, Err(HandshakeError::CountersignatureMissing));
			trace.event_with(AttributeInjectionSpec::session_never_activates, &[], activation_refused)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

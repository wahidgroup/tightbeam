//! # Unprotected-attribute injection threat (CMS)
//!
//! ## Weakness
//! The client Finished travels sealed as an `EncryptedData`, whose
//! unprotected attributes (RFC 5652 § 8) no key covers. An intermediary can
//! add attributes there without invalidating the message.
//!
//! If the server read a handshake attribute from beside the seal, an injected
//! value would steer what the server consumes, such as a forged receipt
//! acknowledgement.
//!
//! ## Attack
//! A MITM captures the sealed client Finished and inserts a `RECEIPT_ACK`
//! unprotected attribute that carries a forged value beside the seal.
//!
//! ## Expected control
//! The server reads every handshake attribute of the client Finished from
//! inside the seal, where the handshake secret authenticates it. Beside the
//! seal, it reads only an abort alert. The forged value is therefore never
//! consumed, the closing settles on the client's own countersignature, and the
//! session activates.
//!
//! Inside the seal, every handshake attribute is single-use, so a client that
//! sends a duplicate fails closed. The CMS flow tests cover that case.
//!
//! ## References
//! - CWE-345: Insufficient Verification of Data Authenticity
//!   <https://cwe.mitre.org/data/definitions/345.html>
//! - CWE-694: Use of Multiple Resources with Duplicate Identifier
//!   <https://cwe.mitre.org/data/definitions/694.html>
//! - RFC 5652 § 8: the unprotected attributes of `EncryptedData`
//!   <https://datatracker.ietf.org/doc/html/rfc5652#section-8>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::asn1::{Any, OctetString};
use tightbeam::cms::content_info::CmsVersion;
use tightbeam::cms::encrypted_data::EncryptedData;
use tightbeam::der::asn1::SetOfVec;
use tightbeam::exactly;
use tightbeam::oids::RECEIPT_ACK;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::HandshakeMessage;
use tightbeam::urn::Urn;
use tightbeam::x509::attr::{Attribute, Attributes};
use tightbeam::TightBeamError;

pub(crate) const INJECTED_ATTRIBUTE_NEVER_CONSUMED: Urn<'static> =
	tightbeam::urn!("test", "event:attribute-injection/injected-attribute-never-consumed");
pub(crate) const SESSION_SETTLES_ON_THE_SEALED_ACK: Urn<'static> =
	tightbeam::urn!("test", "event:attribute-injection/session-settles-on-the-sealed-ack");

use crate::common::security::{cms_mutual_budget_pair, CmsSessionHooks, GrantingAuthorizer, ServerMaterials};

const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// The sealed client Finished with a `RECEIPT_ACK` unprotected attribute
/// that carries a forged value beside the seal.
fn inject_receipt_ack(sealed_finished: &EncryptedData) -> Result<EncryptedData, TightBeamError> {
	let forged_value = Any::encode_from(&OctetString::new(*b"forged-acknowledgement")?)?;
	let mut values = SetOfVec::new();
	values.insert(forged_value)?;

	let mut attrs = Attributes::new();
	attrs.insert(Attribute { oid: RECEIPT_ACK, values })?;

	// An EncryptedData with unprotected attributes is version 2 (RFC 5652 § 8).
	let version = CmsVersion::V2;
	Ok(EncryptedData { version, unprotected_attrs: Some(attrs), ..sealed_finished.to_owned() })
}

tb_assert_spec! {
	pub AttributeInjectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(INJECTED_ATTRIBUTE_NEVER_CONSUMED, exactly!(1), equals!(true)),
			(SESSION_SETTLES_ON_THE_SEALED_ACK, exactly!(1), equals!(true))
		]
	}
}

// No key covers an unprotected attribute, so the injected acknowledgement
// travels beside the seal unchanged. The server reads the acknowledgement only
// from inside the seal, so the closing settles on the client's own
// acknowledgement.
tb_scenario! {
	name: cms_injected_receipt_attribute_is_never_consumed,
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

			let reply = server.reply(client.start()?).await?;

			// The MITM injects the forged acknowledgement on the wire.
			let sealed_finished = client.respond(reply).await?.encrypted()?;
			let injected = inject_receipt_ack(sealed_finished.value())?;

			let closing = server.finish(HandshakeMessage::try_from(injected)?).await;
			trace.event_with(
				INJECTED_ATTRIBUTE_NEVER_CONSUMED,
				&[],
				closing.is_ok(),
			)?;

			let activation = server.complete();
			let settled = activation.is_ok_and(|session| session.receipt().is_some());
			trace.event_with(SESSION_SETTLES_ON_THE_SEALED_ACK, &[], settled)?;

			Ok::<(), TightBeamError>(())
		}
	}
}

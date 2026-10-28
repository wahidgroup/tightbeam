//! # Unprotected-attribute injection threat (CMS)
//!
//! ## Weakness
//! The client Finished travels sealed as an `AuthEnvelopedData`, whose
//! unauthenticated attributes (RFC 5083 § 2.1) no key covers. An intermediary
//! can add attributes there, and the message stays valid.
//!
//! If the server read a handshake attribute from beside the seal, an injected
//! value would steer what the server consumes, such as a forged receipt
//! acknowledgement.
//!
//! ## Attack
//! A MITM captures the sealed client Finished and inserts a `RECEIPT_ACK`
//! unauthenticated attribute that carries a forged value beside the seal.
//!
//! ## Expected control
//! The server reads every handshake attribute of the client Finished from
//! inside the seal, where the handshake secret authenticates it. Beside the
//! seal, it reads an abort alert alone, and the open refuses any other
//! unauthenticated attribute. The server refuses the closing before it reads
//! the forged value, and the session stays inactive.
//!
//! Inside the seal, every handshake attribute is single-use, so a client that
//! sends a duplicate fails closed. The CMS flow tests cover that case.
//!
//! ## References
//! - CWE-345: Insufficient Verification of Data Authenticity
//!   <https://cwe.mitre.org/data/definitions/345.html>
//! - CWE-694: Use of Multiple Resources with Duplicate Identifier
//!   <https://cwe.mitre.org/data/definitions/694.html>
//! - RFC 5083 § 2.1: the unauthenticated attributes of `AuthEnvelopedData`
//!   <https://datatracker.ietf.org/doc/html/rfc5083#section-2.1>

#![cfg(all(feature = "transport-cms", feature = "transport-multiplex", feature = "testing"))]

use std::sync::Arc;

use tightbeam::absent;
use tightbeam::asn1::{Any, OctetString};
use tightbeam::crypto::cms::AuthEnvelopedData;
use tightbeam::der::asn1::SetOfVec;
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::oids::RECEIPT_ACK;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::SetupEnv;
use tightbeam::transport::handshake::negotiation::MuxBudgets;
use tightbeam::transport::handshake::HandshakeMessage;
use tightbeam::x509::attr::{Attribute, Attributes};
use tightbeam::TightBeamError;

use crate::common::security::{ClientMaterials, GrantingAuthorizer, ServerMaterials};
use crate::security::common::HandshakeBackendKind;
use crate::security::live::{AttackStep, FrameEdit, LiveHandshake, ReceiptHooks, CLOSING_FRAME};

const REQUEST: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 128 };

/// The sealed client Finished with a `RECEIPT_ACK` unauthenticated
/// attribute that carries a forged value beside the seal.
fn inject_receipt_ack(sealed_finished: &AuthEnvelopedData) -> Result<AuthEnvelopedData, TightBeamError> {
	let forged_value = Any::encode_from(&OctetString::new(*b"forged-acknowledgement")?)?;
	let mut values = SetOfVec::new();
	values.insert(forged_value)?;

	let mut attrs = Attributes::new();
	attrs.insert(Attribute { oid: RECEIPT_ACK, values })?;

	Ok(AuthEnvelopedData { unauth_attrs: Some(attrs), ..sealed_finished.to_owned() })
}

/// `closing`, the client Finished, with the forged acknowledgement injected
/// beside its seal.
fn injected(closing: HandshakeMessage) -> Result<HandshakeMessage, TightBeamError> {
	let sealed_finished = closing.auth_enveloped()?;
	let injected = inject_receipt_ack(sealed_finished.value())?;
	Ok(HandshakeMessage::try_from(injected)?)
}

tb_assert_spec! {
	pub AttributeInjectionSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("sealed-closing/encoding")),
			(events::SESSION_HANDSHAKE_COMPLETE, absent!()),
			(events::SESSION_RECEIPT_SETTLED, absent!())
		]
	}
}

// The injected acknowledgement travels beside the seal, and the open of the
// seal refuses the closing that carries it.
tb_scenario! {
	name: cms_injected_receipt_attribute_is_never_consumed,
	spec: AttributeInjectionSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let identity = ClientMaterials::generate().identity();
			let hooks = ReceiptHooks {
				authorizer: Some(Arc::new(GrantingAuthorizer::challenge_free())),
				..ReceiptHooks::default()
			};

			// The MITM injects the forged acknowledgement on the wire.
			let injection = AttackStep::new(CLOSING_FRAME, FrameEdit::Rewrite(Box::new(injected)));
			let kind = HandshakeBackendKind::Cms;
			let handshake = LiveHandshake::budget_bearing(kind, materials, identity, REQUEST, hooks);
			let outcome = handshake.audit_server(&trace).with_step(injection).run().await?;
			outcome.refused_by_server("server accepted a closing that carries an unauthenticated attribute")?;

			Ok::<(), TightBeamError>(())
		}
	}
}

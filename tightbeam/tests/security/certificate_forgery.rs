//! # Certificate forgery threat
//!
//! ## Weakness
//! If the handshake skips a configured certificate validator, a forged or
//! untrusted certificate can pass validation, and the endpoint accepts it.
//!
//! ## Attack
//! A peer presents a forged certificate: it names the authority that the other
//! endpoint trusts as its issuer, and the key of the forger signs it. A server
//! forges towards a client that anchors the authority, and a client forges
//! towards a server whose client store anchors it. The scenarios also run the
//! configured validators on a genuine certificate.
//!
//! ## Expected control
//! The handshake MUST enforce certificate validation: it MUST reject a forged
//! certificate, and a valid certificate MUST pass. Validator configuration is
//! the application's responsibility. The trust store verifies the signature of
//! a leaf under the key of its authority, so it refuses the forged leaf and
//! admits a genuine leaf. The handshake carries the refusal of a validator:
//!
//! - `SignatureVerificationFailed` from the store, for a forged leaf, on either endpoint.
//! - `PublicKeyNotPinned` from the pin of a wrong key.
//! - `CertificateNotTrusted` from direct trust whose anchors hold another certificate.
//! - `CertificateDenied` from the validator that refuses every certificate.
//!
//! ## References
//! - CWE-295: Improper Certificate Validation <https://cwe.mitre.org/data/definitions/295.html>
//! - CWE-347: Improper Verification of Cryptographic Signature
//!   <https://cwe.mitre.org/data/definitions/347.html>
//! - CAPEC-459: Creating a Rogue Certification Authority Certificate
//!   <https://capec.mitre.org/data/definitions/459.html>
//! - CAPEC-94: Adversary in the Middle (AiTM) <https://capec.mitre.org/data/definitions/94.html>
//! - RFC 5280 §6: Certification Path Validation

use std::sync::Arc;

use tightbeam::{
	crypto::sign::ecdsa::Secp256k1SigningKey,
	crypto::x509::{
		policy::{CertificateValidation, DirectTrustValidator, PublicKeyPinning},
		Certificate,
	},
	der::Encode,
	exactly,
	instrumentation::events,
	tb_assert_spec, tb_scenario,
	testing::{SetupEnv, TestCertificate},
	TightBeamError,
};

use crate::common::security::{combined_validator, fixed_signing_key, ClientMaterials, ServerMaterials};
use crate::security::common::{HandshakeBackendKind, RejectAllValidator};
use crate::security::live::LiveHandshake;

/// The name of the authority that an endpoint anchors.
const AUTHORITY: &str = "tightbeam test authority";

/// The seed of the key of the authority.
const AUTHORITY_SEED: u8 = 0xa1;

/// The seed of the key of a forger, which signs a leaf in the name of the
/// authority.
const FORGER_SEED: u8 = 0xf0;

/// The seed of a key that no fixture of this module presents.
const STRANGER_SEED: u8 = 0x03;

/// The authority and its key.
fn authority() -> Result<(Secp256k1SigningKey, Certificate), TightBeamError> {
	let authority_key = fixed_signing_key(AUTHORITY_SEED);
	let authority = TestCertificate::authority(&authority_key, AUTHORITY)?;
	Ok((authority_key, authority))
}

/// A leaf of `subject_key` named `cn` that names the authority as its issuer
/// and that `issuer_key` signs.
fn leaf_of(
	issuer_key: &Secp256k1SigningKey,
	subject_key: &Secp256k1SigningKey,
	cn: &str,
) -> Result<Certificate, TightBeamError> {
	let uri = format!("urn:tightbeam:test-{cn}");
	TestCertificate::issued_with_uri_sans(issuer_key, AUTHORITY, subject_key, cn, &[uri.as_str()])
}

/// A validator that pins the key of `certificate` alone.
fn pinning(certificate: &Certificate) -> Result<PublicKeyPinning, TightBeamError> {
	let pin = certificate.tbs_certificate.subject_public_key_info.to_der()?;
	Ok(PublicKeyPinning::new([pin])?)
}

/// A validator that pins the key of [`STRANGER_SEED`], which no fixture
/// presents.
fn pinning_a_stranger(_genuine: &Certificate) -> Result<PublicKeyPinning, TightBeamError> {
	pinning(&TestCertificate::self_signed(&fixed_signing_key(STRANGER_SEED)))
}

/// Direct trust that anchors `certificate` alone.
fn direct_trust(certificate: &Certificate) -> Result<DirectTrustValidator, TightBeamError> {
	Ok(DirectTrustValidator::default().with_trust_chain([certificate.to_owned()])?)
}

/// Direct trust that anchors the self-signed, unexpired certificate of
/// [`STRANGER_SEED`] alone.
fn direct_trust_in_a_stranger(_genuine: &Certificate) -> Result<DirectTrustValidator, TightBeamError> {
	direct_trust(&TestCertificate::self_signed(&fixed_signing_key(STRANGER_SEED)))
}

/// A live HPKE handshake whose client admits its server under the validator
/// that `policy` builds over the genuine server certificate.
fn pinned_under<V>(
	policy: impl FnOnce(&Certificate) -> Result<V, TightBeamError>,
) -> Result<LiveHandshake, TightBeamError>
where
	V: CertificateValidation + 'static,
{
	let materials = ServerMaterials::fixed();
	let validator: Arc<dyn CertificateValidation> = Arc::new(policy(&materials.certificate)?);
	Ok(LiveHandshake::new(HandshakeBackendKind::Hpke, materials).with_server_policy([validator]))
}

/// A live HPKE handshake whose client anchors the authority alone, and whose
/// server presents a leaf that names that authority as its issuer and that
/// `issuer_key` signs.
fn server_leaf_signed_by(issuer_key: &Secp256k1SigningKey) -> Result<LiveHandshake, TightBeamError> {
	let (authority_key, authority) = authority()?;
	let server_key = fixed_signing_key(0xb2);
	let leaf = leaf_of(issuer_key, &server_key, "server")?;

	let server = ServerMaterials::presenting(server_key, leaf);
	let anchor = ServerMaterials::presenting(authority_key, authority);
	Ok(LiveHandshake::new(HandshakeBackendKind::Hpke, server).trusting(anchor))
}

/// A live HPKE handshake whose server anchors the authority alone for its
/// clients, and whose client presents a leaf that names that authority as its
/// issuer and that `issuer_key` signs.
fn client_leaf_signed_by(issuer_key: &Secp256k1SigningKey) -> Result<LiveHandshake, TightBeamError> {
	let (_, authority) = authority()?;
	let client_key = fixed_signing_key(0xb3);
	let leaf = leaf_of(issuer_key, &client_key, "client")?;

	let identity = ClientMaterials::presenting(client_key, leaf).identity();
	let handshake = LiveHandshake::new(HandshakeBackendKind::Hpke, ServerMaterials::fixed());
	Ok(handshake
		.with_client_validators([combined_validator(&[&authority])])
		.with_client_identity(identity))
}

tb_assert_spec! {
	pub ValidCertificateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_HANDSHAKE_COMPLETE, exactly!(2))
		]
	}
}

// A valid certificate under the matching pin completes the handshake on both
// endpoints.
tb_scenario! {
	name: certificate_forgery_valid_certificate_accepted,
	spec: ValidCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = pinned_under(pinning)?.audit_client(&trace).audit_server(&trace);
			let outcome = handshake.run().await?;
			let (_client, _server) = outcome.established()?;

			Ok::<(), TightBeamError>(())
		}
	}
}

// Direct trust that anchors the genuine certificate completes the handshake
// on both endpoints.
tb_scenario! {
	name: direct_trust_in_the_genuine_certificate_completes_the_handshake,
	spec: ValidCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = pinned_under(direct_trust)?.audit_client(&trace).audit_server(&trace);
			let outcome = handshake.run().await?;
			let (_client, _server) = outcome.established()?;

			Ok::<(), TightBeamError>(())
		}
	}
}

// A leaf of the authority completes the handshake under a client that anchors
// that authority alone.
tb_scenario! {
	name: certificate_forgery_issued_certificate_accepted,
	spec: ValidCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = server_leaf_signed_by(&fixed_signing_key(AUTHORITY_SEED))?;
			let outcome = handshake.audit_client(&trace).audit_server(&trace).run().await?;
			let (_client, _server) = outcome.established()?;

			Ok::<(), TightBeamError>(())
		}
	}
}

// A client leaf of the authority completes the handshake under a server whose
// client store anchors that authority alone.
tb_scenario! {
	name: an_issued_client_certificate_completes_the_handshake,
	spec: ValidCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = client_leaf_signed_by(&fixed_signing_key(AUTHORITY_SEED))?;
			let outcome = handshake.audit_client(&trace).audit_server(&trace).run().await?;
			let (_client, _server) = outcome.established()?;

			Ok::<(), TightBeamError>(())
		}
	}
}

tb_assert_spec! {
	pub ForgedCertificateSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/signature-verification-failed"))
		]
	}
}

// A forged server leaf names the authority as its issuer, and the key of the
// forger signs it, so the trust store of the client fails its signature, with
// no server policy in the way.
tb_scenario! {
	name: certificate_forgery_forged_certificate_rejected,
	spec: ForgedCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = server_leaf_signed_by(&fixed_signing_key(FORGER_SEED))?;
			let outcome = handshake.audit_client(&trace).run().await?;
			outcome.refused_by_client("a forged certificate was accepted")
		}
	}
}

// A forged client leaf names the authority as its issuer, and the key of the
// forger signs it, so the client store of the server fails its signature when
// the server admits the closing.
tb_scenario! {
	name: a_forged_client_certificate_is_refused_by_the_server,
	spec: ForgedCertificateSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let handshake = client_leaf_signed_by(&fixed_signing_key(FORGER_SEED))?;
			let outcome = handshake.audit_server(&trace).run().await?;
			outcome.refused_by_server("a forged client certificate was accepted")
		}
	}
}

tb_assert_spec! {
	pub WrongKeySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/public-key-not-pinned"))
		]
	}
}

// A pin on another public key fails the handshake on the genuine certificate
// when the client reads the reply.
tb_scenario! {
	name: a_pin_on_another_key_refuses_the_genuine_certificate,
	spec: WrongKeySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let outcome = pinned_under(pinning_a_stranger)?.audit_client(&trace).run().await?;
			outcome.refused_by_client("certificate with wrong pinned key should be rejected")
		}
	}
}

tb_assert_spec! {
	pub NotTrustedSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/certificate-not-trusted"))
		]
	}
}

// Direct trust that anchors another self-signed, unexpired certificate
// refuses the genuine certificate when the client reads the reply, so an
// adversary with a certificate outside the anchors cannot stand in for the
// server (CAPEC-94).
tb_scenario! {
	name: direct_trust_in_another_anchor_refuses_the_genuine_certificate,
	spec: NotTrustedSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let outcome = pinned_under(direct_trust_in_a_stranger)?.audit_client(&trace).run().await?;
			outcome.refused_by_client("a certificate outside the anchors was accepted")
		}
	}
}

tb_assert_spec! {
	pub RejectAllSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::SESSION_CERT_REJECTED, exactly!(1), equals!("certificate/certificate-denied"))
		]
	}
}

// The RejectAll validator fails the handshake on the genuine certificate when
// the client reads the reply.
tb_scenario! {
	name: a_policy_that_refuses_all_refuses_the_genuine_certificate,
	spec: RejectAllSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let outcome = pinned_under(|_| Ok(RejectAllValidator))?.audit_client(&trace).run().await?;
			outcome.refused_by_client("RejectAll validator should reject all certificates")
		}
	}
}

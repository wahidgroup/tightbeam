//! Dual-signed session receipts.
//!
//! A [`SessionReceipt`] binds the handshake transcript, the granted session
//! budgets, and an optional settlement challenge into one DER body. The
//! body travels as the `eContent` of a CMS `SignedData`
//! ([RFC 5652 §5](https://datatracker.ietf.org/doc/html/rfc5652#section-5))
//! with one `SignerInfo` per party: the server signs it inside its
//! handshake response, the client countersigns (optionally answering the
//! challenge through a signed attribute) inside its key exchange. The
//! completed artifact, held as a [`StoredReceipt`], is verifiable by any
//! third party holding both certificates: each signature covers the
//! standard signed attributes (content type, message digest, role, and
//! the client's answer), so verification needs no transcript replay.
//!
//! TightBeam never parses the challenge or the response and never checks an
//! instrument amount against `budgets x credit_unit`: price binding is
//! application truth, enforced by the [`TransportAuthorizer`] and
//! [`ReceiptApprover`] hooks.
//!
//! # Confidentiality
//!
//! The two opaque fields travel differently. The server's challenge
//! travels in the cleartext handshake response: treat it as public wire
//! data and never put a secret in it. The client's answer is a bearer
//! secret (a payment preimage, a signed instrument): it goes inside the
//! client's `SignerInfo`, which travels only encrypted to the server
//! (inside the ECIES key-exchange payload, or a CMS `EnvelopedData`),
//! and its bytes are redacted from `Debug` output so they cannot leak
//! through logs.
//!
//! # Retention
//!
//! TightBeam is `no_std`-capable with no clock and no storage. The
//! endpoints hold the completed [`StoredReceipt`] only for the life of the
//! session object: an application that may need to prove or dispute the
//! agreement later must persist the artifact together with both
//! certificates for its own dispute window.
//!
//! [`TransportAuthorizer`]: crate::transport::handshake::negotiation::TransportAuthorizer

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::fmt;

use crate::asn1::DigestInfo;
use crate::cms::signed_data::SignedData;
use crate::der::asn1::OctetString;
use crate::der::Sequence;
use crate::transport::handshake::negotiation::MuxBudgets;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
mod handshake {
	#[cfg(not(feature = "std"))]
	pub use alloc::vec::Vec;
	#[cfg(feature = "std")]
	pub use std::vec::Vec;

	#[cfg(not(feature = "std"))]
	pub use alloc::vec;
	#[cfg(feature = "std")]
	pub use std::vec;

	#[cfg(not(feature = "std"))]
	pub use alloc::borrow::ToOwned;

	pub use crate::cms::content_info::CmsVersion;
	pub use crate::cms::signed_data::{
		EncapsulatedContentInfo, SignedAttributes, SignerIdentifier, SignerInfo, SignerInfos,
	};
	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::crypto::sign::PrehashVerifier;
	pub use crate::crypto::x509::utils::{compute_signer_identifier, compute_signer_identifier_from_der};
	pub use crate::der::asn1::{ObjectIdentifier, SetOfVec};
	pub use crate::der::oid::AssociatedOid;
	pub use crate::der::{Any, Decode, Encode};
	pub use crate::oids::{
		ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST, RECEIPT_ANSWER, RECEIPT_ROLE, SESSION_RECEIPT_CONTENT,
	};
	pub use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey};
	pub use crate::transport::handshake::error::HandshakeError;
	pub use crate::transport::handshake::negotiation::SETTLEMENT_UNSUPPORTED_CODE;
	pub use crate::transport::handshake::utils::compute_transcript_digest;
	pub use x509_cert::attr::Attribute;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use handshake::*;

#[cfg(feature = "x509")]
mod x509 {
	pub(crate) use crate::transport::handshake::Arc;
	pub use crate::x509::Certificate;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use crate::transport::handshake::negotiation::TransportAuthorizer;
}

#[cfg(feature = "x509")]
use x509::*;

/// Session agreement body issued by the server for every budget-bearing
/// session.
///
/// # Binding
///
/// - `transcript_hash` pins the receipt to one handshake. Replaying it
///   against another session changes the transcript and breaks the pin.
/// - `budgets` / `credit_unit` are the metered session terms both sides
///   countersign.
/// - `ancillary` is the server's settlement challenge (unsigned
///   transaction, invoice, or other opaque bytes). Public wire data,
///   never a secret; never parsed by TightBeam.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SessionReceipt {
	/// Handshake transcript digest pinning the receipt to a session per
	/// [RFC 8017 §9.2](https://datatracker.ietf.org/doc/html/rfc8017#section-9.2).
	pub transcript_hash: DigestInfo,
	/// Per-direction session budgets granted, in credits.
	pub budgets: MuxBudgets,
	/// Bytes per credit fixed by the accept for both directions.
	pub credit_unit: u32,
	/// Opaque settlement challenge from the server's authorizer. Never
	/// parsed by TightBeam. Travels in the cleartext handshake response:
	/// public wire data, never a secret.
	#[asn1(optional = "true")]
	pub ancillary: Option<OctetString>,
}

/// Role a receipt `SignerInfo` holds, bound by the [`RECEIPT_ROLE`]
/// signed attribute so one party's signature cannot be spliced into the
/// other role (CWE-347).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptRole {
	/// The issuing server, signing the receipt body alone.
	Server,
	/// The countersigning client, additionally binding its settlement
	/// answer through the [`RECEIPT_ANSWER`] signed attribute.
	Client,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl ReceiptRole {
	fn code(self) -> u8 {
		match self {
			ReceiptRole::Server => 0,
			ReceiptRole::Client => 1,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl TryFrom<u8> for ReceiptRole {
	type Error = HandshakeError;

	fn try_from(code: u8) -> Result<Self, Self::Error> {
		match code {
			0 => Ok(ReceiptRole::Server),
			1 => Ok(ReceiptRole::Client),
			_ => Err(HandshakeError::ReceiptMismatch),
		}
	}
}

/// Digest algorithm identifier of `D` with absent parameters.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn digest_algorithm<D>() -> AlgorithmIdentifierOwned
where
	D: AssociatedOid,
{
	AlgorithmIdentifierOwned { oid: D::OID, parameters: None }
}

/// Wrap a computed transcript hash into the self-describing
/// [`DigestInfo`] carried by [`SessionReceipt::transcript_hash`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn transcript_digest_info<D>(hash: [u8; 32]) -> Result<DigestInfo, HandshakeError>
where
	D: AssociatedOid,
{
	let digest = OctetString::new(hash)?;
	let algorithm = digest_algorithm::<D>();
	let digest_info = DigestInfo { algorithm, digest };
	Ok(digest_info)
}

/// SubjectKeyIdentifier-based signer identity of a certificate's public
/// key, matching what [`sign_receipt`] and [`countersign_receipt`] derive
/// from their key providers.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub(crate) fn certificate_signer_identifier<D>(certificate: &Certificate) -> Result<SignerIdentifier, HandshakeError>
where
	D: Digest,
{
	let spki_der = certificate.tbs_certificate.subject_public_key_info.to_der()?;
	let sid = compute_signer_identifier_from_der::<D>(&spki_der)?;
	Ok(sid)
}

/// Build a single-valued attribute.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn single_valued(oid: ObjectIdentifier, value: Any) -> Result<Attribute, HandshakeError> {
	let values = SetOfVec::try_from(vec![value])?;
	let attribute = Attribute { oid, values };
	Ok(attribute)
}

/// Canonical signed attributes of a receipt `SignerInfo`: content type
/// and message digest per
/// [RFC 5652 §11](https://datatracker.ietf.org/doc/html/rfc5652#section-11),
/// the role tag, and the client's settlement answer when present.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn receipt_signed_attrs<D>(
	receipt_der: &[u8],
	role: ReceiptRole,
	answer: Option<&[u8]>,
) -> Result<SignedAttributes, HandshakeError>
where
	D: Digest,
{
	let message_digest = compute_transcript_digest::<D>(receipt_der)?;

	let mut attributes = Vec::with_capacity(4);
	let value = Any::encode_from(&SESSION_RECEIPT_CONTENT)?;
	attributes.push(single_valued(ATTR_CONTENT_TYPE, value)?);

	let value = Any::encode_from(&OctetString::new(message_digest)?)?;
	attributes.push(single_valued(ATTR_MESSAGE_DIGEST, value)?);

	let value = Any::encode_from(&role.code())?;
	attributes.push(single_valued(RECEIPT_ROLE, value)?);

	if let Some(answer) = answer {
		let value = Any::encode_from(&OctetString::new(answer)?)?;
		attributes.push(single_valued(RECEIPT_ANSWER, value)?);
	}

	Ok(SignedAttributes::try_from(attributes)?)
}

/// Prehash a `SignerInfo` signature covers: the digest of the DER `SET OF`
/// signed attributes per
/// [RFC 5652 §5.4](https://datatracker.ietf.org/doc/html/rfc5652#section-5.4).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn signed_attrs_prehash<D>(signed_attrs: &SignedAttributes) -> Result<[u8; 32], HandshakeError>
where
	D: Digest,
{
	let attrs_der = signed_attrs.to_der()?;
	let prehash = compute_transcript_digest::<D>(&attrs_der)?;
	Ok(prehash)
}

/// Find at most one single-valued signed attribute, failing closed on
/// duplicates or multi-valued attributes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn find_signed_attr(attrs: &SignedAttributes, oid: ObjectIdentifier) -> Result<Option<&Any>, HandshakeError> {
	let mut found = None;
	for attribute in attrs.iter() {
		if attribute.oid != oid {
			continue;
		}
		if found.is_some() || attribute.values.len() != 1 {
			return Err(HandshakeError::ReceiptMismatch);
		}

		found = attribute.values.iter().next();
	}

	Ok(found)
}

/// Role declared by a `SignerInfo`'s signed attributes, `None` when the
/// signer carries no role tag.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn signer_role(signer: &SignerInfo) -> Result<Option<ReceiptRole>, HandshakeError> {
	let Some(attrs) = signer.signed_attrs.as_ref() else {
		return Ok(None);
	};
	let Some(value) = find_signed_attr(attrs, RECEIPT_ROLE)? else {
		return Ok(None);
	};

	let code: u8 = value.decode_as().map_err(|_| HandshakeError::ReceiptMismatch)?;
	let role = ReceiptRole::try_from(code)?;
	Ok(Some(role))
}

/// Settlement answer declared by a client `SignerInfo`, un-normalized.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn signer_answer(signer: &SignerInfo) -> Result<Option<OctetString>, HandshakeError> {
	let Some(attrs) = signer.signed_attrs.as_ref() else {
		return Ok(None);
	};
	let Some(value) = find_signed_attr(attrs, RECEIPT_ANSWER)? else {
		return Ok(None);
	};

	let decoded: OctetString = value.decode_as().map_err(|_| HandshakeError::ReceiptMismatch)?;
	Ok(Some(decoded))
}

/// Sign the receipt body into a role-tagged `SignerInfo` with the
/// standard signed attributes.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
async fn signer_info_over_receipt<D>(
	receipt_der: &[u8],
	role: ReceiptRole,
	answer: Option<&[u8]>,
	key_provider: &dyn SigningKeyProvider,
) -> Result<SignerInfo, HandshakeError>
where
	D: Digest + AssociatedOid,
{
	let signed_attrs = receipt_signed_attrs::<D>(receipt_der, role, answer)?;
	let prehash = signed_attrs_prehash::<D>(&signed_attrs)?;
	let signature_bytes = key_provider.sign_prehash(&prehash).await?;
	let public_key_der = key_provider.to_public_key_bytes().await?;
	let sid = compute_signer_identifier_from_der::<D>(&public_key_der)?;

	// SubjectKeyIdentifier identification demands SignerInfo version 3
	// (RFC 5652 §5.3).
	let signer_info = SignerInfo {
		version: CmsVersion::V3,
		sid,
		digest_alg: digest_algorithm::<D>(),
		signed_attrs: Some(signed_attrs),
		signature_algorithm: key_provider.algorithm(),
		signature: OctetString::new(signature_bytes)?,
		unsigned_attrs: None,
	};

	Ok(signer_info)
}

/// Assemble the receipt `SignedData` around the body DER and the
/// server's `SignerInfo`.
///
/// [RFC 5652 §5.1](https://datatracker.ietf.org/doc/html/rfc5652#section-5.1)
/// carries each signer's digest algorithm twice: in the
/// `digestAlgorithms` SET and inside the `SignerInfo`. The SET entry is
/// built fresh from the compile-time OID.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn new_receipt_artifact<D>(receipt_der: &[u8], server_signer: SignerInfo) -> Result<SignedData, HandshakeError>
where
	D: AssociatedOid,
{
	let body = OctetString::new(receipt_der)?;
	let body_der = body.to_der()?;
	let econtent = Any::from_der(&body_der)?;
	let digest_algorithms = SetOfVec::try_from(vec![digest_algorithm::<D>()])?;

	let encap_content_info =
		EncapsulatedContentInfo { econtent_type: SESSION_RECEIPT_CONTENT, econtent: Some(econtent) };
	let signer_infos = SignerInfos(SetOfVec::try_from(vec![server_signer])?);

	// Non-id-data eContentType demands SignedData version 3 (RFC 5652 §5.1).
	let artifact = SignedData {
		version: CmsVersion::V3,
		digest_algorithms,
		encap_content_info,
		certificates: None,
		crls: None,
		signer_infos,
	};

	Ok(artifact)
}

/// Build the [`SessionReceipt`] body and the server-signed `SignedData`
/// artifact around it.
///
/// Shared by both handshake carriages so the body construction and the
/// signed-attribute discipline cannot drift.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) async fn sign_receipt<D>(
	transcript_hash: [u8; 32],
	budgets: MuxBudgets,
	credit_unit: u32,
	challenge: Option<OctetString>,
	key_provider: &dyn SigningKeyProvider,
) -> Result<(SessionReceipt, SignedData), HandshakeError>
where
	D: Digest + AssociatedOid,
{
	let receipt = SessionReceipt {
		transcript_hash: transcript_digest_info::<D>(transcript_hash)?,
		budgets,
		credit_unit,
		ancillary: challenge,
	};

	let receipt_der = receipt.to_der()?;
	let server_role = ReceiptRole::Server;
	let server_signer = signer_info_over_receipt::<D>(&receipt_der, server_role, None, key_provider).await?;
	let artifact = new_receipt_artifact::<D>(&receipt_der, server_signer)?;

	Ok((receipt, artifact))
}

/// Countersign a verified receipt body into the client `SignerInfo`,
/// binding the normalized settlement answer through the
/// [`RECEIPT_ANSWER`] signed attribute.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) async fn countersign_receipt<D>(
	receipt: &SessionReceipt,
	answer: Option<&[u8]>,
	key_provider: &dyn SigningKeyProvider,
) -> Result<SignerInfo, HandshakeError>
where
	D: Digest + AssociatedOid,
{
	let receipt_der = receipt.to_der()?;
	let client_role = ReceiptRole::Client;
	let normalized_answer = normalize_answer(answer);

	let signer_info = signer_info_over_receipt::<D>(&receipt_der, client_role, normalized_answer, key_provider).await?;
	Ok(signer_info)
}

/// Complete a server-signed artifact with the client's `SignerInfo`.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn complete_receipt_artifact(
	mut artifact: SignedData,
	countersignature: SignerInfo,
) -> Result<SignedData, HandshakeError> {
	let digest_present = artifact.digest_algorithms.as_ref().contains(&countersignature.digest_alg);
	if !digest_present {
		// RFC 5652 §5.1 lists each signer's digest algorithm in the
		// digestAlgorithms SET alongside its SignerInfo copy. Heap-free:
		// receipt digest algorithms carry no parameters.
		artifact.digest_algorithms.insert(countersignature.digest_alg.to_owned())?;
	}

	artifact.signer_infos.0.insert(countersignature)?;
	Ok(artifact)
}

/// Parse the [`SessionReceipt`] body out of a receipt artifact, failing
/// closed on a foreign `eContentType` or a detached body.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn receipt_from_artifact(artifact: &SignedData) -> Result<SessionReceipt, HandshakeError> {
	let content_type = artifact.encap_content_info.econtent_type;
	let content_type_matches = content_type == SESSION_RECEIPT_CONTENT;
	if !content_type_matches {
		return Err(HandshakeError::ReceiptMismatch);
	}

	let econtent = artifact
		.encap_content_info
		.econtent
		.as_ref()
		.ok_or(HandshakeError::ReceiptMismatch)?;

	let body: OctetString = econtent.decode_as().map_err(|_| HandshakeError::ReceiptMismatch)?;
	let body_bytes = body.as_bytes();
	let receipt = SessionReceipt::from_der(body_bytes)?;
	Ok(receipt)
}

/// Find the artifact's `SignerInfo` for one role, failing closed when
/// the role appears more than once.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn signer_for_role(artifact: &SignedData, role: ReceiptRole) -> Result<Option<&SignerInfo>, HandshakeError> {
	let mut found = None;
	for signer in artifact.signer_infos.0.iter() {
		if signer_role(signer)? != Some(role) {
			continue;
		}
		if found.is_some() {
			return Err(HandshakeError::ReceiptMismatch);
		}

		found = Some(signer);
	}

	Ok(found)
}

/// Verify one receipt `SignerInfo` against the receipt body, the
/// expected role, and the expected signer identity.
///
/// The received signed attributes must equal the canonical set for the
/// role byte-for-byte (no extra attributes, no drift), the signer
/// identity must match the expected certificate key, and the signature
/// must verify over the attributes DER. Returns the normalized
/// settlement answer for the client role. Parse and verify failures
/// collapse to one variant so both carriages report the same error.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn verify_receipt_signer<D, S, V>(
	receipt_der: &[u8],
	signer: &SignerInfo,
	role: ReceiptRole,
	expected_sid: &SignerIdentifier,
	key: &V,
) -> Result<Option<OctetString>, HandshakeError>
where
	D: Digest + AssociatedOid,
	S: for<'a> TryFrom<&'a [u8]>,
	V: PrehashVerifier<S>,
{
	let attrs = signer
		.signed_attrs
		.as_ref()
		.ok_or(HandshakeError::SignatureVerificationFailed)?;

	let answer = match role {
		ReceiptRole::Server => None,
		ReceiptRole::Client => signer_answer(signer)?,
	};
	let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
	let expected_attrs = receipt_signed_attrs::<D>(receipt_der, role, answer_bytes)?;

	let attrs_canonical = *attrs == expected_attrs;
	let identity_matches = signer.sid == *expected_sid;
	let digest_matches = signer.digest_alg == digest_algorithm::<D>();
	if !attrs_canonical || !identity_matches || !digest_matches {
		return Err(HandshakeError::SignatureVerificationFailed);
	}

	let prehash = signed_attrs_prehash::<D>(attrs)?;
	let signature_bytes = signer.signature.as_bytes();
	let signature = S::try_from(signature_bytes).map_err(|_| HandshakeError::SignatureVerificationFailed)?;
	key.verify_prehash(&prehash, &signature)
		.map_err(|_| HandshakeError::SignatureVerificationFailed)?;

	Ok(normalize_answer(answer))
}

/// Completed dual-signed receipt retained after the handshake.
///
/// Validated view over the CMS `SignedData` artifact: the body parses
/// and exactly one `SignerInfo` per role is present.
///
/// # Verification
///
/// Given the server and client certificates, [`StoredReceipt::verify`]
/// confirms both signatures from the artifact alone (no handshake
/// replay). Endpoints hold it only for the life of the session object.
#[derive(Clone)]
pub struct StoredReceipt {
	/// The dual-signed `SignedData` artifact, the single source of truth.
	artifact: SignedData,
	/// Body parsed out of the artifact's `eContent` at construction.
	receipt: SessionReceipt,
	/// Normalized settlement answer parsed out of the client
	/// `SignerInfo` at construction.
	ancillary_response: Option<OctetString>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl TryFrom<SignedData> for StoredReceipt {
	type Error = HandshakeError;

	fn try_from(artifact: SignedData) -> Result<Self, Self::Error> {
		let receipt = receipt_from_artifact(&artifact)?;

		let server_role = ReceiptRole::Server;
		signer_for_role(&artifact, server_role)?.ok_or(HandshakeError::ReceiptMissing)?;

		let client_role = ReceiptRole::Client;
		let client_signer = signer_for_role(&artifact, client_role)?.ok_or(HandshakeError::CountersignatureMissing)?;
		let answer = signer_answer(client_signer)?;
		let ancillary_response = normalize_answer(answer);

		Ok(StoredReceipt { artifact, receipt, ancillary_response })
	}
}

impl PartialEq for StoredReceipt {
	fn eq(&self, other: &Self) -> bool {
		self.artifact == other.artifact
	}
}

impl Eq for StoredReceipt {}

impl StoredReceipt {
	/// The receipt body both parties signed.
	pub fn receipt(&self) -> &SessionReceipt {
		&self.receipt
	}

	/// Application settlement answer bound by the client's signed
	/// attributes. Never parsed by TightBeam. A bearer secret: redacted
	/// from `Debug`.
	pub fn ancillary_response(&self) -> Option<&OctetString> {
		self.ancillary_response.as_ref()
	}

	/// The underlying CMS `SignedData` artifact.
	pub fn artifact(&self) -> &SignedData {
		&self.artifact
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl StoredReceipt {
	/// DER encoding of the artifact for persistence.
	pub fn to_der(&self) -> Result<Vec<u8>, HandshakeError> {
		let der = self.artifact.to_der()?;
		Ok(der)
	}

	/// The `SignerInfo` holding one role. Presence and uniqueness were
	/// validated at construction.
	pub fn signer(&self, role: ReceiptRole) -> Result<&SignerInfo, HandshakeError> {
		signer_for_role(&self.artifact, role)?.ok_or(HandshakeError::ReceiptMismatch)
	}

	/// Verify both signatures from the artifact and the two keys alone.
	///
	/// Canonical third-party check: a holder of the server and client
	/// certificates can confirm the agreement from the stored artifact
	/// without replaying the handshake.
	pub fn verify<D, S, V>(&self, server_key: &V, client_key: &V) -> Result<(), HandshakeError>
	where
		D: Digest + AssociatedOid,
		S: for<'a> TryFrom<&'a [u8]>,
		V: PrehashVerifier<S> + EncodePublicKey,
	{
		let receipt_der = self.receipt.to_der()?;

		let server_role = ReceiptRole::Server;
		let server_signer = signer_for_role(&self.artifact, server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		let server_sid = compute_signer_identifier::<D, V>(server_key)?;
		verify_receipt_signer::<D, S, V>(&receipt_der, server_signer, server_role, &server_sid, server_key)?;

		let client_role = ReceiptRole::Client;
		let client_signer =
			signer_for_role(&self.artifact, client_role)?.ok_or(HandshakeError::CountersignatureMissing)?;
		let client_sid = compute_signer_identifier::<D, V>(client_key)?;
		verify_receipt_signer::<D, S, V>(&receipt_der, client_signer, client_role, &client_sid, client_key)?;

		Ok(())
	}
}

/// Length-only stand-in for settlement-answer bytes in `Debug` output.
///
/// The answer is a bearer secret. Only presence and length may reach logs.
struct RedactedResponse(usize);

impl fmt::Debug for RedactedResponse {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "<redacted {} bytes>", self.0)
	}
}

fn redact(response: &Option<OctetString>) -> Option<RedactedResponse> {
	let bytes = response.as_ref()?;
	let length = bytes.as_bytes().len();
	Some(RedactedResponse(length))
}

impl fmt::Debug for StoredReceipt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("StoredReceipt")
			.field("receipt", &self.receipt)
			.field("ancillary_response", &redact(&self.ancillary_response))
			.finish()
	}
}

/// Refusal verdict from a [`ReceiptApprover`], carrying an
/// application-defined code from the shared u32 code space.
///
/// Application codes live at or above
/// [`MUX_APPLICATION_CODE_FLOOR`](crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR).
/// Codes below the floor are reserved for the TightBeam protocol (e.g.
/// [`SETTLEMENT_UNSUPPORTED_CODE`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalRefusal {
	/// Shared u32 refusal code (same space as settlement refusals).
	pub code: u32,
}

/// Client policy for countersigning a [`SessionReceipt`] and answering
/// its settlement challenge.
///
/// Runs between the server's handshake response and the client's key
/// exchange. Awaited inline with **no library deadline**: bound long
/// work (paying an invoice, prompting a user) yourself.
///
/// # Verdicts
///
/// - `Ok(None)` - countersign without a settlement answer.
/// - `Ok(Some(bytes))` - attach the answer (paid invoice preimage,
///   signed transaction, or other chain-format bytes). Travels only
///   encrypted to the server.
/// - [`ApprovalRefusal`] - abort the handshake with its application code.
///
/// # When no approver is installed
///
/// Challenge-free receipts are countersigned unanswered.
/// Challenge-bearing receipts abort with [`SETTLEMENT_UNSUPPORTED_CODE`].
pub trait ReceiptApprover: MaybeSend + MaybeSync {
	/// Approve the receipt and optionally attach a settlement answer.
	///
	/// # Errors
	///
	/// [`ApprovalRefusal`] aborts the handshake with its application code.
	fn approve<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>>;
}

/// Terminal verdict of a budget-bearing session's receipt lifecycle,
/// as the server observed it.
#[cfg(feature = "x509")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionVerdict {
	/// Countersignature verified and settlement accepted: the session
	/// activated.
	Activated,
	/// Countersignature verified but the authorizer refused settlement
	/// with an application code. The countersigned receipt is still the
	/// strongest evidence of the disputed agreement.
	SettlementRejected {
		/// Application-defined refusal code from the shared u32 space.
		code: u32,
	},
	/// The client returned no countersignature for the issued receipt.
	/// The handshake aborted.
	CountersignatureMissing,
	/// The client returned a countersignature that failed verification.
	/// The handshake aborted. The bytes that failed stay in the outcome:
	/// a forged-countersignature probe is audit-relevant evidence.
	CountersignatureInvalid,
}

/// Server-side record of how a budget-bearing session concluded.
///
/// The library produces the evidence. The application owns the ledger.
/// TightBeam is `no_std`-capable with no clock and no storage, so
/// timestamps and persistence belong to the [`SessionObserver`].
///
/// # Evidence
///
/// The receipt body pins the transcript hash (and through it identities
/// and negotiation). With the peer certificates the record is
/// third-party-verifiable without replaying the handshake.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct SessionOutcome {
	/// The server-issued receipt body.
	pub receipt: SessionReceipt,
	/// Receipt artifact as the server holds it: dual-signed when the
	/// countersignature verified, server-signed only otherwise.
	pub artifact: SignedData,
	/// Client receipt `SignerInfo` DER as received. Absent exactly when
	/// the verdict is [`SessionVerdict::CountersignatureMissing`].
	/// Present but unverified when it is
	/// [`SessionVerdict::CountersignatureInvalid`]. Its signed attributes
	/// carry the settlement answer, so it is redacted from `Debug` with it.
	pub countersignature: Option<OctetString>,
	/// Application settlement answer recovered from the countersignature's
	/// signed attributes, when the client attached one. A bearer secret:
	/// redacted from `Debug`.
	pub ancillary_response: Option<OctetString>,
	/// Certificate the client authenticated with, identifying the
	/// counterparty of record.
	pub client_certificate: Option<Arc<Certificate>>,
	/// Terminal lifecycle verdict observed by the server.
	pub verdict: SessionVerdict,
}

#[cfg(feature = "x509")]
impl fmt::Debug for SessionOutcome {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SessionOutcome")
			.field("receipt", &self.receipt)
			.field("countersignature", &redact(&self.countersignature))
			.field("ancillary_response", &redact(&self.ancillary_response))
			.field("client_certificate", &self.client_certificate)
			.field("verdict", &self.verdict)
			.finish()
	}
}

/// Server hook receiving the [`SessionOutcome`] of every budget-bearing
/// session whose receipt exchange concluded.
///
/// Covers activated, authorizer-refused, and countersignature
/// missing/invalid endings. Observation is a record, not a decision:
/// the hook cannot veto
/// ([`TransportAuthorizer`](crate::transport::handshake::negotiation::TransportAuthorizer)
/// already decided) and runs after the verdict is final.
///
/// # Contract
///
/// - Awaited inline before the handshake concludes with **no library
///   deadline**. Keep it fast or bound it yourself.
/// - Outcome is borrowed: `to_owned` what you retain.
/// - Stamp your own clock; persist to your own ledger for your dispute
///   window.
#[cfg(feature = "x509")]
pub trait SessionObserver: MaybeSend + MaybeSync {
	/// Observe a terminal receipt outcome.
	fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()>;
}

#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
async fn notify_observer(observer: Option<&dyn SessionObserver>, outcome: &SessionOutcome) {
	if let Some(observer) = observer {
		observer.on_outcome(outcome).await;
	}
}

/// Match a server-issued receipt against the negotiated accept.
///
/// Shared by both handshake carriages so the presence matrix and the
/// transcript / budgets / credit-unit binding cannot drift.
///
/// # Returns
///
/// - `Ok(Some(receipt))` for a budget-bearing session.
/// - `Ok(None)` for an unmetered session.
///
/// # Fail closed
///
/// - Receipt missing when budgets were granted: [`HandshakeError::ReceiptMissing`]
/// - Receipt present when unmetered: [`HandshakeError::ReceiptMismatch`]
/// - Transcript, budgets, or credit unit disagree: [`HandshakeError::ReceiptMismatch`]
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn match_receipt_to_accept<D>(
	receipt: Option<SessionReceipt>,
	granted: Option<MuxBudgets>,
	accept_credit_unit: Option<u32>,
	transcript_hash: &[u8; 32],
) -> Result<Option<SessionReceipt>, HandshakeError>
where
	D: AssociatedOid,
{
	let (receipt, granted_budgets) = match (receipt, granted) {
		(None, None) => return Ok(None),
		(None, Some(_)) => return Err(HandshakeError::ReceiptMissing),
		(Some(_), None) => return Err(HandshakeError::ReceiptMismatch),
		(Some(receipt), Some(granted)) => (receipt, granted),
	};

	let credit_unit = accept_credit_unit.ok_or(HandshakeError::ReceiptMismatch)?;
	let expected_hash = transcript_digest_info::<D>(*transcript_hash)?;
	let transcript_matches = receipt.transcript_hash == expected_hash;
	let budgets_match = receipt.budgets == granted_budgets;
	let credit_unit_matches = receipt.credit_unit == credit_unit;
	if !transcript_matches || !budgets_match || !credit_unit_matches {
		return Err(HandshakeError::ReceiptMismatch);
	}

	Ok(Some(receipt))
}

/// Canonical form of a settlement answer: zero bytes is no answer.
///
/// An absent [`RECEIPT_ANSWER`] attribute and an empty one carry the
/// same meaning, so every boundary where an answer enters the lifecycle
/// (approval, wire recovery) normalizes through here. Otherwise the two
/// endpoints of one exchange could retain diverging receipts for the
/// same signature.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn normalize_answer<T>(answer: Option<T>) -> Option<T>
where
	T: AsRef<[u8]>,
{
	answer.filter(|bytes| !bytes.as_ref().is_empty())
}

/// Approve a receipt and answer its settlement challenge, or fail closed.
///
/// # When no approver is installed
///
/// - Challenge-free: pass unanswered (`Ok(None)`).
/// - Challenge-bearing: abort with [`SETTLEMENT_UNSUPPORTED_CODE`].
///
/// # Normalization
///
/// Empty answers are stored, signed, and sent as no answer
/// ([`normalize_answer`]).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) async fn approve_or_fail_closed(
	approver: Option<&dyn ReceiptApprover>,
	receipt: &SessionReceipt,
) -> Result<Option<OctetString>, HandshakeError> {
	let Some(approver) = approver else {
		let challenge_present = receipt.ancillary.is_some();
		if challenge_present {
			return Err(HandshakeError::ApprovalRefused { code: SETTLEMENT_UNSUPPORTED_CODE });
		}

		return Ok(None);
	};

	let approval = approver.approve(receipt).await;
	let answer = approval.map_err(|refusal| HandshakeError::ApprovalRefused { code: refusal.code })?;
	let normalized = normalize_answer(answer);
	Ok(normalized)
}

/// Verify the client's countersignature and settle into a terminal verdict.
///
/// Returns the recovered settlement answer alongside the
/// [`SessionVerdict`].
///
/// # Fail closed (as verdicts, not early errors)
///
/// A failing countersignature is still a verdict so the attempt reaches
/// the observer as evidence.
///
/// # When no authorizer is installed
///
/// Activate unconditionally once the signature verifies.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub(crate) async fn settle_receipt_ack<D, S, V>(
	receipt: &SessionReceipt,
	ack: Option<&SignerInfo>,
	expected_sid: &SignerIdentifier,
	verifying_key: &V,
	authorizer: Option<&dyn TransportAuthorizer>,
) -> Result<(SessionVerdict, Option<OctetString>), HandshakeError>
where
	D: Digest + AssociatedOid,
	S: for<'a> TryFrom<&'a [u8]>,
	V: PrehashVerifier<S>,
{
	let Some(ack) = ack else {
		return Ok((SessionVerdict::CountersignatureMissing, None));
	};

	let receipt_der = receipt.to_der()?;
	let client_role = ReceiptRole::Client;
	let verified = verify_receipt_signer::<D, S, V>(&receipt_der, ack, client_role, expected_sid, verifying_key);
	let Ok(answer) = verified else {
		return Ok((SessionVerdict::CountersignatureInvalid, None));
	};

	let Some(authorizer) = authorizer else {
		return Ok((SessionVerdict::Activated, answer));
	};

	let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
	let settlement = authorizer.settle(receipt, answer_bytes).await;
	match settlement {
		Ok(()) => Ok((SessionVerdict::Activated, answer)),
		Err(refusal) => Ok((SessionVerdict::SettlementRejected { code: refusal.code }, answer)),
	}
}

/// Record the outcome with the observer, then activate or abort.
///
/// Every concluded receipt exchange reaches the observer before any
/// abort: a refused or forged acknowledgement is the strongest evidence
/// of a disputed agreement.
///
/// # Returns
///
/// - [`StoredReceipt`] when the verdict is [`SessionVerdict::Activated`].
/// - The matching abort [`HandshakeError`] for every other verdict.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub(crate) async fn record_receipt_outcome(
	observer: Option<&dyn SessionObserver>,
	outcome: SessionOutcome,
) -> Result<StoredReceipt, HandshakeError> {
	notify_observer(observer, &outcome).await;

	let SessionOutcome { artifact, verdict, .. } = outcome;
	match verdict {
		SessionVerdict::Activated => StoredReceipt::try_from(artifact),
		SessionVerdict::SettlementRejected { code } => Err(HandshakeError::SettlementRejected { code }),
		SessionVerdict::CountersignatureInvalid => Err(HandshakeError::SignatureVerificationFailed),
		SessionVerdict::CountersignatureMissing => Err(HandshakeError::CountersignatureMissing),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::{Decode, Encode, Error as DerError};

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	use crate::crypto::hash::Sha3_256;

	#[cfg(all(not(feature = "std"), feature = "transport-ecies", feature = "secp256k1"))]
	use alloc::format;
	#[cfg(all(feature = "std", feature = "transport-ecies", feature = "secp256k1"))]
	use std::format;

	const SAMPLE_TRANSCRIPT: [u8; 32] = [7u8; 32];
	const SAMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 1024 };
	const SAMPLE_CREDIT_UNIT: u32 = 1024;

	fn sample_receipt(ancillary: Option<&[u8]>) -> Result<SessionReceipt, DerError> {
		let ancillary = match ancillary {
			Some(bytes) => Some(OctetString::new(bytes)?),
			None => None,
		};

		let algorithm = crate::asn1::AlgorithmIdentifier { oid: crate::oids::HASH_SHA3_256, parameters: None };
		let digest = OctetString::new(SAMPLE_TRANSCRIPT)?;
		let receipt = SessionReceipt {
			transcript_hash: DigestInfo { algorithm, digest },
			budgets: SAMPLE_BUDGETS,
			credit_unit: SAMPLE_CREDIT_UNIT,
			ancillary,
		};
		Ok(receipt)
	}

	#[test]
	fn test_session_receipt_der_round_trip() -> Result<(), DerError> {
		for ancillary in [Some(b"lnbc-invoice".as_slice()), None] {
			let receipt = sample_receipt(ancillary)?;
			let der = receipt.to_der()?;
			let decoded = SessionReceipt::from_der(&der)?;
			assert_eq!(decoded, receipt);
		}
		Ok(())
	}

	// Known answer locks the receipt body DER encoding: wire-format
	// drift invalidates every signed receipt in the wild.
	#[test]
	fn receipt_body_encoding_known_answer() -> Result<(), DerError> {
		const KAT_BODY_DER: [u8; 78] = [
			0x30, 0x4c, 0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08, 0x04,
			0x20, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
			0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x30, 0x07, 0x02,
			0x01, 0x40, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00, 0x04, 0x0c, 0x6c, 0x6e, 0x62, 0x63, 0x2d, 0x69,
			0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65,
		];

		let receipt = sample_receipt(Some(b"lnbc-invoice"))?;
		let body_der = receipt.to_der()?;
		assert_eq!(body_der, KAT_BODY_DER);
		Ok(())
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	mod matching {
		use super::*;

		#[test]
		fn presence_matrix_fails_closed() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;

			assert!(matches!(
				match_receipt_to_accept::<Sha3_256>(None, None, None, &SAMPLE_TRANSCRIPT),
				Ok(None)
			));
			assert!(matches!(
				match_receipt_to_accept::<Sha3_256>(None, Some(granted), Some(unit), &SAMPLE_TRANSCRIPT),
				Err(HandshakeError::ReceiptMissing)
			));
			assert!(matches!(
				match_receipt_to_accept::<Sha3_256>(Some(receipt.to_owned()), None, Some(unit), &SAMPLE_TRANSCRIPT),
				Err(HandshakeError::ReceiptMismatch)
			));
			assert!(matches!(
				match_receipt_to_accept::<Sha3_256>(Some(receipt), Some(granted), Some(unit), &SAMPLE_TRANSCRIPT),
				Ok(Some(_))
			));
			Ok(())
		}

		#[test]
		fn every_binding_drift_is_a_mismatch() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;

			let mut wrong_transcript = receipt.to_owned();
			wrong_transcript.transcript_hash.digest = OctetString::new([8u8; 32])?;
			let mut wrong_algorithm = receipt.to_owned();
			wrong_algorithm.transcript_hash.algorithm.oid = crate::oids::HASH_SHA256;
			let mut wrong_budgets = receipt.to_owned();
			wrong_budgets.budgets.client_to_server += 1;
			let mut wrong_unit = receipt.to_owned();
			wrong_unit.credit_unit += 1;

			for drifted in [wrong_transcript, wrong_algorithm, wrong_budgets, wrong_unit] {
				assert!(matches!(
					match_receipt_to_accept::<Sha3_256>(Some(drifted), Some(granted), Some(unit), &SAMPLE_TRANSCRIPT),
					Err(HandshakeError::ReceiptMismatch)
				));
			}

			assert!(matches!(
				match_receipt_to_accept::<Sha3_256>(Some(receipt), Some(granted), None, &SAMPLE_TRANSCRIPT),
				Err(HandshakeError::ReceiptMismatch)
			));
			Ok(())
		}
	}

	#[cfg(all(feature = "transport-ecies", feature = "secp256k1"))]
	mod artifact {
		use super::*;
		use crate::crypto::key::{InMemorySigningKeyProvider, Secp256k1Provider};
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
		use crate::random::OsRng;

		fn test_provider() -> (Secp256k1Provider, Secp256k1VerifyingKey) {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let verifying_key = *signing_key.verifying_key();
			(InMemorySigningKeyProvider::from(signing_key), verifying_key)
		}

		async fn server_signed(
			challenge: Option<&[u8]>,
		) -> Result<(SessionReceipt, SignedData, Secp256k1VerifyingKey), HandshakeError> {
			let (server_provider, server_key) = test_provider();
			let challenge = match challenge {
				Some(bytes) => Some(OctetString::new(bytes)?),
				None => None,
			};
			let (receipt, artifact) = sign_receipt::<Sha3_256>(
				SAMPLE_TRANSCRIPT,
				SAMPLE_BUDGETS,
				SAMPLE_CREDIT_UNIT,
				challenge,
				&server_provider,
			)
			.await?;
			Ok((receipt, artifact, server_key))
		}

		async fn dual_signed(
			answer: Option<&[u8]>,
		) -> Result<(StoredReceipt, Secp256k1VerifyingKey, Secp256k1VerifyingKey), HandshakeError> {
			let (receipt, artifact, server_key) = server_signed(Some(b"challenge")).await?;
			let (client_provider, client_key) = test_provider();
			let countersignature = countersign_receipt::<Sha3_256>(&receipt, answer, &client_provider).await?;
			let completed = complete_receipt_artifact(artifact, countersignature)?;

			let stored = StoredReceipt::try_from(completed)?;
			Ok((stored, server_key, client_key))
		}

		#[tokio::test]
		async fn dual_signed_artifact_verifies() -> Result<(), HandshakeError> {
			let (stored, server_key, client_key) = dual_signed(Some(b"preimage")).await?;

			stored.verify::<Sha3_256, Secp256k1Signature, _>(&server_key, &client_key)?;

			let answer = stored.ancillary_response().map(OctetString::as_bytes);
			assert_eq!(answer, Some(b"preimage".as_slice()));
			Ok(())
		}

		#[tokio::test]
		async fn artifact_der_round_trip_preserves_equality() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(None).await?;
			let der = stored.to_der()?;
			let artifact = SignedData::from_der(&der)?;

			let decoded = StoredReceipt::try_from(artifact)?;
			assert_eq!(decoded, stored);
			Ok(())
		}

		#[tokio::test]
		async fn swapped_keys_fail_verification() -> Result<(), HandshakeError> {
			let (stored, server_key, client_key) = dual_signed(None).await?;
			let swapped = stored.verify::<Sha3_256, Secp256k1Signature, _>(&client_key, &server_key);
			assert!(matches!(swapped, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		#[tokio::test]
		async fn server_signer_rejected_in_client_role() -> Result<(), HandshakeError> {
			let (receipt, artifact, server_key) = server_signed(None).await?;
			let server_role = ReceiptRole::Server;
			let server_signer = signer_for_role(&artifact, server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
			let receipt_der = receipt.to_der()?;
			let sid = compute_signer_identifier::<Sha3_256, _>(&server_key)?;
			let client_role = ReceiptRole::Client;

			let spliced = verify_receipt_signer::<Sha3_256, Secp256k1Signature, _>(
				&receipt_der,
				server_signer,
				client_role,
				&sid,
				&server_key,
			);
			assert!(matches!(spliced, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		#[tokio::test]
		async fn server_only_artifact_is_not_a_stored_receipt() -> Result<(), HandshakeError> {
			let (_, artifact, _) = server_signed(None).await?;
			let incomplete = StoredReceipt::try_from(artifact);
			assert!(matches!(incomplete, Err(HandshakeError::CountersignatureMissing)));
			Ok(())
		}

		#[tokio::test]
		async fn debug_redacts_settlement_answer() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(Some(b"preimage")).await?;
			let rendered = format!("{stored:?}");
			assert!(rendered.contains("<redacted 8 bytes>"));
			assert!(!rendered.contains("preimage"));
			Ok(())
		}

		// The countersignature SignerInfo carries the settlement answer in
		// its signed attributes: its raw bytes are as secret as the answer.
		#[tokio::test]
		async fn outcome_debug_redacts_countersignature() -> Result<(), HandshakeError> {
			let (receipt, artifact, _) = server_signed(Some(b"challenge")).await?;
			let (client_provider, _) = test_provider();
			let countersignature =
				countersign_receipt::<Sha3_256>(&receipt, Some(b"preimage"), &client_provider).await?;
			let countersignature_der = OctetString::new(countersignature.to_der()?)?;
			let raw_debug = format!("{countersignature_der:?}");
			let countersignature_len = countersignature_der.as_bytes().len();

			let outcome = SessionOutcome {
				receipt,
				artifact,
				countersignature: Some(countersignature_der),
				ancillary_response: Some(OctetString::new(b"preimage")?),
				client_certificate: None,
				verdict: SessionVerdict::Activated,
			};
			let rendered = format!("{outcome:?}");
			assert!(!rendered.contains(&raw_debug));
			assert!(rendered.contains(&format!("<redacted {countersignature_len} bytes>")));
			assert!(rendered.contains("<redacted 8 bytes>"));
			Ok(())
		}

		#[tokio::test]
		async fn empty_answer_countersigns_as_absent() -> Result<(), HandshakeError> {
			let (stored, server_key, client_key) = dual_signed(Some(b"")).await?;

			stored.verify::<Sha3_256, Secp256k1Signature, _>(&server_key, &client_key)?;

			assert_eq!(stored.ancillary_response(), None);
			Ok(())
		}

		// A tampered acknowledgement is a verdict, not an early error:
		// the invalid attempt must surface as settleable evidence.
		#[cfg(feature = "x509")]
		#[tokio::test]
		async fn tampered_ack_settles_as_invalid_verdict() -> Result<(), HandshakeError> {
			let (receipt, _, _) = server_signed(None).await?;
			let (client_provider, client_key) = test_provider();
			let mut ack = countersign_receipt::<Sha3_256>(&receipt, Some(b"preimage"), &client_provider).await?;

			let mut forged = ack.signature.as_bytes().to_vec();
			forged[0] ^= 0x01;
			ack.signature = OctetString::new(forged)?;

			let sid = compute_signer_identifier::<Sha3_256, _>(&client_key)?;
			let (verdict, answer) =
				settle_receipt_ack::<Sha3_256, Secp256k1Signature, _>(&receipt, Some(&ack), &sid, &client_key, None)
					.await?;
			assert!(matches!(verdict, SessionVerdict::CountersignatureInvalid));
			assert!(answer.is_none());
			Ok(())
		}
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	#[test]
	fn test_normalize_answer_maps_empty_to_absent() {
		assert_eq!(normalize_answer(Some(b"".as_slice())), None);
		assert_eq!(normalize_answer(Some(b"preimage".as_slice())), Some(b"preimage".as_slice()));
		assert_eq!(normalize_answer(None::<&[u8]>), None);
	}
}

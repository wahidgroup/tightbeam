//! Dual-signed session receipts.
//!
//! A [`SessionReceipt`] binds the handshake transcript, the granted session
//! budgets, and an optional settlement challenge into one DER body. The body
//! travels as the `eContent` of a CMS `SignedData`
//! ([RFC 5652 §5](https://datatracker.ietf.org/doc/html/rfc5652#section-5))
//! with one `SignerInfo` per party.
//!
//! # Signatures
//!
//! - The server signs the body inside its handshake response.
//! - The client countersigns inside its closing leg and may answer the challenge through a signed attribute.
//! - Each signature covers the signed attributes of the receipt profile:
//!   content type, message digest, algorithm protection, the role, and for
//!   the client its answer.
//!
//! The completed artifact, held as a [`StoredReceipt`], carries the
//! certificate of each signer in its `certificates` (RFC 5652 §5.1). A third
//! party verifies it from the artifact alone, without a transcript replay: it
//! admits each certificate [`StoredReceipt::certificate`] returns against its
//! own trust, and passes both to [`StoredReceipt::verify`].
//!
//! # Price binding
//!
//! Price binding is application truth, and the [`TransportAuthorizer`] and
//! [`ReceiptApprover`] hooks enforce it. TightBeam treats the challenge and
//! the response as opaque bytes, so the check of an instrument amount against
//! `budgets x credit_unit` belongs to those hooks.
//!
//! # Confidentiality
//!
//! The two opaque fields travel differently.
//!
//! - The server's challenge travels in the cleartext handshake response. Treat
//!   it as public data and never put a secret in it.
//! - The client's answer is a bearer secret, such as a payment preimage or a
//!   signed instrument. It goes inside the client's `SignerInfo`, which travels
//!   to the server only sealed under the session's handshake secret, inside
//!   the HPKE key-exchange payload or as the `RECEIPT_ACK` attribute of the
//!   sealed CMS client Finished (see
//!   [forward secrecy](crate::transport::handshake#forward-secrecy)). `Debug`
//!   output redacts its bytes, so they cannot leak through logs.
//!
//! # Retention
//!
//! TightBeam is `no_std`-capable and has no clock and no storage, so the
//! endpoints hold the completed [`StoredReceipt`] only for the life of the
//! session object. An application that may need to prove or dispute the
//! agreement later must persist the artifact, which carries both
//! certificates, for its own dispute window.
//!
//! [`TransportAuthorizer`]:
//! crate::transport::handshake::negotiation::TransportAuthorizer

#[cfg(not(feature = "std"))]
extern crate alloc;

use core::fmt;

use crate::asn1::DigestInfo;
use crate::cms::signed_data::SignedData;
use crate::crypto::sign::Signed;
use crate::der::asn1::OctetString;
use crate::der::Sequence;
use crate::transport::handshake::negotiation::MuxBudgets;
use crate::utils::marker::{MaybeSend, MaybeSendFuture, MaybeSync};
use crate::Beamable;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::hash::ConstantTimeDigest;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod handshake {
	#[cfg(not(feature = "std"))]
	pub use alloc::vec::Vec;
	#[cfg(feature = "std")]
	pub use std::vec::Vec;

	#[cfg(not(feature = "std"))]
	pub use alloc::borrow::ToOwned;

	pub use crate::cms::cert::CertificateChoices;
	pub use crate::cms::signed_data::{CertificateSet, SignedAttributes, SignerInfo};
	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::profiles::SigningProvider;
	pub(crate) use crate::crypto::sign::CertifiedSigner;
	pub use crate::crypto::sign::{CmsSigner, SignedContent, SigningIdentity};
	pub use crate::crypto::x509::{PeerCertificate, Signing};
	pub use crate::der::asn1::{ObjectIdentifier, SetOfVec};
	pub use crate::der::{Any, Decode, Encode};
	pub use crate::oids::{RECEIPT_ANSWER, RECEIPT_ROLE, SESSION_RECEIPT_CONTENT};
	pub use crate::spki::{Error as SpkiError, SubjectPublicKeyInfoRef};
	pub use crate::transport::handshake::error::HandshakeError;
	pub use crate::transport::handshake::negotiation::SETTLEMENT_UNSUPPORTED_CODE;
	pub use crate::transport::handshake::primitives::TranscriptHash;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use handshake::*;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod owners;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use owners::{CountersignedReceipt, IssuedReceipt, PendingReceipt, Settlement};

use crate::transport::handshake::Arc;
use crate::x509::Certificate;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::negotiation::TransportAuthorizer;

/// Session agreement body the server issues for every budget-bearing
/// session.
///
/// Both receipt signatures cover every field, so the receipt binds the
/// transcript, the metered terms, and the settlement challenge together.
#[derive(Clone, Debug, Eq, PartialEq, Beamable, Sequence)]
pub struct SessionReceipt {
	/// Handshake transcript digest, encoded as a `DigestInfo` per
	/// [RFC 8017 §9.2][rfc8017-9.2].
	///
	/// The digest pins the receipt to one handshake. Replaying the receipt
	/// against another session changes the transcript and breaks the pin.
	///
	/// [rfc8017-9.2]: https://datatracker.ietf.org/doc/html/rfc8017#section-9.2
	pub transcript_hash: DigestInfo,
	/// Per-direction session budgets granted, in credits. Both sides
	/// countersign them as the metered session terms.
	pub budgets: MuxBudgets,
	/// Bytes per credit that the accept fixes for both directions. Both sides
	/// countersign it with the budgets.
	pub credit_unit: u32,
	/// Opaque settlement challenge from the server's authorizer, such as an
	/// unsigned transaction or an invoice.
	///
	/// TightBeam treats it as opaque bytes. It travels in the cleartext
	/// handshake response, so it is public data and never a secret.
	#[asn1(optional = "true")]
	pub ancillary: Option<OctetString>,
}

/// Role a receipt `SignerInfo` holds, bound by the [`RECEIPT_ROLE`]
/// signed attribute so one party's signature cannot be spliced into the
/// other role (CWE-347).
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptRole {
	/// The issuing server, which signs the receipt body alone.
	Server,
	/// The countersigning client, which also binds its settlement answer
	/// through the [`RECEIPT_ANSWER`] signed attribute.
	Client,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl ReceiptRole {
	fn code(self) -> u8 {
		match self {
			ReceiptRole::Server => 0,
			ReceiptRole::Client => 1,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

/// The content a receipt `SignerInfo` signs: the receipt body DER under the
/// receipt content type, with the role tag and, for the client, the
/// settlement answer as signed attributes of the receipt profile.
///
/// The CMS signer adds the content type, the message digest, and the
/// algorithm protection ([RFC 5652 §11][rfc5652-11], RFC 6211).
///
/// # Errors
///
/// - [`HandshakeError::DerError`] -- the role or the answer fails to encode.
///
/// [rfc5652-11]: https://datatracker.ietf.org/doc/html/rfc5652#section-11
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn receipt_content<'a>(
	receipt_der: &'a (impl AsRef<[u8]> + ?Sized),
	role: ReceiptRole,
	answer: Option<&[u8]>,
) -> Result<SignedContent<'a>, HandshakeError> {
	let role_value = Any::encode_from(&role.code())?;
	let mut content =
		SignedContent::new(SESSION_RECEIPT_CONTENT, receipt_der).with_single_valued(RECEIPT_ROLE, role_value)?;

	if let Some(answer) = answer {
		let answer_value = Any::encode_from(&OctetString::new(answer)?)?;
		content = content.with_single_valued(RECEIPT_ANSWER, answer_value)?;
	}

	Ok(content)
}

/// Find at most one single-valued signed attribute, failing closed on
/// duplicates or multi-valued attributes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

/// Settlement answer declared by a client `SignerInfo`, before
/// normalization.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

/// Sign the receipt body into a role-tagged `SignerInfo` under `identity`.
///
/// # Errors
///
/// - [`HandshakeError::DerError`] -- an attribute fails to encode.
/// - [`HandshakeError::KeyError`] -- the identity's key provider fails to sign.
/// - [`HandshakeError::SignatureVerificationFailed`] -- the provider returns
///   another encoding than its algorithm's.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn signer_info_over_receipt(
	receipt_der: impl AsRef<[u8]>,
	role: ReceiptRole,
	answer: Option<&[u8]>,
	identity: &SigningIdentity,
) -> Result<Signed<SignerInfo>, HandshakeError> {
	let content = receipt_content(receipt_der.as_ref(), role, answer)?;
	Ok(identity.sign(content).await?)
}

/// Completed dual-signed receipt retained after the handshake.
///
/// The receipt is a validated view over the CMS `SignedData` artifact. The
/// body parses, exactly one `SignerInfo` per role is present, and the
/// artifact carries the certificate each `sid` names. Given those two
/// certificates, [`StoredReceipt::verify`] confirms both signatures from the
/// artifact alone.
#[derive(Clone)]
pub struct StoredReceipt {
	/// The dual-signed `SignedData` artifact, the single source of truth.
	artifact: Signed<SignedData>,
	/// Body parsed out of the artifact's `eContent` at construction.
	receipt: SessionReceipt,
	/// Normalized settlement answer parsed out of the client
	/// `SignerInfo` at construction.
	ancillary_response: Option<OctetString>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl TryFrom<Signed<SignedData>> for StoredReceipt {
	type Error = HandshakeError;

	fn try_from(artifact: Signed<SignedData>) -> Result<Self, Self::Error> {
		let receipt = artifact.receipt()?;

		let server_role = ReceiptRole::Server;
		let server_signer = artifact.signer_for_role(server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
		let server_certificate = CmsSigner::named_certificate(&artifact, server_signer)?;
		server_certificate.ok_or(HandshakeError::MissingServerCertificate)?;

		let client_role = ReceiptRole::Client;
		let client_signer = artifact
			.signer_for_role(client_role)?
			.ok_or(HandshakeError::CountersignatureMissing)?;

		let client_certificate = CmsSigner::named_certificate(&artifact, client_signer)?;
		client_certificate.ok_or(HandshakeError::MissingClientCertificate)?;

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

	/// Application settlement answer that the client's signed attributes
	/// bind. TightBeam treats it as opaque bytes. The answer is a bearer
	/// secret, so `Debug` output redacts it.
	pub fn ancillary_response(&self) -> Option<&OctetString> {
		self.ancillary_response.as_ref()
	}

	/// The underlying CMS `SignedData` artifact.
	pub fn artifact(&self) -> &Signed<SignedData> {
		&self.artifact
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl StoredReceipt {
	/// DER encoding of the artifact for persistence.
	pub fn to_der(&self) -> Result<Vec<u8>, HandshakeError> {
		let der = self.artifact.to_der()?;
		Ok(der)
	}

	/// The `SignerInfo` that holds `role`. Construction validated its
	/// presence and uniqueness.
	pub fn signer(&self, role: ReceiptRole) -> Result<&SignerInfo, HandshakeError> {
		self.artifact.signer_for_role(role)?.ok_or(HandshakeError::ReceiptMismatch)
	}

	/// The certificate the artifact carries for `role`, which the `sid` of its
	/// `SignerInfo` names (RFC 5652 §5.3). Construction validated its presence.
	///
	/// A third-party verifier takes both certificates from here, admits each
	/// against its own trust, and passes them to [`Self::verify`]. The decode
	/// of a [`Signed`] `SignedData` holds each one to the DER it arrived as
	/// (X.690 §11.5), so the trust evaluates the bytes the issuer signed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- the role is absent or repeats.
	/// - [`HandshakeError::CertificateValidationError`] -- a key identifier fails to decode.
	///
	/// # Examples
	///
	/// A third party that holds the DER of an artifact admits each
	/// certificate against its own trust, then verifies both signatures.
	///
	/// ```
	/// use tightbeam::cms::signed_data::SignedData;
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::crypto::sign::Signed;
	/// use tightbeam::crypto::x509::policy::CertificateValidation;
	/// use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
	/// use tightbeam::der::Decode;
	/// use tightbeam::transport::handshake::receipt::{ReceiptRole, StoredReceipt};
	///
	/// /// A signer of a receipt, admitted under the house signer purpose.
	/// type Signer = PeerCertificate<Signing<DefaultCryptoProvider>>;
	///
	/// fn verify_alone(
	///     der: impl AsRef<[u8]>,
	///     trust: &dyn CertificateValidation,
	/// ) -> Result<(), Box<dyn std::error::Error>> {
	///     let artifact = Signed::<SignedData>::from_der(der.as_ref())?;
	///     let receipt = StoredReceipt::try_from(artifact)?;
	///     let server = receipt.certificate(ReceiptRole::Server)?;
	///     let client = receipt.certificate(ReceiptRole::Client)?;
	///     trust.evaluate(server)?;
	///     trust.evaluate(client)?;
	///
	///     // Each admission holds its own certificate, so it takes a copy of
	///     // the one the artifact carries.
	///     let purpose = KeyPurposes::HOUSE.signer;
	///     let server = Signer::parse(server.to_owned(), purpose)?;
	///     let client = Signer::parse(client.to_owned(), purpose)?;
	///     receipt.verify(&server, &client)?;
	///     Ok(())
	/// }
	/// ```
	pub fn certificate(&self, role: ReceiptRole) -> Result<&Certificate, HandshakeError> {
		let signer = self.signer(role)?;
		let named = CmsSigner::named_certificate(&self.artifact, signer)?;
		named.ok_or(HandshakeError::ReceiptMismatch)
	}

	/// Verify both signatures from the artifact and the two certificates
	/// alone, each admitted for signing under the provider `P`.
	///
	/// This is the canonical third-party check, and [`Self::certificate`]
	/// returns both certificates from the artifact. Each `SignerInfo` must
	/// name its certificate (RFC 5652 §5.3) and verify under its key.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMissing`] -- the artifact holds no server signer.
	/// - [`HandshakeError::CountersignatureMissing`] -- the artifact holds no client signer.
	/// - [`HandshakeError::DerError`] -- the receipt body fails to encode.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- a signer names
	///   another certificate, or its signature fails to verify.
	/// - [`HandshakeError::ReceiptMismatch`] -- the role or the answer attribute is malformed.
	pub fn verify<P>(
		&self,
		server: &PeerCertificate<Signing<P>>,
		client: &PeerCertificate<Signing<P>>,
	) -> Result<(), HandshakeError>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = SpkiError>,
	{
		let receipt = &self.receipt;
		let server_role = ReceiptRole::Server;
		let server_signer = self
			.artifact
			.signer_for_role(server_role)?
			.ok_or(HandshakeError::ReceiptMissing)?;

		receipt.verify_signer::<P>(server_signer, server_role, server)?;

		let client_role = ReceiptRole::Client;
		let client_signer = self
			.artifact
			.signer_for_role(client_role)?
			.ok_or(HandshakeError::CountersignatureMissing)?;

		receipt.verify_signer::<P>(client_signer, client_role, client)?;

		Ok(())
	}
}

/// Length-only stand-in for settlement-answer bytes in `Debug` output.
///
/// The answer is a bearer secret, so only its presence and its length may
/// reach logs.
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

/// Refusal verdict from a [`ReceiptApprover`].
///
/// The refusal carries an application-defined code from the shared u32 code
/// space.
///
/// # Code space
///
/// - Application codes sit at or above [`MUX_APPLICATION_CODE_FLOOR`].
/// - Codes below the floor are reserved for the TightBeam protocol, such as [`SETTLEMENT_UNSUPPORTED_CODE`].
///
/// [`MUX_APPLICATION_CODE_FLOOR`]: crate::transport::envelopes::MUX_APPLICATION_CODE_FLOOR
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApprovalRefusal {
	/// Refusal code from the u32 space that settlement refusals also use.
	pub code: u32,
}

/// Client policy for countersigning a [`SessionReceipt`] and answering
/// its settlement challenge.
///
/// The hook runs after the client verified the server Finished of the
/// handshake response, before its closing leg. The handshake awaits it inline
/// with **no library deadline**, so bound long work, such as paying an
/// invoice or prompting a user, in the hook.
///
/// # Verdicts
///
/// - `Ok(None)` countersigns without a settlement answer.
/// - `Ok(Some(bytes))` attaches the answer, such as a paid invoice preimage, a
///   signed transaction, or other chain-format bytes. The answer travels to the
///   server only encrypted.
/// - [`ApprovalRefusal`] aborts the handshake with its application code.
///
/// # Without an approver
///
/// The client countersigns a challenge-free receipt without an answer. A
/// challenge-bearing receipt aborts the handshake with
/// [`SETTLEMENT_UNSUPPORTED_CODE`].
pub trait ReceiptApprover: MaybeSend + MaybeSync {
	/// Approve the receipt and optionally attach a settlement answer.
	///
	/// # Errors
	///
	/// - [`ApprovalRefusal`] -- aborts the handshake with its application code.
	fn approve<'a>(
		&'a self,
		receipt: &'a SessionReceipt,
	) -> MaybeSendFuture<'a, Result<Option<OctetString>, ApprovalRefusal>>;
}

/// Terminal verdict of a budget-bearing session's receipt lifecycle,
/// as the server observed it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionVerdict {
	/// The countersignature verified and settlement succeeded, so the
	/// session activated.
	Activated,
	/// The countersignature verified, and the authorizer refused settlement
	/// with an application code. The countersigned receipt is still the
	/// strongest evidence of the disputed agreement.
	SettlementRejected {
		/// Application-defined refusal code from the shared u32 space.
		code: u32,
	},
	/// The client returned no countersignature for the issued receipt, so
	/// the handshake aborted.
	CountersignatureMissing,
	/// The client returned a countersignature that failed verification, so
	/// the handshake aborted. The failed bytes stay in the outcome, because a
	/// forged-countersignature probe is audit-relevant evidence.
	CountersignatureInvalid,
}

/// Server-side record of how a budget-bearing session concluded.
///
/// The library produces the evidence, and the application owns the ledger.
/// TightBeam is `no_std`-capable and has no clock and no storage, so
/// timestamps and persistence belong to the [`SessionObserver`].
///
/// # Evidence
///
/// The receipt body pins the transcript hash, and through it the identities
/// and the negotiation. The artifact carries the certificate of each signer
/// it holds, so a third party can verify the record without replaying the
/// handshake.
#[derive(Clone)]
#[non_exhaustive]
pub struct SessionOutcome {
	/// The server-issued receipt body.
	pub receipt: SessionReceipt,
	/// Receipt artifact as the server holds it. It is dual-signed when the
	/// countersignature verified, and server-signed only otherwise.
	pub artifact: Signed<SignedData>,
	/// Client receipt `SignerInfo` DER as received.
	///
	/// - It is `None` exactly when the verdict is [`SessionVerdict::CountersignatureMissing`].
	/// - It is present and unverified when the verdict is [`SessionVerdict::CountersignatureInvalid`].
	///
	/// Its signed attributes carry the settlement answer, so `Debug` output
	/// redacts it with the answer.
	pub countersignature: Option<OctetString>,
	/// Application settlement answer recovered from the countersignature's
	/// signed attributes, when the client attached one. The answer is a
	/// bearer secret, so `Debug` output redacts it.
	pub ancillary_response: Option<OctetString>,
	/// Certificate the client authenticated with, identifying the
	/// counterparty of record.
	pub client_certificate: Option<Arc<Certificate>>,
	/// Terminal lifecycle verdict observed by the server.
	pub verdict: SessionVerdict,
}

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
/// The hook sees every ending: activated, authorizer-refused, and
/// countersignature missing or invalid. Observation is a record: the hook
/// runs after the verdict is final, because [`TransportAuthorizer`] already
/// decided, so it has no veto.
///
/// # Contract
///
/// - The handshake awaits the hook inline before it concludes, with **no
///   library deadline**. Keep the hook fast or bound it.
/// - The outcome is borrowed, so call `to_owned` on what you retain.
/// - Stamp your own clock, and persist to your own ledger for your dispute window.
pub trait SessionObserver: MaybeSend + MaybeSync {
	/// Observe a terminal receipt outcome.
	fn on_outcome<'a>(&'a self, outcome: &'a SessionOutcome) -> MaybeSendFuture<'a, ()>;
}

/// Canonical form of a settlement answer, in which zero bytes means no answer.
///
/// An absent [`RECEIPT_ANSWER`] attribute and an empty one carry the same
/// meaning. Every boundary where an answer enters the lifecycle normalizes
/// through this function, at approval and at recovery from a received
/// `SignerInfo`. Without it, the two endpoints of one exchange could retain
/// diverging receipts for the same signature.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn normalize_answer<T>(answer: Option<T>) -> Option<T>
where
	T: AsRef<[u8]>,
{
	answer.filter(|bytes| !bytes.as_ref().is_empty())
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SessionOutcome {
	/// Report this outcome to `observer`, then resolve its verdict.
	///
	/// It returns the [`StoredReceipt`] when the verdict is
	/// [`SessionVerdict::Activated`]. Every concluded receipt exchange reaches
	/// the observer before any abort, because a refused or forged
	/// acknowledgement is the strongest evidence of a disputed agreement.
	///
	/// # Errors
	///
	/// Every verdict other than [`SessionVerdict::Activated`] aborts with the
	/// error that matches it.
	///
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused settlement.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the countersignature failed verification.
	/// - [`HandshakeError::CountersignatureMissing`] -- the client returned no countersignature.
	/// - [`HandshakeError`] -- an activated artifact fails to parse as a [`StoredReceipt`].
	pub(crate) async fn record(self, observer: Option<&dyn SessionObserver>) -> Result<StoredReceipt, HandshakeError> {
		if let Some(observer) = observer {
			observer.on_outcome(&self).await;
		}

		let SessionOutcome { artifact, verdict, .. } = self;
		match verdict {
			SessionVerdict::Activated => StoredReceipt::try_from(artifact),
			SessionVerdict::SettlementRejected { code } => Err(HandshakeError::SettlementRejected { code }),
			SessionVerdict::CountersignatureInvalid => Err(HandshakeError::SignatureVerificationFailed),
			SessionVerdict::CountersignatureMissing => Err(HandshakeError::CountersignatureMissing),
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SessionReceipt {
	/// Build the [`SessionReceipt`] body and the server-signed `SignedData`
	/// artifact around it.
	///
	/// Both handshake carriages share this function, so they build the body
	/// and the signed attributes identically.
	pub(crate) async fn issue(
		transcript_hash: TranscriptHash,
		budgets: MuxBudgets,
		credit_unit: u32,
		challenge: Option<OctetString>,
		identity: &SigningIdentity,
	) -> Result<(Self, Signed<SignedData>), HandshakeError> {
		let receipt = Self {
			transcript_hash: transcript_hash.digest_info()?,
			budgets,
			credit_unit,
			ancillary: challenge,
		};

		let receipt_der = receipt.to_der()?;
		let server_role = ReceiptRole::Server;
		let server_signer = signer_info_over_receipt(&receipt_der, server_role, None, identity).await?;
		let content = SignedContent::new(SESSION_RECEIPT_CONTENT, &receipt_der);

		// The artifact carries the server's certificate, so it verifies from
		// itself alone. A `CertificateSet` owns each certificate it holds, so
		// the artifact takes its own copy.
		let certificate = CertificateChoices::Certificate(identity.certificate().clone());
		let certificates = CertificateSet(SetOfVec::try_from(vec![certificate])?);
		let artifact = CmsSigner::signed_data(content, server_signer, Some(certificates))?;

		Ok((receipt, artifact))
	}

	/// Verify one receipt `SignerInfo` against the receipt body, the expected
	/// role, and the expected signer.
	///
	/// - The CMS signer requires the signed attributes to equal the set for
	///   the role byte for byte: content type, message digest, algorithm
	///   protection, the role, and for the client its answer.
	/// - The `sid` must name `certificate`, and the signature must verify
	///   under the certificate's key, over the attributes DER.
	///
	/// It returns the normalized settlement answer for the client role.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- a parse or verify
	///   step of the CMS signer failed. Those failures collapse to this one
	///   variant, so both carriages report the same error.
	/// - [`HandshakeError::ReceiptMismatch`] -- the answer attribute repeats,
	///   does not carry exactly one value, or does not decode.
	/// - [`HandshakeError::DerError`] -- the receipt body or a signed attribute fails to encode.
	pub(crate) fn verify_signer<P>(
		&self,
		signer: &SignerInfo,
		role: ReceiptRole,
		certificate: &PeerCertificate<Signing<P>>,
	) -> Result<Option<OctetString>, HandshakeError>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = SpkiError>,
	{
		let receipt_der = self.to_der()?;
		let answer = match role {
			ReceiptRole::Server => None,
			ReceiptRole::Client => signer_answer(signer)?,
		};

		let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
		let content = receipt_content(&receipt_der, role, answer_bytes)?;

		// The receipt pins this session's transcript hash, so its verified
		// signature is the key of no ledger and drops here.
		let verified = CmsSigner::verify_signer::<P>(signer, certificate, content);
		verified.map(drop).map_err(|_| HandshakeError::SignatureVerificationFailed)?;

		Ok(normalize_answer(answer))
	}

	/// Check the terms this receipt states against the terms the verifier
	/// expects: the transcript it pins, the budgets, and the credit unit.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- the transcript, budgets, or credit unit disagree.
	pub(crate) fn verify_terms(
		&self,
		transcript_hash: &TranscriptHash,
		budgets: MuxBudgets,
		credit_unit: u32,
	) -> Result<(), HandshakeError> {
		let expected_hash = transcript_hash.digest_info()?;
		let algorithm_matches = self.transcript_hash.algorithm == expected_hash.algorithm;

		let transcript_matches = algorithm_matches && self.transcript_hash.digest_matches(&expected_hash);
		let budgets_match = self.budgets == budgets;
		let credit_unit_matches = self.credit_unit == credit_unit;
		if !transcript_matches || !budgets_match || !credit_unit_matches {
			return Err(HandshakeError::ReceiptMismatch);
		}

		Ok(())
	}

	/// Match a server-issued receipt against the negotiated accept.
	///
	/// Both handshake carriages share this function, so the presence matrix
	/// and the transcript, budget, and credit-unit binding have one home. It
	/// returns the receipt for a budget-bearing session and `None` for an
	/// unmetered one.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMissing`] -- budgets were granted and no receipt came.
	/// - [`HandshakeError::ReceiptMismatch`] -- a receipt came for an unmetered
	///   session, or its transcript, budgets, or credit unit disagree with the
	///   accept.
	pub(crate) fn match_accept(
		receipt: Option<Self>,
		granted: Option<MuxBudgets>,
		accept_credit_unit: Option<u32>,
		transcript_hash: &TranscriptHash,
	) -> Result<Option<Self>, HandshakeError> {
		let (receipt, granted_budgets) = match (receipt, granted) {
			(None, None) => return Ok(None),
			(None, Some(_)) => return Err(HandshakeError::ReceiptMissing),
			(Some(_), None) => return Err(HandshakeError::ReceiptMismatch),
			(Some(receipt), Some(granted)) => (receipt, granted),
		};

		let credit_unit = accept_credit_unit.ok_or(HandshakeError::ReceiptMismatch)?;
		receipt.verify_terms(transcript_hash, granted_budgets, credit_unit)?;

		Ok(Some(receipt))
	}

	/// Approve a receipt and answer its settlement challenge, or fail closed.
	///
	/// # Without an approver
	///
	/// The function applies the fallback that [`ReceiptApprover`] documents, so
	/// a challenge-free receipt passes unanswered as `Ok(None)`.
	///
	/// # Normalization
	///
	/// An empty answer is stored, signed, and sent as no answer
	/// ([`normalize_answer`]).
	pub(crate) async fn approve(
		&self,
		approver: Option<&dyn ReceiptApprover>,
	) -> Result<Option<OctetString>, HandshakeError> {
		let Some(approver) = approver else {
			let challenge_present = self.ancillary.is_some();
			if challenge_present {
				return Err(HandshakeError::ApprovalRefused { code: SETTLEMENT_UNSUPPORTED_CODE });
			}

			return Ok(None);
		};

		let approval = approver.approve(self).await;
		let answer = approval.map_err(|refusal| HandshakeError::ApprovalRefused { code: refusal.code })?;
		let normalized = normalize_answer(answer);
		Ok(normalized)
	}

	/// Create the client half of the receipt's dual signature, which proves
	/// that the caller accepted the session terms this receipt states.
	///
	/// The role is fixed to `Client`, so a caller creates its own half here and
	/// [`Self::issue`] creates the server's. `answer` is the settlement
	/// answer, normalized and bound through the [`RECEIPT_ANSWER`] signed
	/// attribute. The half returns beside the certificate of `identity`.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- encoding or signing failed in the receipt or the key provider.
	pub(crate) async fn countersign(
		&self,
		answer: Option<&[u8]>,
		identity: &SigningIdentity,
	) -> Result<CertifiedSigner, HandshakeError> {
		let receipt_der = self.to_der()?;
		let client_role = ReceiptRole::Client;
		let normalized_answer = normalize_answer(answer);
		let signer = signer_info_over_receipt(&receipt_der, client_role, normalized_answer, identity).await?;
		Ok(CertifiedSigner::new(signer, identity.certificate_arc())?)
	}
}

/// Reads on a CMS receipt artifact.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait ReceiptArtifact: Sized {
	/// Parse the [`SessionReceipt`] body out of this artifact.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- the artifact carries a foreign
	///   `eContentType` or a detached body.
	/// - [`HandshakeError::DerError`] -- the body fails to decode.
	fn receipt(&self) -> Result<SessionReceipt, HandshakeError>;

	/// Find this artifact's `SignerInfo` for one role.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- the role repeats.
	fn signer_for_role(&self, role: ReceiptRole) -> Result<Option<&SignerInfo>, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl ReceiptArtifact for SignedData {
	/// The body is the content of the receipt content type, read through the
	/// CMS signer's `SignedData` checks (RFC 5652 §5.1).
	fn receipt(&self) -> Result<SessionReceipt, HandshakeError> {
		let content = CmsSigner::content(self, SESSION_RECEIPT_CONTENT);
		let body_bytes = content.map_err(|_| HandshakeError::ReceiptMismatch)?;

		let receipt = SessionReceipt::from_der(body_bytes)?;
		Ok(receipt)
	}

	fn signer_for_role(&self, role: ReceiptRole) -> Result<Option<&SignerInfo>, HandshakeError> {
		let mut found = None;
		for signer in self.signer_infos.0.iter() {
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
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl SessionReceipt {
	/// Verify the client's countersignature `ack` under `certificate` and
	/// settle into a terminal verdict, beside the settlement answer and the
	/// countersignature that verified.
	///
	/// - A failing countersignature is still a verdict instead of an early
	///   error, so the attempt reaches the observer as evidence.
	/// - With no authorizer installed, the session activates once the signature verifies.
	/// - A verified countersignature returns beside `certificate`, which its `sid` names.
	pub(crate) async fn settle_ack<P>(
		&self,
		ack: Option<Signed<SignerInfo>>,
		certificate: &PeerCertificate<Signing<P>>,
		authorizer: Option<&dyn TransportAuthorizer>,
	) -> Result<(SessionVerdict, Option<OctetString>, Option<CertifiedSigner>), HandshakeError>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = SpkiError>,
	{
		let Some(ack) = ack else {
			return Ok((SessionVerdict::CountersignatureMissing, None, None));
		};

		let client_role = ReceiptRole::Client;
		let verified = self.verify_signer::<P>(&ack, client_role, certificate);
		// A bad signature and a malformed answer attribute are peer faults, so
		// they settle into a verdict. Any other error is local and propagates.
		let answer = match verified {
			Ok(answer) => answer,
			Err(HandshakeError::SignatureVerificationFailed | HandshakeError::ReceiptMismatch) => {
				return Ok((SessionVerdict::CountersignatureInvalid, None, None));
			}
			Err(local) => return Err(local),
		};

		let countersigner = Some(CertifiedSigner::new(ack, Arc::clone(certificate.certificate()))?);
		let Some(authorizer) = authorizer else {
			return Ok((SessionVerdict::Activated, answer, countersigner));
		};

		let answer_bytes = answer.as_ref().map(OctetString::as_bytes);
		let settlement = authorizer.settle(self, answer_bytes).await;
		match settlement {
			Ok(()) => Ok((SessionVerdict::Activated, answer, countersigner)),
			Err(refusal) => Ok((SessionVerdict::SettlementRejected { code: refusal.code }, answer, countersigner)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::{Decode, Encode, Error as DerError};

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::crypto::hash::Sha3_256;
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	use crate::transport::handshake::tests::fixture_transcript;

	#[cfg(all(not(feature = "std"), feature = "transport-hpke"))]
	use alloc::format;
	#[cfg(all(feature = "std", feature = "transport-hpke"))]
	use std::format;

	const SAMPLE_TRANSCRIPT: [u8; 32] = [7u8; 32];
	const SAMPLE_BUDGETS: MuxBudgets = MuxBudgets { client_to_server: 64, server_to_client: 1024 };
	const SAMPLE_CREDIT_UNIT: u32 = 1024;

	/// [`SAMPLE_TRANSCRIPT`] as the transcript hash a receipt binds.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn sample_transcript() -> TranscriptHash {
		fixture_transcript::<Sha3_256>(SAMPLE_TRANSCRIPT)
	}

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

	// The known answer locks the receipt body DER encoding, because an
	// encoding change invalidates every signed receipt already issued.
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

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	mod matching {
		use super::*;

		#[test]
		fn presence_matrix_fails_closed() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;
			let match_accept = SessionReceipt::match_accept;
			assert!(matches!(match_accept(None, None, None, &sample_transcript()), Ok(None)));
			assert!(matches!(
				match_accept(None, Some(granted), Some(unit), &sample_transcript()),
				Err(HandshakeError::ReceiptMissing)
			));
			assert!(matches!(
				match_accept(Some(receipt.to_owned()), None, Some(unit), &sample_transcript()),
				Err(HandshakeError::ReceiptMismatch)
			));
			assert!(matches!(
				match_accept(Some(receipt), Some(granted), Some(unit), &sample_transcript()),
				Ok(Some(_))
			));
			Ok(())
		}

		#[test]
		fn every_binding_drift_is_a_mismatch() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;
			let match_accept = SessionReceipt::match_accept;

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
					match_accept(Some(drifted), Some(granted), Some(unit), &sample_transcript()),
					Err(HandshakeError::ReceiptMismatch)
				));
			}

			assert!(matches!(
				match_accept(Some(receipt), Some(granted), None, &sample_transcript()),
				Err(HandshakeError::ReceiptMismatch)
			));
			Ok(())
		}
	}

	#[cfg(feature = "transport-hpke")]
	mod artifact {
		use super::*;
		use crate::cms::content_info::CmsVersion;
		use crate::cms::signed_data::SignerInfo;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::sign::{Signed, SigningIdentity};
		use crate::crypto::x509::utils::CertificateExt;
		use crate::crypto::x509::KeyPurposes;
		use crate::der::asn1::SetOfVec;
		use crate::oids::{ATTR_CMS_ALGORITHM_PROTECTION, ATTR_CONTENT_TYPE, ATTR_MESSAGE_DIGEST};
		use crate::random::OsRng;
		use crate::testing::{TestAttributes, TestIdentity};
		use crate::transport::handshake::tests::RefusingAuthorizer;
		use crate::x509::attr::Attribute;
		use crate::x509::Certificate;

		/// One party to a receipt: its signing identity, and its certificate
		/// as a verifier admits it for signing.
		struct Party {
			identity: SigningIdentity,
			signer: PeerCertificate<Signing<DefaultCryptoProvider>>,
		}

		impl Party {
			/// A party of a fresh key, under the test certificate of that key.
			fn fresh() -> Self {
				let identity = TestIdentity::of(&Secp256k1SigningKey::random(&mut OsRng));
				let signer = PeerCertificate::parse(identity.certificate_arc(), KeyPurposes::HOUSE.signer);
				let signer = signer.expect("the test certificate is admitted for signing");
				Self { identity, signer }
			}

			fn certificate(&self) -> &Certificate {
				self.identity.certificate()
			}
		}

		async fn server_signed(
			challenge: Option<&[u8]>,
		) -> Result<(SessionReceipt, Signed<SignedData>, Party), HandshakeError> {
			let server = Party::fresh();
			let challenge = match challenge {
				Some(bytes) => Some(OctetString::new(bytes)?),
				None => None,
			};

			let (receipt, artifact) = SessionReceipt::issue(
				sample_transcript(),
				SAMPLE_BUDGETS,
				SAMPLE_CREDIT_UNIT,
				challenge,
				&server.identity,
			)
			.await?;
			Ok((receipt, artifact, server))
		}

		async fn dual_signed(answer: Option<&[u8]>) -> Result<(StoredReceipt, Party, Party), HandshakeError> {
			let (receipt, artifact, server) = server_signed(Some(b"challenge")).await?;
			let client = Party::fresh();
			let countersignature = receipt.countersign(answer, &client.identity).await?;
			let completed = artifact.with_certified_signer(countersignature)?;

			let stored = StoredReceipt::try_from(completed)?;
			Ok((stored, server, client))
		}

		/// `certificate` admitted for signing, as a third-party verifier
		/// admits a certificate it read from a receipt.
		fn admitted(certificate: &Certificate) -> PeerCertificate<Signing<DefaultCryptoProvider>> {
			let admitted = PeerCertificate::parse(certificate.to_owned(), KeyPurposes::HOUSE.signer);
			admitted.expect("a receipt's test certificate is admitted for signing")
		}

		/// The server's artifact carries the certificate its signer names, so
		/// it verifies from itself alone (RFC 5652 §5.1).
		#[tokio::test]
		async fn a_server_signed_artifact_carries_the_server_certificate() -> Result<(), Box<dyn std::error::Error>> {
			let (_, artifact, server) = server_signed(None).await?;
			let server_signer = artifact.signer_for_role(ReceiptRole::Server)?;
			let signer = server_signer.ok_or("the artifact holds a server signer")?;

			let carried = CmsSigner::named_certificate(&artifact, signer)?;
			assert_eq!(carried, Some(server.certificate()));
			Ok(())
		}

		#[tokio::test]
		async fn a_stored_receipt_returns_the_server_certificate() -> Result<(), HandshakeError> {
			let (stored, server, _) = dual_signed(None).await?;
			assert_eq!(stored.certificate(ReceiptRole::Server)?, server.certificate());
			Ok(())
		}

		#[tokio::test]
		async fn a_stored_receipt_returns_the_client_certificate() -> Result<(), HandshakeError> {
			let (stored, _, client) = dual_signed(None).await?;
			assert_eq!(stored.certificate(ReceiptRole::Client)?, client.certificate());
			Ok(())
		}

		/// A third party that holds the artifact alone takes both certificates
		/// from it, admits each, and verifies both signatures.
		#[tokio::test]
		async fn a_stored_receipt_verifies_under_the_certificates_it_carries() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(Some(b"preimage")).await?;
			let der = stored.to_der()?;
			let received = StoredReceipt::try_from(Signed::<SignedData>::from_der(&der)?)?;
			let server = admitted(received.certificate(ReceiptRole::Server)?);
			let client = admitted(received.certificate(ReceiptRole::Client)?);

			received.verify(&server, &client)?;
			Ok(())
		}

		/// An artifact that carries a countersignature without the certificate
		/// it names fails to parse as a stored receipt, because no third party
		/// can verify it alone.
		#[tokio::test]
		async fn an_artifact_without_the_client_certificate_is_not_a_stored_receipt() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(None).await?;
			let mut artifact = stored.artifact().to_owned().into_inner();
			let server = stored.certificate(ReceiptRole::Server)?;
			let kept = CertificateChoices::Certificate(server.to_owned());

			artifact.certificates = Some(CertificateSet(SetOfVec::try_from(vec![kept])?));

			let der = crate::encode(&artifact)?;
			let refused = StoredReceipt::try_from(Signed::<SignedData>::from_der(&der)?);
			assert!(matches!(refused, Err(HandshakeError::MissingClientCertificate)));
			Ok(())
		}

		#[tokio::test]
		async fn an_artifact_without_the_server_certificate_is_not_a_stored_receipt() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(None).await?;
			let mut artifact = stored.artifact().to_owned().into_inner();
			let client = stored.certificate(ReceiptRole::Client)?;
			let kept = CertificateChoices::Certificate(client.to_owned());

			artifact.certificates = Some(CertificateSet(SetOfVec::try_from(vec![kept])?));

			let refused = StoredReceipt::try_from(Signed::<SignedData>::from_der(&crate::encode(&artifact)?)?);
			assert!(matches!(refused, Err(HandshakeError::MissingServerCertificate)));
			Ok(())
		}

		#[tokio::test]
		async fn dual_signed_artifact_verifies() -> Result<(), HandshakeError> {
			let (stored, server, client) = dual_signed(Some(b"preimage")).await?;
			stored.verify(&server.signer, &client.signer)?;

			let answer = stored.ancillary_response().map(OctetString::as_bytes);
			assert_eq!(answer, Some(b"preimage".as_slice()));
			Ok(())
		}

		/// A receipt signer carries the content type, the message digest, and
		/// the algorithm protection beside its role (RFC 5652 §5.3, RFC 6211).
		#[tokio::test]
		async fn a_receipt_signer_carries_the_three_signed_attributes() -> Result<(), HandshakeError> {
			let (_, artifact, _) = server_signed(None).await?;
			let signer = artifact
				.signer_for_role(ReceiptRole::Server)?
				.ok_or(HandshakeError::ReceiptMissing)?;

			let oids = TestAttributes::oids(signer);
			assert!(oids.contains(&ATTR_CONTENT_TYPE));
			assert!(oids.contains(&ATTR_MESSAGE_DIGEST));
			assert!(oids.contains(&ATTR_CMS_ALGORITHM_PROTECTION));
			assert!(oids.contains(&RECEIPT_ROLE));
			Ok(())
		}

		/// A receipt signer names its certificate by its key identifier, so it
		/// is version 3, and so is the receipt `SignedData` (RFC 5652 §5.1).
		#[tokio::test]
		async fn a_receipt_signer_is_version_3_under_its_key_identifier() -> Result<(), HandshakeError> {
			let (_, artifact, server) = server_signed(None).await?;
			let signer = artifact
				.signer_for_role(ReceiptRole::Server)?
				.ok_or(HandshakeError::ReceiptMissing)?;

			assert_eq!(signer.version, CmsVersion::V3);
			assert_eq!(signer.sid, server.certificate().signer_identifier()?);
			assert_eq!(artifact.version, CmsVersion::V3);
			Ok(())
		}

		/// A receipt signer whose version breaks the RFC 5652 §5.3 rule is
		/// refused.
		#[tokio::test]
		async fn a_receipt_signer_of_the_wrong_version_is_refused() -> Result<(), HandshakeError> {
			let (receipt, artifact, server) = server_signed(None).await?;
			let signer = artifact
				.signer_for_role(ReceiptRole::Server)?
				.ok_or(HandshakeError::ReceiptMissing)?;

			let downgraded = SignerInfo { version: CmsVersion::V1, ..signer.clone() };
			let refused = receipt.verify_signer(&downgraded, ReceiptRole::Server, &server.signer);
			assert!(matches!(refused, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		#[tokio::test]
		async fn artifact_der_round_trip_preserves_equality() -> Result<(), HandshakeError> {
			let (stored, _, _) = dual_signed(None).await?;
			let der = stored.to_der()?;
			let artifact = Signed::<SignedData>::from_der(&der)?;

			let decoded = StoredReceipt::try_from(artifact)?;
			assert_eq!(decoded, stored);
			Ok(())
		}

		#[tokio::test]
		async fn swapped_certificates_fail_verification() -> Result<(), HandshakeError> {
			let (stored, server, client) = dual_signed(None).await?;
			let swapped = stored.verify(&client.signer, &server.signer);
			assert!(matches!(swapped, Err(HandshakeError::SignatureVerificationFailed)));
			Ok(())
		}

		#[tokio::test]
		async fn server_signer_rejected_in_client_role() -> Result<(), HandshakeError> {
			let (receipt, artifact, server) = server_signed(None).await?;
			let server_role = ReceiptRole::Server;
			let server_signer = artifact.signer_for_role(server_role)?.ok_or(HandshakeError::ReceiptMissing)?;
			let client_role = ReceiptRole::Client;

			let spliced = receipt.verify_signer(server_signer, client_role, &server.signer);
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
		// its signed attributes, so its raw bytes are as secret as the answer.
		#[tokio::test]
		async fn outcome_debug_redacts_countersignature() -> Result<(), HandshakeError> {
			let (receipt, artifact, _) = server_signed(Some(b"challenge")).await?;
			let client = Party::fresh();
			let countersignature = receipt.countersign(Some(b"preimage"), &client.identity).await?;
			let countersignature_der = OctetString::new(countersignature.signer().to_der()?)?;
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
			let (stored, server, client) = dual_signed(Some(b"")).await?;
			stored.verify(&server.signer, &client.signer)?;
			assert_eq!(stored.ancillary_response(), None);
			Ok(())
		}

		// A tampered acknowledgement is a verdict instead of an early error,
		// so the invalid attempt must surface as settleable evidence.
		#[tokio::test]
		async fn tampered_ack_settles_as_invalid_verdict() -> Result<(), HandshakeError> {
			let (receipt, _, _) = server_signed(None).await?;
			let client = Party::fresh();
			let countersigned = receipt.countersign(Some(b"preimage"), &client.identity).await?;
			let mut ack = countersigned.signer().to_owned().into_inner();

			let mut forged = ack.signature.as_bytes().to_vec();
			let last = forged.len() - 1;
			forged[last] ^= 0x01;
			ack.signature = OctetString::new(forged)?;

			let received = Signed::<SignerInfo>::from_der(&ack.to_der()?)?;
			let (verdict, answer, countersigner) = receipt.settle_ack(Some(received), &client.signer, None).await?;
			assert!(matches!(verdict, SessionVerdict::CountersignatureInvalid));
			assert!(answer.is_none());
			assert!(countersigner.is_none());
			Ok(())
		}

		/// `ack` with a second value on its answer attribute, a shape only the
		/// peer can produce.
		fn with_two_answer_values(ack: &mut SignerInfo) {
			let attributes = ack.signed_attrs.take().expect("a countersignature carries signed attributes");
			let other = OctetString::new(b"other".as_slice()).expect("short octets encode");
			let second = Any::encode_from(&other).expect("an octet string encodes");
			let rebuilt: Vec<Attribute> = attributes
				.into_vec()
				.into_iter()
				.map(|mut attribute| {
					if attribute.oid == RECEIPT_ANSWER {
						attribute.values.insert(second.clone()).expect("the second value is distinct");
					}
					attribute
				})
				.collect();

			ack.signed_attrs = Some(SetOfVec::try_from(rebuilt).expect("the attribute set stays distinct"));
		}

		#[tokio::test]
		async fn a_malformed_answer_settles_as_invalid_verdict() -> Result<(), HandshakeError> {
			let (receipt, _, _) = server_signed(None).await?;
			let client = Party::fresh();
			let countersigned = receipt.countersign(Some(b"preimage"), &client.identity).await?;
			let mut ack = countersigned.signer().to_owned().into_inner();

			with_two_answer_values(&mut ack);

			let received = Signed::<SignerInfo>::from_der(&ack.to_der()?)?;
			let (verdict, answer, countersigner) = receipt.settle_ack(Some(received), &client.signer, None).await?;
			assert!(matches!(verdict, SessionVerdict::CountersignatureInvalid));
			assert!(answer.is_none());
			assert!(countersigner.is_none());
			Ok(())
		}

		/// A countersignature that verifies, with no authorizer to settle it,
		/// activates the session beside its countersigner, which the artifact
		/// then joins.
		#[tokio::test]
		async fn a_verified_ack_activates_beside_its_countersigner() -> Result<(), HandshakeError> {
			let (receipt, _, _) = server_signed(None).await?;
			let client = Party::fresh();
			let countersigned = receipt.countersign(None, &client.identity).await?;
			let received = countersigned.signer().to_owned();

			let (verdict, _, countersigner) = receipt.settle_ack(Some(received), &client.signer, None).await?;
			assert!(matches!((verdict, countersigner), (SessionVerdict::Activated, Some(_))));
			Ok(())
		}

		/// A countersignature that verifies beside a refused settlement still
		/// returns beside its countersigner, so the refused artifact carries it
		/// as the evidence of the dispute.
		#[tokio::test]
		async fn a_refused_settlement_returns_beside_its_countersigner() -> Result<(), HandshakeError> {
			let (receipt, _, _) = server_signed(Some(b"challenge")).await?;
			let client = Party::fresh();
			let countersigned = receipt.countersign(Some(b"preimage"), &client.identity).await?;
			let received = countersigned.signer().to_owned();

			let authorizer: &dyn TransportAuthorizer = &RefusingAuthorizer;
			let settling = receipt.settle_ack(Some(received), &client.signer, Some(authorizer));
			let (verdict, _, countersigner) = settling.await?;
			assert!(matches!(
				(verdict, countersigner),
				(SessionVerdict::SettlementRejected { .. }, Some(_))
			));
			Ok(())
		}
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn test_normalize_answer_maps_empty_to_absent() {
		assert_eq!(normalize_answer(Some(b"".as_slice())), None);
		assert_eq!(normalize_answer(Some(b"preimage".as_slice())), Some(b"preimage".as_slice()));
		assert_eq!(normalize_answer(None::<&[u8]>), None);
	}
}

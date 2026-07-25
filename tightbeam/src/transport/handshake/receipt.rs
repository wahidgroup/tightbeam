//! Dual-signed session receipts.
//!
//! A [`SessionReceipt`] binds the handshake transcript, the granted session
//! budgets, and an optional settlement challenge into one DER artifact.
//! The server signs the receipt body inside its handshake response. The
//! client countersigns (optionally answering the challenge) inside its key
//! exchange. The completed [`StoredReceipt`] is verifiable by a third party
//! holding both certificates: signatures cover the receipt body DER, not the
//! transcript, so verification needs no transcript replay.
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
//! secret (a payment preimage, a signed instrument): it travels only
//! encrypted to the server (inside the ECIES key-exchange payload, or a
//! CMS `EnvelopedData`), and its bytes are redacted from `Debug` output
//! so they cannot leak through logs.
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

	pub use crate::crypto::hash::Digest;
	pub use crate::crypto::key::SigningKeyProvider;
	pub use crate::crypto::sign::PrehashVerifier;
	pub use crate::der::Encode;
	pub use crate::transport::handshake::error::HandshakeError;
	pub use crate::transport::handshake::negotiation::SETTLEMENT_UNSUPPORTED_CODE;
	pub use crate::transport::handshake::utils::compute_transcript_digest;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use handshake::*;

#[cfg(feature = "x509")]
mod x509 {
	pub use crate::transport::handshake::Arc;
	pub use crate::x509::Certificate;

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub use crate::transport::handshake::negotiation::TransportAuthorizer;
}

#[cfg(feature = "x509")]
use x509::*;

/// Domain tag for the server's receipt signature digest.
///
/// Domain separation keeps the two receipt signatures from covering
/// identical bytes (CWE-347 splice resistance across roles).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const RECEIPT_SERVER_CONTEXT: &[u8] = b"tightbeam-receipt-server-v1";

/// Domain tag for the client's receipt countersignature digest.
///
/// Paired with [`RECEIPT_SERVER_CONTEXT`] so a server signature cannot be
/// spliced into the client role (CWE-347).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
const RECEIPT_CLIENT_CONTEXT: &[u8] = b"tightbeam-receipt-client-v1";

/// Session agreement artifact issued by the server for every
/// budget-bearing session.
///
/// The `transcript_hash` pins the receipt to one handshake. Replaying
/// it against another session changes the transcript and breaks the pin.
/// `ancillary` carries the server's settlement challenge (unsigned
/// transaction, invoice, anything) as opaque bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct SessionReceipt {
	/// 32-byte handshake transcript hash pinning the receipt to a session.
	pub transcript_hash: OctetString,
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

/// Completed dual-signed receipt retained after the handshake.
///
/// Self-contained third-party artifact: given the server and client
/// certificates, both signatures verify against the receipt body DER alone.
/// Endpoints hold it only for the life of the session object.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(feature = "derive", derive(Beamable, Sequence))]
pub struct StoredReceipt {
	/// The receipt body both parties signed.
	pub receipt: SessionReceipt,
	/// Server signature over the domain-tagged receipt body digest.
	pub server_signature: OctetString,
	/// Client countersignature over the domain-tagged receipt body digest
	/// plus the ancillary response.
	pub client_signature: OctetString,
	/// Application settlement answer produced by the client's approver.
	/// Never parsed by TightBeam. A bearer secret: redacted from `Debug`.
	#[asn1(optional = "true")]
	pub ancillary_response: Option<OctetString>,
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
	response.as_ref().map(|bytes| RedactedResponse(bytes.as_bytes().len()))
}

impl fmt::Debug for StoredReceipt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("StoredReceipt")
			.field("receipt", &self.receipt)
			.field("server_signature", &self.server_signature)
			.field("client_signature", &self.client_signature)
			.field("ancillary_response", &redact(&self.ancillary_response))
			.finish()
	}
}

impl StoredReceipt {
	/// Verify both signatures from the receipt body and the two keys alone.
	///
	/// Canonical third-party check: a holder of the server and client
	/// certificates can confirm the agreement from the stored artifact
	/// without replaying the handshake.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub fn verify<D, S, V>(&self, server_key: &V, client_key: &V) -> Result<(), HandshakeError>
	where
		D: Digest,
		S: for<'a> TryFrom<&'a [u8]>,
		V: PrehashVerifier<S>,
	{
		let receipt_der = self.receipt.to_der()?;
		verify_server_receipt::<D, S, V>(&receipt_der, self.server_signature.as_bytes(), server_key)?;
		let settlement_answer = self.ancillary_response.as_ref().map(OctetString::as_bytes);
		verify_client_receipt::<D, S, V>(&receipt_der, settlement_answer, self.client_signature.as_bytes(), client_key)
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

/// Client hook deciding whether to countersign a [`SessionReceipt`] and
/// answering its settlement challenge.
///
/// Runs between the server's handshake response and the client's key
/// exchange. `Ok(None)` countersigns without a settlement answer.
/// `Ok(Some(bytes))` attaches the answer (paid invoice preimage, signed
/// transaction, anything) in chain format. A refusal aborts the handshake.
/// The answer travels only encrypted to the server.
///
/// Without a configured approver the client fails closed: challenge-free
/// receipts are countersigned, challenge-bearing receipts abort.
///
/// The hook is awaited inline in the handshake and TightBeam imposes no
/// deadline: a slow approval (paying an invoice, prompting a user) stalls
/// the handshake and whatever peer timeout applies, so bound long
/// settlements with your own timeout.
pub trait ReceiptApprover: MaybeSend + MaybeSync {
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
/// timestamps and persistence belong to the [`SessionObserver`] that
/// receives this record. The receipt body pins the transcript hash (and
/// through it identities and negotiation), so the record is
/// third-party-verifiable against the certificates alone.
#[cfg(feature = "x509")]
#[derive(Clone)]
pub struct SessionOutcome {
	/// The server-issued receipt body.
	pub receipt: SessionReceipt,
	/// Server signature over the domain-tagged receipt body digest.
	pub server_signature: OctetString,
	/// Client countersignature bytes as received. Absent exactly when
	/// the verdict is [`SessionVerdict::CountersignatureMissing`].
	/// Present but unverified when it is
	/// [`SessionVerdict::CountersignatureInvalid`].
	pub client_signature: Option<OctetString>,
	/// Application settlement answer recovered from the confidential
	/// carriage, when the client attached one. A bearer secret: redacted
	/// from `Debug`.
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
			.field("server_signature", &self.server_signature)
			.field("client_signature", &self.client_signature)
			.field("ancillary_response", &redact(&self.ancillary_response))
			.field("client_certificate", &self.client_certificate)
			.field("verdict", &self.verdict)
			.finish()
	}
}

/// Server hook receiving the [`SessionOutcome`] of every budget-bearing
/// session whose receipt exchange concluded: activated, refused by the
/// authorizer, or aborted on a missing or invalid countersignature.
///
/// Observation is a record, not a decision: the hook cannot veto (the
/// [`TransportAuthorizer`](crate::transport::handshake::negotiation::TransportAuthorizer)
/// already decided) and runs after the verdict is final. Implementations
/// stamp their own clock and persist to their own ledger, retaining the
/// evidence for their own dispute window.
///
/// The hook is awaited inline before the handshake concludes and has no
/// library deadline: keep it fast (enqueue, don't flush) or bound it with
/// your own timeout.
#[cfg(feature = "x509")]
pub trait SessionObserver: MaybeSend + MaybeSync {
	fn on_outcome<'a>(&'a self, outcome: SessionOutcome) -> MaybeSendFuture<'a, ()>;
}

#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
async fn notify_observer(observer: Option<&dyn SessionObserver>, outcome: SessionOutcome) {
	if let Some(observer) = observer {
		observer.on_outcome(outcome).await;
	}
}

/// Domain-tagged digest the server signs over the receipt body DER.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn server_receipt_digest<D>(receipt_der: &[u8]) -> Result<[u8; 32], HandshakeError>
where
	D: Digest,
{
	let mut tagged_body = Vec::with_capacity(RECEIPT_SERVER_CONTEXT.len() + receipt_der.len());
	tagged_body.extend_from_slice(RECEIPT_SERVER_CONTEXT);
	tagged_body.extend_from_slice(receipt_der);

	compute_transcript_digest::<D>(&tagged_body)
}

/// Domain-tagged digest the client countersigns: receipt body DER plus the
/// ancillary response.
///
/// The receipt DER is self-delimiting, so concatenation with trailing
/// response bytes is unambiguous.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn client_receipt_digest<D>(receipt_der: &[u8], response: Option<&[u8]>) -> Result<[u8; 32], HandshakeError>
where
	D: Digest,
{
	let response_bytes = response.unwrap_or_default();
	let mut tagged_body = Vec::with_capacity(RECEIPT_CLIENT_CONTEXT.len() + receipt_der.len() + response_bytes.len());
	tagged_body.extend_from_slice(RECEIPT_CLIENT_CONTEXT);
	tagged_body.extend_from_slice(receipt_der);
	tagged_body.extend_from_slice(response_bytes);

	compute_transcript_digest::<D>(&tagged_body)
}

/// Match a server-issued receipt against the negotiated accept, failing
/// closed on every disagreement.
///
/// Returns the receipt for a budget-bearing session, or `None` for an
/// unmetered one. Shared by both handshake carriages so the presence
/// matrix and the transcript/budgets/credit-unit binding cannot drift.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn match_receipt_to_accept<'a>(
	receipt: Option<&'a SessionReceipt>,
	granted: Option<MuxBudgets>,
	accept_credit_unit: Option<u32>,
	transcript_hash: &[u8; 32],
) -> Result<Option<&'a SessionReceipt>, HandshakeError> {
	let (receipt, granted_budgets) = match (receipt, granted) {
		(None, None) => return Ok(None),
		(None, Some(_)) => return Err(HandshakeError::ReceiptMissing),
		(Some(_), None) => return Err(HandshakeError::ReceiptMismatch),
		(Some(receipt), Some(granted)) => (receipt, granted),
	};

	let credit_unit = accept_credit_unit.ok_or(HandshakeError::ReceiptMismatch)?;
	let transcript_matches = receipt.transcript_hash.as_bytes() == transcript_hash;
	let budgets_match = receipt.budgets == granted_budgets;
	let credit_unit_matches = receipt.credit_unit == credit_unit;
	if !transcript_matches || !budgets_match || !credit_unit_matches {
		return Err(HandshakeError::ReceiptMismatch);
	}

	Ok(Some(receipt))
}

/// Canonical form of a settlement answer: zero bytes is no answer.
///
/// [`client_receipt_digest`] appends the raw answer bytes, so an empty
/// answer countersigns identically to an absent one. Every boundary
/// where an answer enters the lifecycle (approval, wire recovery)
/// normalizes through here. Otherwise the two endpoints of one
/// exchange could retain diverging receipts for the same signature.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) fn normalize_answer<T>(answer: Option<T>) -> Option<T>
where
	T: AsRef<[u8]>,
{
	answer.filter(|bytes| !bytes.as_ref().is_empty())
}

/// Approve a receipt and answer its settlement challenge, or fail closed.
///
/// Without an approver, challenge-free receipts pass unanswered and
/// challenge-bearing receipts abort with [`SETTLEMENT_UNSUPPORTED_CODE`].
/// The answer is normalized: an empty answer is stored, signed, and
/// sent as no answer.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub async fn approve_or_fail_closed(
	approver: Option<&dyn ReceiptApprover>,
	receipt: &SessionReceipt,
) -> Result<Option<OctetString>, HandshakeError> {
	match approver {
		Some(approver) => approver
			.approve(receipt)
			.await
			.map(normalize_answer)
			.map_err(|refusal| HandshakeError::ApprovalRefused { code: refusal.code }),
		None if receipt.ancillary.is_some() => {
			Err(HandshakeError::ApprovalRefused { code: SETTLEMENT_UNSUPPORTED_CODE })
		}
		None => Ok(None),
	}
}

/// Build the [`SessionReceipt`] body and sign it with the server key.
///
/// Shared by both handshake carriages so the body construction and the
/// domain-tagged signing cannot drift.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) async fn sign_receipt<D>(
	transcript_hash: [u8; 32],
	budgets: MuxBudgets,
	credit_unit: u32,
	challenge: Option<OctetString>,
	key_provider: &dyn SigningKeyProvider,
) -> Result<(SessionReceipt, OctetString), HandshakeError>
where
	D: Digest,
{
	let transcript_hash_octets = OctetString::new(transcript_hash)?;
	let receipt = SessionReceipt {
		transcript_hash: transcript_hash_octets,
		budgets,
		credit_unit,
		ancillary: challenge,
	};
	let receipt_der = receipt.to_der()?;
	let receipt_digest = server_receipt_digest::<D>(&receipt_der)?;
	let signature_bytes = key_provider.sign_prehash(&receipt_digest).await?;

	Ok((receipt, OctetString::new(signature_bytes)?))
}

/// Verify the client countersignature and settle it into a terminal verdict.
///
/// A failing countersignature is a verdict, not an early error: the
/// attempt must still reach the observer as evidence. Sessions without
/// an authorizer activate unconditionally once the signature verifies.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub(crate) async fn settle_countersignature<D, S, V>(
	receipt: &SessionReceipt,
	response: Option<&[u8]>,
	signature: &[u8],
	verifying_key: &V,
	authorizer: Option<&dyn TransportAuthorizer>,
) -> Result<SessionVerdict, HandshakeError>
where
	D: Digest,
	S: for<'a> TryFrom<&'a [u8]>,
	V: PrehashVerifier<S>,
{
	let receipt_der = receipt.to_der()?;
	let signature_valid = verify_client_receipt::<D, S, V>(&receipt_der, response, signature, verifying_key).is_ok();
	if !signature_valid {
		return Ok(SessionVerdict::CountersignatureInvalid);
	}

	let Some(authorizer) = authorizer else {
		return Ok(SessionVerdict::Activated);
	};

	match authorizer.settle(receipt, response).await {
		Ok(()) => Ok(SessionVerdict::Activated),
		Err(refusal) => Ok(SessionVerdict::SettlementRejected { code: refusal.code }),
	}
}

/// Record the outcome with the observer, then activate or abort.
///
/// Every concluded receipt exchange reaches the observer before any
/// abort: a refused or forged acknowledgement is the strongest evidence
/// of a disputed agreement. Returns the completed [`StoredReceipt`] for
/// an activated session. Every other verdict maps to its abort error.
#[cfg(all(feature = "x509", any(feature = "transport-cms", feature = "transport-ecies")))]
pub(crate) async fn record_receipt_outcome(
	observer: Option<&dyn SessionObserver>,
	outcome: SessionOutcome,
) -> Result<StoredReceipt, HandshakeError> {
	notify_observer(observer, outcome.clone()).await;

	let SessionOutcome { receipt, server_signature, client_signature, ancillary_response, verdict, .. } = outcome;
	match (verdict, client_signature) {
		(SessionVerdict::Activated, Some(client_signature)) => {
			Ok(StoredReceipt { receipt, server_signature, client_signature, ancillary_response })
		}
		(SessionVerdict::SettlementRejected { code }, _) => Err(HandshakeError::SettlementRejected { code }),
		(SessionVerdict::CountersignatureInvalid, _) => Err(HandshakeError::SignatureVerificationFailed),
		(_, _) => Err(HandshakeError::CountersignatureMissing),
	}
}

/// Verify the server's signature over the receipt body.
///
/// Parse and verify failures collapse to one variant so both carriages
/// report the same error.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn verify_server_receipt<D, S, V>(receipt_der: &[u8], signature: &[u8], key: &V) -> Result<(), HandshakeError>
where
	D: Digest,
	S: for<'a> TryFrom<&'a [u8]>,
	V: PrehashVerifier<S>,
{
	let digest = server_receipt_digest::<D>(receipt_der)?;
	let parsed_signature = S::try_from(signature).map_err(|_| HandshakeError::SignatureVerificationFailed)?;
	key.verify_prehash(&digest, &parsed_signature)
		.map_err(|_| HandshakeError::SignatureVerificationFailed)
}

/// Verify the client's countersignature over the receipt body plus the
/// ancillary response.
///
/// Parse and verify failures collapse to one variant so both carriages
/// report the same error.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub fn verify_client_receipt<D, S, V>(
	receipt_der: &[u8],
	response: Option<&[u8]>,
	signature: &[u8],
	key: &V,
) -> Result<(), HandshakeError>
where
	D: Digest,
	S: for<'a> TryFrom<&'a [u8]>,
	V: PrehashVerifier<S>,
{
	let digest = client_receipt_digest::<D>(receipt_der, response)?;
	let parsed_signature = S::try_from(signature).map_err(|_| HandshakeError::SignatureVerificationFailed)?;
	key.verify_prehash(&digest, &parsed_signature)
		.map_err(|_| HandshakeError::SignatureVerificationFailed)
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::{Decode, Encode, Error as DerError};

	#[cfg(not(feature = "std"))]
	use alloc::format;
	#[cfg(feature = "std")]
	use std::format;

	fn sample_receipt(ancillary: Option<&[u8]>) -> Result<SessionReceipt, DerError> {
		let ancillary = match ancillary {
			Some(bytes) => Some(OctetString::new(bytes)?),
			None => None,
		};

		Ok(SessionReceipt {
			transcript_hash: OctetString::new([7u8; 32])?,
			budgets: MuxBudgets { client_to_server: 64, server_to_client: 1024 },
			credit_unit: 1024,
			ancillary,
		})
	}

	#[test]
	fn test_session_receipt_der_round_trip() -> Result<(), DerError> {
		let receipt = sample_receipt(Some(b"lnbc-invoice"))?;
		let der = receipt.to_der()?;
		let decoded = SessionReceipt::from_der(&der)?;
		assert_eq!(decoded, receipt);
		Ok(())
	}

	#[test]
	fn test_session_receipt_der_round_trip_without_ancillary() -> Result<(), DerError> {
		let receipt = sample_receipt(None)?;
		let der = receipt.to_der()?;
		let decoded = SessionReceipt::from_der(&der)?;
		assert_eq!(decoded, receipt);
		Ok(())
	}

	#[test]
	fn test_stored_receipt_der_round_trip() -> Result<(), DerError> {
		let stored = StoredReceipt {
			receipt: sample_receipt(Some(b"challenge"))?,
			server_signature: OctetString::new([1u8; 64])?,
			client_signature: OctetString::new([2u8; 64])?,
			ancillary_response: Some(OctetString::new(b"preimage".as_slice())?),
		};
		let der = stored.to_der()?;
		let decoded = StoredReceipt::from_der(&der)?;
		assert_eq!(decoded, stored);
		Ok(())
	}

	#[test]
	fn debug_redacts_settlement_answer() -> Result<(), DerError> {
		let stored = StoredReceipt {
			receipt: sample_receipt(Some(b"challenge"))?,
			server_signature: OctetString::new([1u8; 64])?,
			client_signature: OctetString::new([2u8; 64])?,
			ancillary_response: Some(OctetString::new(b"preimage".as_slice())?),
		};
		let rendered = format!("{stored:?}");
		assert!(rendered.contains("<redacted 8 bytes>"));
		Ok(())
	}

	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	mod matching {
		use super::*;

		const TRANSCRIPT: [u8; 32] = [7u8; 32];

		#[test]
		fn presence_matrix_fails_closed() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;

			assert!(matches!(match_receipt_to_accept(None, None, None, &TRANSCRIPT), Ok(None)));
			assert!(matches!(
				match_receipt_to_accept(None, Some(granted), Some(unit), &TRANSCRIPT),
				Err(HandshakeError::ReceiptMissing)
			));
			assert!(matches!(
				match_receipt_to_accept(Some(&receipt), None, Some(unit), &TRANSCRIPT),
				Err(HandshakeError::ReceiptMismatch)
			));
			assert!(matches!(
				match_receipt_to_accept(Some(&receipt), Some(granted), Some(unit), &TRANSCRIPT),
				Ok(Some(_))
			));
			Ok(())
		}

		#[test]
		fn every_binding_drift_is_a_mismatch() -> Result<(), DerError> {
			let receipt = sample_receipt(None)?;
			let granted = receipt.budgets;
			let unit = receipt.credit_unit;

			let mut wrong_transcript = receipt.clone();
			wrong_transcript.transcript_hash = OctetString::new([8u8; 32])?;
			let mut wrong_budgets = receipt.clone();
			wrong_budgets.budgets.client_to_server += 1;
			let mut wrong_unit = receipt.clone();
			wrong_unit.credit_unit += 1;

			for drifted in [&wrong_transcript, &wrong_budgets, &wrong_unit] {
				assert!(matches!(
					match_receipt_to_accept(Some(drifted), Some(granted), Some(unit), &TRANSCRIPT),
					Err(HandshakeError::ReceiptMismatch)
				));
			}

			assert!(matches!(
				match_receipt_to_accept(Some(&receipt), Some(granted), None, &TRANSCRIPT),
				Err(HandshakeError::ReceiptMismatch)
			));
			Ok(())
		}
	}

	// Both carriages share the digest construction, so either alone
	// keeps the known-answer regression net
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	mod digests {
		use super::*;
		use crate::crypto::hash::Sha3_256;

		#[test]
		fn test_server_and_client_digests_domain_separated() -> Result<(), HandshakeError> {
			let receipt = sample_receipt(None)?;
			let der = receipt.to_der()?;
			let server_digest = server_receipt_digest::<Sha3_256>(&der)?;
			let client_digest = client_receipt_digest::<Sha3_256>(&der, None)?;
			assert_ne!(server_digest, client_digest);
			Ok(())
		}

		// Known answers lock receipt body DER encoding and domain-tagged
		// digest construction: wire-format or domain-tag drift invalidates
		// every signed receipt in the wild.
		const KAT_BODY_DER: [u8; 63] = [
			0x30, 0x3d, 0x04, 0x20, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
			0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
			0x30, 0x07, 0x02, 0x01, 0x40, 0x02, 0x02, 0x04, 0x00, 0x02, 0x02, 0x04, 0x00, 0x04, 0x0c, 0x6c, 0x6e, 0x62,
			0x63, 0x2d, 0x69, 0x6e, 0x76, 0x6f, 0x69, 0x63, 0x65,
		];
		const KAT_SERVER_DIGEST: [u8; 32] = [
			0xcd, 0x1c, 0x02, 0xd6, 0xfb, 0xa5, 0x61, 0x61, 0x8f, 0x12, 0xe8, 0x31, 0xa6, 0xac, 0x8b, 0x74, 0x22, 0xe3,
			0x4d, 0x16, 0xa7, 0x23, 0x95, 0xc8, 0xad, 0xf3, 0xaf, 0x0f, 0x69, 0xe3, 0xb8, 0xc2,
		];
		const KAT_CLIENT_UNANSWERED_DIGEST: [u8; 32] = [
			0x81, 0x60, 0xe5, 0x3f, 0x8b, 0x8e, 0xbd, 0x35, 0xf8, 0x26, 0x61, 0xf2, 0xb3, 0x2d, 0xf4, 0x1e, 0xdb, 0x46,
			0x64, 0x1b, 0xef, 0x19, 0x45, 0xad, 0x6c, 0xb7, 0x06, 0xbd, 0xe6, 0xd9, 0x16, 0x83,
		];
		const KAT_CLIENT_ANSWERED_DIGEST: [u8; 32] = [
			0x1b, 0x12, 0xf7, 0xed, 0x08, 0x35, 0x62, 0x1f, 0x5e, 0x26, 0xaa, 0x8f, 0x0c, 0x7a, 0x16, 0x3b, 0x6e, 0x2e,
			0x54, 0x12, 0x21, 0x18, 0x57, 0x37, 0xbd, 0x88, 0xd6, 0x34, 0xa4, 0x37, 0x32, 0xf3,
		];

		#[test]
		fn receipt_body_encoding_known_answer() -> Result<(), HandshakeError> {
			let receipt = sample_receipt(Some(b"lnbc-invoice"))?;
			assert_eq!(receipt.to_der()?, KAT_BODY_DER);
			Ok(())
		}

		#[test]
		fn digest_known_answers() -> Result<(), HandshakeError> {
			assert_eq!(
				server_receipt_digest::<Sha3_256>(&KAT_BODY_DER)?.as_slice(),
				KAT_SERVER_DIGEST.as_slice()
			);
			assert_eq!(
				client_receipt_digest::<Sha3_256>(&KAT_BODY_DER, None)?.as_slice(),
				KAT_CLIENT_UNANSWERED_DIGEST.as_slice()
			);
			assert_eq!(
				client_receipt_digest::<Sha3_256>(&KAT_BODY_DER, Some(b"preimage"))?.as_slice(),
				KAT_CLIENT_ANSWERED_DIGEST.as_slice()
			);
			Ok(())
		}

		#[test]
		fn test_client_digest_binds_response() -> Result<(), HandshakeError> {
			let receipt = sample_receipt(Some(b"challenge"))?;
			let der = receipt.to_der()?;
			let unanswered_digest = client_receipt_digest::<Sha3_256>(&der, None)?;
			let answered_digest = client_receipt_digest::<Sha3_256>(&der, Some(b"preimage"))?;
			assert_ne!(unanswered_digest, answered_digest);
			Ok(())
		}

		// Digest cannot tell empty answer from absent, so every boundary
		// MUST canonicalize empty to absent.
		#[test]
		fn test_client_digest_conflates_empty_and_absent_response() -> Result<(), HandshakeError> {
			let receipt = sample_receipt(Some(b"challenge"))?;
			let der = receipt.to_der()?;
			let absent_digest = client_receipt_digest::<Sha3_256>(&der, None)?;
			let empty_digest = client_receipt_digest::<Sha3_256>(&der, Some(b""))?;
			assert_eq!(absent_digest, empty_digest);
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

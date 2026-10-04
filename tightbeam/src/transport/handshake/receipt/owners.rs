//! The receipt each side holds between two legs.
//!
//! - [`IssuedReceipt`] is the server's, issued at the
//!   [reply](crate::transport::handshake#legs) and settled at the closing.
//! - [`PendingReceipt`] is the client's, verified at the reply and countersigned in the closing.
//!
//! The module is private, so the two owners stay inside the crate. The server
//! holds its [`IssuedReceipt`] in the phase that awaits the closing, and the
//! client holds its [`PendingReceipt`] inside the step that reads the reply.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::crypto::hash::Digest;
use crate::crypto::key::SigningKeyProvider;
use crate::der::asn1::OctetString;
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Encode};
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::negotiation::{TransportAccept, TransportAuthorizer};
use crate::transport::handshake::receipt::{
	ReceiptApprover, ReceiptArtifact, ReceiptRole, ReceiptSigner, SessionObserver, SessionOutcome, SessionReceipt,
	SessionVerdict, StoredReceipt,
};
use crate::transport::handshake::schedule::{HandshakeVerifyingKey, Terms};
use crate::transport::handshake::{AdmittedPeer, Arc, HandshakeProvider, HandshakeSecret};
use crate::transport::state::ClientIdentity;
use crate::x509::Certificate;
use crate::zeroize::Zeroizing;

/// The receipt a server issued and the artifact it signed, held from the
/// [reply](crate::transport::handshake#legs) to the settlement.
pub struct IssuedReceipt {
	receipt: SessionReceipt,
	artifact: SignedData,
}

impl IssuedReceipt {
	/// Issue and sign the receipt of a budget-bearing session.
	///
	/// It returns `None` when `accept` grants no budgets. The receipt pins
	/// `transcript_hash`, and `challenge` is the settlement challenge the
	/// authorizer attached.
	///
	/// # Fail closed
	///
	/// Budgets demand a client countersignature, so a budget-bearing accept on
	/// a server that requires no client certificate aborts the handshake.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MutualAuthRequired`] -- the accept grants budgets,
	///   and `requires_certificate` is `false`.
	/// - [`HandshakeError`] -- encoding or signing failed in the receipt or the key provider.
	pub(crate) async fn issue<D>(
		transcript_hash: [u8; 32],
		accept: Option<&TransportAccept>,
		challenge: Option<OctetString>,
		requires_certificate: bool,
		key: &dyn SigningKeyProvider,
	) -> Result<Option<Self>, HandshakeError>
	where
		D: Digest + AssociatedOid,
	{
		let Some(accept) = accept else {
			return Ok(None);
		};
		let Some(granted) = accept.granted_budgets else {
			return Ok(None);
		};
		if !requires_certificate {
			return Err(HandshakeError::MutualAuthRequired);
		}

		let credit_unit = accept.credit_unit;
		let issuing = SessionReceipt::issue::<D>(transcript_hash, granted, credit_unit, challenge, key);
		let (receipt, artifact) = issuing.await?;
		Ok(Some(Self { receipt, artifact }))
	}

	/// The server-signed artifact the server's handshake message carries to
	/// the client.
	pub(crate) fn artifact(&self) -> &SignedData {
		&self.artifact
	}

	/// Open the client's sealed countersignature, verify it, settle with the
	/// authorizer, and record the outcome.
	///
	/// The step runs in that order, and it fails closed. A missing or invalid
	/// countersignature aborts the handshake, and so does a settle refusal.
	/// Every concluded exchange reaches `observer` first.
	///
	/// # Ordering
	///
	/// Settlement is an irreversible external side effect, so the caller runs
	/// this as the last gate of the [closing], after every cheaper refusal.
	///
	/// [closing]: crate::transport::handshake#legs
	///
	/// # Errors
	///
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the sealed countersignature fails to open.
	/// - [`HandshakeError::DerError`] -- the opened countersignature is not a `SignerInfo`.
	/// - [`HandshakeError::MutualAuthRequired`] -- `peer` proved no certificate.
	/// - [`HandshakeError::CountersignatureMissing`] -- `sealed_ack` is `None`.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the countersignature fails to verify.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused the settlement answer.
	async fn settle<P>(
		self,
		sealed_ack: Option<impl AsRef<[u8]>>,
		secret: &HandshakeSecret,
		terms: &Terms<P>,
		peer: &AdmittedPeer,
		authorizer: Option<&dyn TransportAuthorizer>,
		observer: Option<&dyn SessionObserver>,
	) -> Result<StoredReceipt, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Self { receipt, artifact } = self;

		// The acknowledgement is the client's receipt SignerInfo sealed under
		// the handshake secret. Its signed attributes bind the bearer
		// settlement answer, so the plaintext wipes on drop.
		let ack = match sealed_ack {
			Some(sealed) => {
				let plaintext = secret.open_ack::<P>(terms.kdf_salt(), terms.transcript_hash(), sealed)?;
				Some(plaintext.with(|bytes| SignerInfo::from_der(bytes))?)
			}
			None => None,
		};

		let (verdict, ancillary_response) = match ack.as_ref() {
			None => (SessionVerdict::CountersignatureMissing, None),
			Some(ack) => {
				let client = peer.proven().ok_or(HandshakeError::MutualAuthRequired)?;
				let sid = client.signer_identifier::<P::Digest>()?;
				let public_key = client.verifying_key::<P::Curve>()?;
				let key = P::VerifyingKey::from(public_key);

				let settling = receipt.settle_ack::<P::Digest, P::Signature, _>(Some(ack), &sid, &key, authorizer);
				settling.await?
			}
		};

		// Take the evidence DER before the move. The raw bytes stay in the
		// outcome even when the SignerInfo folds into the artifact.
		let countersignature = ack.as_ref().map(SignerInfo::to_der).transpose()?;

		// A verified countersignature completes the artifact. A failed one
		// stays out of it, but its DER remains in the outcome as evidence.
		let artifact = match (verdict, ack) {
			(SessionVerdict::Activated | SessionVerdict::SettlementRejected { .. }, Some(ack)) => {
				artifact.complete(ack)?
			}
			(_, _) => artifact,
		};

		let countersignature = countersignature.map(OctetString::new).transpose()?;
		let client_certificate = peer.proven().map(Arc::clone);
		let outcome = SessionOutcome {
			receipt,
			artifact,
			countersignature,
			ancillary_response,
			client_certificate,
			verdict,
		};
		outcome.record(observer).await
	}

	/// Settle the receipt of a session, when the session issued one.
	///
	/// A session that issued no receipt owes no acknowledgement, so one that
	/// arrives is refused instead of being dropped.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- an acknowledgement came, and no receipt was issued.
	/// - The errors of [`Self::settle`], for an issued receipt.
	pub(crate) async fn settle_issued<P>(
		issued: Option<Self>,
		sealed_ack: Option<impl AsRef<[u8]>>,
		secret: &HandshakeSecret,
		terms: &Terms<P>,
		peer: &AdmittedPeer,
		authorizer: Option<&dyn TransportAuthorizer>,
		observer: Option<&dyn SessionObserver>,
	) -> Result<Option<StoredReceipt>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		match (issued, sealed_ack) {
			(Some(issued), sealed_ack) => {
				let settling = issued.settle(sealed_ack, secret, terms, peer, authorizer, observer);
				Ok(Some(settling.await?))
			}
			(None, Some(_)) => Err(HandshakeError::ReceiptMismatch),
			(None, None) => Ok(None),
		}
	}
}

/// The receipt a client verified and the artifact it arrived in, held from
/// the [reply](crate::transport::handshake#legs) to the countersignature.
pub struct PendingReceipt {
	receipt: SessionReceipt,
	artifact: SignedData,
}

impl PendingReceipt {
	/// Match the server's receipt against the negotiated `accept`, and verify
	/// the server's signature over it under the key of `server`.
	///
	/// It returns `None` for an unmetered session. A budget-bearing accept
	/// demands an artifact whose body states the negotiated terms over
	/// `transcript_hash` and whose server [`SignerInfo`] verifies.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMissing`] -- budgets were granted, and no signed receipt came.
	/// - [`HandshakeError::ReceiptMismatch`] -- a receipt came for an unmetered
	///   session, or it disagrees with the accept or the transcript.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the server signature fails to verify.
	/// - [`HandshakeError::InvalidPublicKey`] -- the server key is not a point on the curve.
	pub(crate) fn verify<P>(
		artifact: Option<SignedData>,
		accept: Option<&TransportAccept>,
		transcript_hash: &[u8; 32],
		server: &Certificate,
	) -> Result<Option<Self>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let granted = accept.and_then(|accept| accept.granted_budgets);
		let credit_unit = accept.map(|accept| accept.credit_unit);
		let parsed = artifact.as_ref().map(ReceiptArtifact::receipt).transpose()?;
		let matched = SessionReceipt::match_accept::<P::Digest>(parsed, granted, credit_unit, transcript_hash)?;
		let Some(receipt) = matched else {
			return Ok(None);
		};

		// The server SignerInfo over the receipt body makes the agreement
		// verifiable by a third party, so an unsigned receipt is no receipt.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let role = ReceiptRole::Server;
		let signed = artifact.signer_for_role(role)?;
		let signer = signed.ok_or(HandshakeError::ReceiptMissing)?;

		let sid = server.signer_identifier::<P::Digest>()?;
		let public_key = server.verifying_key::<P::Curve>()?;
		let key = P::VerifyingKey::from(public_key);
		receipt.verify_signer::<P::Digest, P::Signature, _>(signer, role, &sid, &key)?;

		Ok(Some(Self { receipt, artifact }))
	}

	/// Approve the receipt, countersign it under `identity`, and seal the
	/// countersignature under the handshake secret.
	///
	/// - It returns the sealed bytes for the closing and the completed receipt both endpoints retain.
	/// - The approver, or the fail-closed default, answers the settlement challenge.
	/// - The countersignature binds the receipt body and that answer to the client identity.
	///
	/// # Fail closed
	///
	/// A countersignature needs a client identity the server can verify, so a
	/// client with none refuses the receipt. The refusal runs before approval,
	/// because approval can spend an irreversible settlement answer.
	///
	/// # Confidentiality
	///
	/// The countersignature binds the bearer settlement answer in its signed
	/// attributes, so it travels only sealed. What the seal withholds from a
	/// holder of the server's static key is stated under
	/// [forward secrecy](crate::transport::handshake#forward-secrecy).
	///
	/// # Errors
	///
	/// - [`HandshakeError::MutualAuthRequired`] -- `identity` is `None`.
	/// - [`HandshakeError::ApprovalRefused`] -- the approver refused, or a
	///   challenge arrived with no approver set.
	/// - [`HandshakeError::KeyError`] -- the identity's key provider failed.
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the acknowledgement key.
	/// - [`HandshakeError::InvalidKeyMaterialLength`] -- the cipher refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the AEAD refused to seal.
	pub(crate) async fn countersign<P>(
		self,
		approver: Option<&dyn ReceiptApprover>,
		identity: Option<&ClientIdentity<P>>,
		secret: &HandshakeSecret,
		terms: &Terms<P>,
	) -> Result<(Vec<u8>, StoredReceipt), HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Self { receipt, artifact } = self;
		let identity = identity.ok_or(HandshakeError::MutualAuthRequired)?;

		let response = receipt.approve(approver).await?;
		let answer = response.as_ref().map(OctetString::as_bytes);
		let countersignature = receipt.countersign::<P::Digest>(answer, identity.signing_provider()).await?;

		let ack_der = Zeroizing::new(countersignature.to_der()?);
		let sealed_ack = secret.seal_ack::<P>(terms.kdf_salt(), terms.transcript_hash(), &ack_der)?;

		// Both endpoints retain the identical completed artifact.
		let completed = artifact.complete(countersignature)?;
		let stored = StoredReceipt::try_from(completed)?;
		Ok((sealed_ack, stored))
	}
}

#[cfg(all(test, feature = "transport-ecies", feature = "secp256k1"))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::transport::handshake::tests::{
		budget_offer, create_test_certificate, into_provider, TestCertificate, TEST_BUDGETS,
	};

	/// The transcript hash the test receipts bind.
	const TRANSCRIPT: [u8; 32] = [7u8; 32];

	/// An accept that grants the test budgets.
	fn budget_accept() -> TransportAccept {
		let offer = budget_offer();
		TransportAccept {
			mux: true,
			max_peer_initiated_streams: offer.max_peer_initiated_streams,
			chunk_payload_size: offer.chunk_payload_size,
			credit_unit: 1024,
			initial_stream_credit: offer.initial_stream_credit,
			granted_budgets: Some(TEST_BUDGETS),
		}
	}

	/// The artifact a server holding `server` issues for the budget accept
	/// over the test transcript.
	async fn issued_by(server: &TestCertificate) -> SignedData {
		let key = into_provider(server.signing_key.to_owned());
		let accept = budget_accept();
		let issuing = IssuedReceipt::issue::<Sha3_256>(TRANSCRIPT, Some(&accept), None, true, key.as_ref());

		let issued = issuing.await.expect("the test key signs the receipt");
		let issued = issued.expect("a budget-bearing accept issues a receipt");
		issued.artifact().to_owned()
	}

	/// Verify `artifact` as a client that admitted `server`.
	fn verified_under(
		artifact: SignedData,
		server: &TestCertificate,
	) -> Result<Option<PendingReceipt>, HandshakeError> {
		let accept = budget_accept();
		let certificate = &server.certificate;
		PendingReceipt::verify::<DefaultCryptoProvider>(Some(artifact), Some(&accept), &TRANSCRIPT, certificate)
	}

	#[tokio::test]
	async fn a_receipt_the_admitted_server_signed_is_kept() -> Result<(), Box<dyn Error>> {
		let server = create_test_certificate();
		let artifact = issued_by(&server).await;

		let pending = verified_under(artifact, &server)?;
		assert!(pending.is_some());
		Ok(())
	}

	/// A receipt signed under another key is no agreement with the server
	/// the client admitted, so it is refused.
	#[tokio::test]
	async fn a_receipt_another_key_signed_is_refused() {
		let server = create_test_certificate();
		let artifact = issued_by(&create_test_certificate()).await;

		let refusal = verified_under(artifact, &server);
		assert!(matches!(refusal, Err(HandshakeError::SignatureVerificationFailed)));
	}

	/// A server that demands no client certificate has no countersigner to
	/// verify, so it refuses to issue a budget-bearing receipt.
	#[tokio::test]
	async fn budgets_with_no_client_certificate_issue_no_receipt() {
		let key = into_provider(create_test_certificate().signing_key);
		let accept = budget_accept();

		let issuing = IssuedReceipt::issue::<Sha3_256>(TRANSCRIPT, Some(&accept), None, false, key.as_ref());
		assert!(matches!(issuing.await, Err(HandshakeError::MutualAuthRequired)));
	}

	/// An unmetered session issues no receipt.
	#[tokio::test]
	async fn an_accept_with_no_budgets_issues_no_receipt() -> Result<(), Box<dyn Error>> {
		let key = into_provider(create_test_certificate().signing_key);
		let accept = TransportAccept { granted_budgets: None, ..budget_accept() };

		let issued = IssuedReceipt::issue::<Sha3_256>(TRANSCRIPT, Some(&accept), None, true, key.as_ref()).await?;
		assert!(issued.is_none());
		Ok(())
	}
}

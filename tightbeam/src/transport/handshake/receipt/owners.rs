//! The receipt each side holds between two legs.
//!
//! - [`IssuedReceipt`] is the server's, issued at the
//!   [reply](crate::transport::handshake#legs) and settled at the closing.
//! - [`PendingReceipt`] is the client's, verified at the reply and countersigned in the closing.
//! - [`CountersignedReceipt`] is what the countersignature leaves, until the handshake secret seals it.
//!
//! The module is private, so the owners stay inside the crate. The server
//! holds its [`IssuedReceipt`] in the phase that awaits the closing, and the
//! client holds the other two inside the step that reads the reply.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::cms::signed_data::{SignedData, SignerInfo};
use crate::crypto::sign::{CertifiedSigner, Signed, SigningIdentity};
use crate::crypto::x509::{PeerCertificate, Signing};
use crate::der::asn1::OctetString;
use crate::der::{Decode, Encode};
use crate::oids::DATA;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::flow::ServerConfirmed;
use crate::transport::handshake::negotiation::{TransportAccept, TransportAuthorizer};
use crate::transport::handshake::primitives::TranscriptHash;
use crate::transport::handshake::receipt::{
	ReceiptApprover, ReceiptArtifact, ReceiptRole, SessionObserver, SessionOutcome, SessionReceipt, SessionVerdict,
	StoredReceipt,
};
use crate::transport::handshake::schedule::{ConfirmedSecret, SecretSeal, Terms};
use crate::transport::handshake::{AdmittedPeer, Arc, HandshakeProvider, HandshakeSecret};
use crate::zeroize::Zeroizing;

/// What a server settles a receipt against: the secret and the terms of the
/// handshake, the peer the closing admitted, and the two hooks of the server.
pub(crate) struct Settlement<'a, P: HandshakeProvider> {
	/// The handshake secret the client proved it holds.
	pub(crate) secret: &'a ConfirmedSecret,
	/// The terms the handshake agreed.
	pub(crate) terms: &'a Terms<P>,
	/// The peer the closing admitted.
	pub(crate) peer: &'a AdmittedPeer<P>,
	/// The authorizer that settles the countersigned receipt.
	pub(crate) authorizer: Option<&'a dyn TransportAuthorizer>,
	/// The observer every concluded exchange reaches.
	pub(crate) observer: Option<&'a dyn SessionObserver>,
}

/// The receipt a server issued and the artifact it signed, held from the
/// [reply](crate::transport::handshake#legs) to the settlement.
pub struct IssuedReceipt {
	receipt: SessionReceipt,
	artifact: Signed<SignedData>,
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
	pub(crate) async fn issue(
		transcript_hash: TranscriptHash,
		accept: Option<&TransportAccept>,
		challenge: Option<OctetString>,
		requires_certificate: bool,
		identity: &SigningIdentity,
	) -> Result<Option<Self>, HandshakeError> {
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
		let issuing = SessionReceipt::issue(transcript_hash, granted, credit_unit, challenge, identity);
		let (receipt, artifact) = issuing.await?;
		Ok(Some(Self { receipt, artifact }))
	}

	/// The server-signed artifact the server's handshake message carries to
	/// the client.
	pub(crate) fn artifact(&self) -> &Signed<SignedData> {
		&self.artifact
	}

	/// Open the client's sealed countersignature, verify it, settle with the
	/// authorizer, and record the outcome.
	///
	/// The step runs in that order, and it fails closed. A missing or invalid
	/// countersignature aborts the handshake, and so does a settlement refusal.
	/// Every concluded exchange reaches the observer first.
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
	/// - [`HandshakeError::ReceiptAckCipher`] -- the sealed countersignature fails to open.
	/// - [`HandshakeError::DerError`] -- the opened countersignature is not a
	///   `SignerInfo`, or the transcript hash attribute fails to encode.
	/// - [`HandshakeError::MutualAuthRequired`] -- the peer proved no certificate.
	/// - [`HandshakeError::CountersignatureMissing`] -- `sealed_ack` is `None`.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the countersignature fails to verify.
	/// - [`HandshakeError::SettlementRejected`] -- the authorizer refused the settlement answer.
	async fn settle<P>(
		self,
		sealed_ack: Option<impl AsRef<[u8]>>,
		settlement: Settlement<'_, P>,
	) -> Result<StoredReceipt, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Self { receipt, artifact } = self;
		let Settlement { secret, terms, peer, authorizer, observer } = settlement;

		// The acknowledgement is the client's receipt SignerInfo sealed under
		// the handshake secret. Its signed attributes bind the bearer
		// settlement answer, so the plaintext wipes on drop.
		let ack = match sealed_ack {
			Some(sealed) => {
				let key = secret.secret();
				let sealer = terms.sealer(key, SecretSeal::Ack)?;
				let plaintext = sealer.open(SecretSeal::Ack.admit(sealed)?, DATA).await?;
				Some(plaintext.with(|bytes| Signed::<SignerInfo>::from_der(bytes))?)
			}
			None => None,
		};

		// Take the evidence DER before the move. The raw bytes stay in the
		// outcome even when the SignerInfo folds into the artifact.
		let countersignature = ack.as_ref().map(Encode::to_der).transpose()?;

		let (verdict, ancillary_response, countersigner) = match ack {
			None => (SessionVerdict::CountersignatureMissing, None, None),
			Some(ack) => {
				let client = peer.proven().ok_or(HandshakeError::MutualAuthRequired)?;
				let settling = receipt.settle_ack::<P>(Some(ack), client, authorizer);
				settling.await?
			}
		};

		// A verified countersignature completes the artifact, beside the
		// certificate it verified under. A failed one stays out of it, but its
		// DER remains in the outcome as evidence.
		let proven = peer.proven();
		let client_certificate = proven.map(|identity| Arc::clone(identity.certificate()));
		let artifact = match countersigner {
			Some(countersigner) => artifact.with_certified_signer(countersigner)?,
			None => artifact,
		};

		let countersignature = countersignature.map(OctetString::new).transpose()?;
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
	/// A session that issued no receipt owes no acknowledgement, so this
	/// function refuses one that arrives instead of dropping it. The secret
	/// is a [`ConfirmedSecret`], so no settlement runs for a client that did
	/// not prove it holds the handshake secret.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ReceiptMismatch`] -- an acknowledgement came, and no receipt was issued.
	/// - The errors of [`Self::settle`], for an issued receipt.
	pub(crate) async fn settle_issued<P>(
		issued: Option<Self>,
		sealed_ack: Option<impl AsRef<[u8]>>,
		settlement: Settlement<'_, P>,
	) -> Result<Option<StoredReceipt>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		match (issued, sealed_ack) {
			(Some(issued), sealed_ack) => {
				let settling = issued.settle(sealed_ack, settlement);
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
	artifact: Signed<SignedData>,
}

impl PendingReceipt {
	/// Match the server's receipt against the negotiated `accept`, and verify
	/// the server's signature over it under the key of `server`. It takes the
	/// proof that the server Finished verified (RFC 9846 §4.5.3).
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
	pub(crate) fn verify<P>(
		_confirmed: &ServerConfirmed,
		artifact: Option<Signed<SignedData>>,
		accept: Option<&TransportAccept>,
		transcript_hash: &TranscriptHash,
		server: &PeerCertificate<Signing<P>>,
	) -> Result<Option<Self>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let granted = accept.and_then(|accept| accept.granted_budgets);
		let credit_unit = accept.map(|accept| accept.credit_unit);
		let parsed = artifact.as_ref().map(|artifact| artifact.receipt()).transpose()?;
		let matched = SessionReceipt::match_accept(parsed, granted, credit_unit, transcript_hash)?;
		let Some(receipt) = matched else {
			return Ok(None);
		};

		// The server SignerInfo over the receipt body makes the agreement
		// verifiable by a third party, so an unsigned receipt is no receipt.
		let artifact = artifact.ok_or(HandshakeError::ReceiptMissing)?;
		let role = ReceiptRole::Server;
		let signed = artifact.signer_for_role(role)?;
		let signer = signed.ok_or(HandshakeError::ReceiptMissing)?;

		receipt.verify_signer::<P>(signer, role, server)?;

		Ok(Some(Self { receipt, artifact }))
	}

	/// Approve the receipt, and countersign it under `identity`.
	///
	/// - The approver, or the fail-closed default, answers the settlement challenge.
	/// - The countersignature binds the receipt body and that answer to the client identity.
	///
	/// Both awaits run here. [`Self::verify`] took the proof that the server
	/// Finished verified, so the approver answers only a server that proved the
	/// handshake secret, and [`CountersignedReceipt::seal`] seals the result
	/// with no await.
	///
	/// # Fail closed
	///
	/// A countersignature needs a client identity the server can verify, so a
	/// client with none refuses the receipt. The refusal runs before approval,
	/// because approval can spend an irreversible settlement answer.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MutualAuthRequired`] -- `identity` is `None`.
	/// - [`HandshakeError::ApprovalRefused`] -- the approver refused, or a
	///   challenge arrived with no approver set.
	/// - [`HandshakeError::KeyError`] -- the identity's key provider failed.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the provider
	///   returned another encoding than its algorithm's.
	pub(crate) async fn countersign(
		self,
		approver: Option<&dyn ReceiptApprover>,
		identity: Option<&SigningIdentity>,
	) -> Result<CountersignedReceipt, HandshakeError> {
		let Self { receipt, artifact } = self;
		let identity = identity.ok_or(HandshakeError::MutualAuthRequired)?;

		let response = receipt.approve(approver).await?;
		let answer = response.as_ref().map(OctetString::as_bytes);
		let countersignature = receipt.countersign(answer, identity).await?;
		Ok(CountersignedReceipt { artifact, countersignature })
	}
}

/// The receipt a client approved and countersigned, held until the handshake
/// secret exists to seal the countersignature.
pub struct CountersignedReceipt {
	artifact: Signed<SignedData>,
	/// The countersignature, beside the certificate of the client identity
	/// that made it.
	countersignature: CertifiedSigner,
}

impl CountersignedReceipt {
	/// Seal the countersignature under the handshake secret, and complete the
	/// receipt.
	///
	/// It returns the DER of the envelope for the closing and the completed
	/// receipt both endpoints retain.
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
	/// - [`HandshakeError::KdfError`] -- the provider KDF refused the acknowledgement key.
	/// - [`HandshakeError::ReceiptAckCipher`] -- the envelope refused to seal.
	/// - [`HandshakeError::DerError`] -- the countersignature or the envelope fails to encode.
	pub(crate) fn seal<P>(
		self,
		secret: &HandshakeSecret,
		terms: &Terms<P>,
	) -> Result<(Vec<u8>, StoredReceipt), HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Self { artifact, countersignature } = self;
		let mut ack_der = Zeroizing::new(countersignature.signer().to_der()?);
		let sealer = terms.sealer(secret, SecretSeal::Ack)?;
		let sealed_ack = sealer.seal(DATA, core::mem::take(&mut *ack_der))?.to_der()?;

		// Both endpoints retain the identical completed artifact, which
		// carries the client's certificate beside the countersignature. A
		// `CertificateSet` owns each certificate it holds, so the artifact
		// takes its own copy.
		let completed = artifact.with_certified_signer(countersignature)?;
		let stored = StoredReceipt::try_from(completed)?;
		Ok((sealed_ack, stored))
	}
}

#[cfg(all(test, feature = "transport-hpke"))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::KeyPurposes;
	use crate::transport::handshake::tests::{
		budget_offer, create_test_certificate, fixture_handshake_secret, fixture_transcript, signing_identity,
		TestCertificate, TEST_BUDGETS,
	};

	/// The transcript hash the test receipts bind.
	fn transcript() -> TranscriptHash {
		fixture_transcript::<Sha3_256>([7u8; 32])
	}

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
	async fn issued_by(server: &TestCertificate) -> Signed<SignedData> {
		let identity = signing_identity(server);
		let accept = budget_accept();
		let issuing = IssuedReceipt::issue(transcript(), Some(&accept), None, true, &identity);

		let issued = issuing.await.expect("the test key signs the receipt");
		let issued = issued.expect("a budget-bearing accept issues a receipt");
		issued.artifact().to_owned()
	}

	/// Verify `artifact` as a client that admitted `server` and confirmed its
	/// server Finished.
	fn verified_under(
		artifact: Signed<SignedData>,
		server: &TestCertificate,
	) -> Result<Option<PendingReceipt>, HandshakeError> {
		let accept = budget_accept();
		let identity = PeerCertificate::parse(server.certificate.clone(), KeyPurposes::HOUSE.server);
		let identity = identity.expect("the test certificate holds a point");
		let confirmed = ServerConfirmed::assumed(fixture_handshake_secret(0x42));
		let artifact = Some(artifact);
		PendingReceipt::verify::<DefaultCryptoProvider>(&confirmed, artifact, Some(&accept), &transcript(), &identity)
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
		let identity = signing_identity(&create_test_certificate());
		let accept = budget_accept();

		let issuing = IssuedReceipt::issue(transcript(), Some(&accept), None, false, &identity);
		assert!(matches!(issuing.await, Err(HandshakeError::MutualAuthRequired)));
	}

	/// An unmetered session issues no receipt.
	#[tokio::test]
	async fn an_accept_with_no_budgets_issues_no_receipt() -> Result<(), Box<dyn Error>> {
		let identity = signing_identity(&create_test_certificate());
		let accept = TransportAccept { granted_budgets: None, ..budget_accept() };

		let issued = IssuedReceipt::issue(transcript(), Some(&accept), None, true, &identity).await?;
		assert!(issued.is_none());
		Ok(())
	}
}

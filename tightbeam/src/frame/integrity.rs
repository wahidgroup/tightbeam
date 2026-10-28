use crate::core::{IntegrityVerdict, Message};
use crate::crypto::commitment::Opening;
use crate::crypto::hash::{ConstantTimeDigest, Digest};
use crate::der::oid::AssociatedOid;
use crate::error::Result;
use crate::frame::FrameIntegrityScaffold;
use crate::Frame;

impl Frame {
	/// Compute the hash of the frame with the digest algorithm `D`.
	///
	/// # Errors
	///
	/// - The frame does not encode, or its digest does not fit a `DigestInfo`.
	pub fn compute_hash<D>(&self) -> Result<crate::DigestInfo>
	where
		D: Digest + AssociatedOid,
	{
		let encoded = crate::encode(self)?;
		crate::utils::digest::<D>(&encoded)
	}

	/// Check a disclosed [`Opening`] against this frame's message commitment,
	/// and report which condition held.
	pub fn message_commitment_verdict<D>(&self, opening: &Opening) -> Result<IntegrityVerdict>
	where
		D: Digest + AssociatedOid,
	{
		let Some(commitment) = self.metadata.integrity.as_ref() else {
			return Ok(IntegrityVerdict::Absent);
		};
		if commitment.algorithm.oid != D::OID {
			return Ok(IntegrityVerdict::AlgorithmMismatch);
		}

		if opening.verify::<D>(commitment)? {
			Ok(IntegrityVerdict::Verified)
		} else {
			Ok(IntegrityVerdict::Mismatch)
		}
	}

	/// Verify a disclosed [`Opening`] against this frame's message commitment.
	///
	/// It reduces [`Frame::message_commitment_verdict`] to a `bool`, with
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch alike.
	/// A caller that must tell a stripped commitment from a tampered one uses
	/// the verdict.
	pub fn verify_message_commitment<D>(&self, opening: &Opening) -> Result<bool>
	where
		D: Digest + AssociatedOid,
	{
		Ok(self.message_commitment_verdict::<D>(opening)?.is_verified())
	}

	/// Verify this frame's message commitment against a message the caller
	/// holds, with the opening proved again in place.
	///
	/// It joins the proof of an [`Opening`] and
	/// [`Frame::verify_message_commitment`] for a receiver that already decoded
	/// the typed message.
	///
	/// # Contract
	///
	/// - After [`Frame::decrypt_in_place`] unwraps the body, the commitment in
	///   `metadata.integrity` is the surviving cryptographic bind between the
	///   frame and that cleartext.
	/// - `salt` must match the value the sender committed with.
	///
	/// # Returns
	///
	/// `Ok(false)` covers absence, algorithm mismatch, and digest mismatch
	/// alike. A caller that must tell them apart uses
	/// [`Frame::message_commitment_verdict`].
	///
	/// # Errors
	///
	/// - [`InvalidSaltLength`](crate::TightBeamError::InvalidSaltLength) -- a
	///   non-empty `salt` is too short to have hidden the body.
	/// - The encoding errors of `message`.
	pub fn verify_commitment_of<D, M>(&self, message: &M, salt: impl AsRef<[u8]>) -> Result<bool>
	where
		D: Digest + AssociatedOid,
		M: Message,
	{
		let (_, opening) = Opening::prove::<D, M>(message, salt)?;
		self.verify_message_commitment::<D>(&opening)
	}

	/// Check this frame's frame-integrity (FI) digest, and report which
	/// condition held.
	///
	/// It computes `H(SEQUENCE { version, metadata })` again under `D` and
	/// compares it with the stored digest.
	///
	/// # Ordering
	///
	/// The FI digest covers the wire envelope, any `confidentiality` info
	/// included. Verify it *before* [`Frame::decrypt_in_place`], because
	/// decryption rewrites the envelope, and the digest of the rewritten
	/// envelope differs.
	///
	/// # See also
	///
	/// [`Frame::verify_commitment_of`]: the message commitment is the
	/// integrity check that survives decryption.
	pub fn frame_integrity_verdict<D>(&self) -> Result<IntegrityVerdict>
	where
		D: Digest + AssociatedOid,
	{
		let Some(info) = self.integrity.as_ref() else {
			return Ok(IntegrityVerdict::Absent);
		};
		if info.algorithm.oid != D::OID {
			return Ok(IntegrityVerdict::AlgorithmMismatch);
		}

		let scaffold = FrameIntegrityScaffold { version: &self.version, metadata: &self.metadata };
		let recomputed = crate::utils::digest::<D>(&crate::encode(&scaffold)?)?;
		if recomputed.digest_matches(info) {
			Ok(IntegrityVerdict::Verified)
		} else {
			Ok(IntegrityVerdict::Mismatch)
		}
	}

	/// Verify this frame's frame-integrity (FI) digest.
	///
	/// It reduces [`Frame::frame_integrity_verdict`] to a `bool`, with
	/// `Ok(false)` for absence, algorithm mismatch, and digest mismatch alike.
	/// A caller that must tell a stripped FI field from a tampered envelope
	/// uses the verdict.
	pub fn verify_frame_integrity<D>(&self) -> Result<bool>
	where
		D: Digest + AssociatedOid,
	{
		Ok(self.frame_integrity_verdict::<D>()?.is_verified())
	}
}

#[cfg(all(test, feature = "builder", feature = "sha3"))]
mod tests {
	use crate::core::IntegrityVerdict;
	use crate::crypto::commitment::Opening;
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::error::Result;
	use crate::testing::{TestFrame, TestMessage};

	mod message_commitment {
		use super::*;

		#[test]
		fn verify_commitment_of_recomputes_over_message() -> Result<()> {
			let message = TestMessage::sample(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&message, [])?;

			let mut frame = compose! { V1: id: "commit-1", order: 1u64, message: message.clone() }?;
			frame.metadata.integrity = Some(commitment);

			assert!(frame.verify_commitment_of::<Sha3_256, _>(&message, [])?);
			Ok(())
		}

		#[test]
		fn verify_commitment_of_rejects_other_message() -> Result<()> {
			let committed = TestMessage::sample(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&committed, [])?;

			let mut frame = compose! { V1: id: "commit-2", order: 2u64, message: committed }?;
			frame.metadata.integrity = Some(commitment);

			let other = TestMessage::sample(Some("a different body"));
			assert!(!frame.verify_commitment_of::<Sha3_256, _>(&other, [])?);
			Ok(())
		}

		#[test]
		fn verify_commitment_of_is_false_without_commitment() -> Result<()> {
			let message = TestMessage::sample(None);
			let frame = compose! { V1: id: "commit-3", order: 3u64, message: message.clone() }?;
			assert!(!frame.verify_commitment_of::<Sha3_256, _>(&message, [])?);
			Ok(())
		}
	}

	mod frame_integrity {
		use super::*;

		#[test]
		fn verifies_intact_envelope() {
			let frame = TestFrame::with_integrity();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(true)));
		}

		#[test]
		fn rejects_tampered_envelope() {
			let mut frame = TestFrame::with_integrity();
			frame.metadata.id = b"tampered".to_vec();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(false)));
		}

		#[test]
		fn rejects_algorithm_mismatch() {
			let frame = TestFrame::with_integrity();
			assert!(matches!(frame.verify_frame_integrity::<Sha3_512>(), Ok(false)));
		}

		#[test]
		fn absent_integrity_is_false() -> Result<()> {
			let message = TestMessage::sample(None);
			let frame = compose! { V0: id: "no-fi", order: 1u64, message: message }?;
			assert!(matches!(frame.verify_frame_integrity::<Sha3_256>(), Ok(false)));
			Ok(())
		}

		#[test]
		fn verdict_reports_verified() {
			let frame = TestFrame::with_integrity();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Verified)
			));
		}

		#[test]
		fn verdict_reports_mismatch_on_tamper() {
			let mut frame = TestFrame::with_integrity();
			frame.metadata.id = b"tampered".to_vec();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Mismatch)
			));
		}

		#[test]
		fn verdict_reports_algorithm_mismatch() {
			let frame = TestFrame::with_integrity();
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_512>(),
				Ok(IntegrityVerdict::AlgorithmMismatch)
			));
		}

		#[test]
		fn verdict_reports_absent() -> Result<()> {
			let message = TestMessage::sample(None);
			let frame = compose! { V0: id: "no-fi-verdict", order: 1u64, message: message }?;
			assert!(matches!(
				frame.frame_integrity_verdict::<Sha3_256>(),
				Ok(IntegrityVerdict::Absent)
			));

			Ok(())
		}
	}
}

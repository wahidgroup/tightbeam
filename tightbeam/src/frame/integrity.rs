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
	use crate::asn1::DigestInfo;
	use crate::core::IntegrityVerdict;
	use crate::crypto::commitment::Opening;
	use crate::crypto::hash::{Sha3_256, Sha3_512};
	use crate::error::Result;
	use crate::testing::{TestFrame, TestMessage, TestResult};
	use crate::Frame;

	/// A frame of the integrity fixture whose id a tamper changed after its
	/// integrity was computed.
	fn tampered() -> Frame {
		let mut frame = TestFrame::with_integrity();
		frame.metadata.id = b"tampered".to_vec();
		frame
	}

	mod message_commitment {
		use super::*;

		/// The V1 frame of [`TestFrame::v1`], whose metadata holds
		/// `commitment`.
		fn committed(commitment: DigestInfo) -> Frame {
			let mut frame = TestFrame::v1(None, Some("commit"));
			frame.metadata.integrity = Some(commitment);
			frame
		}

		/// The check of a commitment recomputes it over the message it is
		/// handed, so the committed message verifies.
		#[test]
		fn verify_commitment_of_recomputes_over_message() -> TestResult {
			let message = TestMessage::sample(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&message, [])?;
			let frame = committed(commitment);

			let verified = frame.verify_commitment_of::<Sha3_256, _>(&message, [])?;
			assert!(verified);
			Ok(())
		}

		/// A message other than the committed one fails the check.
		#[test]
		fn verify_commitment_of_rejects_other_message() -> TestResult {
			let message = TestMessage::sample(None);
			let (commitment, _) = Opening::prove::<Sha3_256, _>(&message, [])?;
			let frame = committed(commitment);
			let other = TestMessage::sample(Some("a different body"));

			let verified = frame.verify_commitment_of::<Sha3_256, _>(&other, [])?;
			assert!(!verified);
			Ok(())
		}

		/// A frame that holds no commitment verifies no message.
		#[test]
		fn verify_commitment_of_is_false_without_commitment() -> TestResult {
			let message = TestMessage::sample(None);
			let frame = TestFrame::v1(None, Some("commit-3"));

			let verified = frame.verify_commitment_of::<Sha3_256, _>(&message, [])?;
			assert!(!verified);
			Ok(())
		}
	}

	mod frame_integrity {
		use super::*;

		/// A frame, the integrity check under test, and the answer it expects.
		type IntegrityCheckCase = (Frame, fn(&Frame) -> Result<bool>, bool);

		// The integrity check of a frame holds for an intact envelope alone: a
		// tamper, another algorithm, or an absent integrity each fail it.
		crate::tb_cases! {
			fn the_frame_integrity_check_holds_for_an_intact_envelope_alone(
				(frame, check, expected): IntegrityCheckCase
			) {
				assert!(matches!(check(&frame), Ok(verified) if verified == expected));
			}
			cases {
				intact => (TestFrame::with_integrity(), |frame| frame.verify_frame_integrity::<Sha3_256>(), true),
				tampered => (tampered(), |frame| frame.verify_frame_integrity::<Sha3_256>(), false),
				under_another_algorithm => (
					TestFrame::with_integrity(),
					|frame| frame.verify_frame_integrity::<Sha3_512>(),
					false,
				),
				absent => (
					TestFrame::v0(None, Some("no-fi")),
					|frame| frame.verify_frame_integrity::<Sha3_256>(),
					false,
				),
			}
		}

		/// A frame, the verdict under test, and the verdict it expects.
		type IntegrityVerdictCase = (Frame, fn(&Frame) -> Result<IntegrityVerdict>, IntegrityVerdict);

		// The integrity verdict of a frame names why the check holds or fails.
		crate::tb_cases! {
			fn the_frame_integrity_verdict_names_its_reason((frame, verdict, expected): IntegrityVerdictCase) {
				assert!(matches!(verdict(&frame), Ok(reported) if reported == expected));
			}
			cases {
				verified => (
					TestFrame::with_integrity(),
					|frame| frame.frame_integrity_verdict::<Sha3_256>(),
					IntegrityVerdict::Verified,
				),
				mismatch_on_tamper => (
					tampered(),
					|frame| frame.frame_integrity_verdict::<Sha3_256>(),
					IntegrityVerdict::Mismatch,
				),
				algorithm_mismatch => (
					TestFrame::with_integrity(),
					|frame| frame.frame_integrity_verdict::<Sha3_512>(),
					IntegrityVerdict::AlgorithmMismatch,
				),
				absent => (
					TestFrame::v0(None, Some("no-fi")),
					|frame| frame.frame_integrity_verdict::<Sha3_256>(),
					IntegrityVerdict::Absent,
				),
			}
		}
	}
}

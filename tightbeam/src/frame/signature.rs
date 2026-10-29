#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::policy::VerificationPolicy;
use crate::crypto::profiles::SigningProvider;
use crate::crypto::sign::{
	CanonicalForm, CmsSigner, SignatureAlgorithmIdentifier, SignatureEncoding, Signed, SignedContent, SignerInfoDraft,
	SigningIdentity, VerifiedSignature,
};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{ErasedSigning, PeerCertificate, Signing};
use crate::der::Encode;
use crate::error::Result;
use crate::frame::scaffold::TbsScaffold;
use crate::spki::SubjectPublicKeyInfoRef;
use crate::version::GatedField;
use crate::x509::Certificate;
use crate::{Frame, SignerInfo, TightBeamError};

impl Frame {
	/// Encode the frame as its to-be-signed (TBS) bytes for signature
	/// verification.
	///
	/// The encoding excludes `nonrepudiation` without cloning the frame. The
	/// borrowing `TbsScaffold` reuses the derived field encoders, so these
	/// bytes are bit-identical to the DER encoding of the frame with
	/// `nonrepudiation` set to `None`.
	pub fn to_tbs(&self) -> Result<Vec<u8>> {
		let scaffold = TbsScaffold {
			version: &self.version,
			metadata: &self.metadata,
			message: &self.message,
			integrity: self.integrity.as_ref(),
		};

		Ok(scaffold.to_der()?)
	}

	/// Verify the signature of the TightBeam message under `signer`, a
	/// certificate admitted for signing under the provider `P`.
	///
	/// The `SignerInfo` signs the TBS encoding as content of type `id-data`, so
	/// the CMS signer checks it in this order (RFC 5652 §5.4):
	///
	/// 1. Its `sid` names `signer`.
	/// 2. Its signed attributes match those bytes.
	/// 3. The signature verifies over the attributes.
	///
	/// It returns the signature in its canonical form, the replay key of the
	/// frame.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- the frame holds no signature.
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- the SignerInfo names
	///   another signature algorithm than `P`'s, or another digest than the
	///   one it names.
	/// - [`TightBeamError::SerializationError`] -- the TBS or a signed attribute fails to encode.
	/// - [`TightBeamError::SignatureError`] -- the signature is no value of `P` or fails to verify.
	/// - [`TightBeamError::CertificateValidationError`] -- the key identifier of `signer` fails to decode.
	/// - [`TightBeamError::Signer`] -- the `sid` names another certificate, or
	///   the version or the signed attributes break the CMS rules.
	///
	/// # See also
	///
	/// - [`Frame::sign_with_provider`]: the signing counterpart under the same convention
	/// - [`Frame::to_tbs`]: the exact bytes the signature covers
	pub fn verify<P>(&self, signer: &PeerCertificate<Signing<P>>) -> Result<VerifiedSignature>
	where
		P: SigningProvider,
		P::VerifyingKey: for<'a> TryFrom<SubjectPublicKeyInfoRef<'a>, Error = crate::spki::Error>,
	{
		let signer_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;
		let tbs = self.to_tbs()?;
		let content = SignedContent::data(&tbs);
		Ok(CmsSigner::verify_signer::<P>(signer_info, signer, content)?)
	}

	/// Verify the signature of the TightBeam message under `signer`, a
	/// certificate admitted for signing, with the algorithms of `policy`.
	///
	/// A trust store verifies a frame this way once it resolved the signer's
	/// certificate. The `sid` must name `signer`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingSignature`] -- the frame holds no signature.
	/// - [`TightBeamError::SerializationError`] -- the TBS or a signed attribute fails to encode.
	/// - [`TightBeamError::CertificateValidationError`] -- the policy refuses
	///   an algorithm, the key, or the signature.
	/// - [`TightBeamError::Signer`] -- the `sid`, version, or signed attributes break a CMS rule.
	pub fn verify_under(
		&self,
		signer: &PeerCertificate<ErasedSigning>,
		policy: &dyn VerificationPolicy,
	) -> Result<VerifiedSignature> {
		let signer_info = self.nonrepudiation.as_ref().ok_or(TightBeamError::MissingSignature)?;
		let tbs = self.to_tbs()?;
		let content = SignedContent::data(&tbs);
		Ok(CmsSigner::verify_with_policy(signer_info, signer, policy, content)?)
	}

	/// Sign the frame under `identity`, whose key provider may be an HSM or a
	/// KMS, and store the signature in the `nonrepudiation` field.
	///
	/// - The digest the signature algorithm names covers the TBS and the signed attributes.
	/// - The `sid` names the identity's certificate (RFC 5652 §5.3).
	/// - On any error the frame is unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame version predates signatures.
	/// - [`TightBeamError::KeyError`] -- the provider fails to sign.
	/// - [`TightBeamError::SignatureError`] -- the provider returns no DER signature.
	/// - [`TightBeamError::SerializationError`] -- the TBS or a signed attribute fails to encode.
	///
	/// # See also
	///
	/// - [`Frame::verify`]: the verification counterpart under the same convention
	pub async fn sign_with_provider(&mut self, identity: &SigningIdentity) -> Result<()> {
		self.ensure_allows(GatedField::Nonrepudiation)?;

		let tbs = self.to_tbs()?;
		let content = SignedContent::data(&tbs);
		let signer_info = identity.sign(content).await?;

		self.attach_signer_info(signer_info)
	}

	/// Draft the `SignerInfo` that the key of `certificate` signs over this
	/// frame, under the signature type `S` and the digest it names.
	///
	/// This starts detached, two-phase signing, so the private key stays
	/// outside tightbeam:
	///
	/// 1. An external backend, such as an HSM or a KMS, signs [`SignerInfoDraft::prehash`].
	/// 2. [`SignerInfoDraft::complete`] yields the value for [`Frame::attach_signer_info`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::CertificateValidationError`] -- the key identifier fails to decode.
	/// - [`TightBeamError::SerializationError`] -- the TBS or a signed attribute fails to encode.
	pub fn signing_draft<S>(&self, certificate: &Certificate) -> Result<SignerInfoDraft>
	where
		S: CanonicalForm + SignatureEncoding + SignatureAlgorithmIdentifier,
	{
		let sid = certificate.signer_identifier()?;
		let tbs = self.to_tbs()?;
		let content = SignedContent::data(&tbs);
		Ok(CmsSigner::draft::<S>(sid, content)?)
	}

	/// Attach a signer's `SignerInfo` to the frame's `nonrepudiation` field.
	///
	/// The method completes detached, two-phase signing. Pair it with
	/// [`Frame::signing_draft`], which names the bytes an external backend
	/// signs.
	///
	/// On any error the frame is unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame version predates signatures.
	pub fn attach_signer_info(&mut self, signer_info: Signed<SignerInfo>) -> Result<()> {
		self.ensure_allows(GatedField::Nonrepudiation)?;
		self.nonrepudiation = Some(signer_info);
		Ok(())
	}
}

crate::impl_try_from!(Frame, tb => Signed<SignerInfo>: nonrepudiation, TightBeamError::MissingSignature);

#[cfg(all(test, feature = "builder"))]
mod tests;

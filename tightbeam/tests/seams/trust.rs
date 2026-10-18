//! A trust store an outside crate defines through [`CertificateTrust`]
//! alone.
//!
//! [`PinningTrust`] trusts the certificates its operator pins, and resolves a
//! frame signer among them admitted for the signer purpose. The crate's
//! default `verify_frame` runs over it and returns the admitted certificate
//! in [`TrustVerification::Verified`].

use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::cms::signed_data::SignerIdentifier;
use tightbeam::crypto::k256::ecdsa::SigningKey;
use tightbeam::crypto::policy::{Secp256k1Policy, VerificationPolicy};
use tightbeam::crypto::sign::SigningIdentity;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::CertificateValidation;
use tightbeam::crypto::x509::store::{CertificateTrust, TrustVerification};
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{ErasedSigning, KeyPurposes, PeerCertificate};
use tightbeam::random::OsRng;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::{TestCertificate, TestIdentity, TestMessage};
use tightbeam::x509::Certificate;
use tightbeam::{Frame, Version};

/// A store that trusts the certificates its operator pins, each by its
/// whole encoding, and admits the signers among them under the house
/// signer purpose.
#[derive(Debug)]
pub(crate) struct PinningTrust {
	/// The certificates the operator pinned.
	pinned: Vec<Certificate>,
	/// The pinned certificates the signer purpose admits.
	signers: Vec<PeerCertificate<ErasedSigning>>,
}

impl PinningTrust {
	/// A store that pins `pinned`. A certificate the signer purpose refuses
	/// stays pinned and resolves no signer, so its refusal drops here.
	pub(crate) fn of(pinned: Vec<Certificate>) -> Self {
		let purpose = KeyPurposes::HOUSE.signer;
		let admit = |certificate: &Certificate| PeerCertificate::parse(certificate.to_owned(), purpose);
		let signers = pinned.iter().filter_map(|certificate| admit(certificate).ok()).collect();
		Self { pinned, signers }
	}
}

impl CertificateValidation for PinningTrust {
	fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
		match self.pinned.contains(cert) {
			true => Ok(()),
			false => Err(CertificateValidationError::CertificateNotTrusted),
		}
	}
}

impl CertificateTrust for PinningTrust {
	fn is_trusted(&self, cert: &Certificate) -> bool {
		self.pinned.contains(cert)
	}

	fn verify_chain(&self, chain: &[Certificate]) -> Result<(), CertificateValidationError> {
		let leaf = chain.last().ok_or(CertificateValidationError::EmptyChain)?;
		self.evaluate(leaf)
	}

	fn find_by_signer_identifier(&self, sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
		let mut signers = self.signers.iter();
		signers.find(|signer| signer.certificate().is_named_by(sid).unwrap_or(false))
	}

	fn find_by_public_key(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
		let holds_key = |certificate: &&Certificate| certificate.tbs_certificate.subject_public_key_info == *spki;
		self.pinned.iter().find(holds_key)
	}

	fn to_policy_ref(&self) -> &dyn VerificationPolicy {
		&const { Secp256k1Policy::new() }
	}
}

/// A frame that `identity` signed.
async fn signed_by(identity: &SigningIdentity) -> Frame {
	let builder = FrameBuilder::from(Version::V1).with_id(b"pinned-frame").with_order(1696521600);
	let builder = builder.with_message(TestMessage::sample(None));
	let mut frame = builder.build().expect("the frame builds");
	frame.sign_with_provider(identity).await.expect("the identity signs the frame");
	frame
}

/// The certificate of the signer `verification` verified, if it verified.
fn verified_signer(verification: TrustVerification<'_>) -> Option<&Certificate> {
	match verification {
		TrustVerification::Verified(signer, _) => Some(signer.certificate().as_ref()),
		_ => None,
	}
}

/// The crate's default frame verification resolves the signer through the
/// outside store and returns the certificate the store admitted.
#[tokio::test]
async fn an_outside_trust_verifies_a_frame_its_signer_signed() {
	let identity = TestIdentity::of(&SigningKey::random(&mut OsRng));
	let trust = PinningTrust::of(vec![identity.certificate().to_owned()]);
	let frame = signed_by(&identity).await;

	let verification = trust.verify_frame(&frame);
	assert_eq!(verified_signer(verification), Some(identity.certificate()));
}

/// A pinned certificate whose `extendedKeyUsage` names the server's purpose
/// alone is no frame signer, so its frame resolves no signer.
#[tokio::test]
async fn an_outside_trust_resolves_no_signer_of_another_purpose() {
	let key = SigningKey::random(&mut OsRng);
	let certificate = TestCertificate::self_signed(&key);
	let certificate = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.server]);
	let identity = TestIdentity::presenting(certificate.to_owned(), &key);
	let trust = PinningTrust::of(vec![certificate]);
	let frame = signed_by(&identity).await;

	let verification = trust.verify_frame(&frame);
	assert!(matches!(verification, TrustVerification::UnknownSigner));
}

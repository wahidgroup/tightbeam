//! What a handshake server signs and agrees with, as one value per flow.
//!
//! [`ServerIdentity`] hands the orchestrator the signing half of each value:
//!
//! - An HPKE server holds one [`SigningIdentity`], and its secret derives from the two ephemerals alone.
//! - A CMS server holds a [`CmsIdentityPair`]: a signing identity and the
//!   key-agreement identity its opening seals to.
//!
//! `dyn SigningKeyProvider` and `dyn DiffieHellman` are two types, so the
//! compiler refuses a signing handle where a key-agreement handle belongs. A
//! backend of both serves one identity per key, because the pair refuses one
//! key in both identities (NIST SP 800-56A Rev. 3 §5.6.3.2, SP 800-57 Part 1
//! Rev. 5 §5.2).

#[cfg(feature = "transport-cms")]
use core::fmt;

use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::asn1::ObjectIdentifier;
use crate::transport::handshake::{sealed, ServerIdentity};

#[cfg(feature = "transport-cms")]
use crate::crypto::cms::{KeyAgreementIdentity, RecipientKem};
#[cfg(feature = "transport-cms")]
use crate::crypto::x509::SubjectKey;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::HandshakeError;
#[cfg(feature = "transport-cms")]
use crate::x509::ext::pkix::SubjectAltName;
#[cfg(feature = "transport-cms")]
use crate::x509::Certificate;

impl sealed::Sealed for SigningIdentity {}

/// The server of the HPKE flow signs with its one identity, and its secret
/// derives from the two ephemerals alone.
impl ServerIdentity for SigningIdentity {
	fn signing(&self) -> &SigningIdentity {
		self
	}

	fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		self.certificate().require_purpose(purpose)
	}
}

/// The two identities of a CMS server: one signs the reply, and the other
/// opens what the client seals to it under the KEM `K`.
///
/// [`Self::new`] is the one constructor, so every pair names one subject
/// with two distinct keys.
#[cfg(feature = "transport-cms")]
pub struct CmsIdentityPair<K: RecipientKem> {
	signing: SigningIdentity,
	key_agreement: KeyAgreementIdentity<K>,
}

#[cfg(feature = "transport-cms")]
impl<K: RecipientKem> CmsIdentityPair<K> {
	/// Pair `signing` with `key_agreement`, the two identities of one server.
	///
	/// Each identity admits its certificate for its own use when it is built,
	/// so the pair checks what binds the two.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
	/// - [`HandshakeError::CertificateValidationError`] -- a `subjectAltName`
	///   of an empty subject fails to decode.
	/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key,
	///   in either SEC 1 encoding of one point or its negation.
	pub fn new(signing: SigningIdentity, key_agreement: KeyAgreementIdentity<K>) -> Result<Self, HandshakeError> {
		signing.certificate().pairs_with(key_agreement.certificate())?;

		Ok(Self { signing, key_agreement })
	}

	/// The identity that signs the reply and the session receipt.
	pub fn signing(&self) -> &SigningIdentity {
		&self.signing
	}

	/// The identity whose backend opens the CMS opening.
	pub fn key_agreement(&self) -> &KeyAgreementIdentity<K> {
		&self.key_agreement
	}

	/// The identity that signs, moved out of the pair.
	pub(crate) fn into_signing(self) -> SigningIdentity {
		self.signing
	}

	/// Refuse this pair for the server role unless each of its certificates
	/// admits the key purpose `purpose` (RFC 5280 §4.2.1.12).
	///
	/// # Errors
	///
	/// - The errors of [`CertificateExt::require_purpose`].
	pub(crate) fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		self.signing.certificate().require_purpose(purpose)?;
		self.key_agreement.certificate().require_purpose(purpose)
	}
}

/// The rule that binds the two certificates of a CMS server, which the server
/// and its client both apply: one subject, and two distinct keys.
///
/// An empty subject names its holder by a critical `subjectAltName` alone
/// (RFC 5280 §4.1.2.6), so two certificates of an empty subject name one
/// subject when they carry one `subjectAltName`.
#[cfg(feature = "transport-cms")]
pub(crate) trait CmsPairing {
	/// Refuse `key_agreement` as the partner of this signing certificate
	/// unless the two name one subject with two distinct keys.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
	/// - [`HandshakeError::CertificateValidationError`] -- a `subjectAltName`
	///   of an empty subject fails to decode.
	/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key,
	///   in either SEC 1 encoding of one point or its negation.
	fn pairs_with(&self, key_agreement: &Certificate) -> Result<(), HandshakeError>;

	/// Whether this certificate and `other` name one subject: one subject
	/// name that is not empty, or an empty subject name and one
	/// `subjectAltName`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a `subjectAltName`
	///   of an empty subject fails to decode.
	fn names_one_subject(&self, other: &Certificate) -> Result<bool, HandshakeError>;
}

#[cfg(feature = "transport-cms")]
impl CmsPairing for Certificate {
	fn pairs_with(&self, key_agreement: &Certificate) -> Result<(), HandshakeError> {
		if !self.names_one_subject(key_agreement)? {
			return Err(HandshakeError::SubjectMismatch);
		}

		let signing_key = &self.tbs_certificate.subject_public_key_info;
		if signing_key.same_key(&key_agreement.tbs_certificate.subject_public_key_info) {
			return Err(HandshakeError::KeyReuse);
		}

		Ok(())
	}

	fn names_one_subject(&self, other: &Certificate) -> Result<bool, HandshakeError> {
		let subject = &self.tbs_certificate.subject;
		if *subject != other.tbs_certificate.subject {
			return Ok(false);
		}
		if !subject.0.is_empty() {
			return Ok(true);
		}

		let names = self.extension::<SubjectAltName>()?;
		Ok(names.is_some() && names == other.extension::<SubjectAltName>()?)
	}
}

#[cfg(feature = "transport-cms")]
impl<K: RecipientKem> Clone for CmsIdentityPair<K> {
	fn clone(&self) -> Self {
		Self { signing: self.signing.clone(), key_agreement: self.key_agreement.clone() }
	}
}

/// Each identity names itself, and the keys stay behind their backends.
#[cfg(feature = "transport-cms")]
impl<K: RecipientKem> fmt::Debug for CmsIdentityPair<K> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("CmsIdentityPair")
			.field("signing", &self.signing)
			.field("key_agreement", &self.key_agreement)
			.finish()
	}
}

#[cfg(feature = "transport-cms")]
impl<K: RecipientKem> sealed::Sealed for CmsIdentityPair<K> {}

#[cfg(feature = "transport-cms")]
impl<K: RecipientKem<PrivateKey: 'static> + 'static> ServerIdentity for CmsIdentityPair<K> {
	fn signing(&self) -> &SigningIdentity {
		CmsIdentityPair::signing(self)
	}

	fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		CmsIdentityPair::require_purpose(self, purpose)
	}
}

#[cfg(all(test, feature = "transport-cms"))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::hpke::DhKemSecp256k1;
	use crate::crypto::key::{DiffieHellman, Secp256k1KeyProvider};
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::crypto::sign::ecdsa::SigningKey;
	use crate::crypto::x509::KeyPurposes;
	use crate::der::asn1::Ia5String;
	use crate::random::OsRng;
	use crate::testing::{TestCertificate, TestCmsServer, TestIdentity};
	use crate::transport::handshake::Arc;
	use crate::x509::ext::pkix::name::GeneralName;
	use crate::x509::ext::pkix::{KeyUsage, KeyUsages};
	use crate::x509::ext::Extension;
	use crate::x509::name::RdnSequence;

	#[test]
	fn a_pair_of_one_subject_with_two_keys_is_built() {
		let server = TestCmsServer::generate("tightbeam pair");
		let pair = CmsIdentityPair::new(server.signing_identity(), server.key_agreement_identity());
		assert!(pair.is_ok());
	}

	/// One key in both identities would serve two purposes, so the pair is
	/// refused (NIST SP 800-57 Part 1 Rev. 5 §5.2).
	#[test]
	fn a_pair_of_one_key_is_refused() {
		let server = TestCmsServer::generate("tightbeam pair");
		let usage = KeyUsage(KeyUsages::DigitalSignature.into());
		let signing = TestCertificate::with_key_usage(server.key_agreement.to_owned(), usage);
		let signing = TestIdentity::presenting(signing, &server.key_agreement_key);

		let refused = CmsIdentityPair::new(signing, server.key_agreement_identity());
		assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
	}

	/// A key and its negation agree alike (SEC 1 v2.0 §3.3.1), so a pair of
	/// the two is refused as one key.
	#[test]
	fn a_pair_of_a_key_and_its_negation_is_refused() {
		let signing_key = SigningKey::random(&mut OsRng);
		let negated_key = SigningKey::from(-*signing_key.as_nonzero_scalar());
		let server = TestCmsServer::of("tightbeam pair", signing_key, negated_key);

		let refused = CmsIdentityPair::new(server.signing_identity(), server.key_agreement_identity());
		assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
	}

	/// The server role checks the purpose of each certificate of the pair,
	/// so a pair whose key-agreement certificate names the client's purpose
	/// alone is refused for the server role.
	#[test]
	fn a_pair_of_a_client_key_agreement_certificate_is_refused_for_the_server_role() -> Result<(), Box<dyn Error>> {
		let server = TestCmsServer::generate("tightbeam pair");
		let certificate = server.key_agreement.to_owned();
		let certificate = TestCertificate::with_key_purposes(certificate, [KeyPurposes::HOUSE.client]);
		let provider = Secp256k1KeyProvider::from(server.key_agreement_key.to_owned());
		let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(provider);
		let key_agreement = KeyAgreementIdentity::<DhKemSecp256k1>::new(certificate, backend)?;
		let pair = CmsIdentityPair::new(server.signing_identity(), key_agreement)?;

		let refused = pair.require_purpose(KeyPurposes::HOUSE.server);
		assert!(matches!(refused, Err(CertificateValidationError::ExcludedKeyPurpose)));
		Ok(())
	}

	#[test]
	fn a_pair_of_two_subjects_is_refused() {
		let server = TestCmsServer::generate("tightbeam pair");
		let other = TestCmsServer::generate("another pair");

		let refused = CmsIdentityPair::new(server.signing_identity(), other.key_agreement_identity());
		assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
	}

	/// The critical `subjectAltName` that names `uri` alone.
	fn naming(uri: &str) -> Extension {
		let uri = Ia5String::new(uri).expect("a test URI is IA5 text");
		let names = SubjectAltName(vec![GeneralName::UniformResourceIdentifier(uri)]);
		TestCertificate::extension(&names, true)
	}

	/// The signing and key-agreement certificates of a server of an empty
	/// subject, whose `subjectAltName` names the URI `signing` and the URI
	/// `key_agreement`, in that order.
	fn unnamed_pair(signing: &str, key_agreement: &str) -> (Certificate, Certificate) {
		let server = TestCmsServer::named(RdnSequence::default());
		let signing = TestCertificate::with_extension(server.signing, naming(signing));
		let key_agreement = TestCertificate::with_extension(server.key_agreement, naming(key_agreement));
		(signing, key_agreement)
	}

	/// An empty subject names its holder by its `subjectAltName`, so two
	/// certificates of an empty subject that name two holders are two
	/// subjects (RFC 5280 §4.1.2.6).
	#[test]
	fn two_certificates_of_an_empty_subject_that_name_two_holders_are_refused() {
		let (signing, key_agreement) = unnamed_pair("urn:tightbeam:signer", "urn:tightbeam:other");
		let refused = signing.pairs_with(&key_agreement);
		assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
	}

	/// Two certificates of an empty subject that name one holder by their
	/// `subjectAltName` are one subject.
	#[test]
	fn two_certificates_of_an_empty_subject_that_name_one_holder_pair() -> Result<(), HandshakeError> {
		let (signing, key_agreement) = unnamed_pair("urn:tightbeam:signer", "urn:tightbeam:signer");
		signing.pairs_with(&key_agreement)
	}

	/// An empty subject with no `subjectAltName` names no holder, so two such
	/// certificates are refused as two subjects.
	#[test]
	fn two_certificates_of_an_empty_subject_and_no_name_are_refused() {
		let server = TestCmsServer::named(RdnSequence::default());
		let refused = server.signing.pairs_with(&server.key_agreement);
		assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
	}
}

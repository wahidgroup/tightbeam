//! What a handshake server signs and agrees with, as one value per flow.
//!
//! [`ServerIdentity`] hands the orchestrator the signing half of each value:
//!
//! - An HPKE server holds one [`SigningIdentity`], and its secret derives from the two ephemerals alone.
//! - A CMS server holds a [`CmsIdentityPair`]: a signing identity and the
//!   key-agreement identity its opening seals to.
//!
//! A `dyn SigningKeyProvider` is no `dyn DiffieHellman`, so the compiler
//! refuses a signing handle where a key-agreement handle belongs. A backend
//! of both serves one identity per key, because the pair refuses one key in
//! both identities (NIST SP 800-56A Rev. 3 §5.6.3.2, SP 800-57 Part 1 Rev. 5
//! §5.2).

#[cfg(feature = "transport-cms")]
use core::fmt;

use crate::crypto::sign::SigningIdentity;
use crate::crypto::x509::error::CertificateValidationError;
use crate::crypto::x509::utils::CertificateExt;
use crate::der::asn1::ObjectIdentifier;
use crate::utils::marker::{MaybeSend, MaybeSync};

#[cfg(feature = "transport-cms")]
use crate::crypto::cms::{KeyAgreementIdentity, RecipientKem};
#[cfg(feature = "transport-cms")]
use crate::crypto::x509::SubjectKey;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::HandshakeError;
#[cfg(feature = "transport-cms")]
use crate::x509::Certificate;

/// The identity a handshake server holds, which hands the orchestrator the
/// half that signs the reply and its receipt.
pub trait ServerIdentity: MaybeSend + MaybeSync + 'static {
	/// The identity that signs the reply and the session receipt.
	fn signing(&self) -> &SigningIdentity;

	/// Refuse this identity for the server role unless each of its
	/// certificates admits the key purpose `purpose` (RFC 5280 §4.2.1.12).
	///
	/// # Errors
	///
	/// - The [`CertificateExt::require_purpose`] set.
	fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError>;
}

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
	/// Each identity admitted its certificate for its own use when it was
	/// built, so the pair checks what binds the two.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
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
	/// - The [`CertificateExt::require_purpose`] set.
	pub(crate) fn require_purpose(&self, purpose: ObjectIdentifier) -> Result<(), CertificateValidationError> {
		self.signing.certificate().require_purpose(purpose)?;
		self.key_agreement.certificate().require_purpose(purpose)
	}
}

/// The rule that binds the two certificates of a CMS server, which the server
/// and its client both apply: one subject, and two distinct keys.
#[cfg(feature = "transport-cms")]
pub(crate) trait CmsPairing {
	/// Refuse `key_agreement` as the partner of this signing certificate
	/// unless the two name one subject with two distinct keys.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
	/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key,
	///   in either SEC 1 encoding of one point or its negation.
	fn pairs_with(&self, key_agreement: &Certificate) -> Result<(), HandshakeError>;
}

#[cfg(feature = "transport-cms")]
impl CmsPairing for Certificate {
	fn pairs_with(&self, key_agreement: &Certificate) -> Result<(), HandshakeError> {
		let signing = &self.tbs_certificate;
		let key_agreement = &key_agreement.tbs_certificate;
		if signing.subject != key_agreement.subject {
			return Err(HandshakeError::SubjectMismatch);
		}

		let signing_key = &signing.subject_public_key_info;
		if signing_key.same_key(&key_agreement.subject_public_key_info) {
			return Err(HandshakeError::KeyReuse);
		}

		Ok(())
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
	use crate::random::OsRng;
	use crate::testing::{TestCertificate, TestCmsServer, TestIdentity};
	use crate::transport::handshake::Arc;
	use crate::x509::ext::pkix::{KeyUsage, KeyUsages};

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
}

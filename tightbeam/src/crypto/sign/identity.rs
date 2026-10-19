//! The signing identities: a certificate beside the key that proves it.

use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::cms::signed_data::{SignerIdentifier, SignerInfo};
use crate::crypto::key::SigningKeyProvider;
use crate::crypto::policy::VerificationPolicy;
use crate::crypto::profiles::SigningProvider;
use crate::crypto::sign::signer::Scheme;
use crate::crypto::sign::{Keypair, SignedContent, SignerError, SignerInfoDraft};
use crate::crypto::x509::utils::CertificateExt;
use crate::crypto::x509::{CertificateUse, ErasedSigning, PeerCertificate};
use crate::der::Encode;
use crate::frame::Signed;
use crate::spki::DecodePublicKey;
use crate::x509::Certificate;

#[cfg(all(feature = "aead", feature = "kdf", feature = "ecdh"))]
use crate::crypto::profiles::DefaultCryptoProvider;
#[cfg(all(feature = "aead", feature = "kdf", feature = "ecdh"))]
use crate::crypto::x509::CertificateSpec;

/// A signing certificate and the key provider that holds its private key.
///
/// [`Self::new`] pairs them under the house provider, and
/// [`Self::with_provider`] under any [`SigningProvider`]. Each one:
///
/// - admits the certificate for signing,
/// - refuses a key whose public half differs from the certificate's SubjectPublicKeyInfo, and
/// - brings each value the provider returns to its canonical form.
///
/// Both halves are `Arc`, and so is the DER of the certificate, which encodes
/// once at construction. A clone also copies the `sid`.
#[derive(Clone)]
pub struct SigningIdentity {
	certificate: PeerCertificate<ErasedSigning>,
	certificate_der: Arc<[u8]>,
	key: Arc<dyn SigningKeyProvider>,
	sid: SignerIdentifier,
	scheme: Scheme,
}

impl SigningIdentity {
	/// Pair `certificate` with `key` under the house provider, ECDSA with
	/// SHA3-256 on secp256k1.
	///
	/// `certificate` accepts an owned certificate or a handle to a shared one.
	///
	/// # Errors
	///
	/// - The [`Self::with_provider`] set.
	#[cfg(all(feature = "aead", feature = "kdf", feature = "ecdh"))]
	pub fn new(
		certificate: impl Into<Arc<Certificate>>,
		key: Arc<dyn SigningKeyProvider>,
	) -> Result<Self, SignerError> {
		Self::with_provider::<DefaultCryptoProvider>(certificate, key)
	}

	/// Pair `certificate` with `key` under the algorithm of the provider `P`.
	///
	/// An implementor brings its own algorithm as a [`SigningProvider`] whose
	/// signature type implements `CanonicalForm`, `SignatureEncoding`, and
	/// `SignatureAlgorithmIdentifier`, and whose verifying key implements
	/// `PrehashVerifier`, `DecodePublicKey`, and `PartialEq`.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the certificate is refused for
	///   signing, or its key identifier extension fails to decode.
	/// - [`SignerError::UnsupportedAlgorithm`] -- the key declares another
	///   algorithm than `P`, or its public half is no key of `P`.
	/// - [`SignerError::Key`] -- the provider fails to return its public key.
	/// - [`SignerError::Encoding`] -- the certificate or its SubjectPublicKeyInfo fails to encode.
	/// - [`SignerError::PublicKey`] -- the certificate's key is no key of `P`.
	/// - [`SignerError::KeyMismatch`] -- the key's public half differs from the certificate's.
	pub fn with_provider<P>(
		certificate: impl Into<Arc<Certificate>>,
		key: Arc<dyn SigningKeyProvider>,
	) -> Result<Self, SignerError>
	where
		P: SigningProvider + 'static,
		P::VerifyingKey: DecodePublicKey + PartialEq,
	{
		let certificate = PeerCertificate::<ErasedSigning>::own(certificate)?;
		let scheme = Scheme::of::<P>();
		let algorithm = key.algorithm().oid;
		if algorithm != scheme.algorithm() {
			return Err(SignerError::UnsupportedAlgorithm(algorithm));
		}

		// A public half that is no key of `P` holds no signature the scheme
		// verifies, so its decode error is the refusal of the algorithm.
		let public_key_der = key.to_public_key_bytes()?;
		let scheme_key = P::VerifyingKey::from_public_key_der(&public_key_der);
		let scheme_key = scheme_key.map_err(|_| SignerError::UnsupportedAlgorithm(algorithm))?;

		let sid = signer_identifier_of(certificate.certificate(), &scheme_key)?;
		let certificate_der = Arc::<[u8]>::from(certificate.certificate().to_der()?);

		Ok(Self { certificate, certificate_der, key, sid, scheme })
	}

	/// Decode `certificate` and pair it with `key`.
	///
	/// It is the one place a [`CertificateSpec`] becomes an endpoint identity,
	/// so every builder that accepts one decodes it the same way.
	///
	/// # Errors
	///
	/// - [`crate::TightBeamError::SerializationError`] -- `certificate` holds
	///   PEM or DER that does not decode as a certificate.
	/// - [`crate::TightBeamError`] -- the errors of [`Self::new`], as their conversion names them.
	#[cfg(all(feature = "aead", feature = "kdf", feature = "ecdh"))]
	pub fn from_spec(
		certificate: CertificateSpec,
		key: Arc<dyn SigningKeyProvider>,
	) -> Result<Self, crate::TightBeamError> {
		let certificate = Certificate::try_from(certificate)?;
		Ok(Self::new(certificate, key)?)
	}

	/// The certificate this identity presents.
	pub fn certificate(&self) -> &Certificate {
		self.certificate.certificate()
	}

	/// Shared handle to the certificate this identity presents.
	pub fn certificate_arc(&self) -> Arc<Certificate> {
		Arc::clone(self.certificate.certificate())
	}

	/// The DER of the certificate this identity presents, encoded once at
	/// construction, which a handshake transcript binds as it is sent.
	pub fn certificate_der(&self) -> &[u8] {
		&self.certificate_der
	}

	/// The certificate this identity presents, as the signing use admitted
	/// it, which verifies the identity's own signatures under
	/// [`Self::policy`].
	pub fn signing_certificate(&self) -> &PeerCertificate<ErasedSigning> {
		&self.certificate
	}

	/// The key provider behind this identity, which signs for it.
	pub fn provider(&self) -> &dyn SigningKeyProvider {
		self.key.as_ref()
	}

	/// Shared handle to the key provider behind this identity.
	pub fn provider_arc(&self) -> Arc<dyn SigningKeyProvider> {
		Arc::clone(&self.key)
	}

	/// The `SignerIdentifier` that names this identity's certificate (RFC
	/// 5652 §5.3).
	pub fn signer_identifier(&self) -> &SignerIdentifier {
		&self.sid
	}

	/// The policy that verifies a signature of this identity's scheme, under
	/// the scheme's key type.
	pub fn policy(&self) -> &'static dyn VerificationPolicy {
		self.scheme.policy()
	}

	/// Draft the `SignerInfo` this identity signs over `content`, under the
	/// digest its signature algorithm names.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- an attribute fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	pub fn draft(&self, content: SignedContent<'_>) -> Result<SignerInfoDraft, SignerError> {
		self.scheme.draft(self.sid.clone(), content)
	}

	/// Sign `prehash` with this identity's key, and return the signature in
	/// its canonical form: for ECDSA, the DER ECDSA-Sig-Value with `s` in the
	/// low half.
	///
	/// # Errors
	///
	/// - [`SignerError::Key`] -- the provider fails to sign.
	/// - [`SignerError::Signature`] -- the provider returns another encoding than its algorithm's.
	pub async fn sign_prehash(&self, prehash: &[u8]) -> Result<Vec<u8>, SignerError> {
		let signature = self.key.sign_prehash(prehash).await?;
		self.scheme.canonical(&signature)
	}

	/// Sign `content` under the digest its signature algorithm names, and
	/// return the `SignerInfo`.
	///
	/// # Errors
	///
	/// - [`SignerError::Encoding`] -- an attribute or the signature fails to encode.
	/// - [`SignerError::DuplicateAttribute`] -- a profile attribute repeats an OID of the set.
	/// - [`SignerError::Key`] -- the provider fails to sign.
	/// - [`SignerError::Signature`] -- the provider returns another encoding than its algorithm's.
	pub async fn sign(&self, content: SignedContent<'_>) -> Result<Signed<SignerInfo>, SignerError> {
		let draft = self.draft(content)?;
		let signature = self.sign_prehash(draft.prehash()).await?;
		draft.complete(signature, None)
	}
}

/// The subject and the signer identifier, with the key behind its provider.
impl fmt::Debug for SigningIdentity {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SigningIdentity")
			.field("subject", &self.certificate().tbs_certificate.subject)
			.field("sid", &self.sid)
			.finish_non_exhaustive()
	}
}

/// A key that signs in place, beside the certificate that names it.
///
/// [`Self::new`] admits the certificate for signing and refuses a key whose
/// public half differs from the certificate's SubjectPublicKeyInfo, as
/// [`SigningIdentity::new`] does, and reads the `sid` from the certificate. A
/// builder that signs synchronously, such as `FrameBuilder::with_signer`,
/// signs with one.
#[derive(Clone, Debug)]
pub struct CertifiedKey<K> {
	key: K,
	sid: SignerIdentifier,
}

impl<K> CertifiedKey<K> {
	/// Pair `certificate` with `key`.
	///
	/// # Errors
	///
	/// - [`SignerError::Certificate`] -- the certificate is refused for
	///   signing, or its key identifier extension fails to decode.
	/// - [`SignerError::Encoding`] -- the certificate's SubjectPublicKeyInfo fails to encode.
	/// - [`SignerError::PublicKey`] -- the certificate's key is no key of the verifying key's type.
	/// - [`SignerError::KeyMismatch`] -- the key's public half differs from the certificate's.
	pub fn new(certificate: &Certificate, key: K) -> Result<Self, SignerError>
	where
		K: Keypair,
		K::VerifyingKey: DecodePublicKey + PartialEq,
	{
		ErasedSigning::parse_key(certificate)?;
		let sid = signer_identifier_of(certificate, &key.verifying_key())?;
		Ok(Self { key, sid })
	}

	/// The key that signs.
	pub fn key(&self) -> &K {
		&self.key
	}

	/// The `SignerIdentifier` that names the key's certificate (RFC 5652
	/// §5.3).
	pub fn signer_identifier(&self) -> &SignerIdentifier {
		&self.sid
	}
}

/// The `sid` of `certificate`, once `public_key` proves the certificate: the
/// certificate's SubjectPublicKeyInfo decodes as the key `public_key` is.
///
/// Both identity constructors call it, so the check and the read are one.
/// The check compares decoded keys, so one point in either SEC 1 form (RFC
/// 5480 §2.2) is one key.
///
/// # Errors
///
/// - [`SignerError::Encoding`] -- the certificate's SubjectPublicKeyInfo fails to encode.
/// - [`SignerError::PublicKey`] -- the certificate's key is no key of the type of `public_key`.
/// - [`SignerError::KeyMismatch`] -- the key's public half differs from the certificate's.
/// - [`SignerError::Certificate`] -- the key identifier extension fails to decode.
fn signer_identifier_of<V>(certificate: &Certificate, public_key: &V) -> Result<SignerIdentifier, SignerError>
where
	V: DecodePublicKey + PartialEq,
{
	let certified_der = certificate.tbs_certificate.subject_public_key_info.to_der()?;
	let certified = V::from_public_key_der(&certified_der)?;
	if *public_key != certified {
		return Err(SignerError::KeyMismatch);
	}

	Ok(certificate.signer_identifier()?)
}

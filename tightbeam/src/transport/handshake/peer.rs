//! What a handshake endpoint demands of its peer, and what it may record.
//!
//! Each direction of admission has one decider. The opening, the reply, and
//! the closing named below are the three
//! [legs](crate::transport::handshake#legs) of a handshake.
//!
//! - A server admits its client through [`PeerAuthentication::admit`], the one
//!   constructor of [`AdmittedPeer`]. An offered certificate's client Finished
//!   is always verified, and a session records a peer only through
//!   [`AdmittedPeer::proven`], so every session identity is a certificate a
//!   validator chain accepted and whose key signed the closing.
//! - A client admits its server through [`ProvisionedTrust`] when the identity
//!   is known before the opening, and through [`LearnedTrust`] when the reply
//!   names it. Those two implement [`ServerTrust`] and build every
//!   [`AdmittedServer`].
//! - A [`PeerCertificate`] admits each certificate for the one use the
//!   handshake reads it for, and every check of a handshake reads the key that
//!   admission parsed.

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::x509::policy::CertificateValidation;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::point::AffineCoordinates;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::PublicKey;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::{AgreementPoint, PeerCertificate, Signing};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::ObjectIdentifier;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::flow::Offer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::{PeerEphemeral, PeerIdentity, Terms};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::HandshakeProvider;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::utils::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
mod provisioned {
	pub use crate::crypto::cms::KemRecipient;
	pub use crate::crypto::x509::ext::pkix::{AuthorityKeyIdentifier, SubjectKeyIdentifier};
	pub use crate::crypto::x509::name::Name;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::crypto::x509::KeyAgreement;
	pub use crate::der::asn1::OctetString;
	pub use crate::der::referenced::OwnedToRef;
	pub use crate::transport::handshake::{CmsServerCertificates, CmsServerIdentity};
}

#[cfg(feature = "transport-cms")]
use crate::crypto::x509::SubjectKey;
#[cfg(feature = "transport-cms")]
use provisioned::*;

/// How a handshake server authenticates its client.
#[derive(Clone)]
pub enum PeerAuthentication {
	/// Only the server authenticates. The session peer stays empty, and an
	/// offered client certificate names nobody.
	Anonymous,
	/// Both sides authenticate. The client MUST offer a certificate, and every
	/// validator in the chain MUST accept it before the session records it.
	/// The certificate MUST be within its validity period, so a build with no
	/// clock refuses every client.
	Mutual(ValidatorChain),
}

/// The non-empty chain of validators a mutual server runs.
///
/// The field stays private and only [`PeerAuthentication::mutual`] builds a
/// chain, so every mutual server runs at least one check. A build without a
/// handshake protocol has no server to evaluate the chain, so the chain
/// records only that the configuration demands mutual authentication.
#[derive(Clone)]
pub struct ValidatorChain(
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))] Arc<[Arc<dyn CertificateValidation>]>,
);

impl ValidatorChain {
	/// Run every validator against `certificate`, stopping at the first
	/// refusal.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn evaluate(&self, certificate: &Certificate) -> Result<(), HandshakeError> {
		for validator in self.0.iter() {
			validator.evaluate(certificate)?;
		}

		Ok(())
	}
}

impl PeerAuthentication {
	/// Build mutual authentication against `validators`.
	///
	/// An empty set names no check to run, so it demands nothing and yields
	/// [`Self::Anonymous`]. This is the one definition of that rule, so a
	/// caller that holds a possibly empty collection passes it here and lets
	/// this method decide.
	pub fn mutual(validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		let validators = validators.into_iter().collect::<Vec<_>>();
		if validators.is_empty() {
			return Self::Anonymous;
		}

		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		let chain = ValidatorChain(validators.into());
		#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
		let chain = ValidatorChain();

		Self::Mutual(chain)
	}

	/// Whether the client MUST present a certificate.
	pub const fn requires_certificate(&self) -> bool {
		matches!(self, Self::Mutual(_))
	}

	/// Decide what the handshake may do with the identity the client offered,
	/// and verify the client Finished that proves the client holds its key.
	///
	/// [`Handshake::finish`](crate::transport::handshake::Handshake::finish)
	/// calls this, and it is the one constructor of [`AdmittedPeer`]. The rule
	/// is the same for both protocols:
	///
	/// - An [`Offer`] holds a certificate with its client Finished, or neither.
	/// - Under mutual authentication, the validity check and then every validator run before the Finished.
	/// - The Finished is verified whenever a certificate is offered, so an
	///   anonymous server also refuses a certificate the client cannot prove.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingClientCertificate`] -- mutual authentication
	///   is configured and the client offered no certificate.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or a validator refused it.
	/// - Any error of [`ClientFinished::verify`] -- the client Finished fails to verify.
	///
	/// [`ClientFinished::verify`]: crate::transport::handshake::flow::ClientFinished::verify
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn admit<P>(&self, offer: Offer<P>, terms: &Terms<P>) -> Result<AdmittedPeer<P>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		let Some((identity, finished)) = offer.into_identity() else {
			return match self {
				Self::Anonymous => Ok(AdmittedPeer(Admission::Unidentified)),
				Self::Mutual(_) => Err(HandshakeError::MissingClientCertificate),
			};
		};
		// A validator may accept a certificate without reading its validity
		// period, as a pin does, so the server reads it before the chain.
		if let Self::Mutual(chain) = self {
			let certificate = identity.certificate();
			certificate.validate_expiry()?;
			chain.evaluate(certificate)?;
		}

		finished.verify(&identity, terms)?;

		let admission = match self {
			Self::Anonymous => Admission::Offered,
			Self::Mutual(_) => Admission::Proven(identity),
		};
		Ok(AdmittedPeer(admission))
	}
}

/// The outcome of [`PeerAuthentication::admit`].
///
/// The variant stays private, so a proven peer exists only where
/// [`admit`](PeerAuthentication::admit) ran every validator and verified the
/// proof.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct AdmittedPeer<P: HandshakeProvider>(Admission<P>);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
enum Admission<P: HandshakeProvider> {
	/// Under server-only authentication, the client offered no certificate.
	Unidentified,
	/// Under server-only authentication, the client proved the key of the
	/// certificate it offered, and the certificate names nobody.
	Offered,
	/// Every configured validator accepted the certificate, and the client
	/// proved its key.
	Proven(PeerCertificate<Signing<P>>),
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> AdmittedPeer<P> {
	/// The identity the session records as its peer, present only under
	/// mutual authentication after every validator accepted it.
	pub(crate) fn proven(&self) -> Option<&PeerCertificate<Signing<P>>> {
		match &self.0 {
			Admission::Proven(identity) => Some(identity),
			Admission::Unidentified | Admission::Offered => None,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> PeerIdentity for AdmittedPeer<P> {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		let proven = self.proven();
		proven.map(PeerCertificate::certificate)
	}
}

/// The server a client admitted: the certificate whose key signs the reply,
/// and for a CMS server the key the opening sealed to, as a point of the
/// handshake curve.
///
/// The fields stay private, so one exists only where [`ProvisionedTrust`] or
/// [`LearnedTrust`] admitted the certificates for their uses.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub struct AdmittedServer<P: HandshakeProvider> {
	/// The certificate whose key signs the reply.
	signing: PeerCertificate<Signing<P>>,
	/// The key of a CMS server's key-agreement certificate, parsed once at
	/// admission as a point of the handshake curve. `None` for an HPKE
	/// server, whose secret derives from the two ephemerals alone, and for a
	/// key of another curve.
	key_agreement: Option<PublicKey<P::Curve>>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> AdmittedServer<P> {
	/// The certificate whose key signs the reply.
	pub(crate) fn signing(&self) -> &PeerCertificate<Signing<P>> {
		&self.signing
	}
}

/// A server ephemeral collapses into a server key when it shares the
/// x-coordinate of either certificate key, so the check reads both against
/// the ephemeral's x-coordinate, read once.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> PeerEphemeral<P::Curve> for AdmittedServer<P> {
	fn distinct_from(&self, point: &PublicKey<P::Curve>) -> bool {
		let x = point.as_affine().x();
		let signing = !self.signing.shares_x(&x);
		let key_agreement = self.key_agreement.as_ref();
		let agreement = key_agreement.is_none_or(|key| !AgreementPoint::<P::Curve>::shares_x(key, &x));
		signing && agreement
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> PeerIdentity for AdmittedServer<P> {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		Some(self.signing.certificate())
	}
}

/// Where a client learns the identity of its server under the provider `P`.
///
/// A flow names one implementation, so the leg that admits the server and
/// what the reply must name are fixed by type.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait ServerTrust<P: HandshakeProvider>: MaybeSend + MaybeSync + 'static {
	/// What the trust admits before the opening.
	type Provisioned: MaybeSend;
	/// What the reply names for the trust to admit.
	type Named: MaybeSend + 'static;

	/// Admit the server before the opening, when its identity is provisioned,
	/// under the server's key purpose `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a certificate is
	///   outside its validity period, the store refused it or its chain, or its
	///   use or `purpose` refused it.
	fn admit_provisioned(&self, purpose: ObjectIdentifier) -> Result<Self::Provisioned, HandshakeError>;

	/// Admit the server the reply names, under the server's key purpose
	/// `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the validator refused it, or the signing
	///   use or `purpose` refused it.
	fn admit_named(&self, named: Self::Named, purpose: ObjectIdentifier) -> Result<AdmittedServer<P>, HandshakeError>;
}

/// The trust anchor a provisioned certificate names: the certificate a path
/// starts at, or the authority that issued a bare certificate.
#[cfg(feature = "transport-cms")]
enum ProvisionedAnchor<'a> {
	/// The first certificate of a chain, or a self-issued bare certificate.
	Certificate(&'a Certificate),
	/// The authority a bare certificate names as its issuer, by its name and
	/// by the key identifier of its `authorityKeyIdentifier`.
	Issuer { name: &'a Name, key_identifier: Option<OctetString> },
}

#[cfg(feature = "transport-cms")]
impl ProvisionedAnchor<'_> {
	/// Whether this anchor and `other` name one trust anchor. A certificate
	/// matches an issuer by its subject and its `subjectKeyIdentifier`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a key identifier fails to decode.
	fn names(&self, other: &Self) -> Result<bool, HandshakeError> {
		match (self, other) {
			(Self::Certificate(own), Self::Certificate(other)) => Ok(own == other),
			(Self::Issuer { name, key_identifier }, Self::Issuer { name: other, key_identifier: other_key }) => {
				Ok(name == other && key_identifier == other_key)
			}
			(Self::Certificate(certificate), Self::Issuer { name, key_identifier })
			| (Self::Issuer { name, key_identifier }, Self::Certificate(certificate)) => {
				let subject_key = certificate.extension::<SubjectKeyIdentifier>()?;
				let subject_key = subject_key.map(|identifier| identifier.0);
				Ok(certificate.tbs_certificate.subject == **name && subject_key == *key_identifier)
			}
		}
	}
}

#[cfg(feature = "transport-cms")]
impl CmsServerIdentity {
	/// The trust anchor this provisioned certificate names: the root of a
	/// chain, a self-issued bare certificate itself, or the authority an
	/// issued bare certificate names.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the key identifier fails to decode.
	fn anchor(&self) -> Result<ProvisionedAnchor<'_>, HandshakeError> {
		let certificate = match self {
			Self::Chain(chain) => return Ok(ProvisionedAnchor::Certificate(chain.root())),
			Self::Certificate(certificate) => certificate.as_ref(),
		};

		let tbs = &certificate.tbs_certificate;
		if tbs.issuer == tbs.subject {
			return Ok(ProvisionedAnchor::Certificate(certificate));
		}

		let authority = certificate.extension::<AuthorityKeyIdentifier>()?;
		let key_identifier = authority.and_then(|authority| authority.key_identifier);
		Ok(ProvisionedAnchor::Issuer { name: &tbs.issuer, key_identifier })
	}

	/// Admit this provisioned certificate against `store`, and return its
	/// leaf.
	///
	/// - A bare certificate is evaluated against the store directly.
	/// - A chain is path-validated against the store
	///   ([RFC 5280 §6.1][rfc5280-6.1]), and its leaf identifies the server.
	///
	/// A bare certificate must also be within its validity period, because a
	/// store's [`evaluate`](CertificateValidation::evaluate) may accept one
	/// without reading it. Path validation owns the validity period of every
	/// certificate in a chain.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	fn admit(&self, store: &dyn CertificateTrust) -> Result<&Arc<Certificate>, HandshakeError> {
		match self {
			Self::Certificate(certificate) => {
				certificate.validate_expiry()?;
				store.evaluate(certificate)?;
				Ok(certificate)
			}
			Self::Chain(chain) => {
				store.verify_chain(chain.path())?;
				Ok(chain.leaf())
			}
		}
	}
}

/// Trust in a CMS server whose two certificates are known before the
/// opening, so the opening seals to its key-agreement certificate and the
/// signing certificate verifies its reply.
///
/// [`Self::new`] is the one constructor, so the pair it holds names one
/// subject under one trust anchor with two distinct keys.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub struct ProvisionedTrust {
	/// The server's two certificates, each a leaf or a chain.
	certificates: CmsServerCertificates,
	/// The store that authenticates both certificates.
	store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "transport-cms")]
impl ProvisionedTrust {
	/// Trust in the server of `certificates`, as `store` authenticates it.
	///
	/// Each certificate is admitted against the store once here, and again at
	/// each handshake, since its validity period and the store's verdict
	/// change after construction.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a certificate is
	///   outside its validity period, or the store refused it or its chain.
	/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
	/// - [`HandshakeError::AnchorMismatch`] -- the two certificates name two trust anchors.
	/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key.
	pub fn new(certificates: CmsServerCertificates, store: Arc<dyn CertificateTrust>) -> Result<Self, HandshakeError> {
		let CmsServerCertificates { signing, key_agreement } = &certificates;
		let signing_leaf = &signing.admit(store.as_ref())?.tbs_certificate;
		let key_agreement_leaf = &key_agreement.admit(store.as_ref())?.tbs_certificate;

		if signing_leaf.subject != key_agreement_leaf.subject {
			return Err(HandshakeError::SubjectMismatch);
		}

		let signing_anchor = signing.anchor()?;
		let key_agreement_anchor = key_agreement.anchor()?;
		if !signing_anchor.names(&key_agreement_anchor)? {
			return Err(HandshakeError::AnchorMismatch);
		}
		let signing_key = &signing_leaf.subject_public_key_info;
		let key_agreement_key = &key_agreement_leaf.subject_public_key_info;
		if signing_key.same_key(key_agreement_key) {
			return Err(HandshakeError::KeyReuse);
		}

		Ok(Self { certificates, store })
	}
}

/// The two certificates of a CMS server, each admitted for its use, as the
/// client holds them for the opening.
#[cfg(feature = "transport-cms")]
pub struct ProvisionedServer<P: HandshakeProvider> {
	/// The certificate whose key signs the reply.
	signing: PeerCertificate<Signing<P>>,
	/// The certificate whose key the opening seals to.
	key_agreement: PeerCertificate<KeyAgreement<P::Kem>>,
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ProvisionedServer<P> {
	/// The recipient the opening seals to, beside the server the reply is
	/// read against, which keeps the key-agreement key as a point of the
	/// handshake curve for the comparison of the server ephemeral.
	///
	/// # Errors
	///
	/// - [`HandshakeError::Envelope`] -- the key-agreement certificate fails to name its recipient.
	pub(crate) fn into_recipient(self) -> Result<(KemRecipient<P::Kem>, AdmittedServer<P>), HandshakeError> {
		let Self { signing, key_agreement } = self;
		// A key of another curve is no point of the handshake curve and
		// collapses no agreement on it, so its parse refusal drops here.
		let certificate = key_agreement.certificate();
		let spki = certificate.tbs_certificate.subject_public_key_info.owned_to_ref();
		let point = PublicKey::<P::Curve>::try_from(spki).ok();
		let recipient = KemRecipient::from_certificate(key_agreement)?;

		let server = AdmittedServer { signing, key_agreement: point };
		Ok((recipient, server))
	}
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ServerTrust<P> for ProvisionedTrust {
	type Provisioned = ProvisionedServer<P>;
	type Named = AdmittedServer<P>;

	/// Admit the provisioned server before the opening: each certificate
	/// against the store, then each for its use under `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a certificate is
	///   outside its validity period, the store refused it or its chain, or its
	///   use or `purpose` refused it.
	fn admit_provisioned(&self, purpose: ObjectIdentifier) -> Result<ProvisionedServer<P>, HandshakeError> {
		let CmsServerCertificates { signing, key_agreement } = &self.certificates;
		let signing = signing.admit(self.store.as_ref())?;
		let key_agreement = key_agreement.admit(self.store.as_ref())?;

		let signing = PeerCertificate::parse(Arc::clone(signing), purpose)?;
		let key_agreement = PeerCertificate::parse(Arc::clone(key_agreement), purpose)?;
		Ok(ProvisionedServer { signing, key_agreement })
	}

	/// The reply names the server admitted before the opening, so the
	/// admission passes through unchanged.
	fn admit_named(
		&self,
		named: AdmittedServer<P>,
		_purpose: ObjectIdentifier,
	) -> Result<AdmittedServer<P>, HandshakeError> {
		Ok(named)
	}
}

/// Trust in a server whose identity the client learns from the reply.
#[cfg(feature = "transport-hpke")]
pub struct LearnedTrust {
	/// The validator that authenticates the certificate the reply names.
	pub validator: Arc<dyn CertificateValidation>,
}

#[cfg(feature = "transport-hpke")]
impl LearnedTrust {
	/// Trust in the servers whose certificate `validator` accepts.
	pub fn new(validator: impl CertificateValidation + 'static) -> Self {
		Self { validator: Arc::new(validator) }
	}
}

/// A shared validator is the whole trust.
#[cfg(feature = "transport-hpke")]
impl From<Arc<dyn CertificateValidation>> for LearnedTrust {
	fn from(validator: Arc<dyn CertificateValidation>) -> Self {
		Self { validator }
	}
}

#[cfg(feature = "transport-hpke")]
impl<P: HandshakeProvider> ServerTrust<P> for LearnedTrust {
	type Provisioned = ();
	type Named = Certificate;

	/// The reply names the server, so the admission before the opening is `()`.
	fn admit_provisioned(&self, _purpose: ObjectIdentifier) -> Result<(), HandshakeError> {
		Ok(())
	}

	/// Admit the certificate `named` by the reply, for signing under
	/// `purpose`.
	///
	/// The certificate must be within its validity period, and the validator
	/// must accept it. A validity check alone authenticates nobody (CWE-295).
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the validator refused it, or the signing
	///   use or `purpose` refused it.
	fn admit_named(&self, named: Certificate, purpose: ObjectIdentifier) -> Result<AdmittedServer<P>, HandshakeError> {
		named.validate_expiry()?;
		self.validator.evaluate(&named)?;

		let signing = PeerCertificate::parse(named, purpose)?;
		Ok(AdmittedServer { signing, key_agreement: None })
	}
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::KeyPurposes;
	use crate::transport::handshake::tests::{create_test_certificate, put_off_curve_key};

	/// A server admitted under the house provider.
	type HouseServer = AdmittedServer<DefaultCryptoProvider>;

	/// The house server purpose, which a trust admits a server under.
	const SERVER: ObjectIdentifier = KeyPurposes::HOUSE.server;

	#[test]
	fn an_empty_validator_set_demands_nothing() {
		let authentication = PeerAuthentication::mutual([]);
		assert!(matches!(authentication, PeerAuthentication::Anonymous));
		assert!(!authentication.requires_certificate());
	}

	#[cfg(feature = "transport-cms")]
	mod provisioned {
		use super::*;
		use crate::cms::signed_data::SignerIdentifier;
		use crate::crypto::policy::{Secp256k1Policy, VerificationPolicy};
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::sign::elliptic_curve::ALGORITHM_OID as EC_PUBLIC_KEY;
		use crate::crypto::x509::error::CertificateValidationError::{CertificateRevoked, Expired};
		use crate::crypto::x509::store::{CertificateTrustBuilder, StaticRevocationList, TrustBuilder};
		use crate::crypto::x509::ErasedSigning;
		use crate::der::asn1::{BitString, ObjectIdentifier};
		use crate::der::oid::AssociatedOid;
		use crate::der::Any;
		use crate::oids::CURVE_SECP256K1;
		use crate::random::OsRng;
		use crate::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
		use crate::testing::fixtures::{TestCertificate, TestCertificateChain, TestCmsServer};
		use crate::transport::handshake::schedule::CompressedPoint;
		use crate::transport::handshake::tests::{negated, LaterRevocation};
		use crate::transport::handshake::CmsServerChain;
		use crate::x509::ext::pkix::{KeyUsage, KeyUsages};

		/// A consumer's store that accepts every certificate and reads no
		/// validity period, which the [`CertificateTrust`] contract permits
		/// outside path validation.
		#[derive(Debug)]
		struct ExpiryBlindStore;

		impl CertificateValidation for ExpiryBlindStore {
			fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
				Ok(())
			}
		}

		impl CertificateTrust for ExpiryBlindStore {
			fn is_trusted(&self, _cert: &Certificate) -> bool {
				true
			}

			fn verify_chain(&self, _chain: &[Certificate]) -> Result<(), CertificateValidationError> {
				Ok(())
			}

			fn find_by_signer_identifier(&self, _sid: &SignerIdentifier) -> Option<&PeerCertificate<ErasedSigning>> {
				None
			}

			fn find_by_public_key(&self, _spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
				None
			}

			fn to_policy_ref(&self) -> &dyn VerificationPolicy {
				&const { Secp256k1Policy::new() }
			}
		}

		/// The built-in store, holding `trusted` alone.
		fn store_holding(trusted: Certificate) -> Arc<dyn CertificateTrust> {
			let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
			let builder = builder.with_certificate(trusted);
			Arc::new(builder.expect("the store takes a valid test certificate").build())
		}

		/// `signing` and `key_agreement`, each a bare certificate.
		fn bare(signing: Certificate, key_agreement: Certificate) -> CmsServerCertificates {
			let signing = CmsServerIdentity::Certificate(Arc::new(signing));
			let key_agreement = CmsServerIdentity::Certificate(Arc::new(key_agreement));
			CmsServerCertificates { signing, key_agreement }
		}

		/// A fresh test server.
		fn fresh_server() -> TestCmsServer {
			TestCmsServer::generate("tightbeam provisioned server")
		}

		/// The two certificates of `server`, admitted before the opening
		/// under the store of their authority.
		fn admitted(server: &TestCmsServer) -> ProvisionedServer<DefaultCryptoProvider> {
			let provisioned = server.trust().admit_provisioned(SERVER);
			provisioned.expect("the store admits both test certificates")
		}

		/// The server a client reads the reply against, once `server`'s
		/// opening sealed to its key-agreement certificate.
		fn sealed_to(server: &TestCmsServer) -> HouseServer {
			let provisioned = admitted(server);
			let sealed = provisioned.into_recipient();
			let (_, server) = sealed.expect("the key-agreement certificate names itself");
			server
		}

		/// `certificate` with an `id-ecPublicKey` SPKI on the curve `curve`
		/// whose bits are `point`.
		fn with_point(certificate: Certificate, curve: ObjectIdentifier, point: &[u8]) -> Certificate {
			let named_curve = Any::encode_from(&curve).expect("a curve OID encodes");
			let algorithm = AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters: Some(named_curve) };
			let subject_public_key = BitString::from_bytes(point).expect("a point is a BIT STRING");

			let mut certificate = certificate;
			let spki = SubjectPublicKeyInfoOwned { algorithm, subject_public_key };
			certificate.tbs_certificate.subject_public_key_info = spki;
			certificate
		}

		/// The compressed SEC1 point of the key of `key`.
		fn point_of(key: &Secp256k1SigningKey) -> [u8; 33] {
			let point = PublicKey::from(key.verifying_key()).compressed_point();
			point.expect("a secp256k1 point compresses to 33 bytes")
		}

		/// The compressed SEC1 point of the negation of the key of `key`.
		fn negated_point_of(key: &Secp256k1SigningKey) -> [u8; 33] {
			let negation = negated(&PublicKey::from(key.verifying_key()));
			negation.compressed_point().expect("a secp256k1 point compresses to 33 bytes")
		}

		/// The chain of `leaf` under `root`, ordered root to leaf.
		fn chain_of(root: &Certificate, leaf: &Certificate) -> CmsServerIdentity {
			let chain = CmsServerChain::new([root.to_owned(), leaf.to_owned()]);
			CmsServerIdentity::Chain(chain.expect("a chain of two certificates holds a leaf"))
		}

		/// The two certificates of a server under the fixed test chain, beside
		/// that chain: its leaf signs, and a leaf the intermediate issues
		/// agrees.
		fn fixed_chains() -> (CmsServerCertificates, TestCertificateChain) {
			let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
			let key_agreement_key = Secp256k1SigningKey::random(&mut OsRng);
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let issuer = &chain.intermediate_key;
			let issued = TestCertificate::issued(issuer, "Intermediate", &key_agreement_key, "Leaf", 4, usage);
			let leaf = issued.expect("the intermediate issues the key-agreement leaf");

			let key_agreement = [chain.root.to_owned(), chain.intermediate.to_owned(), leaf];
			let signing = CmsServerChain::new(chain.to_arc()).expect("the fixed chain holds a leaf");
			let key_agreement = CmsServerChain::new(key_agreement).expect("the key-agreement chain holds a leaf");
			let signing = CmsServerIdentity::Chain(signing);
			let key_agreement = CmsServerIdentity::Chain(key_agreement);
			(CmsServerCertificates { signing, key_agreement }, chain)
		}

		/// `certificate` with an `extendedKeyUsage` that names `purpose` alone.
		fn of_purpose(certificate: Certificate, purpose: ObjectIdentifier) -> Certificate {
			TestCertificate::with_key_purposes(certificate, [purpose])
		}

		#[test]
		fn a_provisioned_pair_under_its_authority_is_admitted() {
			let server = fresh_server();
			let provisioned = admitted(&server);
			assert_eq!(provisioned.signing.certificate().as_ref(), &server.signing);
		}

		#[test]
		fn a_provisioned_pair_the_store_does_not_anchor_is_refused() {
			let server = fresh_server();
			let store = store_holding(create_test_certificate().certificate);

			let refused = ProvisionedTrust::new(server.certificates(), store);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store may accept a bare certificate without reading its validity
		/// period, so the trust refuses an expired one itself.
		#[test]
		fn a_provisioned_certificate_past_its_validity_is_refused() {
			let server = fresh_server();
			let certificates = bare(TestCertificate::expired(), server.key_agreement.to_owned());

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust parses the key of each certificate for its use, so a
		/// signing certificate whose key is off the curve is refused at the
		/// admission before the opening.
		#[test]
		fn a_provisioned_certificate_whose_key_is_off_the_curve_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let mut signing = server.signing.to_owned();
			put_off_curve_key(&mut signing);

			let trust = ProvisionedTrust::new(bare(signing, server.key_agreement), Arc::new(ExpiryBlindStore))?;
			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::SpkiError(_)
				))
			));
			Ok(())
		}

		/// The signing certificate of a pair must assert `digitalSignature`,
		/// so a pair whose two certificates assert `keyAgreement` alone is
		/// refused at the admission before the opening.
		#[test]
		fn a_provisioned_signing_certificate_without_digital_signature_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let signing = TestCertificate::with_key_usage(server.signing.to_owned(), usage);
			let trust = ProvisionedTrust::new(bare(signing, server.key_agreement), Arc::new(ExpiryBlindStore))?;

			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)
				))
			));
			Ok(())
		}

		/// The key-agreement certificate of a pair must assert `keyAgreement`.
		#[test]
		fn a_provisioned_key_agreement_certificate_without_key_agreement_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let usage = KeyUsage(KeyUsages::DigitalSignature.into());
			let key_agreement = TestCertificate::with_key_usage(server.key_agreement.to_owned(), usage);
			let trust = ProvisionedTrust::new(bare(server.signing, key_agreement), Arc::new(ExpiryBlindStore))?;

			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement)
				))
			));
			Ok(())
		}

		#[test]
		fn provisioned_certificates_of_two_subjects_are_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let certificates = bare(server.signing, other.key_agreement);

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
		}

		/// Two certificates of one subject issued by two authorities name two
		/// trust anchors, so the pair is refused.
		#[test]
		fn provisioned_certificates_of_two_anchors_are_refused() {
			let server = fresh_server();
			let other = fresh_server();
			let certificates = bare(server.signing, other.key_agreement);

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
		}

		/// One point in its compressed SEC 1 encoding is the key of the signing
		/// certificate, so the pair is refused.
		#[test]
		fn provisioned_certificates_of_one_key_in_two_encodings_are_refused() {
			let server = fresh_server();
			let compressed = point_of(&server.signing_key);
			let key_agreement = with_point(server.key_agreement.to_owned(), CURVE_SECP256K1, &compressed);
			let certificates = bare(server.signing, key_agreement);

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		/// A key and its negation agree alike (SEC 1 v2.0 §3.3.1), so the pair
		/// is refused.
		#[test]
		fn provisioned_certificates_of_a_key_and_its_negation_are_refused() {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let negated_key = Secp256k1SigningKey::from(-*signing_key.as_nonzero_scalar());
			let server = TestCmsServer::of("tightbeam provisioned server", signing_key, negated_key);

			let refused = ProvisionedTrust::new(server.certificates(), Arc::new(server.store()));
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		/// Two chains under two roots name two trust anchors.
		#[test]
		fn provisioned_chains_under_two_roots_are_refused() {
			let server = fresh_server();
			let other = fresh_server();
			let signing = chain_of(&server.authority, &server.signing);
			let key_agreement = chain_of(&other.authority, &other.key_agreement);
			let certificates = CmsServerCertificates { signing, key_agreement };

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
		}

		/// A bare certificate names the root of the chain beside it by its
		/// issuer and its `authorityKeyIdentifier`.
		#[test]
		fn a_provisioned_chain_beside_a_certificate_its_root_issued_is_admitted() {
			let server = fresh_server();
			let signing = chain_of(&server.authority, &server.signing);
			let key_agreement = CmsServerIdentity::Certificate(Arc::new(server.key_agreement));
			let certificates = CmsServerCertificates { signing, key_agreement };

			let admitted = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(admitted.is_ok());
		}

		#[test]
		fn a_provisioned_chain_beside_a_certificate_of_another_authority_is_refused() {
			let server = fresh_server();
			let other = fresh_server();
			let signing = chain_of(&server.authority, &server.signing);
			let key_agreement = CmsServerIdentity::Certificate(Arc::new(other.key_agreement));
			let certificates = CmsServerCertificates { signing, key_agreement };

			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
		}

		/// A self-issued certificate is its own anchor, so two of one subject
		/// and no `authorityKeyIdentifier` name two anchors.
		#[test]
		fn provisioned_self_issued_certificates_of_one_subject_are_refused() -> Result<(), Box<dyn Error>> {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let signing = TestCertificate::authority(&signing_key, "self-issued server")?;
			let signing = TestCertificate::without_extension(signing, AuthorityKeyIdentifier::OID);
			let key_agreement_key = Secp256k1SigningKey::random(&mut OsRng);
			let key_agreement = TestCertificate::authority(&key_agreement_key, "self-issued server")?;
			let key_agreement = TestCertificate::without_extension(key_agreement, AuthorityKeyIdentifier::OID);

			let refused = ProvisionedTrust::new(bare(signing, key_agreement), Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
			Ok(())
		}

		/// Path validation refuses a chain whose root the store does not hold
		/// (RFC 5280 §6.1).
		#[test]
		fn provisioned_chains_the_store_does_not_anchor_are_refused() {
			let (certificates, _) = fixed_chains();
			let store = store_holding(create_test_certificate().certificate);

			let refused = ProvisionedTrust::new(certificates, store);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store that revokes the signing certificate after the trust was
		/// built refuses it at the next admission.
		#[test]
		fn a_signing_certificate_revoked_after_the_trust_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revocation = LaterRevocation::of(server.signing.to_owned());
			let trust = ProvisionedTrust::new(server.certificates(), Arc::new(server.store_with(revocation.clone())))?;
			revocation.revoke();

			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		#[test]
		fn a_key_agreement_certificate_revoked_after_the_trust_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revocation = LaterRevocation::of(server.key_agreement.to_owned());
			let trust = ProvisionedTrust::new(server.certificates(), Arc::new(server.store_with(revocation.clone())))?;
			revocation.revoke();

			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		/// A control of the two tests above: the revocation of the signing
		/// certificate leaves the key-agreement certificate admitted, so each
		/// test reads the revocation of its own certificate.
		#[test]
		fn a_later_revocation_admits_the_other_certificate() {
			let server = fresh_server();
			let revocation = LaterRevocation::of(server.signing.to_owned());
			let store = server.store_with(revocation.clone());
			revocation.revoke();

			let admitted = store.evaluate(&server.key_agreement);
			assert!(admitted.is_ok());
		}

		/// The trust admits each certificate against the store when it is
		/// built, so a revoked key-agreement certificate is refused there.
		#[test]
		fn a_provisioned_pair_whose_key_agreement_certificate_is_revoked_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revoked = StaticRevocationList::default().with_certificate(&server.key_agreement)?;
			let store = server.store_with(revoked);

			let refused = ProvisionedTrust::new(server.certificates(), Arc::new(store));
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		/// The pair names the client's purpose alone, so the server role
		/// refuses it at the admission before the opening (RFC 5280
		/// §4.2.1.12).
		#[test]
		fn a_provisioned_pair_of_the_client_purpose_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let signing = of_purpose(server.signing.to_owned(), KeyPurposes::HOUSE.client);
			let trust = ProvisionedTrust::new(bare(signing, server.key_agreement), Arc::new(ExpiryBlindStore))?;

			let refused: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
			Ok(())
		}

		/// A pair that names an implementor's own server purpose is admitted
		/// under that purpose.
		#[test]
		fn a_provisioned_pair_is_admitted_under_its_own_purpose() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");
			let signing = of_purpose(server.signing.to_owned(), own);
			let key_agreement = of_purpose(server.key_agreement.to_owned(), own);
			let trust = ProvisionedTrust::new(bare(signing, key_agreement), Arc::new(ExpiryBlindStore))?;

			let admitted: Result<ProvisionedServer<DefaultCryptoProvider>, _> = trust.admit_provisioned(own);
			assert!(admitted.is_ok());
			Ok(())
		}

		#[test]
		fn provisioned_certificates_of_one_key_are_refused() {
			let server = fresh_server();
			let key_usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let key_agreement = TestCertificate::without_extension(server.signing.to_owned(), KeyUsage::OID);
			let key_agreement = TestCertificate::with_key_usage(key_agreement, key_usage);

			let certificates = bare(server.signing, key_agreement);
			let refused = ProvisionedTrust::new(certificates, Arc::new(ExpiryBlindStore));
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		/// Path validation anchors each chain at its first certificate, so a
		/// pair of chains under one root is admitted.
		#[test]
		fn provisioned_chains_under_one_root_are_admitted() -> Result<(), Box<dyn Error>> {
			let (certificates, chain) = fixed_chains();

			let trust = ProvisionedTrust::new(certificates, store_holding(chain.root.to_owned()))?;
			let admitted: ProvisionedServer<DefaultCryptoProvider> = trust.admit_provisioned(SERVER)?;
			assert_eq!(admitted.signing.certificate().as_ref(), &chain.leaf);
			Ok(())
		}

		#[test]
		fn an_empty_provisioned_chain_is_refused() {
			let refused = CmsServerChain::new(Vec::new());
			assert!(matches!(refused, Err(HandshakeError::MissingServerCertificate)));
		}

		/// A server ephemeral equal to the key of the server's signing
		/// certificate is refused.
		#[test]
		fn a_server_ephemeral_equal_to_the_signing_key_is_refused() {
			let server = fresh_server();
			let refused = sealed_to(&server).server_ephemeral(&point_of(&server.signing_key));
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// A server ephemeral equal to the key of the server's key-agreement
		/// certificate is refused.
		#[test]
		fn a_server_ephemeral_equal_to_the_key_agreement_key_is_refused() {
			let server = fresh_server();
			let refused = sealed_to(&server).server_ephemeral(&point_of(&server.key_agreement_key));
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// The negation of the key-agreement key agrees as the key does, so it
		/// is refused as the server ephemeral.
		#[test]
		fn a_server_ephemeral_of_the_negated_key_agreement_key_is_refused() {
			let server = fresh_server();
			let negation = negated_point_of(&server.key_agreement_key);

			let refused = sealed_to(&server).server_ephemeral(&negation);
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// A server ephemeral distinct from both server keys is admitted.
		#[test]
		fn a_server_ephemeral_of_neither_key_is_admitted() {
			let server = fresh_server();
			let ephemeral = Secp256k1SigningKey::random(&mut OsRng);
			let admitted = sealed_to(&server).server_ephemeral(&point_of(&ephemeral));
			assert!(admitted.is_ok());
		}
	}

	#[cfg(feature = "transport-hpke")]
	mod learned {
		use super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::x509::error::CertificateValidationError::Expired;
		use crate::crypto::x509::policy::{DirectTrustValidator, RuntimeCertificatePinning};
		use crate::der::asn1::ObjectIdentifier;
		use crate::testing::fixtures::TestCertificate;
		use crate::x509::ext::pkix::{KeyUsage, KeyUsages};

		/// Trust that pins `certificate` by its fingerprint alone.
		fn pinned(certificate: &Certificate) -> LearnedTrust {
			let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate.to_owned()]);
			let pinning = pinning.expect("the test certificate has a fingerprint");
			LearnedTrust::new(pinning)
		}

		#[test]
		fn a_learned_certificate_the_validator_accepts_is_admitted() -> Result<(), Box<dyn Error>> {
			let server = create_test_certificate().certificate;
			let admitted: HouseServer = pinned(&server).admit_named(server.to_owned(), SERVER)?;
			let certificate = admitted.signing().certificate();
			assert_eq!(certificate.as_ref(), &server);
			Ok(())
		}

		/// A direct-trust validator with no anchor refuses every certificate.
		#[test]
		fn a_learned_certificate_the_validator_refuses_is_refused() {
			let trust = LearnedTrust::new(DirectTrustValidator::default());
			let unknown = create_test_certificate().certificate;
			let refusal: Result<HouseServer, _> = trust.admit_named(unknown, SERVER);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A validator that pins a certificate reads no validity period, so the
		/// trust refuses an expired certificate itself.
		#[test]
		fn a_learned_certificate_past_its_validity_is_refused() {
			let expired = TestCertificate::expired();
			let refusal: Result<HouseServer, _> = pinned(&expired).admit_named(expired, SERVER);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust admits the certificate the reply names for signing, so a
		/// certificate whose key is off the curve is refused at admission.
		#[test]
		fn a_learned_certificate_whose_key_is_off_the_curve_is_refused() {
			let mut server = create_test_certificate().certificate;
			put_off_curve_key(&mut server);

			let learned = pinned(&server);
			let refusal: Result<HouseServer, _> = learned.admit_named(server, SERVER);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::SpkiError(_)
				))
			));
		}

		/// The reply's certificate signs, so one whose `keyUsage` asserts
		/// `keyAgreement` alone is refused.
		#[test]
		fn a_learned_certificate_without_digital_signature_is_refused() {
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let server = TestCertificate::with_key_usage(create_test_certificate().certificate, usage);

			let refusal: Result<HouseServer, _> = pinned(&server).admit_named(server.to_owned(), SERVER);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)
				))
			));
		}

		/// A certificate that names the client's purpose alone is refused as
		/// the server the reply names (RFC 5280 §4.2.1.12).
		#[test]
		fn a_learned_client_certificate_is_refused_as_the_server() {
			let server = create_test_certificate().certificate;
			let server = TestCertificate::with_key_purposes(server, [KeyPurposes::HOUSE.client]);

			let refusal: Result<HouseServer, _> = pinned(&server).admit_named(server.to_owned(), SERVER);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// A certificate that names an implementor's own server purpose is
		/// admitted under that purpose.
		#[test]
		fn a_learned_certificate_is_admitted_under_its_own_purpose() {
			let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");
			let server = TestCertificate::with_key_purposes(create_test_certificate().certificate, [own]);
			let trust = pinned(&server);

			let admitted: Result<HouseServer, _> = trust.admit_named(server, own);
			assert!(admitted.is_ok());
		}
	}
}

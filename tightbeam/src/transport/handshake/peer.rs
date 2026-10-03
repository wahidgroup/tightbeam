//! What a handshake endpoint demands of its peer, and what it may record.
//!
//! Each direction of admission has one decider. The opening, the reply, and
//! the closing below are the three [legs](crate::transport::handshake#legs) of
//! a handshake.
//!
//! - A server admits its client through [`PeerAuthentication::admit`], the one
//!   constructor of [`AdmittedPeer`]. An offered certificate's proof of
//!   possession is always verified, and a session records a peer only through
//!   [`AdmittedPeer::proven`], so every session identity is a certificate a
//!   validator chain accepted and whose key signed the closing.
//! - A client admits its server through [`ProvisionedTrust`] when the identity
//!   is known before the opening, and through [`LearnedTrust`] when the reply
//!   names it. Those two build every [`AdmittedServer`].

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::x509::policy::CertificateValidation;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::orchestrator::{HandshakeVerifyingKey, PeerIdentity, Terms};
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::HandshakeProvider;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
use crate::crypto::x509::store::CertificateTrust;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::CmsServerIdentity;

/// How a handshake server authenticates its client.
#[derive(Clone)]
pub enum PeerAuthentication {
	/// Server authentication only. The session records no peer, and it
	/// treats an offered client certificate as naming nobody.
	Anonymous,
	/// Mutual authentication. The client MUST offer a certificate, and every
	/// validator in the chain MUST accept it before the session records it.
	Mutual(ValidatorChain),
}

/// The non-empty chain of validators a mutual server runs.
///
/// The field stays private and only [`PeerAuthentication::mutual`] builds a
/// chain, so every mutual server runs at least one check. A build without a
/// handshake protocol has no server to evaluate the chain, so the chain keeps
/// only the decision that mutual authentication was demanded.
#[derive(Clone)]
pub struct ValidatorChain(
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))] Arc<[Arc<dyn CertificateValidation>]>,
);

impl ValidatorChain {
	/// Run every validator against `certificate`, stopping at the first
	/// refusal.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn evaluate(&self, certificate: &Certificate) -> Result<(), HandshakeError> {
		for validator in self.0.iter() {
			validator.evaluate(certificate)?;
		}

		Ok(())
	}
}

/// A closing's proof that the key of the offered certificate signed it.
///
/// Each protocol carries the proof in its own form, and
/// [`PeerAuthentication::admit`] verifies it under the offered certificate's
/// key.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) trait PossessionProof<P: HandshakeProvider> {
	/// Verify this proof under `key`, against the transcript that `terms`
	/// sealed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the proof is
	///   malformed, or it signs another transcript or another role.
	/// - [`HandshakeError::SignatureError`] -- the signature fails to verify.
	fn verify(self, key: P::VerifyingKey, terms: &Terms<P>) -> Result<(), HandshakeError>;
}

impl PeerAuthentication {
	/// Builds mutual authentication against `validators`.
	///
	/// An empty set names no check to run, so it demands nothing and yields
	/// [`Self::Anonymous`]. This is the one definition of that rule, so a
	/// caller holding a possibly empty collection hands it over rather than
	/// deciding for itself.
	pub fn mutual(validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Self {
		let validators = validators.into_iter().collect::<Vec<_>>();
		if validators.is_empty() {
			return Self::Anonymous;
		}

		#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
		let chain = ValidatorChain(validators.into());
		#[cfg(not(any(feature = "transport-cms", feature = "transport-ecies")))]
		let chain = ValidatorChain();

		Self::Mutual(chain)
	}

	/// Whether the client MUST present a certificate.
	pub const fn requires_certificate(&self) -> bool {
		matches!(self, Self::Mutual(_))
	}

	/// Decide what the handshake may do with the certificate the client
	/// offered, and verify the proof that the client holds its key.
	///
	/// Both handshake servers call this, and it is the one constructor of
	/// [`AdmittedPeer`]. The rule is the same for both protocols:
	///
	/// - A certificate and its proof travel together. Either one alone is refused.
	/// - Under mutual authentication every validator runs before the proof.
	/// - The proof is verified whenever a certificate is offered, so an
	///   anonymous server also refuses a certificate the client cannot prove.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingClientCertificate`] -- mutual authentication
	///   is configured and the client offered no certificate, or a proof
	///   arrived with no certificate.
	/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the offered certificate.
	/// - [`HandshakeError::SignatureVerificationFailed`] -- the certificate arrived with no proof.
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	/// - The [`PossessionProof::verify`] set.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) fn admit<P, Proof>(
		&self,
		offered: Option<Certificate>,
		proof: Option<Proof>,
		terms: &Terms<P>,
	) -> Result<AdmittedPeer, HandshakeError>
	where
		P: HandshakeProvider,
		Proof: PossessionProof<P>,
	{
		let Some(certificate) = offered else {
			return match (self, proof) {
				(Self::Anonymous, None) => Ok(AdmittedPeer(Admission::Unidentified)),
				(Self::Anonymous, Some(_)) | (Self::Mutual(_), _) => Err(HandshakeError::MissingClientCertificate),
			};
		};
		if let Self::Mutual(chain) = self {
			chain.evaluate(&certificate)?;
		}

		let proof = proof.ok_or(HandshakeError::SignatureVerificationFailed)?;
		let public_key = certificate.verifying_key::<P::Curve>()?;
		proof.verify(P::VerifyingKey::from(public_key), terms)?;

		let admission = match self {
			Self::Anonymous => Admission::Offered,
			Self::Mutual(_) => Admission::Proven(Arc::new(certificate)),
		};
		Ok(AdmittedPeer(admission))
	}
}

/// The outcome of [`PeerAuthentication::admit`].
///
/// The variant stays private, so a proven peer exists only where `admit`
/// ran every validator and verified the proof.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct AdmittedPeer(Admission);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
enum Admission {
	/// Under server-only authentication, the client offered no certificate.
	Unidentified,
	/// Under server-only authentication, the client proved the key of the
	/// certificate it offered, and the certificate names nobody.
	Offered,
	/// Every configured validator accepted the certificate, and the client
	/// proved its key.
	Proven(Arc<Certificate>),
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl AdmittedPeer {
	/// The certificate the session records as its peer, present only under
	/// mutual authentication after every validator accepted it.
	pub(crate) fn proven(&self) -> Option<&Arc<Certificate>> {
		match &self.0 {
			Admission::Proven(certificate) => Some(certificate),
			Admission::Unidentified | Admission::Offered => None,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl PeerIdentity for AdmittedPeer {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		self.proven()
	}
}

/// The server certificate a client admitted.
///
/// The field stays private, so one exists only where [`ProvisionedTrust`] or
/// [`LearnedTrust`] validated the certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Clone)]
pub(crate) struct AdmittedServer(Arc<Certificate>);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl AdmittedServer {
	/// The certificate that identifies the server.
	pub(crate) fn certificate(&self) -> &Arc<Certificate> {
		&self.0
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl PeerIdentity for AdmittedServer {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		Some(&self.0)
	}
}

/// Trust in a server whose identity is known before the opening, which
/// encrypts to it.
#[cfg(feature = "transport-cms")]
pub(crate) struct ProvisionedTrust {
	/// The provisioned server identity.
	pub(crate) identity: CmsServerIdentity,
	/// The store that authenticates the identity.
	pub(crate) store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "transport-cms")]
impl ProvisionedTrust {
	/// Admit the provisioned server before the opening.
	///
	/// - A bare certificate is evaluated against the store directly.
	/// - A chain is path-validated against the store
	///   ([RFC 5280 §6.1][rfc5280-6.1]), and its leaf identifies the server.
	///
	/// A bare certificate must also be within its validity period, because a
	/// store's `evaluate` may accept one without reading it. Path validation
	/// owns the validity period of every certificate in a chain.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingServerCertificate`] -- the provisioned chain is empty.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	pub(crate) fn admit_provisioned(&self) -> Result<AdmittedServer, HandshakeError> {
		match &self.identity {
			CmsServerIdentity::Certificate(certificate) => {
				certificate.validate_expiry()?;
				self.store.evaluate(certificate)?;
				Ok(AdmittedServer(Arc::clone(certificate)))
			}
			CmsServerIdentity::Chain(chain) => {
				let leaf = chain.last().ok_or(HandshakeError::MissingServerCertificate)?;
				self.store.verify_chain(chain)?;
				Ok(AdmittedServer(Arc::new(leaf.clone())))
			}
		}
	}
}

/// Trust in a server whose identity the client learns from the reply.
#[cfg(feature = "transport-ecies")]
pub(crate) struct LearnedTrust {
	/// The validator that authenticates the certificate the reply names.
	pub(crate) validator: Arc<dyn CertificateValidation>,
}

#[cfg(feature = "transport-ecies")]
impl LearnedTrust {
	/// Admit the certificate `named` by the reply.
	///
	/// The certificate must be within its validity period, and the validator
	/// must accept it. Expiry alone authenticates nobody (CWE-295).
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the validator refused it.
	pub(crate) fn admit_named(&self, named: Certificate) -> Result<AdmittedServer, HandshakeError> {
		named.validate_expiry()?;
		self.validator.evaluate(&named)?;
		Ok(AdmittedServer(Arc::new(named)))
	}
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-ecies")))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::transport::handshake::tests::create_test_certificate;

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
		use crate::crypto::x509::error::CertificateValidationError::{self, Expired};
		use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
		use crate::testing::fixtures::TestCertificate;

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

			fn find_by_signer_identifier(&self, _sid: &SignerIdentifier) -> Option<&Certificate> {
				None
			}

			fn to_policy_ref(&self) -> &dyn VerificationPolicy {
				&Secp256k1Policy
			}
		}

		/// The built-in store, holding `trusted` alone.
		fn store_holding(trusted: Certificate) -> impl CertificateTrust {
			let builder = CertificateTrustBuilder::from(Secp256k1Policy);
			let builder = builder
				.with_certificate(trusted)
				.expect("the store takes a valid test certificate");
			builder.build()
		}

		/// Trust in the bare certificate `provisioned` against `store`.
		fn trust(provisioned: Certificate, store: impl CertificateTrust + 'static) -> ProvisionedTrust {
			let identity = CmsServerIdentity::Certificate(Arc::new(provisioned));
			ProvisionedTrust { identity, store: Arc::new(store) }
		}

		#[test]
		fn a_provisioned_certificate_the_store_holds_is_admitted() -> Result<(), Box<dyn Error>> {
			let server = create_test_certificate().certificate;
			let store = store_holding(server.to_owned());

			let admitted = trust(server.to_owned(), store).admit_provisioned()?;
			assert_eq!(admitted.certificate().as_ref(), &server);
			Ok(())
		}

		#[test]
		fn a_provisioned_certificate_the_store_does_not_hold_is_refused() {
			let server = create_test_certificate().certificate;
			let store = store_holding(create_test_certificate().certificate);

			let refusal = trust(server, store).admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store may accept a bare certificate without reading its validity
		/// period, so the trust refuses an expired one itself.
		#[test]
		fn a_provisioned_certificate_past_its_validity_is_refused() {
			let refusal = trust(TestCertificate::expired(), ExpiryBlindStore).admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}
	}

	#[cfg(feature = "transport-ecies")]
	mod learned {
		use super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::x509::error::CertificateValidationError::Expired;
		use crate::crypto::x509::policy::{DirectTrustValidator, RuntimeCertificatePinning};
		use crate::testing::fixtures::TestCertificate;

		/// Trust that pins `certificate` by fingerprint and checks nothing
		/// else about it.
		fn pinned(certificate: &Certificate) -> LearnedTrust {
			let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate.to_owned()]);
			let pinning = pinning.expect("the test certificate has a fingerprint");
			LearnedTrust { validator: Arc::new(pinning) }
		}

		#[test]
		fn a_learned_certificate_the_validator_accepts_is_admitted() -> Result<(), Box<dyn Error>> {
			let server = create_test_certificate().certificate;
			let admitted = pinned(&server).admit_named(server.to_owned())?;
			assert_eq!(admitted.certificate().as_ref(), &server);
			Ok(())
		}

		/// A direct-trust validator with no anchor refuses every certificate.
		#[test]
		fn a_learned_certificate_the_validator_refuses_is_refused() {
			let trust = LearnedTrust { validator: Arc::new(DirectTrustValidator::default()) };
			let refusal = trust.admit_named(create_test_certificate().certificate);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A validator that pins a certificate says nothing about its validity
		/// period, so the trust refuses an expired certificate itself.
		#[test]
		fn a_learned_certificate_past_its_validity_is_refused() {
			let expired = TestCertificate::expired();
			let refusal = pinned(&expired).admit_named(expired);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}
	}
}

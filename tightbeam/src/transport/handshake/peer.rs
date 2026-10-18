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
//! - [`PeerCertificate`] parses the key of a peer certificate once, and every
//!   check of a handshake reads that key.

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::x509::policy::CertificateValidation;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::cms::signed_data::SignedData;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, PublicKey};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::{CmsSigner, SignedContent};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::flow::Offer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::{HandshakeVerifyingKey, PeerIdentity, Terms};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{HandshakeCurve, HandshakeProvider};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::utils::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
use crate::crypto::x509::store::CertificateTrust;
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::CmsServerIdentity;

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

/// The certificate of a peer, with its key parsed once.
///
/// [`Self::parse`] is the one constructor. A server holds the certificate its
/// client offers in one, and a client holds the certificate of the server it
/// admitted, so each check of a handshake reads the key parsed here.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone)]
pub struct PeerCertificate<C: CurveArithmetic> {
	certificate: Arc<Certificate>,
	key: PublicKey<C>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> PeerCertificate<C> {
	/// Parse the key of `certificate`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	pub(crate) fn parse(certificate: impl Into<Arc<Certificate>>) -> Result<Self, HandshakeError> {
		let certificate = certificate.into();
		let key = certificate.verifying_key::<C>()?;
		Ok(Self { certificate, key })
	}

	/// The certificate the peer presented.
	pub(crate) fn certificate(&self) -> &Arc<Certificate> {
		&self.certificate
	}

	/// The public key that [`Self::parse`] read from the certificate.
	pub(crate) fn key(&self) -> &PublicKey<C> {
		&self.key
	}

	/// Verify the one `SignerInfo` of `signed_data` over `content` under the
	/// key of this certificate, which its `sid` must name.
	///
	/// Each signature verified here covers a transcript hash, which is fresh
	/// for each handshake, so the verified signature is the key of no ledger
	/// and drops here.
	///
	/// # Errors
	///
	/// - [`HandshakeError::SignatureVerificationFailed`] -- `signed_data` does not
	///   have exactly one signer, or the signer's checks refuse it.
	/// - [`HandshakeError::DerError`] -- a signed attribute fails to encode.
	/// - [`HandshakeError::CertificateValidationError`] -- the key identifier fails to decode.
	pub(crate) fn verify_signed<P>(
		&self,
		signed_data: &SignedData,
		content: SignedContent<'_>,
	) -> Result<(), HandshakeError>
	where
		P: HandshakeProvider<Curve = C>,
	{
		let signer_info = CmsSigner::sole_signer(signed_data)?;
		let key = P::VerifyingKey::from(self.key);
		let verifying = CmsSigner::verify_signer::<P::Signature, _>;
		verifying(signer_info, &self.certificate, &key, content).map(drop)?;
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
	pub(crate) fn admit<P>(
		&self,
		offer: Offer<P::Curve>,
		terms: &Terms<P>,
	) -> Result<AdmittedPeer<P::Curve>, HandshakeError>
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
pub struct AdmittedPeer<C: CurveArithmetic>(Admission<C>);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
enum Admission<C: CurveArithmetic> {
	/// Under server-only authentication, the client offered no certificate.
	Unidentified,
	/// Under server-only authentication, the client proved the key of the
	/// certificate it offered, and the certificate names nobody.
	Offered,
	/// Every configured validator accepted the certificate, and the client
	/// proved its key.
	Proven(PeerCertificate<C>),
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> AdmittedPeer<C> {
	/// The identity the session records as its peer, present only under
	/// mutual authentication after every validator accepted it.
	pub(crate) fn proven(&self) -> Option<&PeerCertificate<C>> {
		match &self.0 {
			Admission::Proven(identity) => Some(identity),
			Admission::Unidentified | Admission::Offered => None,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> PeerIdentity for AdmittedPeer<C> {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		let proven = self.proven();
		proven.map(PeerCertificate::certificate)
	}
}

/// The server certificate a client admitted, with its key.
///
/// The field stays private, so one exists only where [`ProvisionedTrust`] or
/// [`LearnedTrust`] validated the certificate.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone)]
pub struct AdmittedServer<C: CurveArithmetic>(PeerCertificate<C>);

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> AdmittedServer<C> {
	/// The certificate that identifies the server, with its key.
	pub(crate) fn identity(&self) -> &PeerCertificate<C> {
		&self.0
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<C: HandshakeCurve> PeerIdentity for AdmittedServer<C> {
	fn certificate(&self) -> Option<&Arc<Certificate>> {
		Some(self.0.certificate())
	}
}

/// Where a client learns the identity of its server, whose key is on `C`.
///
/// A flow names one implementation, so the leg that admits the server and
/// what the reply must name are fixed by type.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait ServerTrust<C: HandshakeCurve>: MaybeSend + MaybeSync + 'static {
	/// What the trust admits before the opening.
	type Provisioned: MaybeSend;
	/// What the reply names for the trust to admit.
	type Named: MaybeSend + 'static;

	/// Admit the server before the opening, when its identity is provisioned.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingServerCertificate`] -- the provisioned chain is empty.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	fn admit_provisioned(&self) -> Result<Self::Provisioned, HandshakeError>;

	/// Admit the server the reply names.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the validator refused it.
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	fn admit_named(&self, named: Self::Named) -> Result<AdmittedServer<C>, HandshakeError>;
}

/// Trust in a server whose identity is known before the opening, so the
/// opening encrypts to it.
#[cfg(feature = "transport-cms")]
pub struct ProvisionedTrust {
	/// The certificate of the server, or a chain whose leaf identifies the
	/// server.
	pub identity: CmsServerIdentity,
	/// The store that authenticates the identity.
	pub store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "transport-cms")]
impl<C: HandshakeCurve> ServerTrust<C> for ProvisionedTrust {
	type Provisioned = AdmittedServer<C>;
	type Named = AdmittedServer<C>;

	/// Admit the provisioned server before the opening.
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
	/// - [`HandshakeError::MissingServerCertificate`] -- the provisioned chain is empty.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	fn admit_provisioned(&self) -> Result<AdmittedServer<C>, HandshakeError> {
		let leaf = match &self.identity {
			CmsServerIdentity::Certificate(certificate) => {
				certificate.validate_expiry()?;
				self.store.evaluate(certificate)?;
				Arc::clone(certificate)
			}
			CmsServerIdentity::Chain(chain) => {
				let leaf = chain.last().ok_or(HandshakeError::MissingServerCertificate)?;
				self.store.verify_chain(chain)?;
				Arc::new(leaf.clone())
			}
		};

		let server = PeerCertificate::parse(leaf)?;
		Ok(AdmittedServer(server))
	}

	/// The reply names the server admitted before the opening, so the
	/// admission passes through unchanged.
	fn admit_named(&self, named: AdmittedServer<C>) -> Result<AdmittedServer<C>, HandshakeError> {
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
impl<C: HandshakeCurve> ServerTrust<C> for LearnedTrust {
	type Provisioned = ();
	type Named = Certificate;

	/// The reply names the server, so the admission before the opening is `()`.
	fn admit_provisioned(&self) -> Result<(), HandshakeError> {
		Ok(())
	}

	/// Admit the certificate `named` by the reply.
	///
	/// The certificate must be within its validity period, and the validator
	/// must accept it. A validity check alone authenticates nobody (CWE-295).
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the validator refused it.
	/// - [`HandshakeError::InvalidPublicKey`] -- the certificate key is not a point on the curve.
	fn admit_named(&self, named: Certificate) -> Result<AdmittedServer<C>, HandshakeError> {
		named.validate_expiry()?;
		self.validator.evaluate(&named)?;
		let server = PeerCertificate::parse(named)?;
		Ok(AdmittedServer(server))
	}
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
mod tests {
	use std::error::Error;

	use super::*;
	use crate::crypto::sign::ecdsa::k256::Secp256k1;
	use crate::transport::handshake::tests::{create_test_certificate, put_off_curve_key};

	#[test]
	fn an_empty_validator_set_demands_nothing() {
		let authentication = PeerAuthentication::mutual([]);
		assert!(matches!(authentication, PeerAuthentication::Anonymous));
		assert!(!authentication.requires_certificate());
	}

	/// A peer certificate holds its parsed key, so a certificate whose key is
	/// off the curve yields none.
	#[test]
	fn a_certificate_whose_key_is_off_the_curve_yields_no_peer_certificate() {
		let mut client = create_test_certificate();
		put_off_curve_key(&mut client.certificate);

		let refused = PeerCertificate::<Secp256k1>::parse(client.certificate);
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
	}

	#[cfg(feature = "transport-cms")]
	mod provisioned {
		use super::*;
		use crate::cms::signed_data::SignerIdentifier;
		use crate::crypto::policy::{Secp256k1Policy, VerificationPolicy};
		use crate::crypto::x509::error::CertificateValidationError::{self, Expired};
		use crate::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
		use crate::spki::SubjectPublicKeyInfoOwned;
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

			fn find_by_public_key(&self, _spki: &SubjectPublicKeyInfoOwned) -> Option<&Certificate> {
				None
			}

			fn to_policy_ref(&self) -> &dyn VerificationPolicy {
				&const { Secp256k1Policy::new() }
			}
		}

		/// The built-in store, holding `trusted` alone.
		fn store_holding(trusted: Certificate) -> impl CertificateTrust {
			let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
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

			let admitted: AdmittedServer<Secp256k1> = trust(server.to_owned(), store).admit_provisioned()?;
			let certificate = admitted.identity().certificate();
			assert_eq!(certificate.as_ref(), &server);
			Ok(())
		}

		#[test]
		fn a_provisioned_certificate_the_store_does_not_hold_is_refused() {
			let server = create_test_certificate().certificate;
			let store = store_holding(create_test_certificate().certificate);

			let refusal: Result<AdmittedServer<Secp256k1>, _> = trust(server, store).admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store may accept a bare certificate without reading its validity
		/// period, so the trust refuses an expired one itself.
		#[test]
		fn a_provisioned_certificate_past_its_validity_is_refused() {
			let provisioned = trust(TestCertificate::expired(), ExpiryBlindStore);
			let refusal: Result<AdmittedServer<Secp256k1>, _> = provisioned.admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust parses the key of the certificate it admits, so a
		/// certificate whose key is off the curve is refused at admission.
		#[test]
		fn a_provisioned_certificate_whose_key_is_off_the_curve_is_refused() {
			let mut server = create_test_certificate().certificate;
			put_off_curve_key(&mut server);
			let provisioned = trust(server, ExpiryBlindStore);

			let refusal: Result<AdmittedServer<Secp256k1>, _> = provisioned.admit_provisioned();

			assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
		}

		/// Trust in the provisioned `chain` against `store`.
		fn chain_trust(chain: Arc<[Certificate]>, store: impl CertificateTrust + 'static) -> ProvisionedTrust {
			ProvisionedTrust { identity: CmsServerIdentity::Chain(chain), store: Arc::new(store) }
		}

		/// A provisioned chain is path-validated against the store, and its
		/// leaf identifies the server.
		#[test]
		fn a_provisioned_chain_the_store_anchors_is_admitted_as_its_leaf() -> Result<(), Box<dyn Error>> {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = store_holding(chain.root.to_owned());

			let admitted: AdmittedServer<Secp256k1> = chain_trust(chain.to_arc(), store).admit_provisioned()?;
			let certificate = admitted.identity().certificate();
			assert_eq!(certificate.as_ref(), &chain.leaf);
			Ok(())
		}

		#[test]
		fn a_provisioned_chain_the_store_does_not_anchor_is_refused() -> Result<(), Box<dyn Error>> {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = store_holding(create_test_certificate().certificate);

			let refusal: Result<AdmittedServer<Secp256k1>, _> = chain_trust(chain.to_arc(), store).admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
			Ok(())
		}

		#[test]
		fn an_empty_provisioned_chain_is_refused() -> Result<(), Box<dyn Error>> {
			let chain = TestCertificate::insecure_fixed_chain()?;
			let store = store_holding(chain.root);

			let provisioned = chain_trust(Arc::from(Vec::new()), store);
			let refusal: Result<AdmittedServer<Secp256k1>, _> = provisioned.admit_provisioned();
			assert!(matches!(refusal, Err(HandshakeError::MissingServerCertificate)));
			Ok(())
		}
	}

	#[cfg(feature = "transport-hpke")]
	mod learned {
		use super::*;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::x509::error::CertificateValidationError::Expired;
		use crate::crypto::x509::policy::{DirectTrustValidator, RuntimeCertificatePinning};
		use crate::testing::fixtures::TestCertificate;

		/// Trust that pins `certificate` by its fingerprint alone.
		fn pinned(certificate: &Certificate) -> LearnedTrust {
			let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate.to_owned()]);
			let pinning = pinning.expect("the test certificate has a fingerprint");
			LearnedTrust { validator: Arc::new(pinning) }
		}

		#[test]
		fn a_learned_certificate_the_validator_accepts_is_admitted() -> Result<(), Box<dyn Error>> {
			let server = create_test_certificate().certificate;
			let admitted: AdmittedServer<Secp256k1> = pinned(&server).admit_named(server.to_owned())?;
			let certificate = admitted.identity().certificate();
			assert_eq!(certificate.as_ref(), &server);
			Ok(())
		}

		/// A direct-trust validator with no anchor refuses every certificate.
		#[test]
		fn a_learned_certificate_the_validator_refuses_is_refused() {
			let trust = LearnedTrust { validator: Arc::new(DirectTrustValidator::default()) };
			let unknown = create_test_certificate().certificate;
			let refusal: Result<AdmittedServer<Secp256k1>, _> = trust.admit_named(unknown);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A validator that pins a certificate reads no validity period, so the
		/// trust refuses an expired certificate itself.
		#[test]
		fn a_learned_certificate_past_its_validity_is_refused() {
			let expired = TestCertificate::expired();
			let refusal: Result<AdmittedServer<Secp256k1>, _> = pinned(&expired).admit_named(expired);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust parses the key of the certificate the reply names, so a
		/// certificate whose key is off the curve is refused at admission.
		#[test]
		fn a_learned_certificate_whose_key_is_off_the_curve_is_refused() {
			let mut server = create_test_certificate().certificate;
			put_off_curve_key(&mut server);
			let learned = pinned(&server);

			let refusal: Result<AdmittedServer<Secp256k1>, _> = learned.admit_named(server);

			assert!(matches!(refusal, Err(HandshakeError::InvalidPublicKey(_))));
		}
	}
}

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
//! - A client admits its server through [`ProvisionedTrust`], which pins the
//!   key-agreement certificate the opening seals to, and through
//!   [`LearnedTrust`]. In both flows the reply names the signing certificate.
//!   Those two implement [`ServerTrust`] and build every [`AdmittedServer`].
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
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::CertificateExt;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::{AgreementPoint, PeerCertificate, Signing};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::ObjectIdentifier;
#[cfg(any(
	feature = "transport-cms",
	all(feature = "transport-hpke", feature = "transport-multiplex")
))]
use crate::der::referenced::OwnedToRef;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::flow::Offer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::{PeerEphemeral, PeerIdentity, Terms};
#[cfg(any(
	feature = "transport-cms",
	all(feature = "transport-hpke", feature = "transport-multiplex")
))]
use crate::transport::handshake::HandshakeCurve;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::HandshakeProvider;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::SessionPeer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::utils::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
mod provisioned {
	pub use crate::crypto::cms::KemRecipient;
	pub use crate::crypto::x509::store::CertificateTrust;
	pub use crate::crypto::x509::KeyAgreement;
	pub(crate) use crate::transport::handshake::identity::CmsPairing;
	pub use crate::transport::handshake::CmsServerIdentity;
}

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
	fn peer(&self) -> Option<SessionPeer> {
		let proven = self.proven();
		proven.map(|identity| SessionPeer::from(Arc::clone(identity.certificate())))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) use pair::AdmittedServer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use pair::AdmittedSigning;
#[cfg(feature = "transport-cms")]
use pair::CmsServerPair;

/// The admitted server, the proof that admits its signing certificate, and
/// the CMS pair it holds. Their fields are private to this module, so
/// [`AdmittedSigning::admit`] alone builds the proof, and every
/// [`AdmittedServer`] holds a proof or a pair [`CmsServerPair::admit`] built.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod pair {
	use super::*;

	/// The server a client admitted, by the trust of its flow.
	///
	/// Its case stays private, and each constructor takes what an admission
	/// of this module returned, so every server holds a signing certificate
	/// its trust admitted.
	pub struct AdmittedServer<P: HandshakeProvider>(Admitted<P>);

	/// The case of an [`AdmittedServer`].
	enum Admitted<P: HandshakeProvider> {
		/// An HPKE server, which signs with the certificate its reply names.
		#[cfg(feature = "transport-hpke")]
		Signing(PeerCertificate<Signing<P>>),
		/// A CMS server: the signing certificate its reply names, paired with
		/// the key-agreement certificate the opening sealed to.
		#[cfg(feature = "transport-cms")]
		Cms(CmsServerPair<P>),
	}

	impl<P: HandshakeProvider> AdmittedServer<P> {
		/// The HPKE server of `signing`, the signing certificate its trust
		/// admitted.
		#[cfg(feature = "transport-hpke")]
		pub(super) fn learned(signing: AdmittedSigning<P, ()>) -> Self {
			let AdmittedSigning { signing, verdict: () } = signing;
			Self(Admitted::Signing(signing))
		}

		/// The CMS server of `pair`.
		#[cfg(feature = "transport-cms")]
		pub(super) fn paired(pair: CmsServerPair<P>) -> Self {
			Self(Admitted::Cms(pair))
		}

		/// The certificate whose key signs the reply.
		pub(crate) fn signing(&self) -> &PeerCertificate<Signing<P>> {
			match &self.0 {
				#[cfg(feature = "transport-hpke")]
				Admitted::Signing(signing) => signing,
				#[cfg(feature = "transport-cms")]
				Admitted::Cms(pair) => &pair.signing,
			}
		}

		/// Every static key of this server, which its ephemeral must differ
		/// from.
		fn keys(&self) -> ServerKeys<'_, P> {
			match &self.0 {
				#[cfg(feature = "transport-hpke")]
				Admitted::Signing(signing) => ServerKeys { signing, key_agreement: None },
				#[cfg(feature = "transport-cms")]
				Admitted::Cms(pair) => ServerKeys { signing: &pair.signing, key_agreement: pair.point.as_ref() },
			}
		}
	}

	impl<P: HandshakeProvider> PeerEphemeral<P::Curve> for AdmittedServer<P> {
		fn distinct_from(&self, point: &PublicKey<P::Curve>) -> bool {
			self.keys().distinct_from(point)
		}
	}

	impl<P: HandshakeProvider> PeerIdentity for AdmittedServer<P> {
		fn peer(&self) -> Option<SessionPeer> {
			match &self.0 {
				#[cfg(feature = "transport-hpke")]
				Admitted::Signing(signing) => Some(SessionPeer::from(Arc::clone(signing.certificate()))),
				#[cfg(feature = "transport-cms")]
				Admitted::Cms(pair) => Some(pair.peer()),
			}
		}
	}

	/// A signing certificate a reply names, as its trust admitted it under
	/// the server's purpose, beside what the trust's validator returned.
	///
	/// [`Self::admit`] is its one constructor, so a server is built only from
	/// a certificate its trust admitted.
	pub(super) struct AdmittedSigning<P: HandshakeProvider, V> {
		/// The certificate whose key signs the reply.
		signing: PeerCertificate<Signing<P>>,
		/// What the trust's validator returned for the certificate.
		verdict: V,
	}

	impl<P: HandshakeProvider, V> AdmittedSigning<P, V> {
		/// Admit `named`, the signing certificate a reply names, under
		/// `purpose`: within its validity period, then as `validate` decides,
		/// then for the signing use. Both trusts admit the reply's signer here.
		///
		/// A validator may accept a certificate without reading its validity
		/// period, as a pin does, and a validity check alone authenticates
		/// nobody (CWE-295).
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- the certificate
		///   is outside its validity period, `validate` refused it, or the
		///   signing use or `purpose` refused it.
		pub(super) fn admit(
			named: Certificate,
			purpose: ObjectIdentifier,
			validate: impl FnOnce(&Certificate) -> Result<V, CertificateValidationError>,
		) -> Result<Self, HandshakeError> {
			named.validate_expiry()?;

			let verdict = validate(&named)?;
			let signing = PeerCertificate::parse(named, purpose)?;
			Ok(Self { signing, verdict })
		}
	}

	/// The two certificates of a CMS server as its client admitted them: the
	/// signing certificate the reply names, and the key-agreement certificate
	/// the opening sealed to.
	///
	/// [`Self::admit`] is the one constructor, so every pair names one subject
	/// under one trust anchor with two distinct keys.
	#[cfg(feature = "transport-cms")]
	pub struct CmsServerPair<P: HandshakeProvider> {
		/// The certificate whose key signs the reply.
		signing: PeerCertificate<Signing<P>>,
		/// The key-agreement certificate, shared with the trust that pins it,
		/// which the session keeps for a rekey.
		#[cfg(feature = "transport-multiplex")]
		key_agreement: Arc<Certificate>,
		/// The key of the key-agreement certificate as a point of the
		/// handshake curve, or `None` for a key of another curve.
		point: Option<PublicKey<P::Curve>>,
	}

	#[cfg(feature = "transport-cms")]
	impl<P: HandshakeProvider> CmsServerPair<P> {
		/// Pair `signing`, the certificate the reply names as the store
		/// admitted it beside the trust anchor its path ended at, with
		/// `key_agreement`, the certificate the opening sealed to.
		///
		/// # Errors
		///
		/// - [`HandshakeError::SubjectMismatch`] -- the two certificates name two subjects.
		/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key.
		/// - [`HandshakeError::AnchorMismatch`] -- the two certificates name two trust anchors.
		pub(super) fn admit(
			signing: AdmittedSigning<P, Arc<Certificate>>,
			key_agreement: PinnedKeyAgreement<P>,
		) -> Result<Self, HandshakeError> {
			let AdmittedSigning { signing, verdict: signing_anchor } = signing;
			let PinnedKeyAgreement { certificate, anchor, point } = key_agreement;
			signing.certificate().pairs_with(&certificate)?;
			if *signing_anchor != *anchor {
				return Err(HandshakeError::AnchorMismatch);
			}

			Ok(Self {
				signing,
				#[cfg(feature = "transport-multiplex")]
				key_agreement: certificate,
				point,
			})
		}

		/// The two certificates of this pair as the session records them.
		fn peer(&self) -> SessionPeer {
			SessionPeer {
				certificate: Arc::clone(self.signing.certificate()),
				#[cfg(feature = "transport-multiplex")]
				key_agreement: Some(Arc::clone(&self.key_agreement)),
			}
		}
	}
}

/// The static keys a server ephemeral must differ from: the key of the
/// server's signing certificate, and for a CMS server the key of its
/// key-agreement certificate as a point of the handshake curve.
///
/// The handshake reads them from the [`AdmittedServer`], and a rekey from the
/// session, so both compare a server ephemeral alike.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) struct ServerKeys<'a, P: HandshakeProvider> {
	/// The certificate whose key signs the reply.
	pub(crate) signing: &'a PeerCertificate<Signing<P>>,
	/// The key of a CMS server's key-agreement certificate, or `None` for an
	/// HPKE server and for a key of another curve.
	pub(crate) key_agreement: Option<&'a PublicKey<P::Curve>>,
}

/// A server ephemeral collapses into a server key when it shares the
/// x-coordinate of either certificate key, so the check reads both against
/// the ephemeral's x-coordinate, read once.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> PeerEphemeral<P::Curve> for ServerKeys<'_, P> {
	fn distinct_from(&self, point: &PublicKey<P::Curve>) -> bool {
		let x = point.as_affine().x();
		let signing = !self.signing.shares_x(&x);
		let agreement = self
			.key_agreement
			.is_none_or(|key| !AgreementPoint::<P::Curve>::shares_x(key, &x));
		signing && agreement
	}
}

/// A certificate read as a key of the handshake curve, the form an agreement
/// compares it in.
#[cfg(any(
	feature = "transport-cms",
	all(feature = "transport-hpke", feature = "transport-multiplex")
))]
pub(crate) trait AgreementCertificate {
	/// The key of this certificate as a point of the curve `C`, or `None` for
	/// a key of another curve.
	fn agreement_point<C: HandshakeCurve>(&self) -> Option<PublicKey<C>>;
}

#[cfg(any(
	feature = "transport-cms",
	all(feature = "transport-hpke", feature = "transport-multiplex")
))]
impl AgreementCertificate for Certificate {
	fn agreement_point<C: HandshakeCurve>(&self) -> Option<PublicKey<C>> {
		// A key of another curve is no point of the handshake curve and
		// collapses no agreement on it, so its parse refusal drops here.
		let spki = self.tbs_certificate.subject_public_key_info.owned_to_ref();
		PublicKey::<C>::try_from(spki).ok()
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
	/// - [`HandshakeError::Envelope`] -- the key-agreement certificate fails to name its recipient.
	fn admit_provisioned(&self, purpose: ObjectIdentifier) -> Result<Self::Provisioned, HandshakeError>;

	/// Admit the server the reply names, under the server's key purpose
	/// `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the validator refused it, or the signing
	///   use or `purpose` refused it.
	/// - The [`CmsServerPair::admit`] set, for a CMS server.
	fn admit_named(&self, named: Self::Named, purpose: ObjectIdentifier) -> Result<AdmittedServer<P>, HandshakeError>;
}

#[cfg(feature = "transport-cms")]
impl CmsServerIdentity {
	/// Admit this provisioned certificate against `store`, and return its
	/// leaf beside the trust anchor at which the store's path validation ends
	/// (RFC 5280 §6.1.1 (d)).
	///
	/// - A bare certificate must be within its validity period, because a
	///   store's [`evaluate`](CertificateValidation::evaluate) may accept one
	///   without reading it, and the store then names its anchor.
	/// - A chain is path-validated against the store
	///   ([RFC 5280 §6.1][rfc5280-6.1]), which owns the validity period of
	///   each certificate in it. Its leaf identifies the server, and
	///   [`CertificateTrust::verify_chain`] returns its anchor.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	fn admit(&self, store: &dyn CertificateTrust) -> Result<(&Arc<Certificate>, Arc<Certificate>), HandshakeError> {
		match self {
			Self::Certificate(certificate) => {
				certificate.validate_expiry()?;
				let anchor = store.trust_anchor(certificate)?;
				Ok((certificate, anchor))
			}
			Self::Chain(chain) => {
				let anchor = store.verify_chain(chain.path())?;
				Ok((chain.leaf(), anchor))
			}
		}
	}
}

/// Trust in a CMS server whose key-agreement certificate the client pins, so
/// the opening seals to it.
///
/// The server's signing certificate travels in its Finished. At each reply
/// the store admits it, and the client pairs it with the pinned certificate:
/// one subject, one trust anchor, and two distinct keys.
#[cfg(feature = "transport-cms")]
#[derive(Clone)]
pub struct ProvisionedTrust {
	/// The server's key-agreement certificate, a leaf or a chain.
	key_agreement: CmsServerIdentity,
	/// The store that authenticates both of the server's certificates.
	store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "transport-cms")]
impl ProvisionedTrust {
	/// Trust in the server whose key-agreement certificate is
	/// `key_agreement`, as `store` authenticates it.
	///
	/// The certificate is admitted against the store once here, and again at
	/// each handshake, since its validity period and the store's verdict
	/// change after construction.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	pub fn new(
		key_agreement: impl Into<CmsServerIdentity>,
		store: Arc<dyn CertificateTrust>,
	) -> Result<Self, HandshakeError> {
		let key_agreement = key_agreement.into();
		// The admission here refuses a certificate the store refuses, and each
		// handshake admits it again, so its leaf and anchor drop here.
		key_agreement.admit(store.as_ref())?;
		Ok(Self { key_agreement, store })
	}
}

/// The key-agreement certificate of a CMS server, admitted for its use before
/// the opening, beside the key the opening seals to.
///
/// [`ProvisionedTrust`] builds it once at its admission before the opening.
#[cfg(feature = "transport-cms")]
pub struct ProvisionedKeyAgreement<P: HandshakeProvider> {
	/// The certificate as the client holds it from the opening to the reply.
	pinned: PinnedKeyAgreement<P>,
	/// The key the opening seals to, beside its `rid`.
	recipient: KemRecipient<P::Kem>,
}

/// The key-agreement certificate of a CMS server, as its client holds it from
/// the opening to the reply, where the pair with the signing certificate
/// reads it.
#[cfg(feature = "transport-cms")]
pub struct PinnedKeyAgreement<P: HandshakeProvider> {
	/// The certificate, shared with the trust that pins it.
	certificate: Arc<Certificate>,
	/// The trust anchor at which the store's path validation of the
	/// certificate ended.
	anchor: Arc<Certificate>,
	/// The key, parsed once as a point of the handshake curve, or `None` for a
	/// key of another curve.
	point: Option<PublicKey<P::Curve>>,
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ProvisionedKeyAgreement<P> {
	/// `admitted`, whose path the store ended at `anchor`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::Envelope`] -- the certificate fails to name its recipient.
	fn new(admitted: PeerCertificate<KeyAgreement<P::Kem>>, anchor: Arc<Certificate>) -> Result<Self, HandshakeError> {
		let certificate = Arc::clone(admitted.certificate());
		let point = certificate.agreement_point::<P::Curve>();
		let recipient = KemRecipient::from_certificate(admitted)?;
		let pinned = PinnedKeyAgreement { certificate, anchor, point };
		Ok(Self { pinned, recipient })
	}

	/// The certificate the client holds to the reply, and the key the opening
	/// seals to, beside its `rid`.
	pub(crate) fn into_parts(self) -> (PinnedKeyAgreement<P>, KemRecipient<P::Kem>) {
		(self.pinned, self.recipient)
	}
}

/// What a CMS reply names for its client to admit: the signing certificate its
/// Finished carries, beside the key-agreement certificate the opening sealed
/// to.
#[cfg(feature = "transport-cms")]
pub struct CmsNamedServer<P: HandshakeProvider> {
	/// The certificate the Finished's `sid` names, parsed from the bytes the
	/// transcript bound.
	pub(crate) signing: Certificate,
	/// The key-agreement certificate, admitted before the opening.
	pub(crate) key_agreement: PinnedKeyAgreement<P>,
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ServerTrust<P> for ProvisionedTrust {
	type Provisioned = ProvisionedKeyAgreement<P>;
	type Named = CmsNamedServer<P>;

	/// Admit the pinned key-agreement certificate before the opening: against
	/// the store, then for key agreement under `purpose`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the store refused it or its chain, or its
	///   use or `purpose` refused it.
	/// - [`HandshakeError::Envelope`] -- the certificate fails to name its recipient.
	fn admit_provisioned(&self, purpose: ObjectIdentifier) -> Result<ProvisionedKeyAgreement<P>, HandshakeError> {
		let (certificate, anchor) = self.key_agreement.admit(self.store.as_ref())?;
		let admitted = PeerCertificate::parse(Arc::clone(certificate), purpose)?;
		ProvisionedKeyAgreement::new(admitted, anchor)
	}

	/// Admit the server the reply names: its signing certificate against the
	/// store for signing under `purpose`, then the pair it makes with the
	/// key-agreement certificate the opening sealed to.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the signing
	///   certificate is outside its validity period, the store refused it, or
	///   the signing use or `purpose` refused it.
	/// - The [`CmsServerPair::admit`] set.
	fn admit_named(
		&self,
		named: CmsNamedServer<P>,
		purpose: ObjectIdentifier,
	) -> Result<AdmittedServer<P>, HandshakeError> {
		let CmsNamedServer { signing, key_agreement } = named;
		let trust_anchor = |certificate: &Certificate| self.store.trust_anchor(certificate);
		let signing = AdmittedSigning::admit(signing, purpose, trust_anchor)?;

		let pair = CmsServerPair::admit(signing, key_agreement)?;
		Ok(AdmittedServer::paired(pair))
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
	/// must accept it.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the validator refused it, or the signing
	///   use or `purpose` refused it.
	fn admit_named(&self, named: Certificate, purpose: ObjectIdentifier) -> Result<AdmittedServer<P>, HandshakeError> {
		let evaluate = |certificate: &Certificate| self.validator.evaluate(certificate);
		let signing = AdmittedSigning::admit(named, purpose, evaluate)?;
		Ok(AdmittedServer::learned(signing))
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
		use crate::crypto::x509::ext::pkix::AuthorityKeyIdentifier;
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

		/// The key-agreement certificate a client of the house provider holds
		/// from the admission before the opening.
		type HouseKeyAgreement = ProvisionedKeyAgreement<DefaultCryptoProvider>;

		/// A consumer's store that accepts every certificate under one trust
		/// anchor and reads no validity period, which the [`CertificateTrust`]
		/// contract permits outside path validation.
		#[derive(Debug)]
		struct ExpiryBlindStore {
			/// The anchor the store names for every certificate.
			anchor: Arc<Certificate>,
		}

		impl ExpiryBlindStore {
			/// A store that names the authority of `server` as every anchor.
			fn under(server: &TestCmsServer) -> Arc<dyn CertificateTrust> {
				Arc::new(Self { anchor: Arc::new(server.authority.to_owned()) })
			}
		}

		impl CertificateValidation for ExpiryBlindStore {
			fn evaluate(&self, _cert: &Certificate) -> Result<(), CertificateValidationError> {
				Ok(())
			}
		}

		impl CertificateTrust for ExpiryBlindStore {
			fn is_trusted(&self, _cert: &Certificate) -> bool {
				true
			}

			fn verify_chain(&self, _chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
				Ok(Arc::clone(&self.anchor))
			}

			fn trust_anchor(&self, _cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
				Ok(Arc::clone(&self.anchor))
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

		/// The built-in store, holding `trusted`.
		fn store_holding(trusted: impl IntoIterator<Item = Certificate>) -> Arc<dyn CertificateTrust> {
			let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
			let builder = trusted.into_iter().try_fold(builder, TrustBuilder::with_certificate);
			Arc::new(builder.expect("the store takes valid test certificates").build())
		}

		/// `certificate`, bare, as a client pins it.
		fn bare(certificate: &Certificate) -> CmsServerIdentity {
			CmsServerIdentity::Certificate(Arc::new(certificate.to_owned()))
		}

		/// A fresh test server.
		fn fresh_server() -> TestCmsServer {
			TestCmsServer::generate("tightbeam provisioned server")
		}

		/// A trust that pins `key_agreement` against `store`.
		fn pinning(key_agreement: CmsServerIdentity, store: Arc<dyn CertificateTrust>) -> ProvisionedTrust {
			let trust = ProvisionedTrust::new(key_agreement, store);
			trust.expect("the store admits the pinned test certificate")
		}

		/// The server `trust` admits under `purpose` from a reply that names
		/// `signing`, once its opening sealed to the pinned certificate.
		fn admit_reply(
			trust: &ProvisionedTrust,
			signing: &Certificate,
			purpose: ObjectIdentifier,
		) -> Result<HouseServer, HandshakeError> {
			let provisioned: HouseKeyAgreement = trust.admit_provisioned(purpose)?;
			let (key_agreement, _) = provisioned.into_parts();
			let named = CmsNamedServer { signing: signing.to_owned(), key_agreement };
			trust.admit_named(named, purpose)
		}

		/// The server a client of `server` admits from its honest reply.
		fn admitted(server: &TestCmsServer) -> HouseServer {
			let admitted = admit_reply(&server.trust(), &server.signing, SERVER);
			admitted.expect("the store admits both test certificates as one server")
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

		/// A key-agreement leaf of the subject of the fixed chain's leaf,
		/// which `issuer_key` issues as `issuer_cn`.
		fn key_agreement_leaf(issuer_key: &Secp256k1SigningKey, issuer_cn: &str) -> Certificate {
			let key = Secp256k1SigningKey::random(&mut OsRng);
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());

			let issued = TestCertificate::issued(issuer_key, issuer_cn, &key, "Leaf", 4, usage);
			issued.expect("the issuer issues the key-agreement leaf")
		}

		/// The fixed test chain, whose leaf signs under the intermediate.
		fn fixed_chain() -> TestCertificateChain {
			TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues")
		}

		/// `certificate` with an `extendedKeyUsage` that names `purpose` alone.
		fn of_purpose(certificate: Certificate, purpose: ObjectIdentifier) -> Certificate {
			TestCertificate::with_key_purposes(certificate, [purpose])
		}

		/// The pinned key-agreement certificate under its authority is
		/// admitted before the opening, as the certificate the trust pins.
		#[test]
		fn a_pinned_key_agreement_certificate_under_its_authority_is_admitted() -> Result<(), HandshakeError> {
			let server = fresh_server();
			let admitted: HouseKeyAgreement = server.trust().admit_provisioned(SERVER)?;
			assert_eq!(admitted.pinned.certificate.as_ref(), &server.key_agreement);
			Ok(())
		}

		/// The reply's signing certificate under the pinned certificate's
		/// authority pairs with it, and the client reads the reply against it.
		#[test]
		fn a_signing_certificate_the_reply_names_is_paired() -> Result<(), HandshakeError> {
			let server = fresh_server();
			let paired = admit_reply(&server.trust(), &server.signing, SERVER)?;
			assert_eq!(paired.signing().certificate().as_ref(), &server.signing);
			Ok(())
		}

		/// The admitted pair keeps the key-agreement certificate the opening
		/// sealed to, so the session holds it for a rekey.
		#[cfg(feature = "transport-multiplex")]
		#[test]
		fn a_paired_server_keeps_its_key_agreement_certificate() {
			let server = fresh_server();
			let peer = admitted(&server).peer();
			let key_agreement = peer.as_ref().and_then(SessionPeer::key_agreement);
			assert_eq!(key_agreement, Some(&server.key_agreement));
		}

		/// The admitted pair records its signing certificate as the peer
		/// certificate of the session, the one a client reports for its server.
		#[test]
		fn a_paired_server_records_its_signing_certificate() {
			let server = fresh_server();
			let peer = admitted(&server).peer();
			let certificate = peer.as_ref().map(|peer| peer.certificate().as_ref());
			assert_eq!(certificate, Some(&server.signing));
		}

		#[test]
		fn a_pinned_certificate_the_store_does_not_anchor_is_refused() {
			let server = fresh_server();
			let store = store_holding([create_test_certificate().certificate]);

			let refused = ProvisionedTrust::new(bare(&server.key_agreement), store);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store may accept a bare certificate without reading its validity
		/// period, so the trust refuses an expired one itself.
		#[test]
		fn a_pinned_certificate_past_its_validity_is_refused() {
			let server = fresh_server();
			let refused = ProvisionedTrust::new(bare(&TestCertificate::expired()), ExpiryBlindStore::under(&server));
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The reply's signing certificate is held to its validity period, as
		/// the pinned one is.
		#[test]
		fn a_named_signing_certificate_past_its_validity_is_refused() {
			let server = fresh_server();
			let trust = pinning(bare(&server.key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &TestCertificate::expired(), SERVER);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust parses the key of the reply's certificate for signing, so
		/// a signing certificate whose key is off the curve is refused at the
		/// reply.
		#[test]
		fn a_named_signing_certificate_whose_key_is_off_the_curve_is_refused() {
			let server = fresh_server();
			let mut signing = server.signing.to_owned();
			put_off_curve_key(&mut signing);
			let trust = pinning(bare(&server.key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::SpkiError(_)
				))
			));
		}

		/// The reply's certificate must assert `digitalSignature`.
		#[test]
		fn a_named_signing_certificate_without_digital_signature_is_refused() {
			let server = fresh_server();
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let signing = TestCertificate::with_key_usage(server.signing.to_owned(), usage);
			let trust = pinning(bare(&server.key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)
				))
			));
		}

		/// The pinned certificate must assert `keyAgreement`, which the
		/// admission before the opening reads.
		#[test]
		fn a_pinned_certificate_without_key_agreement_is_refused() {
			let server = fresh_server();
			let usage = KeyUsage(KeyUsages::DigitalSignature.into());
			let key_agreement = TestCertificate::with_key_usage(server.key_agreement.to_owned(), usage);
			let trust = pinning(bare(&key_agreement), ExpiryBlindStore::under(&server));

			let refused: Result<HouseKeyAgreement, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement)
				))
			));
		}

		#[test]
		fn a_named_signing_certificate_of_another_subject_is_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let trust = pinning(bare(&server.key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &other.signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
		}

		/// The signing certificate of `server`'s subject and key that the
		/// authority of `other` issues.
		fn issued_by_other(server: &TestCmsServer, other: &TestCmsServer) -> Certificate {
			let subject = server.signing.tbs_certificate.subject.to_owned();
			other.issue_signing(&server.signing_key, subject, 7)
		}

		/// Two certificates of one subject issued by two authorities name two
		/// trust anchors, so the pair is refused.
		#[test]
		fn a_named_signing_certificate_of_another_anchor_is_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let store = store_holding([server.authority.to_owned(), other.authority.to_owned()]);
			let trust = pinning(bare(&server.key_agreement), store);

			let refused = admit_reply(&trust, &issued_by_other(&server, &other), SERVER);
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
		}

		/// One point in its compressed SEC 1 encoding is the key of the signing
		/// certificate, so the pair is refused.
		#[test]
		fn a_pair_of_one_key_in_two_encodings_is_refused() {
			let server = fresh_server();
			let compressed = point_of(&server.signing_key);
			let key_agreement = with_point(server.key_agreement.to_owned(), CURVE_SECP256K1, &compressed);
			let trust = pinning(bare(&key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &server.signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		/// A key and its negation agree alike (SEC 1 v2.0 §3.3.1), so the pair
		/// is refused.
		#[test]
		fn a_pair_of_a_key_and_its_negation_is_refused() {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let negated_key = Secp256k1SigningKey::from(-*signing_key.as_nonzero_scalar());
			let server = TestCmsServer::of("tightbeam provisioned server", signing_key, negated_key);

			let refused = admit_reply(&server.trust(), &server.signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		#[test]
		fn a_pair_of_one_key_is_refused() {
			let server = fresh_server();
			let key_usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let key_agreement = TestCertificate::without_extension(server.signing.to_owned(), KeyUsage::OID);
			let key_agreement = TestCertificate::with_key_usage(key_agreement, key_usage);
			let trust = pinning(bare(&key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &server.signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
		}

		/// A pinned chain under one root and a signing certificate of another
		/// root name two trust anchors.
		#[test]
		fn a_pinned_chain_beside_a_signing_certificate_of_another_root_is_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let store = store_holding([server.authority.to_owned(), other.authority.to_owned()]);
			let trust = pinning(chain_of(&server.authority, &server.key_agreement), store);

			let refused = admit_reply(&trust, &issued_by_other(&server, &other), SERVER);
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
		}

		/// A pinned chain and the signing certificate its root issued name one
		/// anchor, the root.
		#[test]
		fn a_pinned_chain_beside_a_signing_certificate_its_root_issued_is_paired() -> Result<(), HandshakeError> {
			let server = fresh_server();
			let store = store_holding([server.authority.to_owned()]);
			let trust = pinning(chain_of(&server.authority, &server.key_agreement), store);

			let paired = admit_reply(&trust, &server.signing, SERVER)?;
			assert_eq!(paired.signing().certificate().as_ref(), &server.signing);
			Ok(())
		}

		/// Path validation reads the leaf of a pinned chain, so a chain whose
		/// leaf its root did not issue is refused (RFC 5280 §6.1).
		#[test]
		fn a_pinned_chain_whose_leaf_its_root_did_not_issue_is_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let store = store_holding([server.authority.to_owned()]);

			let refused = ProvisionedTrust::new(chain_of(&server.authority, &other.key_agreement), store);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A store that revokes the leaf of a pinned chain after the trust was
		/// built refuses it at the next opening.
		#[test]
		fn a_pinned_chain_whose_leaf_is_revoked_after_the_trust_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revocation = LaterRevocation::of(server.key_agreement.to_owned());
			let store = Arc::new(server.store_with(revocation.clone()));
			let trust = ProvisionedTrust::new(chain_of(&server.authority, &server.key_agreement), store)?;
			revocation.revoke();

			let refused: Result<HouseKeyAgreement, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		/// A self-issued certificate is its own anchor, so two of one subject
		/// that the store trusts each name two anchors.
		#[test]
		fn self_issued_certificates_of_one_subject_are_refused() -> Result<(), Box<dyn Error>> {
			let signing_key = Secp256k1SigningKey::random(&mut OsRng);
			let signing = TestCertificate::authority(&signing_key, "self-issued server")?;
			let signing = TestCertificate::without_extension(signing, AuthorityKeyIdentifier::OID);
			let signing = TestCertificate::with_key_usage(signing, KeyUsage(KeyUsages::DigitalSignature.into()));
			let key_agreement_key = Secp256k1SigningKey::random(&mut OsRng);
			let key_agreement = TestCertificate::authority(&key_agreement_key, "self-issued server")?;
			let key_agreement = TestCertificate::without_extension(key_agreement, AuthorityKeyIdentifier::OID);
			let key_agreement =
				TestCertificate::with_key_usage(key_agreement, KeyUsage(KeyUsages::KeyAgreement.into()));
			let store = PinnedAnchors::of([signing.to_owned(), key_agreement.to_owned()]);
			let trust = ProvisionedTrust::new(bare(&key_agreement), store)?;

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
			Ok(())
		}

		/// Path validation refuses a pinned chain whose root the store does
		/// not hold (RFC 5280 §6.1).
		#[test]
		fn a_pinned_chain_the_store_does_not_anchor_is_refused() -> Result<(), HandshakeError> {
			let chain = fixed_chain();
			let key_agreement = key_agreement_leaf(&chain.intermediate_key, "Intermediate");
			let pinned = [chain.root.to_owned(), chain.intermediate.to_owned(), key_agreement];
			let pinned = CmsServerIdentity::Chain(CmsServerChain::new(pinned)?);
			let store = store_holding([create_test_certificate().certificate]);

			let refused = ProvisionedTrust::new(pinned, store);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
			Ok(())
		}

		/// The anchor is the one the store's path validation ends at (RFC 5280
		/// §6.1.1 (d)), so a signing certificate under an intermediate pairs
		/// with a key-agreement certificate the root issued.
		#[test]
		fn a_signing_certificate_under_an_intermediate_pairs_with_one_the_root_issued() -> Result<(), HandshakeError> {
			let chain = fixed_chain();
			let key_agreement = key_agreement_leaf(&chain.root_key, "Root");
			let store = store_holding([chain.root.to_owned(), chain.intermediate.to_owned()]);
			let trust = ProvisionedTrust::new(bare(&key_agreement), store)?;

			let paired = admit_reply(&trust, &chain.leaf, SERVER)?;
			assert_eq!(paired.signing().certificate().as_ref(), &chain.leaf);
			Ok(())
		}

		/// A pinned chain through the intermediate and a signing certificate
		/// of the same intermediate end at one root.
		#[test]
		fn chains_under_one_root_are_paired() -> Result<(), HandshakeError> {
			let chain = fixed_chain();
			let key_agreement = key_agreement_leaf(&chain.intermediate_key, "Intermediate");
			let pinned = [chain.root.to_owned(), chain.intermediate.to_owned(), key_agreement];
			let pinned = CmsServerIdentity::Chain(CmsServerChain::new(pinned)?);
			let store = store_holding([chain.root.to_owned(), chain.intermediate.to_owned()]);
			let trust = ProvisionedTrust::new(pinned, store)?;

			let paired = admit_reply(&trust, &chain.leaf, SERVER)?;
			assert_eq!(paired.signing().certificate().as_ref(), &chain.leaf);
			Ok(())
		}

		/// A pinned chain that starts at an intermediate the store holds ends
		/// at the store's root, as the walk of a signing certificate under that
		/// intermediate does (RFC 5280 §6.1.1 (d)).
		#[test]
		fn a_chain_from_a_held_intermediate_pairs_with_its_signing_certificate() -> Result<(), HandshakeError> {
			let chain = fixed_chain();
			let key_agreement = key_agreement_leaf(&chain.intermediate_key, "Intermediate");
			let pinned = [chain.intermediate.to_owned(), key_agreement];
			let pinned = CmsServerIdentity::Chain(CmsServerChain::new(pinned)?);
			let store = store_holding([chain.root.to_owned(), chain.intermediate.to_owned()]);
			let trust = ProvisionedTrust::new(pinned, store)?;

			let paired = admit_reply(&trust, &chain.leaf, SERVER)?;
			assert_eq!(paired.signing().certificate().as_ref(), &chain.leaf);
			Ok(())
		}

		#[test]
		fn an_empty_provisioned_chain_is_refused() {
			let refused = CmsServerChain::new(Vec::new());
			assert!(matches!(refused, Err(HandshakeError::MissingServerCertificate)));
		}

		/// A store that revokes the signing certificate after the trust was
		/// built refuses it at the next reply.
		#[test]
		fn a_signing_certificate_revoked_after_the_trust_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revocation = LaterRevocation::of(server.signing.to_owned());
			let store = Arc::new(server.store_with(revocation.clone()));
			let trust = ProvisionedTrust::new(bare(&server.key_agreement), store)?;
			revocation.revoke();

			let refused = admit_reply(&trust, &server.signing, SERVER);
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
			let store = Arc::new(server.store_with(revocation.clone()));
			let trust = ProvisionedTrust::new(bare(&server.key_agreement), store)?;
			revocation.revoke();

			let refused: Result<HouseKeyAgreement, _> = trust.admit_provisioned(SERVER);
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

		/// The trust admits its pinned certificate against the store when it
		/// is built, so a revoked one is refused there.
		#[test]
		fn a_revoked_pinned_certificate_is_refused() -> Result<(), Box<dyn Error>> {
			let server = fresh_server();
			let revoked = StaticRevocationList::default().with_certificate(&server.key_agreement)?;
			let store = server.store_with(revoked);

			let refused = ProvisionedTrust::new(bare(&server.key_agreement), Arc::new(store));
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		/// A signing certificate of the client's purpose alone is refused as
		/// the server the reply names (RFC 5280 §4.2.1.12).
		#[test]
		fn a_named_signing_certificate_of_the_client_purpose_is_refused() {
			let server = fresh_server();
			let signing = of_purpose(server.signing.to_owned(), KeyPurposes::HOUSE.client);
			let trust = pinning(bare(&server.key_agreement), ExpiryBlindStore::under(&server));

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// A pinned certificate of the client's purpose alone is refused at the
		/// admission before the opening.
		#[test]
		fn a_pinned_certificate_of_the_client_purpose_is_refused() {
			let server = fresh_server();
			let key_agreement = of_purpose(server.key_agreement.to_owned(), KeyPurposes::HOUSE.client);
			let trust = pinning(bare(&key_agreement), ExpiryBlindStore::under(&server));

			let refused: Result<HouseKeyAgreement, _> = trust.admit_provisioned(SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// A pair that names an implementor's own server purpose is admitted
		/// under that purpose.
		#[test]
		fn a_pair_is_admitted_under_its_own_purpose() -> Result<(), HandshakeError> {
			let server = fresh_server();
			let own = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");
			let signing = of_purpose(server.signing.to_owned(), own);
			let key_agreement = of_purpose(server.key_agreement.to_owned(), own);
			let trust = pinning(bare(&key_agreement), ExpiryBlindStore::under(&server));

			let admitted = admit_reply(&trust, &signing, own)?;
			assert_eq!(admitted.signing().certificate().as_ref(), &signing);
			Ok(())
		}

		/// A server ephemeral equal to the key of the server's signing
		/// certificate is refused.
		#[test]
		fn a_server_ephemeral_equal_to_the_signing_key_is_refused() {
			let server = fresh_server();
			let refused = admitted(&server).server_ephemeral(&point_of(&server.signing_key));
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// A server ephemeral equal to the key of the server's key-agreement
		/// certificate is refused.
		#[test]
		fn a_server_ephemeral_equal_to_the_key_agreement_key_is_refused() {
			let server = fresh_server();
			let refused = admitted(&server).server_ephemeral(&point_of(&server.key_agreement_key));
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// The negation of the key-agreement key agrees as the key does, so it
		/// is refused as the server ephemeral.
		#[test]
		fn a_server_ephemeral_of_the_negated_key_agreement_key_is_refused() {
			let server = fresh_server();
			let negation = negated_point_of(&server.key_agreement_key);

			let refused = admitted(&server).server_ephemeral(&negation);
			assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
		}

		/// A server ephemeral distinct from both server keys is admitted.
		#[test]
		fn a_server_ephemeral_of_neither_key_is_admitted() {
			let server = fresh_server();
			let ephemeral = Secp256k1SigningKey::random(&mut OsRng);
			let admitted = admitted(&server).server_ephemeral(&point_of(&ephemeral));
			assert!(admitted.is_ok());
		}

		/// A store that trusts each certificate it pins as its own anchor.
		#[derive(Debug)]
		struct PinnedAnchors(Vec<Arc<Certificate>>);

		impl PinnedAnchors {
			/// A store that pins each of `pinned` as an anchor.
			fn of(pinned: impl IntoIterator<Item = Certificate>) -> Arc<dyn CertificateTrust> {
				Arc::new(Self(pinned.into_iter().map(Arc::new).collect()))
			}

			/// The pin that equals `cert`.
			fn pin(&self, cert: &Certificate) -> Option<&Arc<Certificate>> {
				self.0.iter().find(|pin| pin.as_ref() == cert)
			}
		}

		impl CertificateValidation for PinnedAnchors {
			fn evaluate(&self, cert: &Certificate) -> Result<(), CertificateValidationError> {
				self.pin(cert)
					.map(drop)
					.ok_or(CertificateValidationError::CertificateNotTrusted)
			}
		}

		impl CertificateTrust for PinnedAnchors {
			fn is_trusted(&self, cert: &Certificate) -> bool {
				self.pin(cert).is_some()
			}

			fn verify_chain(&self, _chain: &[Certificate]) -> Result<Arc<Certificate>, CertificateValidationError> {
				Err(CertificateValidationError::CertificateNotTrusted)
			}

			fn trust_anchor(&self, cert: &Certificate) -> Result<Arc<Certificate>, CertificateValidationError> {
				self.pin(cert)
					.map(Arc::clone)
					.ok_or(CertificateValidationError::CertificateNotTrusted)
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

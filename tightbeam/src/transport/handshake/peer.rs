//! What a handshake endpoint demands of its peer, and what it may record.
//!
//! Each direction of admission has one decider. The opening, the reply, and
//! the closing named below are the three
//! [legs](crate::transport::handshake#legs) of a handshake.
//!
//! - A server admits its client through [`PeerAuthentication::admit`], the one
//!   constructor of [`AdmittedPeer`]. It always verifies the client Finished
//!   of an offered certificate, and a session records a peer only through
//!   [`AdmittedPeer::proven`], so every session identity is a certificate a
//!   validator chain accepted and whose key signed the closing.
//! - A client admits its server through [`ProvisionedTrust`], which pins the
//!   key-agreement certificate the opening seals to, and through
//!   [`LearnedTrust`]. In both flows the reply names the signing certificate.
//!   Those two implement [`ServerTrust`] and build every [`AdmittedServer`].
//! - A client's server policy runs once per handshake on the identity
//!   certificate of its flow, in the constructor of what the flow admits:
//!   [`ProvisionedKeyAgreement`] for CMS, and the HPKE [`AdmittedServer`].
//! - A [`PeerCertificate`] admits each certificate for the one use the
//!   handshake reads it for, and every check of a handshake reads the key that
//!   admission parsed.

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::x509::policy::CertificateValidation;

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::clock::Clock;
#[cfg(feature = "transport-hpke")]
use crate::crypto::sign::PresentedIssuers;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::PresentedPath;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::store::CertificateTrust;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::utils::ValidityClock;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::{PeerCertificate, Signing};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::ObjectIdentifier;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::marker::{MaybeSend, MaybeSync};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::ephemeral::{Distinct, PeerStatics};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::flow::Offer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::Terms;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::SessionPeer;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{ClientConfig, ClientFlow};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::{Exchange, HandshakeProvider, ServerShare};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
mod provisioned {
	pub use crate::crypto::cms::{KemRecipient, RecipientKem};
	pub use crate::crypto::x509::KeyAgreement;
	pub(crate) use crate::transport::handshake::identity::CmsPairing;
	pub use crate::transport::handshake::CmsServerIdentity;
}

#[cfg(feature = "transport-cms")]
use provisioned::*;

/// How a handshake server authenticates its client.
#[derive(Clone, Debug)]
pub enum PeerAuthentication {
	/// Only the server authenticates. The session peer stays empty, even for a
	/// client that offers a certificate.
	Anonymous,
	/// Both sides authenticate. The client MUST offer a certificate, and every
	/// validator in the chain MUST accept it before the session records it.
	/// The certificate MUST be within its validity period on the clock of the
	/// server. A server on the crate clock of a build that has none refuses
	/// every client.
	Mutual(ValidatorChain),
}

pub use chain::ValidatorChain;

/// The validator chain, with one evaluation per identity type. Its field and
/// its evaluation of a bare certificate are private to this module, so a
/// policy reads the identity certificate of its role alone.
mod chain {
	use super::*;

	/// The non-empty chain of validators a policy runs: a mutual server's
	/// policy of its client, or a client's policy of its server.
	///
	/// [`Self::new`] builds a chain of a non-empty set, and [`Self::with`]
	/// builds one around the check it adds, so every chain runs at least one
	/// check. In a build without a handshake protocol, the chain records only
	/// that a policy is set.
	#[derive(Clone)]
	pub struct ValidatorChain(
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))] Arc<[Arc<dyn CertificateValidation>]>,
	);

	impl ValidatorChain {
		/// The chain of `validators`, or `None` for an empty set, which names
		/// no check to run. It is the one definition of that rule, for client
		/// and server policies alike.
		pub(crate) fn new(validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Option<Self> {
			let validators = validators.into_iter().collect::<Arc<[_]>>();
			if validators.is_empty() {
				return None;
			}

			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			let chain = Self(validators);
			#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
			let chain = Self();

			Some(chain)
		}

		/// The chain that runs every check of `prior`, then `validator`.
		pub(super) fn with(prior: Option<Self>, validator: Arc<dyn CertificateValidation>) -> Self {
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			{
				let held = prior.iter().flat_map(|chain| chain.0.iter().map(Arc::clone));
				Self(held.chain([validator]).collect())
			}
			#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
			{
				drop((prior, validator));
				Self()
			}
		}

		/// Run every validator against `certificate` until the first refusal.
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		fn evaluate(&self, certificate: &Certificate) -> Result<(), HandshakeError> {
			for validator in self.0.iter() {
				validator.evaluate(certificate)?;
			}

			Ok(())
		}

		/// Admit the certificate `offer` holds under this chain, the policy of
		/// a mutual server: within its validity period on `clock`, then as
		/// every validator decides on it beside the issuers the client
		/// presents above it. This chain passes an offer of no certificate,
		/// and [`PeerAuthentication::admit`] decides on it.
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- the certificate
		///   is outside its validity period, or a validator refused it or its
		///   path.
		#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
		pub(super) fn admit_offer<P: HandshakeProvider>(
			&self,
			offer: &Offer<P>,
			clock: &ValidityClock<dyn Clock>,
		) -> Result<(), HandshakeError> {
			let Some((identity, issuers)) = offer.presented() else {
				return Ok(());
			};
			// A validator may accept a certificate and leave its validity
			// period unread, as a pin does, so the chain reads it first.
			let certificate = identity.certificate();
			clock.admits(certificate)?;
			for validator in self.0.iter() {
				validator.evaluate_presented(issuers.as_slice(), certificate)?;
			}

			Ok(())
		}

		/// Admit `key_agreement`, the pinned certificate of a CMS server, under
		/// this chain, the server policy of its client.
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the certificate.
		#[cfg(feature = "transport-cms")]
		pub(super) fn admit_key_agreement<K: RecipientKem>(
			&self,
			key_agreement: &PeerCertificate<KeyAgreement<K>>,
		) -> Result<(), HandshakeError> {
			self.evaluate(key_agreement.certificate())
		}

		/// Admit `signing`, the certificate an HPKE reply names as its
		/// [`LearnedTrust`] admitted it, under this chain, the server policy of
		/// its client.
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- a validator refused the certificate.
		#[cfg(feature = "transport-hpke")]
		pub(super) fn admit_learned<P: HandshakeProvider>(
			&self,
			signing: &AdmittedSigning<P, LearnedVerdict>,
		) -> Result<(), HandshakeError> {
			self.evaluate(signing.certificate())
		}
	}

	/// The chain writes the count of the validators it runs. A build without a
	/// handshake protocol holds the mark of a policy alone, so there the chain
	/// writes its name.
	impl core::fmt::Debug for ValidatorChain {
		fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
			#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
			{
				f.debug_struct("ValidatorChain").field("validators", &self.0.len()).finish()
			}
			#[cfg(not(any(feature = "transport-cms", feature = "transport-hpke")))]
			{
				f.debug_struct("ValidatorChain").finish_non_exhaustive()
			}
		}
	}
}

impl PeerAuthentication {
	/// Builds mutual authentication against `validators`, or answers `None`
	/// for an empty set, which names no check to run.
	///
	/// The caller names its own fallback for an empty set, so anonymous
	/// clients follow only from its word (CWE-1188). For one validator,
	/// [`Self::Anonymous`] with [`Self::and`] names the same demand.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::x509::policy::{CertificateValidation, ExpiryValidator};
	/// use tightbeam::transport::handshake::PeerAuthentication;
	///
	/// let validators: Vec<Arc<dyn CertificateValidation>> = vec![Arc::new(ExpiryValidator::default())];
	/// let mutual = PeerAuthentication::mutual(validators).ok_or("an empty validator set")?;
	/// assert!(mutual.requires_certificate());
	///
	/// assert!(PeerAuthentication::mutual(Vec::new()).is_none());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn mutual(validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> Option<Self> {
		ValidatorChain::new(validators).map(Self::Mutual)
	}

	/// Adds `validator` to the checks a client's certificate MUST pass.
	///
	/// - [`Self::Anonymous`] becomes [`Self::Mutual`] over `validator` alone,
	///   so the server demands a certificate.
	/// - [`Self::Mutual`] runs `validator` after every check it holds.
	///
	/// Both cases give [`Self::Mutual`], so a server that adds its own trust to
	/// the authentication an operator named always demands a certificate.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::x509::policy::ExpiryValidator;
	/// use tightbeam::transport::handshake::PeerAuthentication;
	///
	/// let authentication = PeerAuthentication::Anonymous.and(Arc::new(ExpiryValidator::default()));
	/// assert!(authentication.requires_certificate());
	/// ```
	#[must_use]
	pub fn and(self, validator: Arc<dyn CertificateValidation>) -> Self {
		let prior = match self {
			Self::Anonymous => None,
			Self::Mutual(chain) => Some(chain),
		};
		Self::Mutual(ValidatorChain::with(prior, validator))
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
	/// - Under mutual authentication, the validity check on `clock` and then
	///   every validator run before the Finished. Each validator reads the
	///   certificate beside the issuers the Finished presents, through
	///   [`CertificateValidation::evaluate_presented`].
	/// - It verifies the Finished whenever the client offers a certificate,
	///   so an anonymous server also refuses a certificate the client cannot
	///   prove.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingClientCertificate`] -- mutual authentication
	///   is configured and the client offered no certificate.
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, a validator refused it, or the key of
	///   the proven certificate reads as no point of its curve.
	/// - The errors of [`ClientFinished::verify`], when the client Finished fails to verify.
	/// - [`HandshakeError::DerError`] -- the DER encoder refuses the key of the proven certificate.
	///
	/// [`ClientFinished::verify`]: crate::transport::handshake::flow::ClientFinished::verify
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(crate) fn admit<P>(
		&self,
		offer: Offer<P>,
		terms: &Terms<P>,
		clock: &ValidityClock<dyn Clock>,
	) -> Result<AdmittedPeer<P>, HandshakeError>
	where
		P: HandshakeProvider,
	{
		if let Self::Mutual(chain) = self {
			chain.admit_offer(&offer, clock)?;
		}
		let Some((identity, finished)) = offer.into_identity() else {
			return match self {
				Self::Anonymous => Ok(AdmittedPeer(Admission::Unidentified)),
				Self::Mutual(_) => Err(HandshakeError::MissingClientCertificate),
			};
		};

		finished.verify(&identity, terms)?;

		let admission = match self {
			Self::Anonymous => Admission::Offered,
			Self::Mutual(_) => {
				let peer = SessionPeer::admitted(&identity)?;
				Admission::Proven { identity, peer }
			}
		};
		Ok(AdmittedPeer(admission))
	}
}

#[cfg(test)]
impl PeerAuthentication {
	/// Mutual authentication against `validator` alone.
	pub(crate) fn mutual_with(validator: impl CertificateValidation + 'static) -> Self {
		let validator: Arc<dyn CertificateValidation> = Arc::new(validator);
		PeerAuthentication::Anonymous.and(validator)
	}

	/// Mutual authentication under the default expiry check alone.
	pub(crate) fn mutual_by_expiry() -> Self {
		let expiry = crate::crypto::x509::policy::ExpiryValidator::default();
		PeerAuthentication::mutual_with(expiry)
	}
}

/// The admitted party a role records as its peer.
///
/// It is sealed to this module, so its implementors are the admissions of
/// both roles. Each builds its record where it admits, so
/// [`Agreed::server`](super::schedule::Agreed::server) and
/// [`Agreed::client`](super::schedule::Agreed::client) record only a peer an
/// admission built.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub(crate) trait PeerIdentity: sealed::Admitted {
	/// The peer the session records, or `None` when the peer proved no
	/// identity.
	fn into_peer(self) -> Option<SessionPeer>;
}

/// The seal of [`PeerIdentity`]: its supertrait is unnameable outside this
/// module.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
mod sealed {
	/// A party an admission of this module built.
	pub trait Admitted {}
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
	/// certificate it offered, and the session stays anonymous.
	Offered,
	/// Every configured validator accepted the certificate, and the client
	/// proved its key.
	Proven {
		/// The certificate the validators accepted.
		identity: PeerCertificate<Signing<P>>,
		/// The record of the certificate the session keeps as its peer.
		peer: SessionPeer,
	},
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> AdmittedPeer<P> {
	/// The identity the session records as its peer, present only under
	/// mutual authentication after every validator accepted it.
	pub(crate) fn proven(&self) -> Option<&PeerCertificate<Signing<P>>> {
		match &self.0 {
			Admission::Proven { identity, .. } => Some(identity),
			Admission::Unidentified | Admission::Offered => None,
		}
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> sealed::Admitted for AdmittedPeer<P> {}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<P: HandshakeProvider> PeerIdentity for AdmittedPeer<P> {
	fn into_peer(self) -> Option<SessionPeer> {
		match self.0 {
			Admission::Proven { peer, .. } => Some(peer),
			Admission::Unidentified | Admission::Offered => None,
		}
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
	/// its trust admitted, beside the record the session keeps of it.
	pub struct AdmittedServer<P: HandshakeProvider> {
		/// The case of this server.
		admitted: Admitted<P>,
		/// The static keys this server's ephemeral must differ from.
		statics: PeerStatics<Exchange<P>>,
		/// The record of this server the session keeps as its peer.
		peer: SessionPeer,
	}

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
		/// The HPKE server of `signing`, the signing certificate its
		/// [`LearnedTrust`] admitted, once `policy`, the server policy, admits
		/// it. It is the one constructor of the HPKE case, so every HPKE server
		/// meets the policy.
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- a validator of
		///   `policy` refused the certificate, or its key reads as no point of
		///   its curve.
		/// - [`HandshakeError::DerError`] -- the DER encoder refuses the key of the certificate.
		#[cfg(feature = "transport-hpke")]
		pub(super) fn learned(
			signing: AdmittedSigning<P, LearnedVerdict>,
			policy: Option<&ValidatorChain>,
		) -> Result<Self, HandshakeError> {
			if let Some(policy) = policy {
				policy.admit_learned(&signing)?;
			}

			// The verdict proved the trust's admission for the policy above, so
			// its life ends here.
			let AdmittedSigning { signing, verdict } = signing;
			let _admitted: LearnedVerdict = verdict;
			let statics = PeerStatics::of(signing.certificate(), None);
			let peer = SessionPeer::admitted(&signing)?;
			Ok(Self { admitted: Admitted::Signing(signing), statics, peer })
		}

		/// The CMS server of `pair`.
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- the key of the
		///   signing certificate reads as no point of its curve.
		/// - [`HandshakeError::DerError`] -- the DER encoder refuses the key of the signing certificate.
		#[cfg(feature = "transport-cms")]
		pub(super) fn paired(pair: CmsServerPair<P>) -> Result<Self, HandshakeError> {
			let statics = PeerStatics::of(pair.signing.certificate(), Some(&pair.key_agreement));
			let peer = pair.peer()?;
			Ok(Self { admitted: Admitted::Cms(pair), statics, peer })
		}

		/// The certificate whose key signs the reply.
		pub(crate) fn signing(&self) -> &PeerCertificate<Signing<P>> {
			match &self.admitted {
				#[cfg(feature = "transport-hpke")]
				Admitted::Signing(signing) => signing,
				#[cfg(feature = "transport-cms")]
				Admitted::Cms(pair) => &pair.signing,
			}
		}

		/// Admits `share` as the share of this server, distinct from each of
		/// its static keys.
		///
		/// # Errors
		///
		/// - The errors of [`PeerStatics::server_ephemeral`].
		pub(crate) fn server_ephemeral(
			&self,
			share: ServerShare<P>,
		) -> Result<Distinct<ServerShare<P>>, HandshakeError> {
			self.statics.server_ephemeral(share)
		}
	}

	impl<P: HandshakeProvider> sealed::Admitted for AdmittedServer<P> {}

	impl<P: HandshakeProvider> PeerIdentity for AdmittedServer<P> {
		fn into_peer(self) -> Option<SessionPeer> {
			Some(self.peer)
		}
	}

	/// A signing certificate a reply names, as its trust admitted it under
	/// the server's purpose, beside what the trust's validator returned.
	///
	/// [`Self::admit`] is its one constructor, so every server this module
	/// builds holds a certificate its trust admitted.
	pub(super) struct AdmittedSigning<P: HandshakeProvider, V> {
		/// The certificate whose key signs the reply.
		signing: PeerCertificate<Signing<P>>,
		/// What the trust's validator returned for the certificate.
		verdict: V,
	}

	impl<P: HandshakeProvider, V> AdmittedSigning<P, V> {
		/// Admit `named`, the signing certificate a reply names, under
		/// `admission`. Both trusts admit the reply's signer here, in this
		/// order:
		///
		/// 1. The validity period on the clock of `admission`, which a
		///    validator may leave unread, as a pin does.
		/// 2. The signing use under the purpose of `admission`, which decodes
		///    the key that a validator then reads.
		/// 3. `validate`, because a validity check alone authenticates nobody (CWE-295).
		///
		/// # Errors
		///
		/// - [`HandshakeError::CertificateValidationError`] -- the certificate
		///   is outside its validity period, `validate` refused it, or the
		///   signing use or the purpose refused it.
		pub(super) fn admit(
			named: Certificate,
			admission: ServerAdmission<'_>,
			validate: impl FnOnce(&Certificate) -> Result<V, CertificateValidationError>,
		) -> Result<Self, HandshakeError> {
			admission.clock.admits(&named)?;

			let signing = PeerCertificate::parse(named, admission.purpose)?;
			let verdict = validate(signing.certificate())?;
			Ok(Self { signing, verdict })
		}

		/// The certificate the trust admitted, which the server policy reads.
		#[cfg(feature = "transport-hpke")]
		pub(super) fn certificate(&self) -> &Certificate {
			self.signing.certificate()
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
		/// The key-agreement certificate, shared with the trust that pins it.
		/// The admitted server reads its key once, and the session keeps it for
		/// a rekey.
		key_agreement: Arc<Certificate>,
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
		/// - [`HandshakeError::CertificateValidationError`] -- a
		///   `subjectAltName` of an empty subject fails to decode.
		/// - [`HandshakeError::KeyReuse`] -- the two certificates hold one key.
		/// - [`HandshakeError::AnchorMismatch`] -- the two certificates name two trust anchors.
		pub(super) fn admit(
			signing: AdmittedSigning<P, Arc<Certificate>>,
			key_agreement: PinnedKeyAgreement,
		) -> Result<Self, HandshakeError> {
			let AdmittedSigning { signing, verdict: signing_anchor } = signing;
			let PinnedKeyAgreement { certificate, anchor } = key_agreement;
			signing.certificate().pairs_with(&certificate)?;
			if *signing_anchor != *anchor {
				return Err(HandshakeError::AnchorMismatch);
			}

			Ok(Self { signing, key_agreement: certificate })
		}

		/// The certificates of this pair as the session records them: the
		/// signing certificate, and in a build with the mux rekey the
		/// key-agreement certificate beside it, for that rekey.
		fn peer(&self) -> Result<SessionPeer, HandshakeError> {
			let peer = SessionPeer::admitted(&self.signing)?;
			#[cfg(mux_rekey)]
			let peer = peer.with_key_agreement(Arc::clone(&self.key_agreement));
			Ok(peer)
		}
	}
}

/// What a client lends its server trust at each admission: the key purpose
/// of the server's role, the server policy, and the clock of the client.
///
/// [`Self::of`] is its one constructor, so every admission carries the policy
/// and the clock of its client configuration. Each trust runs the policy on
/// the identity certificate of its flow: the pinned key-agreement certificate
/// of a CMS server, and the signing certificate of an HPKE server.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
#[derive(Clone, Copy)]
pub struct ServerAdmission<'a> {
	/// The key purpose that every certificate of the server admits.
	purpose: ObjectIdentifier,
	/// The server policy, or `None` when the client sets none.
	policy: Option<&'a ValidatorChain>,
	/// The clock that the validity period of each certificate of the server
	/// is read on.
	clock: &'a ValidityClock<dyn Clock>,
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl<'a> ServerAdmission<'a> {
	/// The admission of `config`: its server purpose, its server policy, and
	/// its clock.
	pub(crate) fn of<F: ClientFlow<P>, P: HandshakeProvider>(config: &'a ClientConfig<F, P>) -> Self {
		Self {
			purpose: config.key_purposes().server,
			policy: config.server_policy(),
			clock: config.clock(),
		}
	}
}

/// Where a client learns the identity of its server under the provider `P`.
///
/// A flow names one implementation, so its type fixes the leg that admits the
/// server and what the reply must name.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait ServerTrust<P: HandshakeProvider>: MaybeSend + MaybeSync + 'static {
	/// What the trust admits before the opening.
	type Provisioned: MaybeSend;
	/// What the reply names for the trust to admit.
	type Named: MaybeSend + 'static;

	/// Admit the server before the opening, when its identity is provisioned,
	/// under `admission`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a certificate is
	///   outside its validity period, the store refused it or its chain, its
	///   use or the server's purpose refused it, or the server policy refused
	///   it.
	/// - [`HandshakeError::Envelope`] -- the key-agreement certificate fails to name its recipient.
	fn admit_provisioned(&self, admission: ServerAdmission<'_>) -> Result<Self::Provisioned, HandshakeError>;

	/// Admit the server the reply names, under `admission`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the trust refused it or its path, the
	///   signing use or the server's purpose refused it, or the server policy
	///   of an HPKE server refused it.
	/// - The errors of [`CmsServerPair::admit`], for a CMS server.
	fn admit_named(
		&self,
		named: Self::Named,
		admission: ServerAdmission<'_>,
	) -> Result<AdmittedServer<P>, HandshakeError>;
}

#[cfg(feature = "transport-cms")]
impl CmsServerIdentity {
	/// Admit this provisioned certificate against `store`, and return its
	/// leaf beside the trust anchor at which the store's path validation ends
	/// (RFC 5280 §6.1.1(d)).
	///
	/// - A bare certificate must be within its validity period on `clock`,
	///   because a store's [`evaluate`](CertificateValidation::evaluate) may
	///   accept one and leave that period unread, and the store then names
	///   its anchor.
	/// - The store path-validates a chain ([RFC 5280 §6.1][rfc5280-6.1]) and
	///   owns the validity period of each certificate in it. Its leaf
	///   identifies the server, and [`CertificateTrust::verify_chain`] returns
	///   its anchor.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, or the store refused it or its chain.
	///
	/// [rfc5280-6.1]: https://datatracker.ietf.org/doc/html/rfc5280#section-6.1
	fn admit(
		&self,
		store: &dyn CertificateTrust,
		clock: &ValidityClock<dyn Clock>,
	) -> Result<(&Arc<Certificate>, Arc<Certificate>), HandshakeError> {
		match self {
			Self::Certificate(certificate) => {
				clock.admits(certificate)?;
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
	/// The store that runs path validation and revocation on both of the
	/// server's certificates. The server policy reads the key-agreement
	/// certificate at its own leg.
	store: Arc<dyn CertificateTrust>,
}

#[cfg(feature = "transport-cms")]
impl ProvisionedTrust {
	/// Trust in the server whose key-agreement certificate is
	/// `key_agreement`, as `store` authenticates it.
	///
	/// It admits the certificate against the store once, on the crate clock,
	/// and each handshake admits it again on the clock of its client, because
	/// its validity period and the store's verdict change after construction.
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
		// The trust precedes every client, so this admission reads the crate
		// clock. Each handshake admits the certificate again, so its leaf and
		// anchor drop here.
		key_agreement.admit(store.as_ref(), &ValidityClock::CRATE)?;
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
	pinned: PinnedKeyAgreement,
	/// The key the opening seals to, beside its `rid`.
	recipient: KemRecipient<P::Kem>,
}

/// The key-agreement certificate of a CMS server, as its client holds it from
/// the opening to the reply, where the pair with the signing certificate
/// reads it.
#[cfg(feature = "transport-cms")]
pub struct PinnedKeyAgreement {
	/// The certificate, shared with the trust that pins it.
	certificate: Arc<Certificate>,
	/// The trust anchor at which the store's path validation of the
	/// certificate ended.
	anchor: Arc<Certificate>,
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ProvisionedKeyAgreement<P> {
	/// `admitted`, whose path the store ended at `anchor`, once `policy`, the
	/// server policy, admits it. It is the one constructor of what the opening
	/// seals to, so the opening seals to a certificate the policy admitted.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- a validator of `policy` refused the certificate.
	/// - [`HandshakeError::Envelope`] -- the certificate fails to name its recipient.
	fn new(
		admitted: PeerCertificate<KeyAgreement<P::Kem>>,
		anchor: Arc<Certificate>,
		policy: Option<&ValidatorChain>,
	) -> Result<Self, HandshakeError> {
		if let Some(policy) = policy {
			policy.admit_key_agreement(&admitted)?;
		}

		let certificate = Arc::clone(admitted.certificate());
		let recipient = KemRecipient::from_certificate(admitted)?;
		let pinned = PinnedKeyAgreement { certificate, anchor };
		Ok(Self { pinned, recipient })
	}

	/// The certificate the client holds to the reply, and the key the opening
	/// seals to, beside its `rid`.
	pub(crate) fn into_parts(self) -> (PinnedKeyAgreement, KemRecipient<P::Kem>) {
		(self.pinned, self.recipient)
	}
}

/// What a CMS reply names for its client to admit: the path of the signing
/// certificate its Finished carries, beside the key-agreement certificate the
/// opening sealed to.
#[cfg(feature = "transport-cms")]
pub struct CmsNamedServer {
	/// The certificate the Finished's `sid` names and the issuers above it
	/// that the Finished presents, parsed from the bytes the transcript
	/// bound.
	pub(crate) signing: PresentedPath,
	/// The key-agreement certificate, admitted before the opening.
	pub(crate) key_agreement: PinnedKeyAgreement,
}

#[cfg(feature = "transport-cms")]
impl<P: HandshakeProvider> ServerTrust<P> for ProvisionedTrust {
	type Provisioned = ProvisionedKeyAgreement<P>;
	type Named = CmsNamedServer;

	/// Admit the pinned key-agreement certificate before the opening: against
	/// the store, then for key agreement under the server's purpose, then
	/// under the server policy of `admission`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the store refused it or its chain, its
	///   use or the server's purpose refused it, or the server policy refused
	///   it.
	/// - [`HandshakeError::Envelope`] -- the certificate fails to name its recipient.
	fn admit_provisioned(&self, admission: ServerAdmission<'_>) -> Result<ProvisionedKeyAgreement<P>, HandshakeError> {
		let (certificate, anchor) = self.key_agreement.admit(self.store.as_ref(), admission.clock)?;
		let admitted = PeerCertificate::parse(Arc::clone(certificate), admission.purpose)?;
		ProvisionedKeyAgreement::new(admitted, anchor, admission.policy)
	}

	/// Admit the server the reply names. Its signing certificate passes for
	/// signing under the server's purpose, its presented path validated to an
	/// anchor of the store (RFC 5280 §6.1). It then pairs with the
	/// key-agreement certificate that the opening sealed to and the server
	/// policy admitted.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the signing
	///   certificate is outside its validity period, the store refused its
	///   path, or the signing use or the server's purpose refused it.
	/// - The errors of [`CmsServerPair::admit`].
	fn admit_named(
		&self,
		named: CmsNamedServer,
		admission: ServerAdmission<'_>,
	) -> Result<AdmittedServer<P>, HandshakeError> {
		let CmsNamedServer { signing, key_agreement } = named;
		let (leaf, issuers) = signing.into_parts();
		let anchor = |leaf: &Certificate| self.store.verify_presented(issuers.as_slice(), leaf);
		let signing = AdmittedSigning::admit(leaf, admission, anchor)?;

		let pair = CmsServerPair::admit(signing, key_agreement)?;
		AdmittedServer::paired(pair)
	}
}

/// Trust in a server whose identity the client learns from the reply.
///
/// The reply presents its signing certificate and the issuers above it. The
/// trust admits them in one of two forms:
///
/// - [`Self::anchored`] validates the presented path to an anchor of a store
///   (RFC 5280 §6.1), as a CMS client does.
/// - [`Self::new`] runs a validator on the signing certificate alone, such as a pin of that certificate.
#[cfg(feature = "transport-hpke")]
pub struct LearnedTrust(Learned);

/// The form of a [`LearnedTrust`]. It stays private, so the constructors of
/// the trust alone pick one.
#[cfg(feature = "transport-hpke")]
enum Learned {
	/// A validator that reads the signing certificate alone.
	Validator(Arc<dyn CertificateValidation>),
	/// A store that validates the presented path to one of its trust anchors.
	Store(Arc<dyn CertificateTrust>),
}

#[cfg(feature = "transport-hpke")]
impl LearnedTrust {
	/// Trust in the servers whose certificate `validator` accepts.
	pub fn new(validator: impl CertificateValidation + 'static) -> Self {
		Self(Learned::Validator(Arc::new(validator)))
	}

	/// Trust in the servers whose presented path `store` validates to one of
	/// its trust anchors, through [`CertificateTrust::verify_presented`].
	///
	/// A reply carries the issuers above its signing certificate
	/// (RFC 5652 §5.1), so a store that holds the root alone admits a server
	/// whose signing certificate an intermediate issued.
	///
	/// # Examples
	///
	/// ```
	/// use std::sync::Arc;
	///
	/// use tightbeam::crypto::policy::Secp256k1Policy;
	/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
	/// use tightbeam::crypto::x509::store::{CertificateTrustBuilder, NoRevocation, TrustBuilder};
	/// use tightbeam::crypto::x509::{KeyCurves, KeyPurposes};
	/// use tightbeam::testing::fixtures::{TestCertificate, TestCertificateChain};
	/// use tightbeam::transport::handshake::{ClientConfig, Hpke, HpkeClientSettings, LearnedTrust};
	///
	/// // The keys of the fixture chain are public, so it serves an example
	/// // alone.
	/// let TestCertificateChain { root, .. } = TestCertificate::insecure_fixed_chain()?;
	///
	/// // The store holds the root alone, and each reply presents the path
	/// // below it.
	/// let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	/// let store = builder.with_certificate(root)?.build();
	/// let settings = HpkeClientSettings::new(LearnedTrust::anchored(Arc::new(store)));
	/// let _config = ClientConfig::<Hpke, DefaultCryptoProvider>::new(settings, KeyPurposes::HOUSE)?;
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn anchored(store: Arc<dyn CertificateTrust>) -> Self {
		Self(Learned::Store(store))
	}

	/// Validate `leaf`, the signing certificate a reply names, beside
	/// `issuers`, the issuers above it that the reply presents.
	///
	/// A validator reads `leaf` alone. A store validates the path of `leaf`
	/// under `issuers`.
	///
	/// # Errors
	///
	/// - The errors of the validator's [`CertificateValidation::evaluate`].
	/// - The errors of the store's [`CertificateTrust::verify_presented`].
	fn validate(&self, leaf: &Certificate, issuers: PresentedIssuers) -> Result<(), CertificateValidationError> {
		match &self.0 {
			Learned::Validator(validator) => validator.evaluate(leaf),
			Learned::Store(store) => {
				// An HPKE server signs under one certificate, so no other path
				// compares with this anchor, and the anchor drops here.
				let anchor = store.verify_presented(issuers.as_slice(), leaf);
				anchor.map(drop)
			}
		}
	}
}

/// A shared validator is the whole trust.
#[cfg(feature = "transport-hpke")]
impl From<Arc<dyn CertificateValidation>> for LearnedTrust {
	fn from(validator: Arc<dyn CertificateValidation>) -> Self {
		Self(Learned::Validator(validator))
	}
}

#[cfg(feature = "transport-hpke")]
impl<P: HandshakeProvider> ServerTrust<P> for LearnedTrust {
	type Provisioned = ();
	type Named = PresentedPath;

	/// The reply names the server, so the admission before the opening is `()`.
	fn admit_provisioned(&self, _admission: ServerAdmission<'_>) -> Result<(), HandshakeError> {
		Ok(())
	}

	/// Admit `named`, the path the reply presents: its signing certificate for
	/// signing under the server's purpose, as the trust validates the
	/// certificate or the path, then under the server policy of `admission`.
	///
	/// The certificate must be within its validity period.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the certificate is
	///   outside its validity period, the trust refused it or its path, the
	///   signing use or the server's purpose refused it, or the server policy
	///   refused it.
	fn admit_named(
		&self,
		named: PresentedPath,
		admission: ServerAdmission<'_>,
	) -> Result<AdmittedServer<P>, HandshakeError> {
		let (leaf, issuers) = named.into_parts();
		let evaluate = |leaf: &Certificate| LearnedVerdict::of(self, leaf, issuers);
		let signing = AdmittedSigning::admit(leaf, admission, evaluate)?;
		AdmittedServer::learned(signing, admission.policy)
	}
}

#[cfg(feature = "transport-hpke")]
use learned::LearnedVerdict;

/// The verdict of a [`LearnedTrust`], in a module of its own, so its field
/// stays private and [`LearnedVerdict::of`] alone builds one.
#[cfg(feature = "transport-hpke")]
mod learned {
	use super::*;

	/// What a [`LearnedTrust`] returns for the signing certificate an HPKE
	/// reply names: the proof that the trust admitted the certificate. The
	/// HPKE evaluation of the server policy takes it, so the policy reads a
	/// certificate that trust admitted.
	pub(super) struct LearnedVerdict(());

	impl LearnedVerdict {
		/// The verdict of `trust` on `leaf`, the signing certificate, beside
		/// `issuers`, the issuers above it that the reply presents.
		///
		/// # Errors
		///
		/// - The errors of [`LearnedTrust::validate`].
		pub(super) fn of(
			trust: &LearnedTrust,
			leaf: &Certificate,
			issuers: PresentedIssuers,
		) -> Result<Self, CertificateValidationError> {
			trust.validate(leaf, issuers)?;
			Ok(Self(()))
		}
	}
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-hpke")))]
mod tests {
	use super::*;
	use crate::crypto::hash::Sha3_256;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::crypto::x509::error::CertificateValidationError;
	use crate::crypto::x509::KeyPurposes;
	use crate::testing::TestResult;
	use crate::transport::handshake::tests::{create_test_certificate, pin_of, put_off_curve_key};

	/// A server admitted under the house provider.
	type HouseServer = AdmittedServer<DefaultCryptoProvider>;

	/// The house server purpose, which a trust admits a server under.
	const SERVER: ObjectIdentifier = KeyPurposes::HOUSE.server;

	/// A server purpose that an implementor names for its own servers, outside
	/// the house purposes.
	const OWN_PURPOSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");

	/// The admission under the house server purpose on the crate clock, with
	/// no server policy.
	const ADMISSION: ServerAdmission<'static> =
		ServerAdmission { purpose: SERVER, policy: None, clock: &ValidityClock::CRATE };

	/// The admission under the house server purpose and `policy`, on the
	/// crate clock.
	fn admission_under(policy: &ValidatorChain) -> ServerAdmission<'_> {
		ServerAdmission { purpose: SERVER, policy: Some(policy), clock: &ValidityClock::CRATE }
	}

	/// The server policy of `validators`, a non-empty set.
	fn policy_of(validators: impl IntoIterator<Item = Arc<dyn CertificateValidation>>) -> ValidatorChain {
		ValidatorChain::new(validators).expect("a non-empty set is a chain")
	}

	/// The server policy that pins `certificate` alone, by its fingerprint.
	fn pinning_policy(certificate: &Certificate) -> ValidatorChain {
		policy_of([pin_of(certificate)])
	}

	/// The path a reply presents when it carries `certificate` alone.
	fn named(certificate: &Certificate) -> PresentedPath {
		let path = PresentedPath::walk(certificate.to_owned(), Vec::new());
		path.expect("a lone certificate is a path")
	}

	/// The test certificate of the fixed key of `seed`.
	fn test_certificate(seed: u8) -> Certificate {
		create_test_certificate(seed).certificate
	}

	/// An empty validator set names no demand, so the caller names its
	/// fallback (CWE-1188).
	#[test]
	fn an_empty_validator_set_names_no_authentication() {
		assert!(PeerAuthentication::mutual([]).is_none());
	}

	/// A rule writes its name, and a mutual rule the count of the validators
	/// its chain runs, so a config that holds the rule writes it whole.
	#[test]
	fn a_rule_writes_its_name_and_the_count_of_its_validators() {
		let certificate = test_certificate(0xf0);
		let mutual = PeerAuthentication::Anonymous
			.and(pin_of(&certificate))
			.and(pin_of(&certificate));

		let anonymous = format!("{:?}", PeerAuthentication::Anonymous);
		let mutual = format!("{mutual:?}");
		let expected = ("Anonymous", "Mutual(ValidatorChain { validators: 2 })");
		assert_eq!((anonymous.as_str(), mutual.as_str()), expected);
	}

	/// The signing use decodes the key of a reply's signer before the trust's
	/// validator reads it, so a validator never reads an off-curve key.
	#[test]
	fn a_signer_off_the_curve_never_reaches_the_validator() {
		let mut named = test_certificate(0xf1);
		put_off_curve_key(&mut named);

		let validate = |_: &Certificate| Err::<(), _>(CertificateValidationError::CertificateDenied);
		let refused = AdmittedSigning::<DefaultCryptoProvider, ()>::admit(named, ADMISSION, validate);
		assert!(matches!(
			refused,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::SpkiError(_)
			))
		));
	}

	#[cfg(feature = "transport-cms")]
	mod provisioned {
		use super::*;
		use crate::crypto::exchange::{EcdheShare, KeyShare};
		use crate::crypto::sign::ecdsa::k256::Secp256k1;
		use crate::crypto::sign::ecdsa::Secp256k1SigningKey;
		use crate::crypto::sign::elliptic_curve::PublicKey;
		use crate::crypto::x509::error::CertificateValidationError::{
			CertificateNotPinned, CertificateRevoked, Expired,
		};
		use crate::crypto::x509::ext::pkix::AuthorityKeyIdentifier;
		use crate::crypto::x509::store::{CertificateTrustStore, StaticRevocationList};
		use crate::der::asn1::ObjectIdentifier;
		use crate::der::oid::AssociatedOid;
		use crate::oids::CURVE_SECP256K1;
		use crate::testing::fixtures::{
			AcceptsEveryCertificate, TestCertificate, TestCertificateChain, TestCmsServer, TestStore,
		};
		use crate::testing::TestKey;
		use crate::transport::handshake::tests::LaterRevocation;
		use crate::transport::handshake::CmsServerChain;
		use crate::x509::ext::pkix::{KeyUsage, KeyUsages};

		/// The key-agreement certificate a client of the house provider holds
		/// from the admission before the opening.
		type HouseKeyAgreement = ProvisionedKeyAgreement<DefaultCryptoProvider>;

		/// The pin of the key-agreement certificate of a test server, as a
		/// row of a table builds it.
		type PinOf = fn(&TestCmsServer) -> CmsServerIdentity;

		/// The key-agreement certificate `trust` admits under `admission` for a
		/// client of the house provider. [`ProvisionedTrust`] admits under any
		/// provider, so the call names the one it admits under.
		fn admit_provisioned(
			trust: &ProvisionedTrust,
			admission: ServerAdmission<'_>,
		) -> Result<HouseKeyAgreement, HandshakeError> {
			ServerTrust::<DefaultCryptoProvider>::admit_provisioned(trust, admission)
		}

		/// `certificate`, bare, as a client pins it.
		fn bare(certificate: &Certificate) -> CmsServerIdentity {
			CmsServerIdentity::Certificate(Arc::new(certificate.to_owned()))
		}

		/// The pinned chain of `certificates`, ordered root to leaf.
		fn chain_of(certificates: impl IntoIterator<Item = Certificate>) -> CmsServerIdentity {
			let chain = CmsServerChain::new(certificates.into_iter().collect::<Arc<[Certificate]>>());
			CmsServerIdentity::Chain(chain.expect("a chain of certificates holds a leaf"))
		}

		/// The key-agreement certificate of `server`, bare.
		fn bare_pin(server: &TestCmsServer) -> CmsServerIdentity {
			bare(&server.key_agreement)
		}

		/// The key-agreement certificate of `server` as the leaf of a chain
		/// under its authority.
		fn chain_pin(server: &TestCmsServer) -> CmsServerIdentity {
			chain_of([server.authority.to_owned(), server.key_agreement.to_owned()])
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

		/// A store that accepts every certificate under the authority of
		/// `server`, so the checks of the trust itself decide each admission.
		fn blind_store(server: &TestCmsServer) -> Arc<dyn CertificateTrust> {
			Arc::new(AcceptsEveryCertificate::under(server.authority.to_owned()))
		}

		/// A trust that pins `key_agreement`, bare, against the
		/// [`blind_store`] of `server`.
		fn blind_trust(server: &TestCmsServer, key_agreement: &Certificate) -> ProvisionedTrust {
			pinning(bare(key_agreement), blind_store(server))
		}

		/// A trust that pins `pinned` against the store of `server`, which
		/// revokes `revoked` once the trust is built.
		fn revoked_after_build(
			server: &TestCmsServer,
			revoked: &Certificate,
			pinned: CmsServerIdentity,
		) -> ProvisionedTrust {
			let revocation = LaterRevocation::of(revoked.to_owned());
			let trust = pinning(pinned, Arc::new(server.store_with(revocation.clone())));

			revocation.revoke();
			trust
		}

		/// The server `trust` admits under `purpose` from a reply that names
		/// `signing`, once its opening sealed to the pinned certificate.
		fn admit_reply(
			trust: &ProvisionedTrust,
			signing: &Certificate,
			purpose: ObjectIdentifier,
		) -> Result<HouseServer, HandshakeError> {
			let admission = ServerAdmission { purpose, policy: None, clock: &ValidityClock::CRATE };
			let provisioned = admit_provisioned(trust, admission)?;
			let (key_agreement, _) = provisioned.into_parts();
			let named = CmsNamedServer { signing: named(signing), key_agreement };
			trust.admit_named(named, admission)
		}

		/// The server a client of `server` admits from its honest reply.
		fn admitted(server: &TestCmsServer) -> HouseServer {
			let admitted = admit_reply(&server.trust(), &server.signing, SERVER);
			admitted.expect("the store admits both test certificates as one server")
		}

		/// The house share of the key of `key`.
		fn share_of(key: &Secp256k1SigningKey) -> EcdheShare<Secp256k1> {
			EcdheShare::from(PublicKey::from(key.verifying_key()))
		}

		/// The signing certificate of `server`, marked for key agreement, so
		/// it holds the signing key itself.
		fn signing_as_key_agreement(server: &TestCmsServer) -> Certificate {
			TestCertificate::with_key_usage(server.signing.to_owned(), KeyUsage(KeyUsages::KeyAgreement.into()))
		}

		/// The key-agreement certificate of `server` with the compressed SEC 1
		/// point of `key` in place of its own key.
		fn holding_key_of(server: &TestCmsServer, key: &Secp256k1SigningKey) -> Certificate {
			let point = share_of(key).to_octets();
			TestCertificate::with_curve_point(server.key_agreement.to_owned(), CURVE_SECP256K1, &point)
		}

		/// A key-agreement leaf of the subject of the fixed chain's leaf,
		/// which `issuer_key` issues as `issuer_cn`.
		fn key_agreement_leaf(issuer_key: &Secp256k1SigningKey, issuer_cn: &str) -> Certificate {
			let key = TestKey::fixed(0x44);
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());

			let issued = TestCertificate::issued(issuer_key, issuer_cn, &key, "Leaf", 4, usage);
			issued.expect("the issuer issues the key-agreement leaf")
		}

		/// The fixed test chain, whose leaf signs under the intermediate.
		fn fixed_chain() -> TestCertificateChain {
			TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues")
		}

		/// The pinned chain from the root of `chain` through its intermediate
		/// to a key-agreement leaf that the intermediate issued.
		fn through_intermediate(chain: &TestCertificateChain) -> CmsServerIdentity {
			let key_agreement = key_agreement_leaf(&chain.intermediate_key, "Intermediate");
			chain_of([chain.root.to_owned(), chain.intermediate.to_owned(), key_agreement])
		}

		/// The pinned chain from the intermediate of `chain` to a key-agreement
		/// leaf that the intermediate issued.
		fn from_intermediate(chain: &TestCertificateChain) -> CmsServerIdentity {
			let key_agreement = key_agreement_leaf(&chain.intermediate_key, "Intermediate");
			chain_of([chain.intermediate.to_owned(), key_agreement])
		}

		/// The signing certificate of `server`'s subject and key that the
		/// authority of `other` issues.
		fn issued_by_other(server: &TestCmsServer, other: &TestCmsServer) -> Certificate {
			let subject = server.signing.tbs_certificate.subject.to_owned();
			other.issue_signing(&server.signing_key, subject, 7)
		}

		/// The trust admits the pinned key-agreement certificate under its
		/// authority before the opening, as the certificate it pins.
		#[test]
		fn a_pinned_key_agreement_certificate_under_its_authority_is_admitted() -> TestResult {
			let server = fresh_server();
			let admitted = admit_provisioned(&server.trust(), ADMISSION)?;
			assert_eq!(admitted.pinned.certificate.as_ref(), &server.key_agreement);
			Ok(())
		}

		// The reply's signing certificate under the authority of the pinned
		// certificate pairs with it, and the client reads the reply against it.
		crate::tb_cases! {
			fn a_signing_certificate_the_reply_names_is_paired(pinned: PinOf) -> TestResult {
				let server = fresh_server();
				let trust = pinning(pinned(&server), Arc::new(server.store()));

				let paired = admit_reply(&trust, &server.signing, SERVER)?;
				assert_eq!(paired.signing().certificate().as_ref(), &server.signing);
				Ok(())
			}
			cases {
				bare => bare_pin,
				/// A pinned chain and the signing certificate its root issued
				/// name one anchor, the root.
				chain => chain_pin,
			}
		}

		/// The admitted pair keeps the key-agreement certificate the opening
		/// sealed to, so the session holds it for a rekey.
		#[cfg(mux_rekey)]
		#[test]
		fn a_paired_server_keeps_its_key_agreement_certificate() {
			let server = fresh_server();
			let peer = admitted(&server).into_peer();
			let key_agreement = peer.as_ref().and_then(SessionPeer::key_agreement);
			assert_eq!(key_agreement, Some(&server.key_agreement));
		}

		/// The admitted pair records its signing certificate as the peer
		/// certificate of the session, the one a client reports for its server.
		#[test]
		fn a_paired_server_records_its_signing_certificate() {
			let server = fresh_server();
			let peer = admitted(&server).into_peer();
			let certificate = peer.as_ref().map(|peer| peer.certificate().as_ref());
			assert_eq!(certificate, Some(&server.signing));
		}

		// The trust admits its pin against the store at its construction, so
		// it refuses a pin whose path the store does not validate
		// (RFC 5280 §6.1).
		crate::tb_cases! {
			fn a_pin_the_store_does_not_validate_is_refused((pin, store): (CmsServerIdentity, CertificateTrustStore)) {
				let refused = ProvisionedTrust::new(pin, Arc::new(store));
				assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(_))));
			}
			cases {
				/// The store holds another certificate in place of the
				/// authority of the pinned certificate.
				store_lacks_anchor => (bare_pin(&fresh_server()), TestStore::holding([test_certificate(0xf2)])),
				/// The store holds the root of the fixed chain, which did not
				/// issue the leaf of the pinned chain.
				leaf_not_issued_by_root => (
					chain_of([fixed_chain().root, fresh_server().key_agreement]),
					TestStore::holding([fixed_chain().root]),
				),
				/// The store holds another certificate in place of the root of
				/// the pinned chain.
				chain_root_not_held => (
					through_intermediate(&fixed_chain()),
					TestStore::holding([test_certificate(0xf3)]),
				),
			}
		}

		/// A store may accept a bare certificate and leave its validity period
		/// unread, so the trust refuses an expired one itself.
		#[test]
		fn a_pinned_certificate_past_its_validity_is_refused() {
			let server = fresh_server();
			let refused = ProvisionedTrust::new(bare(&TestCertificate::expired()), blind_store(&server));
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust holds the reply's signing certificate to its validity
		/// period, as it holds the pinned one.
		#[test]
		fn a_named_signing_certificate_past_its_validity_is_refused() {
			let server = fresh_server();
			let trust = blind_trust(&server, &server.key_agreement);

			let refused = admit_reply(&trust, &TestCertificate::expired(), SERVER);
			assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust parses the key of the reply's certificate for signing, so
		/// it refuses a signing certificate whose key is off the curve at the
		/// reply.
		#[test]
		fn a_named_signing_certificate_whose_key_is_off_the_curve_is_refused() {
			let server = fresh_server();
			let mut signing = server.signing.to_owned();
			put_off_curve_key(&mut signing);

			let trust = blind_trust(&server, &server.key_agreement);
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
			let trust = blind_trust(&server, &server.key_agreement);

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
			let trust = blind_trust(&server, &key_agreement);

			let refused = admit_provisioned(&trust, ADMISSION);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::KeyAgreement)
				))
			));
		}

		/// The two certificates of a pair name one subject, so the trust
		/// refuses a signing certificate of another subject.
		#[test]
		fn a_named_signing_certificate_of_another_subject_is_refused() {
			let server = fresh_server();
			let other = TestCmsServer::generate("another server");
			let trust = blind_trust(&server, &server.key_agreement);

			let refused = admit_reply(&trust, &other.signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::SubjectMismatch)));
		}

		// Two certificates of one subject that two authorities issued name two
		// trust anchors, so the trust refuses the pair, whether it pins the
		// key-agreement certificate bare or as a chain under its root.
		crate::tb_cases! {
			fn a_signing_certificate_of_another_anchor_is_refused(pinned: PinOf) {
				let server = fresh_server();
				let other = TestCmsServer::generate("another server");
				let store = TestStore::holding([server.authority.to_owned(), other.authority.to_owned()]);
				let trust = pinning(pinned(&server), Arc::new(store));

				let refused = admit_reply(&trust, &issued_by_other(&server, &other), SERVER);
				assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
			}
			cases {
				bare => bare_pin,
				chain => chain_pin,
			}
		}

		// One key in both certificates of a pair would serve two purposes, so
		// the trust refuses the pair, in each form whose agreement collapses
		// into the signing key.
		crate::tb_cases! {
			fn a_pair_of_one_key_is_refused(key_agreement: fn(&TestCmsServer) -> Certificate) {
				let server = fresh_server();
				let trust = blind_trust(&server, &key_agreement(&server));

				let refused = admit_reply(&trust, &server.signing, SERVER);
				assert!(matches!(refused, Err(HandshakeError::KeyReuse)));
			}
			cases {
				same_key => signing_as_key_agreement,
				/// One point in its compressed SEC 1 encoding is the key of the
				/// signing certificate.
				compressed_twin => |server| holding_key_of(server, &server.signing_key),
				/// A key and its negation agree alike (SEC 1 v2.0 §3.3.1).
				negation => |server| holding_key_of(server, &TestKey::negation_of(&server.signing_key)),
			}
		}

		/// A self-issued certificate is its own anchor, so two of one subject
		/// that the store trusts each name two anchors.
		#[test]
		fn self_issued_certificates_of_one_subject_are_refused() -> TestResult {
			let signing_key = TestKey::fixed(0x45);
			let signing = TestCertificate::authority(&signing_key, "self-issued server")?;
			let signing = TestCertificate::without_extension(signing, AuthorityKeyIdentifier::OID);
			let signing = TestCertificate::with_key_usage(signing, KeyUsage(KeyUsages::DigitalSignature.into()));
			let key_agreement_key = TestKey::fixed(0x46);
			let key_agreement = TestCertificate::authority(&key_agreement_key, "self-issued server")?;
			let key_agreement = TestCertificate::without_extension(key_agreement, AuthorityKeyIdentifier::OID);
			let agreement_usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let key_agreement = TestCertificate::with_key_usage(key_agreement, agreement_usage);

			let store = TestStore::holding([signing.to_owned(), key_agreement.to_owned()]);
			let trust = ProvisionedTrust::new(bare(&key_agreement), Arc::new(store))?;

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(refused, Err(HandshakeError::AnchorMismatch)));
			Ok(())
		}

		// The anchor is the one the store's path validation ends at
		// (RFC 5280 §6.1.1(d)), so a pin under the root of the fixed chain
		// pairs with the signing certificate under its intermediate.
		crate::tb_cases! {
			fn chains_under_one_root_are_paired(pinned: fn(&TestCertificateChain) -> CmsServerIdentity) -> TestResult {
				let chain = fixed_chain();
				let store = TestStore::holding([chain.root.to_owned(), chain.intermediate.to_owned()]);
				let trust = ProvisionedTrust::new(pinned(&chain), Arc::new(store))?;

				let paired = admit_reply(&trust, &chain.leaf, SERVER)?;
				assert_eq!(paired.signing().certificate().as_ref(), &chain.leaf);
				Ok(())
			}
			cases {
				/// A key-agreement certificate the root issued pairs with a
				/// signing certificate under the intermediate.
				root_issued_key_agreement => |chain| bare(&key_agreement_leaf(&chain.root_key, "Root")),
				/// A pinned chain through the intermediate ends at the root of
				/// the signing certificate.
				chain_through_intermediate => through_intermediate,
				/// A pinned chain that starts at an intermediate the store
				/// holds ends at the store's root, as the walk of the signing
				/// certificate under that intermediate does.
				chain_from_held_intermediate => from_intermediate,
			}
		}

		/// A chain holds its leaf, so the trust refuses an empty chain.
		#[test]
		fn an_empty_provisioned_chain_is_refused() {
			let refused = CmsServerChain::new(Vec::new());
			assert!(matches!(refused, Err(HandshakeError::MissingServerCertificate)));
		}

		/// A store that revokes the signing certificate after the test builds
		/// the trust refuses it at the next reply.
		#[test]
		fn a_signing_certificate_revoked_after_the_trust_is_refused() {
			let server = fresh_server();
			let trust = revoked_after_build(&server, &server.signing, bare_pin(&server));

			let refused = admit_reply(&trust, &server.signing, SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
		}

		// A store that revokes the pinned key-agreement certificate after the
		// test builds the trust refuses it at the next opening, whether the
		// trust pins it bare or as the leaf of a chain.
		crate::tb_cases! {
			fn a_pin_revoked_after_the_trust_is_refused(pinned: PinOf) {
				let server = fresh_server();
				let trust = revoked_after_build(&server, &server.key_agreement, pinned(&server));

				let refused = admit_provisioned(&trust, ADMISSION);
				assert!(matches!(refused, Err(HandshakeError::CertificateValidationError(CertificateRevoked))));
			}
			cases {
				bare => bare_pin,
				chain => chain_pin,
			}
		}

		/// A control of the revocation tests above: the revocation of the
		/// signing certificate leaves the pinned key-agreement certificate
		/// admitted, so each test reads the revocation of its own certificate.
		#[test]
		fn a_later_revocation_admits_the_other_certificate() -> TestResult {
			let server = fresh_server();
			let trust = revoked_after_build(&server, &server.signing, bare_pin(&server));

			let admitted = admit_provisioned(&trust, ADMISSION)?;
			assert_eq!(admitted.pinned.certificate.as_ref(), &server.key_agreement);
			Ok(())
		}

		/// The trust admits its pinned certificate against the store at its
		/// construction, so it refuses a revoked one there.
		#[test]
		fn a_revoked_pinned_certificate_is_refused() -> TestResult {
			let server = fresh_server();
			let revoked = StaticRevocationList::<Sha3_256>::default().with_certificate(&server.key_agreement)?;
			let store = server.store_with(revoked);

			let refused = ProvisionedTrust::new(bare(&server.key_agreement), Arc::new(store));
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateRevoked))
			));
			Ok(())
		}

		/// The trust refuses a signing certificate of the client's purpose
		/// alone as the server the reply names (RFC 5280 §4.2.1.12).
		#[test]
		fn a_named_signing_certificate_of_the_client_purpose_is_refused() {
			let server = fresh_server();
			let signing = TestCertificate::with_key_purposes(server.signing.to_owned(), [KeyPurposes::HOUSE.client]);
			let trust = blind_trust(&server, &server.key_agreement);

			let refused = admit_reply(&trust, &signing, SERVER);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// The trust refuses a pinned certificate of the client's purpose alone
		/// at the admission before the opening.
		#[test]
		fn a_pinned_certificate_of_the_client_purpose_is_refused() {
			let server = fresh_server();
			let key_agreement = server.key_agreement.to_owned();
			let key_agreement = TestCertificate::with_key_purposes(key_agreement, [KeyPurposes::HOUSE.client]);
			let trust = blind_trust(&server, &key_agreement);

			let refused = admit_provisioned(&trust, ADMISSION);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// The trust admits a pair that names an implementor's own server
		/// purpose under that purpose.
		#[test]
		fn a_pair_is_admitted_under_its_own_purpose() -> TestResult {
			let server = fresh_server();
			let signing = TestCertificate::with_key_purposes(server.signing.to_owned(), [OWN_PURPOSE]);
			let key_agreement = TestCertificate::with_key_purposes(server.key_agreement.to_owned(), [OWN_PURPOSE]);
			let trust = blind_trust(&server, &key_agreement);

			let admitted = admit_reply(&trust, &signing, OWN_PURPOSE)?;
			assert_eq!(admitted.signing().certificate().as_ref(), &signing);
			Ok(())
		}

		// The server policy reads the pinned key-agreement certificate before
		// the opening, so a pin of that certificate admits it, whether the
		// trust pins it bare or as the leaf of a chain under its authority.
		crate::tb_cases! {
			fn a_policy_that_pins_the_key_agreement_certificate_admits_it(pinned: PinOf) -> TestResult {
				let server = fresh_server();
				let trust = pinning(pinned(&server), Arc::new(server.store()));
				let policy = pinning_policy(&server.key_agreement);

				let admitted = admit_provisioned(&trust, admission_under(&policy))?;
				assert_eq!(admitted.pinned.certificate.as_ref(), &server.key_agreement);
				Ok(())
			}
			cases {
				bare => bare_pin,
				chain => chain_pin,
			}
		}

		/// The server policy reads the key-agreement certificate, so a policy
		/// that pins the signing certificate refuses the server before the
		/// opening seals anything to it.
		#[test]
		fn a_policy_that_refuses_the_key_agreement_certificate_refuses_it_before_the_opening() {
			let server = fresh_server();
			let policy = pinning_policy(&server.signing);
			let admission = admission_under(&policy);

			let refused = admit_provisioned(&server.trust(), admission);
			assert!(matches!(
				refused,
				Err(HandshakeError::CertificateValidationError(CertificateNotPinned))
			));
		}

		// The admitted server refuses a server ephemeral of either of its
		// static keys, in each form whose agreement collapses into the key.
		crate::tb_cases! {
			fn a_server_ephemeral_of_a_static_key_is_refused(share: fn(&TestCmsServer) -> EcdheShare<Secp256k1>) {
				let server = fresh_server();

				let refused = admitted(&server).server_ephemeral(share(&server));
				assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
			}
			cases {
				signing_key => |server| share_of(&server.signing_key),
				key_agreement_key => |server| share_of(&server.key_agreement_key),
				/// The negated key-agreement key agrees as the key does.
				negated_key_agreement_key => |server| share_of(&TestKey::negation_of(&server.key_agreement_key)),
			}
		}

		/// The admitted server admits a server ephemeral distinct from both of
		/// its keys.
		#[test]
		fn a_server_ephemeral_of_neither_key_is_admitted() -> TestResult {
			let server = fresh_server();
			let ephemeral = TestKey::fixed(0x47);

			admitted(&server).server_ephemeral(share_of(&ephemeral))?;
			Ok(())
		}
	}

	#[cfg(feature = "transport-hpke")]
	mod learned {
		use super::*;
		use crate::crypto::x509::error::CertificateValidationError::{CertificateNotPinned, Expired};
		use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator, RuntimeCertificatePinning};
		use crate::testing::fixtures::TestCertificate;
		use crate::x509::ext::pkix::{KeyUsage, KeyUsages};

		/// A trust that pins `certificate` by its fingerprint alone.
		fn pinned(certificate: &Certificate) -> LearnedTrust {
			let pinning = RuntimeCertificatePinning::<Sha3_256>::from_certificates([certificate.to_owned()]);
			let pinning = pinning.expect("the test certificate has a fingerprint");
			LearnedTrust::new(pinning)
		}

		/// The server that a trust that pins `certificate` admits under
		/// `admission` from a reply that names `certificate`.
		fn learned_admission(
			certificate: &Certificate,
			admission: ServerAdmission<'_>,
		) -> Result<HouseServer, HandshakeError> {
			pinned(certificate).admit_named(named(certificate), admission)
		}

		/// The trust admits a certificate its validator accepts, as the server
		/// the reply names.
		#[test]
		fn a_learned_certificate_the_validator_accepts_is_admitted() -> TestResult {
			let server = test_certificate(0xf4);
			let admitted = learned_admission(&server, ADMISSION)?;
			let certificate = admitted.signing().certificate();
			assert_eq!(certificate.as_ref(), &server);
			Ok(())
		}

		/// A direct-trust validator with no anchor refuses every certificate.
		#[test]
		fn a_learned_certificate_the_validator_refuses_is_refused() {
			let trust = LearnedTrust::new(DirectTrustValidator::default());
			let unknown = test_certificate(0xf5);
			let refusal: Result<HouseServer, _> = trust.admit_named(named(&unknown), ADMISSION);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
		}

		/// A validator that pins a certificate reads no validity period, so the
		/// trust refuses an expired certificate itself.
		#[test]
		fn a_learned_certificate_past_its_validity_is_refused() {
			let refusal = learned_admission(&TestCertificate::expired(), ADMISSION);
			assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(Expired))));
		}

		/// The trust admits the certificate the reply names for signing, so it
		/// refuses a certificate whose key is off the curve at admission.
		#[test]
		fn a_learned_certificate_whose_key_is_off_the_curve_is_refused() {
			let mut server = test_certificate(0xf6);
			put_off_curve_key(&mut server);

			let refusal = learned_admission(&server, ADMISSION);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::SpkiError(_)
				))
			));
		}

		/// The reply's certificate signs, so the trust refuses one whose
		/// `keyUsage` asserts `keyAgreement` alone.
		#[test]
		fn a_learned_certificate_without_digital_signature_is_refused() {
			let usage = KeyUsage(KeyUsages::KeyAgreement.into());
			let server = TestCertificate::with_key_usage(test_certificate(0xf7), usage);

			let refusal = learned_admission(&server, ADMISSION);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::MissingKeyUsage(KeyUsages::DigitalSignature)
				))
			));
		}

		/// The trust refuses a certificate that names the client's purpose
		/// alone as the server the reply names (RFC 5280 §4.2.1.12).
		#[test]
		fn a_learned_client_certificate_is_refused_as_the_server() {
			let server = TestCertificate::with_key_purposes(test_certificate(0xf8), [KeyPurposes::HOUSE.client]);
			let refusal = learned_admission(&server, ADMISSION);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(
					CertificateValidationError::ExcludedKeyPurpose
				))
			));
		}

		/// The trust admits a certificate that names an implementor's own
		/// server purpose under that purpose.
		#[test]
		fn a_learned_certificate_is_admitted_under_its_own_purpose() -> TestResult {
			let server = TestCertificate::with_key_purposes(test_certificate(0xf9), [OWN_PURPOSE]);
			let admission = ServerAdmission { purpose: OWN_PURPOSE, policy: None, clock: &ValidityClock::CRATE };

			let admitted = learned_admission(&server, admission)?;
			assert_eq!(admitted.signing().certificate().as_ref(), &server);
			Ok(())
		}

		/// The server policy reads the certificate the reply names, so a pin
		/// of that certificate admits the server.
		#[test]
		fn a_policy_that_pins_the_learned_certificate_admits_it() -> TestResult {
			let server = test_certificate(0xfa);
			let policy = pinning_policy(&server);
			let admission = admission_under(&policy);

			let admitted = learned_admission(&server, admission)?;
			assert_eq!(admitted.signing().certificate().as_ref(), &server);
			Ok(())
		}

		/// A server policy that pins another certificate refuses the server
		/// the reply names, though its trust admits it.
		#[test]
		fn a_policy_that_pins_another_certificate_refuses_the_learned_one() {
			let server = test_certificate(0xfb);
			let policy = pinning_policy(&test_certificate(0xfc));
			let admission = admission_under(&policy);

			let refusal = learned_admission(&server, admission);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(CertificateNotPinned))
			));
		}

		/// Every validator of a server policy runs, so a pin of another
		/// certificate after an expiry check the server passes refuses it.
		#[test]
		fn the_second_validator_of_a_policy_refuses_the_learned_certificate() {
			let server = test_certificate(0xfd);
			let expiry: Arc<dyn CertificateValidation> = Arc::new(ExpiryValidator::default());
			let policy = policy_of([expiry, pin_of(&test_certificate(0xfe))]);
			let admission = admission_under(&policy);

			let refusal = learned_admission(&server, admission);
			assert!(matches!(
				refusal,
				Err(HandshakeError::CertificateValidationError(CertificateNotPinned))
			));
		}
	}
}

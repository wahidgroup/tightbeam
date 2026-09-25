//! What a handshake server demands of its client, and what it may record.
//!
//! [`PeerAuthentication`] is the one decision both handshake servers consult,
//! and [`AdmittedPeer`] is the only value that carries a certificate a
//! validator chain accepted. A session records a peer only through
//! [`AdmittedPeer::proven`], so every session identity is a certificate a
//! validator chain accepted.

#[cfg(not(feature = "std"))]
use alloc::{sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::crypto::x509::policy::CertificateValidation;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::transport::handshake::error::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::x509::Certificate;

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

/// The validators a mutual server runs, which always hold at least one.
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
	/// offered.
	///
	/// Both handshake servers call this, and it is the one constructor of
	/// [`AdmittedPeer`].
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingClientCertificate`] -- mutual authentication
	///   is configured and the client offered no certificate.
	/// - [`HandshakeError::CertificateValidationError`] -- a validator refused
	///   the offered certificate.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	pub(crate) fn admit(&self, offered: Option<Certificate>) -> Result<AdmittedPeer, HandshakeError> {
		let admission = match (self, offered) {
			(Self::Anonymous, None) => Admission::Unidentified,
			#[cfg(feature = "transport-cms")]
			(Self::Anonymous, Some(certificate)) => Admission::Offered(Arc::new(certificate)),
			#[cfg(not(feature = "transport-cms"))]
			(Self::Anonymous, Some(_)) => Admission::Unidentified,
			(Self::Mutual(_), None) => return Err(HandshakeError::MissingClientCertificate),
			(Self::Mutual(chain), Some(certificate)) => {
				chain.evaluate(&certificate)?;
				Admission::Proven(Arc::new(certificate))
			}
		};

		Ok(AdmittedPeer(admission))
	}
}

/// The outcome of [`PeerAuthentication::admit`].
///
/// The variant stays private, so a proven peer exists only where `admit`
/// ran every validator.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub(crate) struct AdmittedPeer(Admission);

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
enum Admission {
	/// Server authentication only, with no certificate the handshake reads.
	Unidentified,
	/// Server authentication only. The certificate can verify a signature the
	/// client made, but it names nobody. Only the CMS Finished carries a
	/// signature from an anonymous client, so only CMS keeps the certificate.
	#[cfg(feature = "transport-cms")]
	Offered(Arc<Certificate>),
	/// Every configured validator accepted the certificate.
	Proven(Arc<Certificate>),
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl AdmittedPeer {
	/// The certificate whose key MUST verify the client's signature, present
	/// whenever the client offered one.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn verifier(&self) -> Option<&Certificate> {
		match &self.0 {
			Admission::Unidentified => None,
			Admission::Offered(certificate) | Admission::Proven(certificate) => Some(certificate),
		}
	}

	/// The certificate the session records as its peer, present only under
	/// mutual authentication after every validator accepted it.
	pub(crate) fn proven(&self) -> Option<&Arc<Certificate>> {
		match &self.0 {
			Admission::Proven(certificate) => Some(certificate),
			Admission::Unidentified => None,
			#[cfg(feature = "transport-cms")]
			Admission::Offered(_) => None,
		}
	}
}

#[cfg(all(test, any(feature = "transport-cms", feature = "transport-ecies")))]
mod tests {
	use super::*;
	use crate::crypto::x509::policy::{DirectTrustValidator, ExpiryValidator};
	use crate::transport::handshake::tests::{create_test_certificate, mutual_with};

	fn offered() -> Certificate {
		create_test_certificate().certificate
	}

	#[test]
	fn an_empty_validator_set_demands_nothing() {
		let authentication = PeerAuthentication::mutual([]);
		assert!(matches!(authentication, PeerAuthentication::Anonymous));
		assert!(!authentication.requires_certificate());
	}

	#[test]
	fn an_anonymous_server_records_no_offered_certificate() -> Result<(), HandshakeError> {
		let admitted = PeerAuthentication::Anonymous.admit(Some(offered()))?;
		assert!(admitted.proven().is_none());
		Ok(())
	}

	#[cfg(feature = "transport-cms")]
	#[test]
	fn an_anonymous_server_verifies_with_the_offered_certificate() -> Result<(), HandshakeError> {
		let admitted = PeerAuthentication::Anonymous.admit(Some(offered()))?;
		assert!(admitted.verifier().is_some());
		Ok(())
	}

	#[test]
	fn a_mutual_server_refuses_a_missing_certificate() {
		let refusal = mutual_with(ExpiryValidator).admit(None);
		assert!(matches!(refusal, Err(HandshakeError::MissingClientCertificate)));
	}

	#[test]
	fn a_mutual_server_refuses_a_certificate_any_validator_refuses() {
		// The expiry check accepts, and a direct-trust check with no anchor
		// refuses every certificate.
		let validators: [Arc<dyn CertificateValidation>; 2] =
			[Arc::new(ExpiryValidator), Arc::new(DirectTrustValidator::default())];

		let authentication = PeerAuthentication::mutual(validators);
		let refusal = authentication.admit(Some(offered()));
		assert!(matches!(refusal, Err(HandshakeError::CertificateValidationError(_))));
	}

	#[test]
	fn a_mutual_server_records_an_accepted_certificate() -> Result<(), HandshakeError> {
		let admitted = mutual_with(ExpiryValidator).admit(Some(offered()))?;
		assert!(admitted.proven().is_some());
		Ok(())
	}
}

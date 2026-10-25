//! The record of the peer a session admitted, which a rekey renews against
//! and each session context of a gate shares.

use crate::crypto::x509::CanonicalKey;
use crate::transport::handshake::Arc;
use crate::x509::Certificate;

#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::error::CertificateValidationError;
#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::{KeyCurves, KeyIdentity};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::{PeerCertificate, Signing};
#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
use crate::spki::Error as SpkiError;
#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::HandshakeError;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::HandshakeProvider;

/// The peer a session recorded: the certificate the handshake validated, the
/// canonical form of its key, and for a CMS server the key-agreement
/// certificate the admission paired with it.
///
/// Its fields are private to this leaf module, so two rules hold:
///
/// - One derivation builds the canonical form of the key from the certificate beside it.
/// - A key-agreement certificate joins only where the handshake pairs it.
///
/// Its production constructors are visible to the handshake alone, whose
/// admissions build every peer a session records.
#[derive(Debug)]
pub(crate) struct SessionPeer {
	/// The certificate the handshake validated: the client's under mutual
	/// authentication, or the server's signing certificate.
	certificate: Arc<Certificate>,
	/// The canonical form of the key of the certificate, derived once where
	/// the handshake admits the peer, which a per-peer decision keys on.
	key: CanonicalKey,
	/// The key-agreement certificate of a CMS server, whose key a rekey's
	/// server ephemeral must differ from, as the handshake's did.
	#[cfg(mux_rekey)]
	key_agreement: Option<Arc<Certificate>>,
}

/// A peer of `certificate`, for a test that builds a session from a
/// certificate it holds.
#[cfg(test)]
impl TryFrom<Arc<Certificate>> for SessionPeer {
	type Error = HandshakeError;

	fn try_from(certificate: Arc<Certificate>) -> Result<Self, Self::Error> {
		Self::recorded(certificate)
	}
}

impl SessionPeer {
	/// The peer of `certificate`, a certificate its signing use decoded: a
	/// client, an HPKE server, or a CMS server's signing certificate, which a
	/// build with the mux rekey pairs with its key-agreement certificate.
	///
	/// - The signing use decoded the key with the parse of `P`, which the
	///   [`Signing`] contract requires to refuse a point off the curve its key
	///   names.
	/// - It fails when the key reads as no point under [`KeyCurves::HOUSE`], so
	///   the elliptic-curve key of every session peer is a point of its curve.
	/// - It fails when the DER encoder refuses the key, so every peer holds the canonical form of its key.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::recorded`].
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	pub(super) fn admitted<P: HandshakeProvider>(
		certificate: &PeerCertificate<Signing<P>>,
	) -> Result<Self, HandshakeError> {
		Self::recorded(Arc::clone(certificate.certificate()))
	}

	/// The one derivation of the canonical form of a session peer's key from
	/// `certificate`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::CertificateValidationError`] -- the key reads as no
	///   point under [`KeyCurves::HOUSE`]: an `id-ecPublicKey` key that reads
	///   as its bits, or a key under `id-ecDH` or `id-ecMQV`.
	/// - [`HandshakeError::DerError`] -- the DER encoder refuses the key.
	#[cfg(any(test, feature = "transport-cms", feature = "transport-hpke"))]
	fn recorded(certificate: Arc<Certificate>) -> Result<Self, HandshakeError> {
		let spki = &certificate.tbs_certificate.subject_public_key_info;
		let identity = KeyIdentity::of(spki, KeyCurves::HOUSE);
		if identity.names_no_point() {
			return Err(CertificateValidationError::SpkiError(SpkiError::KeyMalformed).into());
		}

		let key = identity.to_canonical()?;
		Ok(Self {
			certificate,
			key,
			#[cfg(mux_rekey)]
			key_agreement: None,
		})
	}

	/// This peer, the signing certificate of a CMS server, beside
	/// `key_agreement`, the key-agreement certificate the admission paired
	/// with it. It keeps the certificate and the key of this peer.
	#[cfg(all(mux_rekey, any(feature = "transport-cms", test)))]
	pub(super) fn with_key_agreement(self, key_agreement: Arc<Certificate>) -> Self {
		Self { key_agreement: Some(key_agreement), ..self }
	}

	/// A CMS server of `certificate`, its signing certificate, beside
	/// `key_agreement`, the key-agreement certificate paired with it, for a
	/// test that builds a session.
	///
	/// # Errors
	///
	/// - [`HandshakeError`] -- the errors of [`Self::recorded`].
	#[cfg(all(test, mux_rekey))]
	pub(crate) fn paired(
		certificate: Arc<Certificate>,
		key_agreement: Arc<Certificate>,
	) -> Result<Self, HandshakeError> {
		let peer = Self::try_from(certificate)?;
		Ok(peer.with_key_agreement(key_agreement))
	}

	/// The certificate the handshake validated.
	pub(crate) fn certificate(&self) -> &Arc<Certificate> {
		&self.certificate
	}

	/// The canonical form of the key of the certificate the handshake
	/// validated.
	pub(crate) fn key(&self) -> &CanonicalKey {
		&self.key
	}

	/// The key-agreement certificate the admission paired with a CMS server,
	/// or `None` when it paired none.
	#[cfg(mux_rekey)]
	pub(crate) fn key_agreement(&self) -> Option<&Certificate> {
		self.key_agreement.as_deref()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::{TestCertificate, TestKey};

	/// A peer whose secp256k1 key is off its curve reads as no point under
	/// the house set, so the handshake refuses it and a peer list can name
	/// the key of every session.
	#[test]
	fn a_peer_whose_key_is_off_its_curve_is_refused() {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let off_curve = TestCertificate::with_off_curve_key(certificate);

		let refused = SessionPeer::try_from(Arc::new(off_curve));
		assert!(matches!(
			refused,
			Err(HandshakeError::CertificateValidationError(
				CertificateValidationError::SpkiError(SpkiError::KeyMalformed)
			))
		));
	}
}

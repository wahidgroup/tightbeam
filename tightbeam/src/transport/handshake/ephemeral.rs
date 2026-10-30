//! A peer's agreement ephemeral as an agreement takes it, and the static keys
//! of that peer it must differ from.
//!
//! ECDH keeps the x-coordinate of its product alone (SEC 1 v2.0 §3.3.1), so an
//! ephemeral that shares the x-coordinate of a static key of its sender, the
//! key itself or its negation, collapses the agreement into a static one. The
//! session then loses the forward secrecy of two ephemerals. This module is
//! the one home of that rule, and three types carry it:
//!
//! - [`PeerStatics`] holds a peer's static keys as points of the handshake curve, parsed once at admission.
//! - [`DistinctPoint`] is an ephemeral that a [`PeerStatics`] checked against
//!   every key it holds. The client's agreement and both agreements of a
//!   rekey take only this proof.
//! - [`OpenedPoint`] is the client's ephemeral `R` as a server reads it before
//!   the client's identity opens. The server agrees with it at the reply, and
//!   [`PeerStatics::admit_client`] checks that same value once the closing
//!   names the identity.
//!
//! # Sources
//!
//! - SEC 1 v2.0 (May 2009), §2.3.3 and §3.3.1, the point forms and the
//!   x-coordinate an ECDH keeps: <https://www.secg.org/sec1-v2.pdf>
//! - RFC 5480 (March 2009), §2.2, the two point forms of an `id-ecPublicKey`
//!   key: <https://datatracker.ietf.org/doc/html/rfc5480#section-2.2>

use crate::crypto::sign::elliptic_curve::point::AffineCoordinates;
use crate::crypto::sign::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint};
use crate::crypto::sign::elliptic_curve::{CurveArithmetic, Error as EllipticCurveError, PublicKey};
use crate::crypto::x509::Sec1Point;
use crate::der::referenced::OwnedToRef;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::HandshakeCurve;
use crate::x509::Certificate;

/// A peer's ephemeral as a point of the curve other than the identity.
///
/// [`Self::parse`] is the one parse of every ephemeral an agreement takes. The
/// type stays private to this module, so a point reaches an agreement only
/// inside a [`DistinctPoint`] or an [`OpenedPoint`].
struct PeerPoint<C: CurveArithmetic>(PublicKey<C>);

impl<C: HandshakeCurve> PeerPoint<C> {
	/// Parses `sec1` as a peer ephemeral. [`Sec1Point::read`] reads the form
	/// from the first octet (SEC 1 v2.0 §2.3.3) before the curve decodes a
	/// point:
	///
	/// - The compressed and the uncompressed forms, the two that RFC 5480 §2.2 names, parse.
	/// - The parse refuses the compact form `0x05` and the identity `0x00`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is no point on the
	///   curve in a form RFC 5480 §2.2 names.
	fn parse(sec1: impl AsRef<[u8]>) -> Result<Self, HandshakeError> {
		let octets = sec1.as_ref();
		let named_form = Sec1Point::read(octets).is_some();
		if !named_form {
			return Err(EllipticCurveError.into());
		}

		let encoded = EncodedPoint::<C>::from_bytes(octets).map_err(|_| EllipticCurveError)?;
		let decoded = PublicKey::<C>::from_encoded_point(&encoded);

		let point = Option::from(decoded).ok_or(EllipticCurveError)?;
		Ok(Self(point))
	}
}

/// The static keys of a peer as points of the handshake curve, which every
/// ephemeral of that peer must differ from.
///
/// [`Self::of`] parses them once, when the peer is admitted: the key of its
/// signing certificate, and for a CMS server the key of its key-agreement
/// certificate. A key outside the group of the curve, such as a signing key on
/// another curve, collapses no agreement on it, so it reads as `None`.
pub(crate) struct PeerStatics<C: CurveArithmetic> {
	/// The key of the signing certificate, or `None` for a key outside the
	/// group of the curve.
	signing: Option<PublicKey<C>>,
	/// The key of a CMS server's key-agreement certificate, or `None` for a
	/// key outside the group of the curve and for every other peer.
	key_agreement: Option<PublicKey<C>>,
}

impl<C: HandshakeCurve> PeerStatics<C> {
	/// The static keys of a peer that signs under `signing`, and for a CMS
	/// server agrees under `key_agreement`.
	pub(crate) fn of(signing: &Certificate, key_agreement: Option<&Certificate>) -> Self {
		let signing = Self::point_of(signing);
		let key_agreement = key_agreement.and_then(Self::point_of);
		Self { signing, key_agreement }
	}

	/// The key of `certificate` as a point of the curve, or `None` for a key
	/// outside the group of the curve, which collapses no agreement on it.
	fn point_of(certificate: &Certificate) -> Option<PublicKey<C>> {
		let spki = certificate.tbs_certificate.subject_public_key_info.owned_to_ref();
		PublicKey::<C>::try_from(spki).ok()
	}

	/// The statics of a fixture peer whose keys no test compares.
	#[cfg(test)]
	pub(crate) fn none() -> Self {
		Self { signing: None, key_agreement: None }
	}

	/// Parses `sec1` as the ephemeral of this server.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is no point on the
	///   curve in a form RFC 5480 §2.2 names.
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the point collapses into a static key of the server.
	pub(crate) fn server_ephemeral(&self, sec1: impl AsRef<[u8]>) -> Result<DistinctPoint<C>, HandshakeError> {
		let point = PeerPoint::parse(sec1)?;
		let distinct = self.distinct(point);
		distinct.ok_or(HandshakeError::ServerEphemeralIsStatic)
	}

	/// Parses `sec1` as the ephemeral of this client at a rekey, where the
	/// client's static key is known before the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is no point on the
	///   curve in a form RFC 5480 §2.2 names.
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the point collapses into the client's static key.
	#[cfg(mux_rekey)]
	pub(crate) fn client_ephemeral(&self, sec1: impl AsRef<[u8]>) -> Result<DistinctPoint<C>, HandshakeError> {
		let point = PeerPoint::parse(sec1)?;
		let distinct = self.distinct(point);
		distinct.ok_or(HandshakeError::ClientEphemeralIsStatic)
	}

	/// Admits `opened`, the client ephemeral a server agreed with before the
	/// client's identity opened, once the closing names this client. The
	/// point ends here.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the point collapses into the client's static key.
	pub(crate) fn admit_client(&self, opened: OpenedPoint<C>) -> Result<(), HandshakeError> {
		let OpenedPoint(point) = opened;
		let distinct = self.distinct(point);
		distinct.map(drop).ok_or(HandshakeError::ClientEphemeralIsStatic)
	}

	/// `point` as an agreement input, or `None` when it shares the
	/// x-coordinate of a static key of this peer. The x-coordinate is read
	/// once for every key.
	fn distinct(&self, point: PeerPoint<C>) -> Option<DistinctPoint<C>> {
		let x = point.0.as_affine().x();
		let statics = [self.signing.as_ref(), self.key_agreement.as_ref()];
		let collapses = statics.into_iter().flatten().any(|key| key.as_affine().x() == x);
		let distinct = !collapses;
		distinct.then_some(DistinctPoint(point))
	}
}

/// A peer's ephemeral that a [`PeerStatics`] checked against every static key
/// of its sender, the one point the client's agreement and a rekey agreement
/// take.
///
/// [`PeerStatics::server_ephemeral`] and [`PeerStatics::client_ephemeral`]
/// are its constructors.
pub struct DistinctPoint<C: CurveArithmetic>(PeerPoint<C>);

impl<C: CurveArithmetic> DistinctPoint<C> {
	/// The point, for the scalar multiplication that reads it.
	pub(crate) fn as_public_key(&self) -> &PublicKey<C> {
		&self.0 .0
	}
}

/// The client's ephemeral `R` as a server reads it from the opening, before
/// the closing names the identity it must differ from.
///
/// [`Self::parse`] is its one constructor, and the server agrees with it at
/// the reply. The value is not `Clone`: the server's flow moves it into the
/// pending server, and [`PeerStatics::admit_client`] takes that same value at
/// the closing.
pub struct OpenedPoint<C: CurveArithmetic>(PeerPoint<C>);

impl<C: HandshakeCurve> OpenedPoint<C> {
	/// Parses `sec1` as the client ephemeral of an opening.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidPublicKey`] -- `sec1` is no point on the
	///   curve in a form RFC 5480 §2.2 names.
	pub(crate) fn parse(sec1: impl AsRef<[u8]>) -> Result<Self, HandshakeError> {
		let point = PeerPoint::parse(sec1)?;
		Ok(Self(point))
	}
}

impl<C: CurveArithmetic> OpenedPoint<C> {
	/// The point, for the scalar multiplication that reads it.
	pub(crate) fn as_public_key(&self) -> &PublicKey<C> {
		&self.0 .0
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::oids::CURVE_NIST_P384;
	use crate::random::OsRng;
	use crate::testing::TestCertificate;
	use crate::transport::handshake::tests::{create_test_certificate, negated};

	/// The certificate of a fresh secp256k1 key, beside that key.
	fn static_peer() -> (Certificate, PublicKey<Secp256k1>) {
		let peer = create_test_certificate();
		let key = PublicKey::from(peer.signing_key.verifying_key());
		(peer.certificate, key)
	}

	/// The statics of a peer that signs under a fresh secp256k1 key, beside
	/// that key.
	fn signer_statics() -> (PeerStatics<Secp256k1>, PublicKey<Secp256k1>) {
		let (signing, key) = static_peer();
		(PeerStatics::of(&signing, None), key)
	}

	/// A certificate of a fresh P-384 key, a key outside the group of
	/// secp256k1.
	fn p384_certificate() -> Certificate {
		let point = p384::SecretKey::random(&mut OsRng).public_key().to_encoded_point(false);
		TestCertificate::with_curve_point(create_test_certificate().certificate, CURVE_NIST_P384, point.as_bytes())
	}

	/// The compressed SEC 1 octets of `key`.
	fn compressed(key: &PublicKey<Secp256k1>) -> Vec<u8> {
		key.to_encoded_point(true).as_bytes().to_vec()
	}

	/// A valid point that belongs to no party of the test.
	fn stray_key() -> PublicKey<Secp256k1> {
		SecretKey::random(&mut OsRng).public_key()
	}

	/// The parse reads the point alone, so any point of the curve parses as a
	/// peer point.
	#[test]
	fn any_point_of_the_curve_parses_as_a_peer_point() -> Result<(), HandshakeError> {
		let key = stray_key();

		let parsed = OpenedPoint::<Secp256k1>::parse(compressed(&key))?;
		assert_eq!(parsed.as_public_key(), &key);
		Ok(())
	}

	/// The uncompressed form is one of the two forms RFC 5480 §2.2 names, so
	/// a point in it parses as a peer point, as the CMS flow carries one.
	#[test]
	fn a_point_in_the_uncompressed_form_parses_as_a_peer_point() -> Result<(), HandshakeError> {
		let key = stray_key();
		let point = key.to_encoded_point(false);

		let parsed = OpenedPoint::<Secp256k1>::parse(point.as_bytes())?;
		assert_eq!(parsed.as_public_key(), &key);
		Ok(())
	}

	/// RFC 5480 §2.2 names no compact form, so the parse refuses the compact
	/// form `0x05` of a point the curve decodes from it.
	#[test]
	fn a_point_in_the_compact_form_is_refused_at_the_parse() {
		let mut compact = compressed(&stray_key());
		compact[0] = 0x05;

		let refused = OpenedPoint::<Secp256k1>::parse(&compact);
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
	}

	#[test]
	fn the_identity_is_refused_at_the_parse() {
		let refused = OpenedPoint::<Secp256k1>::parse([0x00]);
		assert!(matches!(refused, Err(HandshakeError::InvalidPublicKey(_))));
	}

	#[test]
	fn a_server_ephemeral_other_than_the_static_keys_is_admitted() -> Result<(), HandshakeError> {
		let (signing, _) = static_peer();
		let (key_agreement, _) = static_peer();
		let statics = PeerStatics::<Secp256k1>::of(&signing, Some(&key_agreement));
		let other = stray_key();

		let admitted = statics.server_ephemeral(compressed(&other))?;
		assert_eq!(admitted.as_public_key(), &other);
		Ok(())
	}

	#[test]
	fn a_server_ephemeral_equal_to_the_signing_key_is_refused() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.server_ephemeral(compressed(&signing_key));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// ECDH keeps the x-coordinate alone, so the negation of a static key
	/// agrees to the secret the key itself agrees to.
	#[test]
	fn the_negation_of_the_signing_key_is_refused_as_the_server_ephemeral() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.server_ephemeral(compressed(&negated(&signing_key)));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// A server that signs under a key on P-384 holds no static point of
	/// secp256k1 but its key-agreement key, which its ephemeral must still
	/// differ from.
	#[test]
	fn a_signer_on_another_curve_leaves_the_key_agreement_key_to_compare() {
		let (key_agreement, agreement_key) = static_peer();
		let statics = PeerStatics::<Secp256k1>::of(&p384_certificate(), Some(&key_agreement));

		let refused = statics.server_ephemeral(compressed(&agreement_key));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// A signing key outside the group of the curve collapses no agreement on
	/// the curve, so every point of the curve is distinct from it.
	#[test]
	fn a_signer_on_another_curve_admits_every_point_of_the_curve() -> Result<(), HandshakeError> {
		let statics = PeerStatics::<Secp256k1>::of(&p384_certificate(), None);
		let other = stray_key();

		let admitted = statics.server_ephemeral(compressed(&other))?;
		assert_eq!(admitted.as_public_key(), &other);
		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn a_client_ephemeral_equal_to_the_client_static_key_is_refused() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.client_ephemeral(compressed(&signing_key));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[cfg(mux_rekey)]
	#[test]
	fn a_client_ephemeral_other_than_the_static_key_is_admitted() -> Result<(), HandshakeError> {
		let (statics, _) = signer_statics();
		let other = stray_key();

		let admitted = statics.client_ephemeral(compressed(&other))?;
		assert_eq!(admitted.as_public_key(), &other);
		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn the_negation_of_the_client_static_key_is_refused_as_its_ephemeral() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.client_ephemeral(compressed(&negated(&signing_key)));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[test]
	fn an_opened_point_equal_to_the_client_key_is_refused_at_admission() -> Result<(), HandshakeError> {
		let (statics, signing_key) = signer_statics();
		let opened = OpenedPoint::parse(compressed(&signing_key))?;

		let refused = statics.admit_client(opened);
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	#[test]
	fn an_opened_point_of_the_negated_client_key_is_refused_at_admission() -> Result<(), HandshakeError> {
		let (statics, signing_key) = signer_statics();
		let opened = OpenedPoint::parse(compressed(&negated(&signing_key)))?;

		let refused = statics.admit_client(opened);
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
		Ok(())
	}

	#[test]
	fn an_opened_point_other_than_the_client_key_is_admitted() -> Result<(), HandshakeError> {
		let (statics, _) = signer_statics();
		let opened = OpenedPoint::parse(compressed(&stray_key()))?;

		statics.admit_client(opened)
	}
}

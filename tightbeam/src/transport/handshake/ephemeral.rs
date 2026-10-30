//! A peer's share as an agreement takes it, and the static keys of that peer
//! it must differ from.
//!
//! A share that collapses into a static key of its sender turns the exchange
//! into a static one, as an ECDH point equal to the key or to its negation
//! does (SEC 1 v2.0 §3.3.1). The session then loses the forward secrecy of two
//! ephemerals. The share's own rule, [`KeyShare::collapses_into`], decides
//! what a collapse is, and this module is the one home of the check:
//!
//! - [`PeerStatics`] holds a peer's static keys as its exchange reads them, once at admission.
//! - [`Distinct`] is a share that a [`PeerStatics`] checked against every key
//!   it holds. The client's agreement and both agreements of a rekey run on
//!   this proof alone.
//! - [`OpenedShare`] is the client's share `R` as a server reads it before the
//!   client's identity opens. The server agrees with it at the reply, and
//!   [`PeerStatics::admit_client`] checks that same value once the closing
//!   names the identity.
//! - [`ExchangeSecret`] is the secret an agreement on a proof returns, the one a handshake secret takes.
//! - [`DistinctSecret`] is the secret of an agreement on a [`Distinct`] share, the one a rekey epoch takes.
//!
//! # Sources
//!
//! - SEC 1 v2.0 (May 2009), §3.3.1, the x-coordinate an ECDH keeps: <https://www.secg.org/sec1-v2.pdf>

#[cfg(all(test, not(feature = "std")))]
use alloc::vec::Vec;

use crate::crypto::exchange::{KeyExchange, KeyShare};
use crate::crypto::secret::SecretSlice;
use crate::der::referenced::OwnedToRef;
use crate::random::CryptoRngCore;
use crate::transport::handshake::error::HandshakeError;
use crate::x509::Certificate;

#[cfg(feature = "transport-cms")]
use crate::cms::enveloped_data::OriginatorPublicKey;

/// The static keys of a peer as its exchange `X` reads them, which every share
/// of that peer must differ from.
///
/// [`Self::of`] reads them once, when the peer is admitted: the key of its
/// signing certificate, and for a CMS server the key of its key-agreement
/// certificate. A key whose secret produces no share of `X`, such as a signing
/// key on another curve, collapses no agreement of `X`, so it reads as `None`.
pub(crate) struct PeerStatics<X: KeyExchange> {
	/// The key of the signing certificate, or `None` for a key that produces
	/// no share of `X`.
	signing: Option<X::StaticKey>,
	/// The key of a CMS server's key-agreement certificate, or `None` for a
	/// key that produces no share of `X` and for every other peer.
	key_agreement: Option<X::StaticKey>,
}

impl<X: KeyExchange> PeerStatics<X> {
	/// The static keys of a peer that signs under `signing`, and for a CMS
	/// server agrees under `key_agreement`.
	pub(crate) fn of(signing: &Certificate, key_agreement: Option<&Certificate>) -> Self {
		let signing = Self::key_of(signing);
		let key_agreement = key_agreement.and_then(Self::key_of);
		Self { signing, key_agreement }
	}

	/// The key of `certificate` as `X` reads it.
	fn key_of(certificate: &Certificate) -> Option<X::StaticKey> {
		let spki = certificate.tbs_certificate.subject_public_key_info.owned_to_ref();
		X::static_key(spki)
	}

	/// The statics of a fixture peer whose keys no test compares.
	#[cfg(test)]
	pub(crate) fn none() -> Self {
		Self { signing: None, key_agreement: None }
	}

	/// Admits `share` as the share of this server.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ServerEphemeralIsStatic`] -- the share collapses into a static key of the server.
	pub(crate) fn server_ephemeral(&self, share: X::Reply) -> Result<Distinct<X::Reply>, HandshakeError> {
		let distinct = self.distinct(share);
		distinct.ok_or(HandshakeError::ServerEphemeralIsStatic)
	}

	/// Admits `share` as the share of this client at a rekey, where the
	/// client's static key is known before the agreement.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the share collapses into the client's static key.
	#[cfg(mux_rekey)]
	pub(crate) fn client_ephemeral(&self, share: X::Offer) -> Result<Distinct<X::Offer>, HandshakeError> {
		let distinct = self.distinct(share);
		distinct.ok_or(HandshakeError::ClientEphemeralIsStatic)
	}

	/// Admits `opened`, the client share a server agreed with before the
	/// client's identity opened, once the closing names this client. The share
	/// ends here.
	///
	/// # Errors
	///
	/// - [`HandshakeError::ClientEphemeralIsStatic`] -- the share collapses into the client's static key.
	pub(crate) fn admit_client(&self, opened: OpenedShare<X::Offer>) -> Result<(), HandshakeError> {
		let OpenedShare(share) = opened;
		let distinct = self.distinct(share);
		distinct.map(drop).ok_or(HandshakeError::ClientEphemeralIsStatic)
	}

	/// `share` as an agreement input, or `None` when it collapses into a static
	/// key of this peer.
	fn distinct<S: KeyShare<X>>(&self, share: S) -> Option<Distinct<S>> {
		let statics = [self.signing.as_ref(), self.key_agreement.as_ref()];
		let collapses = statics.into_iter().flatten().any(|key| share.collapses_into(key));
		let distinct = !collapses;
		distinct.then_some(Distinct(share))
	}
}

/// A peer's share that a [`PeerStatics`] checked against every static key of
/// its sender, the one share the client's agreement and a rekey agreement
/// take.
///
/// [`PeerStatics::server_ephemeral`] and [`PeerStatics::client_ephemeral`]
/// are its constructors.
pub struct Distinct<S>(S);

impl<S> Distinct<S> {
	/// Completes the exchange of `pending` with this reply.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the exchange refuses the reply.
	pub(crate) fn complete<X>(&self, pending: &X::Pending) -> Result<DistinctSecret, HandshakeError>
	where
		X: KeyExchange<Reply = S>,
	{
		let secret = X::complete(pending, &self.0)?;
		Ok(DistinctSecret(ExchangeSecret(secret)))
	}

	/// Answers this offer of a rekey with a share drawn from `rng`.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the exchange refuses the offer.
	#[cfg(mux_rekey)]
	pub(crate) fn respond<X>(&self, rng: &mut dyn CryptoRngCore) -> Result<(X::Reply, DistinctSecret), HandshakeError>
	where
		X: KeyExchange<Offer = S>,
	{
		let (reply, secret) = X::respond(&self.0, rng)?;
		Ok((reply, DistinctSecret(ExchangeSecret(secret))))
	}
}

/// The client's share `R` as a server reads it from the opening, before the
/// closing names the identity it must differ from.
///
/// The parses of the two carriers are its constructors, and the server agrees
/// with it at the reply. The value is not `Clone`: the server's flow moves it
/// into the pending server, and [`PeerStatics::admit_client`] takes that same
/// value at the closing.
pub struct OpenedShare<S>(S);

impl<S> OpenedShare<S> {
	/// Parses `octets`, the share of an HPKE hello.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- `octets` is no share of `X`.
	#[cfg(feature = "transport-hpke")]
	pub(crate) fn from_octets<X>(octets: &[u8]) -> Result<Self, HandshakeError>
	where
		X: KeyExchange<Offer = S>,
		S: KeyShare<X>,
	{
		let share = S::from_octets(octets)?;
		Ok(Self(share))
	}

	/// Parses `key`, the `agreementKey` of a CMS opening.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- `key` names another algorithm or is no share of `X`.
	#[cfg(feature = "transport-cms")]
	pub(crate) fn from_originator_key<X>(key: &OriginatorPublicKey) -> Result<Self, HandshakeError>
	where
		X: KeyExchange<Offer = S>,
		S: KeyShare<X>,
	{
		let share = S::from_originator_key(key)?;
		Ok(Self(share))
	}

	/// The share of an opening a test builds by hand.
	#[cfg(test)]
	pub(crate) fn fixture(share: S) -> Self {
		Self(share)
	}

	/// Answers this offer with a share drawn from `rng`, before the closing.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KeyExchange`] -- the exchange refuses the offer.
	pub(crate) fn respond<X>(&self, rng: &mut dyn CryptoRngCore) -> Result<(X::Reply, ExchangeSecret), HandshakeError>
	where
		X: KeyExchange<Offer = S>,
	{
		let (reply, secret) = X::respond(&self.0, rng)?;
		Ok((reply, ExchangeSecret(secret)))
	}
}

/// The shared secret of one exchange, which an agreement on a proof share
/// returns and a handshake secret takes. It wipes where it drops.
pub struct ExchangeSecret(SecretSlice<u8>);

impl ExchangeSecret {
	/// Lends the secret to `f` for the length of the call.
	pub(crate) fn with<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
		self.0.with(|secret| f(secret))
	}

	/// The secret of `octets`, for a fixture that derives from a fixed secret.
	#[cfg(test)]
	pub(crate) fn fixture(octets: impl Into<Vec<u8>>) -> Self {
		Self(SecretSlice::from(octets.into()))
	}
}

/// The secret of an exchange on a [`Distinct`] share, the one secret a rekey
/// epoch takes. [`Distinct::complete`] and [`Distinct::respond`] are its
/// constructors.
pub struct DistinctSecret(ExchangeSecret);

impl DistinctSecret {
	/// The secret of `octets`, for a fixture of a rekey epoch.
	#[cfg(test)]
	pub(crate) fn fixture(octets: impl Into<Vec<u8>>) -> Self {
		Self(ExchangeSecret::fixture(octets))
	}
}

/// The secret as the key schedule of a handshake takes it.
impl AsRef<ExchangeSecret> for DistinctSecret {
	fn as_ref(&self) -> &ExchangeSecret {
		&self.0
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::exchange::{Ecdhe, EcdheShare};
	use crate::crypto::sign::ecdsa::k256::{Secp256k1, SecretKey};
	use crate::crypto::sign::elliptic_curve::sec1::ToEncodedPoint;
	use crate::crypto::sign::elliptic_curve::PublicKey;
	use crate::oids::CURVE_NIST_P384;
	use crate::random::OsRng;
	use crate::testing::TestCertificate;
	use crate::transport::handshake::tests::{create_test_certificate, negated};

	/// The house exchange of the tests.
	type House = Ecdhe<Secp256k1>;

	/// The certificate of a fresh secp256k1 key, beside that key.
	fn static_peer() -> (Certificate, PublicKey<Secp256k1>) {
		let peer = create_test_certificate();
		let key = PublicKey::from(peer.signing_key.verifying_key());
		(peer.certificate, key)
	}

	/// The statics of a peer that signs under a fresh secp256k1 key, beside
	/// that key.
	fn signer_statics() -> (PeerStatics<House>, PublicKey<Secp256k1>) {
		let (signing, key) = static_peer();
		(PeerStatics::of(&signing, None), key)
	}

	/// A certificate of a fresh P-384 key, a key outside the group of
	/// secp256k1.
	fn p384_certificate() -> Certificate {
		let point = p384::SecretKey::random(&mut OsRng).public_key().to_encoded_point(false);
		TestCertificate::with_curve_point(create_test_certificate().certificate, CURVE_NIST_P384, point.as_bytes())
	}

	/// The share of `key`.
	fn share(key: &PublicKey<Secp256k1>) -> EcdheShare<Secp256k1> {
		EcdheShare::from(*key)
	}

	/// The share of a valid point that belongs to no party of the test.
	fn stray_share() -> EcdheShare<Secp256k1> {
		share(&SecretKey::random(&mut OsRng).public_key())
	}

	/// The client share an opening carries as `key`.
	fn opened(key: &PublicKey<Secp256k1>) -> OpenedShare<EcdheShare<Secp256k1>> {
		OpenedShare(share(key))
	}

	#[test]
	fn a_server_share_other_than_the_static_keys_is_admitted() -> Result<(), HandshakeError> {
		let (signing, _) = static_peer();
		let (key_agreement, _) = static_peer();
		let statics = PeerStatics::<House>::of(&signing, Some(&key_agreement));
		let other = stray_share();

		let admitted = statics.server_ephemeral(other)?;
		assert_eq!(admitted.0, other);
		Ok(())
	}

	#[test]
	fn a_server_share_equal_to_the_signing_key_is_refused() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.server_ephemeral(share(&signing_key));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// ECDH keeps the x-coordinate alone, so the negation of a static key
	/// agrees to the secret the key itself agrees to.
	#[test]
	fn the_negation_of_the_signing_key_is_refused_as_the_server_share() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.server_ephemeral(share(&negated(&signing_key)));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// A server that signs under a key on P-384 holds no static key of the
	/// secp256k1 exchange but its key-agreement key, which its share must still
	/// differ from.
	#[test]
	fn a_signer_on_another_curve_leaves_the_key_agreement_key_to_compare() {
		let (key_agreement, agreement_key) = static_peer();
		let statics = PeerStatics::<House>::of(&p384_certificate(), Some(&key_agreement));

		let refused = statics.server_ephemeral(share(&agreement_key));
		assert!(matches!(refused, Err(HandshakeError::ServerEphemeralIsStatic)));
	}

	/// A signing key outside the group of the curve collapses no agreement on
	/// the curve, so every share of the curve is distinct from it.
	#[test]
	fn a_signer_on_another_curve_admits_every_share_of_the_curve() -> Result<(), HandshakeError> {
		let statics = PeerStatics::<House>::of(&p384_certificate(), None);
		let other = stray_share();

		let admitted = statics.server_ephemeral(other)?;
		assert_eq!(admitted.0, other);
		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn a_client_share_equal_to_the_client_static_key_is_refused() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.client_ephemeral(share(&signing_key));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[cfg(mux_rekey)]
	#[test]
	fn a_client_share_other_than_the_static_key_is_admitted() -> Result<(), HandshakeError> {
		let (statics, _) = signer_statics();
		let other = stray_share();

		let admitted = statics.client_ephemeral(other)?;
		assert_eq!(admitted.0, other);
		Ok(())
	}

	#[cfg(mux_rekey)]
	#[test]
	fn the_negation_of_the_client_static_key_is_refused_as_its_share() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.client_ephemeral(share(&negated(&signing_key)));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[test]
	fn an_opened_share_equal_to_the_client_key_is_refused_at_admission() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.admit_client(opened(&signing_key));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[test]
	fn an_opened_share_of_the_negated_client_key_is_refused_at_admission() {
		let (statics, signing_key) = signer_statics();

		let refused = statics.admit_client(opened(&negated(&signing_key)));
		assert!(matches!(refused, Err(HandshakeError::ClientEphemeralIsStatic)));
	}

	#[test]
	fn an_opened_share_other_than_the_client_key_is_admitted() -> Result<(), HandshakeError> {
		let (statics, _) = signer_statics();
		let other = OpenedShare(stray_share());

		statics.admit_client(other)
	}

	/// The agreement on a proof share is the exchange itself, so both ends of
	/// a handshake derive one secret.
	#[test]
	fn both_ends_agree_on_their_proof_shares() -> Result<(), HandshakeError> {
		let (pending, offer) = House::offer(&mut OsRng);
		let (reply, responder) = OpenedShare(offer).respond::<House>(&mut OsRng)?;
		let reply = PeerStatics::<House>::none().server_ephemeral(reply)?;
		let initiator = reply.complete::<House>(&pending)?;

		let equal = initiator.as_ref().with(|secret| responder.with(|other| secret == other));
		assert!(equal);
		Ok(())
	}
}

//! The key-exchange role of a provider: the ephemeral exchange of a handshake
//! and of each rekey.
//!
//! An exchange runs in the shape of a KEM, the order in which TLS 1.3 runs its
//! `key_share` (RFC 8446 §4.2.8). The initiator offers a share, the responder
//! answers with a share of its own and the shared secret, and the initiator
//! completes with the same secret. RFC 9180 §4.1 builds a KEM from a DH group,
//! so one role serves an elliptic-curve group, X25519, ML-KEM, and a hybrid.
//!
//! | Item | What it owns |
//! | --- | --- |
//! | [`KeyExchange`] | The operation, the static keys a share must differ from, and the strength |
//! | [`KeyShare`] | One share in each carrier of the handshake, and its collapse rule |
//! | [`ReplyAttribute`] | The attribute that carries the server's share in the CMS Finished |
//! | [`ReplyKind`] | The kind of a reply, which picks its attribute |
//! | [`Ecdhe`] | The house exchange: ECDH over a [`HandshakeCurve`] |
//! | [`MlKem`] | ML-KEM-768 and ML-KEM-1024, under the `preview-pqc` feature |
//! | [`Hybrid`] | A KEM paired with a classical exchange, under the `preview-pqc`, `sha3`, and `kdf` features |
//!
//! # Sources
//!
//! - RFC 8446 (August 2018), §4.2.8, the key share, and §7.4.2, the all-zero X25519 refusal.
//! - RFC 9180 (February 2022), §4.1, a KEM built from a DH group.
//! - RFC 5652 (September 2009), §6.2.2, `OriginatorPublicKey`, the sender's key agreement public key.
//! - RFC 9629 (August 2024), §3, the `kem` and `kemct` of a KEM recipient.
//! - SEC 1 v2.0 (May 2009), §2.3.3 and §3.3.1, the point forms and the x-coordinate an ECDH keeps.
//! - NIST SP 800-227 (September 2025), §4.6, a multi-algorithm KEM is a KEM.

#[cfg(all(feature = "preview-pqc", feature = "sha3", feature = "kdf"))]
mod hybrid;
#[cfg(feature = "preview-pqc")]
mod lattice;

#[cfg(all(feature = "preview-pqc", feature = "sha3", feature = "kdf"))]
pub use hybrid::{Hybrid, HybridPair, HybridPending, HybridShare, Secp256k1MlKem768};
#[cfg(feature = "preview-pqc")]
pub use lattice::{MlKem, MlKem1024, MlKem768, MlKemOffer, MlKemParameterSet, MlKemReply};

use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use elliptic_curve::bigint::ArrayEncoding;
use elliptic_curve::ecdh::{diffie_hellman, EphemeralSecret, SharedSecret};
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::sec1::{CompressedPointSize, EncodedPoint, FromEncodedPoint, ModulusSize, Tag, ToEncodedPoint};
use elliptic_curve::{Curve, CurveArithmetic, NonZeroScalar, PrimeCurve, PublicKey, SecretKey};

use crate::cms::enveloped_data::OriginatorPublicKey;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::profiles::SecurityStrength;
use crate::crypto::secret::SecretSlice;
use crate::der::asn1::{BitString, ObjectIdentifier, OctetString};
use crate::der::oid::db::rfc5912::{ID_EC_DH, ID_EC_MQV, ID_EC_PUBLIC_KEY};
use crate::der::oid::AssociatedOid;
use crate::der::{Decode, Sequence};
use crate::random::CryptoRngCore;
use crate::spki::{AlgorithmIdentifierOwned, EncodePublicKey, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use crate::zeroize::{ZeroizeOnDrop, Zeroizing};
use crate::Errorizable;

/// A curve the house exchange runs on: a prime-order Weierstrass curve with
/// SEC 1 encodings, which names its OID. Every curve that meets the bounds is
/// a handshake curve, such as secp256k1, P-256, P-384, or P-521.
///
/// - A shared secret is the x-coordinate of an agreement, as wide as the field (SEC 1 v2.0 §3.3.1).
/// - A share of the HPKE flow or of a rekey travels in its compressed SEC 1 form (SEC 1 v2.0 §2.3.3).
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::exchange::HandshakeCurve;
///
/// fn runs_a_handshake<C: HandshakeCurve>() {}
///
/// runs_a_handshake::<tightbeam::crypto::k256::Secp256k1>();
/// runs_a_handshake::<p256::NistP256>();
/// runs_a_handshake::<p384::NistP384>();
/// runs_a_handshake::<p521::NistP521>();
/// ```
pub trait HandshakeCurve:
	PrimeCurve
	+ Curve<FieldBytesSize: ModulusSize>
	+ CurveArithmetic<AffinePoint: FromEncodedPoint<Self> + ToEncodedPoint<Self>>
	+ AssociatedOid
	+ Send
	+ Sync
	+ 'static
{
}

impl<C> HandshakeCurve for C where
	C: PrimeCurve
		+ Curve<FieldBytesSize: ModulusSize>
		+ CurveArithmetic<AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>>
		+ AssociatedOid
		+ Send
		+ Sync
		+ 'static
{
}

/// One ephemeral key exchange of a handshake or of a rekey, in the shape of a
/// KEM. Its OID is the one a security profile negotiates for it.
///
/// # Contract
///
/// An implementation meets each of these rules, and the house [`Ecdhe`] does:
///
/// - `complete`, given the pending state of `offer` and the reply of
///   `respond`, returns the secret `respond` returned.
/// - `respond` and `complete` refuse a share only with a
///   [`KeyExchangeError`], and a refusal aborts the handshake.
/// - `static_key` MUST read every certificate key whose secret can produce a
///   share of this exchange. X25519 reads `id-X25519` and `id-Ed25519`,
///   because one scalar serves both keys (RFC 7748 §4.1). A hybrid reads the
///   keys of its classical part. An exchange names `StaticKey = Infallible`
///   when no certificate key of a sender can produce its share, as ML-KEM
///   does: its offer is a client's share, and a client's certificate holds a
///   signing key.
/// - `REPLY` is [`ReplyKind::Dh`] when the reply is the responder's public
///   key, and [`ReplyKind::Kem`] when it is a ciphertext.
/// - `Pending` wipes its secret where it drops (CWE-226).
/// - The secret of one exchange always has one width, so the key schedule's `ee || base` stays unambiguous.
/// - `strength` rates the exchange as its own standard does. See [`SecurityStrength`].
pub trait KeyExchange: AssociatedOid + Sized + Send + Sync + 'static {
	/// The initiator's share.
	type Offer: KeyShare<Self>;
	/// The responder's share.
	type Reply: KeyShare<Self>;
	/// What the initiator holds from its offer to the completion.
	type Pending: ZeroizeOnDrop + Send + Sync + 'static;
	/// A peer's static key, in the form that a share is compared with.
	type StaticKey: Send + Sync + 'static;

	/// The kind of the reply, which fixes the attribute that carries it in the
	/// CMS Finished.
	const REPLY: ReplyKind;

	/// The security strength of this exchange, which the strength floor of a
	/// handshake reads.
	fn strength() -> SecurityStrength;

	/// Draws the initiator's share from `rng`, beside what the initiator holds
	/// to complete the exchange.
	fn offer(rng: &mut dyn CryptoRngCore) -> (Self::Pending, Self::Offer);

	/// Answers `offer` with a share drawn from `rng`, beside the shared secret.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Refused`] -- the exchange refuses the offer.
	/// - [`KeyExchangeError::Encoding`] -- a value the secret binds fails to encode.
	fn respond(
		offer: &Self::Offer,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(Self::Reply, SecretSlice<u8>), KeyExchangeError>;

	/// Completes the exchange of `pending` with `reply`, and returns the shared
	/// secret. `pending` is lent, so it wipes in place where its owner drops
	/// it, once this call returns.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Refused`] -- the exchange refuses the reply.
	/// - [`KeyExchangeError::Encoding`] -- a value the secret binds fails to encode.
	fn complete(pending: &Self::Pending, reply: &Self::Reply) -> Result<SecretSlice<u8>, KeyExchangeError>;

	/// Reads `spki`, the key of a certificate, in the form that a share of this
	/// exchange is compared with. A key whose secret produces no share of this
	/// exchange reads as `None`.
	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self::StaticKey>;
}

/// One share of the exchange `X`, in each carrier of the handshake.
///
/// - The HPKE hello and reply and both rekey legs carry a share as an OCTET STRING: [`Self::from_octets`].
/// - The CMS opening carries the client's share as its `agreementKey`, an
///   `OriginatorPublicKey` (RFC 5652 §6.2.2): [`Self::from_originator_key`].
/// - The CMS Finished carries the server's share in the [`ReplyAttribute`] that [`KeyExchange::REPLY`] names.
///
/// The opening form is provided. It names the exchange by its OID with no
/// parameters, and holds the octets as the public key.
pub trait KeyShare<X: KeyExchange>: Sized + Send + Sync + 'static {
	/// Parses `octets` as a share of the OCTET STRING carriers.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Width`] -- `octets` is not as wide as a share.
	/// - [`KeyExchangeError::Malformed`] -- `octets` encodes no share.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError>;

	/// The octets of this share, as the OCTET STRING carriers hold it.
	fn to_octets(&self) -> Vec<u8>;

	/// Whether an agreement with this share collapses into one with `key`, a
	/// static key of the share's sender.
	fn collapses_into(&self, key: &X::StaticKey) -> bool;

	/// Parses the `agreementKey` of a CMS opening as a share. The parse MUST
	/// refuse an identifier that names another algorithm.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Algorithm`] -- `key` names another algorithm, or carries parameters.
	/// - The errors of [`Self::from_octets`].
	fn from_originator_key(key: &OriginatorPublicKey) -> Result<Self, KeyExchangeError> {
		if !names_exchange::<X>(&key.algorithm) {
			return Err(KeyExchangeError::Algorithm);
		}

		let octets = key.public_key.as_bytes().ok_or(KeyExchangeError::Malformed)?;
		Self::from_octets(octets)
	}

	/// This share as the `agreementKey` of a CMS opening.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Encoding`] -- the share fails to encode as a BIT STRING.
	fn to_originator_key(&self) -> Result<OriginatorPublicKey, KeyExchangeError> {
		let algorithm = AlgorithmIdentifierOwned { oid: X::OID, parameters: None };
		let public_key = BitString::from_bytes(&self.to_octets()).map_err(|_| KeyExchangeError::Encoding)?;
		Ok(OriginatorPublicKey { algorithm, public_key })
	}
}

/// A share whose OCTET STRING form has one width, so a [`Hybrid`] splits a
/// share of two parts at the width of the first.
///
/// An implementation keeps both rules:
///
/// - [`KeyShare::to_octets`] returns `WIDTH` octets.
/// - [`KeyShare::from_octets`] refuses octets of any other width with [`KeyExchangeError::Width`].
#[cfg(feature = "preview-pqc")]
pub trait FixedWidthShare {
	/// The width of the share in its OCTET STRING form, in bytes.
	const WIDTH: usize;
}

/// The kind of an exchange's reply, which fixes its [`ReplyAttribute`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplyKind {
	/// The reply is the responder's public key, as a DH reply is. It travels
	/// as a [`ReplyAttribute::OriginatorKey`] in the share's opening form.
	Dh,
	/// The reply is a ciphertext, as a KEM's encapsulation is. It travels as a
	/// [`ReplyAttribute::KemCiphertext`] under the OID of the exchange.
	Kem,
}

/// The attribute that carries the server's share in the CMS Finished, one
/// carrier for each kind of reply, as CMS itself splits key agreement from KEM
/// recipients.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReplyAttribute {
	/// The reply of a DH exchange: the responder's public key
	/// (RFC 5652 §6.2.2), under [`HANDSHAKE_SERVER_EPHEMERAL`].
	///
	/// [`HANDSHAKE_SERVER_EPHEMERAL`]: crate::oids::HANDSHAKE_SERVER_EPHEMERAL
	OriginatorKey(OriginatorPublicKey),
	/// The reply of a KEM, a hybrid among them (NIST SP 800-227 §4.6): the
	/// ciphertext the responder encapsulated, under
	/// [`HANDSHAKE_SERVER_KEM_CIPHERTEXT`].
	///
	/// [`HANDSHAKE_SERVER_KEM_CIPHERTEXT`]: crate::oids::HANDSHAKE_SERVER_KEM_CIPHERTEXT
	KemCiphertext(KemCiphertext),
}

impl ReplyAttribute {
	/// The attribute that carries `share`, the reply of `X`, in the carrier
	/// [`KeyExchange::REPLY`] names.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Encoding`] -- the share fails to encode.
	pub fn of<X: KeyExchange>(share: &X::Reply) -> Result<Self, KeyExchangeError> {
		match X::REPLY {
			ReplyKind::Dh => {
				let key = share.to_originator_key()?;
				Ok(Self::OriginatorKey(key))
			}
			ReplyKind::Kem => {
				let kem = AlgorithmIdentifierOwned { oid: X::OID, parameters: None };
				let kemct = OctetString::new(share.to_octets()).map_err(|_| KeyExchangeError::Encoding)?;
				Ok(Self::KemCiphertext(KemCiphertext { kem, kemct }))
			}
		}
	}

	/// The reply of `X` that this attribute carries. The parse refuses the
	/// carrier of the other kind of reply, and a `kem` that names another
	/// algorithm or carries parameters.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Algorithm`] -- the attribute is the carrier of the
	///   other kind of reply, or names another algorithm.
	/// - The errors of [`KeyShare::from_originator_key`] and [`KeyShare::from_octets`].
	pub fn reply<X: KeyExchange>(&self) -> Result<X::Reply, KeyExchangeError> {
		match (X::REPLY, self) {
			(ReplyKind::Dh, Self::OriginatorKey(key)) => <X::Reply as KeyShare<X>>::from_originator_key(key),
			(ReplyKind::Kem, Self::KemCiphertext(ciphertext)) => {
				if !names_exchange::<X>(&ciphertext.kem) {
					return Err(KeyExchangeError::Algorithm);
				}

				<X::Reply as KeyShare<X>>::from_octets(ciphertext.kemct.as_bytes())
			}
			(ReplyKind::Dh, Self::KemCiphertext(_)) | (ReplyKind::Kem, Self::OriginatorKey(_)) => {
				Err(KeyExchangeError::Algorithm)
			}
		}
	}
}

/// Whether `algorithm` names the exchange `X`: its OID, with no parameters.
fn names_exchange<X: KeyExchange>(algorithm: &AlgorithmIdentifierOwned) -> bool {
	algorithm.oid == X::OID && algorithm.parameters.is_none()
}

/// The ciphertext of a KEM reply, with the KEM that produced it: the `kem`
/// and `kemct` fields RFC 9629 §3 gives a KEM recipient.
///
/// ```text
/// KemCiphertext ::= SEQUENCE {
///   kem    AlgorithmIdentifier,
///   kemct  OCTET STRING }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Sequence)]
pub struct KemCiphertext {
	/// The KEM that produced the ciphertext.
	pub kem: AlgorithmIdentifierOwned,
	/// The ciphertext the responder encapsulated for the initiator.
	pub kemct: OctetString,
}

/// A refusal of a share or of an exchange.
#[derive(Errorizable, Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyExchangeError {
	/// A share is not as wide as its exchange requires.
	#[error("Key share of {actual} bytes, where the exchange takes {expected}")]
	Width {
		/// The width the exchange takes, in bytes.
		expected: usize,
		/// The width of the share, in bytes.
		actual: usize,
	},

	/// A share encodes no valid share of its exchange.
	#[error("Malformed key share")]
	Malformed,

	/// A share names another algorithm than the negotiated exchange, or travels
	/// in the carrier of another kind of reply.
	#[error("Key share of another algorithm")]
	Algorithm,

	/// The exchange refuses a share, such as an X25519 share whose agreement is
	/// all zeros (RFC 8446 §7.4.2).
	#[error("Key exchange refused the share")]
	Refused,

	/// A share fails to encode in its carrier.
	#[error("Key share failed to encode")]
	Encoding,
}

/// The house exchange: ephemeral ECDH over the curve `C`, in the shape of a
/// KEM. Its OID is the OID of `C`, so a profile names the curve it runs on.
///
/// The shared secret is the raw x-coordinate of the agreement (SEC 1 v2.0
/// §3.3.1), which the key schedule of the handshake extracts.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::exchange::{Ecdhe, KeyExchange};
/// use tightbeam::crypto::k256::Secp256k1;
/// use tightbeam::random::OsRng;
///
/// let (pending, offer) = Ecdhe::<Secp256k1>::offer(&mut OsRng);
/// let (reply, responder) = Ecdhe::<Secp256k1>::respond(&offer, &mut OsRng)?;
/// let initiator = Ecdhe::<Secp256k1>::complete(&pending, &reply)?;
///
/// assert!(initiator.with(|secret| responder.with(|other| secret == other)));
/// # Ok::<(), tightbeam::crypto::exchange::KeyExchangeError>(())
/// ```
pub struct Ecdhe<C>(PhantomData<fn() -> C>);

impl<C: HandshakeCurve> AssociatedOid for Ecdhe<C> {
	const OID: ObjectIdentifier = C::OID;
}

/// One share of [`Ecdhe`]: a point of the curve other than the identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcdheShare<C: CurveArithmetic>(PublicKey<C>);

impl<C: HandshakeCurve> EcdheShare<C> {
	/// Parses `sec1` as a share in the form its first octet names
	/// (SEC 1 v2.0 §2.3.3). It admits the compressed and the uncompressed
	/// forms, the two that RFC 5480 §2.2 names, and refuses the compact form
	/// and the identity.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Malformed`] -- `sec1` is no point of the curve in a form RFC 5480 §2.2 names.
	fn parse(sec1: &[u8]) -> Result<Self, KeyExchangeError> {
		let encoded = EncodedPoint::<C>::from_bytes(sec1).map_err(|_| KeyExchangeError::Malformed)?;
		let named_form = matches!(encoded.tag(), Tag::CompressedEvenY | Tag::CompressedOddY | Tag::Uncompressed);
		if !named_form {
			return Err(KeyExchangeError::Malformed);
		}

		let decoded = PublicKey::<C>::from_encoded_point(&encoded);
		let point = Option::from(decoded).ok_or(KeyExchangeError::Malformed)?;
		Ok(Self(point))
	}
}

/// The share of a point, so a known answer names the point it pins.
impl<C: CurveArithmetic> From<PublicKey<C>> for EcdheShare<C> {
	fn from(point: PublicKey<C>) -> Self {
		Self(point)
	}
}

/// The OCTET STRING carriers hold the compressed form at its width on the
/// curve, and the CMS carriers hold the SPKI encoding of the point.
impl<C: HandshakeCurve> KeyShare<Ecdhe<C>> for EcdheShare<C> {
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let expected = CompressedPointSize::<C>::USIZE;
		if octets.len() != expected {
			return Err(KeyExchangeError::Width { expected, actual: octets.len() });
		}

		Self::parse(octets)
	}

	fn to_octets(&self) -> Vec<u8> {
		let compressed = self.0.to_encoded_point(true);
		compressed.as_bytes().to_vec()
	}

	/// ECDH keeps the x-coordinate alone, so a point and its negation agree
	/// alike (SEC 1 v2.0 §3.3.1).
	fn collapses_into(&self, key: &PublicKey<C>) -> bool {
		self.0.as_affine().x() == key.as_affine().x()
	}

	/// The key is an `id-ecPublicKey` of the curve `C`, in either point form.
	fn from_originator_key(key: &OriginatorPublicKey) -> Result<Self, KeyExchangeError> {
		let parameters = key.algorithm.parameters.as_ref();
		let curve = parameters.and_then(|parameters| parameters.decode_as::<ObjectIdentifier>().ok());
		let named = key.algorithm.oid == ID_EC_PUBLIC_KEY && curve == Some(C::OID);
		if !named {
			return Err(KeyExchangeError::Algorithm);
		}

		let octets = key.public_key.as_bytes().ok_or(KeyExchangeError::Malformed)?;
		Self::parse(octets)
	}

	/// The SPKI encoding of the point: `id-ecPublicKey` on the curve `C`, with
	/// the uncompressed point.
	fn to_originator_key(&self) -> Result<OriginatorPublicKey, KeyExchangeError> {
		let spki_der = self.0.to_public_key_der().map_err(|_| KeyExchangeError::Encoding)?;
		let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes()).map_err(|_| KeyExchangeError::Encoding)?;
		let public_key = BitString::from_bytes(spki.subject_public_key.raw_bytes());
		let public_key = public_key.map_err(|_| KeyExchangeError::Encoding)?;
		Ok(OriginatorPublicKey { algorithm: spki.algorithm, public_key })
	}
}

/// The compressed form, which the OCTET STRING carriers hold.
#[cfg(feature = "preview-pqc")]
impl<C: HandshakeCurve> FixedWidthShare for EcdheShare<C> {
	const WIDTH: usize = CompressedPointSize::<C>::USIZE;
}

impl<C: HandshakeCurve> KeyExchange for Ecdhe<C> {
	type Offer = EcdheShare<C>;
	type Reply = EcdheShare<C>;
	type Pending = SecretKey<C>;
	type StaticKey = PublicKey<C>;

	const REPLY: ReplyKind = ReplyKind::Dh;

	/// The size of the order of the base point, as NIST SP 800-57 Part 1
	/// Rev. 5 Table 2 rates an ECC key.
	fn strength() -> SecurityStrength {
		// The bit length of the order: its width less the leading zeros of its
		// big-endian octets.
		let order = C::ORDER.to_be_byte_array();
		let zero_octets = order.iter().take_while(|octet| **octet == 0).count();
		let top_zeros = order.get(zero_octets).map_or(0, |octet| octet.leading_zeros() as usize);
		let leading = zero_octets.saturating_mul(8).saturating_add(top_zeros);
		let width = order.len().saturating_mul(8);
		SecurityStrength::of_ecc_order(width.saturating_sub(leading))
	}

	fn offer(mut rng: &mut dyn CryptoRngCore) -> (SecretKey<C>, EcdheShare<C>) {
		let pending = SecretKey::<C>::random(&mut rng);
		let offer = EcdheShare(pending.public_key());
		(pending, offer)
	}

	fn respond(
		offer: &EcdheShare<C>,
		mut rng: &mut dyn CryptoRngCore,
	) -> Result<(EcdheShare<C>, SecretSlice<u8>), KeyExchangeError> {
		let ephemeral = EphemeralSecret::<C>::random(&mut rng);
		let reply = EcdheShare(ephemeral.public_key());
		let shared = ephemeral.diffie_hellman(&offer.0);
		Ok((reply, Self::secret_of(&shared)))
	}

	fn complete(pending: &SecretKey<C>, reply: &EcdheShare<C>) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let owned = Zeroizing::new(pending.to_nonzero_scalar());
		let scalar: &NonZeroScalar<C> = &owned;
		let shared = diffie_hellman(scalar, reply.0.as_affine());
		Ok(Self::secret_of(&shared))
	}

	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<PublicKey<C>> {
		// RFC 5480 §2.1.1 and §2.1.2 publish a key of the curve under three
		// algorithms, each with the curve as its parameters and the point as
		// its bits. A key outside the group of `C` collapses no agreement on
		// `C`, so its parse refusal reads as no static key.
		let algorithm = spki.algorithm;
		let ec_key = [ID_EC_PUBLIC_KEY, ID_EC_DH, ID_EC_MQV].contains(&algorithm.oid);
		let on_curve = algorithm.assert_parameters_oid(C::OID).is_ok();
		if !ec_key || !on_curve {
			return None;
		}

		let point = spki.subject_public_key.as_bytes()?;
		PublicKey::<C>::from_sec1_bytes(point).ok()
	}
}

impl<C: HandshakeCurve> Ecdhe<C> {
	/// The x-coordinate of `shared`, as wide as the field of `C`, copied into
	/// the wiping buffer the key schedule reads. `shared` wipes where it drops.
	fn secret_of(shared: &SharedSecret<C>) -> SecretSlice<u8> {
		let x_coordinate = shared.raw_secret_bytes();
		SecretSlice::from(x_coordinate.to_vec())
	}
}

#[cfg(test)]
mod tests {
	use p256::NistP256;
	use p384::NistP384;
	use p521::NistP521;

	use super::*;
	use crate::crypto::k256::Secp256k1;
	use crate::der::referenced::OwnedToRef;
	use crate::random::OsRng;

	/// The point of a fresh secp256k1 scalar.
	pub(super) fn fresh_point() -> PublicKey<Secp256k1> {
		SecretKey::<Secp256k1>::random(&mut OsRng).public_key()
	}

	/// The octets of `secret`, to compare with a vector or another secret.
	#[cfg(feature = "preview-pqc")]
	pub(super) fn octets_of(secret: &SecretSlice<u8>) -> Vec<u8> {
		secret.with(|octets| octets.to_vec())
	}

	#[test]
	fn both_ends_of_an_exchange_derive_one_secret() -> Result<(), KeyExchangeError> {
		let (pending, offer) = Ecdhe::<Secp256k1>::offer(&mut OsRng);
		let (reply, responder) = Ecdhe::<Secp256k1>::respond(&offer, &mut OsRng)?;
		let initiator = Ecdhe::<Secp256k1>::complete(&pending, &reply)?;

		let equal = initiator.with(|secret| responder.with(|other| secret == other));
		assert!(equal);
		Ok(())
	}

	#[test]
	fn a_share_of_another_width_is_refused() {
		let uncompressed = fresh_point().to_encoded_point(false);
		let refused = EcdheShare::<Secp256k1>::from_octets(uncompressed.as_bytes());
		assert_eq!(refused, Err(KeyExchangeError::Width { expected: 33, actual: 65 }));
	}

	#[test]
	fn a_share_in_the_compact_form_is_refused() {
		let mut compact = fresh_point().to_encoded_point(true).as_bytes().to_vec();
		compact[0] = 0x05;

		let refused = EcdheShare::<Secp256k1>::from_octets(&compact);
		assert_eq!(refused, Err(KeyExchangeError::Malformed));
	}

	/// The opening's `agreementKey` names `id-ecPublicKey` on the curve, so an
	/// originator key of another curve names another algorithm.
	#[test]
	fn an_originator_key_of_another_curve_is_refused() -> Result<(), KeyExchangeError> {
		let point = p256::SecretKey::random(&mut OsRng).public_key();
		let key = EcdheShare::<NistP256>::from(point).to_originator_key()?;

		let refused = EcdheShare::<Secp256k1>::from_originator_key(&key);
		assert_eq!(refused, Err(KeyExchangeError::Algorithm));
		Ok(())
	}

	/// The CMS carriers admit a point in both SEC 1 forms that RFC 5480 §2.2
	/// names, as one share.
	#[test]
	fn an_originator_key_admits_both_point_forms() -> Result<(), KeyExchangeError> {
		let point = fresh_point();
		let share = EcdheShare::<Secp256k1>::from(point);
		let uncompressed = share.to_originator_key()?;
		let compressed_point = point.to_encoded_point(true);
		let public_key = BitString::from_bytes(compressed_point.as_bytes()).map_err(|_| KeyExchangeError::Encoding)?;
		let compressed = OriginatorPublicKey { algorithm: uncompressed.algorithm.clone(), public_key };

		let parse = EcdheShare::<Secp256k1>::from_originator_key;
		assert_eq!((parse(&uncompressed)?, parse(&compressed)?), (share, share));
		Ok(())
	}

	/// A DH share travels as an `OriginatorPublicKey`, so a reply in the KEM
	/// carrier names another kind of reply.
	#[test]
	fn a_ciphertext_reply_is_refused_for_a_dh_share() -> Result<(), KeyExchangeError> {
		let compressed = fresh_point().to_encoded_point(true);
		let kem = AlgorithmIdentifierOwned { oid: Secp256k1::OID, parameters: None };
		let kemct = OctetString::new(compressed.as_bytes()).map_err(|_| KeyExchangeError::Encoding)?;
		let attribute = ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct });

		let refused = attribute.reply::<Ecdhe<Secp256k1>>();
		assert_eq!(refused, Err(KeyExchangeError::Algorithm));
		Ok(())
	}

	/// A key of the curve reads as a static key under each algorithm that RFC
	/// 5480 §2.1.1 and §2.1.2 publish it under, and as none under another
	/// algorithm or for another curve.
	#[test]
	fn the_house_exchange_reads_a_static_key_under_each_ec_algorithm() -> Result<(), crate::spki::Error> {
		let key = fresh_point();
		let mut spki = SubjectPublicKeyInfoOwned::from_key(key)?;
		for algorithm in [ID_EC_PUBLIC_KEY, ID_EC_DH, ID_EC_MQV] {
			spki.algorithm.oid = algorithm;
			let read = Ecdhe::<Secp256k1>::static_key(spki.owned_to_ref());
			assert_eq!(read, Some(key));
		}

		// A point of P-256 under the parameters of secp256k1 decodes on P-256,
		// so only the parameters refuse it.
		let p256_key = p256::SecretKey::random(&mut OsRng).public_key();
		let mut mislabeled = SubjectPublicKeyInfoOwned::from_key(p256_key)?;
		mislabeled.algorithm.parameters = spki.algorithm.parameters.clone();

		let other_curve = Ecdhe::<NistP256>::static_key(mislabeled.owned_to_ref());
		assert_eq!(other_curve, None);

		spki.algorithm.oid = Secp256k1::OID;

		let other_algorithm = Ecdhe::<Secp256k1>::static_key(spki.owned_to_ref());
		assert_eq!(other_algorithm, None);
		Ok(())
	}

	/// NIST SP 800-57 Part 1 Rev. 5 Table 2 rates an ECC key by the size
	/// of its base point's order: 256 bits rate 128, 384 rate 192, and 521
	/// rate 256.
	#[test]
	fn the_house_exchange_rates_the_order_of_its_curve() {
		assert_eq!(Ecdhe::<Secp256k1>::strength(), SecurityStrength::BITS_128);
		assert_eq!(Ecdhe::<NistP384>::strength(), SecurityStrength::BITS_192);
		assert_eq!(Ecdhe::<NistP521>::strength(), SecurityStrength::BITS_256);
	}
}

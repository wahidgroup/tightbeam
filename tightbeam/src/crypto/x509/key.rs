//! The identity of a public key, read in place from the SubjectPublicKeyInfo
//! that carries it.
//!
//! [`KeyIdentity`] is the one rule of "the same key" for a reader that holds
//! a key as its encoding alone: the trust store's key index and its collision
//! check, [`PublicKeyPinning`], [`PeerListGate`], and the peer key of a
//! session. [`CanonicalKey`] states the rule.
//!
//! The parts of the rule:
//!
//! - [`CurvePoints`] decodes the points of one curve, and only refuses.
//! - [`KeyCurves`] holds the decoders of a reader.
//! - [`CanonicalKey`] holds one identity in its canonical form.
//! - [`KeyIndex`] finds a key in either SEC 1 form of its point.
//!
//! ## Sources
//!
//! - RFC 5480 §2.1.1 and §2.2, the named curve and the first octet of an
//!   elliptic-curve key:
//!   <https://datatracker.ietf.org/doc/html/rfc5480#section-2.2>
//! - SEC 1 v2.0 §2.3.3 and §2.3.4, a point as an octet string and its decode:
//!   <https://www.secg.org/sec1-v2.pdf>
//! - SEC 2 v1.0 Appendix A and ANSI X9.62, the binary-field curves: <https://www.secg.org/SEC2-Ver-1.0.pdf>
//!
//! [`PeerListGate`]: crate::colony::hive::PeerListGate
//! [`PublicKeyPinning`]: crate::crypto::x509::policy::PublicKeyPinning

use core::fmt::{self, Debug, Formatter};
use core::marker::PhantomData;

use elliptic_curve::point::DecompressPoint;
use elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{AffinePoint, CurveArithmetic, FieldBytesSize, PublicKey};

use crate::der::asn1::{BitStringRef, ObjectIdentifier};
use crate::der::oid::db::rfc5912::ID_EC_PUBLIC_KEY;
use crate::der::oid::AssociatedOid;
use crate::der::referenced::OwnedToRef;
use crate::der::{Encode, EncodeValue, FixedTag, Length, Tag, Writer};
use crate::oids::{BINARY_FIELD_CURVES, CURVE_X962_C_TWO};
use crate::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};

#[cfg(not(feature = "std"))]
use alloc::sync::Arc;
#[cfg(feature = "std")]
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "secp256k1")]
use crate::crypto::k256::Secp256k1;
#[cfg(any(
	feature = "transport-cms",
	feature = "transport-hpke",
	all(test, feature = "transport")
))]
use crate::der::oid::db::rfc5912::{ID_EC_DH, ID_EC_MQV};

/// A point of an `id-ecPublicKey` key, read in place as its compressed SEC 1
/// form names it: the parity of its y-coordinate and its x-coordinate.
///
/// The compressed form `0x02` or `0x03` and the uncompressed form `0x04` of one
/// point read as one value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Sec1Point<'a> {
	/// Whether the y-coordinate is odd, which the first octet `0x03` names.
	odd: bool,
	/// The x-coordinate, as the point encodes it.
	x: &'a [u8],
}

impl<'a> Sec1Point<'a> {
	/// Read `point`, whose first octet names its form. It returns `None` for a
	/// form that RFC 5480 §2.2 refuses or for an uncompressed point of uneven
	/// halves.
	pub(crate) fn read(point: &'a [u8]) -> Option<Self> {
		let (form, coordinates) = point.split_first()?;
		match form {
			0x02 | 0x03 => Some(Self { odd: *form == 0x03, x: coordinates }),
			0x04 if coordinates.len().is_multiple_of(2) => {
				let (x, y) = coordinates.split_at_checked(coordinates.len() / 2)?;
				let odd = (y.last()? & 1) == 1;
				Some(Self { odd, x })
			}
			_ => None,
		}
	}

	/// The x-coordinate, as the point encodes it.
	#[cfg(feature = "signature")]
	pub(crate) fn x(&self) -> &'a [u8] {
		self.x
	}
}

/// The decoder of the points of one named curve, which refuses an encoding
/// that is no point of the curve (SEC 1 v2.0 §2.3.4).
///
/// - A reader of keys holds its decoders in a [`KeyCurves`].
/// - An implementation MUST accept every point of its curve in both SEC 1
///   forms, so a point it accepts reads as one key at every reader.
/// - An implementation MUST give one answer to one input on every call, so a key an index holds stays found.
/// - [`Sec1Curve`] decodes a curve that the `elliptic-curve` crate implements.
pub trait CurvePoints: Debug + Send + Sync {
	/// The `namedCurve` OID of the curve (RFC 5480 §2.1.1.1).
	fn curve(&self) -> ObjectIdentifier;

	/// Whether `point`, an SEC 1 octet string in the compressed or the
	/// uncompressed form, is a point of the curve.
	fn decodes(&self, point: &[u8]) -> bool;
}

/// The decoder of the curve `C`, which runs the range and curve checks of SEC 1
/// v2.0 §2.3.4 through the arithmetic of `C`, on the stack.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::k256::Secp256k1;
/// use tightbeam::crypto::x509::{CurvePoints, Sec1Curve};
/// use tightbeam::oids::CURVE_SECP256K1;
///
/// let decoder = Sec1Curve::<Secp256k1>::new();
/// assert_eq!(decoder.curve(), CURVE_SECP256K1);
///
/// // The SEC 1 octet string of the point at infinity is no point of a curve.
/// assert!(!decoder.decodes(&[0x00]));
/// ```
pub struct Sec1Curve<C>(PhantomData<fn() -> C>);

impl<C> Sec1Curve<C> {
	/// The decoder of `C`.
	#[must_use]
	pub const fn new() -> Self {
		Self(PhantomData)
	}
}

impl<C> Default for Sec1Curve<C> {
	fn default() -> Self {
		Self::new()
	}
}

impl<C: AssociatedOid> Debug for Sec1Curve<C> {
	fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
		f.debug_tuple("Sec1Curve").field(&C::OID).finish()
	}
}

/// The arithmetic of `C` decompresses a point, so the decoder reads both
/// SEC 1 forms that the contract of [`CurvePoints`] names.
impl<C> CurvePoints for Sec1Curve<C>
where
	C: CurveArithmetic + AssociatedOid,
	FieldBytesSize<C>: ModulusSize,
	AffinePoint<C>: DecompressPoint<C> + FromEncodedPoint<C> + ToEncodedPoint<C>,
{
	fn curve(&self) -> ObjectIdentifier {
		C::OID
	}

	fn decodes(&self, point: &[u8]) -> bool {
		PublicKey::<C>::from_sec1_bytes(point).is_ok()
	}
}

/// The decoders a reader of keys holds, one for each curve whose off-curve
/// encodings it refuses.
///
/// A set decides only which encodings read as bits. A valid point keeps its
/// identity under every set, so two readers that hold two sets agree on every
/// valid key. The first decoder of a curve decides.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::k256::Secp256k1;
/// use tightbeam::crypto::x509::{KeyCurves, Sec1Curve};
/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
///
/// // A set that holds the decoder of secp256k1, and a set that holds none.
/// const SECP256K1: KeyCurves = KeyCurves::new(&[&Sec1Curve::<Secp256k1>::new()]);
/// const NONE: KeyCurves = KeyCurves::new(&[]);
///
/// // A valid point has one canonical form under every set.
/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let spki = &certificate.tbs_certificate.subject_public_key_info;
/// assert_eq!(SECP256K1.canonical(spki)?, NONE.canonical(spki)?);
/// # Ok::<(), tightbeam::der::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct KeyCurves(&'static [&'static dyn CurvePoints]);

impl KeyCurves {
	/// The house set: the decoder of secp256k1 in a build with the `secp256k1`
	/// feature, and no decoder otherwise.
	#[cfg(feature = "secp256k1")]
	pub const HOUSE: Self = Self(&[&Sec1Curve::<Secp256k1>::new()]);

	/// The house set: the decoder of secp256k1 in a build with the `secp256k1`
	/// feature, and no decoder otherwise.
	#[cfg(not(feature = "secp256k1"))]
	pub const HOUSE: Self = Self(&[]);

	/// The set of `decoders`.
	#[must_use]
	pub const fn new(decoders: &'static [&'static dyn CurvePoints]) -> Self {
		Self(decoders)
	}

	/// The decoder this set holds for `curve`.
	fn decoder(self, curve: ObjectIdentifier) -> Option<&'static dyn CurvePoints> {
		self.0.iter().copied().find(|decoder| decoder.curve() == curve)
	}

	/// The canonical form of the key that `spki` holds, read under this set.
	///
	/// # Errors
	///
	/// - [`der::Error`](crate::der::Error) -- the canonical form is longer than the DER length cap.
	pub fn canonical(self, spki: &SubjectPublicKeyInfoOwned) -> crate::der::Result<CanonicalKey> {
		KeyIdentity::of(spki, self).to_canonical()
	}
}

impl Default for KeyCurves {
	fn default() -> Self {
		Self::HOUSE
	}
}

/// The key a BIT STRING of a SubjectPublicKeyInfo holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyValue<'a> {
	/// The point of an `id-ecPublicKey` key on a named curve outside the
	/// binary-field curves, in the compressed or the uncompressed SEC 1 form.
	Point(Sec1Point<'a>),
	/// The bits of any other key.
	Bits(BitStringRef<'a>),
}

impl<'a> KeyValue<'a> {
	/// The key `bits` holds under `algorithm`, as `curves` reads it.
	fn read(algorithm: AlgorithmIdentifierRef<'a>, bits: BitStringRef<'a>, curves: KeyCurves) -> Self {
		let point = Self::point(algorithm, bits, curves);
		point.map_or(Self::Bits(bits), Self::Point)
	}

	/// The named curve of `algorithm` when it is `id-ecPublicKey` with a
	/// `namedCurve` parameter (RFC 5480 §2.1.1.1).
	fn named_curve(algorithm: AlgorithmIdentifierRef<'_>) -> Option<ObjectIdentifier> {
		if algorithm.oid != ID_EC_PUBLIC_KEY {
			return None;
		}

		algorithm.parameters?.decode_as::<ObjectIdentifier>().ok()
	}

	/// The point that `bits` holds under `algorithm`, read by its SEC 1 form.
	///
	/// The key is a point when all three hold:
	///
	/// 1. `algorithm` is `id-ecPublicKey` on a named curve that no binary-field list of SEC 2 or X9.62 names.
	/// 2. Its form is one that RFC 5480 §2.2 admits.
	/// 3. The decoder that `curves` holds for the curve, if any, accepts it.
	///
	/// The parity rule of SEC 1 v2.0 §2.3.3 holds over an odd prime field
	/// alone, so the field of the curve decides how a key reads:
	///
	/// - A key on a binary-field curve of SEC 2 or ANSI X9.62 reads as its bits.
	/// - A key on any other named curve reads by the parity rule.
	fn point(
		algorithm: AlgorithmIdentifierRef<'a>,
		bits: BitStringRef<'a>,
		curves: KeyCurves,
	) -> Option<Sec1Point<'a>> {
		let curve = Self::named_curve(algorithm)?;
		let binary = BINARY_FIELD_CURVES.contains(&curve) || curve.parent() == Some(CURVE_X962_C_TWO);
		if binary {
			return None;
		}

		let octets = bits.as_bytes()?;
		let point = Sec1Point::read(octets)?;
		let refused = curves.decoder(curve).is_some_and(|decoder| !decoder.decodes(octets));
		(!refused).then_some(point)
	}
}

impl FixedTag for KeyValue<'_> {
	const TAG: Tag = Tag::BitString;
}

/// The key as the BIT STRING of the canonical SubjectPublicKeyInfo: a point in
/// its compressed SEC 1 form, or the bits of any other key as they arrived.
impl EncodeValue for KeyValue<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		match self {
			// The octet of unused bits and the form octet precede the
			// x-coordinate.
			Self::Point(point) => Length::try_from(point.x.len())? + 2u8,
			Self::Bits(bits) => bits.value_len(),
		}
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		match self {
			Self::Point(point) => {
				// The form octet is `0x02` for an even y and `0x03` for an
				// odd y (SEC 1 v2.0 §2.3.3).
				let form = 0x02 | u8::from(point.odd);
				writer.write(&[0, form])?;
				writer.write(point.x)
			}
			Self::Bits(bits) => bits.encode_value(writer),
		}
	}
}

/// The identity of a public key: its algorithm, its key in one form, and the
/// decoders it was read under.
///
/// [`Self::of`] reads it in place, so a comparison borrows each key. A point
/// reads as a [`Sec1Point`], so its two SEC 1 forms are one key, and every
/// other key reads as its bits, by the rule that [`CanonicalKey`] states.
#[derive(Clone, Copy, Debug)]
pub(crate) struct KeyIdentity<'a> {
	/// The algorithm identifier, with its parameters, such as the named curve.
	algorithm: AlgorithmIdentifierRef<'a>,
	/// The key, with a point in one form.
	key: KeyValue<'a>,
	/// The decoders the key was read under, which read a pin too.
	curves: KeyCurves,
}

impl<'a> KeyIdentity<'a> {
	/// The identity of the key `spki` holds, as `curves` reads it.
	pub(crate) fn of(spki: &'a SubjectPublicKeyInfoOwned, curves: KeyCurves) -> Self {
		Self::read(spki.owned_to_ref(), curves)
	}

	/// The identity of the key that `spki`, a borrowed SubjectPublicKeyInfo,
	/// holds, as `curves` reads it.
	pub(crate) fn read(spki: SubjectPublicKeyInfoRef<'a>, curves: KeyCurves) -> Self {
		let key = KeyValue::read(spki.algorithm, spki.subject_public_key, curves);
		Self { algorithm: spki.algorithm, key, curves }
	}

	/// Whether `bits`, the octets of a key BIT STRING under this identity's
	/// algorithm, hold this key as the curves of this identity read them. A
	/// pin names a key by these octets alone.
	///
	/// The SEC 1 form of a pin compares before its decoder runs, so only a pin
	/// of this point pays for the decode.
	pub(crate) fn holds(&self, bits: &[u8]) -> bool {
		let Ok(bits) = BitStringRef::from_bytes(bits) else {
			return false;
		};

		let candidate = match self.key {
			KeyValue::Point(point) => bits.as_bytes().and_then(Sec1Point::read) == Some(point),
			KeyValue::Bits(own) => bits == own,
		};
		candidate && KeyValue::read(self.algorithm, bits, self.curves) == self.key
	}

	/// Whether this identity names an elliptic-curve key that reads as no
	/// point, by the rule that [`CanonicalKey`] states. The handshake refuses
	/// every peer that holds such a key, which is one of these:
	///
	/// - An `id-ecPublicKey` key that reads as its bits.
	/// - A key under `id-ecDH` or `id-ecMQV` (RFC 5480 §2.1.2), which each use refuses.
	#[cfg(any(
		feature = "transport-cms",
		feature = "transport-hpke",
		all(test, feature = "transport")
	))]
	pub(crate) fn names_no_point(&self) -> bool {
		let restricted = self.algorithm.oid == ID_EC_DH || self.algorithm.oid == ID_EC_MQV;
		let unread = self.algorithm.oid == ID_EC_PUBLIC_KEY && matches!(self.key, KeyValue::Bits(_));
		restricted || unread
	}

	/// Whether this identity names a point on a named curve that its curves
	/// hold no decoder for. Its reader reads an off-curve encoding with the x
	/// and the y parity of the point as that point.
	#[cfg(feature = "colony")]
	pub(crate) fn names_an_undecoded_curve(&self) -> bool {
		let point = matches!(self.key, KeyValue::Point(_));
		let curve = KeyValue::named_curve(self.algorithm);
		point && curve.is_some_and(|curve| self.curves.decoder(curve).is_none())
	}

	/// The canonical form of this identity, the key of a store's key index and
	/// of a session's peer.
	///
	/// # Errors
	///
	/// - [`der::Error`](crate::der::Error) -- the canonical form is longer than the DER length cap.
	pub(crate) fn to_canonical(self) -> crate::der::Result<CanonicalKey> {
		self.lend(|der| CanonicalKey(Arc::from(der)))
	}

	/// Lend the canonical DER of this identity to `view`.
	///
	/// This method writes the DER on the stack when it fits [`INLINE_SIZE`]
	/// octets, so a lookup of a named-curve key stays on the stack. A
	/// longer canonical form goes on the heap.
	///
	/// # Errors
	///
	/// - [`der::Error`](crate::der::Error) -- the canonical form is longer than the DER length cap.
	pub(crate) fn lend<R>(&self, view: impl FnOnce(&[u8]) -> R) -> crate::der::Result<R> {
		let length = usize::try_from(self.encoded_len()?)?;
		let mut inline = [0u8; INLINE_SIZE];
		match inline.get_mut(..length) {
			Some(buffer) => {
				let der = self.encode_to_slice(buffer)?;
				Ok(view(der))
			}
			None => {
				let der = self.to_der()?;
				Ok(view(&der))
			}
		}
	}
}

/// The size in octets of the stack buffer that [`KeyIdentity::lend`] writes a
/// canonical form into. It holds the canonical form of every named-curve key
/// up to P-521: 90 octets for a point, and 158 octets for an uncompressed
/// encoding that a decoder refuses.
const INLINE_SIZE: usize = 192;

impl FixedTag for KeyIdentity<'_> {
	const TAG: Tag = Tag::Sequence;
}

/// The identity as the canonical SubjectPublicKeyInfo: the algorithm with its
/// parameters as they arrived, then the key as [`KeyValue`] encodes it.
impl EncodeValue for KeyIdentity<'_> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.algorithm.encoded_len()? + self.key.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		self.algorithm.encode(writer)?;
		self.key.encode(writer)
	}
}

/// A public key in its canonical form, the DER of a SubjectPublicKeyInfo that
/// holds each key in one form.
///
/// Two keys are one key exactly when their canonical forms are one, under the
/// [`KeyCurves`] of the reader:
///
/// - A point of a named curve outside the binary-field curves of SEC 2 and
///   ANSI X9.62, in either SEC 1 form, reads as its compressed form (RFC 5480
///   §2.2), and its negation is another key.
/// - Every other key keeps its bits as they arrived:
///   - An encoding that the decoder of its curve refuses.
///   - A malformed point, or a form that RFC 5480 §2.2 refuses.
///   - An `id-ecPublicKey` key with no named curve.
///   - A key on a binary-field curve of SEC 2 or ANSI X9.62.
///   - A key of another algorithm.
///
/// A session proves its peer by this value, so a gate compares it with the
/// [`Self::of`] or [`KeyCurves::canonical`] of a key it lists.
///
/// # Sources
///
/// - RFC 5480 §2.1.1 and §2.2, the named curve and the first octet of an
///   elliptic-curve key:
///   <https://datatracker.ietf.org/doc/html/rfc5480#section-2.2>
/// - SEC 1 v2.0 §2.3.3 and §2.3.4, a point as an octet string and its decode:
///   <https://www.secg.org/sec1-v2.pdf>
/// - SEC 2 v1.0 Appendix A and ANSI X9.62, the binary-field curves: <https://www.secg.org/SEC2-Ver-1.0.pdf>
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalKey(Arc<[u8]>);

impl CanonicalKey {
	/// The canonical form of the key that `spki` holds, read under
	/// [`KeyCurves::HOUSE`].
	///
	/// # Errors
	///
	/// - [`der::Error`](crate::der::Error) -- the canonical form is longer than the DER length cap.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::CanonicalKey;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // One key in its uncompressed and its compressed SEC 1 form.
	/// let uncompressed = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let compressed = TestCertificate::with_compressed_key(uncompressed.clone());
	///
	/// let first = CanonicalKey::of(&uncompressed.tbs_certificate.subject_public_key_info)?;
	/// let second = CanonicalKey::of(&compressed.tbs_certificate.subject_public_key_info)?;
	/// assert_eq!(first, second);
	/// # Ok::<(), tightbeam::der::Error>(())
	/// ```
	pub fn of(spki: &SubjectPublicKeyInfoOwned) -> crate::der::Result<Self> {
		KeyCurves::HOUSE.canonical(spki)
	}

	/// The DER of the canonical SubjectPublicKeyInfo.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::x509::CanonicalKey;
	/// use tightbeam::der::Encode;
	/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
	///
	/// // The compressed form of a secp256k1 key is its canonical form.
	/// let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	/// let compressed = TestCertificate::with_compressed_key(certificate);
	/// let spki = &compressed.tbs_certificate.subject_public_key_info;
	///
	/// let canonical = CanonicalKey::of(spki)?;
	/// assert_eq!(canonical.as_der(), spki.to_der()?.as_slice());
	/// # Ok::<(), tightbeam::der::Error>(())
	/// ```
	#[must_use]
	pub fn as_der(&self) -> &[u8] {
		&self.0
	}
}

/// A map keyed by canonical keys, which finds the key of a SubjectPublicKeyInfo
/// in either SEC 1 form of its point.
///
/// - The index reads each key it inserts, finds, or removes under its own [`KeyCurves`].
/// - A lookup writes the canonical DER on the stack, so a lookup of a named-curve key stays on the stack.
/// - The built-in trust store indexes its keys with one, and an outside store gets the same lookup.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::x509::KeyIndex;
/// use tightbeam::testing::fixtures::{TestCertificate, TestKey};
///
/// let uncompressed = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
/// let compressed = TestCertificate::with_compressed_key(uncompressed.clone());
///
/// // Index the key in its uncompressed form, and find it in the other.
/// let mut index = KeyIndex::default();
/// let replaced = index.insert(&uncompressed.tbs_certificate.subject_public_key_info, "enrolled")?;
/// assert_eq!(replaced, None);
///
/// let found = index.find(&compressed.tbs_certificate.subject_public_key_info);
/// assert_eq!(found, Some(&"enrolled"));
/// # Ok::<(), tightbeam::der::Error>(())
/// ```
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct KeyIndex<V> {
	/// Each indexed value, under the canonical form of its key.
	keys: HashMap<IndexedKey, V>,
	/// The decoders the index reads each key under.
	curves: KeyCurves,
}

#[cfg(feature = "std")]
impl<V> Default for KeyIndex<V> {
	fn default() -> Self {
		Self::new(KeyCurves::HOUSE)
	}
}

#[cfg(feature = "std")]
impl<V> KeyIndex<V> {
	/// An empty index that reads a key under `curves`.
	#[must_use]
	pub fn new(curves: KeyCurves) -> Self {
		Self { keys: HashMap::new(), curves }
	}

	/// The value indexed under the key that `spki` holds, in either SEC 1 form
	/// of its point.
	#[must_use]
	pub fn find(&self, spki: &SubjectPublicKeyInfoOwned) -> Option<&V> {
		let identity = KeyIdentity::of(spki, self.curves);
		let found = identity.lend(|der| self.keys.get(der));
		// A key whose canonical form the encoder refuses names no indexed key,
		// so the lookup finds nothing.
		found.ok().flatten()
	}

	/// Index `value` under the key that `spki` holds, and return the value
	/// that key held before, if any.
	///
	/// # Errors
	///
	/// - [`der::Error`](crate::der::Error) -- the canonical form is longer than the DER length cap.
	pub fn insert(&mut self, spki: &SubjectPublicKeyInfoOwned, value: V) -> crate::der::Result<Option<V>> {
		let key = self.curves.canonical(spki)?;
		Ok(self.keys.insert(IndexedKey(key), value))
	}

	/// Remove the value indexed under the key that `spki` holds, in either
	/// SEC 1 form of its point, and return it.
	pub fn remove(&mut self, spki: &SubjectPublicKeyInfoOwned) -> Option<V> {
		let identity = KeyIdentity::of(spki, self.curves);
		let removed = identity.lend(|der| self.keys.remove(der));
		// A key whose canonical form the encoder refuses names no indexed key,
		// so the removal finds nothing.
		removed.ok().flatten()
	}
}

/// A key of a [`KeyIndex`], which the index finds by its canonical DER.
///
/// It hashes and compares as its DER, so [`Borrow`] keeps the contract of a
/// map that finds it by that DER.
#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq, Hash)]
struct IndexedKey(CanonicalKey);

#[cfg(feature = "std")]
impl Borrow<[u8]> for IndexedKey {
	fn borrow(&self) -> &[u8] {
		self.0.as_der()
	}
}

#[cfg(all(test, feature = "std", feature = "signature"))]
mod tests {
	use super::*;

	use crate::der::asn1::{BitString, ObjectIdentifier};
	use crate::der::oid::db::rfc8410::{ID_ED_25519, ID_X_25519};
	use crate::der::{Any, Error};
	use crate::oids::{CURVE_NIST_P256, CURVE_NIST_P384, CURVE_NIST_P521, CURVE_SECP256K1};
	use crate::testing::fixtures::{TestCertificate, TestKey, TestP256Points};

	/// `sect233k1`, a SEC 2 curve over a binary field.
	const SECT233K1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.26");

	/// `c2pnb163v1`, an ANSI X9.62 curve over a binary field.
	const C2PNB163V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.0.1");

	/// A decoder of secp256k1 that accepts every encoding. It breaks the
	/// contract of [`CurvePoints`] on an off-curve encoding, the one input on
	/// which two decoders of one curve can disagree, so it shows which of two
	/// decoders decides.
	#[derive(Debug)]
	struct PermissiveSecp256k1;

	impl CurvePoints for PermissiveSecp256k1 {
		fn curve(&self) -> ObjectIdentifier {
			CURVE_SECP256K1
		}

		fn decodes(&self, _point: &[u8]) -> bool {
			true
		}
	}

	/// The real decoder of secp256k1 ahead of the permissive one.
	const STRICT_FIRST: KeyCurves = KeyCurves::new(&[&Sec1Curve::<Secp256k1>::new(), &PermissiveSecp256k1]);

	/// The permissive decoder of secp256k1 ahead of the real one.
	const PERMISSIVE_FIRST: KeyCurves = KeyCurves::new(&[&PermissiveSecp256k1, &Sec1Curve::<Secp256k1>::new()]);

	/// The set that holds no decoder.
	const NO_DECODER: KeyCurves = KeyCurves::new(&[]);

	/// The SubjectPublicKeyInfo of the fixed test key, in the uncompressed
	/// form the test certificate carries.
	fn uncompressed() -> SubjectPublicKeyInfoOwned {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		certificate.tbs_certificate.subject_public_key_info
	}

	/// The SubjectPublicKeyInfo of the fixed test key in its compressed form.
	fn compressed() -> SubjectPublicKeyInfoOwned {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::with_compressed_key(certificate);
		certificate.tbs_certificate.subject_public_key_info
	}

	/// The SubjectPublicKeyInfo of the negation of the fixed test key, whose
	/// point shares the x-coordinate of that key.
	fn negated() -> SubjectPublicKeyInfoOwned {
		let negation = TestKey::negation_of(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::self_signed(&negation);
		certificate.tbs_certificate.subject_public_key_info
	}

	/// [`uncompressed`] under the named curve `curve`.
	fn on_curve(curve: ObjectIdentifier) -> SubjectPublicKeyInfoOwned {
		let mut spki = uncompressed();
		let named_curve = Any::encode_from(&curve).expect("a curve OID encodes");
		spki.algorithm.parameters = Some(named_curve);
		spki
	}

	/// [`uncompressed`] with its y-coordinate changed off the curve, so the
	/// encoding keeps the x-coordinate and the y parity of the fixed key.
	fn off_curve_alias() -> SubjectPublicKeyInfoOwned {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::with_off_curve_key(certificate);
		certificate.tbs_certificate.subject_public_key_info
	}

	/// [`uncompressed`] under `oid` with no parameters, so its algorithm OID
	/// alone names its kind.
	fn under(oid: ObjectIdentifier) -> SubjectPublicKeyInfoOwned {
		let mut spki = uncompressed();
		spki.algorithm.oid = oid;
		spki.algorithm.parameters = None;
		spki
	}

	/// `point` as the key of an `id-ecPublicKey` SubjectPublicKeyInfo on the
	/// named curve `curve`.
	fn with_point(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
		let mut spki = on_curve(curve);
		spki.subject_public_key = BitString::from_bytes(point).expect("a point is a BIT STRING");
		spki
	}

	/// The P-256 key of RFC 6979 §A.2.5 in the uncompressed SEC 1 form.
	fn p256_uncompressed() -> SubjectPublicKeyInfoOwned {
		with_point(CURVE_NIST_P256, &TestKey::RFC6979_P256_UNCOMPRESSED)
	}

	/// The P-256 key of RFC 6979 §A.2.5 in the compressed SEC 1 form.
	fn p256_compressed() -> SubjectPublicKeyInfoOwned {
		with_point(CURVE_NIST_P256, &TestKey::RFC6979_P256_COMPRESSED)
	}

	/// [`under`] Ed25519 with a key of 300 octets, whose canonical form exceeds
	/// the inline bound.
	fn long_key() -> SubjectPublicKeyInfoOwned {
		let mut spki = under(ID_ED_25519);
		let bits = BitString::from_bytes(&[0x2a; 300]).expect("300 octets are a BIT STRING");
		spki.subject_public_key = bits;
		spki
	}

	/// [`under`] Ed25519 with a key of 178 octets, whose canonical form fills
	/// the inline bound to its last octet.
	fn edge_key() -> SubjectPublicKeyInfoOwned {
		let mut spki = under(ID_ED_25519);
		let bits = BitString::from_bytes(&[0x2a; 178]).expect("178 octets are a BIT STRING");
		spki.subject_public_key = bits;
		spki
	}

	/// The octets of the uncompressed point of the fixed key with `form` as
	/// its first octet.
	fn in_form(form: u8) -> Vec<u8> {
		let spki = uncompressed();
		let point = spki.subject_public_key.raw_bytes();
		let (_, coordinates) = point.split_first().expect("the point names its form");
		[&[form][..], coordinates].concat()
	}

	/// The octets of the point of the fixed key in the compact form, the
	/// octet `0x05` before the x-coordinate alone.
	fn compact() -> SubjectPublicKeyInfoOwned {
		let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
		let certificate = TestCertificate::with_compact_key(certificate);
		certificate.tbs_certificate.subject_public_key_info
	}

	/// One secp256k1 point in its compressed and its uncompressed form is one
	/// key.
	#[test]
	fn one_point_in_both_forms_is_one_key() -> Result<(), Error> {
		let compressed = compressed();
		let uncompressed = uncompressed();

		let compressed = KeyIdentity::of(&compressed, KeyCurves::HOUSE).to_canonical()?;
		assert_eq!(compressed, KeyIdentity::of(&uncompressed, KeyCurves::HOUSE).to_canonical()?);
		Ok(())
	}

	/// The canonical form of the uncompressed fixed key is the DER of its
	/// compressed SubjectPublicKeyInfo, which k256 compresses and the DER
	/// encoder writes outside the code under test.
	#[test]
	fn the_canonical_form_of_an_uncompressed_point_is_its_compressed_der() -> Result<(), Error> {
		let expected = compressed().to_der()?;

		let canonical = CanonicalKey::of(&uncompressed())?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// A key that reads as its bits keeps its DER as its canonical form.
	#[test]
	fn a_key_read_as_its_bits_keeps_its_der() -> Result<(), Error> {
		let ed25519 = under(ID_ED_25519);
		let expected = ed25519.to_der()?;

		let canonical = CanonicalKey::of(&ed25519)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// The P-256 key of RFC 6979 §A.2.5 in its two SEC 1 forms is one key,
	/// read by its form with no decoder of P-256.
	#[test]
	fn one_point_of_a_curve_without_a_decoder_in_both_forms_is_one_key() -> Result<(), Error> {
		let compressed = CanonicalKey::of(&p256_compressed())?;
		assert_eq!(compressed, CanonicalKey::of(&p256_uncompressed())?);
		Ok(())
	}

	/// An encoding that the decoder of its curve refuses reads as its bits,
	/// so it keeps its DER (SEC 1 v2.0 §2.3.4).
	#[test]
	fn a_point_its_decoder_refuses_keeps_its_der() -> Result<(), Error> {
		let alias = off_curve_alias();
		let expected = alias.to_der()?;

		let canonical = KeyCurves::HOUSE.canonical(&alias)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// The first decoder of a curve decides, so the real decoder ahead of a
	/// permissive one reads an off-curve alias as its bits.
	#[test]
	fn a_strict_first_decoder_reads_an_alias_as_its_bits() -> Result<(), Error> {
		let alias = off_curve_alias();
		let expected = alias.to_der()?;

		let canonical = STRICT_FIRST.canonical(&alias)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// The first decoder of a curve decides, so a permissive decoder ahead of
	/// the real one reads an off-curve alias as the point it names.
	#[test]
	fn a_permissive_first_decoder_reads_an_alias_as_its_point() -> Result<(), Error> {
		let expected = compressed().to_der()?;

		let canonical = PERMISSIVE_FIRST.canonical(&off_curve_alias())?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// The decoder of secp256k1 accepts its generator in the uncompressed
	/// form that SEC 2 v2.0 §2.4.1 publishes.
	#[test]
	fn the_secp256k1_decoder_accepts_the_published_uncompressed_generator() {
		let decoder = Sec1Curve::<Secp256k1>::new();
		assert!(decoder.decodes(&TestKey::SEC2_SECP256K1_G_UNCOMPRESSED));
	}

	/// The decoder of secp256k1 accepts its generator in the compressed form
	/// that SEC 2 v2.0 §2.4.1 publishes.
	#[test]
	fn the_secp256k1_decoder_accepts_the_published_compressed_generator() {
		let decoder = Sec1Curve::<Secp256k1>::new();
		assert!(decoder.decodes(&TestKey::SEC2_SECP256K1_G_COMPRESSED));
	}

	/// The test decoder of P-256 accepts the key of RFC 6979 §A.2.5 in the
	/// uncompressed form, whose coordinates solve the curve equation.
	#[test]
	fn the_test_p256_decoder_accepts_the_rfc6979_key_uncompressed() {
		assert!(TestP256Points.decodes(&TestKey::RFC6979_P256_UNCOMPRESSED));
	}

	/// The test decoder of P-256 accepts the key of RFC 6979 §A.2.5 in the
	/// compressed form, whose x-coordinate gives a square.
	#[test]
	fn the_test_p256_decoder_accepts_the_rfc6979_key_compressed() {
		assert!(TestP256Points.decodes(&TestKey::RFC6979_P256_COMPRESSED));
	}

	/// The test decoder of P-256 refuses the RFC 6979 key with the
	/// second-lowest bit of y flipped, which solves no curve equation.
	#[test]
	fn the_test_p256_decoder_refuses_an_off_curve_alias() {
		let mut alias = TestKey::RFC6979_P256_UNCOMPRESSED;
		alias[64] ^= 0b10;
		assert!(!TestP256Points.decodes(&alias));
	}

	/// The test decoder of P-256 refuses a compressed point whose x-coordinate,
	/// the one of the RFC 6979 key plus one, gives no square.
	#[test]
	fn the_test_p256_decoder_refuses_an_x_of_no_point() {
		let mut point = TestKey::RFC6979_P256_COMPRESSED;
		point[32] += 1;
		assert!(!TestP256Points.decodes(&point));
	}

	/// The canonical form of the published uncompressed generator holds the
	/// compressed generator that SEC 2 v2.0 §2.4.1 publishes.
	#[test]
	fn the_canonical_form_of_the_generator_is_its_published_compressed_form() -> Result<(), Error> {
		let expected = with_point(CURVE_SECP256K1, &TestKey::SEC2_SECP256K1_G_COMPRESSED).to_der()?;

		let uncompressed = with_point(CURVE_SECP256K1, &TestKey::SEC2_SECP256K1_G_UNCOMPRESSED);
		let canonical = CanonicalKey::of(&uncompressed)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// The canonical form of the P-521 key of RFC 6979 §A.2.7 holds its
	/// compressed form, read with no decoder of P-521.
	#[test]
	fn the_canonical_form_of_the_rfc6979_p521_key_is_its_compressed_form() -> Result<(), Error> {
		let expected = with_point(CURVE_NIST_P521, &TestKey::RFC6979_P521_COMPRESSED).to_der()?;

		let canonical = CanonicalKey::of(&with_point(CURVE_NIST_P521, &TestKey::RFC6979_P521_UNCOMPRESSED))?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// A key on a SEC 2 binary-field curve reads as its bits, so its two forms
	/// are two keys (SEC 1 v2.0 §2.3.3).
	#[test]
	fn a_key_on_a_sec2_binary_curve_in_two_forms_is_two_keys() -> Result<(), Error> {
		let uncompressed = with_point(SECT233K1, &in_form(0x04));
		let compressed = with_point(SECT233K1, compressed().subject_public_key.raw_bytes());

		let uncompressed = CanonicalKey::of(&uncompressed)?;
		assert_ne!(uncompressed, CanonicalKey::of(&compressed)?);
		Ok(())
	}

	/// A key on an X9.62 binary-field curve reads as its bits, so its two
	/// forms are two keys.
	#[test]
	fn a_key_on_an_x962_binary_curve_in_two_forms_is_two_keys() -> Result<(), Error> {
		let uncompressed = with_point(C2PNB163V1, &in_form(0x04));
		let compressed = with_point(C2PNB163V1, compressed().subject_public_key.raw_bytes());

		let uncompressed = CanonicalKey::of(&uncompressed)?;
		assert_ne!(uncompressed, CanonicalKey::of(&compressed)?);
		Ok(())
	}

	/// A key whose canonical form fills the inline bound keeps its whole DER.
	#[test]
	fn a_key_at_the_inline_bound_keeps_its_der() -> Result<(), Error> {
		let edge = edge_key();
		let expected = edge.to_der()?;

		let canonical = CanonicalKey::of(&edge)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// A key whose canonical form exceeds the inline bound keeps its whole DER
	/// as its canonical form.
	#[test]
	fn a_key_past_the_inline_bound_keeps_its_der() -> Result<(), Error> {
		let long = long_key();
		let expected = long.to_der()?;

		let canonical = CanonicalKey::of(&long)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}

	/// A key index finds the key it holds by the point in its other SEC 1 form.
	#[test]
	fn an_index_finds_a_key_by_its_point_in_the_other_form() -> Result<(), Error> {
		let compressed = compressed();
		let uncompressed = uncompressed();
		let mut index = KeyIndex::default();
		index.insert(&compressed, ())?;

		let found = index.find(&uncompressed);
		assert_eq!(found, Some(&()));
		Ok(())
	}

	/// A key index finds no key by the negation of the point it holds.
	#[test]
	fn an_index_finds_no_key_by_the_negation_of_its_point() -> Result<(), Error> {
		let negated = negated();
		let uncompressed = uncompressed();
		let mut index = KeyIndex::default();
		index.insert(&uncompressed, ())?;

		let found = index.find(&negated);
		assert_eq!(found, None);
		Ok(())
	}

	/// A key index returns the value that the key it indexes again, in its
	/// other SEC 1 form, held before.
	#[test]
	fn an_index_returns_the_value_it_replaces() -> Result<(), Error> {
		let mut index = KeyIndex::default();
		index.insert(&uncompressed(), "first")?;

		let replaced = index.insert(&compressed(), "second")?;
		assert_eq!(replaced, Some("first"));
		Ok(())
	}

	/// A key index removes the key it holds by the point in its other SEC 1
	/// form, and returns its value.
	#[test]
	fn an_index_removes_a_key_by_its_point_in_the_other_form() -> Result<(), Error> {
		let mut index = KeyIndex::default();
		index.insert(&uncompressed(), "enrolled")?;

		let removed = index.remove(&compressed());
		assert_eq!(removed, Some("enrolled"));
		Ok(())
	}

	/// A key index reads the key it inserts under its own curves, so an index
	/// with no decoder of secp256k1 reads an off-curve alias as the point it
	/// names, and finds that point by it.
	#[test]
	fn an_index_reads_the_key_it_inserts_under_its_own_curves() -> Result<(), Error> {
		let mut index = KeyIndex::new(NO_DECODER);
		index.insert(&off_curve_alias(), ())?;

		let found = index.find(&uncompressed());
		assert_eq!(found, Some(&()));
		Ok(())
	}

	/// A point and its negation share an x-coordinate and are two keys.
	#[test]
	fn a_point_and_its_negation_are_two_keys() -> Result<(), Error> {
		let negated = negated();
		let uncompressed = uncompressed();

		let negated = KeyIdentity::of(&negated, KeyCurves::HOUSE).to_canonical()?;
		assert_ne!(negated, KeyIdentity::of(&uncompressed, KeyCurves::HOUSE).to_canonical()?);
		Ok(())
	}

	/// One point encoding under P-256 and under P-384 reads by its form under
	/// each, so the named curve alone separates the two keys.
	#[test]
	fn one_encoding_on_two_curves_is_two_keys() -> Result<(), Error> {
		let p256 = on_curve(CURVE_NIST_P256);
		let p384 = on_curve(CURVE_NIST_P384);

		let p256 = KeyIdentity::of(&p256, KeyCurves::HOUSE).to_canonical()?;
		assert_ne!(p256, KeyIdentity::of(&p384, KeyCurves::HOUSE).to_canonical()?);
		Ok(())
	}

	/// A key holds no point of its negation, whose x-coordinate it shares.
	#[test]
	fn a_key_holds_no_point_of_its_negation() {
		let negated = negated();
		let uncompressed = uncompressed();

		let bits = negated.subject_public_key.raw_bytes();
		assert!(!KeyIdentity::of(&uncompressed, KeyCurves::HOUSE).holds(bits));
	}

	/// The key holds its point in the other form, the octets a pin names.
	#[test]
	fn a_key_holds_its_point_in_the_other_form() {
		let compressed = compressed();
		let uncompressed = uncompressed();

		let bits = compressed.subject_public_key.raw_bytes();
		assert!(KeyIdentity::of(&uncompressed, KeyCurves::HOUSE).holds(bits));
	}

	/// A key reads a pin under the curves it was read under, so a key read
	/// with no decoder of secp256k1 holds an off-curve alias of its point.
	#[test]
	fn a_key_reads_a_pin_under_its_own_curves() {
		let alias = off_curve_alias();
		let uncompressed = uncompressed();

		let bits = alias.subject_public_key.raw_bytes();
		assert!(KeyIdentity::of(&uncompressed, NO_DECODER).holds(bits));
	}

	/// A key of another algorithm reads its BIT STRING whole, so the octets
	/// of its point in another form name another key.
	#[test]
	fn a_key_of_another_algorithm_holds_its_bits_alone() {
		let compressed = compressed();
		let mut other = uncompressed();
		other.algorithm.oid = ID_ED_25519;

		let bits = compressed.subject_public_key.raw_bytes();
		assert!(!KeyIdentity::of(&other, KeyCurves::HOUSE).holds(bits));
	}

	/// A key of another algorithm holds the octets of its own BIT STRING.
	#[test]
	fn a_key_of_another_algorithm_holds_its_own_bits() {
		let ed25519 = under(ID_ED_25519);

		let bits = ed25519.subject_public_key.raw_bytes();
		assert!(KeyIdentity::of(&ed25519, KeyCurves::HOUSE).holds(bits));
	}

	/// An encoding of the x-coordinate and the y parity of the fixed key that
	/// is no point of its curve reads as its bits, so it is another key (SEC 1
	/// v2.0 §2.3.4).
	#[test]
	fn an_off_curve_alias_of_a_point_is_another_key() -> Result<(), Error> {
		let alias = off_curve_alias();
		let uncompressed = uncompressed();

		let alias = KeyIdentity::of(&alias, KeyCurves::HOUSE).to_canonical()?;
		assert_ne!(alias, KeyIdentity::of(&uncompressed, KeyCurves::HOUSE).to_canonical()?);
		Ok(())
	}

	/// One bit string under Ed25519 and under X25519 is two keys, which the
	/// algorithm OID alone separates (RFC 8410 §3).
	#[test]
	fn one_bit_string_under_two_algorithms_is_two_keys() -> Result<(), Error> {
		let signing = under(ID_ED_25519);
		let agreement = under(ID_X_25519);

		let signing = KeyIdentity::of(&signing, KeyCurves::HOUSE).to_canonical()?;
		assert_ne!(signing, KeyIdentity::of(&agreement, KeyCurves::HOUSE).to_canonical()?);
		Ok(())
	}

	/// An uncompressed point whose two halves differ in length holds no x and
	/// y of one field, so it is no point.
	#[test]
	fn an_uncompressed_point_of_uneven_halves_is_no_point() {
		let uneven = [in_form(0x04), vec![0]].concat();
		assert_eq!(Sec1Point::read(&uneven), None);
	}

	/// RFC 5480 §2.2 refuses the hybrid form, so its octet `0x06` names no
	/// point.
	#[test]
	fn a_hybrid_point_of_even_y_is_no_point() {
		let hybrid = in_form(0x06);
		assert_eq!(Sec1Point::read(&hybrid), None);
	}

	/// RFC 5480 §2.2 refuses the hybrid form, so its octet `0x07` names no
	/// point.
	#[test]
	fn a_hybrid_point_of_odd_y_is_no_point() {
		let hybrid = in_form(0x07);
		assert_eq!(Sec1Point::read(&hybrid), None);
	}

	/// RFC 5480 §2.2 refuses the compact form, so a key in it reads as its
	/// bits and keeps its DER.
	#[test]
	fn a_compact_point_keeps_its_der() -> Result<(), Error> {
		let compact = compact();
		let expected = compact.to_der()?;

		let canonical = CanonicalKey::of(&compact)?;
		assert_eq!(canonical.as_der(), expected.as_slice());
		Ok(())
	}
}

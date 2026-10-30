//! X25519 (RFC 7748) as an outside crate brings it, through `x25519-dalek`.
//!
//! [`X25519`] reads two kinds of static key: an `id-X25519` key, and an
//! `id-Ed25519` key through the birational map of RFC 7748 §4.1, because one
//! scalar serves both. It compares a share with a static key by the
//! u-coordinate each decodes to, and it refuses an all-zero agreement
//! (RFC 8446 §7.4.2).

use core::marker::PhantomData;
use std::error::Error;

use x25519_dalek::{PublicKey, StaticSecret};

use tightbeam::crypto::exchange::{KeyExchange, KeyExchangeError, KeyShare, ReplyKind};
use tightbeam::crypto::k256::elliptic_curve::bigint::modular::constant_mod::Residue;
use tightbeam::crypto::k256::elliptic_curve::bigint::{impl_modulus, Encoding, U256};
use tightbeam::crypto::k256::sha2::{Digest, Sha512};
use tightbeam::crypto::profiles::SecurityStrength;
use tightbeam::crypto::secret::SecretSlice;
use tightbeam::der::asn1::{BitStringRef, ObjectIdentifier};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::oids::CURVE_X25519;
use tightbeam::random::CryptoRngCore;
use tightbeam::spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoRef};
use tightbeam::testing::unhex;
use tightbeam::transport::handshake::HandshakeError;
use tightbeam::zeroize::ZeroizeOnDrop;

use super::{cms_opens, hello_carrying, hpke_opens, hpke_pair, p384_identity, OnP384, PublishedDraw, CONTENT};

/// `id-Ed25519` (RFC 8410 §3).
const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

/// RFC 7748 §6.1: Alice's scalar.
const RFC_7748_ALICE_SCALAR: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";

/// RFC 7748 §6.1: Alice's public key.
const RFC_7748_ALICE_PUBLIC: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";

/// RFC 7748 §6.1: Bob's scalar.
const RFC_7748_BOB_SCALAR: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";

/// RFC 7748 §6.1: Bob's public key.
const RFC_7748_BOB_PUBLIC: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";

/// RFC 7748 §6.1: the shared secret of Alice and Bob.
const RFC_7748_SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

/// RFC 8032 §7.1, TEST 1: the secret key of Ed25519.
const RFC_8032_TEST_1_SECRET: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// RFC 8032 §7.1, TEST 1: the public key of Ed25519.
const RFC_8032_TEST_1_PUBLIC: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

impl_modulus!(
	Curve25519Prime,
	U256,
	"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

/// An element of the field of curve25519, modulo 2^255 - 19.
type FieldElement = Residue<Curve25519Prime, { U256::LIMBS }>;

/// The canonical u-coordinate of a curve25519 point, as X25519 compares one
/// share with one static key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MontgomeryU([u8; 32]);

impl MontgomeryU {
	/// `octets` with the top bit of its last octet cleared, the bit RFC 7748
	/// §5 masks from a u-coordinate and RFC 8032 §5.1.3 reads as the sign of x.
	fn masked(octets: &[u8; 32]) -> [u8; 32] {
		let mut masked = *octets;
		if let Some(last) = masked.last_mut() {
			*last &= 0x7f;
		}

		masked
	}

	/// The u-coordinate of the X25519 octets `octets`: the top bit masked, and
	/// the value reduced modulo the prime (RFC 7748 §5).
	fn of_x25519(octets: &[u8; 32]) -> Self {
		let reduced = FieldElement::new(&U256::from_le_slice(&Self::masked(octets)));
		Self(reduced.retrieve().to_le_bytes())
	}

	/// The u-coordinate of the curve25519 point that the edwards25519 key
	/// `key` maps to, u = (1 + y) / (1 - y) (RFC 7748 §4.1). `y` is the key
	/// with its sign bit cleared (RFC 8032 §5.1.3). The result is `None` for a
	/// `y` at or above the prime, and for the `y` of the identity.
	fn of_ed25519(key: &[u8; 32]) -> Option<Self> {
		let y = U256::from_le_slice(&Self::masked(key));
		let element = FieldElement::new(&y);
		if element.retrieve() != y {
			return None;
		}

		let (inverse, invertible) = (FieldElement::ONE - element).invert();
		if !bool::from(invertible) {
			return None;
		}

		let u = (FieldElement::ONE + element) * inverse;
		Some(Self(u.retrieve().to_le_bytes()))
	}
}

/// How the responder of [`X25519`] answers an offer.
pub(super) trait Answer: Default + Copy + Send + Sync + 'static {
	/// Answers `offer` with a share drawn from `rng`, beside the secret.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Refused`] -- the agreement is all zeros.
	fn answer(
		offer: &X25519Share,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(X25519Share, SecretSlice<u8>), KeyExchangeError>;
}

/// The responder draws a fresh scalar, as an honest server does.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct Honest;

impl Answer for Honest {
	fn answer(
		offer: &X25519Share,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(X25519Share, SecretSlice<u8>), KeyExchangeError> {
		let secret = StaticSecret::random_from_rng(rng);
		let reply = X25519Share(PublicKey::from(&secret));
		let shared = X25519Pending(secret).agreed_with(offer)?;
		Ok((reply, shared))
	}
}

/// The responder answers with u = 0, a point of small order, as a hostile
/// server does, and keeps an all-zero secret.
#[derive(Debug, Default, Clone, Copy)]
struct SmallOrder;

impl Answer for SmallOrder {
	fn answer(
		_offer: &X25519Share,
		_rng: &mut dyn CryptoRngCore,
	) -> Result<(X25519Share, SecretSlice<u8>), KeyExchangeError> {
		let reply = X25519Share(PublicKey::from([0u8; 32]));
		Ok((reply, SecretSlice::from(vec![0u8; 32])))
	}
}

/// X25519 (RFC 7748 §5) in the shape of a KEM, as an outside crate writes it,
/// whose responder answers as `A` does.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct X25519<A = Honest>(PhantomData<fn() -> A>);

impl<A: Answer> AssociatedOid for X25519<A> {
	const OID: ObjectIdentifier = CURVE_X25519;
}

/// One share of [`X25519`]: the 32 octets of a u-coordinate.
pub(super) struct X25519Share(PublicKey);

/// What the initiator of [`X25519`] holds: its scalar, which `x25519-dalek`
/// wipes where it drops.
pub(super) struct X25519Pending(StaticSecret);

impl ZeroizeOnDrop for X25519Pending {}

/// The opening form is the provided one, which matches the `id-X25519` key
/// of RFC 8410 §3.
impl<A: Answer> KeyShare<X25519<A>> for X25519Share {
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let width = KeyExchangeError::Width { expected: 32, actual: octets.len() };
		let u: [u8; 32] = octets.try_into().map_err(|_| width)?;
		Ok(Self(PublicKey::from(u)))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// X25519 reads the u-coordinate alone, so a point and its negation agree
	/// alike, and so do two encodings of one u.
	fn collapses_into(&self, key: &MontgomeryU) -> bool {
		MontgomeryU::of_x25519(self.0.as_bytes()) == *key
	}
}

impl<A: Answer> KeyExchange for X25519<A> {
	type Offer = X25519Share;
	type Reply = X25519Share;
	type Pending = X25519Pending;
	type StaticKey = MontgomeryU;

	const REPLY: ReplyKind = ReplyKind::Dh;

	/// RFC 7748 §1 gives X25519 a security level of about 128 bits.
	fn strength() -> SecurityStrength {
		SecurityStrength::BITS_128
	}

	fn offer(rng: &mut dyn CryptoRngCore) -> (X25519Pending, X25519Share) {
		let secret = StaticSecret::random_from_rng(rng);
		let offer = X25519Share(PublicKey::from(&secret));
		(X25519Pending(secret), offer)
	}

	fn respond(
		offer: &X25519Share,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(X25519Share, SecretSlice<u8>), KeyExchangeError> {
		A::answer(offer, rng)
	}

	fn complete(pending: &X25519Pending, reply: &X25519Share) -> Result<SecretSlice<u8>, KeyExchangeError> {
		pending.agreed_with(reply)
	}

	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<MontgomeryU> {
		let key: &[u8; 32] = spki.subject_public_key.as_bytes()?.try_into().ok()?;
		let algorithm = spki.algorithm.oid;
		if algorithm == CURVE_X25519 {
			Some(MontgomeryU::of_x25519(key))
		} else if algorithm == ID_ED25519 {
			MontgomeryU::of_ed25519(key)
		} else {
			None
		}
	}
}

impl X25519Pending {
	/// The agreement of this scalar with `share`.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Refused`] -- the agreement is all zeros, as a
	///   share of small order gives (RFC 8446 §7.4.2).
	fn agreed_with(&self, share: &X25519Share) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let shared = self.0.diffie_hellman(&share.0);
		if !shared.was_contributory() {
			return Err(KeyExchangeError::Refused);
		}

		Ok(SecretSlice::from(shared.as_bytes().to_vec()))
	}
}

/// The SPKI of `algorithm` over `key`, with no parameters.
fn spki_of(algorithm: ObjectIdentifier, key: &[u8]) -> Result<SubjectPublicKeyInfoRef<'_>, Box<dyn Error>> {
	let subject_public_key = BitStringRef::from_bytes(key)?;
	let algorithm = AlgorithmIdentifierRef { oid: algorithm, parameters: None };
	Ok(SubjectPublicKeyInfoRef { algorithm, subject_public_key })
}

/// The X25519 key of the Ed25519 secret key of RFC 8032 §7.1 TEST 1: the key
/// of its scalar, the first half of SHA-512 over the secret key, which X25519
/// clamps as Ed25519 does (RFC 8032 §5.1.5).
fn rfc_8032_test_1_x25519_key() -> Result<PublicKey, Box<dyn Error>> {
	let digest = Sha512::digest(unhex(RFC_8032_TEST_1_SECRET));
	let scalar: [u8; 32] = digest[..32].try_into()?;
	Ok(PublicKey::from(&StaticSecret::from(scalar)))
}

/// Alice offers and Bob responds under the scalars of RFC 7748 §6.1. Each
/// share is the public key the vector names, and both ends derive its shared
/// secret.
#[test]
fn x25519_runs_the_vector_of_rfc_7748() -> Result<(), KeyExchangeError> {
	let (pending, offer) = <X25519>::offer(&mut PublishedDraw(unhex(RFC_7748_ALICE_SCALAR)));
	let (reply, responder) = <X25519>::respond(&offer, &mut PublishedDraw(unhex(RFC_7748_BOB_SCALAR)))?;
	let initiator = <X25519>::complete(&pending, &reply)?;

	let octets = <X25519Share as KeyShare<X25519>>::to_octets;
	let shares = (octets(&offer), octets(&reply));
	assert_eq!(shares, (unhex(RFC_7748_ALICE_PUBLIC), unhex(RFC_7748_BOB_PUBLIC)));

	let initiator = initiator.with(|secret| secret.to_vec());
	let responder = responder.with(|secret| secret.to_vec());
	assert_eq!((initiator, responder), (unhex(RFC_7748_SHARED), unhex(RFC_7748_SHARED)));
	Ok(())
}

/// The `id-Ed25519` key of RFC 8032 §7.1 TEST 1 reads as the X25519 key of
/// its own scalar.
#[test]
fn an_ed25519_key_reads_as_the_x25519_key_of_its_scalar() -> Result<(), Box<dyn Error>> {
	let public = unhex(RFC_8032_TEST_1_PUBLIC);
	let x25519_key = rfc_8032_test_1_x25519_key()?;

	let read = <X25519>::static_key(spki_of(ID_ED25519, &public)?);
	assert_eq!(read, Some(MontgomeryU::of_x25519(x25519_key.as_bytes())));
	Ok(())
}

/// A share of the X25519 key of an Ed25519 static key collapses into that
/// static key, with the top bit of its last octet clear or set, because
/// RFC 7748 §5 masks that bit.
#[test]
fn a_share_of_an_ed25519_static_collapses_in_either_encoding() -> Result<(), Box<dyn Error>> {
	let public = unhex(RFC_8032_TEST_1_PUBLIC);
	let x25519_key = rfc_8032_test_1_x25519_key()?;
	let read = <X25519>::static_key(spki_of(ID_ED25519, &public)?).ok_or("the key maps to a u-coordinate")?;
	let mut top_bit_set = x25519_key.to_bytes();
	top_bit_set[31] |= 0x80;

	let plain = X25519Share(x25519_key);
	let masked = <X25519Share as KeyShare<X25519>>::from_octets(&top_bit_set)?;

	let collapses = <X25519Share as KeyShare<X25519>>::collapses_into;
	assert_eq!((collapses(&plain, &read), collapses(&masked, &read)), (true, true));
	Ok(())
}

/// A hello whose share is u = 0, a point of small order, gives an all-zero
/// agreement, so the server refuses it (RFC 8446 §7.4.2).
#[tokio::test]
async fn a_server_refuses_an_x25519_share_of_small_order() -> Result<(), Box<dyn Error>> {
	let (mut client, mut server) = hpke_pair::<OnP384<X25519>>(p384_identity());
	let hello = hello_carrying(client.start()?, &[0u8; 32])?;

	let refused = server.reply(hello).await;
	assert!(matches!(refused, Err(HandshakeError::KeyExchange(KeyExchangeError::Refused))));
	Ok(())
}

/// A server that answers with u = 0 signs a reply whose agreement is all
/// zeros, so the client refuses it at `complete` (RFC 8446 §7.4.2).
#[tokio::test]
async fn a_client_refuses_an_x25519_reply_of_small_order() -> Result<(), Box<dyn Error>> {
	let (mut client, mut server) = hpke_pair::<OnP384<X25519<SmallOrder>>>(p384_identity());
	let reply = server.reply(client.start()?).await?;

	let refused = client.respond(reply).await;
	assert!(matches!(refused, Err(HandshakeError::KeyExchange(KeyExchangeError::Refused))));
	Ok(())
}

/// The HPKE flow runs under X25519.
#[tokio::test]
async fn x25519_runs_the_hpke_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(hpke_opens::<OnP384<X25519>>().await?, CONTENT);
	Ok(())
}

/// The CMS flow runs under X25519.
#[tokio::test]
async fn x25519_runs_the_cms_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(cms_opens::<OnP384<X25519>>().await?, CONTENT);
	Ok(())
}

/// A session under X25519 renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn x25519_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::super::renewal::renews_its_epoch::<OnP384<X25519>>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

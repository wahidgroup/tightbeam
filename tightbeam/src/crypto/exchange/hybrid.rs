//! The hybrid of a post-quantum KEM and a classical exchange, in the exchange
//! role.
//!
//! A hybrid is a KEM (NIST SP 800-227 §4.6). It runs both parts on each share
//! and derives one secret from both, so the secret holds while either part
//! holds.
//!
//! - Each share is the post-quantum share, then the classical share, each at its fixed width.
//! - A share collapses into a static key of its classical part, whose static keys the hybrid reads.
//! - The reply travels in the CMS Finished as a `KemCiphertext` under the identifier of the pairing.
//!
//! # Combiner
//!
//! The combiner is the one-step key derivation of NIST SP 800-56C Rev. 2 §4.1
//! over SHA3-256, with the post-quantum secret as `Z` and the classical secret
//! as the auxiliary `T` of its §2. The fixed info binds the label, the pairing,
//! and both shares of both parts:
//!
//! ```text
//! secret = SHA3-256(00000001 || ss_pq || ss_classical
//!                   || TIGHTBEAM_HYBRID_EXCHANGE_LABEL || DER(pairing OID) || offer || reply)
//! ```
//!
//! Each share has the width its `FixedWidthShare` states, each secret has one
//! width by the contract of `KeyExchange`, and the DER of the OID delimits
//! itself, so the input parses one way.
//!
//! # Sources
//!
//! - NIST SP 800-227 (September 2025), §4.6, multi-algorithm KEMs and the binding a combiner needs.
//! - NIST SP 800-56C Rev. 2 (August 2020), §2, the secret `Z′ = Z || T`, and §4.1, the one-step KDF.
//! - FIPS 202 (August 2015), SHA3-256.

use core::cmp::max;
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::constants::TIGHTBEAM_HYBRID_EXCHANGE_LABEL;
use crate::crypto::exchange::{Ecdhe, FixedWidthShare, KeyExchange, KeyExchangeError, KeyShare, MlKem768, ReplyKind};
use crate::crypto::hash::Sha3_256;
use crate::crypto::k256::Secp256k1;
use crate::crypto::kdf::ZeroizingHash;
use crate::crypto::profiles::SecurityStrength;
use crate::crypto::secret::SecretSlice;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::der::Encode;
use crate::oids::KEM_SECP256K1_ML_KEM_768;
use crate::random::CryptoRngCore;
use crate::spki::SubjectPublicKeyInfoRef;
use crate::zeroize::ZeroizeOnDrop;

/// The counter of the one block that the one-step key derivation of NIST
/// SP 800-56C Rev. 2 §4.1 hashes for a 256-bit secret.
const ONE_STEP_COUNTER: [u8; 4] = 1u32.to_be_bytes();

/// A post-quantum exchange paired with a classical one, under the identifier
/// the pairing negotiates as. An outside crate names a pairing of its own with
/// a marker type of its own.
///
/// Each part keeps the contract of [`KeyExchange`], so its secret has one
/// width, and its shares state their widths through [`FixedWidthShare`].
pub trait HybridPair: AssociatedOid + Send + Sync + 'static {
	/// The post-quantum part, whose share leads each share of the hybrid and
	/// whose secret is the `Z` of the combiner.
	type PostQuantum: KeyExchange<Offer: FixedWidthShare, Reply: FixedWidthShare>;
	/// The classical part, whose static keys each share of the hybrid is
	/// compared with.
	type Classical: KeyExchange<Offer: FixedWidthShare, Reply: FixedWidthShare>;
}

/// The house pairing: ML-KEM-768 with ECDH over secp256k1, under
/// [`KEM_SECP256K1_ML_KEM_768`]. It rates 192 bits.
#[derive(Debug, Default, Clone, Copy)]
pub struct Secp256k1MlKem768;

impl AssociatedOid for Secp256k1MlKem768 {
	const OID: ObjectIdentifier = KEM_SECP256K1_ML_KEM_768;
}

impl HybridPair for Secp256k1MlKem768 {
	type PostQuantum = MlKem768;
	type Classical = Ecdhe<Secp256k1>;
}

/// The hybrid exchange of the pairing `P`. Its OID is the OID of `P`.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::exchange::{Hybrid, KeyExchange, Secp256k1MlKem768};
/// use tightbeam::random::OsRng;
///
/// type Exchange = Hybrid<Secp256k1MlKem768>;
///
/// let (pending, offer) = Exchange::offer(&mut OsRng);
/// let (reply, responder) = Exchange::respond(&offer, &mut OsRng)?;
/// let initiator = Exchange::complete(&pending, &reply)?;
///
/// assert!(initiator.with(|secret| responder.with(|other| secret == other)));
/// # Ok::<(), tightbeam::crypto::exchange::KeyExchangeError>(())
/// ```
pub struct Hybrid<P>(PhantomData<fn() -> P>);

impl<P: HybridPair> AssociatedOid for Hybrid<P> {
	const OID: ObjectIdentifier = P::OID;
}

/// One share of the [`Hybrid`] of the pairing `P`: the share `Q` of its
/// post-quantum part, then the share `C` of its classical part.
pub struct HybridShare<P, Q, C> {
	post_quantum: Q,
	classical: C,
	pairing: PhantomData<fn() -> P>,
}

impl<P, Q: FixedWidthShare, C: FixedWidthShare> HybridShare<P, Q, C> {
	/// The width of a share of both parts, in bytes.
	const WIDTH: usize = Q::WIDTH.saturating_add(C::WIDTH);

	/// The share of both parts.
	fn of(post_quantum: Q, classical: C) -> Self {
		Self { post_quantum, classical, pairing: PhantomData }
	}
}

impl<P, Q, C> KeyShare<Hybrid<P>> for HybridShare<P, Q, C>
where
	P: HybridPair,
	Q: KeyShare<P::PostQuantum> + FixedWidthShare,
	C: KeyShare<P::Classical> + FixedWidthShare,
{
	/// Each part parses under its own exchange, at its fixed width.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let refused = KeyExchangeError::Width { expected: Self::WIDTH, actual: octets.len() };
		let (post_quantum, classical) = octets.split_at_checked(Q::WIDTH).ok_or(refused)?;
		if classical.len() != C::WIDTH {
			return Err(refused);
		}

		let post_quantum = Q::from_octets(post_quantum)?;
		let classical = C::from_octets(classical)?;
		Ok(Self::of(post_quantum, classical))
	}

	fn to_octets(&self) -> Vec<u8> {
		[self.post_quantum.to_octets(), self.classical.to_octets()].concat()
	}

	/// The classical part alone can collapse into a static key of its sender.
	fn collapses_into(&self, key: &<P::Classical as KeyExchange>::StaticKey) -> bool {
		self.classical.collapses_into(key)
	}
}

/// What the initiator of a [`Hybrid`] holds to its completion: the pending
/// state of each part, and the octets of its offer, which the combiner binds.
pub struct HybridPending<P: HybridPair> {
	post_quantum: <P::PostQuantum as KeyExchange>::Pending,
	classical: <P::Classical as KeyExchange>::Pending,
	offer: Vec<u8>,
}

/// The pending state of each part wipes where it drops, and the offer is
/// public.
impl<P: HybridPair> ZeroizeOnDrop for HybridPending<P> {}

impl<P: HybridPair> KeyExchange for Hybrid<P> {
	type Offer = HybridShare<P, <P::PostQuantum as KeyExchange>::Offer, <P::Classical as KeyExchange>::Offer>;
	type Reply = HybridShare<P, <P::PostQuantum as KeyExchange>::Reply, <P::Classical as KeyExchange>::Reply>;
	type Pending = HybridPending<P>;
	type StaticKey = <P::Classical as KeyExchange>::StaticKey;

	/// A hybrid is a KEM, whatever kind each part is (NIST SP 800-227 §4.6).
	const REPLY: ReplyKind = ReplyKind::Kem;

	/// The combiner binds both shares of each part, so the hybrid rates at its
	/// stronger part (NIST SP 800-227 §4.6.3).
	fn strength() -> SecurityStrength {
		max(P::PostQuantum::strength(), P::Classical::strength())
	}

	fn offer(rng: &mut dyn CryptoRngCore) -> (HybridPending<P>, Self::Offer) {
		let (post_quantum_pending, post_quantum) = P::PostQuantum::offer(rng);
		let (classical_pending, classical) = P::Classical::offer(rng);
		let offer = HybridShare::of(post_quantum, classical);

		let octets = offer.to_octets();
		let pending = HybridPending { post_quantum: post_quantum_pending, classical: classical_pending, offer: octets };
		(pending, offer)
	}

	fn respond(
		offer: &Self::Offer,
		rng: &mut dyn CryptoRngCore,
	) -> Result<(Self::Reply, SecretSlice<u8>), KeyExchangeError> {
		let (post_quantum, post_quantum_secret) = P::PostQuantum::respond(&offer.post_quantum, rng)?;
		let (classical, classical_secret) = P::Classical::respond(&offer.classical, rng)?;

		let reply = HybridShare::of(post_quantum, classical);
		let secret = Self::combine(&post_quantum_secret, &classical_secret, &offer.to_octets(), &reply.to_octets())?;
		Ok((reply, secret))
	}

	fn complete(pending: &HybridPending<P>, reply: &Self::Reply) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let post_quantum_secret = P::PostQuantum::complete(&pending.post_quantum, &reply.post_quantum)?;
		let classical_secret = P::Classical::complete(&pending.classical, &reply.classical)?;
		Self::combine(&post_quantum_secret, &classical_secret, &pending.offer, &reply.to_octets())
	}

	fn static_key(spki: SubjectPublicKeyInfoRef<'_>) -> Option<Self::StaticKey> {
		P::Classical::static_key(spki)
	}
}

impl<P: HybridPair> Hybrid<P> {
	/// The secret of both parts: SHA3-256 over the counter, `post_quantum`
	/// and `classical` as the hybrid secret, then the label, the DER of the
	/// pairing's OID, `offer`, and `reply` as the fixed info. The hash wipes
	/// its state and its buffered input where it drops, and so does the digest.
	///
	/// # Errors
	///
	/// - [`KeyExchangeError::Encoding`] -- the OID of the pairing fails to encode.
	fn combine(
		post_quantum: &SecretSlice<u8>,
		classical: &SecretSlice<u8>,
		offer: &[u8],
		reply: &[u8],
	) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let pairing = P::OID.to_der().map_err(|_| KeyExchangeError::Encoding)?;

		let mut hasher = ZeroizingHash::<Sha3_256>::new();
		hasher.update(&ONE_STEP_COUNTER);
		post_quantum.with(|secret| hasher.update(secret));
		classical.with(|secret| hasher.update(secret));
		hasher.update(TIGHTBEAM_HYBRID_EXCHANGE_LABEL);
		hasher.update(&pairing);
		hasher.update(offer);
		hasher.update(reply);

		let digest = hasher.finalize();
		let secret = SecretSlice::from(digest.as_slice().to_vec());
		Ok(secret)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::crypto::exchange::tests::{fresh_point, octets_of};
	use crate::crypto::exchange::{EcdheShare, KemCiphertext, ReplyAttribute};
	use crate::crypto::hash::Digest;
	use crate::der::asn1::OctetString;
	use crate::der::referenced::OwnedToRef;
	use crate::random::OsRng;
	use crate::spki::{AlgorithmIdentifierOwned, Error as SpkiError, SubjectPublicKeyInfoOwned};
	use crate::testing::vectors::ml_kem::ML_KEM_768;
	use crate::testing::{unhex, PublishedDraw};

	/// The house hybrid.
	type HouseHybrid = Hybrid<Secp256k1MlKem768>;

	/// The offer of the house hybrid.
	type HouseOffer = <HouseHybrid as KeyExchange>::Offer;

	/// The secret of [`the_house_hybrid_derives_its_known_secret`].
	const KNOWN_HOUSE_HYBRID_SECRET: &str = "b4fe42825fe5f6710bd2a7f5550419b856c00a2201b45ad68b98eebf4410d7ca";

	/// A pairing of the parts of the house pairing, under another identifier.
	struct Renamed;

	impl AssociatedOid for Renamed {
		const OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.99");
	}

	impl HybridPair for Renamed {
		type PostQuantum = MlKem768;
		type Classical = Ecdhe<Secp256k1>;
	}

	#[test]
	fn both_ends_of_a_hybrid_derive_one_secret() -> Result<(), KeyExchangeError> {
		let (pending, offer) = HouseHybrid::offer(&mut OsRng);
		let (reply, responder) = HouseHybrid::respond(&offer, &mut OsRng)?;
		let initiator = HouseHybrid::complete(&pending, &reply)?;

		let equal = initiator.with(|secret| responder.with(|other| secret == other));
		assert!(equal);
		Ok(())
	}

	/// Each share is the ML-KEM-768 share, then the compressed secp256k1
	/// point: 1184 and 33 octets in the offer, 1088 and 33 in the reply.
	#[test]
	fn a_share_is_the_post_quantum_share_then_the_classical_share() -> Result<(), KeyExchangeError> {
		let (_pending, offer) = HouseHybrid::offer(&mut OsRng);
		let (reply, _secret) = HouseHybrid::respond(&offer, &mut OsRng)?;
		let parts = [offer.post_quantum.to_octets(), offer.classical.to_octets()].concat();

		let widths = (offer.to_octets().len(), reply.to_octets().len());
		assert_eq!((offer.to_octets(), widths), (parts, (1217, 1121)));
		Ok(())
	}

	/// A share of another width is refused at the width of both parts, and a
	/// share with a malformed part is refused by that part: an ML-KEM key
	/// whose first coefficient is at or above the modulus (FIPS 203 §7.2), and
	/// a point in the compact form.
	#[test]
	fn a_share_of_another_width_or_a_malformed_part_is_refused() {
		let (_pending, offer) = HouseHybrid::offer(&mut OsRng);
		let octets = offer.to_octets();
		let short = octets.get(1..).unwrap_or_default().to_vec();
		let mut above_modulus = octets.clone();
		above_modulus[0] = 0xff;
		above_modulus[1] |= 0x0f;

		let mut compact = octets;
		compact[1184] = 0x05;

		let refused = [&short, &above_modulus, &compact].map(|octets| HouseOffer::from_octets(octets).err());
		let width = KeyExchangeError::Width { expected: 1217, actual: 1216 };
		let malformed = Some(KeyExchangeError::Malformed);
		assert_eq!(refused, [Some(width), malformed, malformed]);
	}

	/// The combiner binds both shares of both parts, so the house hybrid rates
	/// at ML-KEM-768, the stronger part.
	#[test]
	fn the_hybrid_rates_at_its_stronger_part() {
		assert_eq!(HouseHybrid::strength(), SecurityStrength::BITS_192);
	}

	/// The combiner hashes the counter, both secrets, the label, the pairing,
	/// and both shares under SHA3-256, in that order.
	#[test]
	fn the_combiner_hashes_its_inputs_in_order() -> Result<(), Box<dyn std::error::Error>> {
		let post_quantum = SecretSlice::from(vec![0x11; 32]);
		let classical = SecretSlice::from(vec![0x22; 32]);
		let (offer, reply) = ([0x33; 1217], [0x44; 1121]);
		let pairing = KEM_SECP256K1_ML_KEM_768.to_der()?;
		let label = TIGHTBEAM_HYBRID_EXCHANGE_LABEL;

		let combined = HouseHybrid::combine(&post_quantum, &classical, &offer, &reply)?;
		let input = [&[0, 0, 0, 1][..], &[0x11; 32], &[0x22; 32], label, &pairing, &offer, &reply].concat();
		assert_eq!(octets_of(&combined), Sha3_256::digest(&input).to_vec());
		Ok(())
	}

	/// A change to any one input of the combiner, the pairing among them,
	/// changes the secret.
	#[test]
	fn the_combiner_binds_each_input() -> Result<(), KeyExchangeError> {
		let secret = |octet| SecretSlice::from(vec![octet; 32]);
		let (offer, reply) = ([0x33; 1217], [0x44; 1121]);
		let (other_offer, other_reply) = ([0x55; 1217], [0x66; 1121]);
		let base = octets_of(&HouseHybrid::combine(&secret(0x11), &secret(0x22), &offer, &reply)?);

		let post_quantum = octets_of(&HouseHybrid::combine(&secret(0x77), &secret(0x22), &offer, &reply)?);
		let classical = octets_of(&HouseHybrid::combine(&secret(0x11), &secret(0x77), &offer, &reply)?);
		let offered = octets_of(&HouseHybrid::combine(&secret(0x11), &secret(0x22), &other_offer, &reply)?);
		let replied = octets_of(&HouseHybrid::combine(&secret(0x11), &secret(0x22), &offer, &other_reply)?);
		let pairing = octets_of(&Hybrid::<Renamed>::combine(&secret(0x11), &secret(0x22), &offer, &reply)?);
		assert_ne!(post_quantum, base);
		assert_ne!(classical, base);
		assert_ne!(offered, base);
		assert_ne!(replied, base);
		assert_ne!(pairing, base);
		Ok(())
	}

	/// The secret of fixed draws, so a change to the shares or the combiner
	/// fails here. The initiator draws `d` and `z` of the ML-KEM-768 key
	/// generation vector and the secp256k1 scalar `0x11..11`, and the responder
	/// draws `m` of its encapsulation vector and the scalar `0x22..22`.
	#[test]
	fn the_house_hybrid_derives_its_known_secret() -> Result<(), KeyExchangeError> {
		let offer_draw = [unhex(ML_KEM_768.keygen_d), unhex(ML_KEM_768.keygen_z), vec![0x11; 32]].concat();
		let reply_draw = [unhex(ML_KEM_768.encap_m), vec![0x22; 32]].concat();
		let (pending, offer) = HouseHybrid::offer(&mut PublishedDraw(offer_draw));
		let (reply, responder) = HouseHybrid::respond(&offer, &mut PublishedDraw(reply_draw))?;
		let initiator = HouseHybrid::complete(&pending, &reply)?;

		let known = unhex(KNOWN_HOUSE_HYBRID_SECRET);
		assert_eq!((octets_of(&initiator), octets_of(&responder)), (known.clone(), known));
		Ok(())
	}

	/// The classical part alone collapses into a static key: a share whose
	/// point is the sender's key collapses, and a fresh share does not.
	#[test]
	fn a_share_collapses_into_a_static_key_of_its_classical_part() -> Result<(), KeyExchangeError> {
		let key = fresh_point();
		let (_pending, offer) = HouseHybrid::offer(&mut OsRng);
		let collapsing = [offer.post_quantum.to_octets(), EcdheShare::from(key).to_octets()].concat();
		let collapsing = HouseOffer::from_octets(&collapsing)?;

		let collapses = (collapsing.collapses_into(&key), offer.collapses_into(&key));
		assert_eq!(collapses, (true, false));
		Ok(())
	}

	/// The hybrid reads a secp256k1 key as its static key, as its classical
	/// part does.
	#[test]
	fn the_hybrid_reads_the_static_keys_of_its_classical_part() -> Result<(), SpkiError> {
		let key = fresh_point();
		let spki = SubjectPublicKeyInfoOwned::from_key(key)?;
		assert_eq!(HouseHybrid::static_key(spki.owned_to_ref()), Some(key));
		Ok(())
	}

	/// The reply travels in the CMS Finished as a `KemCiphertext` under the
	/// identifier of the pairing, and a reply under the identifier of its
	/// post-quantum part names another algorithm.
	#[test]
	fn a_reply_travels_as_a_kem_ciphertext_under_the_pairing() -> Result<(), Box<dyn std::error::Error>> {
		let (_pending, offer) = HouseHybrid::offer(&mut OsRng);
		let (reply, _secret) = HouseHybrid::respond(&offer, &mut OsRng)?;

		let attribute = ReplyAttribute::of::<HouseHybrid>(&reply)?;
		let ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct }) = attribute else {
			return Err("a hybrid reply travels as a KEM ciphertext".into());
		};

		let carried = (kem.oid, kemct.as_bytes());
		let reply_octets = reply.to_octets();
		assert_eq!(carried, (KEM_SECP256K1_ML_KEM_768, reply_octets.as_slice()));

		let kem = AlgorithmIdentifierOwned { oid: MlKem768::OID, parameters: None };
		let kemct = OctetString::new(reply.to_octets())?;
		let refused = ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct }).reply::<HouseHybrid>();
		assert!(matches!(refused, Err(KeyExchangeError::Algorithm)));
		Ok(())
	}
}

//! ML-KEM (FIPS 203) in the exchange role, through `ml-kem`.
//!
//! The house runs ML-KEM-768 and ML-KEM-1024, and [`MlKemParameterSet`] is
//! sealed to those two. ML-KEM-512 samples its noise with a wider table, which
//! widens the timing exposure that SECURITY.md records for `ml-kem` 0.2.
//!
//! - The initiator's share is an encapsulation key, which passes the modulus check of FIPS 203 §7.2.
//! - The responder's share is a ciphertext, which travels in the CMS Finished as a `KemCiphertext`.
//! - A client's certificate holds a signing key, which produces no offer, so `StaticKey = Infallible`.
//!
//! # Sources
//!
//! - FIPS 203 (August 2024), §7.2 and §7.3, the input checks, and §8, the security categories.
//! - RFC 9935, the ML-KEM algorithm identifiers.

use core::convert::Infallible;
use core::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::common::typenum::Unsigned;
use crate::crypto::exchange::{FixedWidthShare, KeyExchange, KeyExchangeError, KeyShare, ReplyKind};
use crate::crypto::ml_kem;
use crate::crypto::ml_kem::kem::{Decapsulate, Encapsulate};
use crate::crypto::ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore};
use crate::crypto::profiles::SecurityStrength;
use crate::crypto::secret::SecretSlice;
use crate::der::asn1::ObjectIdentifier;
use crate::der::oid::AssociatedOid;
use crate::oids::{KEM_ML_KEM_1024, KEM_ML_KEM_768};
use crate::random::CryptoRngCore;
use crate::spki::SubjectPublicKeyInfoRef;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// A parameter set of ML-KEM that the house exchange runs, with the
/// identifier NIST registers for it and the strength of its category.
pub trait MlKemParameterSet:
	KemCore<DecapsulationKey: ZeroizeOnDrop + Send + Sync + 'static, EncapsulationKey: Send + Sync + 'static>
	+ sealed::Sealed
	+ Send
	+ Sync
	+ 'static
{
	/// The identifier of the parameter set (RFC 9935).
	const OID: ObjectIdentifier;
	/// The strength of the security category of the parameter set
	/// (FIPS 203 §8).
	const STRENGTH: SecurityStrength;
}

/// Category 3, which rates 192 bits.
impl MlKemParameterSet for ml_kem::MlKem768 {
	const OID: ObjectIdentifier = KEM_ML_KEM_768;
	const STRENGTH: SecurityStrength = SecurityStrength::BITS_192;
}

/// Category 5, which rates 256 bits.
impl MlKemParameterSet for ml_kem::MlKem1024 {
	const OID: ObjectIdentifier = KEM_ML_KEM_1024;
	const STRENGTH: SecurityStrength = SecurityStrength::BITS_256;
}

mod sealed {
	use crate::crypto::ml_kem::{MlKem1024, MlKem768};

	/// The parameter sets [`super::MlKemParameterSet`] admits.
	pub trait Sealed {}

	impl Sealed for MlKem768 {}
	impl Sealed for MlKem1024 {}
}

/// ML-KEM (FIPS 203) in the exchange role, over the parameter set `K`. Its
/// OID is the OID of `K`.
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::exchange::{KeyExchange, MlKem768};
/// use tightbeam::random::OsRng;
///
/// let (pending, offer) = MlKem768::offer(&mut OsRng);
/// let (reply, responder) = MlKem768::respond(&offer, &mut OsRng)?;
/// let initiator = MlKem768::complete(&pending, &reply)?;
///
/// assert!(initiator.with(|secret| responder.with(|other| secret == other)));
/// # Ok::<(), tightbeam::crypto::exchange::KeyExchangeError>(())
/// ```
pub struct MlKem<K>(PhantomData<fn() -> K>);

/// ML-KEM-768, of security category 3.
pub type MlKem768 = MlKem<ml_kem::MlKem768>;

/// ML-KEM-1024, of security category 5.
pub type MlKem1024 = MlKem<ml_kem::MlKem1024>;

impl<K: MlKemParameterSet> AssociatedOid for MlKem<K> {
	const OID: ObjectIdentifier = K::OID;
}

/// The initiator's share of [`MlKem`]: an encapsulation key.
pub struct MlKemOffer<K: MlKemParameterSet>(K::EncapsulationKey);

/// The responder's share of [`MlKem`]: a ciphertext.
pub struct MlKemReply<K: MlKemParameterSet>(Ciphertext<K>);

impl<K: MlKemParameterSet> FixedWidthShare for MlKemOffer<K> {
	const WIDTH: usize = <K::EncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
}

impl<K: MlKemParameterSet> FixedWidthShare for MlKemReply<K> {
	const WIDTH: usize = K::CiphertextSize::USIZE;
}

/// The CMS forms are the provided ones: the opening names the key by its
/// identifier, with no parameters.
impl<K: MlKemParameterSet> KeyShare<MlKem<K>> for MlKemOffer<K> {
	/// The key passes the modulus check of FIPS 203 §7.2: it encodes to the
	/// octets it decodes from, so every coefficient is below the modulus.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let refused = KeyExchangeError::Width { expected: Self::WIDTH, actual: octets.len() };
		let encoded = Encoded::<K::EncapsulationKey>::try_from(octets).map_err(|_| refused)?;

		let key = K::EncapsulationKey::from_bytes(&encoded);
		if key.as_bytes() != encoded {
			return Err(KeyExchangeError::Malformed);
		}

		Ok(Self(key))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// [`MlKem`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

/// The reply travels as a `KemCiphertext`, because [`MlKem`] names
/// [`ReplyKind::Kem`].
impl<K: MlKemParameterSet> KeyShare<MlKem<K>> for MlKemReply<K> {
	/// A ciphertext of the width of the parameter set passes the type check of
	/// FIPS 203 §7.3.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let refused = KeyExchangeError::Width { expected: Self::WIDTH, actual: octets.len() };
		let ciphertext = Ciphertext::<K>::try_from(octets).map_err(|_| refused)?;
		Ok(Self(ciphertext))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	/// [`MlKem`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

impl<K: MlKemParameterSet> KeyExchange for MlKem<K> {
	type Offer = MlKemOffer<K>;
	type Reply = MlKemReply<K>;
	type Pending = K::DecapsulationKey;
	type StaticKey = Infallible;

	const REPLY: ReplyKind = ReplyKind::Kem;

	fn strength() -> SecurityStrength {
		K::STRENGTH
	}

	fn offer(mut rng: &mut dyn CryptoRngCore) -> (K::DecapsulationKey, MlKemOffer<K>) {
		let (decapsulation, encapsulation) = K::generate(&mut rng);
		(decapsulation, MlKemOffer(encapsulation))
	}

	fn respond(
		offer: &MlKemOffer<K>,
		mut rng: &mut dyn CryptoRngCore,
	) -> Result<(MlKemReply<K>, SecretSlice<u8>), KeyExchangeError> {
		let encapsulated = offer.0.encapsulate(&mut rng).map_err(|_| KeyExchangeError::Refused)?;
		let (ciphertext, mut shared) = encapsulated;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok((MlKemReply(ciphertext), secret))
	}

	/// A ciphertext that fails the re-encryption check of FIPS 203 §6.3 yields
	/// the implicit rejection key, so the key confirmation of the handshake
	/// refuses it.
	fn complete(pending: &K::DecapsulationKey, reply: &MlKemReply<K>) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let mut shared = pending.decapsulate(&reply.0).map_err(|_| KeyExchangeError::Refused)?;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok(secret)
	}

	fn static_key(_spki: SubjectPublicKeyInfoRef<'_>) -> Option<Infallible> {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::cms::enveloped_data::OriginatorPublicKey;
	use crate::crypto::exchange::tests::{kem_ciphertext_of, octets_of};
	use crate::crypto::exchange::ReplyAttribute;
	use crate::der::Any;
	use crate::oids::CURVE_X25519;
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::fixtures::TestAlgorithm;
	use crate::testing::vectors::ml_kem::{MlKemVectors, ML_KEM_1024, ML_KEM_768};
	use crate::testing::{unhex, PublishedDraw, SeededStream, TestResult};

	/// The decapsulation key of the vector's test group.
	fn decapsulation_key_of<K: MlKemParameterSet>(vectors: &MlKemVectors) -> K::DecapsulationKey {
		let encoded = unhex(vectors.decap_dk);
		let encoded = Encoded::<K::DecapsulationKey>::try_from(encoded.as_slice());
		let encoded = encoded.expect("the vector holds a decapsulation key of its parameter set");
		K::DecapsulationKey::from_bytes(&encoded)
	}

	/// Key generation draws `d`, then `z`, holds the decapsulation key of the
	/// vector, and offers its encapsulation key.
	fn generates_the_keys_of_its_vector<K: MlKemParameterSet>(vectors: &MlKemVectors) {
		let seeds = [unhex(vectors.keygen_d), unhex(vectors.keygen_z)].concat();
		let (pending, offer) = MlKem::<K>::offer(&mut PublishedDraw(seeds));

		let keys = (pending.as_bytes().to_vec(), offer.to_octets());
		assert_eq!(keys, (unhex(vectors.keygen_dk), unhex(vectors.keygen_ek)));
	}

	/// An offer of the vector's key, answered under its message `m`, gives the
	/// ciphertext and the shared key of the vector.
	fn responds_as_its_vector<K: MlKemParameterSet>(vectors: &MlKemVectors) {
		let offer = MlKemOffer::<K>::from_octets(&unhex(vectors.encap_ek));
		let offer = offer.expect("the vector holds an encapsulation key of its parameter set");

		let responded = MlKem::<K>::respond(&offer, &mut PublishedDraw(unhex(vectors.encap_m)));
		let responded = responded.map(|(reply, shared)| (reply.to_octets(), octets_of(&shared)));
		assert_eq!(responded, Ok((unhex(vectors.encap_c), unhex(vectors.encap_k))));
	}

	/// The decapsulation key of the vector completes an unmodified ciphertext
	/// with its shared key.
	fn completes_as_its_vector<K: MlKemParameterSet>(vectors: &MlKemVectors) {
		let pending = decapsulation_key_of::<K>(vectors);
		let reply = MlKemReply::<K>::from_octets(&unhex(vectors.decap_c));
		let reply = reply.expect("the vector holds a ciphertext of its parameter set");

		let shared = MlKem::<K>::complete(&pending, &reply);
		assert_eq!(shared.map(|shared| octets_of(&shared)), Ok(unhex(vectors.decap_k)));
	}

	/// The decapsulation key of the vector completes a modified ciphertext with
	/// its implicit rejection key (FIPS 203 §6.3).
	fn rejects_as_its_vector<K: MlKemParameterSet>(vectors: &MlKemVectors) {
		let pending = decapsulation_key_of::<K>(vectors);
		let reply = MlKemReply::<K>::from_octets(&unhex(vectors.reject_c));
		let reply = reply.expect("the vector holds a ciphertext of its parameter set");

		let rejected = MlKem::<K>::complete(&pending, &reply);
		assert_eq!(rejected.map(|rejected| octets_of(&rejected)), Ok(unhex(vectors.reject_k)));
	}

	/// An encapsulation key whose first coefficient encodes as 4095, at or
	/// above the modulus 3329, fails the modulus check of FIPS 203 §7.2.
	fn refuses_a_key_above_the_modulus<K: MlKemParameterSet>(vectors: &MlKemVectors) {
		let mut key = unhex(vectors.encap_ek);
		key[0] = 0xff;
		key[1] |= 0x0f;

		let refused = MlKemOffer::<K>::from_octets(&key);
		assert!(matches!(refused, Err(KeyExchangeError::Malformed)));
	}

	/// The CMS `agreementKey` of a seeded ML-KEM-768 offer, under `algorithm`.
	fn agreement_key_under(algorithm: AlgorithmIdentifierOwned) -> OriginatorPublicKey {
		let (_pending, offer) = MlKem768::offer(&mut SeededStream(0x10));
		let key = offer.to_originator_key().expect("an ML-KEM offer encodes as an agreement key");
		OriginatorPublicKey { algorithm, ..key }
	}

	/// ML-KEM-768 key generation holds the keys of its vector.
	#[test]
	fn ml_kem_768_generates_the_keys_of_its_vector() {
		generates_the_keys_of_its_vector::<ml_kem::MlKem768>(&ML_KEM_768);
	}

	/// An ML-KEM-768 response matches its vector.
	#[test]
	fn ml_kem_768_responds_as_its_vector() {
		responds_as_its_vector::<ml_kem::MlKem768>(&ML_KEM_768);
	}

	/// An ML-KEM-768 completion matches its vector.
	#[test]
	fn ml_kem_768_completes_as_its_vector() {
		completes_as_its_vector::<ml_kem::MlKem768>(&ML_KEM_768);
	}

	/// An ML-KEM-768 rejection matches its vector.
	#[test]
	fn ml_kem_768_rejects_as_its_vector() {
		rejects_as_its_vector::<ml_kem::MlKem768>(&ML_KEM_768);
	}

	/// ML-KEM-768 refuses a key above the modulus.
	#[test]
	fn ml_kem_768_refuses_a_key_above_the_modulus() {
		refuses_a_key_above_the_modulus::<ml_kem::MlKem768>(&ML_KEM_768);
	}

	/// ML-KEM-1024 key generation holds the keys of its vector.
	#[test]
	fn ml_kem_1024_generates_the_keys_of_its_vector() {
		generates_the_keys_of_its_vector::<ml_kem::MlKem1024>(&ML_KEM_1024);
	}

	/// An ML-KEM-1024 response matches its vector.
	#[test]
	fn ml_kem_1024_responds_as_its_vector() {
		responds_as_its_vector::<ml_kem::MlKem1024>(&ML_KEM_1024);
	}

	/// An ML-KEM-1024 completion matches its vector.
	#[test]
	fn ml_kem_1024_completes_as_its_vector() {
		completes_as_its_vector::<ml_kem::MlKem1024>(&ML_KEM_1024);
	}

	/// An ML-KEM-1024 rejection matches its vector.
	#[test]
	fn ml_kem_1024_rejects_as_its_vector() {
		rejects_as_its_vector::<ml_kem::MlKem1024>(&ML_KEM_1024);
	}

	/// ML-KEM-1024 refuses a key above the modulus.
	#[test]
	fn ml_kem_1024_refuses_a_key_above_the_modulus() {
		refuses_a_key_above_the_modulus::<ml_kem::MlKem1024>(&ML_KEM_1024);
	}

	// FIPS 203 §8 places ML-KEM-768 in category 3 and ML-KEM-1024 in category
	// 5, and each names its RFC 9935 identifier.
	crate::tb_cases! {
		fn each_parameter_set_rates_and_names_itself(
			(rated, expected): ((SecurityStrength, ObjectIdentifier), (SecurityStrength, ObjectIdentifier))
		) {
			assert_eq!(rated, expected);
		}
		cases {
			ml_kem_768 => ((MlKem768::strength(), MlKem768::OID), (SecurityStrength::BITS_192, KEM_ML_KEM_768)),
			ml_kem_1024 => ((MlKem1024::strength(), MlKem1024::OID), (SecurityStrength::BITS_256, KEM_ML_KEM_1024)),
		}
	}

	// A share one octet short of its parameter set is refused at its width.
	crate::tb_cases! {
		fn a_share_of_another_width_is_refused((refused, expected): (Option<KeyExchangeError>, KeyExchangeError)) {
			assert_eq!(refused, Some(expected));
		}
		cases {
			offer => (
				MlKemOffer::<ml_kem::MlKem768>::from_octets(&unhex(ML_KEM_768.encap_ek)[1..]).err(),
				KeyExchangeError::Width { expected: 1184, actual: 1183 },
			),
			reply => (
				MlKemReply::<ml_kem::MlKem768>::from_octets(&unhex(ML_KEM_768.encap_c)[1..]).err(),
				KeyExchangeError::Width { expected: 1088, actual: 1087 },
			),
		}
	}

	// The `agreementKey` of a CMS opening names `id-alg-ml-kem-768` with no
	// parameters, so a key under another identifier, or with parameters,
	// names another algorithm.
	crate::tb_cases! {
		fn an_agreement_key_of_another_algorithm_is_refused(key: OriginatorPublicKey) {
			let refused = MlKemOffer::<ml_kem::MlKem768>::from_originator_key(&key);
			assert!(matches!(refused, Err(KeyExchangeError::Algorithm)));
		}
		cases {
			another_identifier => agreement_key_under(TestAlgorithm::of(CURVE_X25519)),
			with_parameters => agreement_key_under(AlgorithmIdentifierOwned {
				oid: KEM_ML_KEM_768,
				parameters: Any::encode_from(&KEM_ML_KEM_768).ok(),
			}),
		}
	}

	/// The reply travels in the CMS Finished as a `KemCiphertext` under the
	/// identifier of the parameter set (RFC 9629 §3).
	#[test]
	fn a_reply_travels_as_a_kem_ciphertext_alone() -> TestResult {
		let (_pending, offer) = MlKem1024::offer(&mut SeededStream(0x10));
		let (reply, _shared) = MlKem1024::respond(&offer, &mut SeededStream(0x20))?;

		let attribute = ReplyAttribute::of::<MlKem1024>(&reply)?;
		assert_eq!(kem_ciphertext_of(attribute), Some((KEM_ML_KEM_1024, reply.to_octets())));
		Ok(())
	}

	/// The parse of a reply refuses the `OriginatorPublicKey` carrier of a DH
	/// reply.
	#[test]
	fn a_reply_in_the_carrier_of_a_dh_reply_is_refused() -> TestResult {
		let (_pending, offer) = MlKem1024::offer(&mut SeededStream(0x10));
		let dh_carrier = ReplyAttribute::OriginatorKey(offer.to_originator_key()?);
		let refused = dh_carrier.reply::<MlKem1024>();
		assert!(matches!(refused, Err(KeyExchangeError::Algorithm)));
		Ok(())
	}
}

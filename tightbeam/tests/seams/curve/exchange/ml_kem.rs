//! ML-KEM-768 (FIPS 203) as an outside crate brings it, through `ml-kem`.
//!
//! [`MlKem768`] is a KEM. Its reply is a ciphertext, which travels in the CMS
//! Finished as a `KemCiphertext`, and its shares collapse into no static key.
//! Each of its operations runs the ML-KEM-768 vector of the NIST ACVP for
//! FIPS 203 that [`ML_KEM_768`] holds. Its shares have fixed widths, so a
//! hybrid pairs it.

use core::convert::Infallible;
use std::error::Error;

use ml_kem::array::typenum::Unsigned;
use ml_kem::kem::{Decapsulate, DecapsulationKey, Encapsulate, EncapsulationKey};
use ml_kem::{Ciphertext, Encoded, EncodedSizeUser, KemCore, MlKem768Params};
use tightbeam::cms::enveloped_data::OriginatorPublicKey;
use tightbeam::crypto::exchange::{KemCiphertext, KeyExchange, KeyExchangeError, KeyShare, ReplyAttribute, ReplyKind};
use tightbeam::crypto::profiles::SecurityStrength;
use tightbeam::crypto::secret::SecretSlice;
use tightbeam::der::asn1::{ObjectIdentifier, OctetString};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::Any;
use tightbeam::oids::{CURVE_X25519, KEM_ML_KEM_768};
use tightbeam::random::{CryptoRngCore, OsRng};
use tightbeam::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoRef};
use tightbeam::testing::vectors::ml_kem::ML_KEM_768;
use tightbeam::testing::{unhex, PublishedDraw};
use tightbeam::zeroize::Zeroize;

#[cfg(feature = "preview-pqc")]
use tightbeam::crypto::exchange::FixedWidthShare;

use super::{cms_opens, hpke_opens, p384_identity, OnP384, CONTENT};

/// The encapsulation key of ML-KEM-768.
type MlKemEncapsulationKey = EncapsulationKey<MlKem768Params>;

/// The decapsulation key of ML-KEM-768, which wipes where it drops.
type MlKemDecapsulationKey = DecapsulationKey<MlKem768Params>;

/// ML-KEM-768 (FIPS 203) in the exchange role, as an outside crate writes it.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct MlKem768;

impl AssociatedOid for MlKem768 {
	const OID: ObjectIdentifier = KEM_ML_KEM_768;
}

/// The initiator's share of [`MlKem768`]: an encapsulation key.
pub(super) struct EncapsulationShare(MlKemEncapsulationKey);

/// The responder's share of [`MlKem768`]: a ciphertext.
pub(super) struct CiphertextShare(Ciphertext<ml_kem::MlKem768>);

#[cfg(feature = "preview-pqc")]
impl FixedWidthShare for EncapsulationShare {
	const WIDTH: usize = <MlKemEncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
}

#[cfg(feature = "preview-pqc")]
impl FixedWidthShare for CiphertextShare {
	const WIDTH: usize = <ml_kem::MlKem768 as KemCore>::CiphertextSize::USIZE;
}

/// The CMS forms are the provided ones: the opening names the key by its
/// identifier, with no parameters.
impl KeyShare<MlKem768> for EncapsulationShare {
	/// The key passes the modulus check of FIPS 203 §7.2: it encodes to the
	/// octets it decodes from, so every coefficient is below the modulus.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let expected = <MlKemEncapsulationKey as EncodedSizeUser>::EncodedSize::USIZE;
		let encoded = Encoded::<MlKemEncapsulationKey>::try_from(octets);
		let encoded = encoded.map_err(|_| KeyExchangeError::Width { expected, actual: octets.len() })?;

		let key = MlKemEncapsulationKey::from_bytes(&encoded);
		if key.as_bytes() != encoded {
			return Err(KeyExchangeError::Malformed);
		}

		Ok(Self(key))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.as_bytes().to_vec()
	}

	/// [`MlKem768`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

/// The reply travels as a `KemCiphertext`, because [`MlKem768`] names
/// [`ReplyKind::Kem`].
impl KeyShare<MlKem768> for CiphertextShare {
	/// A ciphertext of the width of ML-KEM-768 passes the type check of
	/// FIPS 203 §7.3.
	fn from_octets(octets: &[u8]) -> Result<Self, KeyExchangeError> {
		let ciphertext = Ciphertext::<ml_kem::MlKem768>::try_from(octets);
		let expected = <ml_kem::MlKem768 as KemCore>::CiphertextSize::USIZE;
		let ciphertext = ciphertext.map_err(|_| KeyExchangeError::Width { expected, actual: octets.len() })?;
		Ok(Self(ciphertext))
	}

	fn to_octets(&self) -> Vec<u8> {
		self.0.to_vec()
	}

	/// [`MlKem768`] names `StaticKey = Infallible`, so no static key exists to
	/// compare a share with.
	fn collapses_into(&self, key: &Infallible) -> bool {
		match *key {}
	}
}

impl KeyExchange for MlKem768 {
	type Offer = EncapsulationShare;
	type Reply = CiphertextShare;
	type Pending = MlKemDecapsulationKey;
	type StaticKey = Infallible;

	const REPLY: ReplyKind = ReplyKind::Kem;

	/// FIPS 203 §8 places ML-KEM-768 in security category 3, a strength of
	/// 192 bits.
	fn strength() -> SecurityStrength {
		SecurityStrength::BITS_192
	}

	fn offer(mut rng: &mut dyn CryptoRngCore) -> (MlKemDecapsulationKey, EncapsulationShare) {
		let (decapsulation, encapsulation) = ml_kem::MlKem768::generate(&mut rng);
		(decapsulation, EncapsulationShare(encapsulation))
	}

	fn respond(
		offer: &EncapsulationShare,
		mut rng: &mut dyn CryptoRngCore,
	) -> Result<(CiphertextShare, SecretSlice<u8>), KeyExchangeError> {
		let encapsulated = offer.0.encapsulate(&mut rng).map_err(|()| KeyExchangeError::Refused)?;
		let (ciphertext, mut shared) = encapsulated;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok((CiphertextShare(ciphertext), secret))
	}

	fn complete(pending: &MlKemDecapsulationKey, reply: &CiphertextShare) -> Result<SecretSlice<u8>, KeyExchangeError> {
		let mut shared = pending.decapsulate(&reply.0).map_err(|()| KeyExchangeError::Refused)?;
		let secret = SecretSlice::from(shared.to_vec());
		shared.as_mut_slice().zeroize();
		Ok(secret)
	}

	fn static_key(_spki: SubjectPublicKeyInfoRef<'_>) -> Option<Infallible> {
		None
	}
}

/// Key generation draws `d`, then `z`, and offers the encapsulation key of
/// the ACVP vector.
#[test]
fn ml_kem_offers_the_key_of_its_key_generation_vector() {
	let seeds = [unhex(ML_KEM_768.keygen_d), unhex(ML_KEM_768.keygen_z)].concat();
	let (_pending, offer) = MlKem768::offer(&mut PublishedDraw(seeds));
	assert_eq!(offer.to_octets(), unhex(ML_KEM_768.keygen_ek));
}

/// An offer of the ACVP key, answered under the message `m` of the vector,
/// gives the ciphertext and the shared key of the vector.
#[test]
fn ml_kem_responds_as_its_encapsulation_vector() -> Result<(), KeyExchangeError> {
	let offer = EncapsulationShare::from_octets(&unhex(ML_KEM_768.encap_ek))?;
	let (reply, shared) = MlKem768::respond(&offer, &mut PublishedDraw(unhex(ML_KEM_768.encap_m)))?;

	let shared = shared.with(|secret| secret.to_vec());
	let expected = (unhex(ML_KEM_768.encap_c), unhex(ML_KEM_768.encap_k));
	assert_eq!((reply.to_octets(), shared), expected);
	Ok(())
}

/// The decapsulation key of the ACVP vector completes the ciphertext of the
/// vector with its shared key.
#[test]
fn ml_kem_completes_as_its_decapsulation_vector() -> Result<(), Box<dyn Error>> {
	let encoded = Encoded::<MlKemDecapsulationKey>::try_from(unhex(ML_KEM_768.decap_dk).as_slice())?;
	let pending = MlKemDecapsulationKey::from_bytes(&encoded);
	let reply = CiphertextShare::from_octets(&unhex(ML_KEM_768.decap_c))?;

	let shared = MlKem768::complete(&pending, &reply)?;
	assert_eq!(shared.with(|secret| secret.to_vec()), unhex(ML_KEM_768.decap_k));
	Ok(())
}

/// An encapsulation key whose first coefficient encodes as 4095, at or above
/// the modulus 3329, fails the modulus check of FIPS 203 §7.2.
#[test]
fn an_encapsulation_key_above_the_modulus_is_refused() {
	let mut key = unhex(ML_KEM_768.encap_ek);
	key[0] = 0xff;
	key[1] |= 0x0f;

	let refused = EncapsulationShare::from_octets(&key);
	assert!(matches!(refused, Err(KeyExchangeError::Malformed)));
}

/// The `agreementKey` of a CMS opening names `id-alg-ml-kem-768` with no
/// parameters, so a key under another identifier, or with parameters, names
/// another algorithm.
#[test]
fn an_agreement_key_of_another_algorithm_is_refused() -> Result<(), KeyExchangeError> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let key = offer.to_originator_key()?;
	let other = AlgorithmIdentifierOwned { oid: CURVE_X25519, parameters: None };
	let parameters = Any::encode_from(&KEM_ML_KEM_768).ok();
	let with_parameters = AlgorithmIdentifierOwned { oid: KEM_ML_KEM_768, parameters };

	let keys = [other, with_parameters].map(|algorithm| OriginatorPublicKey { algorithm, ..key.clone() });
	let refused = keys.map(|key| EncapsulationShare::from_originator_key(&key).err());
	assert_eq!(refused, [Some(KeyExchangeError::Algorithm); 2]);
	Ok(())
}

/// The reply travels in the CMS Finished as a `KemCiphertext` of the
/// ciphertext under the identifier of ML-KEM-768 (RFC 9629 §3).
#[test]
fn an_ml_kem_reply_travels_as_a_kem_ciphertext() -> Result<(), Box<dyn Error>> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let (reply, _shared) = MlKem768::respond(&offer, &mut OsRng)?;

	let attribute = ReplyAttribute::of::<MlKem768>(&reply)?;
	let ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct }) = attribute else {
		return Err("an ML-KEM reply travels as a KEM ciphertext".into());
	};
	assert_eq!((kem.oid, kemct.as_bytes()), (KEM_ML_KEM_768, reply.to_octets().as_slice()));
	Ok(())
}

/// A KEM reply travels as a `KemCiphertext` alone, so the parse of an ML-KEM
/// reply refuses the `OriginatorPublicKey` carrier of a DH reply.
#[test]
fn a_reply_in_the_dh_carrier_is_refused() -> Result<(), KeyExchangeError> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let key = offer.to_originator_key()?;

	let refused = ReplyAttribute::OriginatorKey(key).reply::<MlKem768>();
	assert!(matches!(refused, Err(KeyExchangeError::Algorithm)));
	Ok(())
}

/// The `kem` of an ML-KEM reply names `id-alg-ml-kem-768` with no
/// parameters, so a ciphertext under another identifier, or with
/// parameters, names another algorithm.
#[test]
fn a_ciphertext_of_another_algorithm_is_refused() -> Result<(), Box<dyn Error>> {
	let (_pending, offer) = MlKem768::offer(&mut OsRng);
	let (reply, _shared) = MlKem768::respond(&offer, &mut OsRng)?;
	let kemct = OctetString::new(reply.to_octets())?;
	let other = AlgorithmIdentifierOwned { oid: CURVE_X25519, parameters: None };
	let parameters = Any::encode_from(&KEM_ML_KEM_768).ok();
	let with_parameters = AlgorithmIdentifierOwned { oid: KEM_ML_KEM_768, parameters };

	let carried = |kem| ReplyAttribute::KemCiphertext(KemCiphertext { kem, kemct: kemct.clone() });
	let refused = [other, with_parameters].map(|kem| carried(kem).reply::<MlKem768>().err());
	assert_eq!(refused, [Some(KeyExchangeError::Algorithm); 2]);
	Ok(())
}

/// The HPKE flow runs under ML-KEM-768.
#[tokio::test]
async fn ml_kem_runs_the_hpke_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(hpke_opens::<OnP384<MlKem768>>().await?, CONTENT);
	Ok(())
}

/// The CMS flow runs under ML-KEM-768.
#[tokio::test]
async fn ml_kem_runs_the_cms_flow() -> Result<(), Box<dyn Error>> {
	assert_eq!(cms_opens::<OnP384<MlKem768>>().await?, CONTENT);
	Ok(())
}

/// A session under ML-KEM-768 renews its epoch in band.
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
#[tokio::test]
async fn ml_kem_renews_its_epoch() -> Result<(), Box<dyn Error>> {
	let renewed = super::super::renewal::renews_its_epoch::<OnP384<MlKem768>>(p384_identity).await?;
	assert!(renewed);
	Ok(())
}

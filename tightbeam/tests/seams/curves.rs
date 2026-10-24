//! A curve an outside crate brings through [`CurvePoints`], which refuses the
//! off-curve encodings of its curve at each reader of operator material.
//!
//! [`ListedP256`] accepts the P-256 key of RFC 6979 §A.2.5 alone, and stands
//! in for the decoder of P-256 an outside crate writes. The alias keeps the
//! x-coordinate and the y parity of that key, and the decoder refuses it, so
//! a reader that holds the decoder reads the alias as its bits.

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, CurvePoints, KeyCurves, KeyIndex, KeyListError};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::{Encode, Error};
use tightbeam::oids::CURVE_NIST_P256;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fixtures::{TestCertificate, TestKey};

#[cfg(feature = "colony")]
use tightbeam::colony::hive::{PeerListGate, PeerListMode};

/// The decoder of P-256 an outside crate brings, which accepts the two SEC 1
/// forms of the RFC 6979 key alone. It keeps the contract of [`CurvePoints`]
/// on every encoding these tests read: the two forms of that key, which it
/// accepts, and the alias, which it refuses.
#[derive(Debug)]
struct ListedP256;

impl CurvePoints for ListedP256 {
	fn curve(&self) -> ObjectIdentifier {
		CURVE_NIST_P256
	}

	fn decodes(&self, point: &[u8]) -> bool {
		let uncompressed = point == TestKey::RFC6979_P256_UNCOMPRESSED.as_slice();
		uncompressed || point == TestKey::RFC6979_P256_COMPRESSED.as_slice()
	}
}

/// The set that holds [`ListedP256`].
const CURVES: KeyCurves = KeyCurves::new(&[&ListedP256]);

/// The RFC 6979 key in the uncompressed form with the second-lowest bit of y
/// flipped, which keeps x and the y parity and is no point of the curve.
const ALIAS: [u8; 65] = {
	let mut point = TestKey::RFC6979_P256_UNCOMPRESSED;
	point[64] ^= 0b10;
	point
};

/// A certificate whose key is `point` on P-256.
fn certificate_of(point: &[u8]) -> Certificate {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	TestCertificate::with_curve_point(certificate, CURVE_NIST_P256, point)
}

/// The SubjectPublicKeyInfo of a key that is `point` on P-256.
fn spki_of(point: &[u8]) -> SubjectPublicKeyInfoOwned {
	certificate_of(point).tbs_certificate.subject_public_key_info
}

/// A store built under the outside decoder that holds the certificate of
/// `point`.
fn store_of(point: &[u8]) -> Result<impl CertificateTrust, CertificateValidationError> {
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), CURVES);
	Ok(builder.with_certificate(certificate_of(point))?.build())
}

/// The pin of a key that is `point` on P-256: the DER of its
/// SubjectPublicKeyInfo.
fn pin_of(point: &[u8]) -> Vec<u8> {
	spki_of(point).to_der().expect("a test SubjectPublicKeyInfo encodes")
}

/// A pin that holds the outside decoder refuses a certificate of the alias.
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_pin() -> Result<(), KeyListError> {
	let pin = PublicKeyPinning::with_curves(CURVES, [pin_of(&TestKey::RFC6979_P256_COMPRESSED)])?;

	let refused = pin.evaluate(&certificate_of(&ALIAS));
	assert!(matches!(refused, Err(CertificateValidationError::PublicKeyNotPinned)));
	Ok(())
}

/// A pin of the alias reads as no point under the outside decoder, so the
/// pinning refuses it where it is built, with its index.
#[test]
fn an_outside_decoder_refuses_a_pin_of_the_alias() {
	let refused = PublicKeyPinning::with_curves(CURVES, [pin_of(&ALIAS)]);
	assert_eq!(refused.err(), Some(KeyListError::NoPoint { index: 0 }));
}

/// A pin that holds the outside decoder admits the pinned key in its other
/// SEC 1 form, so the decoder changes no valid point.
#[test]
fn an_outside_decoder_admits_a_pinned_key_in_its_other_form() -> Result<(), Box<dyn core::error::Error>> {
	let pin = PublicKeyPinning::with_curves(CURVES, [pin_of(&TestKey::RFC6979_P256_COMPRESSED)])?;

	pin.evaluate(&certificate_of(&TestKey::RFC6979_P256_UNCOMPRESSED))?;
	Ok(())
}

/// An index that holds the outside decoder finds no key by the alias.
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_index() -> Result<(), Error> {
	let mut index = KeyIndex::new(CURVES);
	index.insert(&spki_of(&TestKey::RFC6979_P256_COMPRESSED), ())?;

	let found = index.find(&spki_of(&ALIAS));
	assert_eq!(found, None);
	Ok(())
}

/// An index that holds the outside decoder reads the alias it indexes as its
/// bits, so the valid key whose x and y parity it keeps finds no entry.
#[test]
fn an_outside_decoder_indexes_an_alias_as_its_bits() -> Result<(), Error> {
	let mut index = KeyIndex::new(CURVES);
	index.insert(&spki_of(&ALIAS), ())?;

	let found = index.find(&spki_of(&TestKey::RFC6979_P256_UNCOMPRESSED));
	assert_eq!(found, None);
	Ok(())
}

/// An index that holds the outside decoder finds the RFC 6979 key by its
/// other SEC 1 form, so the decoder changes no valid point.
#[test]
fn an_outside_decoder_finds_a_key_by_its_other_form_at_the_index() -> Result<(), Error> {
	let mut index = KeyIndex::new(CURVES);
	index.insert(&spki_of(&TestKey::RFC6979_P256_UNCOMPRESSED), ())?;

	let found = index.find(&spki_of(&TestKey::RFC6979_P256_COMPRESSED));
	assert_eq!(found, Some(&()));
	Ok(())
}

/// A store built with the outside decoder finds no certificate by the alias
/// of a key it holds.
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_store() -> Result<(), CertificateValidationError> {
	let store = store_of(&TestKey::RFC6979_P256_COMPRESSED)?;
	let found = store.find_by_public_key(&spki_of(&ALIAS));
	assert_eq!(found, None);
	Ok(())
}

/// A store built with the outside decoder enrols an alias as its bits, so
/// the valid key whose x and y parity it keeps names no certificate.
#[test]
fn an_outside_decoder_enrols_an_alias_as_its_bits_at_the_store() -> Result<(), CertificateValidationError> {
	let store = store_of(&ALIAS)?;
	let found = store.find_by_public_key(&spki_of(&TestKey::RFC6979_P256_UNCOMPRESSED));
	assert_eq!(found, None);
	Ok(())
}

/// A deny list that holds the outside decoder refuses an entry of the alias,
/// which no session holds.
#[cfg(feature = "colony")]
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_gate() -> Result<(), Error> {
	let entry = spki_of(&ALIAS).to_der()?;
	let refused = PeerListGate::new(PeerListMode::Deny, CURVES, [entry]);
	assert_eq!(refused.err(), Some(KeyListError::NoPoint { index: 0 }));
	Ok(())
}

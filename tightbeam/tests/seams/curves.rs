//! A curve an outside crate brings through [`CurvePoints`], which refuses the
//! off-curve encodings of its curve at each reader of operator material.
//!
//! [`ListedP256`] stands in for the decoder of P-256 an outside crate writes.
//! It refuses the alias, which keeps the x-coordinate and the y parity of the
//! RFC 6979 §A.2.5 key, so a reader that holds the decoder reads the alias as
//! its bits.

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::policy::{CertificateValidation, PublicKeyPinning};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::{Certificate, CurvePoints, KeyCurves, KeyIndex, KeyListError};
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Encode;
use tightbeam::oids::CURVE_NIST_P256;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fixtures::{TestCertificate, TestKey};

#[cfg(feature = "colony")]
use tightbeam::colony::hive::{PeerListGate, PeerListMode};

use crate::common::result::TestResult;

/// The decoder of P-256 an outside crate brings, which accepts the two SEC 1
/// forms of the RFC 6979 key alone, so it keeps the contract of
/// [`CurvePoints`] on every encoding these tests read.
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
fn store_of(point: &[u8]) -> impl CertificateTrust {
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), CURVES, NoRevocation);
	let anchored = builder.with_certificate(certificate_of(point));
	let anchored = anchored.expect("the store admits a certificate of a point the decoder holds");
	anchored.build()
}

/// The bits of the key that `certificate` holds.
fn point_of(certificate: &Certificate) -> &[u8] {
	certificate
		.tbs_certificate
		.subject_public_key_info
		.subject_public_key
		.raw_bytes()
}

/// The pin of a key that is `point` on P-256: the DER of its
/// SubjectPublicKeyInfo.
fn pin_of(point: &[u8]) -> Vec<u8> {
	spki_of(point).to_der().expect("a test SubjectPublicKeyInfo encodes")
}

/// A pin that holds the outside decoder refuses a certificate of the alias.
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_pin() -> TestResult {
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
fn an_outside_decoder_admits_a_pinned_key_in_its_other_form() -> TestResult {
	let pin = PublicKeyPinning::with_curves(CURVES, [pin_of(&TestKey::RFC6979_P256_COMPRESSED)])?;
	pin.evaluate(&certificate_of(&TestKey::RFC6979_P256_UNCOMPRESSED))?;
	Ok(())
}

// An index that holds the outside decoder answers a lookup by the point that
// the decoder reads from each key.
tightbeam::tb_cases! {
	fn an_outside_decoder_at_the_index((indexed, sought, found): (&[u8], &[u8], Option<()>)) -> TestResult {
		let mut index = KeyIndex::new(CURVES);
		index.insert(&spki_of(indexed), ())?;

		let entry = index.find(&spki_of(sought));
		assert_eq!(entry.copied(), found);
		Ok(())
	}
	cases {
		/// The index finds no key by the alias.
		refuses_an_alias => (&TestKey::RFC6979_P256_COMPRESSED, &ALIAS, None),
		/// The index reads the alias it indexes as its bits, so the valid key
		/// whose x and y parity it keeps finds no entry.
		indexes_an_alias_as_its_bits => (&ALIAS, &TestKey::RFC6979_P256_UNCOMPRESSED, None),
		/// The index finds the RFC 6979 key by its other SEC 1 form, so the
		/// decoder changes no valid point.
		finds_a_key_by_its_other_form => (
			&TestKey::RFC6979_P256_UNCOMPRESSED,
			&TestKey::RFC6979_P256_COMPRESSED,
			Some(())
		),
	}
}

// A store built with the outside decoder answers a lookup by the point that
// the decoder reads from each key, so a key of another point finds nothing,
// and a key of the held point finds the certificate that holds it.
tightbeam::tb_cases! {
	fn an_outside_decoder_at_the_store((held, sought, found): (&[u8], &[u8], Option<&[u8]>)) {
		let store = store_of(held);
		let answer = store.find_by_public_key(&spki_of(sought));
		assert_eq!(answer.map(point_of), found);
	}
	cases {
		/// The store finds no certificate by the alias of a key it holds.
		refuses_an_alias => (&TestKey::RFC6979_P256_COMPRESSED, &ALIAS, None),
		/// The store enrols an alias as its bits, so the valid key whose x and
		/// y parity it keeps names no certificate.
		enrols_an_alias_as_its_bits => (&ALIAS, &TestKey::RFC6979_P256_UNCOMPRESSED, None),
		/// The store finds the certificate of an alias by the bits it enrolled.
		finds_an_alias_by_its_bits => (&ALIAS, &ALIAS, Some(ALIAS.as_slice())),
		/// The store finds the certificate of the RFC 6979 key by its other
		/// SEC 1 form, so the decoder changes no valid point.
		finds_a_key_by_its_other_form => (
			&TestKey::RFC6979_P256_UNCOMPRESSED,
			&TestKey::RFC6979_P256_COMPRESSED,
			Some(TestKey::RFC6979_P256_UNCOMPRESSED.as_slice())
		),
	}
}

/// A deny list that holds the outside decoder refuses an entry of the alias,
/// which no session holds.
#[cfg(feature = "colony")]
#[test]
fn an_outside_decoder_refuses_an_alias_at_the_gate() -> TestResult {
	let entry = spki_of(&ALIAS).to_der()?;
	let refused = PeerListGate::new(PeerListMode::Deny, CURVES, [entry]);
	assert_eq!(refused.err(), Some(KeyListError::NoPoint { index: 0 }));
	Ok(())
}

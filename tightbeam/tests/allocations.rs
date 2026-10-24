//! The allocation counts of the reads the handshake and a key index make
//! in place, under a counting allocator that this test binary alone
//! installs.
//!
//! - A lookup writes the canonical form of a key on the stack when that form
//!   fits the stack buffer, which holds every named-curve key up to P-521.
//! - A `sid` of the key-identifier form names a certificate by the extension
//!   value as the certificate holds it.
//! - The built-in store validates a presented path from where its parts sit.
//! - A signed `SignerInfo` encodes in place, as its inner value does.
//!
//! Only an allocation count shows these bounds, so the counting allocator
//! lives in this test binary alone.

// Tests are exempt from the zero-panic index and arithmetic lints (workspace
// lints): an index out of range fails its test at its location.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, TrustBuilder};
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::KeyIndex;
use tightbeam::der::asn1::{BitString, ObjectIdentifier};
use tightbeam::der::oid::db::rfc8410::ID_ED_25519;
use tightbeam::der::Encode;
use tightbeam::oids::{CURVE_NIST_P256, CURVE_NIST_P521};
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fixtures::{TestCertificate, TestKey, TestSigner};

thread_local! {
	/// The count of the allocations of this thread. A `Cell` of an integer
	/// lives as long as its thread, so the allocator reads it at every
	/// allocation of the thread.
	static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// The system allocator, wrapped to count each allocation of the thread that
/// makes it.
struct Counting;

// SAFETY: each method forwards its own arguments to `System`, which keeps the
// contract of `GlobalAlloc`.
unsafe impl GlobalAlloc for Counting {
	unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
		ALLOCATIONS.with(|count| count.set(count.get().saturating_add(1)));
		// SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
		unsafe { System.alloc(layout) }
	}

	unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
		// SAFETY: `System.alloc` returned `ptr` under `layout`.
		unsafe { System.dealloc(ptr, layout) }
	}
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The SubjectPublicKeyInfo of the key that is `point` on the named curve
/// `curve`.
fn spki_of(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let certificate = TestCertificate::with_curve_point(certificate, curve, point);
	certificate.tbs_certificate.subject_public_key_info
}

/// The SubjectPublicKeyInfo of the fixed secp256k1 key, whose curve the house
/// set holds a decoder of.
fn house_key() -> SubjectPublicKeyInfoOwned {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	certificate.tbs_certificate.subject_public_key_info
}

/// An Ed25519 key of 300 octets, whose canonical form exceeds the stack
/// buffer.
fn long_key() -> SubjectPublicKeyInfoOwned {
	let mut spki = house_key();
	spki.algorithm.oid = ID_ED_25519;
	spki.algorithm.parameters = None;
	spki.subject_public_key = BitString::from_bytes(&[0x2a; 300]).expect("300 octets are a BIT STRING");
	spki
}

/// Whether an index that holds `spki` finds it, beside the count of the
/// allocations that the lookup makes.
fn lookup_of(spki: &SubjectPublicKeyInfoOwned) -> (bool, usize) {
	let mut index = KeyIndex::default();
	index.insert(spki, ()).expect("a test key has a canonical form");

	let before = ALLOCATIONS.with(Cell::get);
	let found = index.find(spki).is_some();
	let after = ALLOCATIONS.with(Cell::get);
	(found, after - before)
}

/// A lookup of the fixed secp256k1 key decodes it and writes its canonical
/// form on the stack.
#[test]
fn a_lookup_of_the_house_key_allocates_nothing() {
	assert_eq!(lookup_of(&house_key()), (true, 0));
}

/// A lookup of the P-256 key of RFC 6979 §A.2.5 writes its canonical form on
/// the stack.
#[test]
fn a_lookup_of_the_rfc6979_p256_key_allocates_nothing() {
	let spki = spki_of(CURVE_NIST_P256, &TestKey::RFC6979_P256_UNCOMPRESSED);
	assert_eq!(lookup_of(&spki), (true, 0));
}

/// A lookup of the P-521 key of RFC 6979 §A.2.7, the widest named prime
/// curve, writes its canonical form on the stack.
#[test]
fn a_lookup_of_the_rfc6979_p521_key_allocates_nothing() {
	let spki = spki_of(CURVE_NIST_P521, &TestKey::RFC6979_P521_UNCOMPRESSED);
	assert_eq!(lookup_of(&spki), (true, 0));
}

/// A key whose canonical form exceeds the stack buffer goes on the heap.
#[test]
fn a_lookup_past_the_stack_bound_allocates() {
	let lookup = lookup_of(&long_key());
	assert!(matches!(lookup, (true, allocations) if allocations > 0));
}

/// Whether the `sid` of the house certificate of the fixed key names that
/// certificate, beside the count of the allocations that the match makes.
fn naming_of_the_house_certificate() -> (bool, usize) {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let sid = certificate.signer_identifier();
	let sid = sid.expect("a house certificate carries its key identifier");

	let before = ALLOCATIONS.with(Cell::get);
	let named = certificate.is_named_by(&sid).expect("the key identifier decodes");
	let after = ALLOCATIONS.with(Cell::get);
	(named, after - before)
}

/// A `sid` of the key-identifier form names a house certificate by the
/// extension value the certificate holds, read in place (RFC 5652 §5.3).
#[test]
fn a_key_identifier_names_its_certificate_with_no_allocation() {
	assert_eq!(naming_of_the_house_certificate(), (true, 0));
}

/// The counts of the allocations that a store of the fixed root makes as it
/// validates the fixed path, as one chain and as a presented path.
fn validations_of_the_fixed_path() -> (usize, usize) {
	let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
	let builder = CertificateTrustBuilder::from(Secp256k1Policy::default());
	let builder = builder.with_certificate(chain.root);
	let store = builder.expect("the root is within its validity period").build();
	let whole = [chain.intermediate.to_owned(), chain.leaf.to_owned()];
	let issuers = [chain.intermediate];

	let before = ALLOCATIONS.with(Cell::get);
	store.verify_chain(&whole).expect("the path validates as one chain");
	let between = ALLOCATIONS.with(Cell::get);
	let presented = store.verify_presented(&issuers, &chain.leaf);
	presented.expect("the path validates as presented");
	let after = ALLOCATIONS.with(Cell::get);
	(between - before, after - between)
}

/// The built-in store validates a presented path from where its issuers and
/// its leaf sit, so it allocates what one chain allocates, and no copy of a
/// certificate.
#[test]
fn a_presented_path_validates_with_the_allocations_of_one_chain() {
	let (whole, presented) = validations_of_the_fixed_path();
	assert_eq!(presented, whole);
}

/// The counts of the allocations that the DER of the fixed signer structure
/// makes, through its `Signed` wrapper and as its inner `SignerInfo`.
fn encodings_of_the_fixed_signer() -> (usize, usize) {
	let signed = TestSigner::info();

	let before = ALLOCATIONS.with(Cell::get);
	signed.to_der().expect("the signed structure encodes");
	let between = ALLOCATIONS.with(Cell::get);
	signed.as_ref().to_der().expect("the inner structure encodes");
	let after = ALLOCATIONS.with(Cell::get);
	(between - before, after - between)
}

/// A frame signature encodes in place, so the `Signed` wrapper of a
/// `SignerInfo` allocates what its inner value allocates, and no buffer.
#[test]
fn a_signed_signer_info_encodes_with_the_allocations_of_its_value() {
	let (wrapped, inner) = encodings_of_the_fixed_signer();
	assert_eq!(wrapped, inner);
}

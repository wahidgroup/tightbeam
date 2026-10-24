//! The allocation counts of a lookup in a key index, under a counting
//! allocator that this test binary alone installs.
//!
//! A lookup writes the canonical form of a key on the stack when that form
//! fits the stack buffer, which holds every named-curve key up to P-521. Only
//! an allocation count shows that bound, so the counting allocator lives in
//! this test binary alone.

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};

use tightbeam::crypto::x509::KeyIndex;
use tightbeam::der::asn1::{BitString, ObjectIdentifier};
use tightbeam::der::oid::db::rfc8410::ID_ED_25519;
use tightbeam::oids::{CURVE_NIST_P256, CURVE_NIST_P521};
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fixtures::{TestCertificate, TestKey};

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

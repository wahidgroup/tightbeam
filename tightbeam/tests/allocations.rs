//! Allocation bounds of hot paths. Only an allocation count shows them, so
//! the counting allocator lives in this test binary alone.

// Tests are exempt from the zero-panic index and arithmetic lints (workspace
// lints): an index out of range fails its test at its location.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use core::cell::Cell;
use core::future::{ready, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::alloc::{GlobalAlloc, Layout, System};
use std::error::Error;
use std::sync::Arc;

use tightbeam::asn1::{AuthEnvelopedData, WireDer};
use tightbeam::clock::UnixMillis;
use tightbeam::colony::cluster::{AdmittedGossip, GossipDigest, WantList};
use tightbeam::colony::protocol::GossipRumor;
use tightbeam::colony::servlet::ServletContext;
use tightbeam::compress::ZstdCompression;
use tightbeam::core::Inflator;
use tightbeam::crypto::cms::{KemRecipient, Recipient};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::hpke::HpkeEncryptor;
use tightbeam::crypto::key::{KeyBackend, Secp256k1KeyProvider};
use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::{DefaultCryptoProvider, Kek};
use tightbeam::crypto::x509::store::{CertificateTrust, CertificateTrustBuilder, NoRevocation, TrustBuilder};
use tightbeam::crypto::x509::utils::CertificateExt;
use tightbeam::crypto::x509::{CanonicalKey, KeyCurves, KeyIndex};
use tightbeam::der::asn1::{BitString, ObjectIdentifier};
use tightbeam::der::oid::db::rfc8410::ID_ED_25519;
use tightbeam::der::{Decode, Encode};
use tightbeam::instrumentation::{events, TbInstrumentationConfig};
use tightbeam::macros::server::SingleFlightAnswer;
use tightbeam::oids::{COMPRESSION_ZSTD, CURVE_NIST_P256, CURVE_NIST_P521, DATA};
use tightbeam::policy::TransitStatus;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
use tightbeam::testing::fixtures::{TestCertificate, TestKey, TestRumor, TestSigner};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::testing::{TestFrame, TestMessage};
use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
use tightbeam::transport::EndpointConfig;
use tightbeam::urn::{UrnSpecBuilder, UrnValidationError};
use tightbeam::{compose, Frame, TightBeamError};

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

/// An Ed25519 key of 300 octets, whose canonical form exceeds the stack buffer.
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

/// A lookup of the P-256 key of RFC 6979 § A.2.5 writes its canonical form on
/// the stack.
#[test]
fn a_lookup_of_the_rfc6979_p256_key_allocates_nothing() {
	let spki = spki_of(CURVE_NIST_P256, &TestKey::RFC6979_P256_UNCOMPRESSED);
	assert_eq!(lookup_of(&spki), (true, 0));
}

/// A lookup of the P-521 key of RFC 6979 § A.2.7, the widest named prime
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

/// Whether a store of the fixed key's house certificate finds the canonical
/// form of that key, beside the count of allocations the lookup makes.
fn canonical_lookup_on_the_house_store() -> (bool, usize) {
	let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
	let key = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info);
	let key = key.expect("a house key has a canonical form");
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	let builder = builder.with_certificate(certificate);
	let store = builder.expect("the fixed certificate enrols").build();

	let before = ALLOCATIONS.with(Cell::get);
	let found = store.find_by_canonical_key(&key).is_some();
	let after = ALLOCATIONS.with(Cell::get);
	(found, after - before)
}

/// The house store finds the canonical key a session holds in its key index
/// with no decode, so a session classification lookup allocates nothing.
#[test]
fn a_canonical_key_lookup_on_the_house_store_allocates_nothing() {
	assert_eq!(canonical_lookup_on_the_house_store(), (true, 0));
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
/// extension value the certificate holds, read in place (RFC 5652 § 5.3).
#[test]
fn a_key_identifier_names_its_certificate_with_no_allocation() {
	assert_eq!(naming_of_the_house_certificate(), (true, 0));
}

/// The counts of the allocations that a store of the fixed root makes as it
/// validates the fixed path, as one chain and as a presented path.
fn validations_of_the_fixed_path() -> (usize, usize) {
	let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
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

/// The built-in store validates a presented path where its issuers and leaf
/// sit, so it allocates what one chain allocates and copies no certificate.
#[test]
fn a_presented_path_validates_with_the_allocations_of_one_chain() {
	let (whole, presented) = validations_of_the_fixed_path();
	assert_eq!(presented, whole);
}

/// The counts of the allocations that the DER encoding of the fixed signer
/// structure makes, through its `Signed` wrapper and as its inner `SignerInfo`.
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

/// The count of the allocations that a read of a 32-octet SHA3-256 rumor
/// digest makes.
fn allocations_of_a_digest_read() -> usize {
	let bytes = [7u8; 32];

	let before = ALLOCATIONS.with(Cell::get);
	let digest = GossipDigest::read::<Sha3_256>(bytes);
	let after = ALLOCATIONS.with(Cell::get);
	digest.expect("32 octets read as a SHA3-256 digest");
	after - before
}

/// A rumor digest that a peer names reads onto the stack.
#[test]
fn a_rumor_digest_reads_with_no_allocation() {
	assert_eq!(allocations_of_a_digest_read(), 0);
}

/// The allocation counts of the fixed rumor's admission and of its two steps
/// that own a buffer: the decode of its body and the encoding of its
/// to-be-signed frame.
fn admissions_of_the_fixed_rumor() -> (usize, usize) {
	let rumor = TestRumor::verified(TestRumor::application(1_000, [1, 2, 3]));
	let frame = rumor.frame();
	let now = UnixMillis::new(1_000);

	let before = ALLOCATIONS.with(Cell::get);
	let admitted = AdmittedGossip::admit::<Sha3_256>(&rumor, 0, Duration::from_secs(30), now);
	let between = ALLOCATIONS.with(Cell::get);
	let body = frame.decode_message::<GossipRumor>();
	let tbs = frame.to_tbs();
	let after = ALLOCATIONS.with(Cell::get);

	admitted.expect("the fixed rumor is fresh and within its bounds");
	body.expect("the fixed rumor's body decodes");
	tbs.expect("the fixed rumor encodes");
	(between - before, after - between)
}

/// A rumor admits with no allocation for its digest: the admission allocates
/// what its body decode and its to-be-signed encoding allocate, and the digest
/// it records sits on the stack.
#[test]
fn a_rumor_admits_with_no_allocation_for_its_digest() {
	let (admission, parts) = admissions_of_the_fixed_rumor();
	assert_eq!(admission, parts);
}

/// The SHA3-256 rumor digest whose leading octets spell `index`.
fn digest_of(index: u32) -> GossipDigest {
	let mut bytes = [0u8; 32];
	bytes[..4].copy_from_slice(&index.to_be_bytes());
	GossipDigest::read::<Sha3_256>(bytes).expect("32 octets read as a SHA3-256 digest")
}

/// Whether a want list against 4,096 advertised entries that the replier
/// holds in full wants nothing, beside the count of allocations the list makes.
fn want_list_against_held_entries() -> (bool, usize) {
	let held: Vec<GossipDigest> = (0..4_096).map(digest_of).collect();
	let advertised: Vec<Vec<u8>> = held.iter().map(|digest| digest.as_bytes().to_vec()).collect();

	let before = ALLOCATIONS.with(Cell::get);
	let want = WantList::against::<Sha3_256>(&advertised, &held);
	let after = ALLOCATIONS.with(Cell::get);
	(want.digests().is_empty(), after - before)
}

/// A want list against entries the replier holds in full allocates its held
/// set alone, and borrows the advertised entries it drops.
#[test]
fn a_want_list_against_held_entries_allocates_the_held_set_alone() {
	assert_eq!(want_list_against_held_entries(), (true, 1));
}

/// An inflator that hands a body back as it arrived, so each inflate makes
/// the one allocation of the buffer it returns. It names zstd, the algorithm
/// of the frames it inflates.
struct CopyInflator;

impl Inflator for CopyInflator {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		COMPRESSION_ZSTD
	}

	fn decompress(&self, data: &[u8]) -> tightbeam::error::Result<Vec<u8>> {
		Ok(data.to_vec())
	}
}

/// A cleartext frame whose body `zstd` compressed.
fn compressed_frame() -> Result<Frame, TightBeamError> {
	let message = TestMessage::sample(None);
	compose! { V0: id: "detail-off", order: 1u64, message: message, compactness: ZstdCompression::default() }
}

/// The allocation counts of a compressed frame's inflate, alone and through
/// the typed delivery of a servlet whose trace config leaves
/// `enable_internal_detail` off.
fn inflations_with_the_detail_off() -> Result<(usize, usize), TightBeamError> {
	let inflator: Arc<dyn Inflator + Send + Sync> = Arc::new(CopyInflator);
	let ctx = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), [], None);
	let ctx = ctx.with_message_inflator(Some(inflator));
	let mut alone = compressed_frame()?;
	let mut delivered = compressed_frame()?;
	let mut cx = Context::from_waker(Waker::noop());

	let before = ALLOCATIONS.with(Cell::get);
	let inflated = alone.inflate_in_place(&CopyInflator);
	let between = ALLOCATIONS.with(Cell::get);
	let delivery = pin!(delivered.prepare_typed(&ctx)).poll(&mut cx);
	let after = ALLOCATIONS.with(Cell::get);

	let _opened = inflated?;

	let Poll::Ready(prepared) = delivery else {
		panic!("the inflate of a typed delivery completes on its first poll");
	};

	prepared?;

	Ok((between - before, after - between))
}

/// The internal events cost no allocation while they are off: the typed
/// delivery of a compressed frame allocates what its inflate allocates, and
/// the internal event at the inflate allocates nothing.
#[test]
fn a_typed_delivery_with_the_detail_off_allocates_what_its_inflate_allocates() -> Result<(), TightBeamError> {
	let (inflate, delivery) = inflations_with_the_detail_off()?;
	assert_eq!(delivery, inflate);
	Ok(())
}

/// A frame of a sample message, sealed to a bare recipient of the house KEM.
fn kem_sealed_frame() -> Result<Frame, Box<dyn Error>> {
	let backend = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
	let recipient = KemRecipient::bare(backend.to_public_key_bytes()?)?;
	let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
	let message = TestMessage::sample(None);

	Ok(compose! { V1: id: "kem-shape", order: 1u64, message: message, encryptor: encryptor }?)
}

/// The allocation count of the requirement check of a frame sealed to one
/// KEM recipient.
fn allocations_of_a_kem_shape() -> Result<usize, Box<dyn Error>> {
	let frame = kem_sealed_frame()?;

	let before = ALLOCATIONS.with(Cell::get);
	let admitted = frame.validate_for::<TestMessage>();
	let after = ALLOCATIONS.with(Cell::get);

	admitted?;
	Ok(after - before)
}

/// The requirement check reads the wrap of a KEM recipient in place, so it
/// allocates the list of wraps alone and copies no field of the recipient.
#[test]
fn the_requirement_check_of_a_kem_recipient_allocates_its_wrap_list_alone() -> Result<(), Box<dyn Error>> {
	assert_eq!(allocations_of_a_kem_shape()?, 1);
	Ok(())
}

/// A cleartext transport over a loopback connection, whose trace leaves
/// `enable_internal_detail` off.
async fn loopback_transport() -> Result<TcpTransport<TokioStream>, TightBeamError> {
	let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;

	let stream = tokio::net::TcpStream::connect(listener.local_addr()?).await?;
	let config = EndpointConfig::<DefaultCryptoProvider>::cleartext();
	Ok(TcpTransport::new(TokioStream::from(stream), config).with_trace(TraceCollector::new()))
}

/// The count of the allocations that a single-flight turn makes as it answers
/// one admitted frame with a handler that allocates nothing, on a connection
/// whose trace leaves `enable_internal_detail` off.
fn single_flight_turn_with_the_detail_off() -> Result<usize, TightBeamError> {
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
	let mut transport = runtime.block_on(loopback_transport())?;
	let collected = (Arc::new(TestFrame::v0(None, None)), TransitStatus::Ok);
	let echo = |frame: Frame, _session| ready(Ok::<_, TightBeamError>(Some(frame)));
	let mut session = None;
	let mut cx = Context::from_waker(Waker::noop());

	let before = ALLOCATIONS.with(Cell::get);
	let turn = pin!(SingleFlightAnswer::of(&mut transport, &mut session, collected, echo)).poll(&mut cx);
	let after = ALLOCATIONS.with(Cell::get);

	let Poll::Ready(answer) = turn else {
		panic!("a turn whose handler is ready completes on its first poll");
	};
	if let Some(failure) = answer.failure {
		return Err(failure);
	}

	Ok(after - before)
}

/// The handler span costs no allocation while the internal events are off: a
/// single-flight turn that answers an admitted frame, with a handler that
/// allocates nothing, allocates nothing.
#[test]
fn a_single_flight_turn_with_the_detail_off_allocates_nothing() -> Result<(), TightBeamError> {
	assert_eq!(single_flight_turn_with_the_detail_off()?, 0);
	Ok(())
}

/// The allocation counts of a record with evidence and of a bare assertion on
/// a trace whose sink holds no event, after one warm-up record of each.
fn records_on_a_full_sink() -> Result<(usize, usize), TightBeamError> {
	let config = TbInstrumentationConfig { max_events: 0, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	trace.emit_event_with_evidence(events::GATE_ACCEPT, "Ok", None)?;
	trace.event(&events::GATE_ACCEPT)?.emit();

	let before = ALLOCATIONS.with(Cell::get);
	let evidenced = trace.emit_event_with_evidence(events::GATE_ACCEPT, "Ok", None);
	let between = ALLOCATIONS.with(Cell::get);
	let asserted = trace.event(&events::GATE_ACCEPT).map(|builder| builder.emit());
	let after = ALLOCATIONS.with(Cell::get);

	evidenced?;
	asserted?;
	Ok((between - before, after - between))
}

/// An event that a full sink drops costs no allocation of its own: a record
/// with evidence allocates what a bare assertion allocates, the assertion of
/// the testing layer alone.
#[test]
fn a_record_that_a_full_sink_drops_allocates_its_assertion_alone() -> Result<(), TightBeamError> {
	let (evidenced, asserted) = records_on_a_full_sink()?;
	assert_eq!(evidenced, asserted);
	Ok(())
}

/// A process with no hidden event, whose `ping` and `pong` take `S0` to `S1`
/// and back.
fn ring() -> Result<Process, ProcessBuildError> {
	Process::builder("Ring")
		.initial_state(State("S0"))
		.add_observable(Event("ping"))
		.add_observable(Event("pong"))
		.add_transition(State("S0"), Event("ping"), State("S1"))
		.add_transition(State("S1"), Event("pong"), State("S0"))
		.build()
}

/// The count of the allocations that one seed of `process` makes with
/// `max_internal_run` at `bound`.
fn allocations_of_one_seed(process: &Process, bound: usize) -> usize {
	let config = FdrConfig { seeds: 1, max_internal_run: bound, ..Default::default() };
	let mut explorer = DefaultFdrExplorer::with_defaults(process, config);
	// A first exploration fills the lazy state of the thread, which the count
	// leaves out.
	explorer.explore().expect("the run asks for no FMEA report");

	let before = ALLOCATIONS.with(Cell::get);
	explorer.explore().expect("the run asks for no FMEA report");

	let after = ALLOCATIONS.with(Cell::get);
	after - before
}

/// The hidden run bound sets no work on a process with no hidden event, so
/// its exploration allocates the same at any bound.
#[test]
fn a_process_with_no_hidden_event_allocates_the_same_at_any_hidden_run_bound() -> Result<(), ProcessBuildError> {
	let process = ring()?;

	let at_zero = allocations_of_one_seed(&process, 0);
	let at_thirty_two = allocations_of_one_seed(&process, 32);
	assert_eq!(at_zero, at_thirty_two);
	Ok(())
}

/// The divergent states of a process with no hidden event cost no allocation.
#[test]
fn a_process_with_no_hidden_event_computes_its_divergent_states_with_no_allocation() -> Result<(), ProcessBuildError> {
	let process = ring()?;
	let before = ALLOCATIONS.with(Cell::get);

	let divergent = process.divergent_states();
	let after = ALLOCATIONS.with(Cell::get);
	assert_eq!((divergent.contains(State("S0")), after - before), (false, 0));
	Ok(())
}

/// A process whose observable `ping` takes `S0` to `S1`, and whose hidden
/// `tick` takes `S1` back to `S0`, so `S0` has no hidden step.
fn ticking() -> Result<Process, ProcessBuildError> {
	Process::builder("Ticking")
		.initial_state(State("S0"))
		.add_observable(Event("ping"))
		.add_hidden(Event("tick"))
		.add_transition(State("S0"), Event("ping"), State("S1"))
		.add_transition(State("S1"), Event("tick"), State("S0"))
		.build()
}

/// Whether `S0` of `ticking` is stable and has no divergence witness, beside
/// the count of the allocations that the two answers make.
fn answers_at_a_state_with_no_hidden_step() -> Result<(bool, bool, usize), ProcessBuildError> {
	let process = ticking()?;
	let divergent = process.divergent_states();

	let before = ALLOCATIONS.with(Cell::get);
	let stable = process.is_stable(State("S0"));
	let witness = divergent.witness(State("S0"));
	let after = ALLOCATIONS.with(Cell::get);
	Ok((stable, witness.is_none(), after - before))
}

/// A state with no hidden step answers whether it is stable and whether it
/// diverges with no allocation.
#[test]
fn a_state_with_no_hidden_step_answers_with_no_allocation() -> Result<(), ProcessBuildError> {
	assert_eq!(answers_at_a_state_with_no_hidden_step()?, (true, true, 0));
	Ok(())
}

/// The allocation count of the conversion of a trace into a process, when the
/// trace holds one gate acceptance and `extra` records the chain leaves out.
fn chain_with_records_left_out(extra: u32) -> usize {
	use tightbeam::testing::fdr::TraceProcessMode;

	const PLAIN: tightbeam::urn::Urn<'static> = tightbeam::urn!("test", "event:allocations/plain");

	let collector = TraceCollector::new();
	collector.emit(events::GATE_ACCEPT, "Ok");
	for _ in 0..extra {
		collector.emit(PLAIN, "Ok");
	}

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);

	// The first conversion interns the names of the chain, which the intern
	// pool keeps, so the count reads the second.
	let mode = TraceProcessMode::WithObservableInstrumentation;
	drop(trace.to_process_with_mode(mode));

	let before = ALLOCATIONS.with(Cell::get);
	let process = trace.to_process_with_mode(mode);
	let after = ALLOCATIONS.with(Cell::get);

	drop(process);
	after.saturating_sub(before)
}

#[test]
fn a_record_that_the_chain_leaves_out_renders_nothing() {
	assert_eq!(chain_with_records_left_out(3), chain_with_records_left_out(0));
}

/// The DER of a frame envelope: a content sealed to one KEK recipient.
fn sealed_envelope() -> Result<Vec<u8>, Box<dyn Error>> {
	let key = [0x5au8; 32];
	let kek = Kek::try_from(key.as_slice())?;
	let recipient: Recipient<'_, DefaultCryptoProvider> = Recipient::Kek { kek, key_identifier: b"allocations" };
	let sealed = AuthEnvelopedData::seal(recipient, DATA, b"content".to_vec(), [], None)?;
	Ok(sealed.to_der()?)
}

/// The counts of the allocations that the decode of a frame envelope makes
/// through its `WireDer`, which holds the value to its arrival, and through a
/// plain decode beside the one copy of its bytes that a `WireDer` keeps.
fn decodes_of_a_frame_envelope() -> Result<(usize, usize), Box<dyn Error>> {
	let arrived = sealed_envelope()?;

	let before = ALLOCATIONS.with(Cell::get);
	let held = WireDer::<AuthEnvelopedData>::try_from(arrived.as_slice());
	let between = ALLOCATIONS.with(Cell::get);
	let decoded = AuthEnvelopedData::from_der(&arrived);
	let kept = arrived.to_vec();
	let after = ALLOCATIONS.with(Cell::get);

	held?;
	decoded?;
	drop(kept);
	Ok((between - before, after - between))
}

/// The hold of a frame envelope streams its encoding against its arrival, so
/// its decode allocates what a plain decode and the kept copy allocate.
#[test]
fn a_frame_envelope_holds_its_arrival_with_no_allocation() -> Result<(), Box<dyn Error>> {
	let (held, decoded) = decodes_of_a_frame_envelope()?;
	assert_eq!(held, decoded);
	Ok(())
}

/// The counts of the allocations that two specs of the fields `kind` and `id`
/// make as each reads the NSS `trace/abc`: one that joins the fields at `/`,
/// and one whose format places the `/`.
fn reads_of_one_nss() -> Result<(usize, usize), UrnValidationError> {
	let spec = UrnSpecBuilder::from("example").field_required("kind").field_required("id");
	let joined = spec.clone().field_nss_separator("id", "/");
	let formatted = spec.nss_format("{}/{}");

	let before = ALLOCATIONS.with(Cell::get);
	let joined_read = joined.parse_nss("trace/abc");
	let between = ALLOCATIONS.with(Cell::get);
	let formatted_read = formatted.parse_nss("trace/abc");
	let after = ALLOCATIONS.with(Cell::get);

	joined_read?;
	formatted_read?;
	Ok((between - before, after - between))
}

/// A join format reads each separator from the fields of its spec, so it
/// reads an NSS with the allocations of a custom format of the same values.
#[test]
fn a_joined_nss_reads_with_the_allocations_of_a_formatted_one() -> Result<(), UrnValidationError> {
	let (joined, formatted) = reads_of_one_nss()?;
	assert_eq!(joined, formatted);
	Ok(())
}

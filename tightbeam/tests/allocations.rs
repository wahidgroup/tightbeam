//! Allocation bounds of hot paths. Only an allocation count shows them, so
//! the counting allocator lives in this test binary alone.
//!
//! The paths need `colony`, `hpke`, `zstd`, `testing-fdr`, `instrument`, and
//! the tokio TCP transport. The dev feature set and `--all-features` turn on
//! each of them, and the target builds under those two.

// Tests are exempt from the zero-panic index and arithmetic lints (workspace
// lints): an index out of range fails its test at its location.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
// Raw `unwrap()` is banned crate-wide: test cases propagate with `?`, and
// helpers state their invariant through `expect`.
#![deny(clippy::unwrap_used)]

use core::cell::Cell;
use core::future::{ready, Future};
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::alloc::{GlobalAlloc, Layout, System};
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
use tightbeam::oids::{CURVE_NIST_P256, CURVE_NIST_P521, DATA};
use tightbeam::policy::TransitStatus;
use tightbeam::spki::SubjectPublicKeyInfoOwned;
use tightbeam::testing::fdr::{DefaultFdrExplorer, FdrConfig};
use tightbeam::testing::fixtures::{TestCertificate, TestKey, TestRumor, TestSigner};
use tightbeam::testing::specs::csp::{Event, Process, ProcessBuildError, State};
use tightbeam::testing::{TestFrame, TestMessage};
use tightbeam::trace::{ConsumedTrace, TraceCollector, TraceConfig};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioStream};
use tightbeam::transport::{
	AsyncProtocolStream, AsyncReadStream, EndpointConfig, EnvelopeSource, MessageIO, SplittableStream,
};
use tightbeam::urn::UrnSpecBuilder;
use tightbeam::x509::Certificate;
use tightbeam::{compose, tb_cases, Frame, TightBeamError};

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

/// The output of `act`, beside the count of the allocations that `act` makes
/// on this thread.
fn counted<T>(act: impl FnOnce() -> T) -> (T, usize) {
	let before = ALLOCATIONS.with(Cell::get);
	let output = act();
	let after = ALLOCATIONS.with(Cell::get);
	(output, after - before)
}

/// The self-signed certificate of the fixed secp256k1 key.
fn house_certificate() -> Certificate {
	TestCertificate::self_signed(&TestKey::insecure_fixed_signing())
}

/// The SubjectPublicKeyInfo of the key that is `point` on the named curve
/// `curve`.
fn spki_of(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
	let certificate = TestCertificate::with_curve_point(house_certificate(), curve, point);
	certificate.tbs_certificate.subject_public_key_info
}

/// The SubjectPublicKeyInfo of the fixed secp256k1 key, whose curve the house
/// set holds a decoder of.
fn house_key() -> SubjectPublicKeyInfoOwned {
	house_certificate().tbs_certificate.subject_public_key_info
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

	counted(|| index.find(spki).is_some())
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
	let certificate = house_certificate();
	let key = CanonicalKey::of(&certificate.tbs_certificate.subject_public_key_info);
	let key = key.expect("a house key has a canonical form");
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	let builder = builder.with_certificate(certificate);
	let store = builder.expect("the fixed certificate enrols").build();

	counted(|| store.find_by_canonical_key(&key).is_some())
}

/// Whether the `sid` of the house certificate of the fixed key names that
/// certificate, beside the count of the allocations that the match makes.
fn naming_of_the_house_certificate() -> (bool, usize) {
	let certificate = house_certificate();
	let sid = certificate.signer_identifier();
	let sid = sid.expect("a house certificate carries its key identifier");

	let (named, allocations) = counted(|| certificate.is_named_by(&sid));
	(named.expect("the key identifier decodes"), allocations)
}

/// The counts of the allocations that a store of the fixed root makes as it
/// validates the fixed path, as a presented path and as one chain.
fn validations_of_the_fixed_path() -> (usize, usize) {
	let chain = TestCertificate::insecure_fixed_chain().expect("the fixed test chain issues");
	let builder = CertificateTrustBuilder::new(Secp256k1Policy::default(), KeyCurves::HOUSE, NoRevocation);
	let builder = builder.with_certificate(chain.root);
	let store = builder.expect("the root is within its validity period").build();
	let whole = [chain.intermediate.to_owned(), chain.leaf.to_owned()];
	let issuers = [chain.intermediate];

	let (chained, as_one_chain) = counted(|| store.verify_chain(&whole));
	let (presented, as_presented) = counted(|| store.verify_presented(&issuers, &chain.leaf));
	chained.expect("the path validates as one chain");
	presented.expect("the path validates as presented");
	(as_presented, as_one_chain)
}

/// The counts of the allocations that the DER encoding of the fixed signer
/// structure makes, through its `Signed` wrapper and as its inner `SignerInfo`.
fn encodings_of_the_fixed_signer() -> (usize, usize) {
	let signed = TestSigner::info();

	let (wrapped, through_wrapper) = counted(|| signed.to_der());
	let (inner, as_inner) = counted(|| signed.as_ref().to_der());
	wrapped.expect("the signed structure encodes");
	inner.expect("the inner structure encodes");
	(through_wrapper, as_inner)
}

/// The count of the allocations that a read of a 32-octet SHA3-256 rumor
/// digest makes.
fn allocations_of_a_digest_read() -> usize {
	let bytes = [7u8; 32];

	let (digest, allocations) = counted(|| GossipDigest::read::<Sha3_256>(bytes));
	digest.expect("32 octets read as a SHA3-256 digest");
	allocations
}

/// The allocation counts of the fixed rumor's admission and of its two steps
/// that own a buffer: the decode of its body and the encoding of its
/// to-be-signed frame.
fn admissions_of_the_fixed_rumor() -> (usize, usize) {
	let rumor = TestRumor::verified(TestRumor::application(1_000, [1, 2, 3]));
	let frame = rumor.frame();
	let now = UnixMillis::new(1_000);

	let (admitted, admission) = counted(|| AdmittedGossip::admit::<Sha3_256>(&rumor, 0, Duration::from_secs(30), now));
	let ((body, tbs), parts) = counted(|| (frame.decode_message::<GossipRumor>(), frame.to_tbs()));
	admitted.expect("the fixed rumor is fresh and within its bounds");
	body.expect("the fixed rumor's body decodes");
	tbs.expect("the fixed rumor encodes");
	(admission, parts)
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

	let (want, allocations) = counted(|| WantList::against::<Sha3_256>(&advertised, &held));
	(want.digests().is_empty(), allocations)
}

/// A cleartext frame whose body `zstd` compressed.
fn compressed_frame() -> Frame {
	let message = TestMessage::sample(None);
	let compressor = ZstdCompression::default();
	let composed = compose! { V0: id: "detail-off", order: 1u64, message: message, compactness: compressor };
	composed.expect("a sample message composes")
}

/// The allocation counts of a compressed frame's inflate through the typed
/// delivery of a servlet whose trace config leaves `enable_internal_detail`
/// off, and alone.
fn inflations_with_the_detail_off() -> (usize, usize) {
	let inflator: Arc<dyn Inflator + Send + Sync> = Arc::new(ZstdCompression::default());
	let ctx = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), [], None);
	let ctx = ctx.with_message_inflator(Some(inflator));
	let mut alone = compressed_frame();
	let mut delivered = compressed_frame();
	let mut cx = Context::from_waker(Waker::noop());

	let (inflated, inflate) = counted(|| alone.inflate_in_place(&ZstdCompression::default()));
	let (delivery, through_delivery) = counted(|| pin!(delivered.prepare_typed(&ctx)).poll(&mut cx));
	let _opened = inflated.expect("the zstd body inflates");

	let Poll::Ready(prepared) = delivery else {
		panic!("the inflate of a typed delivery completes on its first poll");
	};

	prepared.expect("the typed delivery inflates the zstd body");
	(through_delivery, inflate)
}

/// A frame of a sample message, sealed to a bare recipient of the house KEM.
fn kem_sealed_frame() -> Frame {
	let backend = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
	let public_key = backend.to_public_key_bytes().expect("the fixed key has a public key");
	let recipient = KemRecipient::bare(public_key).expect("a secp256k1 public key is a KEM recipient");
	let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
	let message = TestMessage::sample(None);

	let composed = compose! { V1: id: "kem-shape", order: 1u64, message: message, encryptor: encryptor };
	composed.expect("a sample message seals to a KEM recipient")
}

/// The allocation count of the requirement check of a frame sealed to one
/// KEM recipient.
fn allocations_of_a_kem_shape() -> usize {
	let frame = kem_sealed_frame();
	let (admitted, allocations) = counted(|| frame.validate_for::<TestMessage>());
	admitted.expect("a sealed frame meets the requirements of its message");

	allocations
}

/// The two ends of a loopback connection: the end that dialed, as a stream a
/// transport takes, and the end that the listener accepted.
async fn loopback_pair() -> (TokioStream, tokio::net::TcpStream) {
	let bound = tokio::net::TcpListener::bind("127.0.0.1:0").await;
	let listener = bound.expect("a loopback port binds");
	let address = listener.local_addr().expect("a bound listener has an address");
	let connected = tokio::net::TcpStream::connect(address).await;

	let stream = connected.expect("a loopback listener accepts");
	let (peer, _) = listener.accept().await.expect("the listener accepts the dial");
	(TokioStream::from(stream), peer)
}

/// A cleartext transport over a loopback connection, whose trace leaves
/// `enable_internal_detail` off, beside the end it talks to.
async fn loopback_transport() -> (TcpTransport<TokioStream>, tokio::net::TcpStream) {
	let (stream, peer) = loopback_pair().await;
	let config = EndpointConfig::<DefaultCryptoProvider>::cleartext();
	(TcpTransport::new(stream, config).with_trace(TraceCollector::new()), peer)
}

/// A current-thread runtime with its I/O and its timers.
fn runtime() -> tokio::runtime::Runtime {
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
	runtime.expect("a current-thread runtime builds")
}

/// The count of the allocations that a single-flight turn makes as it answers
/// one admitted frame with a handler that allocates nothing, on a connection
/// whose trace leaves `enable_internal_detail` off.
fn single_flight_turn_with_the_detail_off() -> usize {
	let runtime = runtime();
	let (mut transport, _peer) = runtime.block_on(loopback_transport());
	let collected = (Arc::new(TestFrame::v0(None, None)), TransitStatus::Ok);
	let echo = |frame: Frame, _session| ready(Ok::<_, TightBeamError>(Some(frame)));
	let mut session = None;
	let mut cx = Context::from_waker(Waker::noop());

	let one_turn = || pin!(SingleFlightAnswer::of(&mut transport, &mut session, collected, echo)).poll(&mut cx);
	let (turn, allocations) = counted(one_turn);
	let Poll::Ready(answer) = turn else {
		panic!("a turn whose handler is ready completes on its first poll");
	};

	answer.failure.map_or(Ok(()), Err).expect("the turn answers the admitted frame");
	allocations
}

/// The DER of an envelope-sized frame: an `OCTET STRING` of two octets.
const FRAME: [u8; 4] = [0x04, 0x02, 0xAA, 0xBB];

/// The counts of the allocations that one write makes through a transport,
/// which bounds it by its operation timeout, and through a bare stream. Each
/// side writes once before the count, so the count reads a connection that
/// is ready to write.
fn writes_with_and_without_a_deadline() -> (usize, usize) {
	let runtime = runtime();
	let _entered = runtime.enter();
	let (mut transport, _peer) = runtime.block_on(loopback_transport());
	let (mut bare, _bare_peer) = runtime.block_on(loopback_pair());

	runtime
		.block_on(transport.write_envelope_bytes(&FRAME))
		.expect("a loopback write completes");
	runtime.block_on(bare.write_frame(&FRAME)).expect("a loopback write completes");

	let mut cx = Context::from_waker(Waker::noop());
	let (bounded, through_deadline) = counted(|| pin!(transport.write_envelope_bytes(&FRAME)).poll(&mut cx));
	let (unbounded, through_bare) = counted(|| pin!(bare.write_frame(&FRAME)).poll(&mut cx));
	assert!(
		matches!(bounded, Poll::Ready(Ok(()))),
		"a write with room completes on its first poll"
	);
	assert!(
		matches!(unbounded, Poll::Ready(Ok(()))),
		"a write with room completes on its first poll"
	);
	(through_deadline, through_bare)
}

/// The counts of the allocations that a read from a silent peer makes as it
/// starts to wait: through a transport, which bounds it by its operation
/// timeout and waited once before, and through a bare stream.
fn waits_with_and_without_a_deadline() -> (usize, usize) {
	let runtime = runtime();
	let _entered = runtime.enter();
	let (mut transport, _peer) = runtime.block_on(loopback_transport());
	let (mut bare, _bare_peer) = runtime.block_on(loopback_pair());
	let mut cx = Context::from_waker(Waker::noop());
	let warmed = pin!(transport.read_envelope_bytes()).poll(&mut cx);
	assert!(warmed.is_pending(), "a read from a silent peer waits");

	let (bounded, through_deadline) = counted(|| pin!(transport.read_envelope_bytes()).poll(&mut cx));
	let (unbounded, through_bare) =
		counted(|| pin!(AsyncProtocolStream::read_frame(&mut bare, FRAME.len())).poll(&mut cx));
	assert!(bounded.is_pending(), "a read from a silent peer waits");
	assert!(unbounded.is_pending(), "a read from a silent peer waits");
	(through_deadline, through_bare)
}

/// The counts of the allocations that a read from a silent peer makes as it
/// starts to wait: through the read half of a split transport, which bounds it
/// and waited once before, and through a bare read half.
fn split_waits_with_and_without_a_deadline() -> (usize, usize) {
	let runtime = runtime();
	let _entered = runtime.enter();
	let (transport, _peer) = runtime.block_on(loopback_transport());
	let (mut reader, _writer) = transport.into_split().expect("a cleartext transport splits");
	let (bare, _bare_peer) = runtime.block_on(loopback_pair());
	let (mut bare_reader, _bare_writer) = bare.into_split();
	let mut cx = Context::from_waker(Waker::noop());
	let warmed = pin!(reader.read_envelope()).poll(&mut cx);
	assert!(warmed.is_pending(), "a read from a silent peer waits");

	let (bounded, through_deadline) = counted(|| pin!(reader.read_envelope()).poll(&mut cx));
	let (unbounded, through_bare) = counted(|| pin!(bare_reader.read_frame(FRAME.len())).poll(&mut cx));
	assert!(bounded.is_pending(), "a read from a silent peer waits");
	assert!(unbounded.is_pending(), "a read from a silent peer waits");
	(through_deadline, through_bare)
}

/// The allocation counts of a record with evidence and of a bare assertion on
/// a trace whose sink holds no event, after one warm-up record of each.
fn records_on_a_full_sink() -> (usize, usize) {
	let config = TbInstrumentationConfig { max_events: 0, ..Default::default() };
	let trace = TraceCollector::from(TraceConfig::with_instrumentation(config));
	let warmed = trace.emit_event_with_evidence(events::GATE_ACCEPT, "Ok", None);
	warmed.expect("a record on a full sink returns");

	let warm_assertion = trace.event(&events::GATE_ACCEPT);
	warm_assertion.expect("an assertion on a full sink returns").emit();

	let (evidenced, with_evidence) = counted(|| trace.emit_event_with_evidence(events::GATE_ACCEPT, "Ok", None));
	let (asserted, bare) = counted(|| trace.event(&events::GATE_ACCEPT).map(|builder| builder.emit()));
	evidenced.expect("a record on a full sink returns");
	asserted.expect("an assertion on a full sink returns");

	(with_evidence, bare)
}

/// A process with no hidden event, whose `ping` and `pong` take `S0` to `S1`
/// and back.
fn ring() -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder("Ring")
		.initial_state(State("S0"))
		.add_observable(Event("ping"))
		.add_observable(Event("pong"))
		.add_transition(State("S0"), Event("ping"), State("S1"))
		.add_transition(State("S1"), Event("pong"), State("S0"))
		.build();

	built.expect("a ring of two events builds")
}

/// The count of the allocations that one seed of `process` makes with
/// `max_internal_run` at `bound`.
fn allocations_of_one_seed(process: &Process, bound: usize) -> usize {
	let config = FdrConfig { seeds: 1, max_internal_run: bound, ..Default::default() };
	let mut explorer = DefaultFdrExplorer::with_defaults(process, config);
	// A first exploration fills the lazy state of the thread, which the count
	// leaves out.
	explorer.explore().expect("the run asks for no FMEA report");

	let (explored, allocations) = counted(|| explorer.explore());
	explored.expect("the run asks for no FMEA report");
	allocations
}

/// The allocation counts of one seed of `ring` with `max_internal_run` at 32
/// and at 0.
fn hidden_run_bounds_of_the_ring() -> (usize, usize) {
	let process = ring();
	(allocations_of_one_seed(&process, 32), allocations_of_one_seed(&process, 0))
}

/// Whether `S0` of `ring` diverges, beside the count of the allocations that
/// the divergent states of `ring` make.
fn divergent_states_of_the_ring() -> (bool, usize) {
	let process = ring();
	let (divergent, allocations) = counted(|| process.divergent_states());
	(divergent.contains(State("S0")), allocations)
}

/// A process whose observable `ping` takes `S0` to `S1`, and whose hidden
/// `tick` takes `S1` back to `S0`, so `S0` has no hidden step.
fn ticking() -> Process {
	let built: Result<Process, ProcessBuildError> = Process::builder("Ticking")
		.initial_state(State("S0"))
		.add_observable(Event("ping"))
		.add_hidden(Event("tick"))
		.add_transition(State("S0"), Event("ping"), State("S1"))
		.add_transition(State("S1"), Event("tick"), State("S0"))
		.build();

	built.expect("a process of one observable and one hidden event builds")
}

/// Whether `S0` of `ticking` is stable and has no divergence witness, beside
/// the count of the allocations that the two answers make.
fn answers_at_a_state_with_no_hidden_step() -> (bool, bool, usize) {
	let process = ticking();
	let divergent = process.divergent_states();

	let answers = || (process.is_stable(State("S0")), divergent.witness(State("S0")).is_none());
	let ((stable, unwitnessed), allocations) = counted(answers);
	(stable, unwitnessed, allocations)
}

/// A state with no hidden step answers whether it is stable and whether it
/// diverges with no allocation.
#[test]
fn a_state_with_no_hidden_step_answers_with_no_allocation() {
	assert_eq!(answers_at_a_state_with_no_hidden_step(), (true, true, 0));
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

	let (process, allocations) = counted(|| trace.to_process_with_mode(mode));
	drop(process);
	allocations
}

/// The allocation counts of the conversion of a trace with three records that
/// the chain leaves out, and of a trace with none.
fn chains_with_and_without_records_left_out() -> (usize, usize) {
	(chain_with_records_left_out(3), chain_with_records_left_out(0))
}

/// The DER of a frame envelope: a content sealed to one KEK recipient.
fn sealed_envelope() -> Vec<u8> {
	let key = [0x5au8; 32];
	let kek = Kek::try_from(key.as_slice()).expect("32 octets are a KEK");
	let recipient: Recipient<'_, DefaultCryptoProvider> = Recipient::Kek { kek, key_identifier: b"allocations" };
	let sealed = AuthEnvelopedData::seal(recipient, DATA, b"content".to_vec(), [], None);
	let sealed = sealed.expect("a content seals to a KEK recipient");
	sealed.to_der().expect("a sealed envelope encodes")
}

/// The counts of the allocations that the decode of a frame envelope makes
/// through its `WireDer`, which holds the value to its arrival, and through a
/// plain decode beside the one copy of its bytes that a `WireDer` keeps.
fn decodes_of_a_frame_envelope() -> (usize, usize) {
	let arrived = sealed_envelope();

	let (held, through_wire_der) = counted(|| WireDer::<AuthEnvelopedData>::try_from(arrived.as_slice()));
	let ((decoded, kept), plain) = counted(|| (AuthEnvelopedData::from_der(&arrived), arrived.to_vec()));
	held.expect("the envelope holds as it arrived");
	decoded.expect("the envelope decodes");
	drop(kept);
	(through_wire_der, plain)
}

/// The counts of the allocations that two specs of the fields `kind` and `id`
/// make as each reads the NSS `trace/abc`: one that joins the fields at `/`,
/// and one whose format places the `/`.
fn reads_of_one_nss() -> (usize, usize) {
	let spec = UrnSpecBuilder::from("example").field_required("kind").field_required("id");
	let joined = spec.clone().field_nss_separator("id", "/");
	let formatted = spec.nss_format("{}/{}");

	let (joined_read, through_join) = counted(|| joined.parse_nss("trace/abc"));
	let (formatted_read, through_format) = counted(|| formatted.parse_nss("trace/abc"));
	joined_read.expect("the joined spec reads the NSS");
	formatted_read.expect("the formatted spec reads the NSS");
	(through_join, through_format)
}

/// The answer of a path, beside the count of the allocations it makes.
type Answered = (bool, usize);

// A path decides its answer with a fixed count of allocations.
tb_cases! {
	fn a_path_answers_with_its_allocation_count((measured, expected): (fn() -> Answered, Answered)) {
		assert_eq!(measured(), expected);
	}
	cases {
		/// A lookup of the fixed secp256k1 key decodes it and writes its
		/// canonical form on the stack.
		house_key_lookup => (|| lookup_of(&house_key()), (true, 0)),
		/// A lookup of the P-256 key of RFC 6979 § A.2.5 writes its canonical
		/// form on the stack.
		rfc6979_p256_lookup => (
			|| lookup_of(&spki_of(CURVE_NIST_P256, &TestKey::RFC6979_P256_UNCOMPRESSED)),
			(true, 0),
		),
		/// A lookup of the P-521 key of RFC 6979 § A.2.7, the widest named
		/// prime curve, writes its canonical form on the stack.
		rfc6979_p521_lookup => (
			|| lookup_of(&spki_of(CURVE_NIST_P521, &TestKey::RFC6979_P521_UNCOMPRESSED)),
			(true, 0),
		),
		/// The house store finds the canonical key a session holds in its key
		/// index with no decode, so a session classification lookup allocates
		/// nothing.
		canonical_key_on_the_house_store => (canonical_lookup_on_the_house_store, (true, 0)),
		/// A `sid` of the key-identifier form names a house certificate by the
		/// extension value the certificate holds, read in place (RFC 5652 §
		/// 5.3).
		key_identifier_naming => (naming_of_the_house_certificate, (true, 0)),
		/// A want list against entries the replier holds in full allocates its
		/// held set alone, and borrows the advertised entries it drops.
		want_list_against_held_entries => (want_list_against_held_entries, (true, 1)),
		/// The divergent states of a process with no hidden event cost no
		/// allocation.
		divergent_states_of_a_process_with_no_hidden_event => (divergent_states_of_the_ring, (false, 0)),
	}
}

// A path allocates what its reference allocates, so the part that the path adds
// to the reference allocates nothing.
tb_cases! {
	fn a_path_allocates_what_its_reference_allocates(measured: fn() -> (usize, usize)) {
		let (path, reference) = measured();
		assert_eq!(path, reference);
	}
	cases {
		/// The built-in store validates a presented path where its issuers and
		/// leaf sit, so it allocates what one chain allocates and copies no
		/// certificate.
		presented_path => validations_of_the_fixed_path,
		/// A frame signature encodes in place, so the `Signed` wrapper of a
		/// `SignerInfo` allocates what its inner value allocates, and no
		/// buffer.
		signed_signer_info => encodings_of_the_fixed_signer,
		/// A rumor admits with no allocation for its digest: the admission
		/// allocates what its body decode and its to-be-signed encoding
		/// allocate, and the digest it records sits on the stack.
		rumor_admission => admissions_of_the_fixed_rumor,
		/// The internal events cost no allocation while they are off: the typed
		/// delivery of a compressed frame allocates what its inflate allocates,
		/// and the internal event at the inflate allocates nothing.
		typed_delivery_with_the_detail_off => inflations_with_the_detail_off,
		/// An event that a full sink drops costs no allocation of its own: a
		/// record with evidence allocates what a bare assertion allocates, the
		/// assertion of the testing layer alone.
		record_on_a_full_sink => records_on_a_full_sink,
		/// The hidden run bound sets no work on a process with no hidden event,
		/// so its exploration allocates the same at any bound.
		hidden_run_bound => hidden_run_bounds_of_the_ring,
		/// A record that the chain leaves out allocates nothing.
		chain_records_left_out => chains_with_and_without_records_left_out,
		/// The hold of a frame envelope streams its encoding against its
		/// arrival, so its decode allocates what a plain decode and the kept
		/// copy allocate.
		frame_envelope_hold => decodes_of_a_frame_envelope,
		/// A join format reads each separator from the fields of its spec, so
		/// it reads an NSS with the allocations of a custom format of the same
		/// values.
		joined_nss => reads_of_one_nss,
		/// A write that completes on its first poll arms no timer, so its
		/// deadline allocates nothing.
		deadlined_write => writes_with_and_without_a_deadline,
		/// A transport keeps the sleep of its first wait and resets it for each
		/// wait after, so the deadline of a later wait allocates nothing.
		deadlined_wait => waits_with_and_without_a_deadline,
		/// The read half of a split transport keeps its sleep as the whole
		/// transport does, so the deadline of a later wait allocates nothing.
		deadlined_split_wait => split_waits_with_and_without_a_deadline,
	}
}

// A path makes an exact count of allocations.
tb_cases! {
	fn a_path_makes_its_allocation_count((measured, allocations): (fn() -> usize, usize)) {
		assert_eq!(measured(), allocations);
	}
	cases {
		/// A rumor digest that a peer names reads onto the stack.
		digest_read => (allocations_of_a_digest_read, 0),
		/// The requirement check reads the wrap of a KEM recipient in place, so
		/// it allocates the list of wraps alone and copies no field of the
		/// recipient.
		kem_shape_check => (allocations_of_a_kem_shape, 1),
		/// The handler span costs no allocation while the internal events are
		/// off: a single-flight turn that answers an admitted frame, with a
		/// handler that allocates nothing, allocates nothing.
		single_flight_turn_with_the_detail_off => (single_flight_turn_with_the_detail_off, 0),
	}
}

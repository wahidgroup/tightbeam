//! The seal and the open of one record and of one frame.
//!
//! Each row reports the time of one seal and one open together, and the
//! allocations of each. A record row also reports the octets its wire
//! envelope adds to the payload.
//!
//! - A record seals an `AuthEnvelopedData` under a fresh content key that
//!   the directional key wraps, and encodes it in a wire envelope.
//! - The record opens through `WireEnvelope::arrive`, in the buffer it arrived in.
//! - A frame seals its body through the house provider and opens it in place.
//! - Each round clones the payload or the cleartext frame it starts from.
//!
//! `make bench` runs it.

mod measure;

use core::cell::Cell;
use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;

use tightbeam::crypto::aead::{RecordDirection, RecvCipher, RuntimeAead, SendCipher};
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::der::Encode;
use tightbeam::testing::{TestKey, TestMessage};
use tightbeam::transport::{Arrived, WireEnvelope};
use tightbeam::{compose, Frame};
use tokio::runtime::{Builder, Runtime};

use measure::median_ns;

/// The payload sizes of the record rows, in octets.
const RECORD_SIZES: [usize; 4] = [0, 64, 1024, 16 * 1024];

/// The sizes of the sample message of the frame rows, in characters.
const FRAME_SIZES: [usize; 3] = [64, 1024, 16 * 1024];

thread_local! {
	/// The count of the allocations of this thread.
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

/// Returns the output of `step` and the allocations it made.
fn counted<T>(step: impl FnOnce() -> T) -> (T, usize) {
	let before = ALLOCATIONS.with(Cell::get);
	let output = step();
	let after = ALLOCATIONS.with(Cell::get);
	(output, after.saturating_sub(before))
}

/// The two ends of one session direction under one key: the send cipher of
/// one peer and the receive cipher of the other.
struct Record {
	send: SendCipher,
	recv: RecvCipher,
}

impl Record {
	fn new() -> Self {
		let key = || RuntimeAead::new::<DefaultCryptoProvider>(vec![0x42u8; 32]).expect("a 32-octet key wrap key");
		let direction = RecordDirection::ClientToServer;

		let send = SendCipher::new(key(), 0, direction);
		let recv = RecvCipher::new(key(), 0, direction);
		Self { send, recv }
	}

	/// The rounds of one measurement of a payload of `size` octets.
	fn rounds(size: usize) -> u32 {
		match size {
			0..=64 => 200_000,
			65..=1024 => 100_000,
			_ => 20_000,
		}
	}

	/// Seals `payload` and encodes its wire envelope.
	fn seal(&self, payload: &[u8]) -> Vec<u8> {
		let record = self.send.encrypt_next(payload.to_vec()).expect("the record seals");
		WireEnvelope::Encrypted(record).to_der().expect("the wire envelope encodes")
	}

	/// Reads the wire envelope in `wire` and opens its record in place, and
	/// returns the length of the payload.
	fn open(&mut self, wire: &mut [u8]) -> usize {
		let Ok(Arrived::Encrypted(record)) = WireEnvelope::arrive(wire) else {
			panic!("the wire envelope arrives as an encrypted record");
		};

		self.recv.open(record).expect("the record opens").len()
	}

	/// Prints the row of a payload of `size` octets.
	fn row(&mut self, size: usize) {
		let payload = vec![0x5Au8; size];
		let (mut wire, seal_allocs) = counted(|| self.seal(&payload));
		let wire_len = wire.len();
		let (opened, open_allocs) = counted(|| self.open(&mut wire));
		assert_eq!(opened, size, "the record opens to its payload");

		let ns = median_ns(Self::rounds(size), || {
			let mut wire = self.seal(&payload);
			black_box(self.open(&mut wire));
		});

		let overhead = wire_len.saturating_sub(size);
		println!(
			"record payload={size:>5} wire={wire_len:>5} overhead={overhead:>4} seal_allocs={seal_allocs:>2} \
			 open_allocs={open_allocs:>2} seal+open={ns:>9.1} ns"
		);
	}
}

/// A cleartext frame, the in-memory key of the house provider, and the
/// runtime the seal and the open of the frame run on.
struct Sealing {
	runtime: Runtime,
	key: Aes256GcmKeyProvider,
	plain: Frame,
}

impl Sealing {
	/// A cleartext V1 frame of a sample message of `size` characters.
	fn new(size: usize) -> Self {
		let runtime = Builder::new_current_thread().build().expect("a current-thread runtime");
		let content = "x".repeat(size);
		let message = TestMessage::sample(Some(&content));
		let plain = compose! { V1: id: "bench", order: 1u64, message: message }.expect("the frame composes");
		let (_, key) = TestKey::insecure_fixed_cipher();

		Self { runtime, key, plain }
	}

	/// The rounds of one measurement of a message of `size` characters.
	fn rounds(size: usize) -> u32 {
		match size {
			0..=1024 => 20_000,
			_ => 5_000,
		}
	}

	/// Seals the body of `frame` in place.
	fn seal(&self, frame: &mut Frame) {
		let sealed = frame.encrypt_with_provider::<DefaultCryptoProvider>(&self.key);
		self.runtime.block_on(sealed).expect("the frame seals");
	}

	/// Opens the body of `frame` in place.
	fn open(&self, frame: &mut Frame) {
		let opened = frame.decrypt_in_place(&self.key, None);
		// The bench frame carries no digest and no signature, so the open
		// takes out nothing to keep.
		let _opened = self.runtime.block_on(opened).expect("the frame opens");
	}

	/// Prints the row of a message of `size` characters.
	fn row(size: usize) {
		let sealing = Self::new(size);
		let mut frame = sealing.plain.clone();
		let ((), seal_allocs) = counted(|| sealing.seal(&mut frame));
		let ((), open_allocs) = counted(|| sealing.open(&mut frame));
		assert_eq!(frame.message(), sealing.plain.message(), "the frame opens to its message");

		let ns = median_ns(Self::rounds(size), || {
			let mut frame = sealing.plain.clone();
			sealing.seal(&mut frame);
			sealing.open(&mut frame);
			black_box(frame);
		});

		let body = sealing.plain.message().len();
		println!(
			"frame  body={body:>5} seal_allocs={seal_allocs:>2} open_allocs={open_allocs:>2} \
			 seal+open={ns:>9.1} ns"
		);
	}
}

fn main() {
	let mut record = Record::new();
	for size in RECORD_SIZES {
		record.row(size);
	}

	for size in FRAME_SIZES {
		Sealing::row(size);
	}
}

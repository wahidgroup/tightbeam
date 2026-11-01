//! The dedup book and the chain state that the payment and queue harnesses
//! share. Each harness names its events through [`HarnessEvents`], and the
//! tests of a harness build its frames through [`HarnessFrame`].
//!
//! The tests of this module are a self-check of the harness: their subject is
//! the book and the chain of the test tree.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use tightbeam::asn1::{DigestInfo, Version};
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::Encode;
use tightbeam::testing::TestMessage;
use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::{utils, Frame, TightBeamError};

/// The trace events of one harness, and the tag that each one carries.
pub trait HarnessEvents {
	/// The tag of every event of the harness.
	const TAG: &'static str;
	/// The book keeps the answer to a new frame.
	const DEDUP_KEPT: Urn<'static>;
	/// The book skips a duplicate.
	const DEDUP_SKIPPED: Urn<'static>;
	/// The book answers a duplicate from its cache.
	const DEDUP_CACHE_HIT: Urn<'static>;
	/// The chain takes a frame.
	const CHAIN_VALID: Urn<'static>;
	/// The chain refuses a frame.
	const CHAIN_BROKEN: Urn<'static>;
}

/// The idempotency key of a frame: its ID and its order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct IdempotencyKey(Vec<u8>, u64);

impl IdempotencyKey {
	/// The key of `frame`.
	fn of(frame: &Frame) -> Self {
		Self(frame.metadata().id().to_owned(), frame.metadata().order())
	}
}

/// The answer that the book keeps for a key, with the digest of its frame.
struct Kept<R> {
	/// The SHA3-256 digest of the DER of the frame.
	digest: DigestInfo,
	/// The response to the frame.
	response: R,
}

impl<R: Clone> Kept<R> {
	/// The response to a frame of this key whose digest is `digest`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- the frame differs from the frame that the book kept.
	fn answer(&self, digest: &DigestInfo) -> Result<R, TightBeamError> {
		if self.digest != *digest {
			return Err(TightBeamError::InvalidMetadata);
		}

		Ok(self.response.to_owned())
	}
}

/// The book that answers each frame once by its ID and order.
///
/// It binds each answer to the digest of its frame. A clone shares the book.
pub struct DedupBook<E, R> {
	answers: Arc<Mutex<HashMap<IdempotencyKey, Kept<R>>>>,
	events: PhantomData<E>,
}

impl<E, R> Default for DedupBook<E, R> {
	fn default() -> Self {
		Self { answers: Arc::default(), events: PhantomData }
	}
}

impl<E, R> Clone for DedupBook<E, R> {
	fn clone(&self) -> Self {
		Self { answers: Arc::clone(&self.answers), events: PhantomData }
	}
}

impl<E: HarnessEvents, R: Clone> DedupBook<E, R> {
	/// Answers `frame`, and runs `respond` once per key under the lock of the
	/// book.
	///
	/// A duplicate gets the cached response, and a refused frame retries.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- `frame` differs from the frame kept under its key.
	/// - [`TightBeamError::LockPoisoned`] -- the lock of the book is poisoned.
	/// - [`TightBeamError`] -- `respond` refuses, the frame fails to encode, or a trace record fails.
	pub fn answer(
		&self,
		frame: &Frame,
		trace: &TraceCollector,
		respond: impl FnOnce() -> Result<R, TightBeamError>,
	) -> Result<R, TightBeamError> {
		let key = IdempotencyKey::of(frame);
		let digest = utils::digest::<Sha3_256>(frame.to_der()?)?;
		let mut answers = self.answers.lock().map_err(|_| TightBeamError::LockPoisoned)?;

		if let Some(kept) = answers.get(&key) {
			let response = kept.answer(&digest)?;
			trace.event_with(E::DEDUP_SKIPPED, &[E::TAG], ())?;
			trace.event_with(E::DEDUP_CACHE_HIT, &[E::TAG], ())?;
			return Ok(response);
		}

		let response = respond()?;
		answers.insert(key, Kept { digest, response: response.to_owned() });
		trace.event_with(E::DEDUP_KEPT, &[E::TAG], ())?;

		Ok(response)
	}
}

/// The tip of a chain: the order and the message digest of its last frame.
#[derive(Default)]
struct ChainTip {
	last_order: Option<u64>,
	last_digest: Option<DigestInfo>,
}

impl ChainTip {
	/// Whether `frame` links to this tip at a higher order.
	fn takes(&self, frame: &Frame) -> bool {
		let links = self.last_digest.as_ref() == frame.metadata().previous_frame();
		let follows = self.last_order.is_none_or(|last| frame.metadata().order() > last);
		links && follows
	}
}

/// The chain of `previous_frame` links that a harness validates.
///
/// Each frame links to the message digest of the frame before it, at a
/// higher order. A clone shares the chain.
pub struct ChainState<E> {
	state: Arc<Mutex<ChainTip>>,
	events: PhantomData<E>,
}

impl<E> Default for ChainState<E> {
	fn default() -> Self {
		Self { state: Arc::default(), events: PhantomData }
	}
}

impl<E> Clone for ChainState<E> {
	fn clone(&self) -> Self {
		Self { state: Arc::clone(&self.state), events: PhantomData }
	}
}

impl<E: HarnessEvents> ChainState<E> {
	/// Records `frame` once `then` passes under the lock of the chain, and
	/// returns its output.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- the link or the order of the frame breaks the chain.
	/// - [`TightBeamError::LockPoisoned`] -- the lock of the chain is poisoned.
	/// - [`TightBeamError`] -- `then` refuses, the digest fails, or a trace record fails.
	pub fn record<T>(
		&self,
		frame: &Frame,
		trace: &TraceCollector,
		then: impl FnOnce() -> Result<T, TightBeamError>,
	) -> Result<T, TightBeamError> {
		let mut tip = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		if !tip.takes(frame) {
			trace.event_with(E::CHAIN_BROKEN, &[E::TAG], ())?;
			return Err(TightBeamError::InvalidMetadata);
		}

		trace.event_with(E::CHAIN_VALID, &[E::TAG], ())?;

		let digest = utils::digest::<Sha3_256>(frame.message())?;
		let output = then()?;

		tip.last_order = Some(frame.metadata().order());
		tip.last_digest = Some(digest);

		Ok(output)
	}

	/// Returns the digest that the next frame links to.
	#[allow(dead_code)]
	pub fn last_digest(&self) -> Option<DigestInfo> {
		let tip = self.state.lock().ok()?;
		tip.last_digest.to_owned()
	}

	/// Resets the chain state, so a test can start a different chain.
	#[allow(dead_code)]
	pub fn reset(&self) -> Result<(), TightBeamError> {
		let mut tip = self.state.lock().map_err(|_| TightBeamError::LockPoisoned)?;
		tip.last_order = None;
		tip.last_digest = None;
		Ok(())
	}
}

/// The V2 test frames of an id at an order, each of which carries a
/// [`TestMessage`]. The tests of this harness, the DTN suite, and the payment
/// suite build their frames with it.
pub struct HarnessFrame;

impl HarnessFrame {
	/// A frame under `id` at `order` that carries `content` and links to no
	/// frame.
	pub fn at(id: impl AsRef<[u8]>, order: u64, content: impl Into<String>) -> Frame {
		let message = TestMessage { content: content.into() };
		let frame = Version::V2.compose().with_id(id).with_order(order).with_message(message);
		frame.build().expect("a V2 frame with an id and an order builds")
	}

	/// A frame under `id` at `order` that carries `content` and links to the
	/// frame that `previous` digests.
	pub fn linked(id: impl AsRef<[u8]>, order: u64, content: impl Into<String>, previous: DigestInfo) -> Frame {
		let message = TestMessage { content: content.into() };
		let frame = Version::V2.compose().with_id(id).with_order(order);
		let frame = frame.with_previous_hash(previous).with_message(message).build();
		frame.expect("a V2 frame with a previous frame builds")
	}

	/// A frame under `id` at `order` that carries `content` and links to the
	/// message digest of `previous`.
	pub fn after(id: impl AsRef<[u8]>, order: u64, content: impl Into<String>, previous: &Frame) -> Frame {
		let previous = utils::digest::<Sha3_256>(previous.message()).expect("SHA3-256 digests a message");
		Self::linked(id, order, content, previous)
	}
}

mod tests {
	use std::cell::Cell;
	use std::sync::TryLockError;

	use super::*;
	use crate::common::result::TestResult;

	/// The events of these tests.
	struct TestEvents;

	impl HarnessEvents for TestEvents {
		const TAG: &'static str = "dedup-test";
		const DEDUP_KEPT: Urn<'static> = tightbeam::urn!("test", "event:dedup-test/dedup-kept");
		const DEDUP_SKIPPED: Urn<'static> = tightbeam::urn!("test", "event:dedup-test/dedup-skipped");
		const DEDUP_CACHE_HIT: Urn<'static> = tightbeam::urn!("test", "event:dedup-test/dedup-cache-hit");
		const CHAIN_VALID: Urn<'static> = tightbeam::urn!("test", "event:dedup-test/chain-valid");
		const CHAIN_BROKEN: Urn<'static> = tightbeam::urn!("test", "event:dedup-test/chain-broken");
	}

	/// A new frame gets the response that the book runs for it.
	#[test]
	fn a_new_frame_gets_its_response() -> TestResult {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		let frame = HarnessFrame::at("txn1", 1, "first");

		let response = dedup.answer(&frame, &trace, || Ok("AUTH1"))?;
		assert_eq!(response, "AUTH1");
		Ok(())
	}

	// The book answers a second frame after it answers `txn1` at order 1: a
	// duplicate from its cache, and a frame at another order afresh.
	tightbeam::tb_cases! {
		fn the_book_answers((second, response): (Frame, &str)) -> TestResult {
			let trace = TraceCollector::default();
			let dedup = DedupBook::<TestEvents, &str>::default();
			dedup.answer(&HarnessFrame::at("txn1", 1, "first"), &trace, || Ok("AUTH1"))?;

			let answered = dedup.answer(&second, &trace, || Ok("AUTH2"))?;
			assert_eq!(answered, response);
			Ok(())
		}
		cases {
			/// A duplicate gets the cached response of its original.
			a_duplicate_with_the_response_of_its_original => (HarnessFrame::at("txn1", 1, "first"), "AUTH1"),
			/// A frame at another order gets a response of its own.
			another_order_with_a_response_of_its_own => (HarnessFrame::at("txn1", 2, "second"), "AUTH2"),
		}
	}

	/// A changed frame that reuses a kept key is refused.
	#[test]
	fn an_altered_frame_that_reuses_a_key_is_refused() -> TestResult {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		dedup.answer(&HarnessFrame::at("txn1", 1, "the transfer"), &trace, || Ok("AUTH1"))?;

		let altered = dedup.answer(&HarnessFrame::at("txn1", 1, "an altered transfer"), &trace, || Ok("AUTH2"));
		assert!(matches!(altered, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}

	/// The book holds its lock while it answers a new frame, so its check for
	/// a kept answer and its insert of the new one are one step. The test reads
	/// the private lock, because the lock is the behavior.
	#[test]
	fn the_book_answers_a_new_frame_under_its_lock() -> TestResult {
		let trace = TraceCollector::default();
		let book = DedupBook::<TestEvents, &str>::default();
		let locked = Cell::new(false);

		book.answer(&HarnessFrame::at("txn1", 1, "first"), &trace, || {
			locked.set(matches!(book.answers.try_lock(), Err(TryLockError::WouldBlock)));
			Ok("AUTH1")
		})?;

		assert!(locked.get());
		Ok(())
	}

	// The chain refuses a frame whose `previous_frame` misses the last frame
	// of the chain.
	tightbeam::tb_cases! {
		fn the_chain_refuses_a_frame((first, second): (Frame, Frame)) -> TestResult {
			let trace = TraceCollector::default();
			let chain = ChainState::<TestEvents>::default();
			chain.record(&first, &trace, || Ok(()))?;

			let refusal = chain.record(&second, &trace, || Ok(()));
			assert!(matches!(refusal, Err(TightBeamError::InvalidMetadata)));
			Ok(())
		}
		cases {
			/// A frame that links to no frame misses the last frame.
			that_misses_its_last_frame => (HarnessFrame::at("txn1", 1, "first"), HarnessFrame::at("txn2", 2, "second")),
			/// A frame that links to another chain misses the last frame.
			linked_to_another_parent => (
				HarnessFrame::at("ours", 1, "our first"),
				HarnessFrame::after("txn", 2, "second", &HarnessFrame::at("theirs", 1, "their first")),
			),
		}
	}
}

//! The dedup book and the chain state that the payment and queue harnesses
//! share. Each harness names its events through [`HarnessEvents`].

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use tightbeam::asn1::DigestInfo;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::der::Encode;
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

#[cfg(test)]
mod tests {
	use std::cell::Cell;
	use std::sync::TryLockError;

	use tightbeam::asn1::Version;
	use tightbeam::builder::TypeBuilder;
	use tightbeam::der::Sequence;
	use tightbeam::Beamable;

	use super::*;

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

	/// The message of the test frames.
	#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	struct Note {
		#[beam(bytes)]
		body: Vec<u8>,
	}

	/// A frame at `order` under `id` that carries `body`.
	fn note(id: &[u8], order: u64, body: &[u8]) -> Frame {
		let message = Note { body: body.to_vec() };
		let frame = Version::V2.compose().with_id(id).with_order(order).with_message(message);
		frame.build().expect("a V2 frame with an id and an order builds")
	}

	/// A frame at `order` that carries `body` and links to `previous`.
	fn note_after(order: u64, body: &[u8], previous: &Frame) -> Frame {
		let previous = utils::digest::<Sha3_256>(previous.message()).expect("SHA3-256 digests a message");
		let message = Note { body: body.to_vec() };
		let frame = Version::V2.compose().with_id(b"txn").with_order(order);
		let frame = frame.with_previous_hash(previous).with_message(message).build();
		frame.expect("a V2 frame with a previous frame builds")
	}

	#[test]
	fn dedup_first_frame_accepted() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		let frame = note(b"txn1", 1, b"first");

		let response = dedup.answer(&frame, &trace, || Ok("AUTH1"))?;
		assert_eq!(response, "AUTH1");
		Ok(())
	}

	/// A duplicate gets the cached response of its original.
	#[test]
	fn a_duplicate_gets_the_response_of_its_original() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		let frame = note(b"txn1", 1, b"first");
		dedup.answer(&frame, &trace, || Ok("AUTH1"))?;

		let duplicate = dedup.answer(&frame, &trace, || Ok("AUTH2"))?;
		assert_eq!(duplicate, "AUTH1");
		Ok(())
	}

	#[test]
	fn dedup_different_order_accepted() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		dedup.answer(&note(b"txn1", 1, b"first"), &trace, || Ok("AUTH1"))?;

		let response = dedup.answer(&note(b"txn1", 2, b"second"), &trace, || Ok("AUTH2"))?;
		assert_eq!(response, "AUTH2");
		Ok(())
	}

	/// A changed frame that reuses a kept key is refused.
	#[test]
	fn an_altered_frame_that_reuses_a_key_is_refused() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let dedup = DedupBook::<TestEvents, &str>::default();
		dedup.answer(&note(b"txn1", 1, b"the transfer"), &trace, || Ok("AUTH1"))?;

		let altered = dedup.answer(&note(b"txn1", 1, b"an altered transfer"), &trace, || Ok("AUTH2"));
		assert!(matches!(altered, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}

	/// The book holds its lock while it answers a new frame.
	#[test]
	fn the_book_answers_a_new_frame_under_its_lock() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let book = DedupBook::<TestEvents, &str>::default();
		let locked = Cell::new(false);

		book.answer(&note(b"txn1", 1, b"first"), &trace, || {
			locked.set(matches!(book.answers.try_lock(), Err(TryLockError::WouldBlock)));
			Ok("AUTH1")
		})?;

		assert!(locked.get());
		Ok(())
	}

	/// The chain refuses a frame whose `previous_frame` misses its last frame.
	#[test]
	fn the_chain_refuses_a_frame_that_misses_its_last_frame() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let chain = ChainState::<TestEvents>::default();
		chain.record(&note(b"txn1", 1, b"first"), &trace, || Ok(()))?;

		let refusal = chain.record(&note(b"txn2", 2, b"second"), &trace, || Ok(()));
		assert!(matches!(refusal, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}

	/// The chain refuses a frame that links to another parent.
	#[test]
	fn a_frame_linked_to_another_parent_breaks_the_chain() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let chain = ChainState::<TestEvents>::default();
		let theirs = note(b"theirs", 1, b"their first");
		chain.record(&note(b"ours", 1, b"our first"), &trace, || Ok(()))?;

		let refusal = chain.record(&note_after(2, b"second", &theirs), &trace, || Ok(()));
		assert!(matches!(refusal, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}
}

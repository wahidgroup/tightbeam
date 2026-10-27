//! The validation components of the payment harness.
//!
//! [`PaymentHarness`] answers each frame once through the shared dedup book
//! and chain state of `common::dedup`.

use tightbeam::trace::TraceCollector;
use tightbeam::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use super::messages::TransactionStatus;
use crate::common::dedup::{ChainState, DedupBook, HarnessEvents};

pub(crate) const CHAIN_BROKEN: Urn<'static> = tightbeam::urn!("test", "event:harness/chain-broken");
pub(crate) const CHAIN_VALID: Urn<'static> = tightbeam::urn!("test", "event:harness/chain-valid");
pub(crate) const DEDUP_CACHE_HIT: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-cache-hit");
pub(crate) const DEDUP_KEPT: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-kept");
pub(crate) const DEDUP_SKIPPED: Urn<'static> = tightbeam::urn!("test", "event:harness/dedup-skipped");

// The tag of every payment event.

pub const PAYMENT_TAG: &str = "payment";

/// The events of the payment harness.
pub struct PaymentEvents;

impl HarnessEvents for PaymentEvents {
	const TAG: &'static str = PAYMENT_TAG;
	const DEDUP_KEPT: Urn<'static> = DEDUP_KEPT;
	const DEDUP_SKIPPED: Urn<'static> = DEDUP_SKIPPED;
	const DEDUP_CACHE_HIT: Urn<'static> = DEDUP_CACHE_HIT;
	const CHAIN_VALID: Urn<'static> = CHAIN_VALID;
	const CHAIN_BROKEN: Urn<'static> = CHAIN_BROKEN;
}

// The payment harness combines both validations.

/// The payment harness, which combines the dedup book and the chain state.
///
/// The servlets of one payment flow share one harness as their environment,
/// so the dedup book and the chain state span every frame of the flow.
#[derive(Clone, Default)]
pub struct PaymentHarness {
	/// The book of the frames the flow has seen, with the reply to each.
	pub dedup: DedupBook<PaymentEvents, TransactionStatus>,
	/// The chain of the frames of the flow, each linked to the one before.
	pub chain: ChainState<PaymentEvents>,
}

impl PaymentHarness {
	/// Answers an incoming frame once, through both validations, and returns
	/// the response.
	///
	/// The book answers a duplicate from its cache. A new frame gets the
	/// response of `respond` once the chain takes it, and the chain and the
	/// book keep the frame only when `respond` passes.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- the `previous_frame` or the
	///   order of a new frame breaks the chain.
	/// - [`TightBeamError`] -- `respond` refuses the frame, a lock is poisoned, or a trace record fails.
	pub fn answer(
		&self,
		frame: &Frame,
		trace: &TraceCollector,
		respond: impl FnOnce() -> Result<TransactionStatus, TightBeamError>,
	) -> Result<TransactionStatus, TightBeamError> {
		// A duplicate returns before the chain check, so a replay leaves the
		// chain intact. A frame that the chain or `respond` refuses leaves no
		// answer, so its resend meets both again. The lock of the book comes
		// before the lock of the chain.
		self.dedup.answer(frame, trace, || self.chain.record(frame, trace, respond))
	}
}

// The unit tests of the harness.

#[cfg(test)]
mod tests {
	use sha3::Sha3_256;

	use super::*;
	use crate::payments::messages::PaymentIdentification;
	use tightbeam::asn1::Version;
	use tightbeam::builder::TypeBuilder;
	use tightbeam::testing::TestMessage;
	use tightbeam::utils;

	fn test_frame(id: impl AsRef<[u8]>, order: u64) -> Frame {
		let id = id.as_ref();
		Version::V2
			.compose()
			.with_id(id)
			.with_order(order)
			.with_message(TestMessage::sample(None))
			.build()
			.expect("a V2 frame with an id and an order builds")
	}

	/// A frame at `order` that carries `content` and links to `previous`.
	fn linked_frame(id: impl AsRef<[u8]>, order: u64, content: &str, previous: &Frame) -> Frame {
		let previous = utils::digest::<Sha3_256>(previous.message()).expect("SHA3-256 digests a message");
		let frame = Version::V2
			.compose()
			.with_id(id.as_ref())
			.with_order(order)
			.with_previous_hash(previous)
			.with_message(TestMessage::sample(Some(content)))
			.build();

		frame.expect("a V2 frame with a previous frame builds")
	}

	/// The approval of a test payment under `code`.
	fn approval(code: &str) -> TransactionStatus {
		let payment_id = PaymentIdentification::new(b"INST", b"E2E", b"TXN").expect("short identifiers fit");
		TransactionStatus::approved(payment_id, code).expect("a short code fits")
	}

	/// A frame whose `previous_frame` misses the last frame of the chain fails.
	#[test]
	fn a_frame_that_breaks_the_chain_fails() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let harness = PaymentHarness::default();
		harness.answer(&test_frame(b"txn1", 1), &trace, || Ok(approval("AUTH1")))?;

		let refusal = harness.answer(&test_frame(b"txn2", 2), &trace, || Ok(approval("AUTH2")));
		assert!(matches!(refusal, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}

	/// A resend of a frame that broke the chain fails again at the chain check.
	#[test]
	fn a_resent_frame_that_breaks_the_chain_fails_again() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let harness = PaymentHarness::default();
		let broken = test_frame(b"txn2", 2);
		harness.answer(&test_frame(b"txn1", 1), &trace, || Ok(approval("AUTH1")))?;

		let first = harness.answer(&broken, &trace, || Ok(approval("AUTH2")));
		let resend = harness.answer(&broken, &trace, || Ok(approval("AUTH2")));
		assert!(first.is_err());
		assert!(matches!(resend, Err(TightBeamError::InvalidMetadata)));
		Ok(())
	}

	/// A frame whose response fails leaves the chain for its resend.
	#[test]
	fn a_frame_whose_response_fails_leaves_the_chain_for_its_resend() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let harness = PaymentHarness::default();
		let first = test_frame(b"txn1", 1);
		let second = linked_frame(b"txn2", 2, "the second transfer", &first);

		harness.answer(&first, &trace, || Ok(approval("AUTH1")))?;

		let failed = harness.answer(&second, &trace, || Err(TightBeamError::InvalidBody));
		let resend = harness.answer(&second, &trace, || Ok(approval("AUTH2")))?;
		assert!(matches!(failed, Err(TightBeamError::InvalidBody)));
		assert_eq!(resend, approval("AUTH2"));
		Ok(())
	}
}

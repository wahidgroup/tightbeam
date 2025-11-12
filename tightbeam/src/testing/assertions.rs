//! Assertion primitives (temporary stub)
//!
//! This stub restores previously referenced types so macro layer
//! compiles. Will be replaced by full implementation later.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use core::cell::RefCell;
use core::sync::atomic::{AtomicUsize, Ordering};

use crate::crypto::hash::{Digest, Sha3_256};
use crate::testing::macros::Cardinality;

#[cfg(feature = "instrument")]
use crate::instrumentation; // for event emission when feature enabled

thread_local! { static ASSERT_BUF: RefCell<Vec<Assertion>> = RefCell::new(Vec::new()); }
static ASSERT_SEQ: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssertionPhase {
	HandlerStart,
	HandlerEnd,
	Gate,
	Response,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionLabel {
	Custom(&'static str),
}

#[derive(Clone, Debug)]
pub struct Assertion {
	pub seq: usize,
	pub phase: AssertionPhase,
	pub label: AssertionLabel,
	pub payload_hash: Option<[u8; 32]>,
}

impl Assertion {
	pub fn new(seq: usize, phase: AssertionPhase, label: AssertionLabel, payload_hash: Option<[u8; 32]>) -> Self {
		Self { seq, phase, label, payload_hash }
	}
}

#[derive(Clone, Debug)]
pub struct AssertionContract {
	pub phase: AssertionPhase,
	pub label: AssertionLabel,
	pub cardinality: Cardinality,
}

impl AssertionContract {
	pub fn new(phase: AssertionPhase, label: AssertionLabel, cardinality: Cardinality) -> Self {
		Self { phase, label, cardinality }
	}

	pub fn is_satisfied_by(&self, assertions: &[Assertion]) -> bool {
		let count = assertions
			.iter()
			.filter(|a| a.phase == self.phase && a.label == self.label)
			.count();
		self.cardinality.is_satisfied_by(count)
	}

	pub fn describe(&self) -> String {
		self.cardinality.describe()
	}
}

// Re-export cardinality functions via nested module for legacy calls
pub mod cardinality {
	pub use crate::testing::macros::{absent, at_least, at_most, between, exactly, present};
}

// -------------------------------------------------------------------------------------------------
// Assertion recording (runtime) API
// -------------------------------------------------------------------------------------------------

fn hash_payload(data: &[u8]) -> [u8; 32] {
	let mut h = Sha3_256::new();
	h.update(data);
	let out = h.finalize();
	let mut arr = [0u8; 32];
	arr.copy_from_slice(&out);
	arr
}

/// Record an assertion at runtime (invoked by `tb_assert!` macro).
pub fn record_assertion(phase: AssertionPhase, label: &'static str, payload: Option<&[u8]>) {
	let seq = ASSERT_SEQ.fetch_add(1, Ordering::Relaxed);
	let payload_hash = payload.map(hash_payload);
	ASSERT_BUF.with(|buf| {
		buf.borrow_mut()
			.push(Assertion::new(seq, phase, AssertionLabel::Custom(label), payload_hash))
	});
	#[cfg(feature = "instrument")]
	{
		let _ = instrumentation::emit(instrumentation::TbEventKind::AssertLabel, Some(label), None, None, 0, None);
		if let Some(p) = payload {
			let _ =
				instrumentation::emit(instrumentation::TbEventKind::AssertPayload, Some(label), Some(p), None, 0, None);
		}
	}
}

/// Record an assertion to an explicit collector (for ServiceClient testing).
#[cfg(feature = "std")]
pub fn record_assertion_to(
	collector: &std::sync::Arc<std::sync::Mutex<Vec<Assertion>>>,
	phase: AssertionPhase,
	label: &'static str,
	payload: Option<&[u8]>,
) {
	let seq = ASSERT_SEQ.fetch_add(1, Ordering::Relaxed);
	let payload_hash = payload.map(hash_payload);
	collector
		.lock()
		.unwrap()
		.push(Assertion::new(seq, phase, AssertionLabel::Custom(label), payload_hash));
	#[cfg(feature = "instrument")]
	{
		let _ = instrumentation::emit(instrumentation::TbEventKind::AssertLabel, Some(label), None, None, 0, None);
		if let Some(p) = payload {
			let _ =
				instrumentation::emit(instrumentation::TbEventKind::AssertPayload, Some(label), Some(p), None, 0, None);
		}
	}
}

/// Drain all recorded assertions (container/harness integration point).
pub fn drain_assertions() -> Vec<Assertion> {
	ASSERT_BUF.with(|buf| {
		let mut v = buf.borrow_mut();
		let out = v.clone();
		v.clear();
		out
	})
}

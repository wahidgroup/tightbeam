//! Assertion primitives for testing framework
//!
//! This module provides core assertion types and contracts used by the
//! testing framework. All runtime recording now uses `TraceCollector`
//! for async-safe, explicit trace collection.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::testing::macros::Cardinality;

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

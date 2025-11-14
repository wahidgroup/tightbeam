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
	/// Matches any phase - useful for FDR/CSP scenarios where lifecycle phase doesn't matter
	Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionLabel {
	Custom(&'static str),
}

/// Type-safe wrapper for assertion values supporting PartialEq comparison
#[derive(Debug, Clone, PartialEq)]
pub enum AssertionValue {
	String(String),
	Bool(bool),
	U8(u8),
	U32(u32),
	U64(u64),
	I32(i32),
	I64(i64),
	F64(f64),
	None,
}

// From implementations for ergonomic conversion
impl From<String> for AssertionValue {
	fn from(s: String) -> Self {
		Self::String(s)
	}
}

impl From<&str> for AssertionValue {
	fn from(s: &str) -> Self {
		Self::String(s.to_string())
	}
}

impl From<bool> for AssertionValue {
	fn from(b: bool) -> Self {
		Self::Bool(b)
	}
}

impl From<u8> for AssertionValue {
	fn from(n: u8) -> Self {
		Self::U8(n)
	}
}

impl From<u32> for AssertionValue {
	fn from(n: u32) -> Self {
		Self::U32(n)
	}
}

impl From<u64> for AssertionValue {
	fn from(n: u64) -> Self {
		Self::U64(n)
	}
}

impl From<i32> for AssertionValue {
	fn from(n: i32) -> Self {
		Self::I32(n)
	}
}

impl From<i64> for AssertionValue {
	fn from(n: i64) -> Self {
		Self::I64(n)
	}
}

#[derive(Clone, Debug)]
pub struct Assertion {
	pub seq: usize,
	pub phase: AssertionPhase,
	pub label: AssertionLabel,
	pub payload_hash: Option<[u8; 32]>,
	pub value: Option<AssertionValue>,
}

impl Assertion {
	pub fn new(seq: usize, phase: AssertionPhase, label: AssertionLabel, payload_hash: Option<[u8; 32]>) -> Self {
		Self { seq, phase, label, payload_hash, value: None }
	}

	pub fn with_value(
		seq: usize,
		phase: AssertionPhase,
		label: AssertionLabel,
		payload_hash: Option<[u8; 32]>,
		value: AssertionValue,
	) -> Self {
		Self { seq, phase, label, payload_hash, value: Some(value) }
	}
}

#[derive(Clone, Debug)]
pub struct AssertionContract {
	pub phase: AssertionPhase,
	pub label: AssertionLabel,
	pub cardinality: Cardinality,
	pub expected_value: Option<AssertionValue>,
}

impl AssertionContract {
	pub fn new(phase: AssertionPhase, label: AssertionLabel, cardinality: Cardinality) -> Self {
		Self { phase, label, cardinality, expected_value: None }
	}

	pub fn with_value(
		phase: AssertionPhase,
		label: AssertionLabel,
		cardinality: Cardinality,
		expected_value: AssertionValue,
	) -> Self {
		Self { phase, label, cardinality, expected_value: Some(expected_value) }
	}

	pub fn is_satisfied_by(&self, assertions: &[Assertion]) -> bool {
		let matching: Vec<_> = assertions
			.iter()
			.filter(|a| {
				// Match label first
				if a.label != self.label {
					return false;
				}
				// Phase matching: Any matches any phase, or exact match
				match (self.phase, a.phase) {
					(AssertionPhase::Any, _) => true,
					(_, AssertionPhase::Any) => true,
					_ => a.phase == self.phase,
				}
			})
			.collect();

		// Check cardinality
		if !self.cardinality.is_satisfied_by(matching.len()) {
			return false;
		}

		// Check value constraint if present
		if let Some(ref expected) = self.expected_value {
			// All matching assertions must have the expected value
			matching.iter().all(|a| a.value.as_ref() == Some(expected))
		} else {
			true
		}
	}

	pub fn describe(&self) -> String {
		let cardinality_desc = self.cardinality.describe();
		if let Some(ref expected) = self.expected_value {
			format!("{} with value {:?}", cardinality_desc, expected)
		} else {
			cardinality_desc
		}
	}
}

// Re-export cardinality functions via nested module for legacy calls
pub mod cardinality {
	pub use crate::testing::macros::{absent, at_least, at_most, between, exactly, present};
}

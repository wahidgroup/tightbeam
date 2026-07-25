//! Assertion contracts for the testing framework
//!
//! Runtime recording types live in `crate::trace`. This module re-exports them
//! and provides `AssertionContract` for spec verification.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::testing::macros::Cardinality;
pub use crate::trace::{Assertion, AssertionLabel, AssertionValue, IsNone, IsSome, Presence, RatioLimit};

#[derive(Clone, Debug)]
pub struct AssertionContract {
	pub label: AssertionLabel,
	pub tag_filter: Option<Vec<&'static str>>,
	pub cardinality: Cardinality,
	pub expected_value: Option<AssertionValue>,
}

impl AssertionContract {
	pub fn new(label: AssertionLabel, cardinality: Cardinality) -> Self {
		Self { label, tag_filter: None, cardinality, expected_value: None }
	}

	pub fn with_tag_filter(mut self, tags: Vec<&'static str>) -> Self {
		self.tag_filter = Some(tags);
		self
	}

	pub fn with_value(mut self, expected_value: AssertionValue) -> Self {
		self.expected_value = Some(expected_value);
		self
	}

	pub fn is_satisfied_by(&self, assertions: &[Assertion]) -> bool {
		let matching: Vec<_> = assertions
			.iter()
			.filter(|a| {
				// Match label (supports tightbeam URN shorthand)
				if !a.label.matches(&self.label) {
					return false;
				}

				// Tag matching: if spec has tag_filter, assertion must have all those tags
				if let Some(ref filter_tags) = self.tag_filter {
					for filter_tag in filter_tags {
						if !a.tags.contains(filter_tag) {
							return false;
						}
					}
				}

				true
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
		let tag_desc = if let Some(ref tags) = self.tag_filter {
			format!(" with tags {tags:?}")
		} else {
			String::new()
		};
		if let Some(ref expected) = self.expected_value {
			format!("{cardinality_desc} with value {expected:?}{tag_desc}")
		} else {
			format!("{cardinality_desc}{tag_desc}")
		}
	}
}

// Re-export cardinality functions via nested module for legacy calls
pub mod cardinality {
	pub use crate::testing::macros::{absent, at_least, at_most, between, exactly, present};
}

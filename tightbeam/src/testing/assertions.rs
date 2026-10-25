//! Assertion contracts for the testing framework.
//!
//! The runtime recording types live in [`crate::trace`]. This module
//! re-exports them and holds [`AssertionContract`], the requirement a spec
//! checks against the recorded assertions.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::testing::macros::Cardinality;
pub use crate::trace::{Assertion, AssertionLabel, AssertionValue, IsNone, IsSome, Presence, RatioLimit};

/// A count and value requirement that a spec places on one assertion label.
#[derive(Clone, Debug)]
pub struct AssertionContract {
	/// The label an assertion must carry to count toward this contract.
	pub label: AssertionLabel,
	/// The tags a counted assertion must all carry, or `None` for any tags.
	pub tag_filter: Option<Vec<&'static str>>,
	/// The number of counted assertions that satisfies this contract.
	pub cardinality: Cardinality,
	/// The value every counted assertion must carry, or `None` for any value.
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

	pub fn is_satisfied_by(&self, assertions: impl AsRef<[Assertion]>) -> bool {
		let assertions = assertions.as_ref();
		let matching: Vec<_> = assertions
			.iter()
			.filter(|a| {
				// A label matches only by exact URN identity.
				if !a.label.matches(&self.label) {
					return false;
				}

				// The assertion must carry every tag of the filter.
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

		if !self.cardinality.is_satisfied_by(matching.len()) {
			return false;
		}

		if let Some(ref expected) = self.expected_value {
			// Every matching assertion must carry the expected value.
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

//! Assertion primitives for testing framework
//!
//! This module provides core assertion types and contracts used by the
//! testing framework. All runtime recording now uses `TraceCollector`
//! for async-safe, explicit trace collection.

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

use crate::asn1::{MessagePriority, Version};
use crate::testing::macros::Cardinality;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionLabel {
	Custom(&'static str),
}

/// Type-safe wrapper for assertion values supporting PartialEq comparison
#[derive(Debug, Clone)]
pub enum AssertionValue {
	String(String),
	Bool(bool),
	U8(u8),
	U32(u32),
	U64(u64),
	I32(i32),
	I64(i64),
	F64(f64),
	MessagePriority(MessagePriority),
	Version(Version),
	Some(Box<AssertionValue>),
	None,
	NotNone,
	RatioActual(u64, u64),
	RatioLimit(u64, u64),
}

impl PartialEq for AssertionValue {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			// NotNone matches any Some(_) value
			(Self::NotNone, Self::Some(_)) => true,
			(Self::Some(_), Self::NotNone) => true,
			// NotNone matches NotNone (both represent "some value exists")
			(Self::NotNone, Self::NotNone) => true,
			// NotNone does not match None
			(Self::NotNone, Self::None) => false,
			(Self::None, Self::NotNone) => false,
			// Standard comparisons for other variants
			(Self::String(a), Self::String(b)) => a == b,
			(Self::Bool(a), Self::Bool(b)) => a == b,
			(Self::U8(a), Self::U8(b)) => a == b,
			(Self::U32(a), Self::U32(b)) => a == b,
			(Self::U64(a), Self::U64(b)) => a == b,
			(Self::I32(a), Self::I32(b)) => a == b,
			(Self::I64(a), Self::I64(b)) => a == b,
			(Self::F64(a), Self::F64(b)) => a == b,
			(Self::MessagePriority(a), Self::MessagePriority(b)) => a == b,
			(Self::Version(a), Self::Version(b)) => a == b,
			(Self::Some(a), Self::Some(b)) => a == b,
			(Self::None, Self::None) => true,
			(Self::RatioActual(an, ad), Self::RatioActual(bn, bd)) => ratio_equal(*an, *ad, *bn, *bd),
			(Self::RatioLimit(an, ad), Self::RatioLimit(bn, bd)) => ratio_equal(*an, *ad, *bn, *bd),
			(Self::RatioActual(an, ad), Self::RatioLimit(bn, bd)) => ratio_less_equal(*an, *ad, *bn, *bd),
			(Self::RatioLimit(an, ad), Self::RatioActual(bn, bd)) => ratio_less_equal(*bn, *bd, *an, *ad),
			_ => false,
		}
	}
}

fn ratio_equal(an: u64, ad: u64, bn: u64, bd: u64) -> bool {
	if ad == 0 || bd == 0 {
		return false;
	}
	an.saturating_mul(bd) == bn.saturating_mul(ad)
}

fn ratio_less_equal(an: u64, ad: u64, bn: u64, bd: u64) -> bool {
	if ad == 0 || bd == 0 {
		return false;
	}
	an.saturating_mul(bd) <= bn.saturating_mul(ad)
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

impl From<MessagePriority> for AssertionValue {
	fn from(p: MessagePriority) -> Self {
		Self::MessagePriority(p)
	}
}

impl From<Version> for AssertionValue {
	fn from(v: Version) -> Self {
		Self::Version(v)
	}
}

// Option support - convert Some(x) to Some(Box<AssertionValue>) and None to None
impl<T> From<Option<T>> for AssertionValue
where
	T: Into<AssertionValue>,
{
	fn from(opt: Option<T>) -> Self {
		match opt {
			Some(val) => Self::Some(Box::new(val.into())),
			None => Self::None,
		}
	}
}

/// Marker type for asserting that an Option is Some(_) without checking the inner value
/// Use with `equals!(NotNone)` in assertion specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsSome;

impl From<IsSome> for AssertionValue {
	fn from(_: IsSome) -> Self {
		Self::NotNone
	}
}

/// Marker type for asserting that an Option is None
/// Use with `equals!(IsNone)` in assertion specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsNone;

impl From<IsNone> for AssertionValue {
	fn from(_: IsNone) -> Self {
		Self::None
	}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RatioLimit(pub u64, pub u64);

impl From<(u64, u64)> for AssertionValue {
	fn from(pair: (u64, u64)) -> Self {
		Self::RatioActual(pair.0, pair.1)
	}
}

impl From<RatioLimit> for AssertionValue {
	fn from(limit: RatioLimit) -> Self {
		Self::RatioLimit(limit.0, limit.1)
	}
}

#[derive(Clone, Debug)]
pub struct Assertion {
	pub seq: usize,
	pub label: AssertionLabel,
	pub tags: Vec<&'static str>,
	pub payload_hash: Option<[u8; 32]>,
	pub value: Option<AssertionValue>,
}

impl Assertion {
	pub fn new(seq: usize, label: AssertionLabel, tags: Vec<&'static str>, payload_hash: Option<[u8; 32]>) -> Self {
		Self { seq, label, tags, payload_hash, value: None }
	}

	pub fn with_value(
		seq: usize,
		label: AssertionLabel,
		tags: Vec<&'static str>,
		payload_hash: Option<[u8; 32]>,
		value: AssertionValue,
	) -> Self {
		Self { seq, label, tags, payload_hash, value: Some(value) }
	}
}

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
				// Match label first
				if a.label != self.label {
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

//! Runtime assertion recording types for `TraceCollector`.

#[cfg(any(test, feature = "testing"))]
use std::borrow::Cow;

use crate::asn1::{MessagePriority, Version};

#[cfg(feature = "policy")]
use crate::policy::TransitStatus;

#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum AssertionLabel {
	Custom(Cow<'static, str>),
}

#[cfg(any(test, feature = "testing"))]
impl AssertionLabel {
	/// Check if this label matches another, supporting tightbeam URN shorthand.
	///
	/// Returns true if:
	/// - Labels are exactly equal, OR
	/// - `self` (recorded) ends with `/{other}` (shorthand)
	///
	/// This allows specs to use shorthand like `"create_frame_start"` to match
	/// recorded URNs like `"urn:tightbeam:instrumentation:event/create_frame_start"`.
	pub fn matches(&self, other: &AssertionLabel) -> bool {
		if self == other {
			return true;
		}

		// Try shorthand matching: recorded ends with /{expected}
		let (Self::Custom(recorded), Self::Custom(expected)) = (self, other);
		let pattern = ["/", expected.as_ref()].concat();
		recorded.ends_with(&pattern)
	}
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
	F64(f64), // f64 implements PartialOrd and PartialEq - not Ord or Eq
	MessagePriority(MessagePriority),
	Version(Version),
	Some(Box<AssertionValue>),
	IsNone,
	IsSome,
	RatioActual(u64, u64),
	RatioLimit(u64, u64),
	#[cfg(feature = "policy")]
	TransitStatus(TransitStatus),
}

impl PartialEq for AssertionValue {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			// IsSome matches any Some(_) value
			(Self::IsSome, Self::Some(_)) => true,
			(Self::Some(_), Self::IsSome) => true,
			// IsSome matches IsSome (both represent "some value exists")
			(Self::IsSome, Self::IsSome) => true,
			// IsSome does not match None
			(Self::IsSome, Self::IsNone) => false,
			(Self::IsNone, Self::IsSome) => false,
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
			(Self::IsNone, Self::IsNone) => true,
			(Self::RatioActual(an, ad), Self::RatioActual(bn, bd)) => ratio_equal(*an, *ad, *bn, *bd),
			(Self::RatioLimit(an, ad), Self::RatioLimit(bn, bd)) => ratio_equal(*an, *ad, *bn, *bd),
			(Self::RatioActual(an, ad), Self::RatioLimit(bn, bd)) => ratio_less_equal(*an, *ad, *bn, *bd),
			(Self::RatioLimit(an, ad), Self::RatioActual(bn, bd)) => ratio_less_equal(*bn, *bd, *an, *ad),
			#[cfg(feature = "policy")]
			(Self::TransitStatus(a), Self::TransitStatus(b)) => a == b,
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

#[cfg(feature = "policy")]
impl From<TransitStatus> for AssertionValue {
	fn from(status: TransitStatus) -> Self {
		Self::TransitStatus(status)
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
			None => Self::IsNone,
		}
	}
}

/// Marker type for asserting that an Option is Some(_) without checking the inner value
/// Use with `equals!(IsSome)` in assertion specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsSome;

impl From<IsSome> for AssertionValue {
	fn from(_: IsSome) -> Self {
		Self::IsSome
	}
}

/// Marker type for asserting that an Option is None
/// Use with `equals!(IsNone)` in assertion specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsNone;

impl From<IsNone> for AssertionValue {
	fn from(_: IsNone) -> Self {
		Self::IsNone
	}
}

/// Option occupancy recorded as an assertion value, without exposing
/// the payload itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
	/// The observed Option was `Some`.
	Present,
	/// The observed Option was `None`.
	Absent,
}

impl Presence {
	/// Classify an Option's occupancy.
	pub fn of_option<T>(opt: &Option<T>) -> Self {
		if opt.is_some() {
			Self::Present
		} else {
			Self::Absent
		}
	}
}

impl From<Presence> for AssertionValue {
	fn from(presence: Presence) -> Self {
		match presence {
			Presence::Present => AssertionValue::IsSome,
			Presence::Absent => AssertionValue::IsNone,
		}
	}
}

/// Ceiling for a ratio assertion: numerator per denominator.
/// Use with `equals!(RatioLimit(n, d))` in assertion specs.
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

/// One recorded trace event: an ordered, labeled observation a spec's
/// assertions are verified against.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug)]
pub struct Assertion {
	/// Position of the event in the recorded trace.
	pub seq: usize,
	/// Spec assertion this event answers to.
	pub label: AssertionLabel,
	/// Free-form tags refining the label.
	pub tags: Vec<&'static str>,
	/// Digest of the associated payload, when one was recorded.
	pub payload_hash: Option<[u8; 32]>,
	/// Observed value, when the assertion compares one.
	pub value: Option<AssertionValue>,
}

#[cfg(any(test, feature = "testing"))]
impl Assertion {
	/// Event carrying no observed value.
	pub fn new(seq: usize, label: AssertionLabel, tags: Vec<&'static str>, payload_hash: Option<[u8; 32]>) -> Self {
		Self { seq, label, tags, payload_hash, value: None }
	}

	/// Event carrying an observed value.
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

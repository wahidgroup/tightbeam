//! The types that a `TraceCollector` records for runtime assertions.

use core::num::NonZeroUsize;
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
	/// Whether this label and `other` name one URN.
	///
	/// Recorded events and spec assertions both carry full URN renderings
	/// (`urn:<nid>:<nss>`), so two labels match only when their strings are
	/// identical, and a shorthand or a suffix never matches.
	pub fn matches(&self, other: &AssertionLabel) -> bool {
		self == other
	}
}

/// The value of an assertion, typed so that a spec compares it through
/// `PartialEq`.
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

impl AssertionValue {
	/// Renders the held value on one line, for an instrument-log payload.
	#[cfg(feature = "instrument")]
	pub(crate) fn render(&self) -> String {
		match self {
			Self::String(s) => s.to_string(),
			Self::Bool(b) => b.to_string(),
			Self::U8(n) => n.to_string(),
			Self::U32(n) => n.to_string(),
			Self::U64(n) => n.to_string(),
			Self::I32(n) => n.to_string(),
			Self::I64(n) => n.to_string(),
			Self::F64(n) => n.to_string(),
			Self::MessagePriority(p) => format!("{p:?}"),
			Self::Version(v) => format!("{v:?}"),
			Self::Some(inner) => format!("Some({inner:?})"),
			Self::IsNone => "none".to_string(),
			Self::IsSome => "some".to_string(),
			Self::RatioActual(n, d) => format!("{n}/{d}"),
			Self::RatioLimit(n, d) => format!("≤{n}/{d}"),
			#[cfg(feature = "policy")]
			Self::TransitStatus(status) => format!("{status:?}"),
		}
	}
}

impl PartialEq for AssertionValue {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			// `IsSome` matches any `Some(_)` value.
			(Self::IsSome, Self::Some(_)) => true,
			(Self::Some(_), Self::IsSome) => true,
			// Two `IsSome` values match, because each asserts a value.
			(Self::IsSome, Self::IsSome) => true,
			// `IsSome` and `IsNone` differ.
			(Self::IsSome, Self::IsNone) => false,
			(Self::IsNone, Self::IsSome) => false,
			// Two values of one variant compare what they hold, and an actual
			// ratio matches a limit when it is at or below the limit.
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

/// A count reads as a `u64`, the type of the value that each counted event
/// carries. A count past `u64::MAX` saturates there.
impl From<usize> for AssertionValue {
	fn from(count: usize) -> Self {
		Self::U64(u64::try_from(count).unwrap_or(u64::MAX))
	}
}

/// A count above 0 reads as a `u64`, as a [`usize`] count does.
impl From<NonZeroUsize> for AssertionValue {
	fn from(count: NonZeroUsize) -> Self {
		Self::from(count.get())
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

// An `Option` converts `Some(x)` to a boxed `Some` value and `None` to
// `IsNone`.
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

/// A marker that asserts an `Option` is `Some(_)`, whatever its inner value.
/// A spec uses it as `equals!(IsSome)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsSome;

impl From<IsSome> for AssertionValue {
	fn from(_: IsSome) -> Self {
		Self::IsSome
	}
}

/// A marker that asserts an `Option` is `None`. A spec uses it as
/// `equals!(IsNone)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IsNone;

impl From<IsNone> for AssertionValue {
	fn from(_: IsNone) -> Self {
		Self::IsNone
	}
}

/// Whether an `Option` holds a value, recorded as an assertion value that
/// keeps the payload out of the trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
	/// The observed `Option` is `Some`.
	Present,
	/// The observed `Option` is `None`.
	Absent,
}

impl Presence {
	/// Classifies whether `opt` holds a value.
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

/// The ceiling of a ratio assertion, as a numerator per denominator. A spec
/// uses it as `equals!(RatioLimit(n, d))`.
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

/// One recorded trace event: an ordered, labeled observation that the
/// assertions of a spec check.
#[cfg(any(test, feature = "testing"))]
#[derive(Clone, Debug)]
pub struct Assertion {
	/// The position of the event in the recorded trace.
	pub seq: usize,
	/// The spec assertion that this event answers.
	pub label: AssertionLabel,
	/// The free-form tags that refine the label.
	pub tags: Vec<&'static str>,
	/// The digest of the associated payload, when the event records one.
	pub payload_hash: Option<[u8; 32]>,
	/// The observed value, when the assertion compares one.
	pub value: Option<AssertionValue>,
}

#[cfg(any(test, feature = "testing"))]
impl Assertion {
	/// Creates an event whose `value` is `None`.
	pub fn new(seq: usize, label: AssertionLabel, tags: Vec<&'static str>, payload_hash: Option<[u8; 32]>) -> Self {
		Self { seq, label, tags, payload_hash, value: None }
	}

	/// Creates an event that carries the observed `value`.
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

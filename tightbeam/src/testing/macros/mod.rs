//! Clean declarative testing macro & builder layer (legacy forms removed)
//!
//! This rewrite provides ONLY the multi-version block syntax:
//! tb_assert_spec! {
//!     pub MySpec,
//!     V 1.0.0: { mode: Accept, gate: Accepted, assertions: [ (HandlerStart, "A", exactly!(1)) ] },
//!     V 1.1.0: { mode: Accept, gate: Accepted, assertions: [ (HandlerStart, "A", exactly!(1)), (Response, "Responded", exactly!(1)) ] },
//! }
//!
//! Response semantics are governed solely by Response-phase assertion cardinalities.
//! No `require_response` flag remains.
//!
//! Hashing domain: b"TBSP" + version triple + spec id + mode code + gate
//! decision presence/value + normalized assertions + optional events.
//! Normalization: sort by (label, phase_code).

#![allow(unexpected_cfgs)]

// ProcessSpec macro (Layer 2 - CSP)
#[cfg(feature = "testing-csp")]
pub mod process_spec;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionContract, AssertionLabel};
use crate::testing::specs::{SpecViolation, TBSpec};
use crate::testing::trace::{ConsumedTrace, ExecutionMode};
use crate::Errorizable;

#[cfg(feature = "instrument")]
use crate::instrumentation::TbEventKind;

// Re-exports
pub use crate::testing::assertions::{AssertionValue, IsNone, IsSome};
pub use crate::testing::trace::TraceCollector;
pub use crate::{absent, at_least, at_most, between, equals, exactly, falsy, present, truthy};

/// Helper macro to wrap values for equality assertions in specs
#[macro_export]
macro_rules! equals {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::from($value))
	};
}

/// Helper macro for boolean true assertions in specs
/// Checks that the value is truthy (non-zero, true, non-empty)
#[macro_export]
macro_rules! truthy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value != 0))
	};
}

/// Helper macro for boolean false assertions in specs
/// Checks that the value is falsy (zero, false, empty)
#[macro_export]
macro_rules! falsy {
	($value:expr) => {
		Some($crate::testing::macros::AssertionValue::Bool($value == 0))
	};
}

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

// Removed: AssertionCollector type alias - use TraceCollector directly

// ---------------------------------------------------------------------------
// Instrumentation Mode
// ---------------------------------------------------------------------------

/// Instrumentation mode for tb_scenario!
#[cfg(feature = "instrument")]
#[derive(Clone, Debug)]
pub enum InstrumentationMode {
	/// Automatic: framework initializes and captures events (default)
	Auto,

	/// Manual: user controls init/start/end
	Manual,

	/// Custom: automatic with custom configuration
	Custom {
		enable_payloads: bool,
		enable_internal_detail: bool,
		sample_enabled_sets: bool,
		sample_refusals: bool,
		divergence_heuristics: bool,
		record_durations: bool,
		max_events: u32,
	},
}

#[cfg(feature = "instrument")]
impl Default for InstrumentationMode {
	fn default() -> Self {
		Self::Auto
	}
}

#[cfg(feature = "instrument")]
impl InstrumentationMode {
	/// Get the TbInstrumentationConfig for this mode
	pub fn config(&self) -> crate::instrumentation::TbInstrumentationConfig {
		match self {
			Self::Auto => crate::instrumentation::TbInstrumentationConfig {
				enable_payloads: false,
				enable_internal_detail: true, // Need hidden events for CSP
				sample_enabled_sets: false,
				sample_refusals: false,
				divergence_heuristics: false,
				record_durations: false,
				max_events: 4096,
			},
			Self::Manual => {
				// Manual mode shouldn't call this, but provide safe default
				crate::instrumentation::TbInstrumentationConfig::default()
			}
			Self::Custom {
				enable_payloads,
				enable_internal_detail,
				sample_enabled_sets,
				sample_refusals,
				divergence_heuristics,
				record_durations,
				max_events,
			} => crate::instrumentation::TbInstrumentationConfig {
				enable_payloads: *enable_payloads,
				enable_internal_detail: *enable_internal_detail,
				sample_enabled_sets: *sample_enabled_sets,
				sample_refusals: *sample_refusals,
				divergence_heuristics: *divergence_heuristics,
				record_durations: *record_durations,
				max_events: *max_events,
			},
		}
	}

	/// Should framework auto-initialize?
	pub fn is_auto(&self) -> bool {
		matches!(self, Self::Auto | Self::Custom { .. })
	}
}

// ---------------------------------------------------------------------------
// Cardinality core
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cardinality {
	min: u32,
	max: Option<u32>,
	must_be_present: bool,
}

impl Cardinality {
	pub const fn new(min: u32, max: Option<u32>, must_be_present: bool) -> Self {
		Self { min, max, must_be_present }
	}
	pub const fn exactly(n: u32) -> Self {
		Self { min: n, max: Some(n), must_be_present: n > 0 }
	}
	pub const fn at_least(n: u32) -> Self {
		Self { min: n, max: None, must_be_present: n > 0 }
	}
	pub const fn at_most(n: u32) -> Self {
		Self { min: 0, max: Some(n), must_be_present: false }
	}
	pub const fn between(min: u32, max: u32) -> Self {
		Self { min, max: Some(max), must_be_present: min > 0 }
	}
	pub const fn present() -> Self {
		Self { min: 1, max: None, must_be_present: true }
	}
	pub const fn absent() -> Self {
		Self { min: 0, max: Some(0), must_be_present: false }
	}
	pub fn describe(&self) -> String {
		match (self.min, self.max) {
			(0, Some(0)) => "absent".into(),
			(m, Some(n)) if m == n => format!("exactly {m}"),
			(m, Some(n)) => format!("between {m} and {n}"),
			(0, None) => "any".into(),
			(m, None) => format!("at least {m}"),
		}
	}
	pub fn is_satisfied_by(&self, count: usize) -> bool {
		let c = count as u32;
		if c < self.min {
			return false;
		}
		if let Some(mx) = self.max {
			if c > mx {
				return false;
			}
		}
		true
	}
	pub fn min(&self) -> u32 {
		self.min
	}
	pub fn max(&self) -> Option<u32> {
		self.max
	}
	pub fn must_be_present(&self) -> bool {
		self.must_be_present
	}
}

pub const fn between(min: u32, max: u32) -> Cardinality {
	Cardinality::between(min, max)
}
pub const fn present() -> Cardinality {
	Cardinality::present()
}
pub const fn absent() -> Cardinality {
	Cardinality::absent()
}

// ---------------------------------------------------------------------------
// Label trait + dynamic representation
// ---------------------------------------------------------------------------

pub trait TbAssertLabelTrait {
	fn name(&self) -> &'static str;
	fn payload_capable(&self) -> bool {
		false
	}
}

// (Dynamic label builder retained for potential future use)

// ---------------------------------------------------------------------------
// Spec builder and concrete implementation
// ---------------------------------------------------------------------------

/// Error type for spec building operations
#[derive(Debug)]
#[cfg_attr(feature = "derive", derive(Errorizable))]
pub enum SpecBuildError {
	#[cfg_attr(feature = "derive", error("Duplicate label: {0}"))]
	DuplicateLabel(&'static str),
	#[cfg_attr(feature = "derive", error("Unknown ordering label: {0}"))]
	UnknownOrderingLabel(&'static str),
	#[cfg_attr(feature = "derive", error("Invalid range: {0}"))]
	InvalidRange(&'static str),
}

/// Builder for programmatic spec construction
pub struct AssertSpecBuilder {
	id: &'static str,
	execution_mode: ExecutionMode,
	gate_decision: Option<TransitStatus>,
	version_major: u16,
	version_minor: u16,
	version_patch: u16,
	assertions: Vec<(&'static str, Vec<&'static str>, Cardinality, Option<AssertionValue>)>,
	tag_filter: Option<Vec<&'static str>>,
	ordering: Vec<&'static str>,
	#[cfg(feature = "instrument")]
	required_events: Vec<TbEventKind>,
	description: Option<&'static str>,
}

impl AssertSpecBuilder {
	pub fn new(id: &'static str, execution_mode: ExecutionMode) -> Self {
		Self {
			id,
			execution_mode,
			gate_decision: None,
			version_major: 1,
			version_minor: 0,
			version_patch: 0,
			assertions: Vec::new(),
			tag_filter: None,
			ordering: Vec::new(),
			#[cfg(feature = "instrument")]
			required_events: Vec::new(),
			description: None,
		}
	}

	pub fn version(mut self, maj: u16, min: u16, patch: u16) -> Self {
		self.version_major = maj;
		self.version_minor = min;
		self.version_patch = patch;
		self
	}

	pub fn gate_decision(mut self, decision: TransitStatus) -> Self {
		self.gate_decision = Some(decision);
		self
	}

	pub fn tag_filter(mut self, tags: Vec<&'static str>) -> Self {
		self.tag_filter = Some(tags);
		self
	}

	pub fn assertion(
		mut self,
		label: &'static str,
		tags: Vec<&'static str>,
		cardinality: Cardinality,
	) -> Result<Self, SpecBuildError> {
		if self.assertions.iter().any(|(l, _, _, _)| *l == label) {
			return Err(SpecBuildError::DuplicateLabel(label));
		}
		if let Some(mx) = cardinality.max {
			if mx < cardinality.min {
				return Err(SpecBuildError::InvalidRange(label));
			}
		}
		self.assertions.push((label, tags, cardinality, None));
		Ok(self)
	}

	pub fn assertion_with_value(
		mut self,
		label: &'static str,
		tags: Vec<&'static str>,
		cardinality: Cardinality,
		expected_value: Option<AssertionValue>,
	) -> Result<Self, SpecBuildError> {
		if self.assertions.iter().any(|(l, _, _, _)| *l == label) {
			return Err(SpecBuildError::DuplicateLabel(label));
		}
		if let Some(mx) = cardinality.max {
			if mx < cardinality.min {
				return Err(SpecBuildError::InvalidRange(label));
			}
		}
		self.assertions.push((label, tags, cardinality, expected_value));
		Ok(self)
	}

	pub fn ordering(mut self, labels: &[&'static str]) -> Result<Self, SpecBuildError> {
		for &lbl in labels {
			if !self.assertions.iter().any(|(l, _, _, _)| *l == lbl) {
				return Err(SpecBuildError::UnknownOrderingLabel(lbl));
			}
			self.ordering.push(lbl);
		}
		Ok(self)
	}

	#[cfg(feature = "instrument")]
	pub fn required_events(mut self, kinds: &[TbEventKind]) -> Self {
		use std::collections::HashSet;
		let mut seen = HashSet::new();
		for &k in kinds {
			if seen.insert(k) {
				self.required_events.push(k);
			}
		}
		self
	}

	pub fn description(mut self, desc: &'static str) -> Self {
		self.description = Some(desc);
		self
	}

	pub fn build(self) -> BuiltAssertSpec {
		BuiltAssertSpec::from_builder(self)
	}
}

pub struct BuiltAssertSpec {
	inner: AssertSpecBuilder,
	contracts: Box<[AssertionContract]>,
	spec_hash: [u8; 32],
}

impl BuiltAssertSpec {
	fn from_builder(builder: AssertSpecBuilder) -> Self {
		let tag_filter = builder.tag_filter.clone();
		let contracts: Vec<AssertionContract> = builder
			.assertions
			.iter()
			.map(|(label, _tags, card, value)| {
				let mut contract = if let Some(ref val) = value {
					AssertionContract::new(AssertionLabel::Custom(label), *card).with_value(val.clone())
				} else {
					AssertionContract::new(AssertionLabel::Custom(label), *card)
				};
				if let Some(ref filter) = tag_filter {
					contract = contract.with_tag_filter(filter.clone());
				}
				contract
			})
			.collect();
		let spec_hash = Self::compute_hash(
			builder.id,
			builder.execution_mode,
			builder.gate_decision,
			builder.version_major,
			builder.version_minor,
			builder.version_patch,
			&contracts,
			builder.tag_filter.as_deref(),
			#[cfg(feature = "instrument")]
			&builder.required_events,
		);
		Self { inner: builder, contracts: contracts.into_boxed_slice(), spec_hash }
	}

	#[allow(clippy::too_many_arguments)]
	fn compute_hash(
		id: &'static str,
		mode: ExecutionMode,
		gate: Option<TransitStatus>,
		version_major: u16,
		version_minor: u16,
		version_patch: u16,
		contracts: &[AssertionContract],
		tag_filter: Option<&[&'static str]>,
		#[cfg(feature = "instrument")] events: &[TbEventKind],
	) -> [u8; 32] {
		let mut h = Sha3_256::new();
		// Domain tag + version triple
		h.update(b"TBSP");
		h.update(version_major.to_be_bytes());
		h.update(version_minor.to_be_bytes());
		h.update(version_patch.to_be_bytes());
		h.update(id.as_bytes());
		let mode_code = match mode {
			ExecutionMode::Accept => 0u8,
			ExecutionMode::Reject => 1u8,
			ExecutionMode::Error => 2u8,
		};
		h.update([mode_code]);
		match gate {
			Some(g) => {
				h.update([1u8]);
				h.update([g as u8]);
			}
			None => h.update([0u8]),
		}
		// Include tag_filter in hash if present
		if let Some(tags) = tag_filter {
			h.update([1u8]);
			h.update((tags.len() as u32).to_be_bytes());
			for tag in tags {
				h.update(tag.as_bytes());
			}
		} else {
			h.update([0u8]);
		}
		// Normalize assertion order independent of insertion sequence
		let mut norm: Vec<(&'static str, u32, Option<u32>, bool)> = Vec::with_capacity(contracts.len());
		for c in contracts {
			let AssertionLabel::Custom(lbl) = c.label;
			norm.push((lbl, c.cardinality.min, c.cardinality.max, c.cardinality.must_be_present));
		}
		norm.sort_by(|a, b| a.0.cmp(b.0)); // label only
		for (lbl, min, max, must) in norm {
			h.update(lbl.as_bytes());
			h.update(min.to_be_bytes());
			match max {
				Some(m) => {
					h.update([1u8]);
					h.update(m.to_be_bytes());
				}
				None => h.update([0u8]),
			}
			h.update([must as u8]);
		}
		#[cfg(feature = "instrument")]
		{
			for ev in events {
				h.update([*ev as u8]);
			}
		}
		let out = h.finalize();
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&out);
		arr
	}

	pub fn spec_hash(&self) -> [u8; 32] {
		self.spec_hash
	}
	pub fn version(&self) -> (u16, u16, u16) {
		(self.inner.version_major, self.inner.version_minor, self.inner.version_patch)
	}
}

impl TBSpec for BuiltAssertSpec {
	fn id(&self) -> &'static str {
		self.inner.id
	}
	fn mode(&self) -> ExecutionMode {
		self.inner.execution_mode
	}
	fn required_assertions(&self) -> &[AssertionContract] {
		&self.contracts
	}
	fn expected_gate_decision(&self) -> Option<TransitStatus> {
		self.inner.gate_decision
	}
	#[cfg(feature = "instrument")]
	fn required_event_kinds(&self) -> &[TbEventKind] {
		&self.inner.required_events
	}
	fn validate_trace(&self, _trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		Ok(())
	}
}

// ---------------------------------------------------------------------------
// Payload encoding trait (AssertEncode) for tb_assert! ergonomic payloads
// ---------------------------------------------------------------------------
/// Trait converting payload values into a canonical byte representation.
/// Numeric primitives are big-endian; &str/&[u8]/Vec<u8> zero-copy.
pub trait AssertEncode {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]>;
}
// Unsigned primitives
impl AssertEncode for u8 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned(vec![*self])
	}
}
impl AssertEncode for u16 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned(self.to_be_bytes().to_vec())
	}
}
impl AssertEncode for u32 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned(self.to_be_bytes().to_vec())
	}
}
impl AssertEncode for u64 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned(self.to_be_bytes().to_vec())
	}
}
// Signed primitives (cast)
impl AssertEncode for i8 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned(vec![*self as u8])
	}
}
impl AssertEncode for i16 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned((*self as u16).to_be_bytes().to_vec())
	}
}
impl AssertEncode for i32 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned((*self as u32).to_be_bytes().to_vec())
	}
}
impl AssertEncode for i64 {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned((*self as u64).to_be_bytes().to_vec())
	}
}
// usize/isize canonical to 64-bit
impl AssertEncode for usize {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned((*self as u64).to_be_bytes().to_vec())
	}
}
impl AssertEncode for isize {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Owned((*self as u64).to_be_bytes().to_vec())
	}
}
// Text / bytes
impl AssertEncode for &str {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Borrowed(self.as_bytes())
	}
}
impl AssertEncode for str {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Borrowed(self.as_bytes())
	}
}
impl AssertEncode for &[u8] {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Borrowed(self)
	}
}
impl AssertEncode for Vec<u8> {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Borrowed(self.as_slice())
	}
}
impl AssertEncode for [u8; 32] {
	fn tb_payload_bytes(&self) -> Cow<'_, [u8]> {
		Cow::Borrowed(self)
	}
}

pub fn __encode_payload<T: AssertEncode + ?Sized>(v: &T) -> Cow<'_, [u8]> {
	T::tb_payload_bytes(v)
}

// ---------------------------------------------------------------------------
// Helper macros
// ---------------------------------------------------------------------------

// Cardinality helper macros (thin wrappers over const fns)
#[macro_export]
macro_rules! exactly {
	($n:expr) => {
		$crate::testing::macros::Cardinality::exactly($n)
	};
}
#[macro_export]
macro_rules! at_least {
	($n:expr) => {
		$crate::testing::macros::Cardinality::at_least($n)
	};
}
#[macro_export]
macro_rules! at_most {
	($n:expr) => {
		$crate::testing::macros::Cardinality::at_most($n)
	};
}
#[macro_export]
macro_rules! between {
	($min:expr, $max:expr) => {
		$crate::testing::macros::Cardinality::between($min, $max)
	};
}
#[macro_export]
macro_rules! present {
	() => {
		$crate::testing::macros::Cardinality::present()
	};
}
#[macro_export]
macro_rules! absent {
	() => {
		$crate::testing::macros::Cardinality::absent()
	};
}

// Label declaration macro
// Usage:
// tb_labels! { pub enum MyLabels { A, B(payload), C } }
#[macro_export]
macro_rules! tb_labels {
	(pub enum $name:ident { $( $label:ident $(=> $payload_marker:ident)? ),* $(,)? }) => {
		#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
		pub enum $name { $( $label ),* }

		impl $crate::testing::macros::TbAssertLabelTrait for $name {
			fn name(&self) -> &'static str { match self { $( $name::$label => stringify!($label) ),* } }
			fn payload_capable(&self) -> bool { match self { $( $name::$label => $crate::tb_labels!(@flag $( $payload_marker )? ) ),* } }
		}

	impl From<$name> for $crate::testing::assertions::AssertionLabel {
		fn from(lbl: $name) -> Self { $crate::testing::assertions::AssertionLabel::Custom(<$name as $crate::testing::macros::TbAssertLabelTrait>::name(&lbl)) }
	}		pub const ALL_LABELS: &[$name] = &[ $( $name::$label ),* ];
	};
	(@flag payload) => { true };
	(@flag) => { false };
}

// Helper macro for common spec building logic (reduces duplication in tb_assert_spec!)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build {
	// Entry point with tag_filter and description
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ], $desc:expr) => {
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(stringify!($base), $crate::testing::trace::ExecutionMode::$mode);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate).tag_filter(vec![ $($tag),* ]);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{ $( builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]); )* }
		builder = builder.description($desc);
		$vec.push(builder.build());
	};
	// Entry point with tag_filter, no description
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ]) => {
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(stringify!($base), $crate::testing::trace::ExecutionMode::$mode);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate).tag_filter(vec![ $($tag),* ]);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{ $( builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]); )* }
		$vec.push(builder.build());
	};
	// Entry point without tag_filter, with description
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ], $desc:expr) => {
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(stringify!($base), $crate::testing::trace::ExecutionMode::$mode);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{ $( builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]); )* }
		builder = builder.description($desc);
		$vec.push(builder.build());
	};
	// Entry point without tag_filter, without description
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ]) => {
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(stringify!($base), $crate::testing::trace::ExecutionMode::$mode);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{ $( builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]); )* }
		$vec.push(builder.build());
	};
}

// Helper to add individual assertions (handles tags and values)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_add_assertion {
	// NEW SYNTAX: With value and tags - match equals! specifically
	($builder:expr, ($label:expr, $card:expr, equals!($value:expr), tags: [ $($tag:expr),* $(,)? ])) => {
		$builder
			.assertion_with_value($label, vec![ $($tag),* ], $card, Some($crate::testing::assertions::AssertionValue::from($value)))
			.expect("duplicate label or invalid range")
	};
	// NEW SYNTAX: With value, no tags - match equals! specifically
	($builder:expr, ($label:expr, $card:expr, equals!($value:expr))) => {
		$builder
			.assertion_with_value($label, vec![], $card, Some($crate::testing::assertions::AssertionValue::from($value)))
			.expect("duplicate label or invalid range")
	};
	// NEW SYNTAX: With tags, no value
	($builder:expr, ($label:expr, $card:expr, tags: [ $($tag:expr),* $(,)? ])) => {
		$builder
			.assertion($label, vec![ $($tag),* ], $card)
			.expect("duplicate label or invalid range")
	};
	// NEW SYNTAX: No tags, no value (2-element tuple)
	($builder:expr, ($label:expr, $card:expr)) => {
		$builder
			.assertion($label, vec![], $card)
			.expect("duplicate label or invalid range")
	};
	// OLD SYNTAX: (Phase, label, cardinality, equals!(value)) - ignore phase, convert to new syntax
	($builder:expr, ($phase:ident, $label:expr, $card:expr, equals!($value:expr))) => {
		$builder
			.assertion_with_value($label, vec![], $card, Some($crate::testing::assertions::AssertionValue::from($value)))
			.expect("duplicate label or invalid range")
	};
	// OLD SYNTAX: (Phase, label, cardinality) - ignore phase, convert to new syntax
	($builder:expr, ($phase:ident, $label:expr, $card:expr)) => {
		$builder
			.assertion($label, vec![], $card)
			.expect("duplicate label or invalid range")
	};
}

// Helper macro to handle optional description
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_with_desc {
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ], $desc:expr) => {
		$crate::__tb_assert_spec_build!($vec, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
	};
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ], $desc:expr) => {
		$crate::__tb_assert_spec_build!($vec, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
	};
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ]) => {
		$crate::__tb_assert_spec_build!($vec, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ]);
	};
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, [ $( $assertion:tt ),* ], [ $( $ev:ident ),* ]) => {
		$crate::__tb_assert_spec_build!($vec, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ]);
	};
}

// Multi-version macro ONLY (full semantic version required maj.min.patch)
#[macro_export]
macro_rules! tb_assert_spec {
	// Without annotations, with tag_filter (must come first)
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : { mode: $mode:ident, gate: $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], assertions: [ $( $assertion:tt ),* $(,)? ] $(, events: [ $( $ev:ident ),* $(,)? ])? } ),+ $(,)?
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ]);
						)+
						v
					}).as_slice()
				}
				#[cfg(not(feature = "std"))]
				{
					use core::sync::atomic::{AtomicBool, Ordering};
					static INIT: AtomicBool = AtomicBool::new(false);
					static mut VEC: Option<Vec<$crate::testing::macros::BuiltAssertSpec>> = None;
					if !INIT.load(Ordering::Acquire) {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ]);
						)+
						unsafe { VEC = Some(v); }
						INIT.store(true, Ordering::Release);
					}
					unsafe { VEC.as_ref().unwrap().as_slice() }
				}
			}

			#[allow(dead_code)]
			pub fn get(maj: u16, min: u16, patch: u16) -> Option<&'static $crate::testing::macros::BuiltAssertSpec> {
				for s in Self::all() {
					let (maj_ver, min_ver, patch_ver) = s.version();
					if maj_ver == maj && min_ver == min && patch_ver == patch {
						return Some(s);
					}
				}
				None
			}

			#[allow(dead_code)]
			pub fn latest() -> &'static $crate::testing::macros::BuiltAssertSpec {
				let mut best: Option<&'static $crate::testing::macros::BuiltAssertSpec> = None;
				for s in Self::all() {
					match best {
						Some(b) => if s.version() > b.version() { best = Some(s); },
						None => best = Some(s)
					}
				}
				best.expect("no versions defined")
			}
		}
	};
	// Without annotations, without tag_filter (must come first)
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : { mode: $mode:ident, gate: $gate:ident, assertions: [ $( $assertion:tt ),* $(,)? ] $(, events: [ $( $ev:ident ),* $(,)? ])? } ),+ $(,)?
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ]);
						)+
						v
					}).as_slice()
				}
				#[cfg(not(feature = "std"))]
				{
					use core::sync::atomic::{AtomicBool, Ordering};
					static INIT: AtomicBool = AtomicBool::new(false);
					static mut VEC: Option<Vec<$crate::testing::macros::BuiltAssertSpec>> = None;
					if !INIT.load(Ordering::Acquire) {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ]);
						)+
						unsafe { VEC = Some(v); }
						INIT.store(true, Ordering::Release);
					}
					unsafe { VEC.as_ref().unwrap().as_slice() }
				}
			}

			#[allow(dead_code)]
			pub fn get(maj: u16, min: u16, patch: u16) -> Option<&'static $crate::testing::macros::BuiltAssertSpec> {
				for s in Self::all() {
					let (maj_ver, min_ver, patch_ver) = s.version();
					if maj_ver == maj && min_ver == min && patch_ver == patch {
						return Some(s);
					}
				}
				None
			}

			#[allow(dead_code)]
			pub fn latest() -> &'static $crate::testing::macros::BuiltAssertSpec {
				let mut best: Option<&'static $crate::testing::macros::BuiltAssertSpec> = None;
				for s in Self::all() {
					match best {
						Some(b) => if s.version() > b.version() { best = Some(s); },
						None => best = Some(s)
					}
				}
				best.expect("no versions defined")
			}
		}
	};
	// With annotations, with tag_filter
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : { mode: $mode:ident, gate: $gate:ident, tag_filter: [ $($tag:expr),* $(,)? ], assertions: [ $( $assertion:tt ),* $(,)? ] $(, events: [ $( $ev:ident ),* $(,)? ])? } ),+ $(,)?
		annotations { description: $desc:expr }
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build_with_desc!(v, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
						)+
						v
					}).as_slice()
				}
				#[cfg(not(feature = "std"))]
				{
					use core::sync::atomic::{AtomicBool, Ordering};
					static INIT: AtomicBool = AtomicBool::new(false);
					static mut VEC: Option<Vec<$crate::testing::macros::BuiltAssertSpec>> = None;
					if !INIT.load(Ordering::Acquire) {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build_with_desc!(v, $base, $maj, $min, $patch, $mode, $gate, tag_filter: [ $($tag),* ], [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
						)+
						unsafe { VEC = Some(v); }
						INIT.store(true, Ordering::Release);
					}
					unsafe { VEC.as_ref().unwrap().as_slice() }
				}
			}

			#[allow(dead_code)]
			pub fn get(maj: u16, min: u16, patch: u16) -> Option<&'static $crate::testing::macros::BuiltAssertSpec> {
				for s in Self::all() {
					let (maj_ver, min_ver, patch_ver) = s.version();
					if maj_ver == maj && min_ver == min && patch_ver == patch {
						return Some(s);
					}
				}
				None
			}

			#[allow(dead_code)]
			pub fn latest() -> &'static $crate::testing::macros::BuiltAssertSpec {
				let mut best: Option<&'static $crate::testing::macros::BuiltAssertSpec> = None;
				for s in Self::all() {
					match best {
						Some(b) => if s.version() > b.version() { best = Some(s); },
						None => best = Some(s)
					}
				}
				best.expect("no versions defined")
			}
		}
	};
	// With annotations, without tag_filter
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : { mode: $mode:ident, gate: $gate:ident, assertions: [ $( $assertion:tt ),* $(,)? ] $(, events: [ $( $ev:ident ),* $(,)? ])? } ),+ $(,)?
		annotations { description: $desc:expr }
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build_with_desc!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
						)+
						v
					}).as_slice()
				}
				#[cfg(not(feature = "std"))]
				{
					use core::sync::atomic::{AtomicBool, Ordering};
					static INIT: AtomicBool = AtomicBool::new(false);
					static mut VEC: Option<Vec<$crate::testing::macros::BuiltAssertSpec>> = None;
					if !INIT.load(Ordering::Acquire) {
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build_with_desc!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( $assertion ),* ], [ $( $ev ),* ], $desc);
						)+
						unsafe { VEC = Some(v); }
						INIT.store(true, Ordering::Release);
					}
					unsafe { VEC.as_ref().unwrap().as_slice() }
				}
			}

			#[allow(dead_code)]
			pub fn get(maj: u16, min: u16, patch: u16) -> Option<&'static $crate::testing::macros::BuiltAssertSpec> {
				for s in Self::all() {
					let (maj_ver, min_ver, patch_ver) = s.version();
					if maj_ver == maj && min_ver == min && patch_ver == patch {
						return Some(s);
					}
				}
				None
			}

			#[allow(dead_code)]
			pub fn latest() -> &'static $crate::testing::macros::BuiltAssertSpec {
				let mut best: Option<&'static $crate::testing::macros::BuiltAssertSpec> = None;
				for s in Self::all() {
					match best {
						Some(b) => if s.version() > b.version() { best = Some(s); },
						None => best = Some(s)
					}
				}
				best.expect("no versions defined")
			}
		}
	};
}

// ---------------------------------------------------------------------------
// Scenario macro MVP: Worker & Bare variants (ServiceClient stubbed)
// ---------------------------------------------------------------------------

/// Helper macro for common trace verification logic (reduces duplication)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_scenario_verify_impl {
	// Single spec variant with optional CSP and FDR
	(
		single_spec: $spec:ty,
		trace: $trace:expr,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		let spec = <$spec>::latest();
		let verification_result = $crate::testing::specs::verify_trace(spec, &$trace);

		// CSP validation if provided
		#[cfg(feature = "testing-csp")]
		let csp_result: Option<$crate::testing::specs::csp::CspValidationResult> = {
			$crate::tb_scenario!(@csp_validate $trace, $($csp)?)
		};

		#[cfg(not(feature = "testing-csp"))]
		let csp_result: Option<$crate::testing::specs::csp::CspValidationResult> = None;

		// Check if CSP validation failed
		#[cfg(feature = "testing-csp")]
		let csp_failed = csp_result.as_ref().map(|r| !r.valid).unwrap_or(false);
		#[cfg(not(feature = "testing-csp"))]
		let csp_failed = false;

		// FDR validation if provided
		#[cfg(feature = "testing-fdr")]
		let (fdr_result, fdr_config): (Option<$crate::testing::fdr::FdrVerdict>, Option<$crate::testing::fdr::FdrConfig>) = {
			$crate::tb_scenario!(@fdr_validate_with_config $trace, $($fdr_config)?)
		};

		#[cfg(not(feature = "testing-fdr"))]
		let (fdr_result, fdr_config): (Option<$crate::testing::fdr::FdrVerdict>, Option<$crate::testing::fdr::FdrConfig>) = (None, None);

		// Check if FDR validation failed
		#[cfg(feature = "testing-fdr")]
		let fdr_failed = fdr_result.as_ref().map(|v| !v.passed).unwrap_or(false);
		#[cfg(not(feature = "testing-fdr"))]
		let fdr_failed = false;

		// Check if FDR failure is expected (for negative tests)
		#[cfg(feature = "testing-fdr")]
		let expect_failure = fdr_config.as_ref().map(|c| c.expect_failure).unwrap_or(false);
		#[cfg(not(feature = "testing-fdr"))]
		let expect_failure = false;

		match &verification_result {
			Ok(()) => {
				// L1 passed, check L2 (CSP) and L3 (FDR)
				if csp_failed {
					panic!("Layer 1 (assertions) passed but Layer 2 (CSP) failed: {:?}", csp_result);
				}

				if fdr_failed {
					// Check if failure is expected (for negative tests)
					if expect_failure {
						// Failure is expected - test passes
						// Verify that we have a witness to prove the failure
						let verdict = fdr_result.as_ref().unwrap();
						if !verdict.trace_refines && verdict.trace_refinement_witness.is_some() {
							// Expected failure confirmed - test passes
						} else {
							panic!("Expected FDR failure but verdict doesn't show refinement failure: {:?}", verdict);
						}
					} else {
						// Failure is unexpected - test fails
						let verdict = fdr_result.as_ref().unwrap();
						panic!("Layer 1 (assertions) passed but Layer 3 (FDR) failed: {:?}", verdict);
					}
				}

				$( $( {
					fn __call_on_pass<F>(f: F, trace: &$crate::testing::trace::ConsumedTrace)
					where
						F: FnOnce(&$crate::testing::trace::ConsumedTrace),
					{
						f(trace)
					}
					__call_on_pass($on_pass, &$trace);
				} )? )?
			}
			Err(_violations) => {
				// L1 failed - also report L2 and L3 if they failed
				if csp_failed {
					eprintln!("Layer 1 (assertions) failed AND Layer 2 (CSP) failed: {:?}", csp_result);
				}

				if fdr_failed {
					let verdict = fdr_result.as_ref().unwrap();
					eprintln!("Layer 1 (assertions) failed AND Layer 3 (FDR) failed: {:?}", verdict);
					// Note: on_fail hook signature expects SpecViolation, not FdrVerdict
				}

				$( $( {
					fn __call_on_fail<F>(f: F, trace: &$crate::testing::trace::ConsumedTrace, violations: &$crate::testing::specs::SpecViolation)
					where
						F: FnOnce(&$crate::testing::trace::ConsumedTrace, &$crate::testing::specs::SpecViolation),
					{
						f(trace, violations)
					}
					__call_on_fail($on_fail, &$trace, _violations);
				} )? )?
			}
		}
		verification_result
	}};

	// Multiple specs variant with optional CSP and FDR
	(
		multi_specs: $specs:expr,
		trace: $trace:expr,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		let mut all_passed = true;
		let mut first_violation = None;

		// CSP validation if provided
		#[cfg(feature = "testing-csp")]
		#[allow(unused_variables)]
		let csp_result: Option<$crate::testing::specs::csp::CspValidationResult> = {
			$crate::tb_scenario!(@csp_validate $trace, $($csp)?)
		};

		#[cfg(not(feature = "testing-csp"))]
		let csp_result: Option<$crate::testing::specs::csp::CspValidationResult> = None;

		// Check if CSP validation failed
		#[cfg(feature = "testing-csp")]
		let csp_failed = csp_result.as_ref().map(|r| !r.valid).unwrap_or(false);
		#[cfg(not(feature = "testing-csp"))]
		let csp_failed = false;

		// FDR validation if provided
		#[cfg(feature = "testing-fdr")]
		let fdr_result: Option<$crate::testing::fdr::FdrVerdict> = {
			$crate::tb_scenario!(@fdr_validate $trace, $($fdr_config)?)
		};

		#[cfg(not(feature = "testing-fdr"))]
		let fdr_result: Option<$crate::testing::fdr::FdrVerdict> = None;

		// Check if FDR validation failed
		#[cfg(feature = "testing-fdr")]
		let fdr_failed = fdr_result.as_ref().map(|v| !v.passed).unwrap_or(false);
		#[cfg(not(feature = "testing-fdr"))]
		let fdr_failed = false;

		for spec in &$specs {
			let verification_result = $crate::testing::specs::verify_trace(*spec, &$trace);
			match &verification_result {
				Ok(()) => {
					$( $( {
						fn __call_on_pass<F>(f: F, trace: &$crate::testing::trace::ConsumedTrace)
						where
							F: FnOnce(&$crate::testing::trace::ConsumedTrace),
						{
							f(trace)
						}
						__call_on_pass($on_pass, &$trace);
					} )? )?
				}
				Err(_violations) => {
					$( $( {
						fn __call_on_fail<F>(f: F, trace: &$crate::testing::trace::ConsumedTrace, violations: &$crate::testing::spec::SpecViolation)
						where
							F: FnOnce(&$crate::testing::trace::ConsumedTrace, &$crate::testing::spec::SpecViolation),
						{
							f(trace, violations)
						}
						__call_on_fail($on_fail, &$trace, _violations);
					} )? )?
					all_passed = false;
					if first_violation.is_none() {
						first_violation = Some(_violations.clone());
					}
				}
			}
		}

		// Check CSP and FDR after all specs are checked
		if all_passed {
			if csp_failed {
				panic!("All specs passed but Layer 2 (CSP) failed: {:?}", csp_result);
			}
			if fdr_failed {
				let verdict = fdr_result.as_ref().unwrap();
				panic!("All specs passed but Layer 3 (FDR) failed: {:?}", verdict);
			}
			Ok(())
		} else {
			// L1 failed - also report L2 and L3 if they failed
			if csp_failed {
				eprintln!("Layer 1 (assertions) failed AND Layer 2 (CSP) failed: {:?}", csp_result);
			}
			if fdr_failed {
				let verdict = fdr_result.as_ref().unwrap();
				eprintln!("Layer 1 (assertions) failed AND Layer 3 (FDR) failed: {:?}", verdict);
			}
			Err(first_violation.unwrap())
		}
	}};
}

/// tb_scenario! macro - MVP implementation
///
/// Supports three execution environments:
/// - Worker: Execute against a single worker instance
/// - Bare: Execute pure logic without transport
/// - ServiceClient: Full transport round-trip testing
///
/// Common top-level keys:
/// - name: test_function_name (creates standalone #[test] function)
/// - spec: AssertSpecType (uses latest version) OR specs: [expr, ...] (specific spec instances)
/// - instrumentation: TbInstrumentationConfig (OPTIONAL, when feature = "instrument")
/// - hooks { on_pass: |trace| {}, on_fail: |trace, violations| {} } (OPTIONAL)
/// - assert_policies { ... } (TODO: future)
#[macro_export]
macro_rules! tb_scenario {
	// ===== Standalone test with name for ServiceClient =====
	// With tokio: generates #[tokio::test] async function (no runtime.block_on)
	// Without tokio: generates #[test] function with runtime.block_on()
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			worker_threads: $threads:literal,
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() {
			// Execute directly in async context - no runtime.block_on needed

			// Create shared trace collector and clone upfront
			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_server = trace_collector.clone();
			let trace_client = trace_collector.clone();

			// Helper function for server closure to enable type inference
			async fn __call_server_closure<F, Fut>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
			) -> Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector) -> Fut,
				Fut: core::future::Future<Output = Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>>,
			{
				closure(trace).await
			}

			// User's server closure - invoke it with the trace parameter
			let server_setup_result = __call_server_closure($server_closure, trace_server).await;
			let (server_handle, server_addr) = server_setup_result.expect("Server setup failed");

			// Default protocol to TokioListener if not specified
			use $crate::tb_scenario;
			type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

			// Build client transport using the actual server address
			let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
				.expect("Failed to connect to server");
			let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

			// Execute client closure - use helper to enable inference
			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			// Collect trace from shared collector
			let mut trace = $crate::testing::trace::ConsumedTrace::new();
			trace.populate_from_collector(&trace_collector);
			trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
			if client_result.is_err() {
				trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
			}

			// Cleanup
			server_handle.abort();

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: $hooks,)?
			};

			if let Err(e) = client_result {
				panic!("Client execution failed: {:?}", e);
			} else if let Err(v) = verification_result {
				panic!("Spec verification failed: {:?}", v);
			}
		}

		#[cfg(not(feature = "tokio"))]
		#[test]
		fn $test_name() {
			tb_scenario!(@execute ServiceClient, single_spec, $spec,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(instrumentation: $instr_cfg,)?
				$(hooks: $hooks,)?
				protocol: { $($protocol)? },
				worker_threads: { $threads },
				server: $server_closure,
				client: $client_closure
			).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Bare environment =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let trace_collector = $crate::testing::macros::TraceCollector::new();

			// Environment-specific execution
			let trace_exec = trace_collector.clone();
			fn __call_exec_closure<F>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace)
			}
			let exec_result = __call_exec_closure($exec_closure, trace_exec);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			let result = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== AFL fuzz target for Bare environment (NO #[test], generates fuzz!) =====
	(
		fuzz: afl,
		spec: $spec:ty,
		csp: $csp:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[allow(unexpected_cfgs)]
		#[cfg(fuzzing)]
		fn main() {
			::afl::fuzz!(|data: &[u8]| {
				// Common setup
				#[cfg(feature = "instrument")]
				let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@init_instrumentation instr_mode);

				// AFL provides the data - use it directly with FuzzContext
				let trace_collector = $crate::testing::trace::TraceCollector::with_fuzz_oracle(
					data.to_vec(),
					<$csp>::process()
				);

				// Environment-specific execution
				let trace_exec = trace_collector.clone();
				fn __call_exec_closure<F>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace)
				}
				let exec_result = __call_exec_closure($exec_closure, trace_exec);

				// Report CSP exploration to IJON (if feature enabled)
				#[cfg(feature = "testing-fuzz-ijon")]
				{
					if exec_result.is_ok() {
						// Use public oracle() method to access oracle context
						let oracle_ctx = trace_collector.oracle();
						::afl::ijon_stack_max!(oracle_ctx.coverage_score());
						::afl::ijon_set!(oracle_ctx.track_state());
						// Track state hash distribution across trace depth
						// old = trace length (how deep), val = current state (where we are)
						let trace_depth = oracle_ctx.trace().len() as u32;
						let state_hash = oracle_ctx.track_state();
						unsafe { ::afl::ijon_hashint(trace_depth, state_hash); }
					}
				}
				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// AFL fuzz targets should not panic on failure - just return
				let _ = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			});
		}

		// Stub main() for IDE - rust-analyzer needs this to see a main() function
		// This is only compiled when NOT fuzzing, so it won't conflict with the generated main() above
		#[allow(unexpected_cfgs)]
		#[cfg(not(fuzzing))]
		#[allow(dead_code)]
		fn main() {
			unreachable!("This main() is only for IDE purposes. The real main() is generated by tb_scenario! macro when cfg(fuzzing) is enabled.")
		}
	};

	// ===== Standalone test with name for Bare environment + fuzz =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		csp: $csp:ty,
		fuzz: $fuzz:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Fuzz wrapper handles iteration
			let result = $crate::tb_scenario!(@fuzz_wrapper $fuzz, |fuzz_input| {
				let trace_collector = $crate::testing::trace::TraceCollector::with_fuzz_oracle(
					fuzz_input,
					<$csp>::process()
				);

				// Environment-specific execution
				let trace_exec = trace_collector.clone();
				fn __call_exec_closure<F>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace)
				}
				let exec_result = __call_exec_closure($exec_closure, trace_exec);

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result exec_result, verification_result)
			});

			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Bare environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			// Environment-specific execution
			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_exec = trace_collector.clone();
			fn __call_exec_closure<F>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace)
			}
			let exec_result = __call_exec_closure($exec_closure, trace_exec);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				multi_specs: specs,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment + fuzz =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		fuzz: $fuzz:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Fuzz wrapper handles iteration
			let result = $crate::tb_scenario!(@fuzz_wrapper $fuzz, |fuzz_input| {
				// Environment-specific execution
				let trace_collector = $crate::testing::macros::TraceCollector::new();
				let trace_setup = trace_collector.clone();
				let trace_stimulus = trace_collector.clone();
				let fuzz_for_setup = fuzz_input.clone();
				let fuzz_for_stimulus = fuzz_input.clone();

				// Helper functions to enable type inference
				fn __call_setup_closure<F, W>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
					fuzz_input: Vec<u8>,
				) -> W
				where
					F: FnOnce($crate::testing::macros::TraceCollector, Vec<u8>) -> W,
				{
					closure(trace, fuzz_input)
				}

				fn __call_stimulus_closure<F, W>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
					worker: &mut W,
					fuzz_input: Vec<u8>,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector, &mut W, Vec<u8>) -> Result<(), $crate::TightBeamError>,
				{
					closure(trace, worker, fuzz_input)
				}

				let mut worker = __call_setup_closure($setup_closure, trace_setup, fuzz_for_setup);
				let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker, fuzz_for_stimulus);

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					$(csp: $csp,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// Return combined result
				tb_scenario!(@propagate_result exec_result, verification_result)
			});

			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			// Environment-specific execution
			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_setup = trace_collector.clone();
			let trace_stimulus = trace_collector.clone();

			// Helper functions to enable type inference (synchronous)
			fn __call_setup_closure<F, W>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
			) -> W
			where
				F: FnOnce($crate::testing::macros::TraceCollector) -> W,
			{
				closure(trace)
			}

			fn __call_stimulus_closure<F, W>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				worker: &mut W,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace, worker)
			}

			let mut worker = __call_setup_closure($setup_closure, trace_setup);
			let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			// Environment-specific execution
			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_setup = trace_collector.clone();
			let trace_stimulus = trace_collector.clone();

			// Helper functions to enable type inference (synchronous)
			fn __call_setup_closure<F, W>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
			) -> W
			where
				F: FnOnce($crate::testing::macros::TraceCollector) -> W,
			{
				closure(trace)
			}

			fn __call_stimulus_closure<F, W>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				worker: &mut W,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
			{
				closure(trace, worker)
			}

			let mut worker = __call_setup_closure($setup_closure, trace_setup);
			let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

			// Common finalization
			let mut trace = $crate::tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
			$crate::tb_scenario!(@finalize_trace trace, exec_result);

			let verification_result = $crate::__tb_scenario_verify_impl! {
				multi_specs: specs,
				trace: trace,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			$crate::tb_scenario!(@propagate_result exec_result, verification_result).expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for ServiceClient environment (single spec) =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			const WORKER_THREADS: usize = $crate::tb_scenario!(@default_worker_threads $($threads)?);

			let runtime = tokio::runtime::Builder::new_multi_thread()
				.worker_threads(WORKER_THREADS)
				.enable_all()
				.build()
				.expect("Failed to build tokio runtime");

			let exec_result = runtime.block_on(async {
				let trace_collector = $crate::testing::macros::TraceCollector::new();
				let trace_server = trace_collector.clone();
				let trace_client = trace_collector.clone();

				let server_setup_result: Result<(tokio::task::JoinHandle<()>, _), $crate::TightBeamError> =
					($server_closure)(trace_server).await;
				let (server_handle, server_addr) = server_setup_result?;

				type ProtocolType = $crate::tb_scenario!(@default_protocol $($protocol)?);

				let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
					.map_err(|e| $crate::TightBeamError::from(e))?;
				let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, client_result);

				server_handle.abort();

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					$(csp: $csp,)?
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result client_result, verification_result)
			});

			exec_result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for ServiceClient environment (multiple specs) =====
	(
		name: $test_name:ident,
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			// Common setup
			#[cfg(feature = "instrument")]
			let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
			#[cfg(feature = "instrument")]
			$crate::tb_scenario!(@init_instrumentation instr_mode);

			let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
				$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
			];

			const WORKER_THREADS: usize = $crate::tb_scenario!(@default_worker_threads $($threads)?);

			let runtime = tokio::runtime::Builder::new_multi_thread()
				.worker_threads(WORKER_THREADS)
				.enable_all()
				.build()
				.expect("Failed to build tokio runtime");

			let exec_result = runtime.block_on(async {
				let trace_collector = $crate::testing::macros::TraceCollector::new();
				let trace_server = trace_collector.clone();
				let trace_client = trace_collector.clone();

				let server_setup_result: Result<(tokio::task::JoinHandle<()>, _), $crate::TightBeamError> =
					($server_closure)(trace_server).await;
				let (server_handle, server_addr) = server_setup_result?;

				type ProtocolType = $crate::tb_scenario!(@default_protocol $($protocol)?);

				let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
					.map_err(|e| $crate::TightBeamError::from(e))?;
				let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, client_result);

				server_handle.abort();

				let verification_result = $crate::__tb_scenario_verify_impl! {
					multi_specs: specs,
					trace: trace,
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				$crate::tb_scenario!(@propagate_result client_result, verification_result)
			});

			exec_result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Bare environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute Bare, single_spec, $spec, $(csp: $csp,)? $(fdr: $fdr_config,)? $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? exec: $exec_closure)
	};

	// ===== Bare environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		// Environment-specific execution
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_exec = trace_collector.clone();
		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}
		let exec_result = __call_exec_closure($exec_closure, trace_exec);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Worker environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		// Environment-specific execution
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Worker environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {{
		// Common setup
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		// Environment-specific execution
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Common finalization
		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== ServiceClient environment - user provides complete server setup =====
	// User receives assertions collector for both server and client
	(
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, single_spec, $spec,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(instrumentation: $instr_cfg,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== ServiceClient environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: |$client:ident| $client_body:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, multi_specs, [ $( $spec_expr ),+ ],
			$(fdr: $fdr_config,)?
			$(instrumentation: $instr_cfg,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client_body: |$client| $client_body
		)
	};

	// ===== Internal: Instrumentation helpers =====
	(@get_instr_mode) => {
		$crate::testing::macros::InstrumentationMode::Auto
	};
	(@get_instr_mode $mode:expr) => {
		$mode
	};

	(@init_instrumentation $mode:expr) => {
		#[cfg(feature = "instrument")]
		{
			let mode = &$mode;
			if mode.is_auto() {
				let cfg = mode.config();
				let _ = $crate::instrumentation::active::init(cfg);
				$crate::instrumentation::active::start_trace();
			}
		}
	};

	(@finalize_instrumentation $trace:expr, $mode:expr) => {
		#[cfg(feature = "instrument")]
		{
			let mode = &$mode;
			if mode.is_auto() {
				let artifact = $crate::instrumentation::active::end_trace();
				$trace.instrument_events = artifact.events;
			}
		}
	};

	// ===== Internal: Common trace setup/teardown =====
	(@setup_trace) => {{
		$crate::testing::trace::ConsumedTrace::new()
	}};

	(@finalize_trace $trace:expr, $exec_result:expr) => {{
		$trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
		if $exec_result.is_err() {
			$trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
		}
	}};

	(@with_instrumentation $instr_mode:expr, $body:block) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = $instr_mode;
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		let result = $body;

		result
	}};

	// ===== Common execution logic helper =====
	(@common_exec_logic $exec_result:expr, $spec:tt, $spec_type:tt, $($instr_cfg:expr)?, $($csp:ty)?, $($hooks:block)?) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@init_instrumentation instr_mode);

		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let exec_result = $exec_result;

		let mut trace = $crate::tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);

		$crate::tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			$spec_type: $spec,
			trace: trace,
			$($csp: $csp,)?
			$($hooks)?
		};

		$crate::tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Unified test function generator =====
	(@test_function $test_name:ident, async=$is_async:tt, $($threads:literal)?, $body:block) => {
		#[cfg(feature = "tokio")]
		#[cfg_attr($($threads)?, tokio::test(flavor = "multi_thread", worker_threads = $($threads)?))]
		#[cfg_attr(not($($threads)?), tokio::test)]
		#[cfg(not(feature = "tokio"))]
		#[test]
		fn $test_name() $body
	};

	// ===== Unified test generation dispatcher =====
	(@generate_test $test_name:ident, async=$is_async:tt, worker_threads=$($threads:literal)?, $execution:expr) => {
		tb_scenario!(@test_function $test_name, async=$is_async, worker_threads=$($threads)?, {
			let result = $execution;
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		});
	};

	// ===== Unified execution wrapper =====
	(@common_execution
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		$(csp: $csp:ty,)?
		$spec_type:tt: $spec:tt,
		$trace:expr,
		$exec_result:expr
	) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation $trace, instr_mode);

		tb_scenario!(@finalize_trace $trace, $exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			$spec_type: $spec,
			trace: $trace,
			$(csp: $csp,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result $exec_result, verification_result)
	}};

	// ===== Environment-specific execution dispatchers =====
	(@environment_exec Bare, $trace_collector:expr, $exec_closure:expr) => {{
		let trace_exec = $trace_collector.clone();

		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}

		__call_exec_closure($exec_closure, trace_exec)
	}};

	(@environment_exec Worker, $trace_collector:expr, $setup_closure:expr, $stimulus_closure:expr) => {{
		let trace_setup = $trace_collector.clone();
		let trace_stimulus = $trace_collector.clone();

		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		__call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker)
	}};

	(@environment_exec ServiceClient, $trace_collector:expr,
		$(protocol: $protocol:path,)?
		worker_threads: $threads:literal,
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[cfg(feature = "tokio")]
		{
			let runtime = tokio::runtime::Builder::new_multi_thread()
				.worker_threads($threads)
				.enable_all()
				.build()
				.expect("Failed to build tokio runtime");

			runtime.block_on(async {
				let trace_server = $trace_collector.clone();
				let trace_client = $trace_collector.clone();

				async fn __call_server_closure<F, Fut>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
				) -> Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector) -> Fut,
					Fut: core::future::Future<Output = Result<(tokio::task::JoinHandle<()>, $crate::transport::tcp::TightBeamSocketAddr), $crate::TightBeamError>>,
				{
					closure(trace).await
				}

				let server_setup_result = __call_server_closure($server_closure, trace_server).await;
				let (server_handle, server_addr) = server_setup_result?;

				type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

				let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
					.map_err(|e| $crate::TightBeamError::from(e))?;
				let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

				async fn __call_client_closure<F, Fut, T>(
					closure: F,
					trace: $crate::testing::macros::TraceCollector,
					client: T,
				) -> Result<(), $crate::TightBeamError>
				where
					F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
					Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
				{
					closure(trace, client).await
				}
				let client_result = __call_client_closure($client_closure, trace_client, client).await;

				server_handle.abort();

				Ok(client_result)
			})
		}

		#[cfg(not(feature = "tokio"))]
		{
			tb_scenario!(@execute ServiceClient, single_spec, $spec,
				$(csp: $csp,)?
				$(instrumentation: $instr_cfg,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				protocol: { $($protocol)? },
				worker_threads: { $threads },
				server: $server_closure,
				client: $client_closure
			)
		}
	}};

	(@environment_exec Servlet, $trace_collector:expr,
		servlet: $servlet_name:ident,
		$(start: $start_expr:expr,)?
		client: $client_closure:expr
	) => {{
		#[cfg(feature = "tokio")]
		{
			let trace_server = $trace_collector.clone();
			let trace_client = $trace_collector.clone();

			let servlet_instance = $crate::__tb_scenario_servlet_start!(
				$servlet_name,
				trace_server,
				$($start_expr)?
			);

			let server_addr = servlet_instance.addr();

			let client = async {
				Ok::<_, $crate::TightBeamError>($crate::client! {
					connect $crate::transport::tcp::r#async::TokioListener: server_addr
				})
			}.await.expect("Failed to connect client");

			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			servlet_instance.stop();

			client_result
		}
	}};

	// ===== Unified execution generation dispatcher =====
	(@generate_execution $env:tt,
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		$(csp: $csp:ty,)?
		$spec_type:tt: $spec:tt,
		$($env_args:tt)*
	) => {{
		let trace_collector = $crate::testing::macros::TraceCollector::new();

		let exec_result = tb_scenario!(@environment_exec $env, trace_collector, $($env_args)*);

		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		tb_scenario!(@common_execution
			$(instrumentation: $instr_mode,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			$(csp: $csp,)?
			$spec_type: $spec,
			trace,
			exec_result
		)
	}};

	// ===== Execution dispatcher for Bare environment =====
	(@execute Bare, single_spec, $spec:ty, $(csp: $csp:ty,)? $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? exec: $exec_closure:expr) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_exec = trace_collector.clone();

		// Helper function to enable type inference for exec closure (synchronous)
		fn __call_exec_closure<F>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace)
		}

		let exec_result = __call_exec_closure($exec_closure, trace_exec);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Shared fuzz iteration wrapper =====
	// Wraps any test execution in fuzz iteration loop
	(@fuzz_wrapper $fuzz:ty, |$input_var:ident| $test_body:expr) => {{
		use $crate::testing::specs::FuzzSpec;

		let mut successes = 0usize;
		let mut failures = 0usize;
		let test_cases = <$fuzz>::test_cases();

		for iteration in 0..test_cases {
			// Generate fuzz input for this iteration
			let $input_var = <$fuzz>::generate_input(iteration);

			// Execute test body with fuzz input
			let result: Result<(), $crate::TightBeamError> = $test_body;

			// Track results
			if result.is_ok() {
				successes += 1;
			} else {
				failures += 1;
			}
		}

		// Report statistics
		let success_rate = (successes as f64 / test_cases as f64) * 100.0;
		let min_rate = <$fuzz>::min_success_rate();

		if <$fuzz>::print_stats() {
			println!("\nFuzz test results:");
			println!("  Test cases: {}", test_cases);
			println!("  Successes: {} ({:.1}%)", successes, success_rate);
			println!("  Failures: {} ({:.1}%)", failures, (failures as f64 / test_cases as f64) * 100.0);
			println!("  Required: >= {:.1}%", min_rate);
		}

		// Verify fuzzer can generate valid inputs at configured rate
		assert!(
			success_rate >= min_rate,
			"Fuzz test failed: only {:.1}% success rate (expected >= {:.1}%). \
			 Fuzzer unable to consistently generate valid inputs. \
			 Successes: {}, Failures: {}, Total: {}",
			success_rate,
			min_rate,
			successes,
			failures,
			test_cases
		);

		Ok::<(), $crate::TightBeamError>(())
	}};

	// ===== Execution dispatcher for Worker environment =====
	(@execute Worker, single_spec, $spec:ty, $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference (synchronous)
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	(@execute Worker, multi_specs, [ $( $spec_expr:expr ),+ ], $(fdr: $fdr_config:expr,)? $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_setup = trace_collector.clone();
		let trace_stimulus = trace_collector.clone();

		// Helper functions to enable type inference
		fn __call_setup_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
		) -> W
		where
			F: FnOnce($crate::testing::macros::TraceCollector) -> W,
		{
			closure(trace)
		}

		fn __call_stimulus_closure<F, W>(
			closure: F,
			trace: $crate::testing::macros::TraceCollector,
			worker: &mut W,
		) -> Result<(), $crate::TightBeamError>
		where
			F: FnOnce($crate::testing::macros::TraceCollector, &mut W) -> Result<(), $crate::TightBeamError>,
		{
			closure(trace, worker)
		}

		let mut worker = __call_setup_closure($setup_closure, trace_setup);
		let exec_result = __call_stimulus_closure($stimulus_closure, trace_stimulus, &mut worker);

		// Populate trace from collector
		let mut trace = tb_scenario!(@setup_trace);
		trace.populate_from_collector(&trace_collector);

		#[cfg(feature = "instrument")]
		tb_scenario!(@finalize_instrumentation trace, instr_mode);

		tb_scenario!(@finalize_trace trace, exec_result);

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== ServiceClient environment (returns Result) =====
	// User provides complete server setup, returns Result for composition
	(
		spec: $spec:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, single_spec, $spec,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== ServiceClient environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment ServiceClient {
			$(protocol: $protocol:path,)?
			$(worker_threads: $threads:literal,)?
			server: $server_closure:expr,
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		tb_scenario!(@execute ServiceClient, multi_specs, [ $( $spec_expr ),+ ],
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== Execution dispatcher for ServiceClient environment =====
	(@execute ServiceClient, single_spec, $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		worker_threads: { $($threads:literal)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[allow(unused_imports)]
		use std::sync::{Arc, Mutex};

		const WORKER_THREADS: usize = tb_scenario!(@default_worker_threads $($threads)?);

		let runtime = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(WORKER_THREADS)
			.enable_all()
			.build()
			.expect("Failed to build tokio runtime");

		let exec_result = runtime.block_on(async {
			#[cfg(feature = "instrument")]
			let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
			#[cfg(feature = "instrument")]
			tb_scenario!(@init_instrumentation instr_mode);

			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_server = trace_collector.clone();
			let trace_client = trace_collector.clone();

			let server_setup_result: Result<(tokio::task::JoinHandle<()>, _), $crate::TightBeamError> =
				($server_closure)(trace_server).await;
			let (server_handle, server_addr) = server_setup_result?;

			type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

			let stream = <ProtocolType as $crate::transport::Protocol>::connect(server_addr).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			let mut trace = tb_scenario!(@setup_trace);
			trace.populate_from_collector(&trace_collector);

			#[cfg(feature = "instrument")]
			tb_scenario!(@finalize_instrumentation trace, instr_mode);

			tb_scenario!(@finalize_trace trace, client_result);

			server_handle.abort();

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			tb_scenario!(@propagate_result client_result, verification_result)
		});

		exec_result
	}};

	(@execute ServiceClient, multi_specs, [ $( $spec_expr:expr ),+ ],
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_mode:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		worker_threads: { $($threads:literal)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		#[allow(unused_imports)]
		use std::sync::Arc;

		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		const WORKER_THREADS: usize = tb_scenario!(@default_worker_threads $($threads)?);

		let runtime = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(WORKER_THREADS)
			.enable_all()
			.build()
			.expect("Failed to build tokio runtime");

		let exec_result = runtime.block_on(async {
			#[cfg(feature = "instrument")]
			let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
			#[cfg(feature = "instrument")]
			tb_scenario!(@init_instrumentation instr_mode);

			let result = tb_scenario!(@execute_service_client_async multi_specs, specs,
				$(fdr: $fdr_config,)?
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				protocol: { $($protocol)? },
				server: $server_closure,
				client: $client_closure
			);

			result
		});

		exec_result
	}};

	// ===== Async ServiceClient execution (single spec) =====
	(@execute_service_client_async single_spec, $spec:ty,
		$(fdr: $fdr_config:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

		let bind_addr = <ProtocolType as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let (listener, addr) = <ProtocolType as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;

		let server_handle = ($server_closure)(listener);

		let stream = <ProtocolType as $crate::transport::Protocol>::connect(addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let mut client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

		let client_result = ($client_closure)(&mut client).await;

		let mut trace = tb_scenario!(@setup_trace);
		tb_scenario!(@finalize_trace trace, client_result);

		server_handle.abort();

		let verification_result = $crate::__tb_scenario_verify_impl! {
			single_spec: $spec,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== Async ServiceClient execution (multi specs) =====
	(@execute_service_client_async multi_specs, $specs:expr,
		$(fdr: $fdr_config:expr,)?
		$(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)?
		protocol: { $($protocol:path)? },
		server: $server_closure:expr,
		client: $client_closure:expr
	) => {{
		type ProtocolType = tb_scenario!(@default_protocol $($protocol)?);

		let bind_addr = <ProtocolType as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let (listener, addr) = <ProtocolType as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;

		let server_handle = ($server_closure)(listener);

		let stream = <ProtocolType as $crate::transport::Protocol>::connect(addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let mut client = <ProtocolType as $crate::transport::Protocol>::create_transport(stream);

		let client_result = ($client_closure)(&mut client).await;

		let mut trace = tb_scenario!(@setup_trace);
		tb_scenario!(@finalize_trace trace, client_result);

		server_handle.abort();

		let verification_result = $crate::__tb_scenario_verify_impl! {
			multi_specs: $specs,
			trace: trace,
			$(fdr: $fdr_config,)?
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== AFL fuzz target for Servlet environment (NO #[test], generates fuzz!) =====
	(
		spec: $spec:ty,
		csp: $csp:ty,
		fuzz: afl,
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Servlet {
			servlet: $servlet_name:ident,
			$(start: $start_expr:expr,)?
			client: $client_closure:expr
		}
		$(, hooks {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		})?
		$(,)?
	) => {
		#[allow(unexpected_cfgs)]
		#[cfg(fuzzing)]
		fn main() {
			// Reuse runtime and servlet across AFL iterations to reduce setup overhead
			// Runtime is created once and reused - servlet tasks run in this persistent runtime
			// Servlet is created once and reused, with state reset before each iteration
			// Use Mutex<Option> to allow async initialization
			static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
			static SERVLET: std::sync::Mutex<Option<std::sync::Arc<std::sync::Mutex<$servlet_name>>>> = std::sync::Mutex::new(None);

			::afl::fuzz!(|data: &[u8]| {
				// DEBUG: Track AFL fuzz closure entry
				eprintln!("[DEBUG] AFL fuzz closure called: data_len={}", data.len());
				let _ = std::fs::write("/tmp/afl_fuzz_closure_entry.txt", format!("afl_fuzz_closure_called: data_len={}\n", data.len()));

				// Common setup
				#[cfg(feature = "instrument")]
				let instr_mode = $crate::tb_scenario!(@get_instr_mode $($instr_cfg)?);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@init_instrumentation instr_mode);

				// AFL provides the data - use it directly with FuzzContext
				let trace_collector = $crate::testing::trace::TraceCollector::with_fuzz_oracle(
					data.to_vec(),
					<$csp>::process()
				);

				// Servlet environment execution - reuse runtime and servlet
				// Get or create runtime (created once, reused for all iterations)
				let runtime = RUNTIME.get_or_init(|| {
					eprintln!("[DEBUG] Creating persistent runtime");
					let _ = std::fs::write("/tmp/afl_runtime_init.txt", "afl_runtime_initializing\n");
					tokio::runtime::Builder::new_current_thread()
						.enable_all()
						.build()
						.expect("Failed to create tokio runtime")
				});

				let _ = std::fs::write("/tmp/afl_block_on_start.txt", "afl_block_on_starting\n");
				// Use runtime.block_on() - it completes when the future completes, not when all tasks complete
				// The servlet's server task runs in background and doesn't block this
				let exec_result = runtime.block_on(async {
							let _ = std::fs::write("/tmp/afl_async_block_entry.txt", "afl_async_block_entered\n");
							let trace_client = trace_collector.clone();
							let trace_server = trace_collector.clone();

							// Get or initialize servlet (created once, reused for all iterations)
							// Since we're already in an async context (runtime.block_on), we can await directly
							// Check if servlet needs initialization (drop lock before await)
							let needs_init = {
								let servlet_guard = SERVLET.lock().unwrap();
								servlet_guard.is_none()
							};

							if needs_init {
								let _ = std::fs::write("/tmp/afl_servlet_init_start.txt", "afl_servlet_init_starting\n");
								let _ = std::fs::write("/tmp/afl_servlet_start_macro_call.txt", "calling_servlet_start_macro\n");
								let servlet_instance = $crate::__tb_scenario_servlet_start!(
									$servlet_name,
									trace_server.clone(),
									$($start_expr)?
								);
								let _ = std::fs::write("/tmp/afl_servlet_start_macro_done.txt", "servlet_start_macro_completed\n");
								let _ = std::fs::write("/tmp/afl_servlet_init_done.txt", "afl_servlet_init_completed\n");
								let mut servlet_guard = SERVLET.lock().unwrap();
								*servlet_guard = Some(std::sync::Arc::new(std::sync::Mutex::new(servlet_instance)));
							}

							let servlet = {
								let servlet_guard = SERVLET.lock().unwrap();
								servlet_guard.as_ref().unwrap().clone()
							};

							// Reset servlet state before each iteration
							// For chess servlet: calls reset_chess_game_state() function
							// Note: reset_chess_game_state() must be defined at module level in test file
							$crate::tb_scenario!(@reset_servlet_state $servlet_name, servlet);

							// Get servlet address (need to lock to access)
							let server_addr = {
								let servlet_guard = servlet.lock().unwrap();
								servlet_guard.addr()
							};

							// Wrap client creation in an async block that returns Result
							let client = async {
								Ok::<_, $crate::TightBeamError>($crate::client! {
									connect $crate::transport::tcp::r#async::TokioListener: server_addr
								})
							}.await.expect("Failed to connect client");

							// Execute client closure
							async fn __call_client_closure<F, Fut, T>(
								closure: F,
								trace: $crate::testing::macros::TraceCollector,
								client: T,
							) -> Result<(), $crate::TightBeamError>
							where
								F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
								Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
							{
								closure(trace, client).await
							}
							let client_result = __call_client_closure($client_closure, trace_client, client).await;

							// Don't stop servlet - keep it alive for reuse
							// servlet_instance.stop(); // REMOVED: servlet stays alive

							client_result
						});

				// Report CSP exploration to IJON (if feature enabled)
				#[cfg(feature = "testing-fuzz-ijon")]
				{
					if exec_result.is_ok() {
						// Use public oracle() method to access oracle context
						let oracle_ctx = trace_collector.oracle();
						::afl::ijon_stack_max!(oracle_ctx.coverage_score());
						::afl::ijon_set!(oracle_ctx.track_state());
						// Track state hash distribution across trace depth
						let trace_depth = oracle_ctx.trace().len() as u32;
						let state_hash = oracle_ctx.track_state();
						unsafe { ::afl::ijon_hashint(trace_depth, state_hash); }
					}
				}

				// Common finalization
				let mut trace = $crate::tb_scenario!(@setup_trace);
				trace.populate_from_collector(&trace_collector);
				#[cfg(feature = "instrument")]
				$crate::tb_scenario!(@finalize_instrumentation trace, instr_mode);
				$crate::tb_scenario!(@finalize_trace trace, exec_result);

				let verification_result = $crate::__tb_scenario_verify_impl! {
					single_spec: $spec,
					trace: trace,
					csp: $csp,
					$(fdr: $fdr_config,)?
					$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
				};

				// AFL fuzz targets should not panic on failure - just return
				let _ = $crate::tb_scenario!(@propagate_result exec_result, verification_result);
			});
		}

		// Stub main() for IDE - rust-analyzer needs this to see a main() function
		// This is only compiled when NOT fuzzing, so it won't conflict with the generated main() above
		#[cfg(not(fuzzing))]
		#[allow(dead_code)]
		fn main() {
			unreachable!("This main() is only for IDE purposes. The real main() is generated by tb_scenario! macro when cfg(fuzzing) is enabled.")
		}
	};

	// ===== Servlet environment variant =====
	// Servlet is defined at module scope, test environment starts it
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(instrumentation: $instr_cfg:expr,)?
		environment Servlet {
			servlet: $servlet_name:ident,
			$(start: $start_expr:expr,)?
			client: $client_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[cfg(feature = "tokio")]
		#[tokio::test]
		async fn $test_name() {
			// Create trace collector
			let trace_collector = $crate::testing::macros::TraceCollector::new();
			let trace_client = trace_collector.clone();
			let trace_server = trace_collector.clone();

			// Start servlet - use custom start expression or default start(trace_server)
			let servlet_instance = $crate::__tb_scenario_servlet_start!(
				$servlet_name,
				trace_server,
				$($start_expr)?
			);

			// Get servlet address and create client
			let server_addr = servlet_instance.addr();

			// Wrap client creation in an async block that returns Result
			let client = async {
				Ok::<_, $crate::TightBeamError>($crate::client! {
					connect $crate::transport::tcp::r#async::TokioListener: server_addr
				})
			}.await.expect("Failed to connect client");

			// Execute client closure
			async fn __call_client_closure<F, Fut, T>(
				closure: F,
				trace: $crate::testing::macros::TraceCollector,
				client: T,
			) -> Result<(), $crate::TightBeamError>
			where
				F: FnOnce($crate::testing::macros::TraceCollector, T) -> Fut,
				Fut: core::future::Future<Output = Result<(), $crate::TightBeamError>>,
			{
				closure(trace, client).await
			}
			let client_result = __call_client_closure($client_closure, trace_client, client).await;

			// Stop servlet
			servlet_instance.stop();

			// Collect trace
			let mut trace = $crate::testing::trace::ConsumedTrace::new();
			trace.populate_from_collector(&trace_collector);
			trace.gate_decision = Some($crate::policy::TransitStatus::Accepted);
			if client_result.is_err() {
				trace.error = Some($crate::transport::error::TransportError::InvalidMessage);
			}

			let verification_result = $crate::__tb_scenario_verify_impl! {
				single_spec: $spec,
				trace: trace,
				$(csp: $csp,)?
				$(fdr: $fdr_config,)?
				$(hooks: $hooks,)?
			};

			if let Err(e) = client_result {
				panic!("Client execution failed: {:?}", e);
			} else if let Err(v) = verification_result {
				panic!("Spec verification failed: {:?}", v);
			}
		}
	};	// ===== Helper dispatchers for defaults =====
	(@default_worker_threads) => { 2 };
	(@default_worker_threads $threads:literal) => { $threads };

	(@default_protocol) => { $crate::transport::tcp::r#async::TokioListener };
	(@default_protocol $protocol:path) => { $protocol };

	// ===== CSP validation helper =====
	(@csp_validate $trace:expr, $csp:ty) => {{
		let csp_spec = <$csp>::default();
		Some(<$csp as $crate::testing::specs::csp::ProcessSpec>::validate_trace(&csp_spec, &$trace))
	}};
	(@csp_validate $trace:expr,) => {{
		None::<$crate::testing::specs::csp::CspValidationResult>
	}};

	// ===== FDR validation helper =====
	(@fdr_validate_with_config $trace:expr, $fdr_config:expr) => {{
		#[cfg(feature = "testing-fdr")]
		{
			use $crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};

			let config: FdrConfig = $fdr_config;
			let trace_process = $trace.to_process();

			// FdrExplorer checks: config.specs ⊑ process (spec ⊑ impl)
			// We want to check: spec_process ⊑ trace_process
			// So we set trace_process as the main process and config.specs as the spec
			// The config.specs should already contain the specification processes
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, config.clone());
			(Some(explorer.explore()), Some(config))
		}
		#[cfg(not(feature = "testing-fdr"))]
		{
			compile_error!("FDR validation requires testing-fdr feature");
		}
	}};
	(@fdr_validate_with_config $trace:expr,) => {{
		(None::<$crate::testing::fdr::FdrVerdict>, None::<$crate::testing::fdr::FdrConfig>)
	}};
	(@fdr_validate $trace:expr, $fdr_config:expr) => {{
		#[cfg(feature = "testing-fdr")]
		{
			use $crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};

			let config: FdrConfig = $fdr_config;
			let trace_process = $trace.to_process();

			// FdrExplorer checks: config.specs ⊑ process (spec ⊑ impl)
			// We want to check: spec_process ⊑ trace_process
			// So we set trace_process as the main process and config.specs as the spec
			// The config.specs should already contain the specification processes
			let mut explorer = DefaultFdrExplorer::with_defaults(&trace_process, config);
			Some(explorer.explore())
		}
		#[cfg(not(feature = "testing-fdr"))]
		{
			compile_error!("FDR validation requires testing-fdr feature");
		}
	}};
	(@fdr_validate $trace:expr,) => {{
		None::<$crate::testing::fdr::FdrVerdict>
	}};

	// ===== Servlet state reset helper (for fuzzing) =====
	// This macro resets servlet state before each fuzz iteration
	// For chess servlet: resets game_state in shared Arc
	// For other servlets: may need servlet-specific reset logic
	(@reset_servlet_state ChessEngineServlet, $servlet:expr) => {
		// Chess servlet: reset shared GAME_STATE Arc
		// Calls reset_chess_game_state() function defined at module level in chess/test.rs
		let _ = $servlet; // Suppress unused warning
		// The reset_chess_game_state() function must be defined at module level in the test file
		// This macro expansion will call it - compilation will fail if function doesn't exist
		reset_chess_game_state();
	};
	(@reset_servlet_state $servlet_name:ident, $servlet:expr) => {
		// Default: no-op (servlet-specific resets can be added)
		let _ = $servlet; // Suppress unused warning
	};

	// ===== Shared result propagation logic =====
	(@propagate_result $exec_result:ident, $verification_result:ident) => {
		if let Err(e) = $exec_result {
			Err(e)
		} else if let Err(_v) = $verification_result {
			panic!("Spec verification failed: {:?}", _v);
		} else {
			Ok(())
		}
	};

	// Catch-all for unrecognized syntax
	($($tt:tt)*) => {
		compile_error!("Unrecognized tb_scenario! syntax; expected: name: test_name, spec: Type, environment <Variant> { ... }");
	};
}

/// Helper macro for starting servlets in tb_scenario!
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_scenario_servlet_start {
	// Custom start expression provided
	($servlet:ident, $trace:expr, $start:expr) => {
		$start.await.expect("Failed to start servlet")
	};
	// Default: call start with trace collector
	($servlet:ident, $trace:expr,) => {
		$servlet::start($trace).await.expect("Failed to start servlet")
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::create_test_message;
	use crate::testing::macros::TraceCollector;
	use crate::testing::trace::ExecutionMode;
	use crate::testing::utils::TestMessage;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;

	#[test]
	fn cardinality_basic() {
		let c = Cardinality::between(1, 3);
		assert!(c.is_satisfied_by(2));
		assert!(!c.is_satisfied_by(0));
		assert!(!c.is_satisfied_by(4));
	}

	#[test]
	fn builder_duplicate_label() -> Result<(), Box<dyn std::error::Error>> {
		let b = AssertSpecBuilder::new("spec", ExecutionMode::Accept)
			.assertion("L1", vec![], Cardinality::exactly(1))?
			.assertion("L1", vec![], Cardinality::exactly(2));
		assert!(matches!(b, Err(SpecBuildError::DuplicateLabel("L1"))));
		Ok(())
	}

	tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(1)),
				("Responded", exactly!(1))
			]
		},
		V(1,1,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(1)),
				("Responded", exactly!(2))
			]
		},
	}

	tb_assert_spec! {
		pub ClientServerSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("Received", exactly!(2)),
				("Responded", exactly!(2)),
				("message_content", exactly!(1), equals!("Hello TightBeam!"))
			]
		},
	}

	#[test]
	fn hash_differs_across_versions() {
		let h1 = DemoSpec::get(1, 0, 0).unwrap().spec_hash();
		let h2 = DemoSpec::get(1, 1, 0).unwrap().spec_hash();
		assert_ne!(h1, h2);
	}

	#[test]
	fn latest_points_to_highest() {
		assert_eq!(DemoSpec::latest().version(), (1, 1, 0));
	}

	tb_scenario! {
		name: scenario_bare_with_hooks,
		spec: DemoSpec,
		environment Bare {
			exec: |trace| {
				trace.assert("Received", &[]);
				trace.assert("Responded", &[]);
				trace.assert("Responded", &[]);
				Ok(())
			}
		}
	}

	tb_scenario! {
		name: scenario_bare_specific_version,
		specs: [DemoSpec::get(1, 0, 0)],
		environment Bare {
			exec: |trace| {
				trace.assert("Received", &[]);
				trace.assert("Responded", &[]);
				Ok(())
			}
		}
	}

	#[test]
	#[should_panic(expected = "Spec verification failed")]
	fn scenario_bare_multiple_versions() {
		// Suppress panic output for cleaner test output
		std::panic::set_hook(Box::new(|_| {}));

		// Test against both versions - v1.1.0 expects exactly 2 Responded, we only emit 1
		// Should panic because v1.1.0 expects 2 Response but we only emitted 1
		let _result = tb_scenario! {
			specs: [DemoSpec::get(1, 0, 0), DemoSpec::get(1, 1, 0)],
			environment Bare {
				exec: |trace| {
					trace.assert("Received", &[]);
					trace.assert("Responded", &[]);
					Ok(())
				}
			}
		};
	}

	// Simple worker struct for testing
	struct TestWorker {
		received_count: usize,
		trace: TraceCollector,
	}

	impl TestWorker {
		fn new(trace: TraceCollector) -> Self {
			Self { received_count: 0, trace }
		}

		fn process(&mut self) -> Result<(), crate::TightBeamError> {
			self.trace.assert("Received", &[]);
			self.received_count += 1;
			self.trace.assert("Responded", &[]);
			self.trace.assert("Responded", &[]);
			Ok(())
		}
	}

	tb_scenario! {
		name: scenario_worker_basic,
		spec: DemoSpec,
		environment Worker {
			setup: TestWorker::new,
			stimulus: |_trace, worker: &mut TestWorker| worker.process()
		}
	}

	tb_scenario! {
		name: scenario_worker_specific_version,
		specs: [DemoSpec::get(1, 0, 0)],
		environment Worker {
			setup: TestWorker::new,
			stimulus: |trace, worker: &mut TestWorker| {
				trace.assert("Received", &[]);
				worker.received_count += 1;
				trace.assert("Responded", &[]);
				Ok(())
			}
		}
	}

	// ServiceClient tests require async runtime and transport features
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: scenario_service_client_basic,
		spec: DemoSpec,
		environment ServiceClient {
			worker_threads: 2,
			server: |trace: TraceCollector| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace,
					handle: |frame, trace| async move {
						trace.assert("Received", &[]);
						trace.assert("Responded", &[]);
						trace.assert("Responded", &[]);
						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |_trace: TraceCollector, mut client| async move {
				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
				}?;

				let _response = client.emit(test_frame, None).await?;

				Ok(())
			}
		}
	}

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	static HOOK_CALLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	tb_scenario! {
		name: scenario_service_client_with_client_assertions_and_hooks,
		spec: ClientServerSpec,
		environment ServiceClient {
			worker_threads: 2,
			server: |trace: TraceCollector| async move {
				let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
				let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
				let handle = crate::server! {
					protocol TokioListener: listener,
					assertions: trace,
					handle: |frame, trace| async move {
						// Server-side assertions
						trace.assert("Received", &[]);
						trace.assert("Responded", &[]);

						// Decode message to extract value for assertion
						let decoded: Result<TestMessage, _> = crate::decode(&frame.message);
						if let Ok(msg) = decoded {
							trace.assert_value("message_content", &[], msg.content);
						}

						Ok(Some(frame))
					}
				};

				Ok((handle, addr))
			},
			client: |trace, mut client| async move {
				// Client-side assertion before sending
				trace.assert("Responded", &[]);

				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
					}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.assert("Received", &[]);

				Ok(())
			}
		},
		hooks {
			on_pass: |_trace| {
				HOOK_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
			},
			on_fail: |_trace, violations| {
				panic!("Test should not fail! Violations: {violations:?}");
			}
		}
	}
}

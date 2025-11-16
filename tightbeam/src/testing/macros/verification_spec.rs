//! Verification-spec macros (`tb_assert_spec!`) plus supporting builders.
//! Provides label helpers, cardinality utilities, and the `BuiltAssertSpec`
//! wrapper that implements `TBSpec`.

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionContract, AssertionLabel, AssertionValue};
use crate::testing::specs::{SpecViolation, TBSpec};
use crate::testing::trace::{ConsumedTrace, ExecutionMode};
use crate::Errorizable;

#[cfg(feature = "instrument")]
use crate::instrumentation::TbEventKind;
#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};
#[cfg(not(feature = "std"))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::borrow::Cow;

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

// Helper macro for common spec building logic (single implementation)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build {
	(
		$vec:ident,
		$base:ident,
		$maj:literal, $min:literal, $patch:literal,
		$mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* $(,)? ],
		events: [ $( $ev:ident ),* $(,)? ]
		$(, tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
	) => {{
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(
			stringify!($base),
			$crate::testing::trace::ExecutionMode::$mode,
		);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate);
		$(
			builder = builder.tag_filter(vec![ $( $tag ),* ]);
		)?
		$(
			if let Some(desc) = $desc {
				builder = builder.description(desc);
			}
		)?
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{
			$(
				builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]);
			)*
		}
		$vec.push(builder.build());
	}};
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

// Multi-version macro ONLY (full semantic version required maj.min.patch)
#[macro_export]
macro_rules! tb_assert_spec {
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : {
			mode: $mode:ident,
			gate: $gate:ident,
			$( tag_filter: [ $( $tag:expr ),* $(,)? ], )?
			assertions: [ $( $assertion:tt ),* $(,)? ]
			$(, events: [ $( $ev:ident ),* $(,)? ])?
		} ),+ $(,)?
		$(, annotations { description: $desc:expr })?
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				let desc_opt: Option<&'static str> = None::<&'static str> $(.or(Some($desc)))?;
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let desc_opt = desc_opt;
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(
								v, $base, $maj, $min, $patch, $mode, $gate,
								assertions: [ $( $assertion ),* ],
								events: [ $( $( $ev ),* )? ]
								$(, tag_filter: [ $( $tag ),* ])?,
								description: desc_opt
							);
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
						let desc_opt = desc_opt;
						let mut v = Vec::new();
						$(
							$crate::__tb_assert_spec_build!(
								v, $base, $maj, $min, $patch, $mode, $gate,
								assertions: [ $( $assertion ),* ],
								events: [ $( $( $ev ),* )? ]
								$(, tag_filter: [ $( $tag ),* ])?,
								description: desc_opt
							);
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
// Scenario macro MVP
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

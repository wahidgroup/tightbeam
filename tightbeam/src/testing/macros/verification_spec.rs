//! Verification-spec macros (`tb_assert_spec!`) plus supporting builders.
//! Provides label helpers, cardinality utilities, and the `BuiltAssertSpec`
//! wrapper that implements `TBSpec`.

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionContract, AssertionLabel, AssertionValue};
use crate::testing::specs::{SpecViolation, TBSpec};
use crate::trace::{ConsumedTrace, ExecutionMode};
use crate::Errorizable;

#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulerType, TaskSet};

// TbEventKind removed - use events module constants instead
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
#[derive(Debug, Clone)]
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
	required_events: Vec<crate::utils::urn::Urn<'static>>,
	description: Option<&'static str>,
	#[cfg(feature = "testing-timing")]
	schedulability: Option<SchedulabilityAssertion>,
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
			#[cfg(feature = "testing-timing")]
			schedulability: None,
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
	pub fn required_events(mut self, kinds: &[crate::utils::urn::Urn<'static>]) -> Self {
		use std::collections::HashSet;
		let mut seen = HashSet::new();
		for k in kinds {
			if seen.insert(k.clone()) {
				self.required_events.push(k.clone());
			}
		}
		self
	}

	pub fn description(mut self, desc: &'static str) -> Self {
		self.description = Some(desc);
		self
	}

	#[cfg(feature = "testing-timing")]
	pub fn schedulability(mut self, assertion: SchedulabilityAssertion) -> Self {
		self.schedulability = Some(assertion);
		self
	}

	pub fn build(self) -> BuiltAssertSpec {
		BuiltAssertSpec::from_builder(self)
	}
}

/// Schedulability assertion for verification
#[cfg(feature = "testing-timing")]
#[derive(Debug, Clone)]
pub struct SchedulabilityAssertion {
	/// Task set to check
	pub task_set: TaskSet,
	/// Whether the task set must be schedulable
	pub must_be_schedulable: bool,
}

#[derive(Debug, Clone)]
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
					AssertionContract::new(AssertionLabel::Custom(Cow::Borrowed(label)), *card).with_value(val.clone())
				} else {
					AssertionContract::new(AssertionLabel::Custom(Cow::Borrowed(label)), *card)
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
			#[cfg(feature = "testing-timing")]
			builder.schedulability.as_ref(),
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
		#[cfg(feature = "instrument")] events: &[crate::utils::urn::Urn<'static>],
		#[cfg(feature = "testing-timing")] schedulability: Option<&SchedulabilityAssertion>,
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
		let mut norm: Vec<(&str, u32, Option<u32>, bool)> = Vec::with_capacity(contracts.len());
		for c in contracts {
			let AssertionLabel::Custom(lbl) = &c.label;
			norm.push((
				lbl.as_ref(),
				c.cardinality.min,
				c.cardinality.max,
				c.cardinality.must_be_present,
			));
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
			// Sort events for deterministic hashing (by string representation)
			let mut sorted_events: Vec<String> = events.iter().map(|e| e.to_string()).collect();
			sorted_events.sort();
			for urn_str in sorted_events {
				h.update(urn_str.as_bytes());
			}
		}
		#[cfg(feature = "testing-timing")]
		{
			if let Some(schedule) = schedulability {
				h.update([1u8]); // Has schedulability
				h.update([schedule.task_set.scheduler as u8]);
				h.update([schedule.must_be_schedulable as u8]);
				h.update((schedule.task_set.tasks.len() as u32).to_be_bytes());
				// Hash task set: sort tasks by ID for deterministic hashing
				let mut tasks: Vec<_> = schedule.task_set.tasks.iter().collect();
				tasks.sort_by(|a, b| a.id.cmp(&b.id));
				for task in tasks {
					h.update(task.id.as_bytes());
					h.update(task.period.as_nanos().to_be_bytes());
					h.update(task.deadline.as_nanos().to_be_bytes());
					h.update(task.wcet.as_nanos().to_be_bytes());
				}
			} else {
				h.update([0u8]); // No schedulability
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
	fn required_events(&self) -> &[crate::utils::urn::Urn<'static>] {
		&self.inner.required_events
	}
	fn validate_trace(&self, _trace: &ConsumedTrace) -> Result<(), SpecViolation> {
		#[cfg(feature = "testing-timing")]
		{
			if let Some(ref schedule) = self.inner.schedulability {
				return Self::check_schedulability(schedule);
			}
		}
		Ok(())
	}
}

#[cfg(feature = "testing-timing")]
impl BuiltAssertSpec {
	/// Check schedulability assertion
	fn check_schedulability(assertion: &SchedulabilityAssertion) -> Result<(), SpecViolation> {
		use crate::testing::schedulability::{is_edf_schedulable, is_rm_schedulable};

		let result = match assertion.task_set.scheduler {
			SchedulerType::RateMonotonic => is_rm_schedulable(&assertion.task_set),
			SchedulerType::EarliestDeadlineFirst => is_edf_schedulable(&assertion.task_set),
		};

		match result {
			Ok(schedule_result) => {
				let is_schedulable = schedule_result.is_schedulable;
				if assertion.must_be_schedulable && !is_schedulable {
					// Task set must be schedulable but isn't
					Err(SpecViolation::SchedulabilityViolation(schedule_result))
				} else if !assertion.must_be_schedulable && is_schedulable {
					// Task set must NOT be schedulable but is
					// Create a synthetic violation for this case
					let violation = crate::testing::schedulability::TaskViolationDetail {
						task_id: "system".to_string(),
						message: format!(
							"Task set is schedulable (utilization: {:.3}, bound: {:.3}) but should not be",
							schedule_result.utilization, schedule_result.utilization_bound
						),
					};
					let mut modified_result = schedule_result;
					modified_result.violations = vec![violation];
					Err(SpecViolation::SchedulabilityViolation(modified_result))
				} else {
					Ok(())
				}
			}
			Err(e) => Err(SpecViolation::SchedulabilityError(e)),
		}
	}
}

// ---------------------------------------------------------------------------
// Payload encoding trait (AssertEncode) for tb_assert! ergonomic payloads
// ---------------------------------------------------------------------------
/// Trait converting payload values into a canonical byte representation.
/// Numeric primitives are big-endian; &str/&\[u8\]/`Vec<u8>` zero-copy.
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

// Helper to build all specs (handles std vs non-std)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all {
	(
		$base:ident,
		$desc_opt:expr,
		$(
			$maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
			assertions: [ $( $assertion:tt ),* ],
			$(
				events: [ $($events_tt:tt)* ],
			)?
			$(, tag_filter: [ $( $tag:expr ),* $(,)? ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		)+
	) => {{
		#[cfg(feature = "std")]
		{
			static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
			CELL.get_or_init(|| {
				let mut v = Vec::new();
				$crate::__tb_assert_spec_build_all_impl!(
					v, $base, $desc_opt,
					$(
						$maj, $min, $patch, $mode, $gate,
						assertions: [ $( $assertion ),* ],
						$(
							events: [ $($events_tt)* ],
						)?
						$(, tag_filter: [ $( $tag ),* ])?
						$(, schedulability: { $($schedule_content)* })?
					)+
				);
				v
			}).as_slice()
		}
		#[cfg(not(feature = "std"))]
		{
			use core::sync::atomic::{AtomicBool, Ordering};
			static INIT: AtomicBool = AtomicBool::new(false);
			static mut VEC: Option<Vec<$crate::testing::macros::BuiltAssertSpec>> = None;
			if !INIT.load(Ordering::Acquire) {
				let desc_opt = $desc_opt;
				let mut v = Vec::new();
				$crate::__tb_assert_spec_build_all_impl!(
					v, $base, desc_opt,
					$(
						$maj, $min, $patch, $mode, $gate,
						assertions: [ $( $assertion ),* ],
						$(
							events: [ $($events_tt)* ],
						)?
						$(, tag_filter: [ $( $tag ),* ])?
						$(, schedulability: { $($schedule_content)* })?
					)+
				);
				unsafe { VEC = Some(v); }
				INIT.store(true, Ordering::Release);
			}
			unsafe { VEC.as_ref().unwrap().as_slice() }
		}
	}};
}

// Implementation helper to avoid nested repetition issues
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all_impl {
	(
		$vec:ident, $base:ident, $desc_opt:expr,
		$(
			$maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
			assertions: [ $( $assertion:tt ),* ],
			$(
				events: [ $($events_tt:tt)* ],
			)?
			$(, tag_filter: [ $( $tag:expr ),* $(,)? ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		)+
	) => {
		$(
			$crate::__tb_assert_spec_build_all_impl_with_events!(
				$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
				assertions: [ $( $assertion ),* ],
				$(
					events: [ $($events_tt:tt)* ],
				)?
				$(, tag_filter: [ $( $tag ),* ])?
				$(, schedulability: { $($schedule_content)* })?
			);
		)+
	};
}

// Helper to handle events in __tb_assert_spec_build_all_impl (avoids nested repetition)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all_impl_with_events {
	(
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		$(
			events: [ $($events_tt:tt)* ],
		)?
		$(, tag_filter: [ $( $tag:expr ),* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// Use @expand_events which handles nested repetition correctly
		// Description is handled separately in @build_with_events via $desc_opt parameter
		$crate::__tb_assert_spec_build! {
			@expand_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			$(
				events_tt: [ $($events_tt:tt)* ],
			)?
			$( tag_filter: [ $( $tag ),* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
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
		$(
			events: [ $($events_tt:tt)* ],
		)?
		$(tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// Expand events token tree to avoid nested repetition issues
		$crate::__tb_assert_spec_build! {
			@expand_events
			$vec, $base, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			$(
				events_tt: [ $($events_tt:tt)* ],
			)?
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, description: $desc)?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
	// Expand events and build - separate arms for events vs no events
	// Pattern with desc_opt parameter (from __tb_assert_spec_build_all_impl_with_events)
	// Has events case
	(@expand_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $($events_tt:tt)* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {
		$crate::__tb_assert_spec_build! {
			@build_with_events_expanded
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			events_tt: [ $($events_tt:tt)* ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	};
	// No events case
	(@expand_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {
		$crate::__tb_assert_spec_build! {
			@build_with_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			events: [ ],
			$( tag_filter: [ $( $tag ),* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	};
	// Legacy pattern without desc_opt (for backward compatibility)
	(@expand_events
		$vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		$(
			events_tt: [ $($events_tt:tt)* ],
		)?
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {
		$(
			// Has events - expand events_tt here
			$crate::__tb_assert_spec_build! {
				@build_with_events_expanded
				$vec, $base, None, $maj, $min, $patch, $mode, $gate,
				assertions: [ $( $assertion ),* ],
				events_tt: [ $($events_tt:tt)* ],
				$( tag_filter: [ $( $tag ),* $(,)? ])?
				$(, description: $desc)?
				$(, schedulability: { $($schedule_content)* })?
			}
		)?
		$(
			// No events case
			$crate::__tb_assert_spec_build! {
				@build_with_events
				$vec, $base, None, $maj, $min, $patch, $mode, $gate,
				assertions: [ $( $assertion ),* ],
				events: [ ],
				$( tag_filter: [ $( $tag ),* $(,)? ])?
				$(, description: $desc)?
				$(, schedulability: { $($schedule_content)* })?
			}
		)?
	};
	(@build_with_events_expanded
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $( $ev:ident ),* $(,)? ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		$crate::__tb_assert_spec_build! {
			@build_with_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			events: [ $( $ev ),* $(,)? ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, description: $desc)?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
	// Handle token tree events (from __tb_assert_spec_build_all_impl_with_events)
	(@build_with_events_expanded
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $($events_tt:tt)* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// Recursively expand token tree to identifiers
		$crate::__tb_assert_spec_build! {
			@build_with_events_expanded
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			events_tt: [ $($events_tt)* ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, description: $desc)?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
	// Legacy pattern without desc_opt (for backward compatibility)
	(@build_with_events_expanded
		$vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $($events_tt:tt)* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// Recursively expand token tree to identifiers
		$crate::__tb_assert_spec_build! {
			@build_with_events_expanded
			$vec, $base, None, $maj, $min, $patch, $mode, $gate,
			assertions: [ $( $assertion ),* ],
			events_tt: [ $($events_tt)* ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, description: $desc)?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
	(@build_with_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events: [ $( $ev:expr ),* $(,)? ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		let mut builder = $crate::__tb_assert_spec_init_builder!(
			$base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			$(tag_filter: [ $( $tag ),* ])?
			$(, description: $desc)?
		);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		#[cfg(feature = "instrument")]
		{
			$(
				builder = builder.required_events(&[$ev.clone()]);
			)*
		}
		$(
			#[cfg(feature = "testing-timing")]
			{
				$crate::__tb_assert_spec_parse_schedulability!(builder, $($schedule_content)*);
			}
		)?
		$vec.push(builder.build());
	}};
	// Empty events case
	(@expand_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, description: $desc:expr)?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		let mut builder = $crate::__tb_assert_spec_init_builder!(
			$base, $desc_opt, $maj, $min, $patch, $mode, $gate,
			$(tag_filter: [ $( $tag ),* ])?
			$(, description: $desc)?
		);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		$(
			#[cfg(feature = "testing-timing")]
			{
				$crate::__tb_assert_spec_parse_schedulability!(builder, $($schedule_content)*);
			}
		)?
		$vec.push(builder.build());
	}};
}

// Helper to parse schedulability assertions
#[doc(hidden)]
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! __tb_assert_spec_parse_schedulability {
	(
		$builder:ident,
		task_set: $task_set:expr,
		scheduler: $scheduler:ident,
		must_be_schedulable: $must_be:expr,
	) => {{
		use $crate::testing::schedulability::SchedulerType;
		let task_set_with_scheduler = {
			let mut ts = $task_set.clone();
			ts.scheduler = SchedulerType::$scheduler;
			ts
		};
		let assertion = $crate::testing::macros::SchedulabilityAssertion {
			task_set: task_set_with_scheduler,
			must_be_schedulable: $must_be,
		};
		$builder = $builder.schedulability(assertion);
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
			$(, events: [ $($events_tt:tt)* ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		} ),+ $(,)?
		$(, annotations { description: $desc:expr })?
	) => {
		$(#[$meta])*
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				let desc_opt: Option<&'static str> = None::<&'static str> $(.or(Some($desc)))?;
				$crate::__tb_assert_spec_build_all!(
					$base,
					desc_opt,
					$(
						$maj, $min, $patch, $mode, $gate,
						assertions: [ $( $assertion ),* ],
						$(
							events: [ $($events_tt:tt)* ],
						)?
						$(, tag_filter: [ $( $tag ),* ])?
						$(, schedulability: { $($schedule_content)* })?
					)+
				)
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

// Helper to validate CSP and FDR (reduces duplication)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_scenario_validate_csp_fdr {
	(
		$trace:expr,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
	) => {{
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

		(csp_result, csp_failed, fdr_result, fdr_config, fdr_failed, expect_failure)
	}};
}

// Helper macro to call hooks and handle results (reduces duplication)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_scenario_call_hooks {
	(
		scenario_result: $scenario_result:expr,
		csp_failed: $csp_failed:expr,
		fdr_failed: $fdr_failed:expr,
		expect_failure: $expect_failure:expr,
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		#[allow(unreachable_code)]
		#[allow(unused_labels)]
		let hook_result: Result<(), Box<dyn std::error::Error>> = 'hook_call: {
			if $scenario_result.passed {
				// Test passed - call on_pass hook if provided
				$(
					$(
						fn __call_hook<F>(f: F, trace: &$crate::trace::ConsumedTrace, result: &$crate::testing::ScenarioResult) -> Result<(), Box<dyn std::error::Error>>
						where
							F: FnOnce(&$crate::trace::ConsumedTrace, &$crate::testing::ScenarioResult) -> Result<(), Box<dyn std::error::Error>>,
						{
							f(trace, result)
						}
						break 'hook_call __call_hook($on_pass, &$scenario_result.trace, &$scenario_result);
					)?
				)?
				Ok(())
			} else {
				// Test failed - call on_fail hook if provided
				$(
					$(
						fn __call_hook<F>(f: F, trace: &$crate::trace::ConsumedTrace, result: &$crate::testing::ScenarioResult) -> Result<(), Box<dyn std::error::Error>>
						where
							F: FnOnce(&$crate::trace::ConsumedTrace, &$crate::testing::ScenarioResult) -> Result<(), Box<dyn std::error::Error>>,
						{
							f(trace, result)
						}
						break 'hook_call __call_hook($on_fail, &$scenario_result.trace, &$scenario_result);
					)?
				)?
				// No hook provided
				Err(format!("{}", $scenario_result).into())
			}
		};
		hook_result
	}};
}

// Helper macro for common spec builder initialization (reduces duplication)
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_init_builder {
	(
		$base:ident,
		$desc_opt:expr,
		$maj:literal,
		$min:literal,
		$patch:literal,
		$mode:ident,
		$gate:ident,
		$(tag_filter: [ $($tag:expr),* $(,)? ])?
		$(, description: $desc:expr)?
	) => {{
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(
			stringify!($base),
			$crate::trace::ExecutionMode::$mode,
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
		// Handle description from desc_opt parameter
		if let Some(desc) = $desc_opt {
			builder = builder.description(desc);
		}
		builder
	}};
}

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
		let l1_result = $crate::testing::specs::verify_trace(spec, &$trace);

		// Build ScenarioResult with all layer results
		let mut scenario_result = $crate::testing::ScenarioResult::default();
		// Move trace into result (transfer ownership)
		scenario_result.trace = $trace;
		// Clone and store the spec
		scenario_result.assert_spec = Some(spec.clone());
		// Layer 1: Spec verification
		scenario_result.spec_violation = l1_result.as_ref().err().cloned();

		let l1_passed = l1_result.is_ok();

		// Delegate to common implementation
		$crate::__tb_scenario_verify_impl! {
			@common
			l1_passed: l1_passed,
			scenario_result: scenario_result,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: {
				$(on_pass: $on_pass,)?
				$(on_fail: $on_fail)?
			},)?
		}
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

		// Validate all specs
		for spec in &$specs {
			let verification_result = $crate::testing::specs::verify_trace(*spec, &$trace);
			if let Err(v) = verification_result {
				all_passed = false;
				if first_violation.is_none() {
					first_violation = Some(v);
				}
			}
		}

		// Build ScenarioResult
		let mut scenario_result = $crate::testing::ScenarioResult::default();

		// Move trace into result
		scenario_result.trace = $trace;
		// Clone and store all specs
		scenario_result.assert_specs = $specs.iter().map(|s| (*s).clone()).collect();
		scenario_result.spec_violation = first_violation;

		// Delegate to common implementation
		$crate::__tb_scenario_verify_impl! {
			@common
			l1_passed: all_passed,
			scenario_result: scenario_result,
			$(csp: $csp,)?
			$(fdr: $fdr_config,)?
			$(hooks: {
				$(on_pass: $on_pass,)?
				$(on_fail: $on_fail)?
			},)?
			}
	}};

	// Common implementation for both single and multiple specs
	(
		@common
		l1_passed: $l1_passed:expr,
		scenario_result: $scenario_result:expr,
		$(csp: $csp:ty,)?
		$(fdr: $fdr_config:expr,)?
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		let mut scenario_result = $scenario_result;
		let l1_passed = $l1_passed;

		// Layer 2: CSP validation (if provided)
		#[allow(unused_mut, unused_assignments)]
		let mut csp_failed = false;

		#[cfg(feature = "testing-csp")]
		{
			$(
				let csp_spec = <$csp>::default();
				let csp_result = <$csp as $crate::testing::specs::csp::ProcessSpec>::validate_trace(&csp_spec, &scenario_result.trace);
				csp_failed = !csp_result.valid;
				scenario_result.csp_result = Some(csp_result);
				// Move process into result
				scenario_result.process = Some(<$csp>::process());

				// Move timing constraints into result (if available)
				#[cfg(feature = "testing-timing")]
				{
					let process = scenario_result.process.as_ref().unwrap();
					scenario_result.timing_constraints = process.timing_constraints.clone();
				}
			)?
		}

		// Layer 3: FDR validation (if provided)
		#[allow(unused_mut, unused_assignments)]
		let mut fdr_failed = false;
		#[allow(unused_mut, unused_assignments)]
		let mut expect_failure = false;

		#[cfg(feature = "testing-fdr")]
		{
			$(
				use $crate::testing::fdr::{DefaultFdrExplorer, FdrConfig};
				let config: FdrConfig = $fdr_config.into();
				expect_failure = config.expect_failure;

				// AUTOMATIC MODE SELECTION:
				// If fault_model + specs provided → explore spec WITH faults (specification robustness)
				// Otherwise → explore execution trace (normal behavior / implementation resilience)
				#[cfg(feature = "testing-fault")]
				let process_to_explore = if config.fault_model.is_some() && !config.specs.is_empty() {
					&config.specs[0]
				} else {
					&scenario_result.trace.to_process()
				};

				#[cfg(not(feature = "testing-fault"))]
				let process_to_explore = &scenario_result.trace.to_process();

				let mut explorer = DefaultFdrExplorer::with_defaults(process_to_explore, config.clone());
				let verdict = explorer.explore();
				fdr_failed = !verdict.passed;
				scenario_result.fdr_verdict = Some(verdict);
			)?
		}

		// Determine overall pass/fail
		scenario_result.passed = l1_passed && !csp_failed && (!fdr_failed || expect_failure);

		// Call hooks and get their decision
		$crate::__tb_scenario_call_hooks!(
			scenario_result: scenario_result,
			csp_failed: csp_failed,
			fdr_failed: fdr_failed,
			expect_failure: expect_failure,
			$(hooks: {
				$(on_pass: $on_pass,)?
				$(on_fail: $on_fail)?
			},)?
		)
	}};
}

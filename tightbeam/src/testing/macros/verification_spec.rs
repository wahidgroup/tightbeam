//! The [`tb_assert_spec!`](crate::tb_assert_spec!) macro and the types behind
//! it: [`Cardinality`] and its macros, the [`AssertSpecBuilder`], and the
//! [`BuiltAssertSpec`] that implements [`TBSpec`].

use core::num::NonZeroU32;

use crate::testing::assertions::{AssertionContract, AssertionLabel, AssertionValue};
use crate::testing::specs::{AssertionOrderContract, ResponseContract, SpecViolation, TBSpec};
use crate::trace::{ConsumedTrace, ExecutionMode, IntoEventLabel, Presence};
use crate::urn::Urn;
use crate::Errorizable;

#[cfg(feature = "digest")]
use crate::crypto::hash::{Digest, Sha3_256};
#[cfg(feature = "policy")]
use crate::policy::TransitStatus;
#[cfg(feature = "testing-timing")]
use crate::testing::schedulability::{SchedulerType, TaskSet};
#[cfg(feature = "instrument")]
use crate::testing::specs::EventCountContract;

// The cardinality of a label.

/// How many times a label may appear for a contract to hold.
///
/// Every constructor states a bound that some count fails, so its contract
/// can reject. The lower bound is a [`NonZeroU32`], because `at_least(0)`
/// would reject nothing.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cardinality {
	min: u32,
	max: Option<u32>,
}

impl Cardinality {
	pub const fn exactly(n: u32) -> Self {
		Self { min: n, max: Some(n) }
	}

	/// At least `n`, which must be positive: a lower bound of zero rejects
	/// nothing. To say a label is optional, leave it out of the spec.
	pub const fn at_least(n: NonZeroU32) -> Self {
		Self { min: n.get(), max: None }
	}
	pub const fn at_most(n: u32) -> Self {
		Self { min: 0, max: Some(n) }
	}

	/// Between `min` and `max` inclusive.
	///
	/// # Panics
	///
	/// Testing suite functions MUST panic on error.
	///
	/// - `max` is below `min`, which no count satisfies. In a constant, the
	///   panic shows at build and not at check, so `cargo check` misses it.
	pub const fn between(min: u32, max: u32) -> Self {
		assert!(min <= max, "between! requires min <= max, or no count can satisfy it");
		Self { min, max: Some(max) }
	}

	pub const fn present() -> Self {
		Self { min: 1, max: None }
	}

	pub const fn absent() -> Self {
		Self { min: 0, max: Some(0) }
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

	/// Whether `count` lies within these bounds.
	///
	/// The comparison widens the count and the bounds to `u64`, so a count
	/// past `u32::MAX` exceeds every maximum.
	pub fn is_satisfied_by(&self, count: usize) -> bool {
		let c = u64::try_from(count).unwrap_or(u64::MAX);
		if c < u64::from(self.min) {
			return false;
		}
		if let Some(mx) = self.max {
			if c > u64::from(mx) {
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

	/// Feeds the bounds into `hasher`: the minimum, then a presence byte and
	/// the maximum when there is one.
	fn hash_into(&self, hasher: &mut Sha3_256) {
		hasher.update(self.min.to_be_bytes());

		match self.max {
			Some(m) => {
				hasher.update([1u8]);
				hasher.update(m.to_be_bytes());
			}
			None => hasher.update([0u8]),
		}
	}
}

/// Whether `versions` strictly ascend in semantic version order.
/// `tb_assert_spec!` asserts it over its version blocks at compile time, and
/// `latest()` selects the highest version.
pub const fn versions_strictly_ascending(versions: &[(u16, u16, u16)]) -> bool {
	let mut index = 1;
	while index < versions.len() {
		let (previous_major, previous_minor, previous_patch) = versions[index - 1];
		let (major, minor, patch) = versions[index];
		let ascending = major > previous_major
			|| (major == previous_major && minor > previous_minor)
			|| (major == previous_major && minor == previous_minor && patch > previous_patch);
		if !ascending {
			return false;
		}

		index += 1;
	}

	true
}

// The spec builder and the built spec.

/// The refusals of [`AssertSpecBuilder`].
#[derive(Debug, Errorizable)]
pub enum SpecBuildError {
	/// The spec already holds an assertion on this label.
	#[error("Duplicate label: {0}")]
	DuplicateLabel(Urn<'static>),
	/// The ordering names a label that no assertion holds.
	#[error("Unknown ordering label: {0}")]
	UnknownOrderingLabel(Urn<'static>),
	/// The cardinality of this label has a maximum below its minimum.
	#[error("Invalid range: {0}")]
	InvalidRange(Urn<'static>),
}

/// A list of tags in sorted order, which a spec reads as a set.
#[derive(Debug, Clone)]
struct TagSet(Vec<&'static str>);

impl TagSet {
	/// The tags of this set, in sorted order.
	fn as_slice(&self) -> &[&'static str] {
		&self.0
	}
}

impl From<Vec<&'static str>> for TagSet {
	fn from(mut tags: Vec<&'static str>) -> Self {
		tags.sort_unstable();
		Self(tags)
	}
}

/// The builder that `tb_assert_spec!` drives, which code may also call.
#[derive(Debug, Clone)]
pub struct AssertSpecBuilder {
	id: &'static str,
	execution_mode: ExecutionMode,
	gate_decision: Option<TransitStatus>,
	response: Option<ResponseContract>,
	version_major: u16,
	version_minor: u16,
	version_patch: u16,
	assertions: Vec<(Urn<'static>, TagSet, Cardinality, Option<AssertionValue>)>,
	tag_filter: Option<TagSet>,
	ordering: AssertionOrderContract,
	#[cfg(feature = "instrument")]
	required_events: Vec<crate::urn::Urn<'static>>,
	#[cfg(feature = "instrument")]
	event_counts: Vec<EventCountContract>,
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
			response: None,
			version_major: 1,
			version_minor: 0,
			version_patch: 0,
			assertions: Vec::new(),
			tag_filter: None,
			ordering: AssertionOrderContract::default(),
			#[cfg(feature = "instrument")]
			required_events: Vec::new(),
			#[cfg(feature = "instrument")]
			event_counts: Vec::new(),
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

	/// The gate decision this spec requires, or `None` to require none.
	pub fn expected_gate(mut self, decision: Option<TransitStatus>) -> Self {
		self.gate_decision = decision;
		self
	}

	/// Whether the run must produce a response, or `None` to accept a run
	/// with a response or without one.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::macros::AssertSpecBuilder;
	/// use tightbeam::testing::specs::{ResponseContract, TBSpec};
	/// use tightbeam::trace::{ExecutionMode, Presence};
	///
	/// let builder = AssertSpecBuilder::new("RepliesOnce", ExecutionMode::Accept);
	/// let spec = builder.expected_response(Some(Presence::Present)).build();
	///
	/// assert_eq!(spec.expected_response(), Some(ResponseContract::new(Presence::Present)));
	/// ```
	pub fn expected_response(mut self, presence: Option<Presence>) -> Self {
		self.response = presence.map(ResponseContract::new);
		self
	}

	pub fn tag_filter(mut self, tags: Vec<&'static str>) -> Self {
		self.tag_filter = Some(TagSet::from(tags));
		self
	}

	pub fn assertion(
		mut self,
		label: Urn<'static>,
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

		self.assertions.push((label, TagSet::from(tags), cardinality, None));
		Ok(self)
	}

	pub fn assertion_with_value(
		mut self,
		label: Urn<'static>,
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

		self.assertions.push((label, TagSet::from(tags), cardinality, expected_value));
		Ok(self)
	}

	pub fn ordering(mut self, labels: impl AsRef<[Urn<'static>]>) -> Result<Self, SpecBuildError> {
		let labels = labels.as_ref();
		for lbl in labels {
			if !self.assertions.iter().any(|(l, _, _, _)| l == lbl) {
				return Err(SpecBuildError::UnknownOrderingLabel(lbl.clone()));
			}

			self.ordering.extend([lbl.clone()]);
		}

		Ok(self)
	}

	#[cfg(feature = "instrument")]
	pub fn required_events(mut self, kinds: impl AsRef<[crate::urn::Urn<'static>]>) -> Self {
		let kinds = kinds.as_ref();
		use std::collections::HashSet;
		let mut seen = HashSet::new();
		for k in kinds {
			if seen.insert(k.clone()) {
				self.required_events.push(k.clone());
			}
		}

		self
	}

	/// Adds a count that the trace must meet for instrumentation event `kind`.
	///
	/// Two counts on one kind must both hold, so a spec can bound a count
	/// from each side.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::instrumentation::events;
	/// use tightbeam::testing::macros::AssertSpecBuilder;
	/// use tightbeam::testing::specs::TBSpec;
	/// use tightbeam::trace::ExecutionMode;
	/// use tightbeam::{absent, exactly};
	///
	/// let spec = AssertSpecBuilder::new("AcceptsOnce", ExecutionMode::Accept)
	///     .event_count(events::GATE_ACCEPT, exactly!(1))
	///     .event_count(events::GATE_REJECT, absent!())
	///     .build();
	///
	/// assert_eq!(spec.required_event_counts().len(), 2);
	/// ```
	#[cfg(feature = "instrument")]
	pub fn event_count(mut self, kind: Urn<'static>, cardinality: Cardinality) -> Self {
		self.event_counts.push(EventCountContract::new(kind, cardinality));
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

	/// The contract of each assertion that this builder holds.
	///
	/// A counted assertion carries every tag of the spec-wide tag filter and of
	/// its own `tags:` list.
	fn contracts(&self) -> Box<[AssertionContract]> {
		let spec_wide = self.tag_filter.as_ref().map(TagSet::as_slice).unwrap_or_default();
		self.assertions
			.iter()
			.map(|(label, tags, cardinality, value)| {
				let label = AssertionLabel::Custom(label.into_label());
				let contract = AssertionContract::new(label, *cardinality);
				let contract = match value {
					Some(value) => contract.with_value(value.clone()),
					None => contract,
				};

				let filter: Vec<&'static str> = spec_wide.iter().chain(tags.as_slice()).copied().collect();
				if filter.is_empty() {
					return contract;
				}

				contract.with_tag_filter(filter)
			})
			.collect()
	}

	/// The hash that [`BuiltAssertSpec::spec_hash`] returns and documents.
	fn spec_hash(&self) -> [u8; 32] {
		let mut digest = SpecDigest::default();
		// The domain tag, then the version triple.
		digest.bytes(b"TBSP");
		digest.bytes(self.version_major.to_be_bytes());
		digest.bytes(self.version_minor.to_be_bytes());
		digest.bytes(self.version_patch.to_be_bytes());
		digest.text(self.id);

		let mode_code = match self.execution_mode {
			ExecutionMode::Accept => 0u8,
			ExecutionMode::Reject => 1u8,
			ExecutionMode::Error => 2u8,
		};

		digest.bytes([mode_code]);

		match self.gate_decision {
			Some(g) => {
				digest.bytes([1u8]);
				digest.bytes([g as u8]);
			}
			None => digest.bytes([0u8]),
		}

		match self.response {
			Some(response) => {
				digest.bytes([1u8]);
				digest.bytes([response.presence as u8]);
			}
			None => digest.bytes([0u8]),
		}
		// A presence byte, then the tag filter when the spec has one.
		if let Some(tags) = &self.tag_filter {
			digest.bytes([1u8]);
			digest.tags(tags);
		} else {
			digest.bytes([0u8]);
		}

		// The hash sorts the assertions by label, so two specs that differ only
		// in insertion order hash the same.
		let mut norm: Vec<_> = Vec::with_capacity(self.assertions.len());
		for (label, tags, cardinality, value) in &self.assertions {
			norm.push((label.to_string(), tags, *cardinality, value));
		}

		norm.sort_by(|a, b| a.0.cmp(&b.0)); // The sort key is the label alone.
		digest.count(norm.len());

		for (lbl, tags, cardinality, value) in norm {
			digest.text(lbl);
			cardinality.hash_into(&mut digest.0);
			digest.tags(tags);

			// A presence byte, then the `equals!` value when the assertion has
			// one.
			match value {
				Some(value) => {
					digest.bytes([1u8]);
					value.hash_into(&mut digest);
				}
				None => digest.bytes([0u8]),
			}
		}

		// The assertion order hashes its length and then its labels in their
		// own order, because the order is the contract.
		let ordering = self.ordering.labels();
		digest.count(ordering.len());

		for label in ordering {
			digest.text(label);
		}
		#[cfg(feature = "instrument")]
		{
			// The required events hash in their own order, because the trace
			// must record them in that order.
			digest.count(self.required_events.len());

			for urn in &self.required_events {
				digest.text(urn.to_string());
			}

			// The event counts hash in URN order, then in bound order, so two
			// specs that differ only in insertion order hash the same.
			let mut sorted_counts: Vec<(String, Cardinality)> = self
				.event_counts
				.iter()
				.map(|contract| (contract.kind.to_string(), contract.cardinality))
				.collect();
			sorted_counts.sort_by(|a, b| (&a.0, a.1.min, a.1.max).cmp(&(&b.0, b.1.min, b.1.max)));
			digest.count(sorted_counts.len());

			for (urn_str, cardinality) in sorted_counts {
				digest.text(urn_str);
				cardinality.hash_into(&mut digest.0);
			}
		}
		#[cfg(feature = "testing-timing")]
		{
			if let Some(schedule) = &self.schedulability {
				digest.bytes([1u8]); // The spec has a schedulability assertion.
				digest.bytes([schedule.task_set.scheduler as u8]);
				digest.bytes([schedule.must_be_schedulable as u8]);
				digest.count(schedule.task_set.tasks.len());

				// The tasks hash in ID order, so the hash is deterministic.
				let mut tasks: Vec<_> = schedule.task_set.tasks.iter().collect();
				tasks.sort_by(|a, b| a.id.cmp(&b.id));

				for task in tasks {
					digest.text(&task.id);
					digest.bytes(task.period.as_nanos().to_be_bytes());
					digest.bytes(task.deadline.as_nanos().to_be_bytes());
					digest.bytes(task.wcet.as_nanos().to_be_bytes());
				}
			} else {
				digest.bytes([0u8]); // The spec has no schedulability assertion.
			}
		}
		digest.finish()
	}
}

/// The SHA3-256 state of a spec hash, which frames each field it takes.
#[derive(Default)]
struct SpecDigest(Sha3_256);

impl SpecDigest {
	/// Takes `bytes` as they are, for a field of a fixed size.
	fn bytes(&mut self, bytes: impl AsRef<[u8]>) {
		self.0.update(bytes);
	}

	/// Takes `len` as a big-endian `u32`, which saturates past `u32::MAX`.
	fn count(&mut self, len: usize) {
		let framed = u32::try_from(len).unwrap_or(u32::MAX);
		self.0.update(framed.to_be_bytes());
	}

	/// Takes `text` after its byte length, so two texts that join to one byte
	/// string hash apart.
	fn text(&mut self, text: impl AsRef<str>) {
		let text = text.as_ref();
		self.count(text.len());
		self.0.update(text.as_bytes());
	}

	/// Takes the count of `tags`, and then each tag in sorted order.
	fn tags(&mut self, tags: &TagSet) {
		let tags = tags.as_slice();
		self.count(tags.len());

		for tag in tags {
			self.text(tag);
		}
	}

	/// The hash of every field taken so far.
	fn finish(self) -> [u8; 32] {
		let out = self.0.finalize();
		let mut arr = [0u8; 32];
		arr.copy_from_slice(&out);
		arr
	}
}

impl AssertionValue {
	/// Feeds this value into `digest`: a byte that names the variant, then its
	/// framed payload. Two specs that differ in an `equals!` value hash apart.
	fn hash_into(&self, digest: &mut SpecDigest) {
		match self {
			Self::String(text) => {
				digest.bytes([0u8]);
				digest.text(text);
			}
			Self::Bool(flag) => digest.bytes([1u8, u8::from(*flag)]),
			Self::U8(number) => digest.bytes([2u8, *number]),
			Self::U32(number) => {
				digest.bytes([3u8]);
				digest.bytes(number.to_be_bytes());
			}
			Self::U64(number) => {
				digest.bytes([4u8]);
				digest.bytes(number.to_be_bytes());
			}
			Self::I32(number) => {
				digest.bytes([5u8]);
				digest.bytes(number.to_be_bytes());
			}
			Self::I64(number) => {
				digest.bytes([6u8]);
				digest.bytes(number.to_be_bytes());
			}
			Self::F64(number) => {
				digest.bytes([7u8]);
				digest.bytes(number.to_bits().to_be_bytes());
			}
			Self::MessagePriority(priority) => digest.bytes([8u8, *priority as u8]),
			Self::Version(version) => digest.bytes([9u8, *version as u8]),
			Self::Some(inner) => {
				digest.bytes([10u8]);
				inner.hash_into(digest);
			}
			Self::IsNone => digest.bytes([11u8]),
			Self::IsSome => digest.bytes([12u8]),
			Self::RatioActual(numerator, denominator) => {
				digest.bytes([13u8]);
				digest.bytes(numerator.to_be_bytes());
				digest.bytes(denominator.to_be_bytes());
			}
			Self::RatioLimit(numerator, denominator) => {
				digest.bytes([14u8]);
				digest.bytes(numerator.to_be_bytes());
				digest.bytes(denominator.to_be_bytes());
			}
			#[cfg(feature = "policy")]
			Self::TransitStatus(status) => digest.bytes([15u8, *status as u8]),
		}
	}
}

/// A schedulability assertion on a task set.
#[cfg(feature = "testing-timing")]
#[derive(Debug, Clone)]
pub struct SchedulabilityAssertion {
	/// The task set that the analysis checks.
	pub task_set: TaskSet,
	/// Whether the task set must pass (`true`) or fail (`false`) the analysis.
	pub must_be_schedulable: bool,
}

/// A spec that [`AssertSpecBuilder::build`] produced, with its contracts and
/// its hash.
#[derive(Debug, Clone)]
pub struct BuiltAssertSpec {
	inner: AssertSpecBuilder,
	contracts: Box<[AssertionContract]>,
	spec_hash: [u8; 32],
}

impl BuiltAssertSpec {
	fn from_builder(builder: AssertSpecBuilder) -> Self {
		let contracts = builder.contracts();
		let spec_hash = builder.spec_hash();

		Self { inner: builder, contracts, spec_hash }
	}

	/// The SHA3-256 hash of the contract of this spec.
	///
	/// Specs that differ in their id, version, or a constraint hash apart. A
	/// set, such as a tag list, hashes the same in any order.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::exactly;
	/// use tightbeam::testing::macros::AssertSpecBuilder;
	/// use tightbeam::trace::ExecutionMode;
	/// use tightbeam::urn::Urn;
	///
	/// const OPEN: Urn<'static> = tightbeam::urn!("doc", "event:hash/open");
	///
	/// let builder = AssertSpecBuilder::new("Tagged", ExecutionMode::Accept);
	/// let hot_first = builder.clone().assertion(OPEN, vec!["hot", "fresh"], exactly!(1))?.build();
	/// let fresh_first = builder.assertion(OPEN, vec!["fresh", "hot"], exactly!(1))?.build();
	///
	/// // A list of tags is a set, so two orders of one list hash the same.
	/// assert_eq!(hot_first.spec_hash(), fresh_first.spec_hash());
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn spec_hash(&self) -> [u8; 32] {
		self.spec_hash
	}
	pub fn version(&self) -> (u16, u16, u16) {
		(self.inner.version_major, self.inner.version_minor, self.inner.version_patch)
	}

	/// The description of the spec, from the `annotations` block of
	/// `tb_assert_spec!` or from [`AssertSpecBuilder::description`].
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::testing::macros::AssertSpecBuilder;
	/// use tightbeam::trace::ExecutionMode;
	///
	/// let spec = AssertSpecBuilder::new("Described", ExecutionMode::Accept).description("one ping").build();
	///
	/// assert_eq!(spec.description(), Some("one ping"));
	/// ```
	pub fn description(&self) -> Option<&'static str> {
		self.inner.description
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
	fn required_assertion_order(&self) -> &AssertionOrderContract {
		&self.inner.ordering
	}
	fn expected_gate_decision(&self) -> Option<TransitStatus> {
		self.inner.gate_decision
	}
	fn expected_response(&self) -> Option<ResponseContract> {
		self.inner.response
	}
	#[cfg(feature = "testing-timing")]
	fn constrains_schedule(&self) -> bool {
		self.inner.schedulability.is_some()
	}
	#[cfg(feature = "instrument")]
	fn required_events(&self) -> &[crate::urn::Urn<'static>] {
		&self.inner.required_events
	}
	#[cfg(feature = "instrument")]
	fn required_event_counts(&self) -> &[EventCountContract] {
		&self.inner.event_counts
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
	/// Checks the task set of `assertion` against its expected outcome.
	///
	/// # Errors
	///
	/// - [`SpecViolation::SchedulabilityViolation`] -- the outcome differs from `must_be_schedulable`.
	/// - [`SpecViolation::SchedulabilityError`] -- the analysis fails.
	fn check_schedulability(assertion: &SchedulabilityAssertion) -> Result<(), SpecViolation> {
		let result = match assertion.task_set.scheduler {
			SchedulerType::RateMonotonic => assertion.task_set.is_rm_schedulable(),
			SchedulerType::EarliestDeadlineFirst => assertion.task_set.is_edf_schedulable(),
		};

		match result {
			Ok(schedule_result) => {
				let is_schedulable = schedule_result.is_schedulable;
				if assertion.must_be_schedulable && !is_schedulable {
					// The task set must be schedulable and fails the analysis.
					Err(SpecViolation::SchedulabilityViolation(schedule_result))
				} else if !assertion.must_be_schedulable && is_schedulable {
					// The task set must be unschedulable and passes the
					// analysis, so a synthetic violation reports it.
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

// The cardinality macros and the macros behind `tb_assert_spec!`.

// The cardinality macros call the matching `Cardinality` constructor.
#[macro_export]
macro_rules! exactly {
	($n:expr) => {
		$crate::testing::macros::Cardinality::exactly($n)
	};
}
#[macro_export]
macro_rules! at_least {
	(0) => {
		::core::compile_error!("a lower bound of zero rejects nothing: leave the label out of the spec")
	};
	($n:expr) => {
		$crate::testing::macros::Cardinality::at_least(
			const {
				match ::core::num::NonZeroU32::new($n) {
					Some(bound) => bound,
					None => ::core::panic!("this lower bound evaluates to zero, which rejects nothing: leave the label out of the spec"),
				}
			},
		)
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

// The hidden macros below carry the expansion of `tb_assert_spec!`.

// Builds every version of a spec once, in a `OnceLock`, and returns the slice.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all {
	(
		$base:ident,
		$desc_opt:expr,
		$(
			$maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
			assertions: [ $( $assertion:tt ),* ],
			$(
				events: [ $($events_tt:tt)* ],
			)?
			$(, tag_filter: [ $( $tag:expr ),* $(,)? ])?
			$(, event_counts: [ $($counts_tt:tt)* ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		)+
	) => {{
		static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
		CELL.get_or_init(|| {
			let mut v = Vec::new();
			$crate::__tb_assert_spec_build_all_impl!(
				v, $base, $desc_opt,
				$(
					$maj, $min, $patch, $mode, $gate, $response,
					assertions: [ $( $assertion ),* ],
					$(
						events: [ $($events_tt)* ],
					)?
					$(, tag_filter: [ $( $tag ),* ])?
					$(, event_counts: [ $($counts_tt)* ])?
					$(, schedulability: { $($schedule_content)* })?
				)+
			);
			v
		}).as_slice()
	}};
}

// Each version block expands in its own call, so the nested repetitions of a
// block stay apart from the repetition over the blocks.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all_impl {
	(
		$vec:ident, $base:ident, $desc_opt:expr,
		$(
			$maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
			assertions: [ $( $assertion:tt ),* ],
			$(
				events: [ $($events_tt:tt)* ],
			)?
			$(, tag_filter: [ $( $tag:expr ),* $(,)? ])?
			$(, event_counts: [ $($counts_tt:tt)* ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		)+
	) => {
		$(
			$crate::__tb_assert_spec_build_all_impl_with_events!(
				$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
				assertions: [ $( $assertion ),* ],
				$(
					events: [ $($events_tt)* ],
				)?
				$(, tag_filter: [ $( $tag ),* ])?
				$(, event_counts: [ $($counts_tt)* ])?
				$(, schedulability: { $($schedule_content)* })?
			);
		)+
	};
}

// Passes one version block to the `@expand_events` arm, so the repetition of
// its `events` list stays apart from the outer repetitions.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build_all_impl_with_events {
	(
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
		assertions: [ $( $assertion:tt ),* ],
		$(
			events: [ $($events_tt:tt)* ],
		)?
		$(, tag_filter: [ $( $tag:expr ),* ])?
		$(, event_counts: [ $($counts_tt:tt)* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// The `@expand_events` arm reads the event list. The `$desc_opt`
		// parameter carries the description to `__tb_assert_spec_init_builder`.
		$crate::__tb_assert_spec_build! {
			@expand_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
			assertions: [ $( $assertion ),* ],
			$(
				events_tt: [ $($events_tt)* ],
			)?
			$( tag_filter: [ $( $tag ),* ])?
			$(, event_counts: [ $($counts_tt)* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
}

// Builds the spec of one version block, with its events and schedulability.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_build {
	// The two `@expand_events` arms take a block with events and one without.
	// This arm takes the block with events.
	(@expand_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $($events_tt:tt)* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, event_counts: [ $($counts_tt:tt)* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {
		$crate::__tb_assert_spec_build! {
			@build_with_events_expanded
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
			assertions: [ $( $assertion ),* ],
			events_tt: [ $($events_tt)* ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, event_counts: [ $($counts_tt)* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	};
	// This arm takes the block without events.
	(@expand_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
		assertions: [ $( $assertion:tt ),* ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, event_counts: [ $($counts_tt:tt)* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {
		$crate::__tb_assert_spec_build! {
			@build_with_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
			assertions: [ $( $assertion ),* ],
			events: [ ],
			$( tag_filter: [ $( $tag ),* ])?
			$(, event_counts: [ $($counts_tt)* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	};
	(@build_with_events_expanded
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
		assertions: [ $( $assertion:tt ),* ],
		events_tt: [ $( $ev:expr ),* $(,)? ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, event_counts: [ $($counts_tt:tt)* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		$crate::__tb_assert_spec_build! {
			@build_with_events
			$vec, $base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
			assertions: [ $( $assertion ),* ],
			events: [ $( $ev ),* ],
			$( tag_filter: [ $( $tag ),* $(,)? ])?
			$(, event_counts: [ $($counts_tt)* ])?
			$(, schedulability: { $($schedule_content)* })?
		}
	}};
	(@build_with_events
		$vec:ident, $base:ident, $desc_opt:expr, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:expr, $response:expr,
		assertions: [ $( $assertion:tt ),* ],
		events: [ $( $ev:expr ),* $(,)? ],
		$( tag_filter: [ $( $tag:expr ),* $(,)? ])?
		$(, event_counts: [ $($counts_tt:tt)* ])?
		$(, schedulability: { $($schedule_content:tt)* })?
	) => {{
		// A block with no assertion, event, count, or schedulability keeps
		// the builder as it starts.
		#[allow(unused_mut)]
		let mut builder = $crate::__tb_assert_spec_init_builder!(
			$base, $desc_opt, $maj, $min, $patch, $mode, $gate, $response,
			$(tag_filter: [ $( $tag ),* ])?
		);
		$(
			builder = $crate::__tb_assert_spec_add_assertion!(builder, $assertion);
		)*
		// A build without `instrument` stops at a required event, so a spec
		// keeps every event it orders. A spec with no events builds without it.
		$(
			$crate::__tb_select_instrument! {
				{
					builder = builder.required_events(::core::slice::from_ref(&$ev));
				}
				{
					::core::compile_error!("the `events:` list of `tb_assert_spec!` needs the `instrument` feature");
				}
			}
		)*
		$(
			$crate::__tb_assert_spec_add_event_counts!(builder, $($counts_tt)*);
		)?
		$(
			$crate::__tb_assert_spec_parse_schedulability!(builder, $($schedule_content)*);
		)?
		$vec.push(builder.build());
	}};
}

// Adds each event count of an `event_counts:` list to the spec under
// construction. A build without `instrument` stops at the list, so a spec
// keeps every count it states.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_add_event_counts {
	($builder:ident, $( ( $kind:expr, $card:expr ) ),* $(,)?) => {
		$crate::__tb_select_instrument! {
			{
				$(
					$builder = $builder.event_count($kind, $card);
				)*
			}
			{
				::core::compile_error!("the `event_counts:` list of `tb_assert_spec!` needs the `instrument` feature");
			}
		}
	};
}

// Attaches a schedulability assertion to the spec under construction.
//
// Every configuration defines the name and the feature selects the body, so an
// expansion needs no guard, and name resolution holds in every feature column.
// A build without `testing-timing` stops at the block and drops no assertion.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_parse_schedulability {
	(
		$builder:ident,
		task_set: $task_set:expr,
		scheduler: $scheduler:ident,
		must_be_schedulable: $must_be:expr,
	) => {
		$crate::__tb_select_testing_timing! {
			{
				{
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
				}
			}
			{
				::core::compile_error!("the `schedulability:` block of `tb_assert_spec!` needs the `testing-timing` feature");
			}
		}
	};
}

// Adds one assertion with its optional value and tags. A label is a URN
// expression, and the builder signature refuses a raw string or an ident key.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_assert_spec_add_assertion {
	// An `equals!` value with tags.
	($builder:expr, ($label:expr, $card:expr, equals!($value:expr), tags: [ $($tag:expr),* $(,)? ])) => {
		$builder
			.assertion_with_value($label, vec![ $($tag),* ], $card, Some($crate::testing::assertions::AssertionValue::from($value)))
			.expect("duplicate label or invalid range")
	};
	// An `equals!` value without tags.
	($builder:expr, ($label:expr, $card:expr, equals!($value:expr))) => {
		$builder
			.assertion_with_value($label, vec![], $card, Some($crate::testing::assertions::AssertionValue::from($value)))
			.expect("duplicate label or invalid range")
	};
	// Tags without a value.
	($builder:expr, ($label:expr, $card:expr, tags: [ $($tag:expr),* $(,)? ])) => {
		$builder
			.assertion($label, vec![ $($tag),* ], $card)
			.expect("duplicate label or invalid range")
	};
	// A label and a cardinality alone, as a two-element tuple.
	($builder:expr, ($label:expr, $card:expr)) => {
		$builder
			.assertion($label, vec![], $card)
			.expect("duplicate label or invalid range")
	};
}

/// Defines an assertion spec, the contract of Layer 1, with a declarative
/// syntax.
///
/// It takes version blocks alone, each with a full semantic version
/// `V(major, minor, patch)`, and emits a unit struct with one
/// [`BuiltAssertSpec`] per block:
///
/// - `latest()` returns the highest version.
/// - `get(major, minor, patch)` returns one version.
/// - `all()` returns every version.
///
/// A version block states these keys:
///
/// - `mode:` is the execution mode, `Accept`, `Reject`, or `Error`.
/// - The optional `gate:` is the gate decision, and the optional `response:` is `Present` or `Absent`.
/// - The optional `tag_filter:` names the tags that every assertion contract requires.
/// - `assertions:` holds each label with its cardinality, an optional `equals!` value, and optional `tags:`.
/// - A counted assertion carries every tag of `tag_filter:` and of the `tags:` of its label.
/// - The optional `events:` names the events in order, and `event_counts:` bounds their counts.
/// - The optional `schedulability:` block states a task set and its expected outcome.
///
/// # Panics
///
/// Testing suite functions MUST panic on error. The first call of `all()`,
/// `get()`, or `latest()` builds every version, and panics when a version
/// block names one label twice or a `between!` bound whose maximum is below
/// its minimum. Version blocks that do not ascend fail to compile.
///
/// # Examples
///
/// ```
/// use tightbeam::{exactly, tb_assert_spec};
///
/// const STEP: tightbeam::urn::Urn<'static> = tightbeam::urn!("doc", "event:spec/step");
///
/// tb_assert_spec! {
///     pub Steps,
///     V(1,0,0): {
///         mode: Accept,
///         assertions: [ (STEP, exactly!(1)) ]
///     },
///     V(1,1,0): {
///         mode: Accept,
///         assertions: [ (STEP, exactly!(2)) ]
///     }
/// }
///
/// assert_eq!(Steps::latest().version(), (1, 1, 0));
/// assert_eq!(Steps::all().len(), 2);
/// ```
///
/// [`BuiltAssertSpec`]: crate::testing::macros::BuiltAssertSpec
#[macro_export]
macro_rules! tb_assert_spec {
	(
		$(#[$meta:meta])*
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : {
			mode: $mode:ident,
			$( gate: $gate:ident, )?
			$( response: $response:ident, )?
			$( tag_filter: [ $( $tag:expr ),* $(,)? ], )?
			assertions: [ $( $assertion:tt ),* $(,)? ]
			$(, events: [ $($events_tt:tt)* ])?
			$(, event_counts: [ $($counts_tt:tt)* ])?
			$(, schedulability: { $($schedule_content:tt)* })?
		} ),+ $(,)?
		$(, annotations { description: $desc:expr })?
	) => {
		$(#[$meta])*
		$vis struct $base;

		// Version blocks must strictly ascend so `latest()` selects the
		// last block in source order.
		const _: () = assert!(
			$crate::testing::macros::versions_strictly_ascending(
				&[ $( ($maj as u16, $min as u16, $patch as u16) ),+ ]
			),
			"tb_assert_spec! version blocks must be in strictly ascending semver order"
		);

		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				let desc_opt: Option<&'static str> = None::<&'static str> $(.or(Some($desc)))?;
				$crate::__tb_assert_spec_build_all!(
					$base,
					desc_opt,
					$(
						$maj, $min, $patch, $mode,
						// One place decides the expected gate and response. A
						// block that omits `gate:` or `response:` requires
						// neither, and the macros below only pass them on.
						::core::option::Option::None $( .or(Some($crate::policy::TransitStatus::$gate)) )?,
						::core::option::Option::None $( .or(Some($crate::trace::Presence::$response)) )?,
						assertions: [ $( $assertion ),* ],
						$(
							events: [ $($events_tt)* ],
						)?
						$(, tag_filter: [ $( $tag ),* ])?
						$(, event_counts: [ $($counts_tt)* ])?
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

// Starts the builder of one version block: its name, mode, version, gate,
// response, tag filter, and description.
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
		$gate:expr,
		$response:expr,
		$(tag_filter: [ $($tag:expr),* $(,)? ])?
	) => {{
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(
			stringify!($base),
			$crate::trace::ExecutionMode::$mode,
		);
		builder = builder.version(maj, min, patch).expected_gate($gate).expected_response($response);
		$(
			builder = builder.tag_filter(vec![ $( $tag ),* ]);
		)?
		// The description applies to every version block.
		if let Some(desc) = $desc_opt {
			builder = builder.description(desc);
		}
		builder
	}};
}

#[cfg(test)]
mod tests {
	use std::borrow::Cow;

	use super::*;
	use crate::trace::TraceCollector;

	const OLDER_KEY: Urn<'static> = crate::urn!("test", "event:spec/older-key");
	const NEWER_KEY: Urn<'static> = crate::urn!("test", "event:spec/newer-key");
	#[cfg(feature = "instrument")]
	const ACCEPTED: Urn<'static> = crate::urn!("test", "event:spec/accepted");
	#[cfg(feature = "instrument")]
	const REJECTED: Urn<'static> = crate::urn!("test", "event:spec/rejected");

	crate::tb_assert_spec! {
		pub VersionedKeySpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(OLDER_KEY, exactly!(1))
			]
		},
		V(2,0,0): {
			mode: Accept,
			assertions: [
				(NEWER_KEY, exactly!(1))
			]
		}
	}

	#[test]
	fn latest_selects_highest_version_block() {
		let latest = VersionedKeySpec::latest();
		let generated = AssertionLabel::Custom(Cow::Owned(NEWER_KEY.to_string()));
		assert_eq!(latest.version(), (2, 0, 0));
		assert!(latest
			.required_assertions()
			.iter()
			.any(|contract| contract.label.matches(&generated)));
	}

	#[test]
	fn version_ascent_check_accepts_and_rejects() {
		assert!(versions_strictly_ascending(&[(1, 0, 0), (1, 1, 0), (2, 0, 0)]));
		assert!(!versions_strictly_ascending(&[(2, 0, 0), (1, 0, 0)]));
		assert!(!versions_strictly_ascending(&[(1, 0, 0), (1, 0, 0)]));
	}

	#[cfg(target_pointer_width = "64")]
	#[test]
	fn a_count_past_u32_max_exceeds_every_maximum() -> Result<(), Box<dyn core::error::Error>> {
		let beyond = usize::try_from(u64::from(u32::MAX) + 1)?;
		assert!(!Cardinality::at_most(u32::MAX).is_satisfied_by(beyond));
		Ok(())
	}

	#[test]
	fn specs_that_differ_in_their_response_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let requires = AssertSpecBuilder::new("Spec", ExecutionMode::Accept).expected_response(Some(Presence::Present));
		let forbids = AssertSpecBuilder::new("Spec", ExecutionMode::Accept).expected_response(Some(Presence::Absent));
		assert_ne!(requires.build().spec_hash(), forbids.build().spec_hash());
		Ok(())
	}

	#[test]
	fn specs_that_differ_in_their_assertion_order_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let builder = builder.assertion(OLDER_KEY, Vec::new(), exactly!(1))?;
		let builder = builder.assertion(NEWER_KEY, Vec::new(), exactly!(1))?;
		let forward = builder.clone().ordering([OLDER_KEY, NEWER_KEY])?;
		let reverse = builder.ordering([NEWER_KEY, OLDER_KEY])?;
		assert_ne!(forward.build().spec_hash(), reverse.build().spec_hash());
		Ok(())
	}

	#[test]
	fn specs_that_differ_in_an_equals_value_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let (one, two) = (builder.clone(), builder);
		let one = one.assertion_with_value(OLDER_KEY, Vec::new(), exactly!(1), crate::equals!(1u8))?;
		let two = two.assertion_with_value(OLDER_KEY, Vec::new(), exactly!(1), crate::equals!(2u8))?;
		assert_ne!(one.build().spec_hash(), two.build().spec_hash());
		Ok(())
	}

	#[test]
	fn specs_that_differ_in_the_tags_of_an_assertion_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let hot = builder.clone().assertion(OLDER_KEY, vec!["hot"], exactly!(1))?;
		let cold = builder.assertion(OLDER_KEY, vec!["cold"], exactly!(1))?;
		assert_ne!(hot.build().spec_hash(), cold.build().spec_hash());
		Ok(())
	}

	#[test]
	fn an_assertion_counts_only_the_records_that_carry_its_own_tags() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let spec = builder.assertion(OLDER_KEY, vec!["hot"], exactly!(1))?.build();

		let collector = TraceCollector::new();
		collector.event_with(OLDER_KEY, &["cold"], ())?.emit();
		let trace = ConsumedTrace::drained_from(&collector);

		let verdict = spec.verify(&trace, &Ok(()));
		assert!(matches!(verdict, Err(SpecViolation::AssertionViolation(_))));
		Ok(())
	}

	#[test]
	fn a_spec_states_its_description() -> Result<(), Box<dyn core::error::Error>> {
		let spec = AssertSpecBuilder::new("Described", ExecutionMode::Accept)
			.description("one ping")
			.build();
		assert_eq!(spec.description(), Some("one ping"));
		Ok(())
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn specs_that_differ_in_an_event_count_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let once = AssertSpecBuilder::new("Spec", ExecutionMode::Accept).event_count(ACCEPTED, exactly!(1));
		let twice = AssertSpecBuilder::new("Spec", ExecutionMode::Accept).event_count(ACCEPTED, exactly!(2));
		assert_ne!(once.build().spec_hash(), twice.build().spec_hash());
		Ok(())
	}

	/// The shorter label of the joined-order specs.
	const JOINED_SHORT: Urn<'static> = crate::urn!("aa", "b");
	/// The longer label, whose rendering is the rendering of `JOINED_SHORT`
	/// twice in a row.
	const JOINED_LONG: Urn<'static> = crate::urn!("aa", "burn:aa:b");

	/// Two orders whose labels join to one byte string hash apart, because
	/// each label takes its length first.
	#[test]
	fn orders_whose_labels_join_to_one_string_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let builder = builder.assertion(JOINED_SHORT, Vec::new(), exactly!(1))?;
		let builder = builder.assertion(JOINED_LONG, Vec::new(), exactly!(1))?;
		let forward = builder.clone().ordering([JOINED_SHORT, JOINED_LONG])?;
		let reverse = builder.ordering([JOINED_LONG, JOINED_SHORT])?;
		assert_ne!(forward.build().spec_hash(), reverse.build().spec_hash());
		Ok(())
	}

	/// The trace must record the required events in order, so two orders of
	/// one set hash apart.
	#[cfg(feature = "instrument")]
	#[test]
	fn specs_that_differ_in_the_order_of_their_required_events_hash_apart() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let forward = builder.clone().required_events([ACCEPTED, REJECTED]);
		let reverse = builder.required_events([REJECTED, ACCEPTED]);
		assert_ne!(forward.build().spec_hash(), reverse.build().spec_hash());
		Ok(())
	}

	#[cfg(feature = "instrument")]
	#[test]
	fn event_counts_in_another_order_hash_the_same() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let forward = builder
			.clone()
			.event_count(ACCEPTED, exactly!(1))
			.event_count(REJECTED, absent!());

		let reverse = builder.event_count(REJECTED, absent!()).event_count(ACCEPTED, exactly!(1));
		assert_eq!(forward.build().spec_hash(), reverse.build().spec_hash());
		Ok(())
	}

	#[test]
	fn tags_in_another_order_hash_the_same() -> Result<(), Box<dyn core::error::Error>> {
		let builder = AssertSpecBuilder::new("Spec", ExecutionMode::Accept);
		let forward = builder.clone().tag_filter(vec!["hot", "fresh"]);
		let forward = forward.assertion(OLDER_KEY, vec!["south", "north"], exactly!(1))?;
		let reverse = builder.tag_filter(vec!["fresh", "hot"]);
		let reverse = reverse.assertion(OLDER_KEY, vec!["north", "south"], exactly!(1))?;
		assert_eq!(forward.build().spec_hash(), reverse.build().spec_hash());
		Ok(())
	}
}

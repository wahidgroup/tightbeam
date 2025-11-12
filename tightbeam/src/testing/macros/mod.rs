//! Clean declarative testing macro & builder layer (legacy forms removed)
//!
//! This rewrite provides ONLY the multi-version block syntax:
//! tb_assert_spec! {
//! 	pub MySpec,
//! 	V 1.0.0: { mode: Accept, gate: Accepted, assertions: [ (HandlerStart, "A", exactly!(1)) ] },
//! 	V 1.1.0: { mode: Accept, gate: Accepted, assertions: [ (HandlerStart, "A", exactly!(1)), (Response, "Responded", exactly!(1)) ] },
//! }
//!
//! Response semantics are governed solely by Response-phase assertion cardinalities.
//! No `require_response` flag remains.
//!
//! Hashing domain: b"TBSP" + version triple + spec id + mode code + gate decision presence/value + normalized assertions + optional events.
//! Normalization: sort by (label, phase_code).

// ProcessSpec macro (Layer 2 - CSP)
#[cfg(feature = "testing-csp")]
pub mod process_spec;

#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::borrow::Cow;

use crate::crypto::hash::{Digest, Sha3_256};
use crate::policy::TransitStatus;
use crate::testing::assertions::{AssertionContract, AssertionLabel, AssertionPhase};
use crate::testing::specs::{SpecViolation, TBSpec};
use crate::testing::trace::{ConsumedTrace, ExecutionMode};
use crate::Errorizable;

#[cfg(feature = "instrument")]
use crate::instrumentation::TbEventKind;

// Re-exports
pub use crate::testing::trace::TraceCollector;
pub use crate::{absent, at_least, at_most, between, exactly, present};

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
			(m, Some(n)) if m == n => format!("exactly {}", m),
			(m, Some(n)) => format!("between {} and {}", m, n),
			(m, None) if m == 0 => "any".into(),
			(m, None) => format!("at least {}", m),
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
	assertions: Vec<(AssertionPhase, &'static str, Cardinality)>,
	ordering: Vec<&'static str>,
	#[cfg(feature = "instrument")]
	required_events: Vec<TbEventKind>,
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
			ordering: Vec::new(),
			#[cfg(feature = "instrument")]
			required_events: Vec::new(),
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

	pub fn assertion(
		mut self,
		phase: AssertionPhase,
		label: &'static str,
		cardinality: Cardinality,
	) -> Result<Self, SpecBuildError> {
		if self.assertions.iter().any(|(_, l, _)| *l == label) {
			return Err(SpecBuildError::DuplicateLabel(label));
		}
		if let Some(mx) = cardinality.max {
			if mx < cardinality.min {
				return Err(SpecBuildError::InvalidRange(label));
			}
		}
		self.assertions.push((phase, label, cardinality));
		Ok(self)
	}

	pub fn ordering(mut self, labels: &[&'static str]) -> Result<Self, SpecBuildError> {
		for &lbl in labels {
			if !self.assertions.iter().any(|(_, l, _)| *l == lbl) {
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
		let contracts: Vec<AssertionContract> = builder
			.assertions
			.iter()
			.map(|(phase, label, card)| AssertionContract::new(*phase, AssertionLabel::Custom(*label), *card))
			.collect();
		let spec_hash = Self::compute_hash(
			builder.id,
			builder.execution_mode,
			builder.gate_decision,
			builder.version_major,
			builder.version_minor,
			builder.version_patch,
			&contracts,
			#[cfg(feature = "instrument")]
			&builder.required_events,
		);
		Self { inner: builder, contracts: contracts.into_boxed_slice(), spec_hash }
	}

	fn compute_hash(
		id: &'static str,
		mode: ExecutionMode,
		gate: Option<TransitStatus>,
		version_major: u16,
		version_minor: u16,
		version_patch: u16,
		contracts: &[AssertionContract],
		#[cfg(feature = "instrument")] events: &[TbEventKind],
	) -> [u8; 32] {
		let mut h = Sha3_256::new();
		// Domain tag + version triple
		h.update(b"TBSP");
		h.update(&version_major.to_be_bytes());
		h.update(&version_minor.to_be_bytes());
		h.update(&version_patch.to_be_bytes());
		h.update(id.as_bytes());
		let mode_code = match mode {
			ExecutionMode::Accept => 0u8,
			ExecutionMode::Reject => 1u8,
			ExecutionMode::Error => 2u8,
		};
		h.update(&[mode_code]);
		match gate {
			Some(g) => {
				h.update(&[1u8]);
				h.update(&[g as u8]);
			}
			None => h.update(&[0u8]),
		}
		// Normalize assertion order independent of insertion sequence
		let mut norm: Vec<(&'static str, u8, u32, Option<u32>, bool)> = Vec::with_capacity(contracts.len());
		for c in contracts {
			let phase_code = match c.phase {
				AssertionPhase::HandlerStart => 0u8,
				AssertionPhase::HandlerEnd => 1u8,
				AssertionPhase::Gate => 2u8,
				AssertionPhase::Response => 3u8,
			};
			let AssertionLabel::Custom(lbl) = c.label;
			norm.push((
				lbl,
				phase_code,
				c.cardinality.min,
				c.cardinality.max,
				c.cardinality.must_be_present,
			));
		}
		norm.sort_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1))); // label then phase
		for (lbl, phase_code, min, max, must) in norm {
			h.update(lbl.as_bytes());
			h.update(&[phase_code]);
			h.update(&min.to_be_bytes());
			match max {
				Some(m) => {
					h.update(&[1u8]);
					h.update(&m.to_be_bytes());
				}
				None => h.update(&[0u8]),
			}
			h.update(&[must as u8]);
		}
		#[cfg(feature = "instrument")]
		{
			for ev in events {
				h.update(&[*ev as u8]);
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
	($vec:ident, $base:ident, $maj:literal, $min:literal, $patch:literal, $mode:ident, $gate:ident, [ $( ($phase:ident, $label:expr, $card:expr) ),* ], [ $( $ev:ident ),* ]) => {
		let (maj, min, patch) = ($maj as u16, $min as u16, $patch as u16);
		let mut builder = $crate::testing::macros::AssertSpecBuilder::new(stringify!($base), $crate::testing::trace::ExecutionMode::$mode);
		builder = builder.version(maj, min, patch).gate_decision($crate::policy::TransitStatus::$gate);
		$( builder = builder.assertion($crate::testing::assertions::AssertionPhase::$phase, $label, $card).expect("duplicate label or invalid range"); )*
		#[cfg(feature = "instrument")]
		{ $( builder = builder.required_events(&[$crate::instrumentation::TbEventKind::$ev]); )* }
		$vec.push(builder.build());
	};
}

// Multi-version macro ONLY (full semantic version required maj.min.patch)
#[macro_export]
macro_rules! tb_assert_spec {
	(
		$vis:vis $base:ident,
		$( V ( $maj:literal , $min:literal , $patch:literal ) : { mode: $mode:ident, gate: $gate:ident, assertions: [ $( ($phase:ident, $label:expr, $card:expr) ),* $(,)? ] $(, events: [ $( $ev:ident ),* $(,)? ])? } ),+ $(,)?
	) => {
		$vis struct $base;
		impl $base {
			pub fn all() -> &'static [$crate::testing::macros::BuiltAssertSpec] {
				#[cfg(feature = "std")]
				{
					static CELL: std::sync::OnceLock<Vec<$crate::testing::macros::BuiltAssertSpec>> = std::sync::OnceLock::new();
					CELL.get_or_init(|| {
						let mut v = Vec::new();
						$( $crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( ($phase, $label, $card) ),* ], [ $( $ev ),* ]); )+
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
						$( $crate::__tb_assert_spec_build!(v, $base, $maj, $min, $patch, $mode, $gate, [ $( ($phase, $label, $card) ),* ], [ $( $ev ),* ]); )+
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
	// Single spec variant
	(
		single_spec: $spec:ty,
		trace: $trace:expr,
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		let spec = <$spec>::latest();
		let verification_result = $crate::testing::specs::verify_trace(spec, &$trace);
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

	// Multiple specs variant
	(
		multi_specs: $specs:expr,
		trace: $trace:expr,
		$(hooks: {
			$(on_pass: $on_pass:expr,)?
			$(on_fail: $on_fail:expr)?
		},)?
	) => {{
		let mut all_passed = true;
		let mut first_violation = None;
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
		if all_passed {
			Ok(())
		} else {
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
			use crate::tb_scenario;
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
		$(instrumentation: $instr_cfg:expr,)?
		environment Bare {
			exec: $exec_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			let result = tb_scenario!(@execute Bare, single_spec, $spec, $(instrumentation: $instr_cfg,)? $(hooks: $hooks,)? exec: $exec_closure);
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Standalone test with name for Worker environment =====
	(
		name: $test_name:ident,
		spec: $spec:ty,
		$(instrumentation: $instr_cfg:expr,)?
		environment Worker {
			setup: $setup_closure:expr,
			stimulus: $stimulus_closure:expr
		}
		$(, hooks $hooks:tt)?
		$(,)?
	) => {
		#[test]
		fn $test_name() {
			let result = tb_scenario!(@execute Worker, single_spec, $spec, $(instrumentation: $instr_cfg,)? $(hooks: $hooks,)? setup: $setup_closure, stimulus: $stimulus_closure);
			result.expect(concat!("Test failed: ", stringify!($test_name)));
		}
	};

	// ===== Bare environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
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
		tb_scenario!(@execute Bare, single_spec, $spec, $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? exec: $exec_closure)
	};

	// ===== Bare environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
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
		tb_scenario!(@execute Bare, multi_specs, [ $( $spec_expr ),+ ], $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? exec: $exec_closure)
	};

	// ===== Worker environment variant (single spec: Type form) =====
	(
		spec: $spec:ty,
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
		tb_scenario!(@execute Worker, single_spec, $spec, $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? setup: $setup_closure, stimulus: $stimulus_closure)
	};

	// ===== Worker environment variant (multiple specs: [...] form) =====
	(
		specs: [ $( $spec_expr:expr ),+ $(,)? ],
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
		tb_scenario!(@execute Worker, multi_specs, [ $( $spec_expr ),+ ], $(instrumentation: $instr_cfg,)? $(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)? setup: $setup_closure, stimulus: $stimulus_closure)
	};

	// ===== ServiceClient environment - user provides complete server setup =====
	// User receives assertions collector for both server and client
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

	// ===== Execution dispatcher for Bare environment =====
	(@execute Bare, single_spec, $spec:ty, $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? exec: $exec_closure:expr) => {{
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	(@execute Bare, multi_specs, [ $( $spec_expr:expr ),+ ], $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? exec: $exec_closure:expr) => {{
		let specs: Vec<&$crate::testing::macros::BuiltAssertSpec> = vec![
			$( $spec_expr.expect(concat!("Spec version not found: ", stringify!($spec_expr))) ),+
		];

		#[cfg(feature = "instrument")]
		let instr_mode = tb_scenario!(@get_instr_mode $($instr_mode)?);
		#[cfg(feature = "instrument")]
		tb_scenario!(@init_instrumentation instr_mode);

		// Create TraceCollector for explicit passing
		let trace_collector = $crate::testing::macros::TraceCollector::new();
		let trace_exec = trace_collector.clone();

		// Helper function to enable type inference
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
			multi_specs: specs,
			trace: trace,
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== Execution dispatcher for Worker environment =====
	(@execute Worker, single_spec, $spec:ty, $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	(@execute Worker, multi_specs, [ $( $spec_expr:expr ),+ ], $(instrumentation: $instr_mode:expr,)? $(hooks: { $(on_pass: $on_pass:expr,)? $(on_fail: $on_fail:expr)? },)? setup: $setup_closure:expr, stimulus: $stimulus_closure:expr) => {{
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result exec_result, verification_result)
	}};

	// ===== ServiceClient environment - wrappable (returns Result) =====
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			protocol: { $($protocol)? },
			worker_threads: { $($threads)? },
			server: $server_closure,
			client: $client_closure
		)
	};

	// ===== Execution dispatcher for ServiceClient environment =====
	(@execute ServiceClient, single_spec, $spec:ty,
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
				$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
			};

			tb_scenario!(@propagate_result client_result, verification_result)
		});

		exec_result
	}};

	(@execute ServiceClient, multi_specs, [ $( $spec_expr:expr ),+ ],
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== Async ServiceClient execution (multi specs) =====
	(@execute_service_client_async multi_specs, $specs:expr,
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
			$(hooks: { $(on_pass: $on_pass,)? $(on_fail: $on_fail)? },)?
		};

		tb_scenario!(@propagate_result client_result, verification_result)
	}};

	// ===== Helper dispatchers for defaults =====
	(@default_worker_threads) => { 2 };
	(@default_worker_threads $threads:literal) => { $threads };

	(@default_protocol) => { $crate::transport::tcp::r#async::TokioListener };
	(@default_protocol $protocol:path) => { $protocol };

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
		compile_error!("Unrecognized tb_scenario! syntax; expected: name: test_name, spec: Type, environment <Variant> { ... }")
	};
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
	use super::*;
	use crate::testing::assertions::AssertionPhase;
	use crate::testing::create_test_message;
	use crate::testing::macros::TraceCollector;
	use crate::testing::trace::ExecutionMode;
	use crate::transport::tcp::r#async::TokioListener;
	use crate::transport::tcp::TightBeamSocketAddr;
	use crate::transport::MessageEmitter;
	use crate::transport::Protocol;
	use crate::TightBeamError;

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
			.assertion(AssertionPhase::HandlerStart, "L1", Cardinality::exactly(1))?
			.assertion(AssertionPhase::HandlerStart, "L1", Cardinality::exactly(2));
		assert!(matches!(b, Err(SpecBuildError::DuplicateLabel("L1"))));
		Ok(())
	}

	tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "Received", exactly!(1)),
				(Response, "Responded", exactly!(1))
			]
		},
		V(1,1,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "Received", exactly!(1)),
				(Response, "Responded", exactly!(2))
			]
		},
	}

	tb_assert_spec! {
		pub ClientServerSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "Received", exactly!(2)),
				(Response, "Responded", exactly!(2))
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

	#[test]
	fn scenario_bare_with_hooks() {
		use std::sync::atomic::{AtomicBool, Ordering};
		static PASS_CALLED: AtomicBool = AtomicBool::new(false);

		let result = tb_scenario! {
			spec: DemoSpec,
			environment Bare {
				exec: |trace| {
					trace.assert(AssertionPhase::HandlerStart, "Received");
					trace.assert(AssertionPhase::Response, "Responded");
					trace.assert(AssertionPhase::Response, "Responded");
					Ok(())
				}
			},
			hooks {
				on_pass: |_trace| {
					PASS_CALLED.store(true, Ordering::SeqCst);
				},
				on_fail: |_trace, _v| {}
			}
		};
		assert!(result.is_ok());
		assert!(PASS_CALLED.load(Ordering::SeqCst), "on_pass hook should have been called");
	}

	#[test]
	fn scenario_bare_specific_version() {
		let result = tb_scenario! {
			specs: [DemoSpec::get(1, 0, 0)],
			environment Bare {
				exec: |trace| {
					trace.assert(AssertionPhase::HandlerStart, "Received");
					trace.assert(AssertionPhase::Response, "Responded");
					Ok(())
				}
			}
		};
		assert!(result.is_ok());
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
					trace.assert(AssertionPhase::HandlerStart, "Received");
					trace.assert(AssertionPhase::Response, "Responded");
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
			self.trace.assert(AssertionPhase::HandlerStart, "Received");
			self.received_count += 1;
			self.trace.assert(AssertionPhase::Response, "Responded");
			self.trace.assert(AssertionPhase::Response, "Responded");
			Ok(())
		}
	}

	#[test]
	fn scenario_worker_basic() {
		let result: Result<(), crate::TightBeamError> = tb_scenario! {
			spec: DemoSpec,
			environment Worker {
				setup: |trace| TestWorker::new(trace),
				stimulus: |_trace, worker: &mut TestWorker| worker.process()
			}
		};
		assert!(result.is_ok());
	}

	#[test]
	fn scenario_worker_specific_version() {
		let result: Result<(), crate::TightBeamError> = tb_scenario! {
			specs: [DemoSpec::get(1, 0, 0)],
			environment Worker {
				setup: |trace| TestWorker::new(trace),
				stimulus: |trace, worker: &mut TestWorker| {
					trace.assert(AssertionPhase::HandlerStart, "Received");
					worker.received_count += 1;
					trace.assert(AssertionPhase::Response, "Responded");
					Ok(())
				}
			}
		};
		assert!(result.is_ok());
	}

	// ServiceClient tests require async runtime and transport features
	#[cfg(all(feature = "tcp", feature = "tokio"))]
	#[test]
	fn scenario_service_client_basic() {
		let result: Result<(), TightBeamError> = tb_scenario! {
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
							trace.assert(AssertionPhase::HandlerStart, "Received");
							trace.assert(AssertionPhase::Response, "Responded");
							trace.assert(AssertionPhase::Response, "Responded");
							Some(frame)
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
		};

		assert!(result.is_ok());
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
						trace.assert(AssertionPhase::HandlerStart, "Received");
						trace.assert(AssertionPhase::Response, "Responded");
						Some(frame)
					}
				};

				Ok((handle, addr))
			},
			client: |trace: TraceCollector, mut client| async move {
				// Client-side assertion before sending
				trace.assert(AssertionPhase::Response, "Responded");

				let test_message = create_test_message(None);
				let test_frame = crate::compose! {
					V0: id: "test", order: 1u64, message: test_message
					}?;

				let _response = client.emit(test_frame, None).await?;

				// Client-side assertion after receiving
				trace.assert(AssertionPhase::HandlerStart, "Received");

				Ok(())
			}
		},
		hooks {
			on_pass: |trace| {
				HOOK_CALLED.store(true, std::sync::atomic::Ordering::SeqCst);
				// Verify we got all 4 assertions (2 server + 2 client)
				assert_eq!(trace.assertions.len(), 4, "Expected 4 total assertions");

				// Count assertions by phase
				let handler_starts = trace.assertions.iter()
					.filter(|a| matches!(a.phase, AssertionPhase::HandlerStart))
					.count();
				let responses = trace.assertions.iter()
					.filter(|a| matches!(a.phase, AssertionPhase::Response))
					.count();

				assert_eq!(handler_starts, 2, "Expected 2 HandlerStart assertions");
				assert_eq!(responses, 2, "Expected 2 Response assertions");

				// Verify labels
				use crate::testing::assertions::AssertionLabel;
				let received_count = trace.assertions.iter()
					.filter(|a| matches!(&a.label, AssertionLabel::Custom(s) if *s == "Received"))
					.count();
				let responded_count = trace.assertions.iter()
					.filter(|a| matches!(&a.label, AssertionLabel::Custom(s) if *s == "Responded"))
					.count();

				assert_eq!(received_count, 2, "Expected 2 'Received' labels");
				assert_eq!(responded_count, 2, "Expected 2 'Responded' labels");
			},
			on_fail: |_trace, violations| {
				panic!("Test should not fail! Violations: {:?}", violations);
			}
		}
	}
}

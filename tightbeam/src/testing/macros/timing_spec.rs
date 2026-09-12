//! Timing-constraint helper macros for `tb_process_spec!` and `tb_assert_spec!`.
//!
//! Each macro builds one `testing::timing` value from the duration syntax a
//! spec writes inline, so a spec states `wcet!(10ms)` where the builder call
//! would otherwise run to four lines.

/// Helper macro for WCET (Worst-Case Execution Time) timing constraint
/// Usage:
///   wcet!(10ms)  (simple case, backward compatible)
///   wcet!(10ms, percentile: P99)  (with percentile)
///   wcet!(10ms, analyzer: my_analyzer)  (with analyzer)
///   wcet!(10ms, percentile: P99, analyzer: my_analyzer)  (with both, order-independent)
///   wcet!(10ms, analyzer: my_analyzer, percentile: P99)  (same as above)
/// Event comes from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! wcet {
	// Unified builder helper - handles all combinations
	(@builder $dur:expr) => {{
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr) => {{
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, analyzer: $a:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_analyzer(Arc::new($a))
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr, analyzer: $a:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.with_analyzer(Arc::new($a))
			.build()
			.expect("Failed to build WcetConfig")
	}};

	// Public API - normalize parameter order and delegate to builder
	($dur:expr) => {
		$crate::wcet!(@builder $dur)
	};
	($dur:expr, percentile: $p:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p)
	};
	($dur:expr, analyzer: $a:expr) => {
		$crate::wcet!(@builder $dur, analyzer: $a)
	};
	($dur:expr, percentile: $p:expr, analyzer: $a:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p, analyzer: $a)
	};
	($dur:expr, analyzer: $a:expr, percentile: $p:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p, analyzer: $a)
	};
}

/// Deadline parameters parsed from one `deadline!` invocation.
#[doc(hidden)]
pub struct DeadlineParams {
	/// Wall-clock budget the event must finish within.
	pub duration: std::time::Duration,
	/// Slack the spec requires to remain when the event finishes.
	pub min_slack: Option<std::time::Duration>,
}

/// Helper macro for deadline timing constraint
/// Usage:
///   deadline!(duration: 100ms, slack: 5ms)  (parentheses)
///   deadline! { duration: 100ms, slack: 5ms }  (curly braces)
///   deadline!(duration: 100ms)  (without slack)
/// Events come from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! deadline {
	// Parentheses syntax: deadline!(duration: ..., slack: ...)
	(duration: $dur:expr, slack: $slack:expr) => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: Some($slack),
		}
	};
	(duration: $dur:expr) => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: None,
		}
	};
	// Curly braces syntax: deadline! { duration: ..., slack: ... }
	{ duration: $dur:expr, slack: $slack:expr } => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: Some($slack),
		}
	};
	{ duration: $dur:expr } => {
		$crate::testing::macros::DeadlineParams {
			duration: $dur,
			min_slack: None,
		}
	};
}

/// Helper macro for timing guard expressions in tb_process_spec!
///
/// Usage:
///   guard!(x < 10ms)  -> ClockLessThan
///   guard!(x <= 5ms)  -> ClockLessEqual
///   guard!(x > 20ms)  -> ClockGreaterThan
///   guard!(x >= 15ms) -> ClockGreaterEqual
///   guard!(x == 10ms) -> ClockEquals
///   guard!(5ms <= x <= 10ms) -> ClockInRange
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! guard {
	// Less than: x < 10ms
	($clock:ident < $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessThan(stringify!($clock).to_string(), $dur)
	};
	// Less than or equal: x <= 5ms
	($clock:ident <= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessEqual(stringify!($clock).to_string(), $dur)
	};
	// Greater than: x > 20ms
	($clock:ident > $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterThan(stringify!($clock).to_string(), $dur)
	};
	// Greater than or equal: x >= 15ms
	($clock:ident >= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterEqual(stringify!($clock).to_string(), $dur)
	};
	// Equals: x == 10ms
	($clock:ident == $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockEquals(stringify!($clock).to_string(), $dur)
	};
	// Range: 5ms <= x <= 10ms
	($min_dur:tt <= $clock:ident <= $max_dur:tt) => {
		$crate::testing::timing::TimingGuard::ClockInRange(stringify!($clock).to_string(), $min_dur, $max_dur)
	};
}

/// Helper macro for jitter timing constraint
/// Usage:
///   jitter!(5ms)  (default MinMaxJitter calculator)
///   jitter!(5ms, calculator)  (custom calculator)
/// Event comes from the key in grouped syntax.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! jitter {
	($dur:expr) => {
		$crate::testing::timing::TimingConstraint::Jitter($dur, None)
	};
	($dur:expr, $calc:expr) => {{
		use std::sync::Arc;
		$crate::testing::timing::TimingConstraint::Jitter($dur, Some(Arc::new($calc)))
	}};
}

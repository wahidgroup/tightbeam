//! The timing-constraint macros of `tb_process_spec!` and `tb_assert_spec!`.
//!
//! Each macro builds one `testing::timing` value from a duration that a spec
//! writes inline, so a spec states `wcet!(Duration::from_millis(10))` where
//! the builder call would otherwise run to four lines.

/// Builds the [`WcetConfig`](crate::testing::timing::WcetConfig) of one event
/// from a duration `d`, with an optional percentile and analyzer in either
/// order. The event comes from the key in grouped syntax.
/// - `wcet!(d)` bounds every run of the event.
/// - `wcet!(d, percentile: Percentile::P99)` bounds the 99th percentile of the runs.
/// - `wcet!(d, analyzer: my_analyzer)` sets the analyzer of a percentile check.
/// - `wcet!(d, percentile: Percentile::P99, analyzer: my_analyzer)` sets both.
/// - `wcet!(d, analyzer: my_analyzer, percentile: Percentile::P99)` sets both in the other order.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! wcet {
	// The `@builder` arms build the config, one arm for each set of options.
	(@builder $dur:expr) => {{
		use $crate::builder::TypeBuilder as _;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr) => {{
		use $crate::builder::TypeBuilder as _;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, analyzer: $a:expr) => {{
		use $crate::builder::TypeBuilder as _;
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_analyzer($a)
			.build()
			.expect("Failed to build WcetConfig")
	}};
	(@builder $dur:expr, percentile: $p:expr, analyzer: $a:expr) => {{
		use $crate::builder::TypeBuilder as _;
		use std::sync::Arc;
		$crate::testing::timing::WcetConfigBuilder::default()
			.with_duration($dur)
			.with_percentile($p)
			.with_analyzer($a)
			.build()
			.expect("Failed to build WcetConfig")
	}};

	// The public arms put the options in one order for the `@builder` arms.
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

/// The parameters that one `deadline!` invocation builds.
#[doc(hidden)]
pub struct DeadlineParams {
	/// The time budget that the event must finish within.
	pub duration: std::time::Duration,
	/// The slack that the spec requires to remain when the event finishes.
	pub min_slack: Option<std::time::Duration>,
}

/// Builds the `DeadlineParams` of a deadline from a duration `d` and an
/// optional slack `s`, in parentheses or in braces. The events come from the
/// key in grouped syntax.
/// - `deadline!(duration: d, slack: s)` and `deadline! { duration: d, slack: s }` require the slack `s`.
/// - `deadline!(duration: d)` and `deadline! { duration: d }` leave the slack unset.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! deadline {
	// These two arms match a call in any delimiter, braces included.
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
	// The two arms above match a braces call first, so these two never match.
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

/// Builds the [`TimingGuard`](crate::testing::timing::TimingGuard) of a clock
/// `x` from a comparison in `tb_process_spec!`.
///
/// Each bound `d` is a duration, and each form builds one variant:
/// - `guard!(x < d)` builds `ClockLessThan`.
/// - `guard!(x <= d)` builds `ClockLessEqual`.
/// - `guard!(x > d)` builds `ClockGreaterThan`.
/// - `guard!(x >= d)` builds `ClockGreaterEqual`.
/// - `guard!(x == d)` builds `ClockEquals`.
/// - `guard!((lo) <= x <= (hi))` builds `ClockInRange`, and each bound is a parenthesized expression.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! guard {
	($clock:ident < $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessThan(stringify!($clock).to_string(), $dur)
	};
	($clock:ident <= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockLessEqual(stringify!($clock).to_string(), $dur)
	};
	($clock:ident > $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterThan(stringify!($clock).to_string(), $dur)
	};
	($clock:ident >= $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockGreaterEqual(stringify!($clock).to_string(), $dur)
	};
	($clock:ident == $dur:expr) => {
		$crate::testing::timing::TimingGuard::ClockEquals(stringify!($clock).to_string(), $dur)
	};
	// Each range bound is one token tree, such as a parenthesized expression.
	($min_dur:tt <= $clock:ident <= $max_dur:tt) => {
		$crate::testing::timing::TimingGuard::ClockInRange(stringify!($clock).to_string(), $min_dur, $max_dur)
	};
}

/// Builds the jitter constraint of one event from its largest allowed jitter,
/// a duration `d`. The event comes from the key in grouped syntax.
/// - `jitter!(d)` measures the jitter with [`MinMaxJitter`](crate::testing::timing::MinMaxJitter).
/// - `jitter!(d, calculator)` measures it with `calculator`, a custom
///   [`JitterCalculator`](crate::testing::timing::JitterCalculator).
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

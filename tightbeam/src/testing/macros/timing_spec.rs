//! The timing-constraint macros of `tb_process_spec!` and `tb_assert_spec!`.
//!
//! Each macro builds one `testing::timing` value from an inline duration, so a
//! spec writes `wcet!(Duration::from_millis(10))` in place of a four-line
//! builder call.

/// Builds the [`WcetConfig`](crate::testing::timing::WcetConfig) of one event
/// from a duration `d`, with an optional percentile and analyzer in either
/// order. The event comes from the key in grouped syntax.
/// - `wcet!(d)` bounds every run of the event.
/// - `wcet!(d, percentile: Percentile::P99)` bounds the 99th percentile of the runs.
/// - `wcet!(d, analyzer: my_analyzer)` fails to compile, because an analyzer computes a percentile.
/// - `wcet!(d, percentile: Percentile::P99, analyzer: my_analyzer)` sets both.
/// - `wcet!(d, analyzer: my_analyzer, percentile: Percentile::P99)` sets both in the other order.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! wcet {
	// The `@builder` arms build the config, one arm for each set of options.
	(@builder $dur:expr) => {
		$crate::testing::timing::WcetConfig { duration: $dur, percentile: None }
	};
	(@builder $dur:expr, percentile: $p:expr) => {
		$crate::testing::timing::WcetConfig {
			duration: $dur,
			percentile: Some($crate::testing::timing::WcetPercentile { percentile: $p, analyzer: None }),
		}
	};
	(@builder $dur:expr, percentile: $p:expr, analyzer: $a:expr) => {
		$crate::testing::timing::WcetConfig {
			duration: $dur,
			percentile: Some($crate::testing::timing::WcetPercentile {
				percentile: $p,
				analyzer: Some(::std::sync::Arc::new($a)),
			}),
		}
	};

	// The public arms put the options in one order for the `@builder` arms.
	($dur:expr) => {
		$crate::wcet!(@builder $dur)
	};
	($dur:expr, percentile: $p:expr) => {
		$crate::wcet!(@builder $dur, percentile: $p)
	};
	($dur:expr, analyzer: $a:expr) => {
		::core::compile_error!("`wcet!` takes an analyzer with a percentile: add `percentile: ...`")
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
		$crate::testing::macros::DeadlineParams { duration: $dur, min_slack: Some($slack) }
	};
	(duration: $dur:expr) => {
		$crate::testing::macros::DeadlineParams { duration: $dur, min_slack: None }
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
/// - `guard!(lo <= x <= hi)` builds `ClockInRange`, and each bound is one token tree, such as `lo` or `(lo)`.
#[cfg(feature = "testing-timing")]
#[macro_export]
macro_rules! guard {
	// The range form comes first, because the `<=` form reads an identifier
	// lower bound as its clock. Each range bound is one token tree.
	($min_dur:tt <= $clock:ident <= $max_dur:tt) => {
		$crate::testing::timing::TimingGuard::ClockInRange(stringify!($clock).to_string(), $min_dur, $max_dur)
	};
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

#[cfg(all(test, feature = "testing-timing"))]
mod tests {
	use core::time::Duration;

	use crate::testing::timing::{DefaultStatisticalAnalyzer, Percentile, TimingGuard};

	#[test]
	fn a_range_guard_takes_identifier_bounds() -> Result<(), Box<dyn core::error::Error>> {
		let lower = Duration::from_millis(5);
		let upper = Duration::from_millis(10);

		let guard = crate::guard!(lower <= clock <= upper);
		assert_eq!(guard, TimingGuard::ClockInRange("clock".to_string(), lower, upper));
		Ok(())
	}

	#[test]
	fn a_wcet_holds_its_analyzer_under_its_percentile() -> Result<(), Box<dyn core::error::Error>> {
		let duration = Duration::from_millis(10);
		let wcet = crate::wcet!(duration, analyzer: DefaultStatisticalAnalyzer, percentile: Percentile::P99);

		let percentile = wcet.percentile.ok_or("the bound holds a percentile")?;
		assert_eq!(percentile.percentile, Percentile::P99);
		assert!(percentile.analyzer.is_some());
		Ok(())
	}

	#[test]
	fn a_deadline_in_braces_keeps_its_slack() -> Result<(), Box<dyn core::error::Error>> {
		let duration = Duration::from_millis(100);
		let slack = Duration::from_millis(5);

		let params = crate::deadline! { duration: duration, slack: slack };
		assert_eq!(params.duration, duration);
		assert_eq!(params.min_slack, Some(slack));
		Ok(())
	}
}

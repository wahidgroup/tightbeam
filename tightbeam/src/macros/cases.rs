//! Case-table tests that report one failure per case.
//!
//! A loop over a case table inside one `#[test]` reports every row as one test,
//! so a failure names the function rather than the case that broke and the rows
//! after the first failure never run. [`tb_cases`](crate::tb_cases) emits one
//! `#[test]` per row instead, which is what the house testing rules ask for
//! where a runner has no parameterized form.

/// Emits one test per row of a case table.
///
/// The body is written once against one parameter, a name or a tuple pattern
/// with its type, and each row supplies one value for it.
///
/// - Each test is named `<fn name>_<case name>`, so a failure names the case and the rows after a
///   failing one still run.
/// - A body that ends in `?` declares its return type the way any test does.
/// - A plain comment above the invocation documents the group, because a rustdoc block cannot
///   repeat across rows.
/// - A row takes outer attributes before its name, such as a `///` doc, a
///   `#[cfg(..)]` gate, or an `#[ignore = ".."]`, and the test of that row
///   carries them.
///
/// # Runners
///
/// The line that opens the table picks the runner of every row:
///
/// | Table | Runner of each row |
/// | --- | --- |
/// | `fn` | `#[test]` |
/// | `async fn` | `#[tokio::test]` |
/// | `#[tokio::test(..)]` above `async fn` | That attribute, with its arguments |
///
/// The async forms name `tokio` by path, so the crate that invokes them
/// depends on `tokio` with its `macros` and `rt` features. The `start_paused`
/// argument also takes the `test-util` feature.
///
/// # Examples
///
/// ```
/// # use tightbeam::tb_cases;
/// fn double(value: u64) -> u64 {
///     value * 2
/// }
///
/// tb_cases! {
///     fn doubling((input, expected): (u64, u64)) {
///         assert_eq!(double(input), expected);
///     }
///     cases {
///         zero => (0, 0),
///         one => (1, 2),
///         large => (1_000, 2_000),
///     }
/// }
/// ```
///
/// The attributes of a row go on the test of that row:
///
/// ```
/// # use tightbeam::tb_cases;
/// # fn double(value: u64) -> u64 {
/// #     value * 2
/// # }
/// tb_cases! {
///     fn doubling((input, expected): (u64, u64)) {
///         assert_eq!(double(input), expected);
///     }
///     cases {
///         /// Zero is the double of itself.
///         zero => (0, 0),
///         #[cfg(unix)]
///         one => (1, 2),
///         #[ignore = "the double of the largest value overflows"]
///         largest => (u64::MAX, 0),
///     }
/// }
/// ```
///
/// An `async fn` table runs each row under `#[tokio::test]`, so a row awaits
/// the task it spawns and ends in `?`:
///
/// ```
/// # use tightbeam::tb_cases;
/// # fn double(value: u64) -> u64 {
/// #     value * 2
/// # }
/// use tokio::task::JoinError;
///
/// tb_cases! {
///     async fn doubling_on_a_task((input, expected): (u64, u64)) -> Result<(), JoinError> {
///         let doubled = tokio::spawn(async move { double(input) }).await?;
///
///         assert_eq!(doubled, expected);
///         Ok(())
///     }
///     cases {
///         zero => (0, 0),
///         one => (1, 2),
///     }
/// }
/// ```
///
/// A `#[tokio::test(..)]` above the table passes its arguments to the runner
/// of every row, here a paused clock:
///
/// ```
/// # use tightbeam::tb_cases;
/// use core::time::Duration;
///
/// use tokio::time::Instant;
///
/// tb_cases! {
///     #[tokio::test(start_paused = true)]
///     async fn a_paused_clock_moves_by_the_advance(span: Duration) {
///         let start = Instant::now();
///
///         tokio::time::advance(span).await;
///
///         assert_eq!(start.elapsed(), span);
///     }
///     cases {
///         one_second => Duration::from_secs(1),
///         one_hour => Duration::from_secs(3_600),
///     }
/// }
/// ```
#[macro_export]
macro_rules! tb_cases {
	(
		fn $name:ident($binding:tt: $ty:ty) $(-> $ret:ty)? $body:block
		cases { $($(#[$attr:meta])* $case:ident => $value:expr),+ $(,)? }
	) => {
		$crate::__tb_cases! {
			@rows [test] [] [$(-> $ret)?] $name ($binding: $ty) $body
			{ $($(#[$attr])* $case => $value),+ }
		}
	};
	(
		async fn $name:ident($binding:tt: $ty:ty) $(-> $ret:ty)? $body:block
		cases { $($(#[$attr:meta])* $case:ident => $value:expr),+ $(,)? }
	) => {
		$crate::__tb_cases! {
			@rows [tokio::test] [async] [$(-> $ret)?] $name ($binding: $ty) $body
			{ $($(#[$attr])* $case => $value),+ }
		}
	};
	(
		#[tokio::test $($arguments:tt)?]
		async fn $name:ident($binding:tt: $ty:ty) $(-> $ret:ty)? $body:block
		cases { $($(#[$attr:meta])* $case:ident => $value:expr),+ $(,)? }
	) => {
		$crate::__tb_cases! {
			@rows [tokio::test $($arguments)?] [async] [$(-> $ret)?] $name ($binding: $ty) $body
			{ $($(#[$attr])* $case => $value),+ }
		}
	};
}

/// The arms behind [`tb_cases`](crate::tb_cases): `@rows` emits one `@row`
/// per row of a table, and `@row` emits the test of that row.
///
/// `macro_rules!` repeats a metavariable only in a repetition of its own
/// depth. So `@rows` passes each optional part of the table, the runner
/// arguments and the return type, as one group, and `@row` opens that group
/// outside the repetition of the rows.
#[doc(hidden)]
#[macro_export]
macro_rules! __tb_cases {
	(
		@rows $runner:tt $asyncness:tt $ret:tt $name:ident $parameter:tt $body:block
		{ $($(#[$attr:meta])* $case:ident => $value:expr),+ }
	) => {
		$(
			$crate::__tb_cases! {
				@row $runner $asyncness $ret $name $case [$(#[$attr])*] $parameter $body $value
			}
		)+
	};
	(
		@row $runner:tt [$($asyncness:tt)?] [$($ret:tt)*] $name:ident $case:ident [$(#[$attr:meta])*]
		($binding:tt: $ty:ty) $body:block $value:expr
	) => {
		$crate::paste::paste! {
			$(#[$attr])*
			#$runner
			$($asyncness)? fn [<$name _ $case>]() $($ret)* {
				let $binding: $ty = $value;

				$body
			}
		}
	};
}

#[cfg(test)]
mod tests {
	use core::num::TryFromIntError;
	use core::time::Duration;

	use tokio::runtime::{Handle, RuntimeFlavor};
	use tokio::task::JoinError;
	use tokio::time::Instant;

	// Each row binds its own value, so a table that bound one value to every
	// row fails on each row whose half differs. A row's attributes go on the
	// test of that row.
	tb_cases! {
		fn a_row_binds_its_own_value((value, half): (u8, u8)) {
			assert_eq!(value / 2, half);
		}
		cases {
			zero => (0, 0),
			/// A doc comment on a row documents the test of that row.
			two => (2, 1),
			#[cfg(test)]
			ten => (10, 5),
			/// `any()` holds in no build, so the table emits no test of this
			/// row, whose half is wrong.
			#[cfg(any())]
			gated_out => (4, 3),
		}
	}

	// A row that returns a `Result` ends in `?`, and its `Err` fails the test.
	tb_cases! {
		fn a_row_returns_its_result((wide, narrow): (u16, u8)) -> Result<(), TryFromIntError> {
			let narrowed = u8::try_from(wide)?;
			assert_eq!(narrowed, narrow);
			Ok(())
		}
		cases {
			zero => (0, 0),
			widest => (255, 255),
		}
	}

	// An `async fn` table runs each row under `#[tokio::test]`, on the
	// current-thread runtime, so a row awaits the task it spawns.
	tb_cases! {
		async fn an_async_row_runs_on_the_default_runner((value, half): (u8, u8)) -> Result<(), JoinError> {
			let halved = tokio::spawn(async move { value / 2 }).await?;
			let flavor = Handle::current().runtime_flavor();
			assert_eq!((halved, flavor), (half, RuntimeFlavor::CurrentThread));
			Ok(())
		}
		cases {
			zero => (0, 0),
			/// A doc comment goes on the test of an async row too.
			ten => (10, 5),
		}
	}

	// A `#[tokio::test(..)]` above the table passes its arguments to the
	// runner of every row. `advance` panics on a clock that runs, so a row
	// passes only on the paused clock that `start_paused` asks for.
	tb_cases! {
		#[tokio::test(start_paused = true)]
		async fn a_paused_clock_moves_by_the_advance(span: Duration) {
			let start = Instant::now();
			tokio::time::advance(span).await;
			assert_eq!(start.elapsed(), span);
		}
		cases {
			one_millisecond => Duration::from_millis(1),
			#[cfg(test)]
			one_hour => Duration::from_secs(3_600),
		}
	}
}

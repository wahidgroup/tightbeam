//! Case-table tests that report one failure per case.
//!
//! A loop over a case table inside one `#[test]` reports every row as one test,
//! so a failure names the function rather than the case that broke and the rows
//! after the first failure never run. [`tb_cases`](crate::tb_cases) emits one
//! `#[test]` per row instead, which is what the house testing rules ask for
//! where a runner has no parameterized form.

/// Emits one `#[test]` per row of a case table.
///
/// The body is written once against one parameter, a name or a tuple pattern
/// with its type, and each row supplies one value for it.
///
/// - Each test is named `<fn name>_<case name>`, so a failure names the case and the rows after a
///   failing one still run.
/// - A body that ends in `?` declares its return type the way any test does.
/// - A plain comment above the invocation documents the group, because a rustdoc block cannot
///   repeat across rows.
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
#[macro_export]
macro_rules! tb_cases {
	(
		fn $name:ident($binding:tt: $ty:ty) -> $ret:ty $body:block
		cases { $($case:ident => $value:expr),+ $(,)? }
	) => {
		$crate::paste::paste! {
			$(
				#[test]
				fn [<$name _ $case>]() -> $ret {
					let $binding: $ty = $value;

					$body
				}
			)+
		}
	};
	(
		fn $name:ident($binding:tt: $ty:ty) $body:block
		cases { $($case:ident => $value:expr),+ $(,)? }
	) => {
		$crate::paste::paste! {
			$(
				#[test]
				fn [<$name _ $case>]() {
					let $binding: $ty = $value;

					$body
				}
			)+
		}
	};
}

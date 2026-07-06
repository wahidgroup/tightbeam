/// Macro to implement `Display` and `Error` for error enums.
///
/// Two entry forms:
///
/// - `impl_error_display!(Type { ... })` emits only when the `derive`
///   feature is disabled, mirroring the strings of an `Errorizable` derive.
///   The message strings exist twice (attribute + macro), so this form is
///   reserved for types that need `Errorizable`'s extra codegen.
/// - `impl_error_display!(unconditional Type { ... })` emits regardless of
///   features.
///
/// Variants may carry `cfg` attributes, which are forwarded to the
/// generated match arms.
#[macro_export]
macro_rules! impl_error_display {
	// Always emitted: the enum must not derive Errorizable.
	(unconditional $error_type:ident { $($body:tt)* }) => {
		$crate::impl_error_display!(@impls $error_type { $($body)* });
	};

	// Derive-mirroring entry: only when the derive feature is disabled.
	($error_type:ident { $($body:tt)* }) => {
		#[cfg(not(feature = "derive"))]
		$crate::impl_error_display!(@impls $error_type { $($body)* });
	};

	// Helper: generate the Display and Error impls
	(@impls $error_type:ident { $($(#[$vattr:meta])* $variant:ident $(($($tuple_field:ident),*))? $({ $($struct_field:ident),* })? => $fmt:expr),* $(,)? }) => {
		impl core::fmt::Display for $error_type {
			fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
				match self {
					$(
						$(#[$vattr])*
						$crate::impl_error_display!(@pattern $error_type :: $variant $(($($tuple_field),*))? $({ $($struct_field),* })?) =>
							write!(f, $fmt $(, $($tuple_field = $tuple_field),*)? $(, $($struct_field = $struct_field),*)?),
					)*
				}
			}
		}

		impl core::error::Error for $error_type {}
	};

	// Helper: generate match pattern for unit variant
	(@pattern $error_type:ident :: $variant:ident) => {
		$error_type::$variant
	};

	// Helper: generate match pattern for tuple variant
	(@pattern $error_type:ident :: $variant:ident ($($tuple_field:ident),*)) => {
		$error_type::$variant($($tuple_field),*)
	};

	// Helper: generate match pattern for struct variant
	(@pattern $error_type:ident :: $variant:ident { $($struct_field:ident),* }) => {
		$error_type::$variant { $($struct_field),* }
	};
}

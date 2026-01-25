/// Macro to implement `Display` and `Error` for error enums when `derive` feature is disabled.
///
/// This reduces boilerplate for error types that use `Errorizable` when derive is enabled
/// but need manual implementations otherwise.
#[macro_export]
macro_rules! impl_error_display {
	// Main entry: error type name and variant mappings
	($error_type:ident { $($variant:ident $(($($tuple_field:ident),*))? $({ $($struct_field:ident),* })? => $fmt:expr),* $(,)? }) => {
		#[cfg(not(feature = "derive"))]
		impl core::fmt::Display for $error_type {
			fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
				match self {
					$(
						$crate::impl_error_display!(@pattern $error_type :: $variant $(($($tuple_field),*))? $({ $($struct_field),* })?) =>
							write!(f, $fmt $(, $($tuple_field = $tuple_field),*)? $(, $($struct_field = $struct_field),*)?),
					)*
				}
			}
		}

		#[cfg(not(feature = "derive"))]
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

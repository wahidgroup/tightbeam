//! Generators for the `From` and `TryFrom` impls of the crate's types.

/// Macro to implement From trait for both reference and owned types
///
/// This generates:
/// - `impl From<&TightBeam> for TargetType` that clones or copies the field
/// - `impl From<TightBeam> for TargetType` that delegates to the reference impl
#[macro_export]
macro_rules! impl_from {
	// Pattern for field extraction from structs
	($source:ty, $param:ident => $target:ty: $($field:tt)*) => {
		impl From<&$source> for $target {
			fn from($param: &$source) -> Self {
				$($field)*
			}
		}

		impl From<$source> for $target {
			fn from($param: $source) -> Self {
				(&$param).into()
			}
		}
	};

	// Pattern for error conversions (unconditional)
	($from_type:ty => $target:ident::$variant:ident) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant(err)
			}
		}
	};

	// Pattern for conditional error conversions (with cfg)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant(err)
			}
		}
	};

	// Pattern for conditional error conversions via enum wrapper (with cfg)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident via $wrapper:path) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant($wrapper(err))
			}
		}
	};

	// Pattern for unconditional error conversions via enum wrapper
	($from_type:ty => $target:ident::$variant:ident via $wrapper:path) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				$target::$variant($wrapper(err))
			}
		}
	};

	// Pattern for extracting inner value from enum variant with fallback
	($from_type:ty => $target:ident::$variant:ident extract $enum_variant:pat => $inner:ident else $fallback:expr) => {
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				match err {
					$enum_variant => $target::$variant($inner),
					_ => $target::$variant($fallback),
				}
			}
		}
	};

	// Pattern for extracting inner value from enum variant with fallback
	// (conditional)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident extract $enum_variant:pat => $inner:ident else $fallback:expr) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(err: $from_type) -> Self {
				match err {
					$enum_variant => $target::$variant($inner),
					_ => $target::$variant($fallback),
				}
			}
		}
	};

	// Pattern for unit variants (discard the error value)
	($from_type:ty => $target:ident::$variant:ident discard) => {
		impl From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for unit variants with cfg (discard the error value)
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident discard) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for generic types to unit variants (e.g., PoisonError<T>)
	(<$($gen:ident),+> $from_type:ty => $target:ident::$variant:ident discard) => {
		impl<$($gen),+> From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for generic types to unit variants with cfg
	(#[cfg($feature:meta)] <$($gen:ident),+> $from_type:ty => $target:ident::$variant:ident discard) => {
		#[cfg($feature)]
		impl<$($gen),+> From<$from_type> for $target {
			fn from(_: $from_type) -> Self {
				$target::$variant
			}
		}
	};

	// Pattern for transformative conversions (wrap error via expression)
	($from_type:ty => $target:ident::$variant:ident via |$err:ident| $transform:expr) => {
		impl From<$from_type> for $target {
			fn from($err: $from_type) -> Self {
				$target::$variant($transform)
			}
		}
	};

	// Pattern for transformative conversions with cfg
	(#[cfg($feature:meta)] $from_type:ty => $target:ident::$variant:ident via |$err:ident| $transform:expr) => {
		#[cfg($feature)]
		impl From<$from_type> for $target {
			fn from($err: $from_type) -> Self {
				$target::$variant($transform)
			}
		}
	};
}

/// Macro to implement TryFrom trait for extracting optional fields
///
/// This generates:
/// - `impl TryFrom<TightBeam> for TargetType` that consumes the source
/// - Uses `take()` for zero-copy extraction when consuming the source
#[macro_export]
macro_rules! impl_try_from {
	// For fields directly on TightBeam
	($source:ty, $param:ident => $target:ty: $field:ident) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> Result<Self, Self::Error> {
				$param.$field.take().ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}
	};

	($source:ty, $param:ident => $target:ty: $field:ident, $error:expr) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> core::result::Result<Self, Self::Error> {
				$param.$field.take().ok_or($error)
			}
		}
	};

	// For fields in metadata
	($source:ty, $param:ident => $target:ty: metadata.$field:ident) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> Result<Self, Self::Error> {
				$param
					.metadata
					.$field
					.take()
					.ok_or($crate::error::TightBeamError::InvalidMetadata)
			}
		}
	};

	($source:ty, $param:ident => $target:ty: metadata.$field:ident, $error:expr) => {
		impl TryFrom<$source> for $target {
			type Error = $crate::error::TightBeamError;

			fn try_from(mut $param: $source) -> core::result::Result<Self, Self::Error> {
				$param.metadata.$field.take().ok_or($error)
			}
		}
	};
}

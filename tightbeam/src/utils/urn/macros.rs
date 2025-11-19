//! Declarative macro for defining URN specifications
//!
//! The `urn_spec!` macro generates a `UrnSpec` implementation with validation,
//! transformation, and NSS construction logic based on a declarative
//! specification.

/// Define a URN specification with validation and NSS structure
///
/// Field configuration supports:
/// - `value: "literal"` - fixed constant value
/// - `values: ["opt1", "opt2", ...]` - one-of validation
/// - `pattern: Pattern::*`
/// - `required: true/false` - whether field is required (defaults to `true`)
/// - `sep: "separator"` - NSS separator for this field (optional)
#[macro_export]
macro_rules! urn_spec {
	// Main entry point
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		nid: $nid:literal,
		nss_structure {
			$($field:ident: { $($config:tt)* }),* $(,)?
		}
		$(, nss_format: $nss_format:literal)?
	) => {
		$(#[$meta])*
		$vis struct $name;

		impl $name {
			/// Get the UrnSpecBuilder configuration for this spec
			fn spec_builder() -> $crate::utils::urn::UrnSpecBuilder {
				let mut builder = $crate::utils::urn::UrnSpecBuilder::from($nid);

				$(
					builder = $crate::urn_spec!(@apply_field builder, $field, $($config)*);
				)*

				$(
					builder = builder.nss_format($nss_format);
				)?

				builder
			}
		}

		impl $crate::utils::urn::UrnSpec for $name {
			const NID: &'static str = $nid;

			fn validate(builder: &$crate::utils::urn::UrnBuilder) -> Result<(), $crate::utils::urn::UrnValidationError> {
				Self::spec_builder().validate(builder)
			}

			fn build_nss(builder: &$crate::utils::urn::UrnBuilder) -> Result<::std::borrow::Cow<'static, str>, $crate::utils::urn::UrnValidationError> {
				let nss = Self::spec_builder().build_nss(builder)?;
				Ok(nss.into())
			}
		}
	};

	// Apply field configuration
	(@apply_field $builder:expr, $field:ident, $($config:tt)*) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, true, { $($config)* })
	};

	// Helper: apply required/optional based on flag
	(@apply_required $builder:expr, $field:ident, $req:expr) => {
		if $req {
			$builder.field_required(stringify!($field))
		} else {
			$builder.field_optional(stringify!($field))
		}
	};

	// Parse field config block recursively - handle required first
	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: true, $($rest:tt)* }) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, true, { $($rest)* })
	};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: false, $($rest:tt)* }) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, false, { $($rest)* })
	};

	// Parse config options recursively
	(@parse_field_config $builder:expr, $field:ident, $req:expr, { value: $val:literal, $($rest:tt)* }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_const(stringify!($field), $val);
		$crate::urn_spec!(@parse_field_config b, $field, $req, { $($rest)* })
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { value: $val:literal }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_const(stringify!($field), $val);
		b
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { values: [$($opts:literal),+ $(,)?], $($rest:tt)* }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_oneof(stringify!($field), &[$($opts),+]);
		$crate::urn_spec!(@parse_field_config b, $field, $req, { $($rest)* })
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { values: [$($opts:literal),+ $(,)?] }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_oneof(stringify!($field), &[$($opts),+]);
		b
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { pattern: $pattern_expr:expr, $($rest:tt)* }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_pattern(stringify!($field), $pattern_expr);
		$crate::urn_spec!(@parse_field_config b, $field, $req, { $($rest)* })
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { pattern: $pattern_expr:expr }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_pattern(stringify!($field), $pattern_expr);
		b
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { sep: $sep:literal, $($rest:tt)* }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_nss_separator(stringify!($field), $sep);
		$crate::urn_spec!(@parse_field_config b, $field, $req, { $($rest)* })
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { sep: $sep:literal }) => {{
		let mut b = $crate::urn_spec!(@apply_required $builder, $field, $req);
		b = b.field_nss_separator(stringify!($field), $sep);
		b
	}};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: true }) => {
		$crate::urn_spec!(@apply_required $builder, $field, true)
	};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: false }) => {
		$crate::urn_spec!(@apply_required $builder, $field, false)
	};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { }) => {
		$crate::urn_spec!(@apply_required $builder, $field, $req)
	};
}

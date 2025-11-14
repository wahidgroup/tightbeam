//! Declarative macro for defining URN specifications
//!
//! The `urn_spec!` macro generates a `UrnSpec` implementation with validation,
//! transformation, and NSS construction logic based on a declarative specification.

/// Define a URN specification with validation and NSS structure
///
/// # Syntax
///
/// ```ignore
/// urn_spec! {
///     pub SpecName,
///     nid: "namespace-id",
///     nss_structure {
///         field1: required, const("value"),
///         field2: required, oneof("opt1", "opt2"),
///         field3: optional, pattern(r"^[a-z0-9-]+$"),
///         nested: required {
///             subfield1: required, pattern(r"^\d+$"),
///             subfield2: optional
///         }
///     },
///     validate {
///         // Custom validation logic
///         if field1 == "value" && field2 == "opt1" {
///             error("invalid combination")
///         }
///     }
/// }
/// ```
///
/// # Generated API
///
/// The macro generates:
/// - `UrnSpec` trait implementation
/// - Validation logic
/// - NSS construction
/// - Builder methods for each field
#[macro_export]
macro_rules! urn_spec {
	// Main entry point
	(
		$vis:vis $name:ident,
		nid: $nid:literal,
		nss_structure {
			$($field:ident: $req:ident $(, $constraint:ident($($args:tt)*))?  $({ $($nested:tt)* })?),* $(,)?
		}
		$(, validate { $($validate:tt)* })?
	) => {
		$vis struct $name;

		impl $crate::utils::urn::UrnSpec for $name {
			const NID: &'static str = $nid;

			fn validate(builder: &$crate::utils::urn::UrnBuilder) -> Result<(), $crate::utils::urn::ValidationError> {
				use $crate::utils::urn::ValidationError;

				// Generate field validation
				$(
					$crate::urn_spec!(@validate_field builder, stringify!($field), $req $(, $constraint($($args)*))?);
				)*

				// TODO: Custom validation block (would require full parsing of validate block)
				// For now, specs can override validate() method manually

				Ok(())
			}

			fn build_nss(builder: &$crate::utils::urn::UrnBuilder) -> Result<::std::borrow::Cow<'static, str>, $crate::utils::urn::ValidationError> {
				use $crate::utils::urn::ValidationError;

				// Build NSS from components
				let mut parts = ::std::vec::Vec::new();

				$(
					$crate::urn_spec!(@build_nss_part builder, parts, stringify!($field) $(, $constraint($($args)*))?);
				)*

				Ok(parts.join(":").into())
			}
		}

		// Generate builder methods
		impl<'a> $crate::utils::urn::UrnBuilder<'a> {
			$(
				$crate::urn_spec!(@builder_method $field);
			)*
		}
	};

	// Validate field: required
	(@validate_field $builder:expr, $field:expr, required) => {
		if $builder.get($field).is_none() {
			return Err($crate::utils::urn::ValidationError::RequiredFieldMissing($field));
		}
	};

	// Validate field: optional
	(@validate_field $builder:expr, $field:expr, optional) => {
		// Optional fields don't need validation
	};

	// Validate field: required with const constraint
	(@validate_field $builder:expr, $field:expr, required, const($val:literal)) => {
		match $builder.get($field) {
			None => return Err($crate::utils::urn::ValidationError::RequiredFieldMissing($field)),
			Some(v) if v.as_ref() != $val => {
				return Err($crate::utils::urn::ValidationError::InvalidFormat {
					field: $field,
					pattern: concat!("const(\"", $val, "\")"),
				});
			}
			_ => {}
		}
	};

	// Validate field: required with oneof constraint
	(@validate_field $builder:expr, $field:expr, required, oneof($($opts:literal),+)) => {
		match $builder.get($field) {
			None => return Err($crate::utils::urn::ValidationError::RequiredFieldMissing($field)),
			Some(v) => {
				let valid = false $(|| v.as_ref() == $opts)+;
				if !valid {
					return Err($crate::utils::urn::ValidationError::InvalidFormat {
						field: $field,
						pattern: concat!("oneof(", $($opts, ", "),+, ")"),
					});
				}
			}
		}
	};

	// Validate field: required with pattern constraint
	(@validate_field $builder:expr, $field:expr, required, pattern($pat:literal)) => {
		match $builder.get($field) {
			None => return Err($crate::utils::urn::ValidationError::RequiredFieldMissing($field)),
			Some(v) => {
				// Pattern validation would require regex - simplified for now
				// Real implementation would use regex crate
			}
		}
	};

	// Build NSS part: simple field
	(@build_nss_part $builder:expr, $parts:expr, $field:expr) => {
		if let Some(val) = $builder.get($field) {
			$parts.push(val.as_ref());
		}
	};

	// Build NSS part: with const constraint
	(@build_nss_part $builder:expr, $parts:expr, $field:expr, const($val:literal)) => {
		$parts.push($val);
	};

	// Builder method: generate setter
	(@builder_method $field:ident) => {
		#[doc = concat!("Set the `", stringify!($field), "` field")]
		#[inline]
		pub fn $field(self, value: impl Into<::std::borrow::Cow<'a, str>>) -> Self {
			self.set(stringify!($field), value)
		}
	};
}


//! The declarative macro that defines a URN specification.
//!
//! `urn_spec!` generates a `UrnSpec` implementation, with validation,
//! transformation, and NSS construction, from a declarative specification.

/// A [`Urn`] from a static NID and NSS, checked at compile time.
///
/// The check runs in a `const` block, so a malformed literal is a build error
/// and there is no run-time panic path. In a `const` item `cargo check` reports
/// it. In a function body the build does. Use [`Urn::from_parts`] for parts
/// known only at run time.
///
/// ## Examples
///
/// ```
/// const EVENT: tightbeam::urn::Urn<'static> = tightbeam::urn!("example", "test:resource");
/// ```
///
/// ```compile_fail
/// const REJECTED: tightbeam::urn::Urn<'static> = tightbeam::urn!("-bad", "resource");
/// ```
///
/// [`Urn`]: crate::urn::Urn
/// [`Urn::from_parts`]: crate::urn::Urn::from_parts
#[macro_export]
macro_rules! urn {
	($nid:expr, $nss:expr $(,)?) => {
		const {
			let nid: &'static str = $nid;
			let nss: &'static str = $nss;

			if $crate::urn::Urn::validate_nid(nid).is_err() {
				::core::panic!(
					"malformed URN literal: the NID must be 2-32 ASCII alphanumerics or hyphens starting and ending with an alphanumeric"
				);
			}

			match $crate::urn::Urn::validate_nss(nss) {
				Ok(()) => {}
				Err($crate::urn::UrnValidationError::InvalidNssCharacters) => ::core::panic!(
					"malformed URN literal: the NSS must be RFC 3986 pchar or '/', and must not start with '/'"
				),
				Err(_) => ::core::panic!("malformed URN literal: the NSS must not be empty"),
			}

			$crate::urn::Urn::new_unchecked(nid, nss)
		}
	};
}

/// Define a URN specification, with its validation and its NSS structure.
///
/// A field takes these options:
///
/// - `value: "literal"` fixes the value to one constant.
/// - `values: ["opt1", "opt2"]` admits one of the listed values.
/// - `pattern: Pattern::*` admits a value of the `Pattern` class.
/// - `required: true` or `required: false` sets whether the field is required, `true` by default.
/// - `sep: "separator"` sets the NSS separator before the field.
///
/// An optional `transform` closure edits the components, in place of the
/// default [`UrnSpec::transform`](crate::urn::UrnSpec::transform).
#[macro_export]
macro_rules! urn_spec {
	// The entry arm defines the spec struct and its `UrnSpec` impl.
	(
		$(#[$meta:meta])*
		$vis:vis $name:ident,
		nid: $nid:literal,
		nss_structure {
			$($field:ident: { $($config:tt)* }),* $(,)?
		}
		$(, nss_format: $nss_format:literal)?
		$(, transform: $transform_expr:expr)?
	) => {
		$(#[$meta])*
		$vis struct $name;

		impl $name {
			/// The `UrnSpecBuilder` of this spec.
			fn spec_builder() -> $crate::urn::UrnSpecBuilder {
				let mut builder = $crate::urn::UrnSpecBuilder::from($nid);

				$(
					builder = $crate::urn_spec!(@apply_field builder, $field, $($config)*);
				)*

				$(
					builder = builder.nss_format($nss_format);
				)?

				builder
			}
		}

		impl $crate::urn::UrnSpec for $name {
			const NID: &'static str = $nid;

			type Components<'a> = $crate::urn::UrnBuilder<'a>;

			fn components<'a>(nss: &'a str) -> Result<Self::Components<'a>, $crate::urn::UrnValidationError> {
				Self::spec_builder().parse_nss(nss)
			}

			$crate::urn_spec!(@generate_transform $($transform_expr)?);

			fn validate<'a>(components: &dyn $crate::urn::UrnComponents<'a>) -> Result<(), $crate::urn::UrnValidationError> {
				Self::spec_builder().validate(components)
			}

			fn build_nss<'a>(components: &dyn $crate::urn::UrnComponents<'a>) -> Result<::std::borrow::Cow<'static, str>, $crate::urn::UrnValidationError> {
				let nss = Self::spec_builder().build_nss(components)?;
				Ok(nss.into())
			}
		}
	};

	// This arm applies the options of one field, which is required by default.
	(@apply_field $builder:expr, $field:ident, $($config:tt)*) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, true, { $($config)* })
	};

	// This arm makes the field required or optional, as `$req` names.
	(@apply_required $builder:expr, $field:ident, $req:expr) => {
		if $req {
			$builder.field_required(stringify!($field))
		} else {
			$builder.field_optional(stringify!($field))
		}
	};

	// A `required` option sets the flag that each later option applies.
	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: true, $($rest:tt)* }) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, true, { $($rest)* })
	};

	(@parse_field_config $builder:expr, $field:ident, $req:expr, { required: false, $($rest:tt)* }) => {
		$crate::urn_spec!(@parse_field_config $builder, $field, false, { $($rest)* })
	};

	// Each other option applies the flag and its own setting, then reads the
	// options after it.
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

	// A spec with a `transform` closure overrides `UrnSpec::transform`.
	(@generate_transform $transform_expr:expr) => {
		fn transform<'a>(components: &mut dyn $crate::urn::UrnComponents<'a>) {
			let closure: fn(&mut dyn $crate::urn::UrnComponents<'a>) = $transform_expr;
			closure(components);
		}
	};

	// A spec with no closure keeps the default `UrnSpec::transform`.
	(@generate_transform) => {
	};
}

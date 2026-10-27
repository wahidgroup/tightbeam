//! The generator of the audit names of a refusal enum.

/// Writes, from one list of the variants of an error enum, one `const fn`
/// per name that a refusal of the enum takes in an audit label.
///
/// Each function joins its prefix and the name of the variant at compile
/// time, so a label is a constant that no refusal builds, and a variant that
/// the list leaves out fails to compile in every function.
macro_rules! refusal_names {
	([ $( $(#[$doc:meta])* fn $name:ident = $prefix:literal; )+ ] $variants:tt) => {
		$( $crate::macros::names::refusal_names!(@name $(#[$doc])* $name = $prefix, $variants); )+
	};

	(@name $(#[$doc:meta])* $name:ident = $prefix:literal, { $( $(#[$gate:meta])* $variant:pat => $label:literal, )* }) => {
		$(#[$doc])*
		pub(crate) const fn $name(&self) -> &'static str {
			match self {
				$( $(#[$gate])* $variant => concat!($prefix, $label), )*
			}
		}
	};
}

pub(crate) use refusal_names;

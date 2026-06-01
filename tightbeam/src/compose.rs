//! The [`compose!`] frame-builder macro.

/// Builds a [`Frame`](crate::asn1::Frame) with a concise, named-argument syntax,
/// expanding to a sequence of [`FrameBuilder`](crate::builder::FrameBuilder)
/// calls followed by [`build`](crate::builder::TypeBuilder::build).
///
/// # Syntax
///
/// The first token selects the [`Version`](crate::Version) variant; the
/// remaining comma-separated `key: value` pairs configure the frame. Trailing
/// commas are allowed and every field except the version is optional.
///
/// ```ignore
/// let frame = compose! {
/// 	V0:
/// 		id: message_id,
/// 		order: sequence,
/// 		message: payload,
/// }?;
/// ```
///
/// # Returns
///
/// The [`Result`](crate::error::Result) produced by `build`; propagate it with
/// `?` or match on it.
#[macro_export(local_inner_macros)]
macro_rules! compose {
	(@call $builder:ident; $key:ident : type $ty:ty) => {
		__compose_call!($builder; $key : type $ty);
	};
	(@call $builder:ident; $key:ident < $($g:ty),+ > : $value:expr) => {
		__compose_call!($builder; $key<$($g),+> : $value);
	};
	(@call $builder:ident; $key:ident : $value:expr) => {
		__compose_call!($builder; $key : $value);
	};

	(@entries $builder:ident; $key:ident : type $ty:ty $(, $($rest:tt)*)?) => {
		compose!(@call $builder; $key : type $ty);
		$(compose!(@entries $builder; $($rest)*);)?
	};
	(@entries $builder:ident; $key:ident < $($g:ty),+ > : $value:expr $(, $($rest:tt)*)?) => {
		compose!(@call $builder; $key<$($g),+> : $value);
		$(compose!(@entries $builder; $($rest)*);)?
	};
	(@entries $builder:ident; $key:ident : $value:expr $(, $($rest:tt)*)?) => {
		compose!(@call $builder; $key : $value);
		$(compose!(@entries $builder; $($rest)*);)?
	};
	(@entries $builder:ident;) => {};

	($variant_id:ident : $($rest:tt)*) => {{
		use $crate::builder::TypeBuilder as _;
		let mut __b: $crate::builder::FrameBuilder<_> = ::core::convert::Into::into($crate::Version::$variant_id);
		compose!(@entries __b; $($rest)*);
		__b.build()
	}};
}

/// Internal dispatcher for [`compose!`]; maps each key to its builder method.
#[doc(hidden)]
#[macro_export]
macro_rules! __compose_call {
	($builder:ident; id < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_id::<$($g),+>($value); };
	($builder:ident; id : $value:expr) => { $builder = $builder.with_id($value); };
	($builder:ident; order < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_order::<$($g),+>($value); };
	($builder:ident; order : $value:expr) => { $builder = $builder.with_order($value); };
	($builder:ident; message < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_message::<$($g),+>($value); };
	($builder:ident; message : $value:expr) => { $builder = $builder.with_message($value); };
	($builder:ident; message_integrity < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_message_hasher::<$($g),+>($value); };
	($builder:ident; message_integrity : $value:expr) => { $builder = $builder.with_message_hasher($value); };
	($builder:ident; frame_integrity : type $ty:ty) => { $builder = $builder.with_witness_hasher::<$ty>(); };
	($builder:ident; confidentiality < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_aead::<$($g),+>($value); };
	($builder:ident; confidentiality : $value:expr) => { $builder = $builder.with_aead($value); };
	($builder:ident; encryptor < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_encryptor::<$($g),+>($value); };
	($builder:ident; encryptor : $value:expr) => { $builder = $builder.with_encryptor($value); };
	($builder:ident; nonrepudiation < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_signer::<$($g),+>($value); };
	($builder:ident; nonrepudiation : $value:expr) => { $builder = $builder.with_signer($value); };
	($builder:ident; compactness < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_compression::<$($g),+>($value); };
	($builder:ident; compactness : $value:expr) => { $builder = $builder.with_compression($value); };
	($builder:ident; priority < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_priority::<$($g),+>($value); };
	($builder:ident; priority : $value:expr) => { $builder = $builder.with_priority($value); };
	($builder:ident; lifetime < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_lifetime::<$($g),+>($value); };
	($builder:ident; lifetime : $value:expr) => { $builder = $builder.with_lifetime($value); };
	($builder:ident; previous_frame < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_previous_hash::<$($g),+>($value); };
	($builder:ident; previous_frame : $value:expr) => { $builder = $builder.with_previous_hash($value); };
	($builder:ident; matrix < $($g:ty),+ > : $value:expr) => { $builder = $builder.with_matrix::<$($g),+>($value); };
	($builder:ident; matrix : $value:expr) => { $builder = $builder.with_matrix($value); };
	($builder:ident; $key:ident $($rest:tt)*) => {
		::core::compile_error!(::core::concat!("unknown builder key: ", ::core::stringify!($key)));
	};
}

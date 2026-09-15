//! The [`compose!`] frame-builder macro.

/// Builds a [`Frame`](crate::asn1::Frame) from named arguments.
///
/// The macro expands to [`FrameBuilder`](crate::builder::FrameBuilder) calls
/// followed by [`build`](crate::builder::TypeBuilder::build), and returns the
/// [`Result`](crate::error::Result) that `build` produces.
///
/// # Syntax
///
/// The first token names the [`Version`](crate::Version) variant. Comma
/// separated `key: value` pairs follow it, and a trailing comma is allowed.
/// Each key calls one builder method:
///
/// | Key | Builder method |
/// |---|---|
/// | `id` | [`with_id`](crate::builder::FrameBuilder::with_id) |
/// | `order` | [`with_order`](crate::builder::FrameBuilder::with_order) |
/// | `message` | [`with_message`](crate::builder::FrameBuilder::with_message) |
/// | `message_integrity<D>` | `with_message_hasher::<D>` |
/// | `frame_integrity: type D` | `with_witness_hasher::<D>` |
/// | `confidentiality` | `with_aead` |
/// | `encryptor<C, _>` | `with_encryptor::<C, _>` |
/// | `nonrepudiation<S, _>` | `with_signer::<S, _>` |
/// | `compactness` | `with_compression` |
/// | `priority` | `with_priority` |
/// | `lifetime` | `with_lifetime` |
/// | `previous_frame` | `with_previous_hash` |
/// | `matrix` | `with_matrix` |
///
/// An unknown key fails to compile.
///
/// # Example
///
/// ```
/// use tightbeam::der::Sequence;
/// use tightbeam::{compose, Beamable};
///
/// #[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
/// struct Ping {
///     count: u32,
/// }
///
/// let frame = compose! {
///     V0:
///         id: "ping-1",
///         order: 1_696_521_600,
///         message: Ping { count: 1 },
/// }?;
///
/// assert_eq!(frame.metadata().id(), b"ping-1");
/// assert_eq!(frame.metadata().order(), 1_696_521_600);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
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

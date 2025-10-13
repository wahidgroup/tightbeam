use quote::quote;

/// Configuration for a specific builder macro
pub struct MacroConfig {
	/// Name of the macro to generate (e.g., "compose")
	pub name: &'static str,
	/// Path to the builder type (e.g., "crate::builder::FrameBuilder")
	pub builder_path: &'static str,
	/// Whether the builder has generic parameters
	pub has_generics: bool,
	/// Optional variant enum path (e.g., "crate::Version")
	pub variant_enum: Option<&'static str>,
	/// Method mappings: (key, method_name, is_generic_only, is_required)
	pub methods: &'static [(&'static str, &'static str, bool, bool)],
}

/// Predefined builder configurations
pub const BUILDER_CONFIGS: &[MacroConfig] = &[MacroConfig {
	name: "compose",
	builder_path: "crate::builder::FrameBuilder",
	has_generics: true,
	variant_enum: Some("crate::Version"),
	methods: &[
		("id", "with_id", false, true),
		("order", "with_order", false, true),
		("message", "with_message", false, true),
		("message_integrity", "with_message_hasher", true, false),
		("frame_integrity", "with_witness_hasher", true, false),
		("confidentiality", "with_cipher", false, false),
		("nonrepudiation", "with_signer", false, false),
		("compactness", "with_compression", false, false),
		("priority", "with_priority", false, false),
		("lifetime", "with_lifetime", false, false),
		("previous_frame", "with_previous_hash", false, false),
		("matrix", "with_matrix", false, false),
	],
}];

/// Generate a builder macro from a configuration
pub fn generate_builder_macro(config: &MacroConfig) -> proc_macro2::TokenStream {
	let macro_name = syn::Ident::new(config.name, proc_macro2::Span::call_site());
	let helper_name = syn::Ident::new(&format!("__{}_call", config.name), proc_macro2::Span::call_site());

	// $crate-qualified paths
	let builder_rest = config.builder_path.strip_prefix("crate::").unwrap_or(config.builder_path);
	let builder_rest_path: syn::Path = syn::parse_str(builder_rest).unwrap();
	let builder_path_tokens = quote! { $crate::#builder_rest_path };

	let variant_path_tokens = if let Some(variant_enum) = config.variant_enum {
		let variant_rest = variant_enum.strip_prefix("crate::").unwrap_or(variant_enum);
		let variant_rest_path: syn::Path = syn::parse_str(variant_rest).unwrap();
		Some(quote! { $crate::#variant_rest_path })
	} else {
		None
	};

	// Build helper macro arms for each key
	let mut helper_arms = Vec::new();

	for (key, method, is_generic_only, _is_required) in config.methods {
		let key_ident = syn::Ident::new(key, proc_macro2::Span::call_site());
		let method_ident = syn::Ident::new(method, proc_macro2::Span::call_site());

		if *is_generic_only {
			helper_arms.push(quote! {
				($builder:ident; #key_ident : type $ty:ty) => {
					$builder = $builder.#method_ident::<$ty>();
				};
			});
		} else {
			helper_arms.push(quote! {
				($builder:ident; #key_ident < $($g:ty),+ > : $value:expr) => {
					$builder = $builder.#method_ident::<$($g),+>($value);
				};
			});
			helper_arms.push(quote! {
				($builder:ident; #key_ident : $value:expr) => {
					$builder = $builder.#method_ident($value);
				};
			});
		}
	}

	let builder_type = if config.has_generics {
		quote! { #builder_path_tokens<_> }
	} else {
		quote! { #builder_path_tokens }
	};

	// Generate helper macro that processes individual entries
	let helper_macro = quote! {
		#[doc(hidden)]
		#[macro_export]
		macro_rules! #helper_name {
			#(#helper_arms)*
			($builder:ident; $key:ident $($rest:tt)*) => {
				compile_error!(concat!("unknown builder key: ", stringify!($key)));
			};
		}
	};

	// Generate main macro - explicitly parse each entry pattern
	let main_macro = if let Some(variant) = &variant_path_tokens {
		quote! {
			#[macro_export]
			macro_rules! #macro_name {
				// Internal dispatcher
				(@call $builder:ident; $key:ident : type $ty:ty) => {
					$crate::#helper_name!($builder; $key : type $ty);
				};

				(@call $builder:ident; $key:ident < $($g:ty),+ > : $value:expr) => {
					$crate::#helper_name!($builder; $key<$($g),+> : $value);
				};

				(@call $builder:ident; $key:ident : $value:expr) => {
					$crate::#helper_name!($builder; $key : $value);
				};

				// Main entry - variant form
				($variant_id:ident : $($rest:tt)*) => {{
					use $crate::builder::TypeBuilder as _;
					let mut __b: #builder_type = ::core::convert::Into::into(#variant::$variant_id);
					$crate::#macro_name!(@entries __b; $($rest)*);
					__b.build()
				}};

				// Process entries - match explicit patterns
				(@entries $builder:ident; $key:ident : type $ty:ty $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key : type $ty);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident; $key:ident < $($g:ty),+ > : $value:expr $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key<$($g),+> : $value);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident; $key:ident : $value:expr $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key : $value);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident;) => {};
			}
		}
	} else {
		quote! {
			#[macro_export]
			macro_rules! #macro_name {
				(@call $builder:ident; $key:ident : type $ty:ty) => {
					$crate::#helper_name!($builder; $key : type $ty);
				};

				(@call $builder:ident; $key:ident < $($g:ty),+ > : $value:expr) => {
					$crate::#helper_name!($builder; $key<$($g),+> : $value);
				};

				(@call $builder:ident; $key:ident : $value:expr) => {
					$crate::#helper_name!($builder; $key : $value);
				};

				($($rest:tt)*) => {{
					use $crate::builder::TypeBuilder as _;
					let mut __b: #builder_type = ::core::default::Default::default();
					$crate::#macro_name!(@entries __b; $($rest)*);
					__b.build()
				}};

				(@entries $builder:ident; $key:ident : type $ty:ty $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key : type $ty);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident; $key:ident < $($g:ty),+ > : $value:expr $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key<$($g),+> : $value);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident; $key:ident : $value:expr $(, $($rest:tt)*)?) => {
					$crate::#macro_name!(@call $builder; $key : $value);
					$($crate::#macro_name!(@entries $builder; $($rest)*);)?
				};

				(@entries $builder:ident;) => {};
			}
		}
	};

	quote! {
		#helper_macro
		#main_macro
	}
}

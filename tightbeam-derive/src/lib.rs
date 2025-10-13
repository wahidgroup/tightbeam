//! Derive macro for TightBeam message types
//!
//! This crate provides the `#[derive(Beamable)]` macro that automatically
//! implements the `Message` trait for structs.

mod build;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Attribute, DeriveInput, Ident, Meta, Token};

fn has_flag(attrs: &[Attribute], name: &str) -> bool {
	for attr in attrs {
		if !attr.path().is_ident("beam") {
			continue;
		}
		if let Meta::List(list) = &attr.meta {
			// Parse the inner tokens as a comma‑separated list of identifiers.
			let parser = Punctuated::<Ident, Token![,]>::parse_terminated;
			if let Ok(idents) = parser.parse2(list.tokens.clone()) {
				for ident in idents {
					if ident == name {
						return true;
					}
				}
			}
		}
	}
	false
}

fn get_version_value(attrs: &[Attribute]) -> Option<syn::Ident> {
	for attr in attrs {
		if !attr.path().is_ident("beam") {
			continue;
		}
		if let Meta::List(list) = &attr.meta {
			let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
			if let Ok(metas) = parser.parse2(list.tokens.clone()) {
				for meta in metas {
					if let Meta::NameValue(nv) = meta {
						if nv.path.is_ident("min_version") {
							if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(lit_str), .. }) = &nv.value {
								return Some(syn::Ident::new(&lit_str.value(), lit_str.span()));
							}
						}
					}
				}
			}
		}
	}
	None
}

fn get_profile_value(attrs: &[Attribute]) -> Option<u8> {
	for attr in attrs {
		if !attr.path().is_ident("beam") {
			continue;
		}
		if let Meta::List(list) = &attr.meta {
			let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
			if let Ok(metas) = parser.parse2(list.tokens.clone()) {
				for meta in metas {
					if let Meta::NameValue(nv) = meta {
						if nv.path.is_ident("profile") {
							if let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit_int), .. }) = &nv.value {
								if let Ok(profile) = lit_int.base10_parse::<u8>() {
									return Some(profile);
								}
							}
						}
					}
				}
			}
		}
	}
	None
}

fn has_attr(attrs: &[Attribute], name: &str) -> bool {
	attrs.iter().any(|attr| attr.path().is_ident(name))
}

fn get_error_message(attrs: &[Attribute]) -> Option<String> {
	for attr in attrs {
		if attr.path().is_ident("error") {
			if let Meta::List(list) = &attr.meta {
				if let Ok(lit_str) = syn::parse2::<syn::LitStr>(list.tokens.clone()) {
					return Some(lit_str.value());
				}
			}
		}
	}
	None
}

/// Derive macro for implementing `Message`
///
/// This macro can be applied to any struct that implements the necessary
/// serialization traits (typically `der::Sequence`).
#[proc_macro_derive(Beamable, attributes(beam))]
pub fn derive_beamable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let name = &input.ident;

	let confidential = has_flag(&input.attrs, "confidential");
	let nonrep = has_flag(&input.attrs, "nonrepudiable");
	let compressed = has_flag(&input.attrs, "compressed");
	let prioritized = has_flag(&input.attrs, "prioritized");
	let min_version = get_version_value(&input.attrs);
	let profile = get_profile_value(&input.attrs);

	// Profile-based security requirements
	let (profile_confidential, profile_nonrep, profile_min_version) = match profile {
		Some(1) => (true, true, Some(syn::Ident::new("V1", name.span()))),
		Some(2) => (true, true, Some(syn::Ident::new("V1", name.span()))),
		Some(p) if p > 2 => (false, false, None),
		_ => (false, false, None),
	};

	// Apply profile requirements (override individual flags)
	let final_confidential = profile_confidential || confidential;
	let final_nonrep = profile_nonrep || nonrep;
	let final_min_version = profile_min_version.or(min_version);

	let mut feature_checks = Vec::new();

	if final_confidential && !cfg!(feature = "aead") {
		feature_checks.push(quote! {
			compile_error!(concat!(
				"Message type `", stringify!(#name), "` is marked as confidential ",
				"but the `aead` feature is not enabled. ",
				"Enable the feature in Cargo.toml: features = [\"aead\"]"
			));
		});
	}

	if final_nonrep && !cfg!(feature = "signature") {
		feature_checks.push(quote! {
			compile_error!(concat!(
				"Message type `", stringify!(#name), "` is marked as non-repudiable ",
				"but the `signature` feature is not enabled. ",
				"Enable the feature in Cargo.toml: features = [\"signature\"]"
			));
		});
	}

	if compressed && !cfg!(feature = "compress") {
		feature_checks.push(quote! {
			compile_error!(concat!(
				"Message type `", stringify!(#name), "` is marked as compressed ",
				"but the `compress` feature is not enabled. ",
				"Enable the feature in Cargo.toml: features = [\"compress\"]"
			));
		});
	}

	let min_version_value = if let Some(version) = final_min_version {
		quote! { ::tightbeam::Version::#version }
	} else {
		quote! { ::tightbeam::Version::V0 }
	};

	let expanded = quote! {
		const _: () = {
			#(#feature_checks)*
		};

		impl ::tightbeam::Message for #name {
			const MUST_BE_CONFIDENTIAL: bool = #final_confidential;
			const MUST_BE_NON_REPUDIABLE: bool = #final_nonrep;
			const MUST_BE_COMPRESSED: bool = #compressed;
			const MUST_BE_PRIORITIZED: bool = #prioritized;
			const MIN_VERSION: ::tightbeam::Version = #min_version_value;
		}
	};

	TokenStream::from(expanded)
}

/// Derive macro for implementing flag enum traits
///
/// This macro automatically adds the necessary attributes and trait
/// implementations for flag enums used with the TightBeam flag system.
#[proc_macro_derive(Flaggable)]
pub fn derive_flaggable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let name = &input.ident;
	let name_str = name.to_string();

	let expanded = quote! {
		impl From<#name> for u8 {
			fn from(val: #name) -> u8 {
				val as u8
			}
		}

		impl PartialEq<u8> for #name {
			fn eq(&self, other: &u8) -> bool {
				(*self as u8) == *other
			}
		}

		impl #name {
			pub const TYPE_NAME: &'static str = #name_str;
		}
	};

	TokenStream::from(expanded)
}

/// Derive macro for implementing error traits with automatic Display and From
/// implementations
///
/// This macro automatically implements `Display`, `Error`, and `From`
/// conversions for error enums, similar to the `snafu` crate.
///
/// # Attributes
///
/// - `#[error("format string")]` - Specifies the display format for the variant
/// - `#[from]` - Automatically implements `From` for the wrapped type
#[proc_macro_derive(Errorizable, attributes(error, from))]
pub fn derive_errorizable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	let name = &input.ident;

	let data_enum = match &input.data {
		syn::Data::Enum(data) => data,
		_ => {
			return syn::Error::new_spanned(&input, "Errorizable can only be derived for enums")
				.to_compile_error()
				.into();
		}
	};

	let mut display_arms = Vec::new();
	let mut from_impls = Vec::new();

	for variant in &data_enum.variants {
		let variant_name = &variant.ident;

		// Get the error message from #[error("...")] attribute
		let error_msg = get_error_message(&variant.attrs);
		let has_from = has_attr(&variant.attrs, "from");

		// Build the display match arm based on variant fields
		match &variant.fields {
			syn::Fields::Unnamed(fields) => {
				let field_count = fields.unnamed.len();
				let field_bindings: Vec<_> = (0..field_count)
					.map(|i| syn::Ident::new(&format!("f{}", i), variant_name.span()))
					.collect();

				if let Some(msg) = error_msg {
					// Check if format string contains field accessors like {expected} or {received}
					if msg.contains("{expected") || msg.contains("{received") {
						// Assume single field with .expected and .received properties
						display_arms.push(quote! {
							#name::#variant_name(ref f0) => {
								write!(f, #msg, expected = f0.expected, received = f0.received)
							}
						});
					} else {
						display_arms.push(quote! {
							#name::#variant_name(#(ref #field_bindings),*) => {
								write!(f, #msg, #(#field_bindings),*)
							}
						});
					}
				} else {
					display_arms.push(quote! {
						#name::#variant_name(#(ref #field_bindings),*) => {
							write!(f, "{}", stringify!(#variant_name))
						}
					});
				}

				// Generate From impl if #[from] is present and there's exactly one field
				if has_from && field_count == 1 {
					let field_type = &fields.unnamed.first().unwrap().ty;
					from_impls.push(quote! {
						impl From<#field_type> for #name {
							fn from(err: #field_type) -> Self {
								#name::#variant_name(err)
							}
						}

						impl From<#name> for #field_type {
							fn from(err: #name) -> Self {
								match err {
									#name::#variant_name(inner) => inner,
									_ => panic!("Cannot convert {} to {}", stringify!(#name), stringify!(#field_type)),
								}
							}
						}
					});
				}
			}
			syn::Fields::Named(fields) => {
				let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

				if let Some(msg) = error_msg {
					display_arms.push(quote! {
						#name::#variant_name { #(ref #field_names),* } => {
							write!(f, #msg, #(#field_names = #field_names),*)
						}
					});
				} else {
					display_arms.push(quote! {
						#name::#variant_name { .. } => {
							write!(f, "{}", stringify!(#variant_name))
						}
					});
				}
			}
			syn::Fields::Unit => {
				if let Some(msg) = error_msg {
					display_arms.push(quote! {
						#name::#variant_name => write!(f, #msg)
					});
				} else {
					display_arms.push(quote! {
						#name::#variant_name => write!(f, "{}", stringify!(#variant_name))
					});
				}
			}
		}
	}

	let expanded = quote! {
		impl core::fmt::Display for #name {
			fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
				match self {
					#(#display_arms,)*
				}
			}
		}

		impl core::error::Error for #name {}

		#(#from_impls)*
	};

	TokenStream::from(expanded)
}

/// Generate all configured builder macros
#[proc_macro]
pub fn generate_builders(_input: TokenStream) -> TokenStream {
	let macros: Vec<_> = build::BUILDER_CONFIGS.iter().map(build::generate_builder_macro).collect();

	let output = quote! {
		#(#macros)*
	};

	output.into()
}

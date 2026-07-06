//! Derive macro for TightBeam message types
//!
//! This crate provides the `#[derive(Beamable)]` macro that automatically
//! implements the `Message` trait for structs.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Attribute, DeriveInput, Meta, Token};

/// Apply `f` to every meta item found inside `#[beam(...)]` attributes.
///
/// `#[beam(...)]` mixes bare identifiers (`confidential`) with name-value
/// pairs (`min_version = "V1"`) and lists (`profile(MyProfile)`), so every
/// reader shares this parse-and-walk shell instead of re-implementing it.
fn for_each_beam_meta<F>(attrs: &[Attribute], mut f: F) -> syn::Result<()>
where
	F: FnMut(Meta) -> syn::Result<()>,
{
	for attr in attrs {
		if !attr.path().is_ident("beam") {
			continue;
		}

		let Meta::List(list) = &attr.meta else {
			continue;
		};

		let parser = Punctuated::<Meta, Token![,]>::parse_terminated;
		for meta in parser.parse2(list.tokens.clone())? {
			f(meta)?;
		}
	}

	Ok(())
}

fn has_flag(attrs: &[Attribute], name: &str) -> syn::Result<bool> {
	let mut found = false;
	for_each_beam_meta(attrs, |meta| {
		if let Meta::Path(path) = &meta {
			if path.is_ident(name) {
				found = true;
			}
		}

		Ok(())
	})?;

	Ok(found)
}

fn get_version_value(attrs: &[Attribute]) -> syn::Result<Option<syn::Ident>> {
	let mut version = None;
	for_each_beam_meta(attrs, |meta| {
		let Meta::NameValue(nv) = &meta else {
			return Ok(());
		};

		if !nv.path.is_ident("min_version") {
			return Ok(());
		}

		let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Str(lit_str), .. }) = &nv.value else {
			return Err(syn::Error::new_spanned(
				&nv.value,
				"min_version expects a string literal, e.g. min_version = \"V1\"",
			));
		};

		let value = lit_str.value();
		if syn::parse_str::<syn::Ident>(&value).is_err() {
			return Err(syn::Error::new_spanned(
				lit_str,
				format!("`{value}` is not a valid version identifier (expected e.g. \"V1\")"),
			));
		}

		version = Some(syn::Ident::new(&value, lit_str.span()));
		Ok(())
	})?;
	Ok(version)
}

fn get_profile_value(attrs: &[Attribute]) -> syn::Result<Option<(u8, proc_macro2::Span)>> {
	let mut profile = None;
	for_each_beam_meta(attrs, |meta| {
		let Meta::NameValue(nv) = &meta else {
			return Ok(());
		};

		if !nv.path.is_ident("profile") {
			return Ok(());
		}

		let syn::Expr::Lit(syn::ExprLit { lit: syn::Lit::Int(lit_int), .. }) = &nv.value else {
			return Err(syn::Error::new_spanned(
				&nv.value,
				"numeric profile expects an integer literal, e.g. profile = 1",
			));
		};

		profile = Some((lit_int.base10_parse::<u8>()?, lit_int.span()));
		Ok(())
	})?;

	Ok(profile)
}

fn get_profile_type(attrs: &[Attribute]) -> syn::Result<Option<syn::Type>> {
	let mut profile = None;
	for_each_beam_meta(attrs, |meta| {
		let Meta::List(profile_list) = &meta else {
			return Ok(());
		};

		if !profile_list.path.is_ident("profile") {
			return Ok(());
		}

		profile = Some(syn::parse2::<syn::Type>(profile_list.tokens.clone())?);
		Ok(())
	})?;

	Ok(profile)
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
///
/// # Attributes
///
/// All configuration lives in a `#[beam(...)]` attribute:
///
/// - `confidential`, `nonrepudiable`, `compressed`, `prioritized`,
///   `message_integrity`, `frame_integrity` - set the corresponding
///   `MUST_*` constant to `true`
/// - `min_version = "V1"` - minimum protocol version for the type
/// - `profile(MyProfile)` - pin the type to a `SecurityProfile`; the digest,
///   AEAD, and signature OIDs used by the builder are then enforced at
///   compile time
/// - `profile = N` - numeric shorthand for a predefined security level:
///
///   | N | Profile  | Effect                                          |
///   |---|----------|-------------------------------------------------|
///   | 1 | FIPS     | confidential + non-repudiable, `MIN_VERSION` V1 |
///   | 2 | Standard | confidential + non-repudiable, `MIN_VERSION` V1 |
///
///   Any other number is rejected at compile time. `profile = N` and
///   `profile(Type)` are mutually exclusive.
#[proc_macro_derive(Beamable, attributes(beam))]
pub fn derive_beamable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	expand_beamable(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

fn expand_beamable(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
	let name = &input.ident;

	let confidential = has_flag(&input.attrs, "confidential")?;
	let nonrep = has_flag(&input.attrs, "nonrepudiable")?;
	let compressed = has_flag(&input.attrs, "compressed")?;
	let prioritized = has_flag(&input.attrs, "prioritized")?;
	let message_integrity = has_flag(&input.attrs, "message_integrity")?;
	let frame_integrity = has_flag(&input.attrs, "frame_integrity")?;
	let min_version = get_version_value(&input.attrs)?;
	let profile_value = get_profile_value(&input.attrs)?;
	let profile_type = get_profile_type(&input.attrs)?;

	// Validate that we don't have both numeric and type-based profiles
	if profile_value.is_some() && profile_type.is_some() {
		return Err(syn::Error::new_spanned(
			input,
			"Cannot specify both numeric profile (= N) and type-based profile (Type) simultaneously",
		));
	}

	// Profile-based security requirements (see the profile table in the
	// derive rustdoc). FIPS and Standard currently impose identical
	// requirements; they are kept distinct as wire-visible policy levels.
	let (profile_confidential, profile_nonrep, profile_min_version) = match profile_value {
		Some((1 | 2, _)) => (true, true, Some(syn::Ident::new("V1", name.span()))),
		Some((n, span)) => {
			return Err(syn::Error::new(
				span,
				format!("unknown numeric profile `{n}`; known profiles: 1 (FIPS), 2 (Standard)"),
			));
		}
		None => (false, false, None),
	};

	// Apply profile requirements (override individual flags)
	let final_confidential = profile_confidential || confidential;
	let final_nonrep = profile_nonrep || nonrep;
	let final_min_version = profile_min_version.or(min_version);
	let final_message_integrity = message_integrity;
	let final_frame_integrity = frame_integrity;

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

	if (final_message_integrity || final_frame_integrity) && !cfg!(feature = "digest") {
		feature_checks.push(quote! {
			compile_error!(concat!(
				"Message type `", stringify!(#name), "` is marked as requiring message integrity ",
				"but the `digest` feature is not enabled. ",
				"Enable the feature in Cargo.toml: features = [\"digest\"]"
			));
		});
	}

	let min_version_value = if let Some(version) = final_min_version {
		quote! { ::tightbeam::Version::#version }
	} else {
		quote! { ::tightbeam::Version::V0 }
	};

	// `Message::Profile` is gated behind tightbeam's `crypto` feature, so the
	// associated-type definition is emitted through `__tb_if_crypto!`, which is
	// resolved in tightbeam's feature context rather than the consumer's.
	let profile_type_impl = if let Some(profile_ty) = &profile_type {
		quote! {
			const HAS_PROFILE: bool = true;
			::tightbeam::__tb_if_crypto! { type Profile = #profile_ty; }
		}
	} else {
		// Always define HAS_PROFILE, even when false (needed for checker trait impls)
		quote! {
			const HAS_PROFILE: bool = false;
			::tightbeam::__tb_if_crypto! { type Profile = ::tightbeam::crypto::profiles::TightbeamProfile; }
		}
	};

	// Generate checker trait implementations for compile-time OID validation
	// When HAS_PROFILE = true: generates impls ONLY for the matching OID type from the profile (compile-time enforcement)
	// When HAS_PROFILE = false: generates generic impls for all OID types (no enforcement, allows any)
	// All types using #[derive(Beamable)] get these impls - types not using derive must implement manually
	let oid_validation_helpers = if let Some(profile_ty) = &profile_type {
		// We know the profile type, so we can reference its associated types directly
		// ONLY implement for the exact OID types from the profile - wrong OIDs will fail to compile
		quote! {
			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_digest! {
				impl ::tightbeam::builder::private::SealedDigestOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::DigestOid> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl ::tightbeam::builder::CheckDigestOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::DigestOid> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }

			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_aead! {
				impl ::tightbeam::builder::private::SealedAeadOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::AeadOid> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl ::tightbeam::builder::CheckAeadOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::AeadOid> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }

			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_signature! {
				impl ::tightbeam::builder::private::SealedSignatureOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::SignatureAlg> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl ::tightbeam::builder::CheckSignatureOid<<#profile_ty as ::tightbeam::crypto::profiles::SecurityProfile>::SignatureAlg> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }
		}
	} else {
		// When HAS_PROFILE = false, generate generic impls for all OID types (no enforcement)
		// These allow FrameBuilder methods to work for types without profiles
		quote! {
			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_digest! {
				impl<D: ::tightbeam::der::oid::AssociatedOid> ::tightbeam::builder::private::SealedDigestOid<D> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl<D: ::tightbeam::der::oid::AssociatedOid> ::tightbeam::builder::CheckDigestOid<D> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }

			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_aead! {
				impl<C: ::tightbeam::der::oid::AssociatedOid> ::tightbeam::builder::private::SealedAeadOid<C> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl<C: ::tightbeam::der::oid::AssociatedOid> ::tightbeam::builder::CheckAeadOid<C> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }

			::tightbeam::__tb_if_builder! { ::tightbeam::__tb_if_signature! {
				impl<S: ::tightbeam::crypto::sign::SignatureAlgorithmIdentifier> ::tightbeam::builder::private::SealedSignatureOid<S> for #name
				where
					#name: ::tightbeam::Message,
				{}

				impl<S: ::tightbeam::crypto::sign::SignatureAlgorithmIdentifier> ::tightbeam::builder::CheckSignatureOid<S> for #name
				where
					#name: ::tightbeam::Message,
				{
					const RESULT: () = ();
				}
			} }
		}
	};

	Ok(quote! {
		const _: () = {
			#(#feature_checks)*
		};

		impl ::tightbeam::Message for #name {
			const MUST_BE_CONFIDENTIAL: bool = #final_confidential;
			const MUST_BE_NON_REPUDIABLE: bool = #final_nonrep;
			const MUST_HAVE_MESSAGE_INTEGRITY: bool = #final_message_integrity;
			const MUST_HAVE_FRAME_INTEGRITY: bool = #final_frame_integrity;
			const MUST_BE_COMPRESSED: bool = #compressed;
			const MUST_BE_PRIORITIZED: bool = #prioritized;
			const MIN_VERSION: ::tightbeam::Version = #min_version_value;
			#profile_type_impl
		}

		#oid_validation_helpers
	})
}

/// Derive macro for implementing flag enum traits
///
/// This macro automatically adds the necessary attributes and trait
/// implementations for flag enums used with the TightBeam flag system.
///
/// The target must be a fieldless enum: the generated conversions cast
/// variants with `as u8`, which only exists for C-like enums.
#[proc_macro_derive(Flaggable)]
pub fn derive_flaggable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	expand_flaggable(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

fn expand_flaggable(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
	let name = &input.ident;
	let name_str = name.to_string();

	let syn::Data::Enum(data_enum) = &input.data else {
		return Err(syn::Error::new_spanned(
			input,
			"Flaggable can only be derived for fieldless enums",
		));
	};

	for variant in &data_enum.variants {
		if !matches!(variant.fields, syn::Fields::Unit) {
			return Err(syn::Error::new_spanned(
				variant,
				"Flaggable requires a fieldless enum: variants with fields cannot be cast to u8",
			));
		}
	}

	Ok(quote! {
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
	})
}

/// Whether a type is (by name) the crate's paired received/expected error,
/// whose display formatting uses `{expected}`/`{received}` field accessors.
fn is_received_expected_error(ty: &syn::Type) -> bool {
	if let syn::Type::Path(type_path) = ty {
		if let Some(segment) = type_path.path.segments.last() {
			return segment.ident == "ReceivedExpectedError";
		}
	}
	false
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
/// - `#[source]` - Reports the wrapped value through `Error::source`
#[proc_macro_derive(Errorizable, attributes(error, from, source))]
pub fn derive_errorizable(input: TokenStream) -> TokenStream {
	let input = parse_macro_input!(input as DeriveInput);
	expand_errorizable(&input).unwrap_or_else(syn::Error::into_compile_error).into()
}

fn expand_errorizable(input: &DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
	let name = &input.ident;

	let syn::Data::Enum(data_enum) = &input.data else {
		return Err(syn::Error::new_spanned(input, "Errorizable can only be derived for enums"));
	};

	let mut display_arms = Vec::new();
	let mut from_impls = Vec::new();
	let mut source_arms = Vec::new();

	for variant in &data_enum.variants {
		let variant_name = &variant.ident;
		let variant_cfgs: Vec<_> = variant.attrs.iter().filter(|attr| attr.path().is_ident("cfg")).collect();

		// Get the error message from #[error("...")] attribute
		let error_msg = get_error_message(&variant.attrs);
		let has_from = has_attr(&variant.attrs, "from");
		let has_source = has_attr(&variant.attrs, "source");

		if has_source && !matches!(&variant.fields, syn::Fields::Unnamed(fields) if fields.unnamed.len() == 1) {
			return Err(syn::Error::new_spanned(
				variant,
				"#[source] requires a tuple variant with exactly one field",
			));
		}

		// Build the display match arm based on variant fields
		match &variant.fields {
			syn::Fields::Unnamed(fields) => {
				let field_count = fields.unnamed.len();
				let field_bindings: Vec<_> = (0..field_count)
					.map(|i| syn::Ident::new(&format!("f{i}"), variant_name.span()))
					.collect();

				// `{expected}`/`{received}` accessors are only meaningful on
				// a `ReceivedExpectedError` wrapper. Every other tuple
				// variant formats positionally. Gating on the field type
				// keeps unrelated messages containing the literal
				// `{expected` from mis-expanding.
				let formats_by_accessor = field_count == 1
					&& fields
						.unnamed
						.first()
						.is_some_and(|field| is_received_expected_error(&field.ty))
					&& error_msg
						.as_ref()
						.is_some_and(|msg| msg.contains("{expected") || msg.contains("{received"));

				if let Some(msg) = error_msg {
					if formats_by_accessor {
						display_arms.push(quote! {
							#(#variant_cfgs)*
							#name::#variant_name(ref f0) => {
								write!(f, #msg, expected = f0.expected, received = f0.received)
							}
						});
					} else {
						display_arms.push(quote! {
							#(#variant_cfgs)*
							#name::#variant_name(#(ref #field_bindings),*) => {
								write!(f, #msg, #(#field_bindings),*)
							}
						});
					}
				} else {
					display_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name(#(ref #field_bindings),*) => {
							write!(f, "{}", stringify!(#variant_name))
						}
					});
				}

				// Generate From impl if #[from] is present and there's exactly one field
				if has_from && field_count == 1 {
					if let Some(field) = fields.unnamed.first() {
						let field_type = &field.ty;
						from_impls.push(quote! {
							#(#variant_cfgs)*
							impl From<#field_type> for #name {
								fn from(err: #field_type) -> Self {
									#name::#variant_name(err)
								}
							}
						});
					}
				}

				// Wrapper variants preserve their cause chain (C-GOOD-ERR).
				if has_source {
					source_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name(ref f0) => Some(f0),
					});
				}
			}
			syn::Fields::Named(fields) => {
				let field_names: Vec<_> = fields.named.iter().map(|f| &f.ident).collect();

				if let Some(msg) = error_msg {
					display_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name { #(ref #field_names),* } => {
							write!(f, #msg, #(#field_names = #field_names),*)
						}
					});
				} else {
					display_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name { .. } => {
							write!(f, "{}", stringify!(#variant_name))
						}
					});
				}
			}
			syn::Fields::Unit => {
				if let Some(msg) = error_msg {
					display_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name => write!(f, #msg)
					});
				} else {
					display_arms.push(quote! {
						#(#variant_cfgs)*
						#name::#variant_name => write!(f, "{}", stringify!(#variant_name))
					});
				}
			}
		}
	}

	// `source()` requires each wrapped type to implement `Error`; some
	// dependencies (e.g. `rand_core`) only do so with `std`, so the method
	// is emitted through tightbeam's `std`-gated delegation macro.
	let source_impl = if source_arms.is_empty() {
		quote! {}
	} else {
		quote! {
			::tightbeam::__tb_if_std! {
				fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
					#[allow(unreachable_patterns)]
					match self {
						#(#source_arms)*
						_ => None,
					}
				}
			}
		}
	};

	Ok(quote! {
		impl core::fmt::Display for #name {
			fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
				match self {
					#(#display_arms,)*
				}
			}
		}

		impl core::error::Error for #name {
			#source_impl
		}

		#(#from_impls)*
	})
}

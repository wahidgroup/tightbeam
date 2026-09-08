//! Feature-delegation helpers for the `client!`/`server!` macros.
//!
//! `#[cfg(feature = "...")]` written inside a `macro_rules!` body is evaluated
//! in the crate that *invokes* the macro, not in the crate that *defines* it.

/// Emits the body when `std` is on, and nothing when it is not.
///
/// The only consumer is generated: `Errorizable` wraps the `source` method in
/// this so a `no_std` build gets an impl without it.
///
/// A form whose whole result is the body wants [`__tb_require_std`] instead.
#[cfg(feature = "std")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_std {
	// Associated-item form: emits the tokens as-is (e.g. a method with a
	// `self` receiver, which the `item` fragment cannot parse).
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "std"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_std {
	($($body:tt)*) => {};
}

/// Emits the body when `std` is on, and refuses to compile when it is not.
///
/// A macro form whose whole result is the body has no correct empty expansion:
/// a `server!` or `client! connect` arm that expanded to `()` would hand the
/// consumer a listener that never listens.
#[cfg(feature = "std")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_require_std {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "std"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_require_std {
	($($body:tt)*) => {
		::core::compile_error!("this macro form requires the `std` feature of tightbeam")
	};
}

#[cfg(feature = "tokio")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_tokio {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(feature = "tokio"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_tokio {
	({ $($body:tt)* }) => {{}};
}

// Harness-feature delegation for `tb_scenario!`. The generated scenario body
// runs in the consumer's crate, where tightbeam's feature names do not exist,
// so a `#[cfg(feature = "testing-csp")]` written into the expansion would
// silently drop the verification it guards.
#[cfg(feature = "testing-csp")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_csp {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(feature = "testing-csp"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_csp {
	({ $($body:tt)* }) => {{}};
}

#[cfg(feature = "testing-fdr")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(feature = "testing-fdr"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr {
	({ $($body:tt)* }) => {{}};
}

#[cfg(all(feature = "testing-fdr", feature = "testing-timing"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr_timing {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(all(feature = "testing-fdr", feature = "testing-timing")))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr_timing {
	({ $($body:tt)* }) => {{}};
}

#[cfg(feature = "builder")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_builder {
	({ $($body:tt)* }) => { { $($body)* } };
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "builder"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_builder {
	({ $($body:tt)* }) => {{}};
	($($item:item)*) => {};
}

#[cfg(feature = "crypto")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_crypto {
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "crypto"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_crypto {
	($($item:item)*) => {};
}

#[cfg(feature = "digest")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_digest {
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "digest"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_digest {
	($($item:item)*) => {};
}

#[cfg(feature = "aead")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_aead {
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "aead"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_aead {
	($($item:item)*) => {};
}

#[cfg(feature = "signature")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_signature {
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "signature"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_signature {
	($($item:item)*) => {};
}

// Both alternatives are statement sequences and every call site is in
// expression position, so the chosen branch is emitted as a block.
#[cfg(feature = "builder")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_builder {
	({ $($with_builder:tt)* } { $($without_builder:tt)* }) => {{ $($with_builder)* }};
}

#[cfg(not(feature = "builder"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_builder {
	({ $($with_builder:tt)* } { $($without_builder:tt)* }) => {{ $($without_builder)* }};
}

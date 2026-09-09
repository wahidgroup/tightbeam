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
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "tokio"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_tokio {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(feature = "testing-timing")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_timing {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "testing-timing"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_timing {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(feature = "testing-schedulability")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_schedulability {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "testing-schedulability"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_schedulability {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(feature = "testing-fault")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fault {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "testing-fault"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fault {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(feature = "instrument")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_instrument {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "instrument"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_instrument {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

// Picks one of two statement sequences on the `testing-timing` feature.
//
// A select takes both halves in one call. Delegating only the positive half
// and leaving a `#[cfg(not(...))]` twin behind emits both in a consumer.
#[cfg(feature = "testing-timing")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_timing {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($enabled)* };
}

#[cfg(not(feature = "testing-timing"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_timing {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($disabled)* };
}

// Picks one of two item sequences on the `tokio` feature.
//
// A select takes both halves in one call. Delegating only the positive half
// and leaving a `#[cfg(not(...))]` twin behind emits both in a consumer.
#[cfg(feature = "tokio")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_tokio {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($enabled)* };
}

#[cfg(not(feature = "tokio"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_tokio {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($disabled)* };
}

// Picks one of two statement sequences on the `testing-fault` feature.
//
// Unlike the `__tb_if_*` helpers this emits the chosen tokens bare rather than
// wrapped in a block, because both alternatives are `let` bindings the
// surrounding code goes on to use, and one of them borrows a temporary whose
// lifetime a block would end.
#[cfg(feature = "testing-fault")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_fault {
	({ $($with_fault:tt)* } { $($without_fault:tt)* }) => { $($with_fault)* };
}

#[cfg(not(feature = "testing-fault"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_fault {
	({ $($with_fault:tt)* } { $($without_fault:tt)* }) => { $($without_fault)* };
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
	// Item form: an `impl` block cannot be produced by the expression form.
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "testing-csp"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_csp {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(feature = "testing-fdr")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(feature = "testing-fdr"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
}

#[cfg(all(feature = "testing-fdr", feature = "testing-timing"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr_timing {
	({ $($body:tt)* }) => { { $($body)* } };
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(all(feature = "testing-fdr", feature = "testing-timing")))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_fdr_timing {
	({ $($body:tt)* }) => {{}};
	($($body:tt)*) => {};
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

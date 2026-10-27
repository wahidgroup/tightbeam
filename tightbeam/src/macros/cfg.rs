//! The feature-delegation macros of the `client!`, `server!`, and test macros.
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
	// The associated-item form emits the tokens as they are, such as a method
	// with a `self` receiver, which the `item` fragment cannot parse.
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

// Picks one of two statement sequences on the `testing-schedulability`
// feature.
//
// A select takes both halves in one call, so a spec form whose feature is off
// reaches the half that refuses it.
#[cfg(feature = "testing-schedulability")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_schedulability {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($enabled)* };
}

#[cfg(not(feature = "testing-schedulability"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_testing_schedulability {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($disabled)* };
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

// Picks one of two statement sequences on the `instrument` feature.
//
// A select takes both halves in one call, so a spec form whose feature is off
// reaches the half that refuses it.
#[cfg(feature = "instrument")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_instrument {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($enabled)* };
}

#[cfg(not(feature = "instrument"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_instrument {
	({ $($enabled:tt)* } { $($disabled:tt)* }) => { $($disabled)* };
}

// Picks one of two statement sequences on the `testing-timing` feature.
//
// A select takes both halves in one call, because a consumer that receives
// a delegated positive half and a `#[cfg(not(...))]` twin emits both.
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
// A select takes both halves in one call, because a consumer that receives
// a delegated positive half and a `#[cfg(not(...))]` twin emits both.
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
// This select emits the chosen tokens bare, where the `__tb_if_*` macros wrap
// them in a block. Both alternatives are `let` bindings that later code uses,
// and one of them borrows a temporary whose lifetime a block would end.
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

// This macro delegates a harness feature of `tb_scenario!`. The generated
// scenario body runs in the consumer's crate, where tightbeam's feature names
// do not exist, so a `#[cfg(feature = "testing-csp")]` written into the
// expansion would silently drop the verification it guards.
#[cfg(feature = "testing-csp")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_testing_csp {
	({ $($body:tt)* }) => { { $($body)* } };
	// The item form emits an `impl` block, which the expression form cannot.
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
	(else { $($absent:tt)* }) => {};
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "digest"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_digest {
	(else { $($absent:tt)* }) => { $($absent)* };
	($($item:item)*) => {};
}

#[cfg(feature = "aead")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_aead {
	(else { $($absent:tt)* }) => {};
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "aead"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_aead {
	(else { $($absent:tt)* }) => { $($absent)* };
	($($item:item)*) => {};
}

#[cfg(feature = "signature")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_signature {
	(else { $($absent:tt)* }) => {};
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "signature"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_signature {
	(else { $($absent:tt)* }) => { $($absent)* };
	($($item:item)*) => {};
}

#[cfg(feature = "compress")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_compress {
	(else { $($absent:tt)* }) => {};
	($($item:item)*) => { $($item)* };
}

#[cfg(not(feature = "compress"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_compress {
	(else { $($absent:tt)* }) => { $($absent)* };
	($($item:item)*) => {};
}

/// Picks one of two `fn main` definitions on the `fuzzing` cfg.
///
/// - The choice follows an attribute instead of a `$crate` path, because a
///   `$crate` path expands to a call, and a call cannot put an item in the
///   consumer's crate root.
/// - The macro emits both halves, so the crate that AFL builds with `--cfg fuzzing` reads the flag.
///
/// Each half MUST be exactly one item: the attribute binds to the first item
/// it precedes.
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_fuzzing {
	({ $($under_fuzzing:tt)* } { $($smoke:tt)* }) => {
		#[cfg(fuzzing)]
		$($under_fuzzing)*

		#[cfg(not(fuzzing))]
		$($smoke)*
	};
}

/// Emits the body when tightbeam compiles its own unit tests.
#[cfg(test)]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_test {
	($($body:tt)*) => { $($body)* };
}

#[cfg(not(test))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_test {
	($($body:tt)*) => {};
}

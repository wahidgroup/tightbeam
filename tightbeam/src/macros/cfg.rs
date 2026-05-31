//! Feature-delegation helpers for the `client!`/`server!` macros.
//!
//! `#[cfg(feature = "…")]` written inside a `macro_rules!` body is evaluated
//! in the crate that *invokes* the macro, not in the crate that *defines* it.

#[cfg(feature = "std")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_std {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(feature = "std"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_std {
	({ $($body:tt)* }) => {{}};
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

#[cfg(feature = "builder")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_builder {
	({ $($body:tt)* }) => { { $($body)* } };
}

#[cfg(not(feature = "builder"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_if_builder {
	({ $($body:tt)* }) => {{}};
}

#[cfg(feature = "builder")]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_builder {
	({ $($with_builder:tt)* } { $($without_builder:tt)* }) => { $($with_builder)* };
}

#[cfg(not(feature = "builder"))]
#[macro_export]
#[doc(hidden)]
macro_rules! __tb_select_builder {
	({ $($with_builder:tt)* } { $($without_builder:tt)* }) => { $($without_builder)* };
}

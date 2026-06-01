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

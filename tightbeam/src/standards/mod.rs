pub mod error;

#[cfg(feature = "standards-iso")]
pub mod iso;
#[cfg(any(feature = "standards-rfc", feature = "logging"))]
pub mod rfc;

#[cfg(any(feature = "standards-rfc", feature = "logging"))]
pub use rfc::rfc5424;

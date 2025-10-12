pub mod error;

#[cfg(feature = "standards-iso")]
pub mod iso;
#[cfg(feature = "standards-rfc")]
pub mod rfc;

// Re-exports
// TODO First supported ISO standard
#[allow(unused_imports)]
#[cfg(feature = "standards-iso")]
pub use iso::*;
#[cfg(feature = "standards-rfc")]
pub use rfc::*;

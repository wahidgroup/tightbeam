// Error macro is always available
pub mod error;

// Builder-dependent macros
#[cfg(feature = "builder")]
pub mod emit;
#[cfg(feature = "builder")]
pub mod flags;
#[cfg(feature = "builder")]
pub mod policy;
#[cfg(feature = "builder")]
pub mod relay;
#[cfg(feature = "builder")]
pub mod server;

#[cfg(feature = "x509")]
pub mod x509;

// Error macro is always available
pub mod error;

// Feature-delegation helpers are always available
pub mod cfg;

// Builder-dependent macros
#[cfg(feature = "builder")]
pub mod emit;
#[cfg(feature = "builder")]
pub mod flags;
#[cfg(feature = "builder")]
pub mod policy;
#[cfg(feature = "builder")]
pub mod relay;
#[cfg(all(feature = "builder", feature = "transport"))]
pub mod server;

#[cfg(feature = "x509")]
pub mod x509;

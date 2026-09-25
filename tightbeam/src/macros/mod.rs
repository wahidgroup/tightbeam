// Error macro is always available

// Feature-delegation helpers are always available
pub mod cfg;

// Case-table tests, compiled for test builds and for a consumer that takes
// the testing surface deliberately.
#[cfg(any(test, feature = "testing"))]
pub mod cases;

// Builder-dependent macros
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

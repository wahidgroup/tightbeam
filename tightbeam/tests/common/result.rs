//! The result type of the fallible integration tests.

/// The result of a fallible test: an error of any type fails the test, and
/// its `Debug` names the cause.
///
/// The alias of the crate is `pub(crate)` under `cfg(test)`, so the
/// integration targets hold this one.
pub type TestResult = Result<(), Box<dyn core::error::Error>>;

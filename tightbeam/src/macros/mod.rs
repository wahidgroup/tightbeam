// The macro modules sit in groups, by the features that each one needs.

// The feature-delegation macros are always available.
pub mod cfg;

// The `From` and `TryFrom` generators are always available.
mod from;

// The generator of the audit names of a refusal lives here, and only the
// records of a refused handshake read those names.
#[cfg(all(
	feature = "instrument",
	any(feature = "transport-cms", feature = "transport-hpke")
))]
pub(crate) mod names;

// The case-table test macro compiles for test builds and for a consumer that
// takes the testing surface deliberately.
#[cfg(any(test, feature = "testing"))]
pub mod cases;

// These macro modules need `builder`, `server` also needs `transport`, and
// `x509` needs only its own feature.
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

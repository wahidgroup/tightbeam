// The macro modules sit in groups by the features each one needs.

// The feature-delegation macros are always available.
pub mod cfg;

// The `From` and `TryFrom` generators are always available.
mod from;

// The generator of the audit names of a refusal. The records of a refused
// handshake and the refusals of a colony gateway read those names.
#[cfg(any(
	feature = "colony",
	all(
		feature = "instrument",
		any(feature = "transport-cms", feature = "transport-hpke")
	)
))]
pub(crate) mod names;

// The case-table test macro builds for tests and for a consumer that opts
// into the testing surface.
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

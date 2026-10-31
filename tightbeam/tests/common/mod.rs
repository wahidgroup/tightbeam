//! The test helpers that the integration suites share.
//!
//! Each module holds the helpers of one concern, and the comment above its
//! declaration names that concern. A helper that one suite alone calls lives
//! in that suite, beside the type it extends.

// The result type of each fallible test. A test target of its own reaches it
// through a `#[path]` module of this one file.
pub mod result;

// The dedup book and the chain state, which the queue and the payment
// harnesses share under their own gates, and the test frames of the DTN and
// payment suites.
#[cfg(feature = "testing")]
pub mod dedup;

// The colony fixtures of the colony, payment, and seam suites.
#[cfg(feature = "colony")]
pub mod hive;

// The bounded waits of each suite that waits on another task.
#[cfg(feature = "tokio")]
pub mod poll;

// The manual clock that records each sleep a task starts on it.
#[cfg(all(feature = "testing", feature = "tokio"))]
pub mod clock;

// The trace constructor and readers of the instrumented suites.
#[cfg(feature = "instrument")]
pub mod trace;

// The CSP processes, the scheduler, and the explorer of the FDR and seam
// suites.
#[cfg(feature = "testing-fdr")]
pub mod csp;

// The gateway identities of the colony transport and federation suites.
#[cfg(feature = "testing")]
pub mod x509;

// The key materials, trust stores, handshake configs, and authorizers of the
// transport, security, colony, and seam suites.
#[cfg(feature = "testing")]
pub mod security;

// The transport fixtures of the transport, security, colony, and seam suites.
#[cfg(all(
	feature = "transport-hpke",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]
pub mod transport;

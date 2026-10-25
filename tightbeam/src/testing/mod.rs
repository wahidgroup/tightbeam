//! The testing module gathers the test submodules and re-exports their types.
//!
//! Its demo spec uses the declarative macros, so a new declarative API that
//! fails to expand shows its compile error here first.

// The fixture constructors take fixed inputs that are valid by construction,
// and a fixture that cannot build must abort the test run with a stated
// invariant (`expect`). An index or an integer operation outside its range
// aborts the run the same way.
#![allow(
	clippy::expect_used,
	clippy::panic,
	clippy::unreachable,
	clippy::todo,
	clippy::unimplemented,
	clippy::indexing_slicing,
	clippy::arithmetic_side_effects
)]

pub mod assertions;
pub mod config;
pub mod env;
pub mod error;
pub mod fdr;
pub mod fixtures;
pub mod macros;
pub mod result;
pub mod schedulability;
pub mod specs;
pub mod teardown;
pub mod vectors;

#[cfg(all(feature = "hpke", feature = "signature"))]
pub mod envelope;
#[cfg(feature = "testing-fault")]
pub mod fault;
#[cfg(feature = "testing-fmea")]
pub mod fmea;
#[cfg(feature = "testing-fuzz")]
pub mod fuzz;
#[cfg(all(feature = "testing-fuzz", feature = "colony"))]
pub mod routes;
#[cfg(feature = "testing-timing")]
pub mod timing;

pub use config::{
	AcceptedObserver, Expect, HookContext, RejectedObserver, ScenarioConfig, ScenarioConfigBuilder,
	ScenarioConfigError, TestHooks,
};
pub use env::{ClientEnv, ClusterEnv, HiveEnv, ServletEnv, SetupEnv, WorkerEnv};
pub use fixtures::{
	ConfidentialNonrepudiableNote, ConfidentialNote, ExpectedMatcher, IntegralNote, TestCertificate, TestDigest,
	TestFrame, TestKey, TestMessage,
};
pub use result::{ScenarioResult, ScenarioVerdict};
pub use specs::{Layer, SpecViolation, TBSpec, Violations};
pub use teardown::Teardown;
pub use vectors::unhex;

#[cfg(feature = "random")]
pub use vectors::SeededStream;

#[cfg(all(feature = "hpke", feature = "signature"))]
pub use envelope::EnvelopeRecipient;
#[cfg(feature = "testing-fault")]
pub use fault::{ProcessEvent, ProcessState};
#[cfg(feature = "testing-fdr")]
pub use fdr::{Decision, FdrConfig, FdrTraceExt, FdrVerdict, SchedulerModel, TraceProcessMode};
#[cfg(feature = "testing-fault")]
pub use fdr::{FaultModel, InjectedFaultRecord, InjectionStrategy};
#[cfg(feature = "signature")]
pub use fixtures::TestAttributes;
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub use fixtures::TestCertificateChain;
#[cfg(feature = "transport-cms")]
pub use fixtures::TestCmsServer;
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub use fixtures::TestIdentity;
#[cfg(feature = "colony")]
pub use fixtures::TestRumor;
#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub use fixtures::TestSigner;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub use fixtures::{Aes256Sha3_512Profile, Aes256Sha3_512Provider};
#[cfg(feature = "testing-fmea")]
pub use fmea::{FailureMode, FmeaConfig, FmeaReport, SeverityScale};

#[cfg(test)]
mod tests {
	use crate::exactly;
	use crate::testing::TBSpec;
	use crate::urn::Urn;

	const MESSAGE_RECEIVED: Urn<'static> = crate::urn!("test", "event:demo/message-received");

	crate::tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			assertions: [
				(MESSAGE_RECEIVED, exactly!(1))
			]
		}
	}

	#[test]
	fn build_demo_spec() {
		let s = DemoSpec::get(1, 0, 0).expect("version exists");
		assert_eq!(s.id(), "DemoSpec");
	}
}

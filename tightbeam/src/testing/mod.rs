//! Testing module orchestrator
//!
//! Aggregates submodules and provides demo macro usage to surface
//! compilation errors early when introducing new declarative APIs.

// Test-fixture surface: constructors take fixed, valid-by-construction
// inputs, and a fixture that cannot build must abort the test run with
// a stated invariant (`expect`).
#![allow(
	clippy::expect_used,
	clippy::panic,
	clippy::unreachable,
	clippy::todo,
	clippy::unimplemented
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

// Re-exports
pub use config::{
	AcceptedObserver, Expect, HookContext, RejectedObserver, ScenarioConfig, ScenarioConfigBuilder,
	ScenarioConfigError, TestHooks,
};
pub use env::{ClientEnv, ClusterEnv, HiveEnv, ServletEnv, SetupEnv, WorkerEnv};
pub use fixtures::{
	ConfidentialNonrepudiableNote, ConfidentialNote, ExpectedMatcher, IntegralNote, TestCertificate, TestDigest,
	TestFrame, TestKey, TestMessage, TestSigner,
};
pub use result::{ScenarioResult, ScenarioVerdict};
pub use specs::{Layer, SpecViolation, TBSpec, Violations};
pub use teardown::Teardown;

#[cfg(feature = "testing-fault")]
pub use fault::{ProcessEvent, ProcessState};
#[cfg(feature = "testing-fdr")]
pub use fdr::{Decision, FdrConfig, FdrTraceExt, FdrVerdict, SchedulerModel, TraceProcessMode};
#[cfg(feature = "testing-fault")]
pub use fdr::{FaultInjection, FaultModel, InjectedFaultRecord, InjectionStrategy};
#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub use fixtures::TestCertificateChain;
#[cfg(feature = "testing-fmea")]
pub use fmea::{FailureMode, FmeaConfig, FmeaReport, SeverityScale};

#[cfg(test)]
mod tests {
	use crate::exactly;
	use crate::testing::TBSpec;
	use crate::utils::urn::Urn;

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

//! Testing module orchestrator
//!
//! Aggregates submodules and provides demo macro usage to surface
//! compilation errors early when introducing new declarative APIs.

pub mod assertions;
pub mod config;
pub mod error;
pub mod export;
pub mod macros;
pub mod result;
pub mod specs;
pub mod trace;
pub mod utils;

#[cfg(feature = "testing-fault")]
pub mod fault;
#[cfg(feature = "testing-fdr")]
pub mod fdr;
#[cfg(feature = "testing-fmea")]
pub mod fmea;
#[cfg(feature = "testing-fuzz")]
pub mod fuzz;
#[cfg(feature = "testing-timing")]
pub mod schedulability;
#[cfg(feature = "testing-timing")]
pub mod timing;

// Re-exports
pub use config::{HookContext, ScenarioConf, ScenarioConfBuilder, TestHooks};
pub use export::ScenarioResultExport;
pub use result::ScenarioResult;
pub use specs::{verify_trace, SpecViolation, TBSpec};
pub use utils::*;

#[cfg(feature = "testing-fault")]
pub use fault::{ProcessEvent, ProcessState};
#[cfg(feature = "testing-fault")]
pub use fdr::FaultModel;
#[cfg(feature = "testing-fdr")]
pub use fdr::*;
#[cfg(feature = "testing-fmea")]
pub use fmea::{FailureMode, FmeaConfig, FmeaReport, SeverityScale};

#[cfg(test)]
mod tests {
	use crate::exactly;
	use crate::testing::TBSpec;

	crate::tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				("MessageReceived", exactly!(1))
			]
		}
	}

	#[test]
	fn build_demo_spec() {
		let s = DemoSpec::get(1, 0, 0).expect("version exists");
		assert_eq!(s.id(), "DemoSpec");
	}
}

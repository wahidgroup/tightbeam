//! Testing module orchestrator
//!
//! Aggregates submodules and provides demo macro usage to surface
//! compilation errors early when introducing new declarative APIs.

pub mod assertions;
pub mod macros;
pub mod specs;
pub mod trace;
pub mod utils;

pub use utils::*;

// Re-export commonly used items from specs module for convenience
pub use specs::{verify_trace, SpecViolation, TBSpec};

// Demo labels using tb_labels! macro (payload + non-payload)
crate::tb_labels! { pub enum TbDemoLabels { MessageReceived => payload, HandlerStart } }

#[cfg(test)]
mod tests {
	use crate::testing::TBSpec;

	crate::tb_assert_spec! {
		pub DemoSpec,
		V(1,0,0): {
			mode: Accept,
			gate: Accepted,
			assertions: [
				(HandlerStart, "MessageReceived", crate::exactly!(1))
			]
		}
	}

	#[test]
	fn build_demo_spec() {
		let s = DemoSpec::get(1, 0, 0).expect("version exists");
		assert_eq!(s.id(), "DemoSpec");
	}
}

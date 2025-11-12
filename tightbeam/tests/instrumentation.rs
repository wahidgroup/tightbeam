//! Integration tests for automatic instrumentation in testing framework
//!
//! Demonstrates Phase 2: tb_scenario! automatic instrumentation capture

#![cfg(feature = "testing")]
#![cfg(feature = "instrument")]

use tightbeam::testing::assertions::AssertionPhase;
use tightbeam::{tb_assert_spec, tb_scenario};

tb_assert_spec! {
	pub AutoInstrSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

tb_scenario! {
	name: test_auto_instrumentation_capture,
	spec: AutoInstrSpec,
	environment Bare {
		exec: |trace| {
			// Framework automatically initialized instrumentation before this
			trace.assert(AssertionPhase::HandlerStart, "test_event");

			Ok(())
		}
	},
	hooks {
		on_pass: |trace| {
			use tightbeam::instrumentation::TbEventKind;

			// Verify events were automatically captured
			assert!(!trace.instrument_events.is_empty(), "Should have captured events automatically");

			// Should have Start + our event + End
			let kinds: Vec<_> = trace.instrument_events.iter().map(|e| e.kind).collect();
			assert_eq!(kinds[0], TbEventKind::Start);
			assert_eq!(kinds[kinds.len() - 1], TbEventKind::End);

			// Verify our event was captured
			let has_event = trace.instrument_events
				.iter()
				.any(|e| e.label.as_deref() == Some("test_event"));
			assert!(has_event, "Should have captured test_event");
		},
		on_fail: |trace, _violations| {
			panic!("Should not fail: {:?}", trace.error);
		}
	}
}

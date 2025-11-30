//! Trace analysis tests demonstrating FdrTraceExt methods.
//!
//! This test demonstrates:
//! - Projection to observable/hidden event subsequences
//! - Acceptance set queries at specific states
//! - Refusal semantic queries

#![cfg(feature = "testing-fdr")]

use std::sync::Arc;
use tightbeam::testing::fdr::{FdrConfig, FdrTraceExt};
use tightbeam::testing::specs::csp::Process;
use tightbeam::testing::{ScenarioConf, TestHooks};
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

fn build_fdr_config(specs: Vec<Process>) -> FdrConfig {
	FdrConfig {
		seeds: 2,
		max_depth: 8,
		max_internal_run: 4,
		timeout_ms: 5000,
		specs,
		fail_fast: true,
		expect_failure: false,
		..Default::default()
	}
}

// ===== Trace Analysis Specification =====

tb_assert_spec! {
	pub TraceAnalysisSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("connect", exactly!(1)),
			("serialize", exactly!(1)),
			("encrypt", exactly!(1)),
			("request", exactly!(1)),
			("decrypt", exactly!(1)),
			("deserialize", exactly!(1)),
			("response", exactly!(1)),
			("disconnect", exactly!(1))
		]
	}
}

// ===== Simple Request-Response Process =====

tb_process_spec! {
	/// Simple request-response process with observable and hidden events.
	///
	/// Observable: connect, request, response, disconnect
	/// Hidden: serialize, encrypt, decrypt, deserialize
	pub SimpleRequestResponse,
	events {
		observable { "connect", "request", "response", "disconnect" }
		hidden { "serialize", "encrypt", "decrypt", "deserialize" }
	}
	states {
		Init => { "connect" => Connected },
		Connected => { "serialize" => Serialized },
		Serialized => { "encrypt" => Encrypted },
		Encrypted => { "request" => Sent },
		Sent => { "decrypt" => Decrypted },
		Decrypted => { "deserialize" => Deserialized },
		Deserialized => { "response" => Responded },
		Responded => { "disconnect" => Complete }
	}
	terminal { Complete }
}

tb_scenario! {
	name: test_trace_analysis_methods,
	config: ScenarioConf::<()>::builder()
		.with_spec(TraceAnalysisSpec::latest())
		.with_fdr(build_fdr_config(vec![SimpleRequestResponse::process()]))
		.with_hooks(TestHooks {
			on_pass: Some(Arc::new(|context| {
				// Acceptance queries: Check what events are accepted at
				// specific states.
				if let Some(acceptance) = context.trace.acceptance_at("Connected") {
					// At Connected state, process accepts "serialize"
					assert!(acceptance.iter().any(|e| e.0 == "serialize"));
				}

				if let Some(acceptance) = context.trace.acceptance_at("Sent") {
					// At Sent state, process accepts "decrypt"
					assert!(acceptance.iter().any(|e| e.0 == "decrypt"));
				}

				// Refusal queries: Verify process can refuse events not in
				// acceptance set. At Connected, process must do "serialize"
				// before "request"
				assert!(context.trace.can_refuse_after("Connected", "request"));
				assert!(context.trace.can_refuse_after("Connected", "disconnect"));

				Ok(())
			})),
			on_fail: None,
		})
		.build(),
	environment Bare {
		exec: |trace| async move {
			// Execute simple request-response flow (simulated)
			trace.event("connect")?;
			trace.event("serialize")?;
			trace.event("encrypt")?;
			trace.event("request")?;
			trace.event("decrypt")?;
			trace.event("deserialize")?;
			trace.event("response")?;
			trace.event("disconnect")?;

			Ok(())
		}
	}
}

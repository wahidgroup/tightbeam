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
use tightbeam::testing::{ScenarioConfig, SetupEnv, TestHooks};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_process_spec, tb_scenario};

pub(crate) const CONNECT: Urn<'static> = Urn::new("test", "event:trace-analysis/connect");
pub(crate) const DECRYPT: Urn<'static> = Urn::new("test", "event:trace-analysis/decrypt");
pub(crate) const DESERIALIZE: Urn<'static> = Urn::new("test", "event:trace-analysis/deserialize");
pub(crate) const DISCONNECT: Urn<'static> = Urn::new("test", "event:trace-analysis/disconnect");
pub(crate) const ENCRYPT: Urn<'static> = Urn::new("test", "event:trace-analysis/encrypt");
pub(crate) const REQUEST: Urn<'static> = Urn::new("test", "event:trace-analysis/request");
pub(crate) const RESPONSE: Urn<'static> = Urn::new("test", "event:trace-analysis/response");
pub(crate) const SERIALIZE: Urn<'static> = Urn::new("test", "event:trace-analysis/serialize");

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
		gate: Ok,
		assertions: [
			(CONNECT, exactly!(1)),
			(SERIALIZE, exactly!(1)),
			(ENCRYPT, exactly!(1)),
			(REQUEST, exactly!(1)),
			(DECRYPT, exactly!(1)),
			(DESERIALIZE, exactly!(1)),
			(RESPONSE, exactly!(1)),
			(DISCONNECT, exactly!(1))
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
		observable { CONNECT, REQUEST, RESPONSE, DISCONNECT }
		hidden { SERIALIZE, ENCRYPT, DECRYPT, DESERIALIZE }
	}
	states {
		Init => { CONNECT => Connected },
		Connected => { SERIALIZE => Serialized },
		Serialized => { ENCRYPT => Encrypted },
		Encrypted => { REQUEST => Sent },
		Sent => { DECRYPT => Decrypted },
		Decrypted => { DESERIALIZE => Deserialized },
		Deserialized => { RESPONSE => Responded },
		Responded => { DISCONNECT => Complete }
	}
	terminal { Complete }
}

tb_scenario! {
	name: test_trace_analysis_methods,
	config: ScenarioConfig::builder()
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
		exec: |SetupEnv { trace, .. }| async move {
			// Execute simple request-response flow (simulated)
			trace.event(CONNECT)?;
			trace.event(SERIALIZE)?;
			trace.event(ENCRYPT)?;
			trace.event(REQUEST)?;
			trace.event(DECRYPT)?;
			trace.event(DESERIALIZE)?;
			trace.event(RESPONSE)?;
			trace.event(DISCONNECT)?;

			Ok(())
		}
	}
}

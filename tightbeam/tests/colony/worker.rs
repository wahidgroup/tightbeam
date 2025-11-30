//! Integration test for Worker environment syntax in tb_scenario!

use std::sync::Arc;
use tightbeam::colony::Worker;
use tightbeam::der::Sequence;
use tightbeam::testing::ScenarioConf;
use tightbeam::Beamable;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, worker};

// Test message types
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct PingMessage {
	content: String,
	lucky_number: u32,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct PongMessage {
	result: String,
}

// Worker with config - generates From impl
worker! {
	name: ConfigurableWorker<PingMessage, Option<PongMessage>>,
	config: {
		response: String,
	},
	handle: |message, _trace, config| async move {
		if message.content == "PING" {
			Some(PongMessage { result: config.response.clone() })
		} else {
			None
		}
	}
}

// Worker without config - generates Default impl
worker! {
	name: DefaultWorker<PingMessage, Option<PongMessage>>,
	handle: |message, _trace| async move {
		if message.content == "PING" {
			Some(PongMessage { result: "DEFAULT_PONG".to_string() })
		} else {
			None
		}
	}
}

tb_assert_spec! {
	pub WorkerSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("relay_start", exactly!(1)),
			("relay_success", exactly!(1), equals!("DEFAULT_PONG"))
		]
	},
	V(2,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("relay_start", exactly!(1)),
			("relay_success", exactly!(1), equals!("CUSTOM_RESPONSE"))
		]
	},
}

tb_scenario! {
	name: test_worker_with_config,
	config: ScenarioConf::<()>::builder()
		.with_specs(vec![WorkerSpec::latest()])
		.build(),
	environment Worker {
		setup: |_trace| {
			ConfigurableWorker::new(ConfigurableWorkerConf {
				response: "CUSTOM_RESPONSE".to_string(),
			})
		},
		stimulus: |trace, worker| async move {
			trace.event_with("relay_start", &[], ())?;

			let ping_msg = PingMessage {
				content: "PING".to_string(),
				lucky_number: 42,
			};

			let response = worker.relay(Arc::new(ping_msg)).await?;
			if let Some(resp) = response {
				trace.event_with("relay_success", &[], resp.result)?;
			}

			Ok(())
		}
	}
}

tb_scenario! {
	name: test_worker_with_type,
	config: ScenarioConf::<()>::builder()
		.with_specs(vec![WorkerSpec::get(1, 0, 0).expect("WorkerSpec 1.0.0")])
		.build(),
	environment Worker {
	setup: |_trace| DefaultWorker::new(()),
	stimulus: |trace, worker| async move {
		trace.event_with("relay_start", &[], ())?;

		let ping_msg = PingMessage {
			content: "PING".to_string(),
				lucky_number: 99,
			};

			let response = worker.relay(Arc::new(ping_msg)).await?;
			if let Some(resp) = response {
				trace.event_with("relay_success", &[], resp.result)?;
			}

			Ok(())
		}
	}
}

//! Simple servlet test for ServletConf pattern with workers

use std::sync::Arc;
use tightbeam::{
	colony::ServletConf,
	compose, decode,
	der::Sequence,
	exactly, servlet, tb_assert_spec, tb_scenario,
	testing::ScenarioConf,
	transport::{tcp::r#async::TokioListener, ClientBuilder, ConnectionBuilder},
	worker, Beamable, TightBeamError,
};

// ============================================================================
// Messages
// ============================================================================

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcRequest {
	pub value: u32,
}

#[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
pub struct CalcResponse {
	pub doubled: u32,
	pub squared: u32,
	pub final_result: u32, // Uses config multiplier on sum
}

// ============================================================================
// Workers
// ============================================================================

// Worker 1: Doubler (no config)
worker! {
	name: DoublerWorker<CalcRequest, Result<u32, TightBeamError>>,
	handle: |input, trace| async move {
		trace.event("doubler_process")?;
		Ok(input.value * 2)
	}
}

// Worker 2: Squarer (with config)
worker! {
	name: SquarerWorker<CalcRequest, Result<u32, TightBeamError>>,
	config: {
		add_offset: u32,
	},
	handle: |input, trace, config| async move {
		trace.event("squarer_process")?;
		Ok(input.value * input.value + config.add_offset)
	}
}

// ============================================================================
// Servlet
// ============================================================================

// Define the servlet's environment config
#[derive(Clone)]
pub struct CalcServletConf {
	pub squarer_offset: u32,
	pub final_multiplier: u32,
	pub value: u32,
}

servlet! {
	/// Simple test servlet that USES config and workers
	pub CalcServlet<CalcRequest, EnvConfig = CalcServletConf>,
	protocol: TokioListener,
	handle: |frame, trace, config, workers| async move {
		trace.event("servlet_receive")?;

		let request: CalcRequest = decode(&frame.message)?;
		let request_arc = Arc::new(request);

		// Process with both workers in parallel
		let (doubled_result, squared_result) = tokio::join!(
			workers.relay::<DoublerWorker>(Arc::clone(&request_arc)),
			workers.relay::<SquarerWorker>(Arc::clone(&request_arc))
		);

		let doubled = doubled_result??;
		let squared = squared_result??;

		// USE THE CONFIG to compute final result
		let sum = doubled + squared;
		let final_result = sum * config.final_multiplier;

		trace.event("servlet_respond")?;

		Ok(Some(compose! {
			V0: id: b"calc-response-id",
				message: CalcResponse { doubled, squared, final_result }
		}?))
	}
}

// ============================================================================
// Tests with tb_scenario!
// ============================================================================

tb_assert_spec! {
	pub CalcServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("servlet_receive", exactly!(1)),
			("doubler_process", exactly!(1)),
			("squarer_process", exactly!(1)),
			("servlet_respond", exactly!(1)),
			("verify_doubled", exactly!(1), equals!(10u32)),
			("verify_squared", exactly!(1), equals!(35u32)),
			("verify_final_result", exactly!(1), equals!(135u32))
		]
	}
}

tb_scenario! {
	name: test_servlet_conf_with_workers,
	config: ScenarioConf::<CalcServletConf>::builder()
		.with_specs(vec![CalcServletSpec::latest()])
		.with_env_config(CalcServletConf {
			squarer_offset: 10,
			final_multiplier: 3,
			value: 5,
		})
		.build(),
	environment Servlet {
		servlet: CalcServlet,
		start: |trace, config| async move {
			let doubler = DoublerWorker::new(());
			let squarer = SquarerWorker::new(SquarerWorkerConf {
				add_offset: config.squarer_offset
			});

			let servlet_conf = ServletConf::<TokioListener, CalcRequest>::builder()
				.with_config(config)
				.with_worker(doubler)
				.with_worker(squarer)
				.build();

			// Start servlet via trait
			CalcServlet::start(trace, Some(servlet_conf)).await
		},
		setup: |servlet_addr, _config| async move {
			let builder = ClientBuilder::<TokioListener>::builder().build();
			let client = builder.connect(servlet_addr).await?;
			Ok(client)
		},
		client: |trace, mut client, config| async move {
			let request = compose! {
				V0: id: b"calc-request-id",
					message: CalcRequest { value: config.value }
			}?;

			let response_frame = client.emit(request, None).await?.ok_or(TightBeamError::MissingResponse)?;
			let response: CalcResponse = decode(&response_frame.message)?;

			// Verify results using trace events with equals! assertions
			trace.event_with("verify_doubled", &[], response.doubled)?;
			trace.event_with("verify_squared", &[], response.squared)?;
			trace.event_with("verify_final_result", &[], response.final_result)?;

			Ok(())
		}
	}
}

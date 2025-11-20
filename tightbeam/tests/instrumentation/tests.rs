//! Integration tests for automatic instrumentation in testing framework
//!
//! Demonstrates Phase 2: tb_scenario! automatic instrumentation capture

#![cfg(feature = "instrument")]

use tightbeam::testing::create_test_message;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::transport::tcp::TightBeamSocketAddr;
use tightbeam::transport::{MessageEmitter, Protocol};
use tightbeam::{compose, server, tb_assert_spec, tb_process_spec, tb_scenario};

tb_assert_spec! {
	pub AutoInstrSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: []
	}
}

// CSP process spec for automatic message flow verification
tb_process_spec! {
	pub MessageFlowProc,
	events {
		observable { "message_emit", "message_collect" }
		hidden { }
	}
	states {
		S0 => { "message_emit" => S1 },
		S1 => { "message_collect" => S2 }
	}
	terminal { S2 }
	annotations { description: "Automatic message emit -> collect flow" }
}

tb_scenario! {
	name: test_auto_instrumentation_capture,
	spec: AutoInstrSpec,
	csp: MessageFlowProc,
	trace: TraceConfig::default(),
	environment ServiceClient {
		worker_threads: 1,
		server: |trace| async move {
			let bind_addr: TightBeamSocketAddr = "127.0.0.1:0".parse().unwrap();
			let (listener, addr) = <TokioListener as Protocol>::bind(bind_addr).await?;
			let handle = server! {
				protocol TokioListener: listener,
				assertions: trace,
				handle: |frame, _trace| async move {
					Ok(Some(frame))
				}
			};
			Ok((handle, addr))
		},
		client: |_trace, mut client| async move {
			let test_message = create_test_message(None);
			let test_frame = compose! {
				V0: id: "test", order: 1u64, message: test_message
			}?;

			let _response = client.emit(test_frame, None).await?;
			Ok(())
		}
	}
}

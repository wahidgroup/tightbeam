//! Minimal Servlet Fuzz Test for AFL
//!
//! This is a bare minimum test to verify AFL fuzzing works with servlets.
//! It has a simple servlet that echoes back a number, and a client that sends numbers.

#![cfg(all(feature = "std", feature = "full"))]

use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, decode, servlet, tb_assert_spec, tb_process_spec, tb_scenario, Beamable, Sequence};

// ============================================================================
// MESSAGE TYPES
// ============================================================================

#[derive(Beamable, Sequence, Debug, Clone)]
#[tightbeam(version = "V(1,0,0)")]
pub struct NumberRequest {
	pub value: u8,
}

#[derive(Beamable, Sequence, Debug, Clone)]
#[tightbeam(version = "V(1,0,0)")]
pub struct NumberResponse {
	pub doubled: u16,
}

// ============================================================================
// SERVLET
// ============================================================================

servlet! {
	EchoServlet<NumberRequest>,
	protocol: TokioListener,
	policies: {},
	config: {},
	handle: |message, _config| async move {
		// DEBUG: Track handler entry
		let _ = std::fs::write("/tmp/simple_servlet_handler_entry.txt", format!("handler_called: order={}\n", message.metadata.order));

		// Decode request
		let req: NumberRequest = match decode(&message.message) {
			Ok(r) => {
				let _ = std::fs::write("/tmp/simple_servlet_decode_success.txt", format!("decode_success: value={}\n", r.value));
				r
			},
			Err(_) => {
				let _ = std::fs::write("/tmp/simple_servlet_decode_failed.txt", "decode_failed\n");
				return Ok(None);
			}
		};

		// Double the value
		let doubled = (req.value as u16) * 2;

		// DEBUG: Track response creation
		let _ = std::fs::write("/tmp/simple_servlet_response_created.txt", format!("response_created: doubled={}\n", doubled));

		let response = NumberResponse { doubled };

		Ok(Some(compose! {
			V0: id: message.metadata.id.clone(),
			order: message.metadata.order + 1,
			message: response
		}?))
	}
}

// ============================================================================
// CSP SPECS
// ============================================================================

tb_assert_spec! {
	pub SimpleServletSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			(HandlerStart, "request_sent", at_least!(0)),
			(HandlerStart, "response_received", at_least!(0)),
		]
	},
}

tb_process_spec! {
	pub struct SimpleServletFlow;
	events {
		observable { "request_sent", "response_received" }
		hidden { }
	}
	states {
		S0 => { "request_sent" => S1 },
		S1 => { "response_received" => S2 }
	}
	terminal { S2 }
}

// ============================================================================
// FUZZ TEST
// ============================================================================

#[cfg(fuzzing)]
tb_scenario! {
	spec: SimpleServletSpec,
	csp: SimpleServletFlow,
	fuzz: afl,
	environment Servlet {
		servlet: EchoServlet<NumberRequest>,
		start: async move {
			// DEBUG: Track servlet start
			let _ = std::fs::write("/tmp/simple_servlet_start.txt", "servlet_starting\n");
			let servlet = EchoServlet::<NumberRequest>::start(None).await?;
			let _ = std::fs::write("/tmp/simple_servlet_started.txt", format!("servlet_started: addr={:?}\n", servlet.addr()));
			Ok(servlet)
		},
		client: |trace, mut client| async move {
			// DEBUG: Track client entry
			let _ = std::fs::write("/tmp/simple_servlet_client_entry.txt", "client_started\n");

			// Read a byte from fuzz input
			let value = match trace.oracle().fuzz_u8() {
				Ok(v) => v,
				Err(_) => {
					let _ = std::fs::write("/tmp/simple_servlet_no_input.txt", "no_input_bytes\n");
					return Ok(());
				}
			};

			// DEBUG: Track request creation
			let _ = std::fs::write("/tmp/simple_servlet_request_creating.txt", format!("creating_request: value={}\n", value));

			let request = NumberRequest { value };
			trace.event("request_sent");

			// DEBUG: Track frame composition
			let _ = std::fs::write("/tmp/simple_servlet_frame_composing.txt", "composing_frame\n");

			let frame = compose! {
				V0: id: "simple-client",
				order: 1,
				message: request
			}?;

			// DEBUG: Track before emit
			let _ = std::fs::write("/tmp/simple_servlet_before_emit.txt", "before_emit\n");

			// Send request
			let response_frame = match client.emit(frame, None).await? {
				Some(f) => {
					let _ = std::fs::write("/tmp/simple_servlet_response_received.txt", "response_received\n");
					f
				},
				None => {
					let _ = std::fs::write("/tmp/simple_servlet_no_response.txt", "no_response\n");
					return Ok(());
				}
			};

			// Decode response
			let response: NumberResponse = match decode(&response_frame.message) {
				Ok(r) => {
					let _ = std::fs::write("/tmp/simple_servlet_response_decoded.txt", format!("response_decoded: doubled={}\n", r.doubled));
					r
				},
				Err(_) => {
					let _ = std::fs::write("/tmp/simple_servlet_response_decode_failed.txt", "response_decode_failed\n");
					return Ok(());
				}
			};

			trace.event("response_received");

			// Verify response is correct (value * 2)
			assert_eq!(response.doubled, (value as u16) * 2);

			let _ = std::fs::write("/tmp/simple_servlet_success.txt", format!("success: value={}, doubled={}\n", value, response.doubled));

			Ok(())
		}
	}
}

//! Minimal Servlet Fuzz Test for AFL
//!
//! This is a bare minimum test to verify AFL fuzzing works with servlets.
//! It has a simple servlet that echoes back a number, and a client that sends numbers.
#![allow(unexpected_cfgs)]
#![cfg(all(feature = "std", feature = "full"))]

use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{at_least, compose, decode, servlet, tb_assert_spec, tb_process_spec, tb_scenario, Beamable, Sequence};

// ============================================================================
// MESSAGE TYPES
// ============================================================================

#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
#[beam(version = "V(1,0,0)")]
pub struct NumberRequest {
	pub value: u8,
}

#[derive(Beamable, Sequence, Debug, Clone, PartialEq, Eq)]
#[beam(version = "V(1,0,0)")]
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
	handle: |message, _trace| async move {
		// Decode request
		let req = match decode::<NumberRequest>(&message.message) {
			Ok(r) => {
				r
			},
			Err(_) => {
				return Ok(None);
			}
		};

		// Double the value
		let doubled = (req.value as u16) * 2;
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
			("request_sent", at_least!(0)),
			("response_received", at_least!(0), equals!(true)),
		]
	},
}

tb_process_spec! {
	pub SimpleServletFlow,
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

tb_scenario! {
	spec: SimpleServletSpec,
	csp: SimpleServletFlow,
	fuzz: afl,
	environment Servlet {
		servlet: EchoServlet,
		client: |trace, mut client| async move {
			// Read a byte from fuzz input
			let value = match trace.oracle().fuzz_u8() {
				Ok(v) => v,
				Err(_) => {
					return Ok(());
				}
			};

			let request = NumberRequest { value };
			trace.event("request_sent");

			let frame = compose! {
				V0: id: "simple-client",
				order: 1,
				message: request
			}?;

			// Send request
			let response_frame = match client.emit(frame, None).await? {
				Some(f) => {
					f
				},
				None => {
					return Ok(());
				}
			};

			// Decode response
			let response = match decode::<NumberResponse>(&response_frame.message) {
				Ok(r) => {
					r
				},
				Err(_) => {
					return Ok(());
				}
			};

			trace.event_with("response_received", &[], response.doubled == (value as u16) * 2);

			Ok(())
		}
	}
}

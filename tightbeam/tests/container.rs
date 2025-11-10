#![cfg(feature = "testing")]
#![cfg(feature = "full")]

use tightbeam::prelude::*;

use tightbeam::prelude::policy::{PolicyConf, RestartLinearBackoff};
use tightbeam::{assert_channel_empty, assert_channels_quiet, assert_recv, test_container};

#[cfg(feature = "tokio")]
use tightbeam::transport::tcp::r#async::TokioListener as Listener;
#[cfg(all(not(feature = "tokio"), feature = "std"))]
use tightbeam::transport::tcp::sync::TcpListener;

#[cfg(all(not(feature = "tokio"), feature = "std"))]
type Listener = TcpListener<std::net::TcpListener>;

use der::{Enumerated, Sequence};

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct RequestMessage {
	content: String,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct ResponseMessage {
	result: String,
}

/// Checklist for container assertions
#[derive(Enumerated, Beamable, Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
enum ServiceAssertChecklist {
	ContainerMessageReceived = 1,
	ContainerPingReceived = 2,
	SentResponse = 3,
}

test_container! {
	name: container_gates_basic,
	worker_threads: 2,
	protocol: Listener,
	service_policies: {
		with_collector_gate: [policy::AcceptAllGate]
	},
	client_policies: {
		with_emitter_gate: [policy::AcceptAllGate],
		with_restart: [RestartLinearBackoff::new(3, 1, 1, None)]
	},
	service: |message, tx| async move {
		tightbeam::relay!(ServiceAssertChecklist::ContainerMessageReceived, tx)?;

		let decoded: RequestMessage = tightbeam::decode(&message.message).ok()?;
		if &decoded.content == "PING" {
			tightbeam::relay!(ServiceAssertChecklist::ContainerPingReceived, tx)?;

			let response = tightbeam::compose! {
				V0: id: message.metadata.id.clone(),
					message: ResponseMessage {
						result: "PONG".into()
					}
			}.ok().map(std::sync::Arc::new);

			tightbeam::relay!(ServiceAssertChecklist::SentResponse, tx)?;
			response
		} else {
			None
		}
	},
	container: |client, channels| async move {
		use tightbeam::transport::MessageEmitter;

		let (rx, ok_rx, reject_rx) = channels;

		// Compose a simple V0 message
		let message = tightbeam::compose! {
			V0: id: b"request",
				message: RequestMessage {
					content: "PING".into()
				}
		}?;

		//# Test message transport

		// Send and expect acceptance + echo response
		let decoded = if let Some(response) = client.emit(message.clone(), None).await? {
			// Collect checklist items
			assert_recv!(rx, ServiceAssertChecklist::ContainerMessageReceived);
			assert_recv!(rx, ServiceAssertChecklist::ContainerPingReceived);
			assert_recv!(rx, ServiceAssertChecklist::SentResponse);
			// Verify response metadata
			assert_eq!(response.metadata.id, message.metadata.id);
			// Ensure we received the message on the server side
			assert_recv!(ok_rx, message);
			// Ensure server did not reject
			assert_channels_quiet!(reject_rx);

			tightbeam::decode::<ResponseMessage>(&response.message).ok()
		} else {
			panic!("Expected a response from the service");
		};

		//# Test message shape

		match decoded {
			Some(reply) => {
				assert_eq!(reply.result, "PONG");
			},
			None => panic!("Expected a PONG")
		};

		Ok(())
	}
}

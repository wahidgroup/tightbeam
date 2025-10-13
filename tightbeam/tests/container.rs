#![cfg(feature = "testing")]
#![cfg(feature = "full")]

use tightbeam::prelude::*;
use tightbeam::{assert_channel_empty, assert_channels_quiet, assert_recv, test_container};

use der::Sequence;

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct RequestMessage {
	content: String,
}

#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
struct ResponseMessage {
	result: String,
}

test_container! {
	name: container_gates_basic,
	features: ["testing", "std", "tcp", "tokio"],
	worker_threads: 2,
	protocol: tcp,
	service_policies: {
		gate: policy::AcceptAllGate
	},
	client_policies: {
		restart: policy::RestartExponentialBackoff::default(),
		gate: policy::AcceptAllGate
	},
	service: |message, tx| async move {
		// Echo the message back when server gate Accepted it
		let result = tx.send(message.clone());
		assert!(result.is_ok());

		let decoded = tightbeam::decode::<RequestMessage, _>(&message.clone().message).ok()?;
		if &decoded.content == "PING" {
			Some(tightbeam::compose! {
				V0: id: message.metadata.id.clone(),
					order: 1_700_000_000u64,
					message: ResponseMessage {
						result: "PONG".into()
					}
			}.ok()?)
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
				order: 1_700_000_000u64,
				message: RequestMessage {
					content: "PING".into()
				}
		}?;

		// Send and expect acceptance + echo response
		let decoded = if let Some(response) = client.emit(message.clone(), None).await? {
			assert_eq!(response.metadata.id, message.metadata.id);
			tightbeam::decode::<ResponseMessage, _>(&response.message).ok()
		} else {
			panic!("Expected a response from the service");
		};

		match decoded {
			Some(reply) => {
				assert_eq!(reply.result, "PONG");
			},
			None => panic!("Expected a PONG")
		};

		assert_recv!(rx, message, 2, 1);
		assert_recv!(ok_rx, message, 2, 1);
		assert_channels_quiet!(reject_rx);

		Ok(())
	}
}

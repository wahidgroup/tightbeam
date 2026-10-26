//! # Post-handshake envelope tamper threat
//!
//! ## Weakness
//! If the receive direction does not bind each record to an exact-next
//! authenticated sequence number, an active attacker on the connection can
//! delete or replay whole encrypted envelopes without detection.
//!
//! A refused forgery that leaves no audit record hides the attack from the
//! operator.
//!
//! ## Attack
//! 1. A pinned client and an encrypted server complete an HPKE handshake through a frame-aware TCP relay.
//! 2. The relay tampers with the client-to-server direction after the
//!    handshake: it drops, duplicates, or forges the first encrypted envelope.
//! 3. The server opens subsequent envelopes under the exact-next sequence discipline.
//!
//! ## Expected control
//! An exact-next record sequence in the authenticated attributes (RFC 9846
//! § 5.3) MUST fail closed:
//!
//! - A deleted envelope desynchronizes the sequence and surfaces `TamperDetected` on the next message.
//! - The server rejects a replayed envelope once the original consumes its sequence number.
//! - A forged record fails its tag, and the server records the refusal as `OpenFailed`.
//!
//! ## References
//! - CWE-345: Insufficient Verification of Data Authenticity
//!   <https://cwe.mitre.org/data/definitions/345.html>
//! - CWE-778: Insufficient Logging <https://cwe.mitre.org/data/definitions/778.html>
//! - RFC 9846 (TLS 1.3) §5.3: the per-record sequence number

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio"
))]

use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::job;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::config::ScenarioConfig;
use tightbeam::testing::{SetupEnv, TestFrame};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::{TokioReadHalf, TokioWriteHalf, TransportReader};
use tightbeam::transport::{EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError, TransportWriter};
use tightbeam::TightBeamError;

use crate::security::common::{Direction, HandshakeBackendKind, ServerMaterials};
use crate::security::live::{AttackStep, FrameEdit, FrameSlot, LiveHandshake};

/// HPKE sends exactly two client handshake frames, the hello and the closing,
/// as cleartext envelopes, so the first encrypted envelope is frame 3.
const FIRST_ENCRYPTED_FRAME: FrameSlot = FrameSlot { direction: Direction::ClientToServer, ordinal: 3 };

// Delete: a dropped encrypted envelope desynchronizes the record sequence.

tb_assert_spec! {
	pub EnvelopeDeleteSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("TamperDetected"))
		]
	}
}

tb_process_spec! {
	pub EnvelopeDeleteProcess,
	events {
		observable { events::TRANSPORT_ENVELOPE_REFUSED }
		hidden { }
	}
	states {
		Idle => { events::TRANSPORT_ENVELOPE_REFUSED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Exact-next record sequence rejects a deleted encrypted envelope" }
}

tb_scenario! {
	name: envelope_delete_detected,
	config: ScenarioConfig::builder()
		.with_spec(EnvelopeDeleteSpec::latest())
		.with_csp(EnvelopeDeleteProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			EnvelopeDeleteScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: EnvelopeDeleteScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let (mut reader, mut writer) = tampered_link(&trace, FrameEdit::Drop).await?;
		write_plain_requests(&mut writer, 2).await?;

		// The relay deletes the first envelope, so sequence 1 arrives where the
		// server expects 0.
		let tampered = reader.read_envelope().await;
		assert!(tampered.is_err(), "server accepted traffic after a deleted encrypted envelope");

		Ok(())
	}
}

// Replay: the server rejects a duplicate encrypted envelope after the original.

tb_assert_spec! {
	pub EnvelopeReplaySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("TamperDetected"))
		]
	}
}

tb_process_spec! {
	pub EnvelopeReplayProcess,
	events {
		observable { events::TRANSPORT_ENVELOPE_REFUSED }
		hidden { }
	}
	states {
		Idle => { events::TRANSPORT_ENVELOPE_REFUSED => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Exact-next record sequence rejects a replayed encrypted envelope" }
}

tb_scenario! {
	name: envelope_replay_detected,
	config: ScenarioConfig::builder()
		.with_spec(EnvelopeReplaySpec::latest())
		.with_csp(EnvelopeReplayProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			EnvelopeReplayScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: EnvelopeReplayScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let (mut reader, mut writer) = tampered_link(&trace, FrameEdit::Duplicate).await?;
		write_plain_requests(&mut writer, 1).await?;

		let original = reader.read_envelope().await?;
		assert!(matches!(original, TransportEnvelope::Request(_)), "server refused the original encrypted envelope");

		// The replay presents sequence 0 again where the server expects 1.
		let replayed = reader.read_envelope().await;
		assert!(replayed.is_err(), "server accepted a replayed encrypted envelope");

		Ok(())
	}
}

// Forgery: a record whose tag fails leaves an audit record of its refusal.

tb_assert_spec! {
	pub EnvelopeForgerySpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::TRANSPORT_ENVELOPE_REFUSED, exactly!(1), equals!("OpenFailed"))
		]
	}
}

tb_scenario! {
	name: envelope_forgery_detected,
	spec: EnvelopeForgerySpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			EnvelopeForgeryScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: EnvelopeForgeryScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		let (mut reader, mut writer) = tampered_link(&trace, FrameEdit::FlipLastOctet).await?;
		write_plain_requests(&mut writer, 1).await?;

		// The forged record reads as a message the server cannot use.
		let forged = reader.read_envelope().await;
		let refused = matches!(forged, Err(TransportError::InvalidMessage));
		assert!(refused, "server accepted a forged encrypted envelope");

		Ok(())
	}
}

// The tampered link that every case shares.

async fn write_plain_requests(
	writer: &mut TransportWriter<TokioWriteHalf>,
	count: usize,
) -> Result<(), TightBeamError> {
	for _ in 0..count {
		let frame = TestFrame::v0(None, None);
		let request = TransportEnvelope::new_request(frame);
		writer.write_envelope(request).await?;
	}
	Ok(())
}

/// Handshake through a relay that applies `edit` to the first encrypted
/// envelope of the client, and return the reader of the server, which files
/// its refusals in `trace`, beside the writer of the client.
async fn tampered_link(
	trace: &TraceCollector,
	edit: FrameEdit,
) -> Result<(TransportReader<TokioReadHalf>, TransportWriter<TokioWriteHalf>), TightBeamError> {
	let step = AttackStep::new(FIRST_ENCRYPTED_FRAME, edit);
	let link = LiveHandshake::new(HandshakeBackendKind::Hpke, ServerMaterials::generate());
	let outcome = link.audit_server(trace).with_step(step).run().await?;

	let (client, server) = outcome.established()?;
	let (reader, _) = server.into_split()?;
	let (_, writer) = client.into_split()?;
	Ok((reader, writer))
}

//! # Post-handshake envelope tamper threat
//!
//! ## Weakness
//! If the receive-direction AEAD nonce is not bound to an exact-next
//! invocation counter, an active attacker on the connection can delete or
//! replay whole encrypted envelopes without detection.
//!
//! ## Attack
//! 1. A pinned client and encrypted server complete a real ECIES handshake
//!    through a frame-aware TCP relay.
//! 2. The relay tampers with the client-to-server direction after the
//!    handshake: either drops or duplicates the first encrypted envelope.
//! 3. The server decrypts subsequent envelopes under the exact-next counter
//!    discipline.
//!
//! ## Expected control
//! Exact-next counter nonces (RFC 8446 § 5.3 analog) MUST fail closed:
//! deleting an envelope desynchronizes the counter and surfaces
//! `TamperDetected` on the very next message. Replaying an envelope is
//! rejected after the original consumes its counter.
//!
//! ## References
//! - CWE-345: Insufficient Verification of Data Authenticity
//!   <https://cwe.mitre.org/data/definitions/345.html>
//! - RFC 8446 (TLS 1.3) §5.3: per-record nonce construction / sequencing

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio"
))]

use std::net::SocketAddr;
use std::sync::Arc;

use tightbeam::exactly;
use tightbeam::job;
use tightbeam::tb_assert_spec;
use tightbeam::tb_process_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::config::ScenarioConf;
use tightbeam::testing::{create_v0_tightbeam, SetupEnv};
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::{
	AsyncReadStream, AsyncWriteStream, SplittableStream, TokioReadHalf, TokioStream, TokioWriteHalf, TransportReader,
};
use tightbeam::transport::{
	EnvelopeSink, EnvelopeSource, TransportEnvelope, TransportError, TransportFailure, TransportWriter,
};
use tightbeam::TightBeamError;
use tokio::net::{TcpListener, TcpStream};

use crate::common::security::ServerMaterials;
use crate::transport::support::{accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split};

/// ECIES sends exactly two cleartext client frames (ClientHello,
/// ClientKeyExchange), so the first encrypted envelope is frame 3.
const FIRST_ENCRYPTED_FRAME: usize = 3;

tb_assert_spec! {
	pub EnvelopeTamperSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(tamper_deleted_envelope_detected, exactly!(1), equals!(true)),
			(tamper_replayed_envelope_detected, exactly!(1), equals!(true))
		]
	}
}

tb_process_spec! {
	pub EnvelopeTamperProcess,
	events {
		observable {
			EnvelopeTamperSpec::tamper_deleted_envelope_detected,
			EnvelopeTamperSpec::tamper_replayed_envelope_detected
		}
		hidden { }
	}
	states {
		Idle => { EnvelopeTamperSpec::tamper_deleted_envelope_detected => DeletedCaught },
		DeletedCaught => { EnvelopeTamperSpec::tamper_replayed_envelope_detected => Done },
		Done => { }
	}
	terminal { Done }
	annotations { description: "Exact-next AEAD counter rejects deleted and replayed envelopes" }
}

tb_scenario! {
	name: envelope_tamper,
	config: ScenarioConf::builder()
		.with_spec(EnvelopeTamperSpec::latest())
		.with_csp(EnvelopeTamperProcess)
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			EnvelopeTamperScenario::run((trace.into(),)).await
		}
	}
}

job! {
	name: EnvelopeTamperScenario,
	async fn run((trace,): (Arc<TraceCollector>,)) -> Result<(), TightBeamError> {
		tamper_deleted_envelope_detected(&trace).await?;
		tamper_replayed_envelope_detected(&trace).await?;
		Ok(())
	}
}

/// How the relay tampers with one client-to-server frame (1-based index).
#[derive(Clone, Copy)]
enum TamperRule {
	Drop(usize),
	Duplicate(usize),
}

/// Bind a frame-aware relay in front of `upstream` and return its address.
///
/// Server-to-client frames pass unchanged. Client-to-server frames go
/// through the tamper rule. Operating on whole DER frames (not bytes)
/// keeps the tampering an active-attacker envelope operation rather than
/// a corruption the AEAD tag would already catch.
async fn spawn_tamper_relay(upstream: SocketAddr, rule: TamperRule) -> Result<SocketAddr, TightBeamError> {
	let listener = TcpListener::bind("127.0.0.1:0").await?;
	let relay_addr = listener.local_addr()?;

	tokio::spawn(async move {
		let Ok((inbound, _)) = listener.accept().await else {
			return;
		};
		let Ok(outbound) = TcpStream::connect(upstream).await else {
			return;
		};

		let (client_read, client_write) = TokioStream::from(inbound).into_split();
		let (server_read, server_write) = TokioStream::from(outbound).into_split();
		tokio::join!(
			forward_tampered_frames(client_read, server_write, rule),
			forward_unchanged_frames(server_read, client_write),
		);
	});
	Ok(relay_addr)
}

fn tamper_repeats(rule: TamperRule, index: usize) -> usize {
	match rule {
		TamperRule::Drop(target) if index == target => 0,
		TamperRule::Duplicate(target) if index == target => 2,
		_ => 1,
	}
}

async fn forward_tampered_frames(mut reader: TokioReadHalf, mut writer: TokioWriteHalf, rule: TamperRule) {
	let mut index = 0usize;
	while let Ok(frame) = reader.read_frame(None).await {
		index += 1;
		for _ in 0..tamper_repeats(rule, index) {
			if writer.write_frame(&frame).await.is_err() {
				return;
			}
		}
	}
}

async fn forward_unchanged_frames(mut reader: TokioReadHalf, mut writer: TokioWriteHalf) {
	while let Ok(frame) = reader.read_frame(None).await {
		if writer.write_frame(&frame).await.is_err() {
			return;
		}
	}
}

fn is_tamper_detected(result: &Result<TransportEnvelope, TransportError>) -> bool {
	matches!(result, Err(TransportError::OperationFailed(TransportFailure::TamperDetected)))
}

async fn write_plain_requests(
	writer: &mut TransportWriter<TokioWriteHalf>,
	count: usize,
) -> Result<(), TightBeamError> {
	for _ in 0..count {
		let request = TransportEnvelope::new_request(create_v0_tightbeam(None, None));
		writer.write_envelope(request).await?;
	}
	Ok(())
}

/// Handshake through a tampering relay, run `on_server` against the server
/// half, and send `request_count` plain encrypted requests from the client.
async fn with_tampered_link<F, Fut>(
	rule: TamperRule,
	request_count: usize,
	on_server: F,
) -> Result<bool, TightBeamError>
where
	F: FnOnce(TransportReader<TokioReadHalf>) -> Fut + Send + 'static,
	Fut: core::future::Future<Output = Result<bool, TightBeamError>> + Send + 'static,
{
	let materials = ServerMaterials::generate();
	let (listener, server_addr) = bind_encrypted_listener(&materials).await?;
	let relay_addr = spawn_tamper_relay(server_addr, rule).await?;

	let server_task = tokio::spawn(async move {
		let (reader, _writer) = accept_handshaken_split(listener).await?;
		on_server(reader).await
	});

	let (_reader, mut writer) = connect_handshaken_split(relay_addr, &materials.certificate).await?;
	write_plain_requests(&mut writer, request_count).await?;
	let detected = await_ok(server_task, "server task must not panic").await?;
	Ok(detected)
}

/// Deleting an encrypted envelope is detected on the next message.
async fn tamper_deleted_envelope_detected(trace: &TraceCollector) -> Result<(), TightBeamError> {
	let detected = with_tampered_link(TamperRule::Drop(FIRST_ENCRYPTED_FRAME), 2, |mut reader| async move {
		// First envelope deleted: second arrives with counter 1 while 0 expected.
		let tampered = reader.read_envelope().await;
		Ok(is_tamper_detected(&tampered))
	})
	.await?;

	trace.event_with(EnvelopeTamperSpec::tamper_deleted_envelope_detected, &[], detected)?;
	Ok(())
}

/// Replaying an encrypted envelope is rejected after the original.
async fn tamper_replayed_envelope_detected(trace: &TraceCollector) -> Result<(), TightBeamError> {
	let detected = with_tampered_link(TamperRule::Duplicate(FIRST_ENCRYPTED_FRAME), 1, |mut reader| async move {
		let original = reader.read_envelope().await?;
		let original_ok = matches!(original, TransportEnvelope::Request(_));

		// Replay re-presents counter 0 while 1 is expected.
		let replayed = reader.read_envelope().await;
		Ok(original_ok && is_tamper_detected(&replayed))
	})
	.await?;

	trace.event_with(EnvelopeTamperSpec::tamper_replayed_envelope_detected, &[], detected)?;
	Ok(())
}

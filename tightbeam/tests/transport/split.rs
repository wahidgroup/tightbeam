//! Split transport integration tests.
//!
//! Drives an ECIES handshake over TCP, splits both endpoints into
//! exclusive read/write halves, and verifies:
//!
//! - Encrypted request/response traffic flows through the split halves in
//!   both directions (directional keys, counter nonces)
//! - Splitting before handshake completion fails closed
//! - A writer at its AEAD record limit fails closed with `RekeyRequired`
//!   (RFC 8446 § 5.5 analog) instead of reusing the key

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::exactly;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::config::ScenarioConf;
use tightbeam::testing::create_v0_tightbeam;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope, TransportError, TransportFailure,
};
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;

use super::support::{accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split};
use crate::common::security::{expectation_failure, ServerMaterials};

tb_assert_spec! {
	pub SplitTransportSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		assertions: [
			("split_encrypted_roundtrip", exactly!(1), equals!(true)),
			("split_rejects_pre_handshake", exactly!(1), equals!(true)),
			("split_rekey_limit_fails_closed", exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: split_transport,
	config: ScenarioConf::<()>::builder()
		.with_spec(SplitTransportSpec::latest())
		.build(),
	environment Bare {
		exec: |trace| async move {
			split_encrypted_roundtrip(&trace).await?;
			split_rejects_pre_handshake(&trace).await?;
			split_rekey_limit_fails_closed(&trace).await?;
			Ok(())
		}
	}
}

fn request_frame() -> Frame {
	create_v0_tightbeam(None, None)
}

fn request_envelope() -> TransportEnvelope {
	TransportEnvelope::new_request(request_frame())
}

/// Full ECIES handshake, split on both ends, encrypted echo roundtrip.
async fn split_encrypted_roundtrip(trace: &TraceCollector) -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;

	let server_handle = tokio::spawn(async move {
		let (mut reader, mut writer) = accept_handshaken_split(listener).await?;

		let request = reader.read_envelope().await?;
		let frame = match request {
			TransportEnvelope::Request(pkg) => Frame::clone(pkg.message()),
			_ => return Err(expectation_failure("server must receive a request envelope")),
		};

		let response = ResponsePackage::new(TransitStatus::Accepted, Some(frame));
		let envelope = TransportEnvelope::from(response);
		writer.write_envelope(envelope).await?;

		Ok::<(), TightBeamError>(())
	});

	let (mut reader, mut writer) = connect_handshaken_split(addr, &materials.certificate).await?;
	let request_frame = request_frame();
	let request_envelope = TransportEnvelope::new_request(request_frame.clone());

	writer.write_envelope(request_envelope).await?;

	let response = reader.read_envelope().await?;
	let package = match response {
		TransportEnvelope::Response(pkg) => pkg,
		_ => return Err(expectation_failure("client must receive a response envelope")),
	};

	let status_ok = package.status() == TransitStatus::Accepted;
	let echoed_frame = package
		.message()
		.map(|arc| Frame::clone(arc))
		.ok_or_else(|| expectation_failure("echo response must carry the request frame"))?;
	let frame_ok = echoed_frame == request_frame;

	await_ok(server_handle, "server task must not panic").await?;

	trace.event_with("split_encrypted_roundtrip", &[], status_ok && frame_ok)?;
	Ok(())
}

/// Splitting an un-handshaken transport must fail closed.
async fn split_rejects_pre_handshake(trace: &TraceCollector) -> Result<(), TightBeamError> {
	let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0")
		.await
		.map_err(TransportError::from)?;

	let addr = listener.local_addr().map_err(TransportError::from)?;
	let stream = TcpStream::connect(addr).await.map_err(TransportError::from)?;
	let transport: TcpTransport<TokioStream> = TcpTransport::from(TokioStream::from(stream));

	let rejected = matches!(transport.into_split(), Err(TransportError::InvalidState));
	trace.event_with("split_rejects_pre_handshake", &[], rejected)?;
	Ok(())
}

/// A lock-step writer at its record limit must fail closed with
/// `RekeyRequired` (RFC 8446 § 5.5 analog), never reuse the key.
async fn split_rekey_limit_fails_closed(trace: &TraceCollector) -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;

	let server_handle = tokio::spawn(async move {
		let (mut reader, _writer) = accept_handshaken_split(listener).await?;

		let within_limit = reader.read_envelope().await?;
		let arrived = matches!(within_limit, TransportEnvelope::Request(_));
		if !arrived {
			return Err(expectation_failure("the write inside the record limit must still arrive"));
		}

		Ok::<(), TightBeamError>(())
	});

	let (_reader, writer) = connect_handshaken_split(addr, &materials.certificate).await?;
	let mut writer = writer.with_rekey_limit(1);

	let first_request = request_envelope();
	writer.write_envelope(first_request).await?;

	// The limit is spent. The second write must demand a rekey before any
	// bytes leave the writer.
	let second_request = request_envelope();
	let limited = writer.write_envelope(second_request).await;
	let rekey_required = matches!(limited, Err(TransportError::MessageNotSent(_, TransportFailure::RekeyRequired)));

	await_ok(server_handle, "server task must not panic").await?;

	trace.event_with("split_rekey_limit_fails_closed", &[], rekey_required)?;
	Ok(())
}

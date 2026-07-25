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
//! - A reader facing a counter past its record limit fails closed with
//!   `RekeyRequired` (peer overran the volume bound) instead of decrypting

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
use tightbeam::testing::{create_v0_tightbeam, SetupEnv};
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope, TransportError, TransportFailure,
};
use tightbeam::{Frame, TightBeamError};
use tokio::net::TcpStream;

use super::support::{accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split};
use crate::common::security::{expectation_failure, ServerMaterials};

fn request_frame() -> Frame {
	create_v0_tightbeam(None, None)
}

fn request_envelope() -> TransportEnvelope {
	TransportEnvelope::new_request(request_frame())
}

tb_assert_spec! {
	pub SplitEncryptedRoundtripSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(status_ok, exactly!(1), equals!(true)),
			(frame_echoed, exactly!(1), equals!(true))
		]
	}
}

// Full ECIES handshake, split on both ends, encrypted echo roundtrip.
tb_scenario! {
	name: split_encrypted_roundtrip,
	spec: SplitEncryptedRoundtripSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) = bind_encrypted_listener(&materials).await?;

			let server_handle = tokio::spawn(async move {
				let (mut reader, mut writer) = accept_handshaken_split(listener).await?;

				let request = reader.read_envelope().await?;
				let frame = match request {
					TransportEnvelope::Request(pkg) => Frame::clone(pkg.message()),
					_ => return Err(expectation_failure("server must receive a request envelope")),
				};

				let response = ResponsePackage::new(TransitStatus::Ok, Some(frame));
				writer.write_envelope(TransportEnvelope::from(response)).await?;

				Ok::<(), TightBeamError>(())
			});

			let (mut reader, mut writer) = connect_handshaken_split(addr, &materials.certificate).await?;
			let sent = request_frame();
			writer.write_envelope(TransportEnvelope::new_request(sent.to_owned())).await?;

			let response = reader.read_envelope().await?;
			let package = match response {
				TransportEnvelope::Response(pkg) => pkg,
				_ => return Err(expectation_failure("client must receive a response envelope")),
			};

			let echoed = package
				.message()
				.map(|arc| Frame::clone(arc))
				.ok_or_else(|| expectation_failure("echo response must carry the request frame"))?;

			await_ok(server_handle, "server task must not panic").await?;

			trace.event_with(
				SplitEncryptedRoundtripSpec::status_ok,
				&[],
				package.status() == TransitStatus::Ok,
			)?;
			trace.event_with(SplitEncryptedRoundtripSpec::frame_echoed, &[], echoed == sent)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SplitRejectsPreHandshakeSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(into_split_reports_invalid_state, exactly!(1), equals!(true))
		]
	}
}

// Splitting an un-handshaken transport must fail closed.
tb_scenario! {
	name: split_rejects_pre_handshake,
	spec: SplitRejectsPreHandshakeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0").await?;
			let addr = listener.local_addr()?;
			let stream = TcpStream::connect(addr).await?;
			let transport: TcpTransport<TokioStream> = TcpTransport::from(TokioStream::from(stream));

			trace.event_with(
				SplitRejectsPreHandshakeSpec::into_split_reports_invalid_state,
				&[],
				matches!(transport.into_split(), Err(TransportError::InvalidState)),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SplitWriteRekeyLimitSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(second_write_demands_rekey, exactly!(1), equals!(true))
		]
	}
}

// A lock-step writer at its record limit must fail closed with
// `RekeyRequired` (RFC 8446 § 5.5 analog), never reuse the key.
tb_scenario! {
	name: split_write_rekey_limit_fails_closed,
	spec: SplitWriteRekeyLimitSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
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

			writer.write_envelope(request_envelope()).await?;

			// Limit spent. Second write must demand rekey before any bytes leave.
			let limited = writer.write_envelope(request_envelope()).await;

			await_ok(server_handle, "server task must not panic").await?;

			trace.event_with(
				SplitWriteRekeyLimitSpec::second_write_demands_rekey,
				&[],
				matches!(limited, Err(TransportError::MessageNotSent(_, TransportFailure::RekeyRequired))),
			)?;
			Ok(())
		}
	}
}

tb_assert_spec! {
	pub SplitReadRekeyLimitSpec,
	V(1,0,0): {
		mode: Accept,
		gate: Ok,
		assertions: [
			(first_record_arrives, exactly!(1), equals!(true)),
			(second_record_demands_rekey, exactly!(1), equals!(true))
		]
	}
}

// A reader facing a counter past its record limit must fail closed with
// `RekeyRequired` (peer overran the AES-GCM volume bound), surfacing it as
// `OperationFailed(RekeyRequired)` rather than a generic `InvalidMessage`.
tb_scenario! {
	name: split_read_rekey_limit_fails_closed,
	spec: SplitReadRekeyLimitSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::generate();
			let (listener, addr) = bind_encrypted_listener(&materials).await?;

			let server_handle = tokio::spawn(async move {
				let (_reader, mut writer) = accept_handshaken_split(listener).await?;

				writer.write_envelope(request_envelope()).await?;
				writer.write_envelope(request_envelope()).await?;

				Ok::<(), TightBeamError>(())
			});

			let (reader, _writer) = connect_handshaken_split(addr, &materials.certificate).await?;
			let mut reader = reader.with_rekey_limit(1);

			let within_limit = reader.read_envelope().await?;
			trace.event_with(
				SplitReadRekeyLimitSpec::first_record_arrives,
				&[],
				matches!(within_limit, TransportEnvelope::Request(_)),
			)?;

			// Peer's second record carries a counter at the clamped limit:
			// reader must demand rekey instead of decrypting.
			let over_limit = reader.read_envelope().await;

			await_ok(server_handle, "server task must not panic").await?;

			trace.event_with(
				SplitReadRekeyLimitSpec::second_record_demands_rekey,
				&[],
				matches!(
					over_limit,
					Err(TransportError::OperationFailed(TransportFailure::RekeyRequired))
				),
			)?;
			Ok(())
		}
	}
}

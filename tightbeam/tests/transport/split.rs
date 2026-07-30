//! Split transport integration tests.

#![cfg(all(
	feature = "transport-ecies",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]

use tokio::net::TcpStream;

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
use tightbeam::utils::urn::Urn;
use tightbeam::{Frame, TightBeamError};

use super::support::{accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split};
use crate::common::security::{expectation_failure, ServerMaterials};

pub(crate) const FIRST_RECORD_ARRIVES: Urn<'static> = Urn::new("test", "event:split/first-record-arrives");
pub(crate) const FRAME_ECHOED: Urn<'static> = Urn::new("test", "event:split/frame-echoed");
pub(crate) const INTO_SPLIT_REPORTS_INVALID_STATE: Urn<'static> =
	Urn::new("test", "event:split/into-split-reports-invalid-state");
pub(crate) const SECOND_RECORD_STILL_ARRIVES: Urn<'static> =
	Urn::new("test", "event:split/second-record-still-arrives");
pub(crate) const SECOND_WRITE_DEMANDS_REKEY: Urn<'static> = Urn::new("test", "event:split/second-write-demands-rekey");
pub(crate) const STATUS_OK: Urn<'static> = Urn::new("test", "event:split/status-ok");
pub(crate) const THRESHOLD_REACHES_ZERO: Urn<'static> = Urn::new("test", "event:split/threshold-reaches-zero");

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
			(STATUS_OK, exactly!(1), equals!(true)),
			(FRAME_ECHOED, exactly!(1), equals!(true))
		]
	}
}

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
				STATUS_OK,
				&[],
				package.status() == TransitStatus::Ok,
			)?;
			trace.event_with(FRAME_ECHOED, &[], echoed == sent)?;
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
			(INTO_SPLIT_REPORTS_INVALID_STATE, exactly!(1), equals!(true))
		]
	}
}

tb_scenario! {
	name: split_rejects_pre_handshake,
	spec: SplitRejectsPreHandshakeSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let listener = TokioListener::<DefaultCryptoProvider>::bind("127.0.0.1:0").await?;
			let listen_addr = listener.local_addr()?;
			let client_stream = TcpStream::connect(listen_addr).await?;
			let tokio_stream = TokioStream::from(client_stream);
			let transport: TcpTransport<TokioStream> = TcpTransport::from(tokio_stream);

			let into_split = transport.into_split();
			trace.event_with(
				INTO_SPLIT_REPORTS_INVALID_STATE,
				&[],
				matches!(into_split, Err(TransportError::InvalidState)),
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
			(SECOND_WRITE_DEMANDS_REKEY, exactly!(1), equals!(true))
		]
	}
}

// RFC 9846 § 5.5: fail closed with RekeyRequired, never reuse key.
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

			// Limit spent; second write must fail before bytes leave.
			let limited = writer.write_envelope(request_envelope()).await;

			await_ok(server_handle, "server task must not panic").await?;

			trace.event_with(
				SECOND_WRITE_DEMANDS_REKEY,
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
			(FIRST_RECORD_ARRIVES, exactly!(1), equals!(true)),
			(THRESHOLD_REACHES_ZERO, exactly!(1), equals!(true)),
			(SECOND_RECORD_STILL_ARRIVES, exactly!(1), equals!(true))
		]
	}
}

// Reader limit is renewal threshold, not refusal bound (AES-GCM volume bound refuses).
tb_scenario! {
	name: split_read_rekey_threshold_never_refuses,
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
				FIRST_RECORD_ARRIVES,
				&[],
				matches!(within_limit, TransportEnvelope::Request(_)),
			)?;
			trace.event_with(
				THRESHOLD_REACHES_ZERO,
				&[],
				reader.remaining_records() == 0,
			)?;

			// Counter past threshold: reader still decrypts.
			let past_threshold = reader.read_envelope().await;

			await_ok(server_handle, "server task must not panic").await?;

			trace.event_with(
				SECOND_RECORD_STILL_ARRIVES,
				&[],
				matches!(past_threshold, Ok(TransportEnvelope::Request(_))),
			)?;
			Ok(())
		}
	}
}

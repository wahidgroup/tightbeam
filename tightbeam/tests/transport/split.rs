//! The integration tests of the split transport.

#![cfg(all(
	feature = "transport-hpke",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "instrument"
))]

use tokio::task::JoinHandle;

use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{SetupEnv, TestFrame};
use tightbeam::transport::tcp::r#async::{SplitTransport, TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope,
	TransportError, TransportFailure,
};
use tightbeam::{Frame, TightBeamError};

use crate::common::poll::joined;
use crate::common::result::TestResult;
use crate::common::security::{combined_trust, ServerMaterials};
use crate::transport::fixtures::{
	accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split, connect_pinned_client,
	loopback_streams,
};

/// The frame that each split test sends: a V0 frame with no label.
fn request_frame() -> Frame {
	TestFrame::v0(None, None)
}

/// [`request_frame`] in a request envelope.
fn request_envelope() -> TransportEnvelope {
	TransportEnvelope::new_request(request_frame())
}

/// The response package that `envelope` carries.
fn response_of(envelope: TransportEnvelope) -> ResponsePackage {
	let TransportEnvelope::Response(package) = envelope else {
		panic!("the client must receive a response envelope");
	};

	package
}

/// The frame of the request that `envelope` carries.
fn request_of(envelope: TransportEnvelope) -> Frame {
	let TransportEnvelope::Request(package) = envelope else {
		panic!("the server must receive a request envelope");
	};

	Frame::clone(package.message())
}

/// An encrypted split session carries a request to the server and the
/// server's echo back, under status `Ok`.
#[tokio::test]
async fn an_encrypted_split_session_echoes_a_request() -> TestResult {
	let materials = ServerMaterials::fixed();
	let (listener, addr) = bind_encrypted_listener(&materials).await?;

	let server_handle = tokio::spawn(async move {
		let (mut reader, mut writer) = accept_handshaken_split(listener).await?;
		let frame = request_of(reader.read_envelope().await?);

		let response = ResponsePackage::new(TransitStatus::Ok, Some(frame));
		writer.write_envelope(TransportEnvelope::from(response)).await?;

		Ok::<(), TightBeamError>(())
	});

	let (mut reader, mut writer) = connect_handshaken_split(addr, &materials.certificate).await?;
	let sent = request_frame();

	writer.write_envelope(TransportEnvelope::new_request(sent.to_owned())).await?;

	let package = response_of(reader.read_envelope().await?);
	let echoed = package.message().map(|frame| Frame::clone(frame));

	joined(server_handle).await?;

	assert_eq!((package.status(), echoed), (TransitStatus::Ok, Some(sent)));
	Ok(())
}

/// A provisioned client whose handshake has not run holds no keys to split,
/// so it refuses the split.
#[tokio::test]
async fn a_transport_whose_handshake_has_not_run_refuses_to_split() -> TestResult {
	let (client_stream, _accepted) = loopback_streams().await;
	let client = ClientBuilder::<TokioListener>::builder().with_trust_store(combined_trust(&[]));
	let transport = client.adopt(TokioStream::from(client_stream))?.into_transport();

	let into_split = transport.into_split();
	assert!(matches!(into_split, Err(TransportError::InvalidState)));
	Ok(())
}

tb_assert_spec! {
	pub SplitWriteRekeyLimitSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(events::TRANSPORT_REKEY_REQUIRED, exactly!(1), equals!(1u64))
		]
	}
}

// RFC 9846 § 5.5: a writer at the record limit of its key fails closed with
// `RekeyRequired`.
tb_scenario! {
	name: split_write_rekey_limit_fails_closed,
	spec: SplitWriteRekeyLimitSpec,
	environment Bare {
		exec: |SetupEnv { trace, .. }| async move {
			let materials = ServerMaterials::fixed();
			let (listener, addr) = bind_encrypted_listener(&materials).await?;

			let server_handle = tokio::spawn(async move {
				let (mut reader, _writer) = accept_handshaken_split(listener).await?;

				let within_limit = request_of(reader.read_envelope().await?);
				assert_eq!(within_limit.message(), request_frame().message(), "the write inside the record limit must still arrive");

				Ok::<(), TightBeamError>(())
			});

			// The client carries the scenario trace from its first handshake
			// message, and its writer half takes the trace at the split.
			let client = connect_pinned_client(addr, &materials.certificate).await?;
			let mut client = client.with_trace(trace.share());
			client.perform_client_handshake().await?;

			let (_reader, writer) = client.into_split()?;

			let mut writer = writer.with_rekey_limit(1);
			writer.write_envelope(request_envelope()).await?;

			// The first write spends the limit, so the second fails before its
			// bytes leave.
			let limited = writer.write_envelope(request_envelope()).await;
			await_ok(server_handle, "server task must not panic").await?;

			let demands_rekey = matches!(limited, Err(TransportError::MessageNotSent(_, TransportFailure::RekeyRequired)));
			assert!(demands_rekey, "the write past the record limit must demand a rekey");
			Ok(())
		}
	}
}

/// A client split session whose reader holds a rekey threshold of one
/// record, beside the server task that writes it two requests.
async fn threshold_of_one_session() -> (SplitTransport<TokioStream>, JoinHandle<Result<(), TightBeamError>>) {
	let materials = ServerMaterials::fixed();
	let (listener, addr) = bind_encrypted_listener(&materials).await.expect("a loopback port binds");
	let server_handle = tokio::spawn(async move {
		let (_reader, mut writer) = accept_handshaken_split(listener).await?;

		writer.write_envelope(request_envelope()).await?;
		writer.write_envelope(request_envelope()).await?;

		Ok::<(), TightBeamError>(())
	});

	let split = connect_handshaken_split(addr, &materials.certificate).await;
	let (reader, writer) = split.expect("the pinned client completes its handshake");
	((reader.with_rekey_limit(1), writer), server_handle)
}

/// The read threshold of a split half counts the records the half reads, so
/// one record spends a threshold of one.
#[tokio::test]
async fn one_record_spends_a_read_threshold_of_one() -> TestResult {
	let ((mut reader, _writer), server_handle) = threshold_of_one_session().await;

	reader.read_envelope().await?;
	joined(server_handle).await?;
	assert_eq!(reader.remaining_records(), 0);
	Ok(())
}

/// The read threshold of a split half triggers a renewal, and the AES-GCM
/// volume bound is the refusal bound, so the reader decrypts a record past
/// the threshold.
#[tokio::test]
async fn a_split_reader_past_its_threshold_still_decrypts() -> TestResult {
	let ((mut reader, _writer), server_handle) = threshold_of_one_session().await;
	reader.read_envelope().await?;

	let past_threshold = reader.read_envelope().await;
	joined(server_handle).await?;
	assert!(matches!(past_threshold, Ok(TransportEnvelope::Request(_))));
	Ok(())
}

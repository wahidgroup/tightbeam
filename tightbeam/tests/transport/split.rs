//! Split transport integration tests.

#![cfg(all(
	feature = "transport-hpke",
	feature = "transport-policy",
	feature = "tcp",
	feature = "tokio",
	feature = "testing",
	feature = "instrument"
))]

use std::sync::Arc;

use tokio::net::TcpStream;

use tightbeam::crypto::policy::Secp256k1Policy;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::x509::store::{CertificateTrustBuilder, TrustBuilder};
use tightbeam::exactly;
use tightbeam::instrumentation::events;
use tightbeam::policy::TransitStatus;
use tightbeam::tb_assert_spec;
use tightbeam::tb_scenario;
use tightbeam::testing::{SetupEnv, TestFrame};
use tightbeam::transport::tcp::r#async::{TokioListener, TokioStream};
use tightbeam::transport::{
	ClientBuilder, EncryptedMessageIO, EnvelopeSink, EnvelopeSource, ResponsePackage, TransportEnvelope,
	TransportError, TransportFailure,
};
use tightbeam::{Frame, TightBeamError};

use super::support::{
	accept_handshaken_split, await_ok, bind_encrypted_listener, connect_handshaken_split, connect_pinned_client,
};
use crate::common::security::{expectation_failure, ServerMaterials};

fn request_frame() -> Frame {
	TestFrame::v0(None, None)
}

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
async fn split_encrypted_roundtrip() -> Result<(), TightBeamError> {
	let materials = ServerMaterials::generate();
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
	let echoed = package
		.message()
		.map(|arc| Frame::clone(arc))
		.ok_or_else(|| expectation_failure("echo response must carry the request frame"))?;

	await_ok(server_handle, "server task must not panic").await?;

	assert_eq!(package.status(), TransitStatus::Ok, "the echo must carry status Ok");
	assert_eq!(echoed, sent, "the server must echo the request frame");
	Ok(())
}

/// A provisioned client whose handshake has not run holds no keys to split,
/// so it refuses the split.
#[tokio::test]
async fn split_rejects_pre_handshake() -> Result<(), TightBeamError> {
	let listener = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await?;
	let listen_addr = listener.local_addr()?;
	let client_stream = TcpStream::connect(listen_addr).await?;
	let data = CertificateTrustBuilder::from(Secp256k1Policy::default()).build();
	let client = ClientBuilder::<TokioListener>::builder().with_trust_store(Arc::new(data));
	let transport = client.adopt(TokioStream::from(client_stream))?.into_transport();

	let into_split = transport.into_split();
	let refused = matches!(into_split, Err(TransportError::InvalidState));
	assert!(refused, "a provisioned transport must refuse to split");
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
			let materials = ServerMaterials::generate();
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

/// The read threshold of a split half triggers a renewal, and the AES-GCM
/// volume bound is the refusal bound, so the reader decrypts a record past
/// the threshold.
#[tokio::test]
async fn split_read_rekey_threshold_never_refuses() -> Result<(), TightBeamError> {
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
	let arrived = matches!(within_limit, TransportEnvelope::Request(_));
	assert!(arrived, "the record inside the threshold must arrive");
	assert_eq!(reader.remaining_records(), 0, "one record must spend a threshold of one");

	let past_threshold = reader.read_envelope().await;
	await_ok(server_handle, "server task must not panic").await?;

	let decrypted = matches!(past_threshold, Ok(TransportEnvelope::Request(_)));
	assert!(decrypted, "a reader past its threshold must still decrypt");
	Ok(())
}

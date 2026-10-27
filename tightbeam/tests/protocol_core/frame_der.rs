//! The DER round trip of a V3 frame through the public builder API.

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::prelude::*;
use tightbeam::testing::TestIdentity;
use tightbeam::TightBeamError;

#[derive(tightbeam::Beamable, Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

impl AsRef<[u8]> for TestMessage {
	fn as_ref(&self) -> &[u8] {
		self.content.as_bytes()
	}
}

#[derive(tightbeam::Flaggable)]
#[repr(u8)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDevelopmentMode {
	#[default]
	Default = 0,
	IsMaintenanceMode = 2,
}

#[derive(tightbeam::Flaggable)]
#[repr(u8)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDebugLevel {
	#[default]
	Default = 0,
	Basic = 1,
}

tightbeam::flagset!(TestFlagSet: FlagTestDevelopmentMode, FlagTestDebugLevel);

fn build_v3_frame(message: &TestMessage) -> Result<tightbeam::Frame, TightBeamError> {
	let key_bytes = [0x44u8; 32];
	let cipher = Aes256GcmKeyProvider::new(key_bytes.to_vec(), b"tb/test/frame-der/kek/v1".to_vec())?;
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let previous_hash = tightbeam::utils::digest::<Sha3_256>(message)?;

	FrameBuilder::from(asn1::Version::V3)
		.with_id("frame-der")
		.with_order(1_696_521_700)
		.with_message(message.to_owned())
		.with_message_hasher::<Sha3_256>([])
		.with_encryptor(cipher)
		.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(signing_key))
		.with_priority(asn1::MessagePriority::Expedited)
		.with_lifetime(3_600)
		.with_previous_hash(previous_hash)
		.with_matrix(tightbeam::flags![
			TestFlagSet:
				FlagTestDevelopmentMode::IsMaintenanceMode,
				FlagTestDebugLevel::Basic
		])
		.build()
}

/// A V3 frame with every optional field set decodes from its DER to the same
/// frame.
#[test]
fn frame_der_roundtrip() -> Result<(), TightBeamError> {
	let message = TestMessage { content: "frame der roundtrip".to_string() };
	let frame = build_v3_frame(&message)?;

	let der_bytes = tightbeam::encode(&frame)?;
	let decoded: tightbeam::Frame = tightbeam::decode(&der_bytes)?;

	assert_eq!(decoded, frame, "the DER decode of the V3 frame equals the frame");
	assert_eq!(decoded.version(), asn1::Version::V3, "the decoded frame keeps the version V3");
	assert!(decoded.metadata().matrix().is_some(), "the decoded V3 frame keeps its matrix");
	Ok(())
}

//! V3 frame DER encode/decode roundtrip via the public builder API.

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::aead::{Aes256Gcm, Key, KeyInit};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::prelude::*;
use tightbeam::testing::{ScenarioConfig, SetupEnv};
use tightbeam::utils::urn::Urn;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, TightBeamError};

pub(crate) const DER_NONEMPTY: Urn<'static> = tightbeam::urn!("test", "event:frame-der/der-nonempty");
pub(crate) const MATRIX_PRESENT: Urn<'static> = tightbeam::urn!("test", "event:frame-der/matrix-present");
pub(crate) const ROUNDTRIP_OK: Urn<'static> = tightbeam::urn!("test", "event:frame-der/roundtrip-ok");
pub(crate) const VERSION: Urn<'static> = tightbeam::urn!("test", "event:frame-der/version");

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
	let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let previous_hash = tightbeam::utils::digest::<Sha3_256>(message)?;

	FrameBuilder::from(asn1::Version::V3)
		.with_id("frame-der")
		.with_order(1_696_521_700)
		.with_message(message.to_owned())
		.with_message_hasher::<Sha3_256>([])
		.with_aead(cipher)
		.with_signer::<Secp256k1Signature, _>(signing_key)
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

tb_assert_spec! {
	pub FrameDerSpec,
	V(1,0,0): {
		mode: Accept,
		assertions: [
			(DER_NONEMPTY, exactly!(1), equals!(true)),
			(ROUNDTRIP_OK, exactly!(1), equals!(true)),
			(MATRIX_PRESENT, exactly!(1), equals!(true)),
			(VERSION, exactly!(1), equals!(asn1::Version::V3))
		]
	}
}

tb_scenario! {
	name: frame_der_roundtrip,
	config: ScenarioConfig::builder()
		.with_specs(vec![
			FrameDerSpec::get(1, 0, 0).expect("FrameDerSpec 1.0.0")
		])
		.build(),
	environment Bare {
		exec: |SetupEnv { trace, .. }| {
			let message = TestMessage { content: "frame der roundtrip".to_string() };
			let frame = build_v3_frame(&message)?;
			let der_bytes = tightbeam::encode(&frame)?;
			let decoded: tightbeam::Frame = tightbeam::decode(&der_bytes)?;

			trace.event_with(DER_NONEMPTY, &[], !der_bytes.is_empty())?;
			trace.event_with(ROUNDTRIP_OK, &[], decoded == frame)?;
			trace.event_with(MATRIX_PRESENT, &[], frame.metadata().matrix().is_some())?;
			trace.event_with(VERSION, &[], frame.version())?;

			Ok(())
		}
	}
}

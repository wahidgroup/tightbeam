//! V3 frame DER encode/decode roundtrip via the public builder API.

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid, Key, KeyInit};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::prelude::*;
use tightbeam::testing::{ScenarioConf, SetupEnv};
use tightbeam::{exactly, tb_assert_spec, tb_scenario, TightBeamError};

#[cfg_attr(feature = "derive", derive(tightbeam::Beamable))]
#[derive(Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

impl AsRef<[u8]> for TestMessage {
	fn as_ref(&self) -> &[u8] {
		self.content.as_bytes()
	}
}

#[cfg(not(feature = "derive"))]
impl tightbeam::Message for TestMessage {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: tb::Version = tb::Version::V0;
}

#[cfg_attr(feature = "derive", derive(tightbeam::Flaggable))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDevelopmentMode {
	#[default]
	Default = 0,
	IsMaintenanceMode = 2,
}

#[cfg(not(feature = "derive"))]
impl From<FlagTestDevelopmentMode> for u8 {
	fn from(flag: FlagTestDevelopmentMode) -> u8 {
		flag as u8
	}
}

#[cfg(not(feature = "derive"))]
impl PartialEq<u8> for FlagTestDevelopmentMode {
	fn eq(&self, other: &u8) -> bool {
		(*self as u8) == *other
	}
}

#[cfg_attr(feature = "derive", derive(tightbeam::Flaggable))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDebugLevel {
	#[default]
	Default = 0,
	Basic = 1,
}

#[cfg(not(feature = "derive"))]
impl From<FlagTestDebugLevel> for u8 {
	fn from(flag: FlagTestDebugLevel) -> u8 {
		flag as u8
	}
}

#[cfg(not(feature = "derive"))]
impl PartialEq<u8> for FlagTestDebugLevel {
	fn eq(&self, other: &u8) -> bool {
		(*self as u8) == *other
	}
}

tightbeam::flagset!(TestFlagSet: FlagTestDevelopmentMode, FlagTestDebugLevel);

fn build_v3_frame(message: &TestMessage) -> Result<tightbeam::Frame, TightBeamError> {
	let key_bytes = [0x44u8; 32];
	let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let previous_hash = tightbeam::utils::digest::<Sha3_256>(message)?;

	FrameBuilder::from(tb::Version::V3)
		.with_id("frame-der")
		.with_order(1_696_521_700)
		.with_message(message.clone())
		.with_message_hasher::<Sha3_256>([])
		.with_aead::<Aes256GcmOid, _>(cipher)
		.with_signer::<Secp256k1Signature, _>(signing_key)
		.with_priority(tb::MessagePriority::Expedited)
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
		gate: Ok,
		assertions: [
			(der_nonempty, exactly!(1), equals!(true)),
			(roundtrip_ok, exactly!(1), equals!(true)),
			(matrix_present, exactly!(1), equals!(true)),
			(version, exactly!(1), equals!(tb::Version::V3))
		]
	}
}

tb_scenario! {
	name: frame_der_roundtrip,
	config: ScenarioConf::builder()
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

			trace.event_with(FrameDerSpec::der_nonempty, &[], !der_bytes.is_empty())?;
			trace.event_with(FrameDerSpec::roundtrip_ok, &[], decoded == frame)?;
			trace.event_with(FrameDerSpec::matrix_present, &[], frame.metadata.matrix.is_some())?;
			trace.event_with(FrameDerSpec::version, &[], frame.version)?;

			Ok(())
		}
	}
}

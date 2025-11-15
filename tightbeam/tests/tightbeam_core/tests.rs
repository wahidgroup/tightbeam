//! Integration tests for TightBeam protocol workflows.
//! TODO Enhance with instrumentation when available.
//!
//! Scenarios are defined declaratively so that each protocol version is
//! validated with the metadata it permits (and rejects).

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid, Key, KeyInit};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Secp256k1SigningKey, VerifyingKey};
use tightbeam::der::ValueOrd;
use tightbeam::prelude::*;
use tightbeam::testing::macros::{IsNone, IsSome};
use tightbeam::utils;
use tightbeam::{exactly, tb_assert_spec, tb_scenario, TightBeamError};

/// Simple test message
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

/// Custom test matrix for message metadata
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

/// Custom test matrix for message metadata
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

// Define the flag set with automatic position assignment
tightbeam::flagset!(TestFlagSet: FlagTestDevelopmentMode, FlagTestDebugLevel);

struct TestCrypto {
	cipher: Aes256Gcm,
	signing_key: Secp256k1SigningKey,
	verifying_key: VerifyingKey<Secp256k1>,
}

fn build_crypto(seed: u8) -> Result<TestCrypto, TightBeamError> {
	let key_bytes = [seed; 32];
	let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let verifying_key = *signing_key.verifying_key();
	Ok(TestCrypto { cipher, signing_key, verifying_key })
}

tb_assert_spec! {
	pub VersionSpec,
	V(0,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v0"],
		assertions: [
			("roundtrip_ok", exactly!(1), equals!(true)),
			("nonrepudiation", exactly!(1), equals!(IsNone)),
			("integrity", exactly!(1), equals!(IsNone)),
			("confidentiality", exactly!(1), equals!(IsNone)),
			("priority", exactly!(1), equals!(IsNone)),
			("lifetime", exactly!(1), equals!(IsNone)),
			("previous_frame", exactly!(1), equals!(IsNone)),
			("matrix", exactly!(1), equals!(IsNone)),
			("version", exactly!(1), equals!(tb::Version::V0))
		]
	},
	V(1,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v1"],
		assertions: [
			("roundtrip_ok", exactly!(1), equals!(true)),
			("sig_valid", exactly!(1), equals!(true)),
			("integrity_ok", exactly!(1), equals!(true)),
			("confidentiality", exactly!(1), equals!(IsSome)),
			("priority", exactly!(1), equals!(IsNone)),
			("lifetime", exactly!(1), equals!(IsNone)),
			("previous_frame", exactly!(1), equals!(IsNone)),
			("matrix", exactly!(1), equals!(IsNone)),
			("version", exactly!(1), equals!(tb::Version::V1))
		]
	},
	V(2,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v2"],
		assertions: [
			("roundtrip_ok", exactly!(1), equals!(true)),
			("sig_valid", exactly!(1), equals!(true)),
			("integrity_ok", exactly!(1), equals!(true)),
			("confidentiality", exactly!(1), equals!(IsSome)),
			("priority", exactly!(1), equals!(Some(tb::MessagePriority::High))),
			("lifetime", exactly!(1), equals!(Some(3_600))),
			("previous_frame", exactly!(1), equals!(IsSome)),
			("matrix", exactly!(1), equals!(IsNone)),
			("version", exactly!(1), equals!(tb::Version::V2))
		]
	},
	V(3,0,0): {
		mode: Accept,
		gate: Accepted,
		tag_filter: ["v3"],
		assertions: [
			("roundtrip_ok", exactly!(1), equals!(true)),
			("sig_valid", exactly!(1), equals!(true)),
			("integrity_ok", exactly!(1), equals!(true)),
			("confidentiality", exactly!(1), equals!(IsSome)),
			("priority", exactly!(1), equals!(Some(tb::MessagePriority::Top))),
			("lifetime", exactly!(1), equals!(Some(3_600))),
			("previous_frame", exactly!(1), equals!(IsSome)),
			("matrix", exactly!(1), equals!(IsSome)),
			("version", exactly!(1), equals!(tb::Version::V3))
		]
	}
}

tb_scenario! {
	name: version_check_all,
	specs: [
		VersionSpec::get(0, 0, 0),
		VersionSpec::get(1, 0, 0),
		VersionSpec::get(2, 0, 0),
		VersionSpec::get(3, 0, 0)
	],
	environment Bare {
		exec: |trace| {
			let message = TestMessage { content: "Hello from workflow".to_string() };
			let crypto = build_crypto(0x44)?;
			let message_hash = utils::digest::<Sha3_256>(&message)?;

			// Build ONE V3 frame with all capabilities
			let builder: FrameBuilder<TestMessage> = FrameBuilder::from(tb::Version::V3);
			let frame = builder
				.with_id("workflow")
				.with_order(1_696_521_700)
				.with_message(message.clone())
				.with_message_hasher::<Sha3_256>()
				.with_cipher::<Aes256GcmOid, _>(&crypto.cipher)
				.with_signer::<Secp256k1Signature, _>(&crypto.signing_key)
				.with_priority(tb::MessagePriority::Top)
				.with_lifetime(3_600)
				.with_previous_hash(message_hash.clone())
				.with_matrix(tightbeam::flags![
					TestFlagSet:
						FlagTestDevelopmentMode::IsMaintenanceMode,
						FlagTestDebugLevel::Basic
				]).build()?;

			let roundtrip = frame.decrypt::<TestMessage>(&crypto.cipher, None)?;
			let sig_valid = frame.verify::<Secp256k1Signature>(&crypto.verifying_key).is_ok();
			let integrity = frame.metadata.integrity.clone().ok_or(TightBeamError::MissingDigestInfo)?;
			let integrity_ok = integrity.value_cmp(&message_hash).is_ok();

			trace.assert_value("roundtrip_ok", &["v0", "v1", "v2", "v3"], roundtrip == message);
			trace.assert_option("nonrepudiation", &["v0"], &frame.nonrepudiation);
			trace.assert_option("integrity", &["v0"], &frame.metadata.integrity);
			trace.assert_option("confidentiality", &["v0", "v1", "v2", "v3"], &frame.metadata.confidentiality);
			trace.assert_value("priority", &["v0", "v1", "v2", "v3"], frame.metadata.priority);
			trace.assert_value("lifetime", &["v0", "v1", "v2", "v3"], frame.metadata.lifetime);
			trace.assert_option("previous_frame", &["v0", "v1", "v2", "v3"], &frame.metadata.previous_frame);
			trace.assert_option("matrix", &["v0", "v1", "v2", "v3"], &frame.metadata.matrix);
			trace.assert_value("version", &["v0", "v1", "v2", "v3"], frame.version);
			trace.assert_value("sig_valid", &["v1", "v2", "v3"], sig_valid);
			trace.assert_value("integrity_ok", &["v1", "v2", "v3"], integrity_ok);

			Ok(())
		}
	}
}

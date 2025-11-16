//! Integration tests for TightBeam protocol workflows.
//! TODO Enhance with instrumentation when available.
//!
//! Scenarios are defined declaratively so that each protocol version is
//! validated with the metadata it permits (and rejects).

#![allow(unexpected_cfgs)]

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid, Key, KeyInit};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::sign::ecdsa::{Secp256k1, Secp256k1Signature, Secp256k1SigningKey, VerifyingKey};
use tightbeam::der::ValueOrd;
use tightbeam::prelude::*;
use tightbeam::testing::assertions::Presence;
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

/// Build a test frame for the given version with appropriate capabilities
fn build_version_frame(
	version: tb::Version,
	message: &TestMessage,
	crypto: &TestCrypto,
	message_hash: &tightbeam::DigestInfo,
) -> Result<tightbeam::Frame, TightBeamError> {
	let mut builder = FrameBuilder::from(version)
		.with_id("test")
		.with_order(1_696_521_700)
		.with_message(message.clone());

	if version >= tb::Version::V1 {
		builder = builder
			.with_message_hasher::<Sha3_256>()
			.with_cipher::<Aes256GcmOid, _>(&crypto.cipher)
			.with_signer::<Secp256k1Signature, _>(&crypto.signing_key);
	}

	if version >= tb::Version::V2 {
		builder = builder
			.with_priority(tb::MessagePriority::Top)
			.with_lifetime(3_600)
			.with_previous_hash(message_hash.clone());
	}

	if version == tb::Version::V3 {
		builder = builder.with_matrix(tightbeam::flags![
			TestFlagSet:
				FlagTestDevelopmentMode::IsMaintenanceMode,
				FlagTestDebugLevel::Basic
		]);
	}

	builder.build()
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
			("priority", exactly!(1), equals!(Some(tb::MessagePriority::Top))),
			("lifetime", exactly!(1), equals!(Some(3_600u64))),
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
			("lifetime", exactly!(1), equals!(Some(3_600u64))),
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

			// Build frames for each version
			let v0_frame = build_version_frame(tb::Version::V0, &message, &crypto, &message_hash)?;
			let v1_frame = build_version_frame(tb::Version::V1, &message, &crypto, &message_hash)?;
			let v2_frame = build_version_frame(tb::Version::V2, &message, &crypto, &message_hash)?;
			let v3_frame = build_version_frame(tb::Version::V3, &message, &crypto, &message_hash)?;

			// Roundtrip checks
			let v0_roundtrip: TestMessage = tightbeam::decode(&v0_frame.message)?;
			trace.event_with("roundtrip_ok", &["v0"], v0_roundtrip == message);
			let v1_roundtrip = v1_frame.decrypt::<TestMessage>(&crypto.cipher, None)?;
			let v2_roundtrip = v2_frame.decrypt::<TestMessage>(&crypto.cipher, None)?;
			let v3_roundtrip = v3_frame.decrypt::<TestMessage>(&crypto.cipher, None)?;
			trace.event_with("roundtrip_ok", &["v1"], v1_roundtrip == message);
			trace.event_with("roundtrip_ok", &["v2"], v2_roundtrip == message);
			trace.event_with("roundtrip_ok", &["v3"], v3_roundtrip == message);

			// V1+ signature checks
			trace.event_with("sig_valid", &["v1"], v1_frame.verify::<Secp256k1Signature>(&crypto.verifying_key).is_ok());
			trace.event_with("sig_valid", &["v2"], v2_frame.verify::<Secp256k1Signature>(&crypto.verifying_key).is_ok());
			trace.event_with("sig_valid", &["v3"], v3_frame.verify::<Secp256k1Signature>(&crypto.verifying_key).is_ok());

			// V1+ integrity checks
			let v1_integrity = v1_frame.metadata.integrity.clone().ok_or(TightBeamError::MissingDigestInfo)?;
			let v2_integrity = v2_frame.metadata.integrity.clone().ok_or(TightBeamError::MissingDigestInfo)?;
			let v3_integrity = v3_frame.metadata.integrity.clone().ok_or(TightBeamError::MissingDigestInfo)?;
			trace.event_with("integrity_ok", &["v1"], v1_integrity.value_cmp(&message_hash).is_ok());
			trace.event_with("integrity_ok", &["v2"], v2_integrity.value_cmp(&message_hash).is_ok());
			trace.event_with("integrity_ok", &["v3"], v3_integrity.value_cmp(&message_hash).is_ok());

			// Frame-level fields
			trace.event_with("nonrepudiation", &["v0"], Presence::of_option(&v0_frame.nonrepudiation));
			trace.event_with("nonrepudiation", &["v1", "v2", "v3"], Presence::of_option(&v1_frame.nonrepudiation));
			trace.event_with("integrity", &["v0"], Presence::of_option(&v0_frame.integrity));
			trace.event_with("integrity", &["v1", "v2", "v3"], Presence::of_option(&v1_frame.integrity));

			// Metadata fields
			trace.event_with("confidentiality", &["v0"], Presence::of_option(&v0_frame.metadata.confidentiality));
			trace.event_with("confidentiality", &["v1", "v2", "v3"], Presence::of_option(&v1_frame.metadata.confidentiality));
			trace.event_with("priority", &["v0", "v1"], v0_frame.metadata.priority);
			trace.event_with("priority", &["v2"], v2_frame.metadata.priority);
			trace.event_with("priority", &["v3"], v3_frame.metadata.priority);
			trace.event_with("lifetime", &["v0", "v1"], v0_frame.metadata.lifetime);
			trace.event_with("lifetime", &["v2"], v2_frame.metadata.lifetime);
			trace.event_with("lifetime", &["v3"], v3_frame.metadata.lifetime);
			trace.event_with("previous_frame", &["v0", "v1"], Presence::of_option(&v0_frame.metadata.previous_frame));
			trace.event_with("previous_frame", &["v2", "v3"], Presence::of_option(&v2_frame.metadata.previous_frame));
			trace.event_with("matrix", &["v0", "v1", "v2"], Presence::of_option(&v0_frame.metadata.matrix));
			trace.event_with("matrix", &["v3"], Presence::of_option(&v3_frame.metadata.matrix));

			// Version checks - each version is unique
			trace.event_with("version", &["v0"], v0_frame.version);
			trace.event_with("version", &["v1"], v1_frame.version);
			trace.event_with("version", &["v2"], v2_frame.version);
			trace.event_with("version", &["v3"], v3_frame.version);

			Ok(())
		}
	}
}

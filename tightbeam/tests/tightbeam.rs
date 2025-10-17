//! Integration test for TightBeam protocol
//!
//! Demonstrates full V2 protocol capabilities using the compose! macro.

use tightbeam::compose;
use tightbeam::matrix::{MatrixDyn, MatrixLike};
use tightbeam::prelude::*;

use tightbeam::crypto::aead::KeyInit;
use tightbeam::crypto::hash::Digest;

/// Simple test message
#[cfg_attr(feature = "derive", derive(tightbeam::Beamable))]
#[derive(Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

#[cfg(not(feature = "derive"))]
impl tightbeam::Message for TestMessage {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: tightbeam::Version = tightbeam::Version::V0;
}

/// Custom test matrix for message metadata
#[cfg_attr(feature = "derive", derive(tightbeam::Flaggable))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDevelopmentMode {
	#[default]
	Default = 0,
	IsDevelopment = 1,
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

/// Helper to hash a message for verification (uses default hash)
fn hash_message(message: &TestMessage) -> Vec<u8> {
	sha3::Sha3_256::digest(tightbeam::encode(message).unwrap()).to_vec()
}

// Define the flag set with automatic position assignment
tightbeam::flagset!(TestFlagSet: FlagTestDevelopmentMode, FlagTestDebugLevel);

#[test]
fn test_workflow_v0() -> Result<(), Box<dyn core::error::Error>> {
	// Create a test message
	let message = TestMessage { content: "Hello, basic world!".to_string() };

	// Create basic V0 message with just hash verification
	let tightbeam = compose! {
		V0: id: "basic-test",
			order: 1696521500,
			message: message.clone()
	}?;

	// Decode the message (no decryption needed for V0)
	let decoded: TestMessage = tightbeam::decode(&tightbeam.message)?;
	assert_eq!(decoded, message);

	// Verify basic metadata
	assert_eq!(str::from_utf8(&tightbeam.metadata.id), Ok("basic-test"));
	assert_eq!(tightbeam.version, tightbeam::Version::V0);

	// V0 doesn't have encryption, signatures, priority, TTL, or matrix
	assert!(tightbeam.nonrepudiation.is_none());
	assert!(tightbeam.metadata.priority.is_none());
	assert!(tightbeam.metadata.lifetime.is_none());
	assert!(tightbeam.metadata.matrix.is_none());

	Ok(())
}

#[test]
fn test_workflow_v2() -> Result<(), Box<dyn core::error::Error>> {
	// Create a test message
	let message = TestMessage { content: "Hello, secure world!".to_string() };
	// Hash the message
	let message_hash = hash_message(&message);

	// Setup metadata
	let order = 1696521600;
	let ttl = 3600;
	let priority = tb::MessagePriority::High;

	// Setup crypto
	let key = crypto::aead::Key::<crypto::aead::Aes256Gcm>::from_slice(&[0x42; 32]);
	let cipher = crypto::aead::Aes256Gcm::new(key);
	let signing_key = crypto::sign::ecdsa::Secp256k1SigningKey::from_bytes(&[0x33; 32].into())?;
	let verifying_key = signing_key.verifying_key();

	// Create V1 previous message (V1 has hash support)
	let previous_msg = compose! {
		V1: id: "integration-test-previous",
			order: 1696521500,
			message: message.clone(),
			message_integrity: type crypto::hash::Sha3_256,
			confidentiality<crypto::aead::Aes256GcmOid, _>: &cipher
	}?;

	// Get the hash of the previous message for linking
	let previous = previous_msg.metadata.integrity.clone().expect("V1 message should have hash");

	// Create custom flags for this message using the flagset
	let flags = tightbeam::flags![
		TestFlagSet:
			FlagTestDevelopmentMode::IsMaintenanceMode,
			FlagTestDebugLevel::Basic
	];

	// Create full V2 message with all features including custom flags
	let tightbeam = compose! {
		V2: id: "integration-test",
			order: order,
			message: message.clone(),
			message_integrity: type crypto::hash::Sha3_256,
			confidentiality<crypto::aead::Aes256GcmOid, _>: &cipher,
			nonrepudiation<crypto::sign::ecdsa::Secp256k1Signature, _>: &signing_key,
			priority: priority,
			lifetime: ttl,
			previous_frame: previous.clone(),
			matrix: flags
	}?;

	// Decrypt and verify the message was correctly processed
	let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, None)?;
	assert_eq!(decrypted, message);

	// Verify signature
	let result = tightbeam.verify::<crypto::sign::ecdsa::Secp256k1Signature>(verifying_key);
	assert!(result.is_ok());

	// Verify metadata
	assert_eq!(str::from_utf8(&tightbeam.metadata.id), Ok("integration-test"));
	assert_eq!(tightbeam.version, tightbeam::Version::V2);
	assert_eq!(tightbeam.metadata.order, order);
	assert_eq!(tightbeam.metadata.priority, Some(priority));
	assert_eq!(tightbeam.metadata.lifetime, Some(ttl));
	assert_eq!(tightbeam.metadata.previous_frame, Some(previous));
	assert!(tightbeam.metadata.integrity.clone().unwrap().compare(&message_hash));
	assert!(tightbeam.metadata.matrix.is_some());
	assert!(tightbeam.metadata.previous_frame.is_some());

	// Check flag switches using position-aware contains method
	let matrix = MatrixDyn::try_from(tightbeam.metadata.matrix.clone())?;
	let flags = TestFlagSet::from(matrix);
	assert!(flags.contains(FlagTestDevelopmentMode::IsMaintenanceMode));
	assert!(flags.contains(FlagTestDebugLevel::Basic));
	// Negative checks
	assert!(!flags.contains(FlagTestDebugLevel::Default));
	assert!(!flags.contains(FlagTestDevelopmentMode::IsDevelopment));

	Ok(())
}

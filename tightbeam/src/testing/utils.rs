use std::sync::Arc;

use crate::asn1::Frame;
use crate::der::Sequence;

#[cfg(feature = "derive")]
use crate::compose;
#[cfg(feature = "derive")]
use crate::Beamable;

/// Simple test message
#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	pub content: String,
}

/// Simple test message
#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct TestMessage {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl crate::Message for TestMessage {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: crate::Version = crate::Version::V0;
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(confidential)]
pub struct ConfidentialNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct ConfidentialNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl crate::Message for ConfidentialNote {
	const MUST_BE_CONFIDENTIAL: bool = true;
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: crate::Version = crate::Version::V0;
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile = 1)]
pub struct ConfidentialNonrepudiableNote {
	pub content: String,
}

#[cfg(feature = "derive")]
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(message_integrity, frame_integrity)]
pub struct IntegralNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
#[derive(Clone, Debug, PartialEq, Sequence)]
pub struct ConfidentialNonrepudiableNote {
	pub content: String,
}

#[cfg(not(feature = "derive"))]
impl crate::Message for ConfidentialNonrepudiableNote {
	const MUST_BE_CONFIDENTIAL: bool = true;
	const MUST_BE_NON_REPUDIABLE: bool = true;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MIN_VERSION: crate::Version = crate::Version::V0;
}

#[cfg(not(feature = "derive"))]
impl crate::Message for IntegralNote {
	const MUST_BE_NON_REPUDIABLE: bool = false;
	const MUST_BE_CONFIDENTIAL: bool = false;
	const MUST_BE_COMPRESSED: bool = false;
	const MUST_BE_PRIORITIZED: bool = false;
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = true;
	const MUST_HAVE_FRAME_INTEGRITY: bool = true;
	const MIN_VERSION: crate::Version = crate::Version::V0;
}

pub fn create_test_message(content: Option<&str>) -> TestMessage {
	TestMessage {
		content: content.map(|c| c.into()).unwrap_or_else(|| "Hello TightBeam!".to_string()),
	}
}

pub fn create_v0_tightbeam(content: Option<&str>, id: Option<&str>) -> Frame {
	let message = create_test_message(content);

	// Get current time
	#[cfg(feature = "std")]
	let order = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.expect("Time went backwards")
		.as_secs();

	#[cfg(not(feature = "std"))]
	let order: u64 = 1_700_000_000;

	// Get a random id
	#[cfg(feature = "std")]
	let id = id.unwrap_or({
		use crate::crypto::hash::{Digest, Sha3_256};
		let mut bytes: [u8; 32] = [0; 32];

		crate::random::generate_random_bytes(&mut bytes, None).expect("Failed to generate random bytes");

		let hash = Sha3_256::digest(bytes);
		Box::leak(format!("{hash:x}").into_boxed_str())
	});

	#[cfg(not(feature = "std"))]
	let id = id.unwrap_or("test-message-id");

	#[cfg(feature = "derive")]
	let result = compose! {
		V0: id: id,
			order: order,
			message: message
	};

	#[cfg(not(feature = "derive"))]
	let result = crate::Frame::new_v0(id, order, &message);

	result.expect("Failed to create TightBeam message")
}

#[cfg(all(feature = "secp256k1", feature = "signature"))]
pub fn create_test_signing_key() -> k256::ecdsa::SigningKey {
	let secret_bytes = [1u8; 32];
	crate::crypto::sign::ecdsa::SigningKey::from_bytes(&secret_bytes.into()).expect("Failed to create signing key")
}

#[cfg(all(feature = "secp256k1", feature = "signature", feature = "x509"))]
pub fn create_test_certificate(signing_key: &k256::ecdsa::SigningKey) -> crate::x509::Certificate {
	use crate::der::Decode;
	use crate::spki::EncodePublicKey;

	let verifying_key = *signing_key.verifying_key();
	let public_key_der = verifying_key.to_public_key_der().unwrap();

	let tbs_cert = crate::x509::TbsCertificate {
		version: crate::x509::Version::V3,
		serial_number: crate::x509::serial_number::SerialNumber::new(&[1]).unwrap(),
		signature: crate::spki::AlgorithmIdentifierOwned {
			oid: crate::oids::SIGNER_ECDSA_WITH_SHA3_256,
			parameters: None,
		},
		issuer: x509_cert::name::RdnSequence::default(),
		validity: crate::x509::time::Validity {
			not_before: crate::x509::time::Time::UtcTime(
				crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap(),
			),
			not_after: crate::x509::time::Time::UtcTime(
				crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(2_000_000_000)).unwrap(),
			),
		},
		subject: x509_cert::name::RdnSequence::default(),
		subject_public_key_info: crate::spki::SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes()).unwrap(),
		issuer_unique_id: None,
		subject_unique_id: None,
		extensions: None,
	};

	crate::x509::Certificate {
		tbs_certificate: tbs_cert,
		signature_algorithm: crate::spki::AlgorithmIdentifierOwned {
			oid: crate::oids::SIGNER_ECDSA_WITH_SHA3_256,
			parameters: None,
		},
		signature: crate::der::asn1::BitString::new(0, vec![0; 64]).unwrap(),
	}
}

#[cfg(feature = "aead")]
pub fn create_test_cipher_key() -> (
	crate::crypto::common::Key<crate::crypto::aead::Aes256Gcm>,
	crate::crypto::aead::Aes256Gcm,
) {
	use crate::crypto::aead::KeyInit;

	let key_bytes = [0x33; 32];
	let key = crate::crypto::common::Key::<crate::crypto::aead::Aes256Gcm>::from(key_bytes);
	let cipher = crate::crypto::aead::Aes256Gcm::new(&key);
	(key, cipher)
}

pub fn create_test_hash_info() -> crate::DigestInfo {
	crate::DigestInfo {
		algorithm: crate::AlgorithmIdentifier {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"), // SHA-256
			parameters: None,
		},
		digest: crate::asn1::OctetString::new(vec![0u8; 32]).expect("Failed to create OctetString"),
	}
}

/// Create a certificate and key pair that expires soon (within 24 hours).
/// Returns (certificate, signing_key).
///
/// Note: This certificate was generated on 2025-11-09 and expires 2025-11-10.
/// Tests using this will fail after the expiration date.
#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
pub fn create_expiring_test_certificate(
) -> crate::error::Result<(crate::x509::Certificate, crate::crypto::sign::ecdsa::Secp256k1SigningKey)> {
	// Certificate that expires on 2025-11-10 06:35:40 UTC
	let cert = crate::pem! {"
		-----BEGIN CERTIFICATE-----
		MIIBiTCCAS+gAwIBAgIBATALBglghkgBZQMEAwowLTErMCkGA1UEAwwiRXhwaXJp
		bmcgVG9tb3Jyb3cgVGVzdCBDZXJ0aWZpY2F0ZTAeFw0yNTExMDkwNjM1NDBaFw0y
		NTExMTAwNjM1NDBaMC0xKzApBgNVBAMMIkV4cGlyaW5nIFRvbW9ycm93IFRlc3Qg
		Q2VydGlmaWNhdGUwVjAQBgcqhkjOPQIBBgUrgQQACgNCAAQbhMVWexJkQJldPtWq
		ugVl1x4YNGBIGf+cF/Xp1d0Hj3C+r49Yi1QVB/7WpkLFq0Lf34Egp/Y53lEi1Hpp
		qOjRo0IwQDAdBgNVHQ4EFgQUQ65suXrNrzVLgobdsptJLJXpWHAwDwYDVR0TAQH/
		BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCwYJYIZIAWUDBAMKA0cAMEQCIA7h0vvv
		anyhANdtbmk2etj57E5fh1lI3Fg2bePzYq0kAiAL9r2v4pwP8s1uec4FT7HAUYf6
		T4zOUKsmsdnnAwTztg==
		-----END CERTIFICATE-----
	"}?;

	// Corresponding private key (fixed test key)
	let key_bytes: [u8; 32] = [0x01; 32];
	let signing_key = crate::crypto::sign::ecdsa::Secp256k1SigningKey::from_bytes(&key_bytes.into())?;

	Ok((cert, signing_key))
}

pub fn create_test_encryption_info() -> crate::EncryptedContentInfo {
	crate::EncryptedContentInfo {
		content_type: crate::oids::COMPRESSION_CONTENT,
		content_enc_alg: crate::AlgorithmIdentifier {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42"), // AES-256-GCM
			parameters: None,
		},
		encrypted_content: Some(crate::der::asn1::OctetString::new(vec![0u8; 12]).unwrap()),
	}
}

pub fn create_test_signer_info() -> crate::SignerInfo {
	use crate::cms::content_info::CmsVersion;
	use crate::cms::signed_data::SignerIdentifier;
	use crate::der::asn1::OctetString;
	use crate::x509::ext::pkix::SubjectKeyIdentifier;

	let skid = SubjectKeyIdentifier::from(OctetString::new([0u8; 20]).unwrap());

	crate::SignerInfo {
		version: CmsVersion::V1,
		sid: SignerIdentifier::SubjectKeyIdentifier(skid),
		digest_alg: crate::AlgorithmIdentifierOwned { oid: crate::oids::HASH_SHA3_256, parameters: None },
		signed_attrs: None,
		signature_algorithm: crate::AlgorithmIdentifierOwned {
			oid: crate::oids::SIGNER_ECDSA_WITH_SHA3_256,
			parameters: None,
		},
		signature: OctetString::new([0u8; 64]).unwrap(),
		unsigned_attrs: None,
	}
}

/// Generic builder test macro
///
/// Similar to test_case! but specifically designed for testing builders.
/// Automatically provides a base builder instance and allows customization.
/// Passes both the input message and the resulting frame to assertions.
///
/// The `message` parameter supports two forms:
/// - Direct value: `message: create_test_message(None)`
/// - Closure: `message: || { create_test_message(None) }`
#[macro_export]
macro_rules! test_builder {
	// Closure form: message: || { ... }
	(
		name: $test_name:ident,
		builder_type: $builder_type:ty,
		version: $version:expr,
		message: || $message_body:expr,
		setup: |$builder:ident, $msg:ident| $setup_body:expr,
		assertions: |$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		$crate::test_builder!(@impl
			$test_name,
			$builder_type,
			$version,
			{ $message_body },
			|$builder, $msg| $setup_body,
			|$msg_result, $frame_result| $assertions_body
		);
	};

	// Direct value form: message: some_value
	(
		name: $test_name:ident,
		builder_type: $builder_type:ty,
		version: $version:expr,
		message: $message:expr,
		setup: |$builder:ident, $msg:ident| $setup_body:expr,
		assertions: |$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		$crate::test_builder!(@impl
			$test_name,
			$builder_type,
			$version,
			$message,
			|$builder, $msg| $setup_body,
			|$msg_result, $frame_result| $assertions_body
		);
	};

	// Internal implementation (not exposed to users)
	(@impl
		$test_name:ident,
		$builder_type:ty,
		$version:expr,
		$message:expr,
		|$builder:ident, $msg:ident| $setup_body:expr,
		|$msg_result:ident, $frame_result:ident| $assertions_body:expr
	) => {
		#[test]
		fn $test_name() -> $crate::error::Result<()> {
			let $msg = $message;
			let msg_clone = $msg.clone();
			let $builder: $builder_type = <$builder_type>::from($version);
			let $frame_result = $setup_body;
			let $msg_result = msg_clone;
			$assertions_body
		}
	};
}

// Helper: match a Frame against various "expected" forms.
// - Frame => compare metadata.id
// - Result<Frame, E> => compare metadata.id from Ok(frame)
// - Any T: Beamable + PartialEq => decode T from frame.message and compare
pub trait ExpectedMatcher {
	fn matches(&self, frame: &Frame) -> bool;
}

impl ExpectedMatcher for crate::Frame {
	fn matches(&self, frame: &Frame) -> bool {
		frame.metadata.id == self.metadata.id
	}
}

impl ExpectedMatcher for Arc<crate::Frame> {
	fn matches(&self, frame: &Frame) -> bool {
		self.metadata.id == frame.metadata.id
	}
}

impl<E> ExpectedMatcher for Result<crate::Frame, E> {
	fn matches(&self, frame: &Frame) -> bool {
		match self {
			Ok(f) => frame.metadata.id == f.metadata.id,
			Err(_) => false,
		}
	}
}

impl<T> ExpectedMatcher for T
where
	T: crate::Message + PartialEq,
{
	fn matches(&self, frame: &Frame) -> bool {
		if let Ok(decoded) = crate::decode::<T>(&frame.message) {
			decoded == *self
		} else {
			false
		}
	}
}

/// Async test macro with worker setup
///
/// Automatically starts a worker and passes it to the assertions block for testing.
/// Properly manages worker lifecycle with shutdown.
#[macro_export]
macro_rules! test_worker {
	(
		name: $test_name:ident,
		setup: || $setup_body:expr,
		assertions: |$worker:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			use $crate::colony::worker::Worker;

			// Build and start the worker
			let builder = $setup_body;
			let trace = std::sync::Arc::new($crate::trace::TraceCollector::new());
			let mut worker = <_ as $crate::colony::worker::Worker>::start(builder, trace).await?;

			// Run assertions with reference to worker
			let result = {
				let $worker = &mut worker;
				$assertions_body.await
			};

			// Worker will be dropped automatically at end of test
			// Explicitly killing causes nested runtime issues when called from async tests
			drop(worker);

			result
		}
	};
}

/// Async test macro with worker setup
///
/// Automatically starts a worker, creates a client, and passes the ready
/// client to the assertions block for testing. Properly manages worker
/// lifecycle.
#[macro_export]
macro_rules! test_servlet {
	// With worker_threads specified
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Call the setup closure and await the resulting future
			let worker = $setup_body.await?;
			// Get the worker address
			let addr = worker.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			worker.stop();

			result
		}
	};

	// Without worker_threads (defaults to single threaded)
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Call the setup closure and await the resulting future
			let worker = ($setup_body).await?;

			// Get the worker address
			let addr = worker.addr();

			// Create client
			let mut $client = $crate::client! {
				async $protocol: connect addr
			}
			.await?;

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			worker.stop();

			result
		}
	};
}

/// Async test macro for drones
///
/// Automatically starts a drone, creates a client, and passes the ready
/// client to the assertions block for testing. Properly manages drone lifecycle.
///
/// Note: Gate observation channels are not yet implemented for drones.
/// The `channels` parameter is reserved for future use.
#[macro_export]
macro_rules! test_drone {
	// With worker_threads and setup callback
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		setup: |$setup_drone:ident| $setup_body:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone =
				<$drone_type as $crate::colony::servlet::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
					.await?;

			// Call the setup closure and await the resulting future
			let $setup_drone = drone;
			let drone = $setup_body.await;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for drones)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Without worker_threads but with setup callback
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		setup: |$setup_drone:ident| $setup_body:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone = <$drone_type as $crate::colony::servlet::Servlet<()>>::start(
				::std::sync::Arc::new($crate::trace::TraceCollector::new()),
				$config,
			)
			.await?;

			// Call the setup closure and await the resulting future
			let $setup_drone = drone;
			let drone = $setup_body.await;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for drones)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Simple variant without setup callback, with worker_threads
	(
		name: $test_name:ident,
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone =
				<$drone_type as $crate::colony::servlet::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
					.await?;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for drones)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};

	// Simple variant without setup callback, without worker_threads
	(
		name: $test_name:ident,
		protocol: $protocol:ident,
		drone: $drone_type:ty,
		config: $config:expr,
		assertions: |$client:ident, $channels:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Start the drone
			let drone =
				<$drone_type as $crate::colony::servlet::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
					.await?;

			// Get the drone address
			let addr = drone.addr();

			// Create client
			let mut $client = $crate::client! {
				connect $protocol: addr
			};

			// Placeholder channels tuple (not yet implemented for drones)
			let $channels = ((), ());

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			drone.stop();

			result
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::builder::MetadataBuilder;
	use crate::{Metadata, Version};

	#[test]
	#[cfg(feature = "std")]
	fn test_create_test_message() -> crate::error::Result<()> {
		let message = create_test_message(Some("Test content"));
		assert_eq!(message.content, "Test content");
		Ok(())
	}

	test_builder! {
		name: test_metadata_builder_basic,
		builder_type: MetadataBuilder,
		version: Version::V0,
		message: (),
		setup: |builder, _msg| {
			builder
				.with_id("test-id")
				.with_order(1696521600)
				.build()
		},
		assertions: |_msg, result| {
			let metadata: Metadata = result?;
			assert_eq!(metadata.id, b"test-id");
			assert_eq!(metadata.order, 1696521600);
			assert!(metadata.integrity.is_none());
			Ok(())
		}
	}
}

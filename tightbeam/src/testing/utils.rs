use crate::asn1::Frame;
use crate::der::Sequence;
use std::sync::Arc;

#[cfg(feature = "derive")]
use crate::{compose, Beamable};

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

/// Generic test macro for data-driven test cases
///
/// Allows specifying setup that returns any type, and assertions that
/// receive that type.
#[macro_export]
macro_rules! test_case {
	(
		name: $test_name:ident,
		setup: $setup:expr,
		assertions: |$result_pat:pat_param| $body:block
	) => {
		#[test]
		fn $test_name() -> $crate::error::Result<()> {
			let $result_pat = $setup();
			$body
		}
	};

	// Back-compat: closure form
	(
		name: $test_name:ident,
		setup: $setup:expr,
		assertions: $assertions:expr
	) => {
		#[test]
		fn $test_name() -> $crate::error::Result<()> {
			let result = $setup();
			$assertions(result)
		}
	};
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

#[macro_export]
macro_rules! test_container {
	// Protocol setup with X.509 support
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident, $cert:ident, with_x509) => {
		#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
		{
			use $crate::crypto::sign::ecdsa::SigningKey;
			use $crate::crypto::sign::ecdsa::signature::Signer;
			use std::str::FromStr;

			// Generate server signing key
			let signing_key = $crate::crypto::sign::ecdsa::SigningKey::random(&mut $crate::random::SecureRng);
			let verifying_key = signing_key.verifying_key();
			let spki = $crate::x509::SubjectPublicKeyInfo::try_from(verifying_key)?;
			let sha3_signer = $crate::crypto::sign::ecdsa::Sha3Signer::new(signing_key.clone());

			// Create validity period
			let not_before = std::time::SystemTime::now();
			let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60);

			// Create self-signed root certificate
			let $cert = $crate::cert!(
				profile: Root,
				subject: "CN=Test Root CA,O=Test Org,C=US",
				serial: 1u32,
				validity: (not_before, not_after),
				signer: &sha3_signer,
				subject_public_key: spki
			)?;

			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let config = $crate::transport::TransportEncryptionConfig::new(
				$cert.clone(),
				std::sync::Arc::new(signing_key.clone())
					as std::sync::Arc<dyn $crate::transport::handshake::ServerHandshakeKey>,
			);
			let ($listener, $addr) = <$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, config).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
		}
	};

	// Protocol setup without X.509
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident, $cert:ident, no_x509) => {
		let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let ($listener, $addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
		#[allow(unused_variables)]
		let $cert: Option<$crate::x509::Certificate> = None;
	};

	// Helper to detect if with_x509 is in policy list
	(@has_x509 []) => { no_x509 };
	(@has_x509 [with_x509 $(, $rest:ident)*]) => { with_x509 };
	(@has_x509 [$first:ident $(, $rest:ident)*]) => { test_container!(@has_x509 [$($rest),*]) };

	// Generic pattern with arbitrary worker_threads
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		worker_threads: $threads:literal,
		protocol: $protocol:path,
		$(service_policies: { $($server_policy_key:ident: $server_policy_val:tt),* $(,)? },)?
		$(client_policies: { $($client_policy_key:ident: $client_policy_val:tt),* $(,)? },)?
		service: |$svc_message:ident, $svc_tx:ident| $service_body:expr,
		container: |$client:ident, $channels:ident| $container_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> ::core::result::Result<(), Box<dyn core::error::Error>> {
			test_container!(@test_body
				$protocol,
				[$($($server_policy_key: $server_policy_val),*)?],
				[$($($client_policy_key: $client_policy_val),*)?],
				|$svc_message, $svc_tx| $service_body,
				|$client, $channels| $container_body
			)
		}
	};

	// Generic pattern with arbitrary worker_threads
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		worker_threads: $threads:literal,
		protocol: $protocol:path,
		$(service_policies: { $($server_policy_key:ident: $server_policy_val:tt),* $(,)? },)?
		$(client_policies: { $($client_policy_key:ident: $client_policy_val:tt),* $(,)? },)?
		service: |$svc_message:ident, $svc_tx:ident| $service_body:expr,
		container: |$client:ident, $channels:ident| $container_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> ::core::result::Result<(), Box<dyn core::error::Error>> {
			test_container!(@test_body
				$protocol,
				[$($($server_policy_key: $server_policy_val),*)?],
				[$($($client_policy_key: $client_policy_val),*)?],
				|$svc_message, $svc_tx| $service_body,
				|$client, $channels| $container_body
			)
		}
	};

	// Pattern without worker_threads (defaults to 2)
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		protocol: $protocol:path,
		$(service_policies: { $($server_policy_key:ident: $server_policy_val:tt),* $(,)? },)?
		$(client_policies: { $($client_policy_key:ident: $client_policy_val:tt),* $(,)? },)?
		service: |$svc_message:ident, $svc_tx:ident| $service_body:expr,
		container: |$client:ident, $channels:ident| $container_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> ::core::result::Result<(), Box<dyn core::error::Error>> {
			test_container!(@test_body
				$protocol,
				[$($($server_policy_key: $server_policy_val),*)?],
				[$($($client_policy_key: $client_policy_val),*)?],
				|$svc_message, $svc_tx| $service_body,
				|$client, $channels| $container_body
			)
		}
	};

	// Test body implementation with X.509 support
	// Specialized: server policies only contain with_x509 (any value) – exclude from server! policies
	(@test_body $protocol:path,
		[with_x509: $xval:tt],
		[$($client_policy_key:tt)*],
		|$svc_message:ident, $svc_tx:ident| $service_body:expr,
		|$client:ident, $channels:ident| $container_body:expr
	) => {{
		{
			use std::sync::{mpsc, Arc};

			// Setup protocol (already handles with_x509)
			#[allow(unused_variables)]
			let (listener, addr, server_cert) = test_container!(@setup_protocol_dispatch $protocol, [with_x509: $xval]);

			let (server_tx, rx_inner) = mpsc::channel();
			let tx = Arc::new(server_tx);
			let (ok_tx_inner, ok_rx_inner): (mpsc::Sender<Arc<$crate::Frame>>, mpsc::Receiver<Arc<$crate::Frame>>) = mpsc::channel();
			let (reject_tx_inner, reject_rx_inner): (mpsc::Sender<Arc<$crate::Frame>>, mpsc::Receiver<Arc<$crate::Frame>>) = mpsc::channel();
			let ok_tx_arc = Arc::new(ok_tx_inner);
			let reject_tx_arc = Arc::new(reject_tx_inner);

			// Build server with NO runtime policies (with_x509 is setup-only)
			let server_handle = {
				let tx_clone = tx.clone();
				let ok_tx_clone = ok_tx_arc.clone();
				let reject_tx_clone = reject_tx_arc.clone();
				test_container!(@build_server
					$protocol,
					listener,
					tx_clone,
					ok_tx_clone,
					reject_tx_clone,
					[],
					|$svc_message: $crate::Frame, $svc_tx| $service_body
				)
			};

			let mut $client = test_container!(@build_client_x509 $protocol, addr, server_cert, [$($client_policy_key)*]);
			let $channels = (rx_inner, ok_rx_inner, reject_rx_inner);
			let container_result: core::result::Result<(), Box<dyn core::error::Error>> = $container_body.await;
			server_handle.abort();
			container_result
		}
	}};
	(@test_body $protocol:path,
		[$($server_policy_key:tt)*],
		[$($client_policy_key:tt)*],
		|$svc_message:ident, $svc_tx:ident| $service_body:expr,
		|$client:ident, $channels:ident| $container_body:expr
	) => {
		{
			use std::sync::{mpsc, Arc};

			// Setup protocol with X.509 if present in server policies
			#[allow(unused_variables)]
			let (listener, addr, server_cert) = test_container!(@setup_protocol_dispatch $protocol, [$($server_policy_key)*]);

			// Server handler channel: tx for server, rx for container
			let (server_tx, rx_inner) = mpsc::channel();
			let tx = Arc::new(server_tx);

			// Status channels (container receives ok/reject)
			let (ok_tx_inner, ok_rx_inner): (mpsc::Sender<Arc<$crate::Frame>>, mpsc::Receiver<Arc<$crate::Frame>>) = mpsc::channel();
			let (reject_tx_inner, reject_rx_inner): (mpsc::Sender<Arc<$crate::Frame>>, mpsc::Receiver<Arc<$crate::Frame>>) = mpsc::channel();
			let ok_tx_arc = Arc::new(ok_tx_inner);
			let reject_tx_arc = Arc::new(reject_tx_inner);

			// Build server
			let server_handle = {
				let tx_clone = tx.clone();
				let ok_tx_clone = ok_tx_arc.clone();
				let reject_tx_clone = reject_tx_arc.clone();
				test_container!(@build_server
					$protocol,
					listener,
					tx_clone,
					ok_tx_clone,
					reject_tx_clone,
					[$($server_policy_key)*],
					|$svc_message: $crate::Frame, $svc_tx| $service_body
				)
			};

			// Build client (pass server_cert which may be None or Some(cert))
			let mut $client = test_container!(@build_client_x509 $protocol, addr, server_cert, [$($client_policy_key)*]);

			// Expose a single tuple to the container
			let $channels = (rx_inner, ok_rx_inner, reject_rx_inner);

			// Run container body returning a Box<dyn Error>
			let container_result: core::result::Result<(), Box<dyn core::error::Error>> = $container_body.await;

			// If the container errors, print a full backtrace to help debugging.
			#[cfg(feature = "std")]
			if let Err(ref e) = container_result {
				let mut source = e.source();
				while let Some(src) = source {
					source = src.source();
				}
			}

			// Cleanup
			server_handle.abort();

			// Return container result
			container_result
		}
	};

	// Dispatch to correct setup based on presence of with_x509 and with_x509_gate
	// Match: with_collector_gate first, then with_x509, then with_x509_gate
	(@setup_protocol_dispatch $protocol:path,
		[with_collector_gate: $gate:tt, with_x509: [], with_x509_gate: [$validator:expr]]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [], with_x509_gate: [$validator])
	};
	(@setup_protocol_dispatch $protocol:path,
		[with_collector_gate: $gate:tt, with_x509: [$cert_expr:expr, $key_expr:expr], with_x509_gate: [$validator:expr]]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [$cert_expr, $key_expr], with_x509_gate: [$validator])
	};
	(@setup_protocol_dispatch $protocol:path,
		[with_collector_gate: $gate:tt, with_x509: []]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [])
	};
	(@setup_protocol_dispatch $protocol:path,
		[with_collector_gate: $gate:tt, with_x509: [$cert_expr:expr, $key_expr:expr]]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [$cert_expr, $key_expr])
	};
	// Match: with_x509 and with_x509_gate
	(@setup_protocol_dispatch $protocol:path,
		[with_x509: [], with_x509_gate: [$validator:expr] $(, $($rest:tt)*)?]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [], with_x509_gate: [$validator])
	};
	(@setup_protocol_dispatch $protocol:path,
		[with_x509: [$cert_expr:expr, $key_expr:expr], with_x509_gate: [$validator:expr] $(, $($rest:tt)*)?]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [$cert_expr, $key_expr], with_x509_gate: [$validator])
	};
	// Match: with_x509 only
	(@setup_protocol_dispatch $protocol:path,
		[with_x509: [] $(, $($rest:tt)*)?]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [])
	};
	(@setup_protocol_dispatch $protocol:path,
		[with_x509: [$cert_expr:expr, $key_expr:expr] $(, $($rest:tt)*)?]) => {
		test_container!(@setup_protocol_x509_impl $protocol, with_x509: [$cert_expr, $key_expr])
	};
	// No with_x509 at all
	(@setup_protocol_dispatch $protocol:path, [$($any:tt)*]) => {
		test_container!(@setup_protocol_x509_impl $protocol)
	};

	// X.509 setup helper - with x509 auto-generate certificate and optional validator
	(@setup_protocol_x509_impl $protocol:path, with_x509: [], with_x509_gate: [$validator:expr]) => {{
		#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
		{
			use spki::SubjectPublicKeyInfoOwned;

			// Generate server signing key using test helper
			let signing_key = $crate::testing::create_test_signing_key();
			let verifying_key = $crate::crypto::sign::ecdsa::Secp256k1VerifyingKey::from(&signing_key);
			let sha3_signer = $crate::crypto::sign::Sha3Signer::from(&signing_key);
			let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

			// Create validity period
			let not_before = std::time::Instant::now();
			let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60);

			// Create self-signed root certificate
			let cert = Some($crate::cert!(
				profile: Root,
				subject: "CN=Test Root CA,O=Test Org,C=US",
				serial: 1u32,
				validity: (not_before, not_after),
				signer: &sha3_signer,
				subject_public_key: spki
			)?);

			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let config = $crate::transport::TransportEncryptionConfig::new(
			cert.clone().unwrap(),
			std::sync::Arc::new(signing_key.clone())
				as std::sync::Arc<dyn $crate::transport::handshake::ServerHandshakeKey>,
		)
		.with_client_validators(vec![std::sync::Arc::new($validator) as std::sync::Arc<dyn $crate::crypto::x509::policy::CertificateValidation>]);
		let (listener, addr) = <$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, config).await
			.map_err(|e| $crate::TightBeamError::from(e))?;			(listener, addr, cert)
		}
		#[cfg(not(all(feature = "x509", feature = "secp256k1", feature = "signature")))]
		{
			// Fallback when features not enabled
			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let cert: Option<$crate::x509::Certificate> = None;

			(listener, addr, cert)
		}
	}};

	// X.509 setup helper - with x509 using provided certificate and signing key, with validator
	(@setup_protocol_x509_impl $protocol:path, with_x509: [$cert_expr:expr, $key_expr:expr], with_x509_gate: [$validator:expr]) => {{
		#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
		{
			let cert = Some($cert_expr);
			let signing_key = $key_expr;

			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let config = $crate::transport::TransportEncryptionConfig::new(
				cert.clone().unwrap(),
				std::sync::Arc::new(signing_key)
					as std::sync::Arc<dyn $crate::transport::handshake::ServerHandshakeKey>,
			)
			.with_certificate_validator(std::sync::Arc::new($validator));
			let (listener, addr) = <$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, config).await
				.map_err(|e| $crate::TightBeamError::from(e))?;

			(listener, addr, cert)
		}
		#[cfg(not(all(feature = "x509", feature = "secp256k1", feature = "signature")))]
		{
			// Fallback when features not enabled
			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let cert: Option<$crate::x509::Certificate> = None;

			(listener, addr, cert)
		}
	}};

	// X.509 setup helper - with x509 auto-generate certificate (no validator)
	(@setup_protocol_x509_impl $protocol:path, with_x509: []) => {{
		#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
		{
			use spki::SubjectPublicKeyInfoOwned;

			// Generate server signing key using test helper
			let signing_key = $crate::testing::create_test_signing_key();
			let verifying_key = $crate::crypto::sign::ecdsa::Secp256k1VerifyingKey::from(&signing_key);
			let sha3_signer = $crate::crypto::sign::Sha3Signer::from(&signing_key);
			let spki = SubjectPublicKeyInfoOwned::from_key(verifying_key)?;

			// Create validity period
			let not_before = std::time::Instant::now();
			let not_after = not_before + std::time::Duration::from_secs(365 * 24 * 60 * 60);

			// Create self-signed root certificate
			let cert = Some($crate::cert!(
				profile: Root,
				subject: "CN=Test Root CA,O=Test Org,C=US",
				serial: 1u32,
				validity: (not_before, not_after),
				signer: &sha3_signer,
				subject_public_key: spki
			)?);

			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let key_manager = signing_key.clone().into();
			let config = $crate::transport::TransportEncryptionConfig::new(
				cert.clone().unwrap(),
				key_manager,
			);
			let (listener, addr) = <$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, config).await
				.map_err(|e| $crate::TightBeamError::from(e))?;

			(listener, addr, cert)
		}
		#[cfg(not(all(feature = "x509", feature = "secp256k1", feature = "signature")))]
		{
			// Fallback when features not enabled
			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let cert: Option<$crate::x509::Certificate> = None;

			(listener, addr, cert)
		}
	}};

	// X.509 setup helper - with x509 using provided certificate and signing key
	(@setup_protocol_x509_impl $protocol:path, with_x509: [$cert_expr:expr, $key_expr:expr]) => {{
		#[cfg(all(feature = "x509", feature = "secp256k1", feature = "signature"))]
		{
			let cert = Some($cert_expr);
			let signing_key = $key_expr;

			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let key_manager = signing_key.into();
			let config = $crate::transport::TransportEncryptionConfig::new(
				cert.clone().unwrap(),
				key_manager,
			);
			let (listener, addr) = <$protocol as $crate::transport::EncryptedProtocol>::bind_with(bind_addr, config).await
				.map_err(|e| $crate::TightBeamError::from(e))?;

			(listener, addr, cert)
		}
		#[cfg(not(all(feature = "x509", feature = "secp256k1", feature = "signature")))]
		{
			// Fallback when features not enabled
			let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
				.map_err(|e| $crate::TightBeamError::from(e))?;
			let cert: Option<$crate::x509::Certificate> = None;

			(listener, addr, cert)
		}
	}};

	// X.509 setup helper - without x509
	(@setup_protocol_x509_impl $protocol:path) => {{
		let bind_addr = <$protocol as $crate::transport::Protocol>::default_bind_address()
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let (listener, addr) = <$protocol as $crate::transport::Protocol>::bind(bind_addr).await
			.map_err(|e| $crate::TightBeamError::from(e))?;
		let cert: Option<$crate::x509::Certificate> = None;

		(listener, addr, cert)
	}};

	// Build client with X.509 support and policies
	(@build_client_x509 $protocol:path, $addr:ident, $cert:ident, [$($policy:tt)*]) => {{
		{
			let stream = <$protocol as $crate::transport::Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let mut transport = <$protocol as $crate::transport::Protocol>::create_transport(stream);

			// Apply X.509 and other policies
			transport = test_container!(@apply_client_policies transport, $cert, [$($policy)*]);

			transport
		}
	}};

	// Apply client policies - handle with_x509 specially (auto-generate)
	(@apply_client_policies $transport:expr, $cert:ident, [with_x509: [] $(, $($rest:tt)*)?]) => {{
		let mut __transport = $transport;
		if let Some(cert) = $cert {
			__transport = __transport.with_server_certificate(cert);
		}
		$( __transport = test_container!(@apply_client_policies __transport, $cert, [$($rest)*]); )?
		__transport
	}};
	// Apply client policies - handle with_x509 with explicit certificate
	(@apply_client_policies $transport:expr, $cert:ident, [with_x509: [$cert_expr:expr] $(, $($rest:tt)*)?]) => {{
		let mut __transport = $transport;
		__transport = __transport.with_server_certificate($cert_expr);
		$( __transport = test_container!(@apply_client_policies __transport, $cert, [$($rest)*]); )?
		__transport
	}};
	// Apply client policies - handle with_x509 with cert and key (ignore key for client)
	(@apply_client_policies $transport:expr, $cert:ident, [with_x509: [$cert_expr:expr, $key_expr:expr] $(, $($rest:tt)*)?]) => {{
		let mut __transport = $transport;
		__transport = __transport.with_server_certificate($cert_expr);
		$( __transport = test_container!(@apply_client_policies __transport, $cert, [$($rest)*]); )?
		__transport
	}};
	// Apply client policies - handle with_x509_gate specially (client validates server cert)
	(@apply_client_policies $transport:expr, $cert:ident, [with_x509_gate: [ $( $validator:expr ),* $(,)? ] $(, $($rest:tt)*)?]) => {{
		let mut __transport = $transport;
		$(
			__transport = __transport.with_x509_gate($validator);
		)*
		$( __transport = test_container!(@apply_client_policies __transport, $cert, [$($rest)*]); )?
		__transport
	}};
	// Apply client policies - generic fallback for other policies
	(@apply_client_policies $transport:expr, $cert:ident, [$policy_key:ident: $policy_val:tt $(, $($rest:tt)*)?]) => {{
		let __transport = $crate::test_container!(@set_client_policy $transport, $policy_key, $policy_val);
		$( let __transport = test_container!(@apply_client_policies __transport, $cert, [$($rest)*]); )?
		__transport
	}};
	(@apply_client_policies $transport:expr, $cert:ident, []) => { $transport };

	// Internal helper to set client policies with correct method names
	// Expects policies in the format: policy_name: [value1, value2, ...]
	(@set_client_policy $transport:expr, with_restart, [ $( $value:expr ),* $(,)? ]) => {{
		let mut __transport = $transport;
		$(
			__transport = __transport.with_restart($value);
		)*
		__transport
	}};
	(@set_client_policy $transport:expr, with_emitter_gate, [ $( $value:expr ),* $(,)? ]) => {{
		let mut __transport = $transport;
		$(
			__transport = __transport.with_emitter_gate($value);
		)*
		__transport
	}};
	(@set_client_policy $transport:expr, with_collector_gate, [ $( $value:expr ),* $(,)? ]) => {{
		let mut __transport = $transport;
		$(
			__transport = __transport.with_collector_gate($value);
		)*
		__transport
	}};
	(@set_client_policy $transport:expr, with_x509_gate, [ $( $value:expr ),* $(,)? ]) => {{
		let mut __transport = $transport;
		$(
			__transport = __transport.with_x509_gate($value);
		)*
		__transport
	}};

	// Build server with policies - wrap with_collector_gate in GateMiddleware for tracking
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident,
		[with_collector_gate: [ $( $gate:expr ),* $(,)? ] $(, $($rest_key:ident: $rest_val:tt),* )?],
		|$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				policies: {
					with_collector_gate: [$(
						{
							let ok_tx_for_gate = $ok_tx.clone();
							let reject_tx_for_gate = $reject_tx.clone();
							$crate::policy::GateMiddleware::new(
								$gate,
								move |message: &$crate::Frame, status: &$crate::policy::TransitStatus| {
									if *status == $crate::policy::TransitStatus::Accepted {
										let _ = ok_tx_for_gate.send(::std::sync::Arc::new(message.clone()));
									} else {
										let _ = reject_tx_for_gate.send(::std::sync::Arc::new(message.clone()));
									}
								}
							)
						}
					),*]
					$(, $($rest_key: $rest_val),*)?
				},
				handle: move |$msg: $msg_ty| {
					let $svc_tx = $tx.clone();
					$body
				}
			}
		}
	};

	// Build server with policies (no with_collector_gate) - policies are already in array format
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident, [$($policy_key:ident: $policy_val:tt),+], |$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),+ },
				handle: move |$msg: $msg_ty| {
					let $svc_tx = $tx.clone();
					$body
				}
			}
		}
	};

	// Build server without any policies
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident, [], |$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				handle: move |$msg: $msg_ty| {
					let $svc_tx = $tx.clone();
					$body
				}
			}
		}
	};
}

/// Assert a channel has no pending message
#[macro_export]
macro_rules! assert_channel_empty {
	($rx:expr) => {
		match $rx.try_recv() {
			Ok(_) => panic!(concat!(stringify!($rx), " received a message")),
			Err(std::sync::mpsc::TryRecvError::Empty) => {}
			Err(std::sync::mpsc::TryRecvError::Disconnected) => {
				panic!(concat!("channel disconnected: ", stringify!($rx)))
			}
		}
	};
	($rx:expr, $msg:expr) => {
		match $rx.try_recv() {
			Ok(_) => panic!($msg),
			Err(std::sync::mpsc::TryRecvError::Empty) => {}
			Err(std::sync::mpsc::TryRecvError::Disconnected) => {
				panic!(concat!("channel disconnected: ", stringify!($rx)))
			}
		}
	};
}

/// Assert server/ok/reject are all quiet (no delivery)
#[macro_export]
macro_rules! assert_channels_quiet {
	($($ch:expr),+ $(,)?) => {{
		$( assert_channel_empty!($ch, concat!(stringify!($ch), " received a message")); )*
	}};
}

#[macro_export]
macro_rules! assert_channel_ne {
	($rx:expr, $msg:expr) => {{
		// Scoped, immediate drain check so the receiver can be moved later.
		let __id = ($msg).metadata.id.clone();
		while let Ok(__m) = $rx.try_recv() {
			assert!(__m.metadata.id != __id, "channel received forbidden message id: {:#?}", __id);
		}
	}};
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

/// Assert that a channel receives a specific TightBeam message within a count,
/// draining whatever is already available (no wait).
/// Supports:
/// - Frame / Result<Frame, E>: matched by metadata.id
/// - Any Beamable/Message value: matched by decoding and comparing equality
#[macro_export]
macro_rules! assert_recv {
	// Count form: consume up to N matches, stop once satisfied (non-blocking)
	($rx:expr, $expected:expr, $n:expr) => {{
		use $crate::testing::ExpectedMatcher as _;
		let __expected_ref = &($expected);
		let mut __got: usize = 0;
		while __got < ($n as usize) {
			match $rx.try_recv() {
				Ok(__m) => {
					if __expected_ref.matches(__m.as_ref()) {
						__got += 1;
					}
				}
				Err(std::sync::mpsc::TryRecvError::Empty) => break,
				Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
			}
		}
		assert!(
			__got == ($n as usize),
			"assert_recv! expected {} occurrences, got {} (non-blocking, stop on match)",
			$n as usize,
			__got
		);
	}};

	// Single form: stop on first match (non-blocking)
	($rx:expr, $expected:expr) => {{
		use $crate::testing::ExpectedMatcher as _;
		let __expected_ref = &($expected);
		let mut __found = false;
		while let Ok(__m) = $rx.try_recv() {
			if __expected_ref.matches(__m.as_ref()) {
				__found = true;
				break;
			}
		}
		assert!(
			__found,
			"assert_recv! expected at least 1 occurrence but none was received (non-blocking, stop on first match)"
		);
	}};
}

/// Start a background collector that orders each reject for a given id.
#[macro_export]
macro_rules! start_reject_order_collection {
	($rx:expr, $id:expr, $attempts:expr) => {{
		use std::sync::{Arc, Mutex};
		let __times: Arc<Mutex<Vec<std::time::Instant>>> = Arc::new(Mutex::new(Vec::new()));
		let __times_thread = __times.clone();
		let __expected_id = ($id);
		let __attempts: usize = $attempts as usize;
		let __handle = std::thread::spawn(move || {
			let mut __seen = 0usize;
			while __seen < __attempts {
				match $rx.recv() {
					Ok(__m) => {
						if __m.metadata.id == __expected_id {
							__times_thread.lock().unwrap().push(std::time::Instant::now());
							__seen += 1;
						}
					}
					Err(_) => break,
				}
			}
		});
		(__times, __handle)
	}};
}

/// Finish the background collector and return the captured Instants.
#[macro_export]
macro_rules! finish_reject_order_collection {
	($times:expr, $handle:expr) => {{
		let _ = $handle.join();
		($times).lock().unwrap().clone()
	}};
}

/// Assert client retry timing against expected backoff ranges.
/// Uses the provided reject tunnel to order each non-Accepted server response
/// for the given message id. attempts must be a compile-time constant; the
/// number of ranges must be attempts-1 (enforced at compile time).
#[macro_export]
macro_rules! assert_retry_metric {
	($client:expr, $msg:expr, $rx:expr, $attempts:expr, [ $( [$min:expr, $max:expr] ),* $(,)? ]) => {{
		// Compile-time attempts constant and ranges length enforcement
		const __ATTEMPTS: usize = $attempts;
		let __expected: [(u64, u64); __ATTEMPTS - 1] = [ $( ($min as u64, $max as u64) ),* ];

		// Expected id
		let __id = ($msg).metadata.id.clone();

		// Start order collection on the provided reject tunnel
		let (__times, __handle) = $crate::start_reject_order_collection!($rx, __id.clone(), __ATTEMPTS);

		// Trigger client send + internal retries according to restart policy
		let __res = $client.emit(($msg).clone(), None).await;
		assert!(__res.is_err(), "expected error after retries to exhaust");

		// Finish collection and validate attempt count
		let __ts = $crate::finish_reject_order_collection!(__times, __handle);
		assert_eq!(__ts.len(), __ATTEMPTS, "expected {} attempts observed on server", __ATTEMPTS);

		// Compare observed deltas to expected ranges (inclusive)
		for (i, (lo, hi)) in __expected.iter().copied().enumerate() {
			let d = __ts[i + 1].duration_since(__ts[i]).as_millis() as u64;
			assert!(d >= lo, "backoff[{}] too small: {}ms < {}ms", i, d, lo);
			assert!(d <= hi, "backoff[{}] too large: {}ms > {}ms", i, d, hi);
		}
	}};
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
			// Call the setup closure and get the worker
			let worker = $setup_body?;

			// Run assertions with reference to worker
			let result = {
				let $worker = &worker;
				$assertions_body.await
			};

			// Clean shutdown
			#[cfg(feature = "tokio")]
			worker.kill().await?;
			#[cfg(all(not(feature = "tokio"), feature = "std"))]
			worker.kill()?;

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
				<$drone_type as $crate::colony::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
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
			let drone =
				<$drone_type as $crate::colony::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
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
				<$drone_type as $crate::colony::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
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
				<$drone_type as $crate::colony::Servlet<()>>::start($crate::trace::TraceCollector::new(), $config)
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

	use crate::policy::{GatePolicy, TransitStatus};
	use crate::transport::policy::{PolicyConf, RestartLinearBackoff};

	/// Custom gate that interprets message.metadata.id:
	/// - "accept-{ID}"  => accept immediately
	/// - "reject-{ID}"  => forbidden
	/// - "timeout-{MS}" => sleep MS millis then timeout (or timeout if MS is invalid)
	#[derive(Default, Clone)]
	pub struct IdPatternGate;

	impl GatePolicy for IdPatternGate {
		fn evaluate(&self, msg: &Frame) -> TransitStatus {
			let id = &msg.metadata.id;
			if id.strip_prefix(b"accept-").is_some() {
				TransitStatus::Accepted
			} else if id.strip_prefix(b"reject-").is_some() {
				TransitStatus::Forbidden
			} else if let Ok(ms_str) = std::str::from_utf8(id.strip_prefix(b"timeout-").unwrap_or(&[])) {
				if let Ok(ms) = ms_str.parse::<u64>() {
					std::thread::sleep(std::time::Duration::from_millis(ms));
					TransitStatus::Timeout
				} else {
					TransitStatus::Timeout
				}
			} else {
				// Default accept
				TransitStatus::Accepted
			}
		}
	} // Client-side gate: block ids starting with "illegal-"
	#[derive(Default, Clone)]
	pub struct IllegalEgressGate;

	impl GatePolicy for IllegalEgressGate {
		fn evaluate(&self, msg: &Frame) -> TransitStatus {
			if msg.metadata.id.starts_with(b"illegal-") {
				TransitStatus::Forbidden
			} else {
				TransitStatus::Accepted
			}
		}
	}
	#[cfg(feature = "std")]
	test_case! {
		name: test_create_test_message,
		setup: || {
			create_test_message(Some("Test content"))
		},
		assertions: |message: TestMessage| {
			assert_eq!(message.content, "Test content");
			Ok(())
		}
	}

	test_builder! {
		name: test_metadata_builder_basic,
		builder_type: crate::builder::MetadataBuilder,
		version: crate::Version::V0,
		message: (),
		setup: |builder, _msg| {
			builder
				.with_id("test-id")
				.with_order(1696521600)
				.build()
		},
		assertions: |_msg, result| {
			let metadata: crate::Metadata = result?;
			assert_eq!(metadata.id, b"test-id");
			assert_eq!(metadata.order, 1696521600);
			assert!(metadata.integrity.is_none());
			Ok(())
		}
	}

	#[cfg(all(feature = "tokio", feature = "tcp", feature = "std"))]
	test_container! {
		name: test_container_custom_gate_patterns,
		worker_threads: 2,
		protocol: crate::transport::tcp::r#async::TokioListener,
		service_policies: {
			with_collector_gate: [IdPatternGate]
		},
		client_policies: {
			with_emitter_gate: [IllegalEgressGate],
			with_restart: [RestartLinearBackoff::new(3, 1, 1, None)],
		},
		service: |message, tx| async move {
			let _ = tx.send(::std::sync::Arc::new(message.clone()));
			Ok(Some(create_v0_tightbeam(Some("OK"), Some(str::from_utf8(&message.metadata.id).map_err(|_| crate::TightBeamError::InvalidBody)?))))
		},
		container: |client, channels| async move {
			use crate::transport::MessageEmitter;

			// Unpack channels
			let (rx, ok_rx, reject_rx) = channels;

			// Blocked by client gate
			let illegal_msg = create_v0_tightbeam(Some("blocked"), Some("illegal-99"));
			let result = client.emit(illegal_msg.clone(), None).await;
			assert!(result.is_err());
			assert_channels_quiet!(rx, ok_rx, reject_rx);

			// Accepted by server gate
			let accept_msg = create_v0_tightbeam(Some("accept case"), Some("accept-42"));
			let response = client.emit(accept_msg.clone(), None).await?;
			assert!(response.is_some());
			let response_message = response.unwrap();
			assert_eq!(response_message.metadata.id, accept_msg.clone().metadata.id);
			assert_eq!(crate::decode::<TestMessage>(&response_message.message)?.content, "OK".to_string());
			assert_recv!(ok_rx, accept_msg, 1);
			assert_recv!(rx, accept_msg, 1);
			assert_channel_ne!(reject_rx, accept_msg);

			// Rejected by server gate
			let reject_msg = create_v0_tightbeam(Some("reject case"), Some("reject-13"));
			let response = client.emit(reject_msg.clone(), None).await;
			assert!(response.is_err());
			assert_recv!(reject_rx, reject_msg.clone(), 4); // 1 initial + 3 retries
			assert_channel_ne!(ok_rx, reject_msg);
			assert_channel_ne!(rx, reject_msg);

			// Test server-side timeout
			let timeout_msg = create_v0_tightbeam(Some("timeout case"), Some("timeout-5"));
			let start = std::time::Instant::now();
			let response = client.emit(timeout_msg.clone(), None).await;
			assert!(response.is_err());
			assert_recv!(reject_rx, timeout_msg.clone(), 4); // 1 initial + 3 retries
			assert!(start.elapsed().as_millis() >= 5);
			assert_channels_quiet!(rx, ok_rx);

			// Retry/backoff case measured via server Busy responses on reject-*
			let busy_msg = create_v0_tightbeam(Some("busy retry"), Some("reject-77"));
			assert_retry_metric!(client, busy_msg, reject_rx, 3, [[1, 3], [2, 4]]);

			Ok(())
		}
	}
}

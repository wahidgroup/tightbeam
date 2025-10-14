use crate::asn1::Frame;
use crate::der::Sequence;

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
	k256::ecdsa::SigningKey::from_bytes(&secret_bytes.into()).expect("Failed to create signing key")
}

#[cfg(feature = "aead")]
pub fn create_test_cipher_key() -> (
	crate::crypto::common::Key<crate::crypto::aead::Aes256Gcm>,
	crate::crypto::aead::Aes256Gcm,
) {
	use crate::crypto::aead::KeyInit;

	let key = crate::crypto::common::Key::<crate::crypto::aead::Aes256Gcm>::from_slice(&[0x33; 32]).to_owned();
	let cipher = crate::crypto::aead::Aes256Gcm::new(&key);
	(key, cipher)
}

pub fn create_test_hash_info() -> crate::IntegrityInfo {
	crate::IntegrityInfo {
		hashing_algorithm: crate::AlgorithmIdentifier {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"), // SHA-256
			parameters: None,
		},
		parameters: vec![0u8; 32],
	}
}

pub fn create_test_encryption_info() -> crate::EncryptionInfo {
	crate::EncryptionInfo {
		encryption_algorithm: crate::AlgorithmIdentifier {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.42"), // AES-256-GCM
			parameters: None,
		},
		parameters: vec![0u8; 12],
	}
}

pub fn create_test_signature_info() -> crate::SignatureInfo {
	crate::SignatureInfo {
		signature_algorithm: crate::AlgorithmIdentifier {
			oid: crate::der::asn1::ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), // ecdsa-with-SHA256
			parameters: None,
		},
		signature: vec![0u8; 64],
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
		$(features: [$($feature:literal),*],)?
		setup: $setup:expr,
		assertions: |$result_pat:pat_param| $body:block
	) => {
		#[test]
		$(#[cfg(all($(feature = $feature),*))])?
		fn $test_name() -> $crate::Result<()> {
			let $result_pat = $setup();
			$body
		}
	};

	// Back-compat: closure form
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		setup: $setup:expr,
		assertions: $assertions:expr
	) => {
		#[test]
		$(#[cfg(all($(feature = $feature),*))])?
		fn $test_name() -> $crate::Result<()> {
			let result = $setup();
			$assertions(result)
		}
	};
}

/// Generic builder test macro
///
/// Similar to test_case! but specifically designed for testing builders.
/// Automatically provides a base builder instance and allows customization.
///
/// # Example
/// ```ignore
/// test_builder! {
///     name: test_metadata_v2,
///     builder_type: MetadataBuilder,
///     version: ProtocolVersion::V2,
///     features: ["std"],
///     setup: |builder| {
///     builder
///         .with_id(b"test")
///         .with_order(123)
///         .build()
///     },
///     assertions: |result| {
///         let metadata = result?;
///         assert_eq!(metadata.id, "test");
///         Ok(())
///     }
/// }
/// ```
#[macro_export]
macro_rules! test_builder {
	(
		name: $test_name:ident,
		builder_type: $builder_type:ty,
		version: $version:expr,
		$(features: [$($feature:literal),*],)?
		setup: |$builder:ident| $setup_body:expr,
		assertions: |$result:ident| $assertions_body:expr
	) => {
		#[test]
		$(#[cfg(all($(feature = $feature),*))])?
		fn $test_name() -> $crate::Result<()> {
			let $builder: $builder_type = <$builder_type>::from($version);
			let $result = $setup_body;
			$assertions_body
		}
	};
}

#[macro_export]
macro_rules! test_container {
	// Protocol setup - separate protocol path from identifiers
	(@setup_protocol $protocol:path, $listener:ident, $addr:ident) => {
		use $crate::transport::Protocol;

		let ($listener, $addr) = <$protocol as Protocol>::bind("127.0.0.1:0").await
			.map_err(|e| $crate::TightBeamError::from(e))?;
	};

	// Generic pattern with arbitrary worker_threads
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		worker_threads: $threads:literal,
		protocol: $protocol:path,
		$(service_policies: { $($server_policy_key:ident: $server_policy_val:expr),* $(,)? },)?
		$(client_policies: { $($client_policy_key:ident: $client_policy_val:expr),* $(,)? },)?
		service: |$svc_message:ident, $svc_tx:ident| $service_body:expr,
		container: |$client:ident, $channels:ident| $container_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> Result<(), Box<dyn core::error::Error>> {
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
		$(service_policies: { $($server_policy_key:ident: $server_policy_val:expr),* $(,)? },)?
		$(client_policies: { $($client_policy_key:ident: $client_policy_val:expr),* $(,)? },)?
		service: |$svc_message:ident, $svc_tx:ident| $service_body:expr,
		container: |$client:ident, $channels:ident| $container_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> Result<(), Box<dyn core::error::Error>> {
			test_container!(@test_body
				$protocol,
				[$($($server_policy_key: $server_policy_val),*)?],
				[$($($client_policy_key: $client_policy_val),*)?],
				|$svc_message, $svc_tx| $service_body,
				|$client, $channels| $container_body
			)
		}
	};

	// Test body implementation (bind a single `channels` tuple)
	(@test_body $protocol:path,
		[$($server_policy_key:ident: $server_policy_val:expr),*],
		[$($client_policy_key:ident: $client_policy_val:expr),*],
		|$svc_message:ident, $svc_tx:ident| $service_body:expr,
		|$client:ident, $channels:ident| $container_body:expr
	) => {
		{
			use std::sync::{mpsc, Arc};
			use $crate::transport::policy::PolicyConfiguration;

			test_container!(@setup_protocol $protocol, listener, addr);

			// Server handler channel: tx for server, rx for container
			let (server_tx, rx_inner) = mpsc::channel();
			let tx = Arc::new(server_tx);

			// Status channels (container receives ok/reject)
			let (ok_tx_inner, ok_rx_inner): (mpsc::Sender<$crate::Frame>, mpsc::Receiver<$crate::Frame>) = mpsc::channel();
			let (reject_tx_inner, reject_rx_inner): (mpsc::Sender<$crate::Frame>, mpsc::Receiver<$crate::Frame>) = mpsc::channel();
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
					[$($server_policy_key: $server_policy_val),*],
					|$svc_message: $crate::Frame, $svc_tx| $service_body
				)
			};

			// Build client
			let mut $client = test_container!(@build_client $protocol, addr, [$($client_policy_key: $client_policy_val),*]);

			// Expose a single tuple to the container
			let $channels = (rx_inner, ok_rx_inner, reject_rx_inner);

			// Run container body returning a Box<dyn Error>
			let container_result: Result<(), Box<dyn core::error::Error>> = $container_body.await;

			// If the container errors, print a full backtrace to help debugging.
			#[cfg(feature = "std")]
			if let Err(ref e) = container_result {
				eprintln!("test_container! container error: {}", e);
				// Print error sources chain
				let mut source = e.source();
				while let Some(cause) = source {
					eprintln!("caused by: {}", cause);
					source = cause.source();
				}
				// Force-capture a backtrace regardless of error type support
				let bt = std::backtrace::Backtrace::force_capture();
				eprintln!("backtrace:\n{}", bt);
			}

			// Cleanup
			server_handle.abort();

			// Return container result
			container_result
		}
	};

	// Build client with policies (direct pass-through; client! supports shorthands)
	(@build_client $protocol:path, $addr:ident, [$($policy_key:ident: $policy_val:expr),+]) => {{
		{
			use $crate::transport::Protocol;
			let stream = <$protocol as Protocol>::connect($addr).await
				.map_err(|e| $crate::transport::error::TransportError::from(e))?;
			let mut transport = <$protocol as Protocol>::create_transport(stream);
			$(
				transport = $crate::test_container!(@set_client_policy transport, $policy_key, $policy_val);
			)*
			transport
		}
	}};

	// Internal helper to set client policies with correct method names
	(@set_client_policy $transport:expr, restart_policy, $value:expr) => {
		$transport.with_restart_policy($value)
	};
	(@set_client_policy $transport:expr, restart, $value:expr) => {
		$transport.with_restart_policy($value)
	};
	(@set_client_policy $transport:expr, emitter_gate, $value:expr) => {
		$transport.with_emitter_gate($value)
	};
	(@set_client_policy $transport:expr, gate, $value:expr) => {
		$transport.with_emitter_gate($value)
	};
	(@set_client_policy $transport:expr, collector_gate, $value:expr) => {
		$transport.with_collector_gate($value)
	};

	// Build client without policies
	(@build_client $protocol:path, $addr:ident, []) => {{
		$crate::client! {
			$protocol: connect $addr
		}
		.await
		.expect("Failed to create client")
	}};

	// Build server with gate policy provided as an inline block that returns a GatePolicy
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident, [gate: { $($gate_block:tt)* } $(, $($rest:tt)*)?], |$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				policies: {
					with_collector_gate: {
						// Generate GateMiddleware here to observe and forward decisions
						let ok_tx_clone = $ok_tx.clone();
						let reject_tx_clone = $reject_tx.clone();
						$crate::policy::GateMiddleware::new(
							{ $($gate_block)* },
							move |message: &$crate::Frame, status: &$crate::policy::TransitStatus| {
								if *status == $crate::policy::TransitStatus::Accepted {
									let _ = ok_tx_clone.send(message.clone());
								} else {
									let _ = reject_tx_clone.send(message.clone());
								}
							}
						)
					}
					$(, $($rest)*)?
				},
				handle: move |$msg: $msg_ty| {
					let $svc_tx = $tx.clone();
					$body
				}
			}
		}
	};

	// Build server with gate policy
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident, [gate: $gate:expr $(, $($rest:tt)*)?], |$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				policies: {
					with_collector_gate: {
						// Generate GateMiddleware here to observe and forward decisions
						let ok_tx_clone = $ok_tx.clone();
						let reject_tx_clone = $reject_tx.clone();
						$crate::policy::GateMiddleware::new(
							$gate,
							move |message: &$crate::Frame, status: &$crate::policy::TransitStatus| {
								if *status == $crate::policy::TransitStatus::Accepted {
									let _ = ok_tx_clone.send(message.clone());
								} else {
									let _ = reject_tx_clone.send(message.clone());
								}
							}
						)
					}
					$(, $($rest)*)?
				},
				handle: move |$msg: $msg_ty| {
					let $svc_tx = $tx.clone();
					$body
				}
			}
		}
	};

	// Build server with policies (but not gate)
	(@build_server $protocol:path, $listener:ident, $tx:ident, $ok_tx:ident, $reject_tx:ident, [$($policy_key:ident: $policy_val:expr),+], |$msg:ident: $msg_ty:ty, $svc_tx:ident| $body:expr) => {
		{
			$crate::server! {
				protocol $protocol: $listener,
				policies: { $($policy_key: $policy_val),* },
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
	fn matches(&self, frame: &crate::Frame) -> bool;
}

impl ExpectedMatcher for crate::Frame {
	fn matches(&self, frame: &crate::Frame) -> bool {
		frame.metadata.id == self.metadata.id
	}
}

impl<E> ExpectedMatcher for Result<crate::Frame, E> {
	fn matches(&self, frame: &crate::Frame) -> bool {
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
	fn matches(&self, frame: &crate::Frame) -> bool {
		if let Ok(decoded) = crate::decode::<T, _>(&frame.message) {
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
					if __expected_ref.matches(&__m) {
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
			if __expected_ref.matches(&__m) {
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
/// Returns (Arc<Mutex<Vec<Instant>>>, JoinHandle<()>).
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
/// number of ranges must be attempts-1 (enforced at compile time). Example:
/// assert_retry_metric!(client, msg.clone(), reject_rx, 3, [[1,3],[2,5]]);
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
/// Automatically starts a worker, creates a client, and passes the ready
/// client to the assertions block for testing. Properly manages worker
/// lifecycle.
#[macro_export]
macro_rules! test_servlet {
	// With worker_threads specified
	(
		name: $test_name:ident,
		$(features: [$($feature:literal),*],)?
		worker_threads: $threads:literal,
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test(flavor = "multi_thread", worker_threads = $threads)]
		$(#[cfg(all($(feature = $feature),*))])?
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
		$(features: [$($feature:literal),*],)?
		protocol: $protocol:ident,
		setup: || $setup_body:expr,
		assertions: |$client:ident| $assertions_body:expr
	) => {
		#[tokio::test]
		$(#[cfg(all($(feature = $feature),*))])?
		async fn $test_name() -> Result<(), Box<dyn std::error::Error>> {
			// Call the setup closure and await the resulting future
			let worker = ($setup_body).await?;

			// Get the worker address
			let addr = worker.addr();

			// Create client
			let mut $client = $crate::client! {
				async $protocol: connect addr
			}.await?;

			// Run assertions
			let result = $assertions_body.await;

			// Clean shutdown
			worker.stop();

			result
		}
	};
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::policy::TransitStatus;

	test_case! {
		name: test_create_test_message,
		features: ["std"],
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
		features: ["std"],
		setup: |builder| {
			builder
				.with_id("test-id")
				.with_order(1696521600)
				.build()
		},
		assertions: |result| {
			let metadata: crate::Metadata = result?;
			assert_eq!(metadata.id, b"test-id");
			assert_eq!(metadata.order, 1696521600);
			assert!(metadata.integrity.is_none());
			assert!(metadata.confidentiality.is_none());
			Ok(())
		}
	}

	// Demonstrates test_container! with custom gate policies and retry backoff.
	test_container! {
		name: test_container_custom_gate_patterns,
		features: ["std", "tcp"],
		worker_threads: 2,
		protocol: crate::transport::tcp::r#async::TokioListener,
		service_policies: {
			gate: {
				/// Custom gate that interprets message.metadata.id:
				/// - "accept-{ID}"  => accept immediately
				/// - "reject-{ID}"  => forbidden
				/// - "timeout-{MS}" => sleep MS millis then timeout (or timeout if MS is invalid)
				#[derive(Default, Clone)]
				struct IdPatternGate;

				impl crate::policy::GatePolicy for IdPatternGate {
					fn evaluate(&self, msg: &crate::Frame) -> TransitStatus {
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
				}

				IdPatternGate
			},
		},
		client_policies: {
			gate: {
				// Client-side gate: block ids starting with "illegal-"
				#[derive(Default, Clone)]
				struct IllegalEgressGate;

				impl crate::policy::GatePolicy for IllegalEgressGate {
					fn evaluate(&self, msg: &crate::Frame) -> TransitStatus {
						if msg.metadata.id.starts_with(b"illegal-") {
							TransitStatus::Forbidden
						} else {
							TransitStatus::Accepted
						}
					}
				}

				IllegalEgressGate
			},
			restart: {
				crate::transport::policy::RestartLinearBackoff {
					max_attempts: 3,
					interval_ms: 1,
					scale_factor: 1,
					jitter: None
				}
			},
		},
		service: |message, tx| async move {
			let _ = tx.send(message.clone());
			Some(create_v0_tightbeam(Some("OK"), Some(str::from_utf8(&message.metadata.id).ok()?)))
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
			assert_eq!(crate::decode::<TestMessage, _>(&response_message.message)?.content, "OK".to_string());
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

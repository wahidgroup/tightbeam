#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

use crate::builder::{MetadataBuilder, TypeBuilder};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::SecurityProfile;
use crate::der::oid::{AssociatedOid, ObjectIdentifier};
use crate::der::Sequence;
use crate::error::Result;
use crate::error::{ExpectError, TightBeamError};
use crate::matrix::{MatrixDyn, MatrixLike};
use crate::{Frame, Message, Metadata, Version};

#[cfg(feature = "aead")]
use crate::crypto::aead::Aead;
#[cfg(feature = "signature")]
use crate::crypto::sign::SignatureEncoding;

#[cfg(feature = "compress")]
use crate::compress::Compressor;
#[cfg(feature = "signature")]
use crate::crypto::sign::{Signatory, SignatureAlgorithmIdentifier};
#[cfg(feature = "digest")]
use crate::helpers::Digestor;

#[cfg(feature = "std")]
use std::time::SystemTime;

/// Scaffold: envelope-only structure (version + metadata) for computing Frame Integrity.
/// Excludes the message field per spec: FI MUST be computed over envelope only.
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct FrameIntegrityScaffold {
	pub version: Version,
	pub metadata: Metadata,
}

/// A fluent builder for creating tightbeam messages with metadata generation
pub struct FrameBuilder<T: Message> {
	version: Version,
	message: Option<T>,
	message_oid: Option<ObjectIdentifier>,
	metadata_builder: MetadataBuilder,
	errors: Vec<TightBeamError>,
	#[cfg(feature = "compress")]
	compressor: Option<Box<dyn Compressor>>,
	#[cfg(feature = "aead")]
	#[allow(clippy::type_complexity)]
	encryptor: Option<Box<dyn FnOnce(&[u8]) -> Result<crate::EncryptedContentInfo>>>,
	rng: Option<Box<dyn rand_core::CryptoRngCore>>,
	#[cfg(feature = "digest")]
	witness: Option<Digestor>,
	#[cfg(feature = "signature")]
	#[allow(clippy::type_complexity)]
	signer: Option<Box<dyn FnOnce(&[u8]) -> Result<crate::SignerInfo>>>,
}

impl<T: Message> From<Version> for FrameBuilder<T> {
	fn from(version: Version) -> Self {
		Self {
			version,
			message: None,
			message_oid: None,
			metadata_builder: MetadataBuilder::from(version),
			errors: Vec::new(),
			#[cfg(feature = "compress")]
			compressor: None,
			#[cfg(feature = "aead")]
			encryptor: None,
			rng: None,
			#[cfg(feature = "digest")]
			witness: None,
			#[cfg(feature = "signature")]
			signer: None,
		}
	}
}

impl<T: Message> FrameBuilder<T> {
	/// Set the message ID
	pub fn with_id(mut self, id: impl AsRef<[u8]>) -> Self {
		self.metadata_builder = self.metadata_builder.with_id(id);
		self
	}

	pub fn with_content_oid(mut self, oid: ObjectIdentifier) -> Self {
		self.message_oid = Some(oid);
		self
	}

	/// Set the order (Unix order in seconds)
	pub fn with_order(mut self, seconds: u64) -> Self {
		self.metadata_builder = self.metadata_builder.with_order(seconds);
		self
	}

	/// Set the message body
	pub fn with_message(mut self, message: T) -> Self {
		self.message = Some(message);
		self
	}

	/// Set the compression algorithm (all versions)
	#[cfg(feature = "compress")]
	pub fn with_compression(mut self, compressor: impl Compressor + 'static) -> Self {
		self.compressor = Some(Box::new(compressor));
		self
	}

	/// Automatically hash the message body using the specified digest algorithm
	#[cfg(feature = "digest")]
	pub fn with_message_hasher<D>(mut self) -> Self
	where
		D: Digest + AssociatedOid,
	{
		// Validate that the digest algorithm matches the message's profile (only if HAS_PROFILE is true)
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::DigestOid::OID {
			self.errors.push(TightBeamError::UnexpectedAlgorithm(ExpectError::from((
				D::OID,
				<T::Profile as SecurityProfile>::DigestOid::OID,
			))));
			return self;
		}

		let message = match self.message.as_ref() {
			Some(m) => m,
			None => {
				self.errors.push(TightBeamError::InvalidBody);
				return self;
			}
		};

		let encoded = match crate::encode(message) {
			Ok(e) => e,
			Err(e) => {
				self.errors.push(e);
				return self;
			}
		};

		match crate::utils::digest::<D>(&encoded) {
			Ok(hash_info) => {
				self.metadata_builder = self.metadata_builder.with_integrity_info(hash_info);
			}
			Err(e) => {
				self.errors.push(e);
			}
		}
		self
	}

	#[cfg(feature = "digest")]
	pub fn with_witness_hasher<D>(mut self) -> Self
	where
		D: Digest + AssociatedOid + 'static,
	{
		// Validate that the digest algorithm matches the message's profile (only if HAS_PROFILE is true)
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::DigestOid::OID {
			self.errors.push(TightBeamError::UnexpectedAlgorithm(ExpectError::from((
				D::OID,
				<T::Profile as SecurityProfile>::DigestOid::OID,
			))));
			return self;
		}

		self.witness = Some(Box::new(|tbs_der: &[u8]| crate::utils::digest::<D>(tbs_der)));
		self
	}

	/// Set the message priority (V2+ only)
	pub fn with_priority(mut self, priority: crate::MessagePriority) -> Self {
		self.metadata_builder = self.metadata_builder.with_priority(priority);
		self
	}

	/// Set the TTL in seconds (V2+ only)
	pub fn with_lifetime(mut self, seconds: u64) -> Self {
		self.metadata_builder = self.metadata_builder.with_lifetime(seconds);
		self
	}

	/// Set the parent message hash (V2+ only)
	/// Links this message to a parent message by including the parent's
	/// message hash. This creates a cryptographic chain of messages where
	/// each message references the hash of its parent's content.
	pub fn with_previous_hash(mut self, parent_hash: crate::DigestInfo) -> Self {
		self.metadata_builder = self.metadata_builder.previous_frame(parent_hash);
		self
	}

	/// Set a custom reality (V2+ only)
	pub fn with_matrix<M>(mut self, matrix: M) -> Self
	where
		M: MatrixLike,
		MatrixDyn: TryFrom<M>,
		<MatrixDyn as TryFrom<M>>::Error: Into<TightBeamError>,
	{
		// Handle Infallible errors (from TryFrom<T> for T) - these can never occur
		match MatrixDyn::try_from(matrix) {
			Ok(matrix_dyn) => {
				self.metadata_builder = self.metadata_builder.with_matrix(matrix_dyn);
			}
			Err(e) => {
				// For Infallible, this branch is unreachable, but we need it for type checking
				#[allow(unreachable_code)]
				self.errors.push(e.into());
			}
		}
		self
	}

	/// Set a custom reality (V2+ only) - convenience method for MatrixDyn
	pub fn with_matrix_dyn(mut self, matrix: MatrixDyn) -> Self {
		self.metadata_builder = self.metadata_builder.with_matrix(matrix);
		self
	}

	#[cfg(feature = "aead")]
	pub fn with_rng(mut self, rng: Box<dyn rand_core::CryptoRngCore>) -> Self {
		self.rng = Some(rng);
		self
	}

	#[cfg(feature = "aead")]
	pub fn with_cipher<C, Cipher>(mut self, cipher: &Cipher) -> Self
	where
		C: AssociatedOid,
		Cipher: Aead + Clone + 'static,
	{
		// Validate that the cipher OID matches the message's profile (only if HAS_PROFILE is true)
		if T::HAS_PROFILE && C::OID != <T::Profile as SecurityProfile>::AeadOid::OID {
			self.errors.push(TightBeamError::UnexpectedAlgorithm(ExpectError::from((
				C::OID,
				<T::Profile as SecurityProfile>::AeadOid::OID,
			))));
			return self;
		}

		// Get the concrete RNG or default to OS RNG
		let rng: &mut dyn rand_core::CryptoRngCore = match self.rng.as_mut() {
			Some(boxed_rng) => &mut **boxed_rng,
			None => &mut rand_core::OsRng,
		};

		// Generate nonce
		let nonce = Cipher::generate_nonce(rng);
		let cipher_cloned = cipher.clone();
		let message_oid = self.message_oid;
		self.encryptor = Some(Box::new(move |plaintext: &[u8]| {
			let encrypted_content = <Cipher as crate::crypto::aead::Encryptor<C>>::encrypt_content(
				&cipher_cloned,
				plaintext,
				&nonce,
				message_oid,
			)?;
			Ok(encrypted_content)
		}));

		self
	}

	/// Set the signer for message signing
	///
	/// The signature will be computed during `build()` over the complete
	/// message structure. This method captures the signer and signing
	/// algorithm to be used later.
	#[cfg(feature = "signature")]
	pub fn with_signer<S, X>(mut self, signer: &X) -> Self
	where
		S: SignatureEncoding + SignatureAlgorithmIdentifier,
		X: Signatory<S> + Clone + 'static,
	{
		// Validate that the signature algorithm matches the message's profile (only if HAS_PROFILE is true)
		if T::HAS_PROFILE && S::ALGORITHM_OID != <T::Profile as SecurityProfile>::SignatureAlg::ALGORITHM_OID {
			self.errors.push(TightBeamError::UnexpectedAlgorithm(ExpectError::from((
				S::ALGORITHM_OID,
				<T::Profile as SecurityProfile>::SignatureAlg::ALGORITHM_OID,
			))));
			return self;
		}

		let signer = signer.clone();
		self.signer = Some(Box::new(move |data: &[u8]| signer.to_signer_info(data)));
		self
	}

	fn validate(&self) -> Result<()> {
		// Check minimum version requirement
		if self.version < T::MIN_VERSION {
			return Err(TightBeamError::UnsupportedVersion(ExpectError::from((
				self.version,
				T::MIN_VERSION,
			))));
		}

		// Check if encryption is set when required
		let has_encryption = self.encryptor.is_some();
		if T::MUST_BE_CONFIDENTIAL && !has_encryption {
			return Err(TightBeamError::MissingEncryptionInfo);
		}

		// Check if signature is set when required
		let has_signer = self.signer.is_some();
		if T::MUST_BE_NON_REPUDIABLE && !has_signer {
			return Err(TightBeamError::MissingSignatureInfo);
		}

		// Check if compression is set when required
		let has_compression = self.compressor.is_some();
		if T::MUST_BE_COMPRESSED && !has_compression {
			return Err(TightBeamError::MissingCompressedData);
		}

		let has_message_integrity = self.metadata_builder.has_hash();
		if T::MUST_HAVE_MESSAGE_INTEGRITY && !has_message_integrity {
			return Err(TightBeamError::MissingDigestInfo);
		}

		let has_frame_integrity = self.witness.is_some();
		if T::MUST_HAVE_FRAME_INTEGRITY && !has_frame_integrity {
			return Err(TightBeamError::MissingDigestInfo);
		}

		// Check if priority is set when required
		if T::MUST_BE_PRIORITIZED && !self.metadata_builder.has_priority() {
			return Err(TightBeamError::MissingPriority);
		}

		Ok(())
	}
}

impl<T: Message> TypeBuilder<Frame> for FrameBuilder<T> {
	type Error = TightBeamError;

	/// Build the final TightBeam message
	///
	/// If a signer was provided via `with_signer()`, the entire message
	/// structure (version + metadata + body) will be signed after
	/// construction. The signature is computed over the DER-encoded TightBeam
	/// structure minus the signature field.
	///
	/// # Errors
	/// Returns an error if:
	/// - Any validation errors occurred during building
	/// - Required fields are missing
	/// - Metadata validation fails
	/// - Signing fails (if signer was provided)
	fn build(self) -> Result<Frame> {
		if !self.errors.is_empty() {
			return Err(TightBeamError::Sequence(self.errors));
		}

		// 0. Validate message restrictions
		self.validate()?;

		let version = self.version;
		let message = self.message.ok_or(TightBeamError::InvalidBody)?;
		let mut metadata_builder = self.metadata_builder;

		// Auto-set current time if order is omitted
		#[cfg(feature = "std")]
		if !metadata_builder.has_order() {
			match SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
				Ok(duration) => {
					metadata_builder = metadata_builder.with_order(duration.as_secs());
				}
				Err(_) => return Err(TightBeamError::InvalidOrder),
			}
		}

		// 1. Encode ASN.1
		let bytes = crate::encode(&message)?;

		// 2. Optional compression
		#[cfg(feature = "compress")]
		let bytes = if let Some(compressor) = self.compressor {
			let (compressed, compression_info) = compressor.compress(&bytes, None)?;

			// Update metadata with compression info
			metadata_builder = metadata_builder.with_compactness_info(compression_info);

			compressed
		} else {
			bytes
		};

		// 3. Optional encryption
		#[cfg(feature = "aead")]
		let message = if let Some(enc) = self.encryptor {
			// Take the encrypted content bytes out
			let mut encrypted_content = enc(&bytes)?;
			let encrypted_bytes = encrypted_content
				.encrypted_content
				.take()
				.ok_or(TightBeamError::MissingEncryptionInfo)?;

			// Update metadata with encryption info without data
			metadata_builder = metadata_builder.with_confidentiality_info(encrypted_content);

			encrypted_bytes.into_bytes()
		} else {
			bytes
		};

		#[cfg(not(feature = "aead"))]
		let message = bytes;

		// Final assembled frame
		let metadata = metadata_builder.build()?;
		let mut tbs = Frame { version, metadata, message, integrity: None, nonrepudiation: None };

		// 4. Optional witness: compute FI over envelope only (version + metadata; excludes message)
		#[cfg(feature = "digest")]
		if let Some(witness_fn) = self.witness {
			let scaffold = FrameIntegrityScaffold { version: tbs.version, metadata: tbs.metadata.clone() };
			let scaffold_der = crate::encode(&scaffold)?;
			let witness_info = witness_fn(&scaffold_der)?;
			tbs.integrity = Some(witness_info);
		}

		// 5. Optional signing
		#[cfg(feature = "signature")]
		let result = if let Some(signer) = self.signer {
			crate::notarize! {
				tbs: tbs,
				position: nonrepudiation,
				signer: signer
			}
		} else {
			Ok(tbs)
		};

		#[cfg(not(feature = "signature"))]
		let result = tbs;

		result
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::compress::ZstdCompression;
	use crate::testing::{create_test_cipher_key, create_test_message, create_test_signing_key, TestMessage};
	use crate::{compose, test_builder, test_case};

	#[cfg(all(feature = "aes-gcm", feature = "sha3"))]
	use crate::crypto::aead::Aes256Gcm;
	#[cfg(all(feature = "aes-gcm", feature = "sha3"))]
	use crate::crypto::hash::Sha3_256;

	#[cfg(feature = "sha3")]
	test_builder! {
		name: test_v0_basic,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V0,
		message: create_test_message(None),
		setup: |builder, msg| {
			builder
				.with_message(msg)
				.with_id("test_v0_basic")
				.with_order(1696521600)
				.build()
		},
		assertions: |_msg, result| {
			let tightbeam  = result?;
			assert_eq!(tightbeam.version, Version::V0);
			assert_eq!(str::from_utf8(&tightbeam.metadata.id), Ok("test_v0_basic"));
			Ok(())
		}
	}

	#[cfg(all(feature = "aes-gcm", feature = "sha3", feature = "secp256k1"))]
	test_builder! {
		name: test_v1_with_encryption,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V1,
		message: create_test_message(None),
		setup: |builder, msg| {
			use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			builder
				.with_message(msg)
				.with_id("test_v1_with_encryption")
				.with_order(1696521600)
				.with_cipher::<Aes256GcmOid, Aes256Gcm>(&cipher)
				.with_signer::<Secp256k1Signature, _>(&signing_key)
				.build()
		},
		assertions: |message, result| {
			let tightbeam  = result?;
			assert_eq!(tightbeam.version, Version::V1);
			assert!(tightbeam.metadata.confidentiality.is_some());
			assert!(tightbeam.nonrepudiation.is_some());

			// Body should be encrypted (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(&tightbeam.message);
			assert!(decode_result.is_err(), "Body should be encrypted");

			// Decrypt and verify
			let (_, cipher) = create_test_cipher_key();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, None)?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	#[cfg(all(
		feature = "compress",
		feature = "aes-gcm",
		feature = "sha3",
		feature = "secp256k1"
	))]
	test_builder! {
		name: test_v1_with_compression,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V1,
		message: create_test_message(None),
		setup: |builder, msg| {
			use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::compress::ZstdCompression;

			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			builder
				.with_message(msg)
				.with_id("test_v1_with_compression")
				.with_order(1696521600)
				.with_compression(ZstdCompression)
				.with_cipher::<Aes256GcmOid, Aes256Gcm>(&cipher)
				.with_signer::<Secp256k1Signature, _>(&signing_key)
				.build()
		},
		assertions: |message, result| {
			let tightbeam = result?;
			assert_eq!(tightbeam.version, Version::V1);
			assert!(tightbeam.metadata.compactness.is_some());
			assert!(tightbeam.metadata.confidentiality.is_some());

			// Body should be encrypted+compressed (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(&tightbeam.message);
			assert!(decode_result.is_err(), "Body should be encrypted/compressed");

			// Decrypt (automatically decompresses) and verify
			let (_, cipher) = create_test_cipher_key();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, Some(&ZstdCompression))?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	#[cfg(all(
		feature = "compress",
		feature = "aes-gcm",
		feature = "sha3",
		feature = "secp256k1",
		feature = "random"
	))]
	test_builder! {
		name: test_v2_full,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V2,
		message: || {
			create_test_message(None)
		},
		setup: |builder, msg| {
			use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			// Create a previous message hash for linking
			let previous_hash = crate::utils::digest::<Sha3_256>(b"previous-message-data")?;
			let rng = rand_core::OsRng;

			// Create custom flags
			let flags = crate::flags::Flags::<2>::from([0x01, 0x02]);

			builder
				.with_message(msg)
				.with_id("test_v2_full")
				.with_order(1696521600)
				.with_message_hasher::<Sha3_256>()
				.with_witness_hasher::<Sha3_256>()
				.with_compression(ZstdCompression)
				.with_rng(Box::new(rng))
				.with_cipher::<Aes256GcmOid, Aes256Gcm>(&cipher)
				.with_signer::<Secp256k1Signature, _>(&signing_key)
				.with_priority(crate::MessagePriority::High)
				.with_lifetime(3600)
				.with_previous_hash(previous_hash)
				.with_matrix(flags)
				.build()
		},
		assertions: |message, result| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let tightbeam = result?;
			assert_eq!(tightbeam.version, Version::V2);
			assert_eq!(tightbeam.metadata.id, b"test_v2_full");
			assert_eq!(tightbeam.metadata.priority, Some(crate::MessagePriority::High));
			assert_eq!(tightbeam.metadata.lifetime, Some(3600));
			assert!(tightbeam.metadata.confidentiality.is_some());
			assert!(tightbeam.metadata.compactness.is_some());
			assert!(tightbeam.metadata.previous_frame.is_some());
			assert!(tightbeam.metadata.matrix.is_some());
			assert!(tightbeam.integrity.is_some());
			assert!(tightbeam.nonrepudiation.is_some());

			// Verify Message Integrity (MI): compute hash over original message and compare
			let message_der = crate::encode(&message)?;
			let expected_mi = crate::utils::digest::<Sha3_256>(&message_der)?;
			let actual_mi = tightbeam.metadata.integrity.as_ref().expect("Message integrity should be present");
			assert_eq!(actual_mi.digest.as_bytes(), expected_mi.digest.as_bytes());

			// Verify Frame Integrity (FI): compute hash over envelope (version + metadata) and compare
			let scaffold = FrameIntegrityScaffold {
				version: tightbeam.version,
				metadata: tightbeam.metadata.clone(),
			};
			let scaffold_der = crate::encode(&scaffold)?;
			let expected_fi = crate::utils::digest::<Sha3_256>(&scaffold_der)?;
			let actual_fi = tightbeam.integrity.as_ref().expect("Frame integrity should be present");
			assert_eq!(actual_fi.digest.as_bytes(), expected_fi.digest.as_bytes());

			// Body should be encrypted+compressed (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(&tightbeam.message);
			assert!(decode_result.is_err());

			// Decrypt (automatically decompresses) and verify
			let (_, cipher) = create_test_cipher_key();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, Some(&ZstdCompression))?;
			assert_eq!(decrypted, message);

			// Verify signature
			let signing_key = create_test_signing_key();
			let verifying_key = signing_key.verifying_key();
			assert!(tightbeam.verify::<Secp256k1Signature>(verifying_key).is_ok());

			Ok(())
		}
	}

	#[cfg(feature = "sha3")]
	test_case! {
		name: test_missing_message,
		setup: || {
			FrameBuilder::<TestMessage>::from(Version::V0)
				.with_id("no-message")
				.with_order(1696521600)
				.with_message_hasher::<Sha3_256>()
				.build()
		},
		assertions: |result: Result<Frame>| {
			assert!(result.is_err());
			Ok(())
		}
	}

	#[cfg(feature = "sha3")]
	test_case! {
		name: test_error_accumulation,
		setup: || {
			let message = create_test_message(None);
			FrameBuilder::from(Version::V0)
				.with_id("error-test")
				.with_order(1696521600)
				.with_message_hasher::<Sha3_256>()
				.with_message(message)
				.build()
		},
		assertions: |result: Result<Frame>| {
			assert!(result.is_err());
			assert!(matches!(result, Err(TightBeamError::Sequence(_))));
			Ok(())
		}
	}

	#[cfg(feature = "derive")]
	test_case! {
		name: test_compose_macro,
		setup: || {
			let message = create_test_message(None);
			compose! {
				V0:
					id: "test-id",
					order: 1696521600,
					message: message,
					message_integrity: type Sha3_256
			}
		},
		assertions: |result: Result<Frame>| {
			let tightbeam = result?;
			assert_eq!(tightbeam.version, Version::V0);
			assert_eq!(tightbeam.metadata.id, b"test-id");
			assert_eq!(tightbeam.metadata.order, 1696521600);
			Ok(())
		}
	}

	#[cfg(all(feature = "aes-gcm", feature = "sha3"))]
	test_case! {
		name: test_unexpected_algorithm_validation,
		setup: || {
			// Create a message with a profile that expects AES-128-GCM
			#[derive(Clone, Debug, PartialEq, Sequence)]
			struct Aes128Message {
				content: String,
			}

			impl crate::Message for Aes128Message {
				const MUST_BE_NON_REPUDIABLE: bool = false;
				const MUST_BE_CONFIDENTIAL: bool = false;
				const MUST_BE_COMPRESSED: bool = false;
				const MUST_BE_PRIORITIZED: bool = false;
				const HAS_PROFILE: bool = true;
				const MIN_VERSION: crate::Version = crate::Version::V0;

				type Profile = Aes128Profile;
			}

			// Define a profile that uses AES-128-GCM
			#[derive(Debug, Default, Clone, Copy)]
			struct Aes128Profile;

			impl SecurityProfile for Aes128Profile {
				type DigestOid = Sha3_256;
				type AeadOid = crate::crypto::aead::Aes128GcmOid;
				type SignatureAlg = crate::crypto::sign::ecdsa::Secp256k1Signature;
				#[cfg(feature = "kdf")]
				type KdfOid = crate::crypto::kdf::HkdfSha3_256Oid;
				#[cfg(feature = "ecdh")]
				type CurveOid = crate::crypto::curves::Secp256k1Oid;
			}

			let message = Aes128Message { content: "test".to_string() };
			let (_, cipher) = create_test_cipher_key(); // This creates an AES-256 key

			// Try to use AES-256-GCM cipher with a message that expects AES-128-GCM
			let builder: FrameBuilder<Aes128Message> = Version::V1.into();
			builder
				.with_message(message)
				.with_id("test_unexpected_algorithm")
				.with_order(1696521600)
				.with_cipher::<crate::crypto::aead::Aes256GcmOid, Aes256Gcm>(&cipher)
				.build()
		},
		assertions: |result: Result<Frame>| {
			// Should fail with UnexpectedAlgorithm error
			assert!(result.is_err());
			if let Err(TightBeamError::Sequence(errors)) = result {
				assert!(!errors.is_empty());
				// Check that one of the errors is UnexpectedAlgorithm
				let has_unexpected_algorithm = errors.iter().any(|e| matches!(e, TightBeamError::UnexpectedAlgorithm(_)));
				assert!(has_unexpected_algorithm, "Expected UnexpectedAlgorithm error, but got: {errors:?}");
			} else {
				panic!("Expected Sequence error, but got: {result:?}");
			}

			Ok(())
		}
	}
}

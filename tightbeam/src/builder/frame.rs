#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, string::String, vec::Vec};

#[cfg(feature = "std")]
use std::time::SystemTime;

use crate::builder::{MetadataBuilder, TypeBuilder};
use crate::crypto::hash::Digest;
use crate::crypto::profiles::SecurityProfile;
use crate::der::oid::{AssociatedOid, ObjectIdentifier};
use crate::der::Sequence;
use crate::error::Result;
use crate::error::{ReceivedExpectedError, TightBeamError};
use crate::matrix::{IntoMatrixDyn, MatrixDyn};
use crate::{Frame, Message, Metadata, Version};

#[cfg(feature = "aead")]
use crate::crypto::aead::Aead;
#[cfg(feature = "aead")]
use crate::crypto::aead::Encryptor;
#[cfg(feature = "signature")]
use crate::crypto::sign::SignatureEncoding;

#[cfg(feature = "compress")]
use crate::compress::Compressor;
#[cfg(feature = "signature")]
use crate::crypto::sign::{Signatory, SignatureAlgorithmIdentifier};
#[cfg(feature = "digest")]
use crate::helpers::Digestor;

#[cfg(feature = "aead")]
type EncryptorFn = Box<dyn FnOnce(&[u8]) -> Result<crate::EncryptedContentInfo>>;

#[cfg(feature = "signature")]
type SignerFn = Box<dyn FnOnce(&[u8]) -> Result<crate::SignerInfo>>;

/// Sealed trait pattern for compile-time OID validation
/// Prevents external impls while allowing conditional enforcement
#[doc(hidden)]
pub mod private {
	use super::*;

	#[cfg(feature = "digest")]
	pub trait SealedDigestOid<D: AssociatedOid> {}

	#[cfg(feature = "aead")]
	pub trait SealedAeadOid<C: AssociatedOid> {}

	#[cfg(feature = "ecdh")]
	pub trait SealedCurveOid<C: AssociatedOid> {}

	#[cfg(feature = "signature")]
	pub trait SealedSignatureOid<S: SignatureAlgorithmIdentifier> {}
}

/// Checker traits for compile-time OID validation
/// Uses sealed trait pattern to prevent external impls and enable conditional enforcement
#[cfg(feature = "digest")]
pub trait CheckDigestOid<D: AssociatedOid>: private::SealedDigestOid<D> {
	const RESULT: ();
}

#[cfg(feature = "aead")]
pub trait CheckAeadOid<C: AssociatedOid>: private::SealedAeadOid<C> {
	const RESULT: ();
}

#[cfg(feature = "ecdh")]
pub trait CheckCurveOid<C: AssociatedOid>: private::SealedCurveOid<C> {
	const RESULT: ();
}

#[cfg(feature = "signature")]
pub trait CheckSignatureOid<S: SignatureAlgorithmIdentifier>: private::SealedSignatureOid<S> {
	const RESULT: ();
}

/// Zero-allocation error accumulator for FrameBuilder.
/// Uses fixed-size storage for up to 5 errors (the maximum possible),
/// falling back to Vec only if exceeded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
enum ErrorAccumulator {
	/// No errors (zero allocation)
	#[default]
	None,
	/// 1 error stored inline (zero allocation)
	One(TightBeamError),
	/// 2-5 errors stored inline (zero allocation)
	Many([Option<TightBeamError>; 5], u8),
	/// 6+ errors (heap allocation)
	Heap(Vec<TightBeamError>),
}

impl ErrorAccumulator {
	fn push(&mut self, error: TightBeamError) {
		match core::mem::replace(self, Self::None) {
			Self::None => *self = Self::One(error),
			Self::One(first) => {
				let mut arr = [None, None, None, None, None];
				arr[0] = Some(first);
				arr[1] = Some(error);
				*self = Self::Many(arr, 2);
			}
			Self::Many(mut arr, len) => {
				let len_usize = len as usize;
				if len_usize < 5 {
					arr[len_usize] = Some(error);
					*self = Self::Many(arr, len + 1);
				} else {
					// Convert to heap storage
					let mut vec = Vec::with_capacity(6);
					for item in arr.iter_mut().take(len_usize) {
						if let Some(err) = core::mem::take(item) {
							vec.push(err);
						}
					}
					vec.push(error);
					*self = Self::Heap(vec);
				}
			}
			Self::Heap(mut errors) => {
				errors.push(error);
				*self = Self::Heap(errors);
			}
		}
	}

	fn is_empty(&self) -> bool {
		matches!(self, Self::None)
	}
}

impl From<ErrorAccumulator> for Vec<TightBeamError> {
	fn from(accumulator: ErrorAccumulator) -> Self {
		match accumulator {
			ErrorAccumulator::None => Vec::new(),
			ErrorAccumulator::One(error) => vec![error],
			ErrorAccumulator::Many(mut arr, len) => {
				let len = len as usize;
				let mut vec = Vec::with_capacity(len);
				for item in arr.iter_mut().take(len) {
					if let Some(err) = core::mem::take(item) {
						vec.push(err);
					}
				}
				vec
			}
			ErrorAccumulator::Heap(errors) => errors,
		}
	}
}

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
	errors: ErrorAccumulator,
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
			errors: ErrorAccumulator::default(),
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
		M: IntoMatrixDyn,
	{
		match matrix.into_matrix_dyn() {
			Ok(matrix_dyn) => {
				self.metadata_builder = self.metadata_builder.with_matrix(matrix_dyn);
			}
			Err(e) => {
				self.errors.push(TightBeamError::MatrixError(e));
			}
		}
		self
	}

	/// Set a custom reality (V2+ only) - convenience method for MatrixDyn
	pub fn with_matrix_dyn(mut self, matrix: MatrixDyn) -> Self {
		self.metadata_builder = self.metadata_builder.with_matrix(matrix);
		self
	}

	fn validate(&self) -> Result<()> {
		// Check minimum version requirement
		if self.version < T::MIN_VERSION {
			return Err(TightBeamError::UnsupportedVersion(ReceivedExpectedError::from((
				self.version,
				T::MIN_VERSION,
			))));
		}

		// Check if encryption is set when required
		#[cfg(feature = "aead")]
		if T::MUST_BE_CONFIDENTIAL && self.encryptor.is_none() {
			return Err(TightBeamError::MissingEncryptionInfo);
		}

		// Check if signature is set when required
		#[cfg(feature = "signature")]
		if T::MUST_BE_NON_REPUDIABLE && self.signer.is_none() {
			return Err(TightBeamError::MissingSignatureInfo);
		}

		// Check if compression is set when required
		#[cfg(feature = "compress")]
		if T::MUST_BE_COMPRESSED && self.compressor.is_none() {
			return Err(TightBeamError::MissingCompressedData);
		}

		let has_message_integrity = self.metadata_builder.has_hash();
		if T::MUST_HAVE_MESSAGE_INTEGRITY && !has_message_integrity {
			return Err(TightBeamError::MissingDigestInfo);
		}

		#[cfg(feature = "digest")]
		if T::MUST_HAVE_FRAME_INTEGRITY && self.witness.is_none() {
			return Err(TightBeamError::MissingDigestInfo);
		}

		// Check if priority is set when required
		if T::MUST_BE_PRIORITIZED && !self.metadata_builder.has_priority() {
			return Err(TightBeamError::MissingPriority);
		}

		Ok(())
	}
}

#[cfg(feature = "compress")]
impl<T: Message> FrameBuilder<T> {
	/// Set the compression algorithm (all versions)
	pub fn with_compression(mut self, compressor: impl Compressor + 'static) -> Self {
		self.compressor = Some(Box::new(compressor));
		self
	}
}

#[cfg(feature = "aead")]
impl<T: Message> FrameBuilder<T> {
	pub fn with_rng(mut self, rng: Box<dyn rand_core::CryptoRngCore>) -> Self {
		self.rng = Some(rng);
		self
	}

	/// Set the AEAD cipher for symmetric encryption
	pub fn with_aead<C, Cipher>(mut self, cipher: Cipher) -> Self
	where
		C: AssociatedOid,
		Cipher: Aead + 'static,
		T: CheckAeadOid<C>,
	{
		// Runtime fallback validation
		if T::HAS_PROFILE && C::OID != <T::Profile as SecurityProfile>::AeadOid::OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
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
		let message_oid = self.message_oid;
		self.encryptor = Some(Box::new(move |plaintext: &[u8]| {
			let encrypted_content = <Cipher as Encryptor<C>>::encrypt_content(&cipher, plaintext, &nonce, message_oid)?;
			Ok(encrypted_content)
		}));

		self
	}

	/// Use a custom encryptor for asymmetric encryption (e.g., ECIES).
	pub fn with_encryptor<C, E>(mut self, encryptor: E) -> Self
	where
		C: AssociatedOid,
		E: Encryptor<C> + 'static,
	{
		// Runtime validation: check either AEAD OID or Curve OID
		if T::HAS_PROFILE {
			let aead_match = C::OID == <T::Profile as SecurityProfile>::AeadOid::OID;
			#[cfg(feature = "ecdh")]
			let curve_match = C::OID == <T::Profile as SecurityProfile>::CurveOid::OID;
			#[cfg(not(feature = "ecdh"))]
			let curve_match = false;

			if !aead_match && !curve_match {
				self.errors
					.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
						C::OID,
						<T::Profile as SecurityProfile>::AeadOid::OID,
					))));
				return self;
			}
		}

		let message_oid = self.message_oid;
		self.encryptor = Some(Box::new(move |plaintext: &[u8]| {
			// Encryptor handles nonce generation internally (e.g., ECIES)
			encryptor.encrypt_content(plaintext, [], message_oid)
		}));

		self
	}
}

#[cfg(feature = "digest")]
impl<T: Message> FrameBuilder<T> {
	/// Automatically hash the message body using the specified digest algorithm
	pub fn with_message_hasher<D>(mut self) -> Self
	where
		D: Digest + AssociatedOid,
		T: CheckDigestOid<D>,
	{
		// Runtime fallback validation
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::DigestOid::OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
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

	pub fn with_witness_hasher<D>(mut self) -> Self
	where
		D: Digest + AssociatedOid + 'static,
		T: CheckDigestOid<D>,
	{
		// Runtime fallback validation
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::DigestOid::OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
					D::OID,
					<T::Profile as SecurityProfile>::DigestOid::OID,
				))));
			return self;
		}

		self.witness = Some(Box::new(|tbs_der: &[u8]| crate::utils::digest::<D>(tbs_der)));
		self
	}

	/// Encode Frame Integrity scaffold (version + metadata).
	fn encode_frame_integrity_scaffold(version: &Version, metadata: &Metadata) -> Result<Vec<u8>> {
		use crate::der::Encode;

		let mut scaffold_data = Vec::new();
		version.encode(&mut scaffold_data)?;
		metadata.encode(&mut scaffold_data)?;

		// Wrap in sequence
		let mut buffer = Vec::new();
		let sequence_len = crate::der::Length::try_from(scaffold_data.len())?;
		buffer.push(crate::der::Tag::Sequence.into());
		sequence_len.encode(&mut buffer)?;
		buffer.extend(scaffold_data);
		Ok(buffer)
	}
}

#[cfg(feature = "signature")]
impl<T: Message> FrameBuilder<T> {
	/// Set the signer for message signing
	///
	/// The signature will be computed during `build()` over the complete
	/// message structure. This method captures the signer and signing
	/// algorithm to be used later.
	pub fn with_signer<S, X>(mut self, signer: X) -> Self
	where
		S: SignatureEncoding + SignatureAlgorithmIdentifier,
		X: Signatory<S> + 'static,
		T: CheckSignatureOid<S>,
	{
		// Runtime fallback validation
		if T::HAS_PROFILE && S::ALGORITHM_OID != <T::Profile as SecurityProfile>::SignatureAlg::ALGORITHM_OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
					S::ALGORITHM_OID,
					<T::Profile as SecurityProfile>::SignatureAlg::ALGORITHM_OID,
				))));
			return self;
		}

		self.signer = Some(Box::new(move |data: &[u8]| signer.to_signer_info(data)));
		self
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
			return Err(TightBeamError::Sequence(self.errors.into()));
		}

		// 0. Validate message restrictions
		self.validate()?;

		let version = self.version;
		let message = self.message.ok_or(TightBeamError::InvalidBody)?;
		let metadata_builder = self.metadata_builder;

		// Delegate to helper methods for better organization

		FrameBuilder::build_impl(
			version,
			message,
			metadata_builder,
			#[cfg(feature = "compress")]
			self.compressor,
			#[cfg(feature = "aead")]
			self.encryptor,
			#[cfg(feature = "digest")]
			self.witness,
			#[cfg(feature = "signature")]
			self.signer,
		)
	}
}

impl<T: Message> FrameBuilder<T> {
	/// Internal build implementation - extracted for cognitive complexity reduction.
	fn build_impl(
		version: Version,
		message: T,
		mut metadata_builder: MetadataBuilder,
		#[cfg(feature = "compress")] compressor: Option<Box<dyn Compressor>>,
		#[cfg(feature = "aead")] encryptor: Option<EncryptorFn>,
		#[cfg(feature = "digest")] witness: Option<Digestor>,
		#[cfg(feature = "signature")] signer: Option<SignerFn>,
	) -> Result<Frame> {
		// Auto-set current time if order is omitted
		metadata_builder = Self::ensure_order_set(metadata_builder)?;

		// 1-3. Build message bytes (encode, compress, encrypt)
		let (message_bytes, metadata_builder) = Self::build_message_bytes(
			message,
			metadata_builder,
			#[cfg(feature = "compress")]
			compressor,
			#[cfg(feature = "aead")]
			encryptor,
		)?;

		// Final assembled frame
		let metadata = metadata_builder.build()?;
		let mut tbs = Frame { version, metadata, message: message_bytes, integrity: None, nonrepudiation: None };

		// Runtime validation: ensure version is compatible with metadata fields
		if !tbs.validate_version_compatibility() {
			return Err(TightBeamError::UnsupportedVersion(ReceivedExpectedError::from((
				version, version,
			))));
		}

		// 4. Optional witness: compute FI over envelope only (version + metadata; excludes message)
		Self::build_frame_integrity(
			&mut tbs,
			#[cfg(feature = "digest")]
			witness,
		)?;

		// 5. Optional signing
		Self::build_signature(
			tbs,
			#[cfg(feature = "signature")]
			signer,
		)
	}

	/// Ensure order is set in metadata builder, auto-setting current time if omitted.
	#[cfg(feature = "std")]
	fn ensure_order_set(mut metadata_builder: MetadataBuilder) -> Result<MetadataBuilder> {
		if !metadata_builder.has_order() {
			match SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
				Ok(duration) => {
					metadata_builder = metadata_builder.with_order(duration.as_secs());
				}
				Err(_) => return Err(TightBeamError::InvalidOrder),
			}
		}
		Ok(metadata_builder)
	}

	#[cfg(not(feature = "std"))]
	fn ensure_order_set(metadata_builder: MetadataBuilder) -> Result<MetadataBuilder> {
		Ok(metadata_builder)
	}

	/// Build message bytes through encoding, compression, and encryption pipeline.
	fn build_message_bytes(
		message: T,
		mut metadata_builder: MetadataBuilder,
		#[cfg(feature = "compress")] compressor: Option<Box<dyn Compressor>>,
		#[cfg(feature = "aead")] encryptor: Option<EncryptorFn>,
	) -> Result<(Vec<u8>, MetadataBuilder)> {
		// 1. Encode ASN.1
		let bytes = crate::encode(&message)?;

		// 2. Optional compression
		#[cfg(feature = "compress")]
		let bytes = if let Some(compressor) = compressor {
			let (compressed, compression_info) = compressor.compress(&bytes, None)?;
			metadata_builder = metadata_builder.with_compactness_info(compression_info);
			compressed
		} else {
			bytes
		};

		// 3. Optional encryption
		#[cfg(feature = "aead")]
		let message_bytes = if let Some(enc) = encryptor {
			let mut encrypted_content = enc(&bytes)?;
			let encrypted_bytes = encrypted_content
				.encrypted_content
				.take()
				.ok_or(TightBeamError::MissingEncryptionInfo)?;
			metadata_builder = metadata_builder.with_confidentiality_info(encrypted_content);
			encrypted_bytes.into_bytes()
		} else {
			bytes
		};

		#[cfg(not(feature = "aead"))]
		let message_bytes = bytes;

		Ok((message_bytes, metadata_builder))
	}

	/// Build frame integrity (FI) over envelope if witness is provided.
	#[cfg(feature = "digest")]
	fn build_frame_integrity(tbs: &mut Frame, witness: Option<Digestor>) -> Result<()> {
		if let Some(witness_fn) = witness {
			// Zero-copy: encode version + metadata directly without cloning metadata
			let scaffold_der = Self::encode_frame_integrity_scaffold(&tbs.version, &tbs.metadata)?;
			let witness_info = witness_fn(&scaffold_der)?;
			tbs.integrity = Some(witness_info);
		}
		Ok(())
	}

	#[cfg(not(feature = "digest"))]
	fn build_frame_integrity(_tbs: &mut Frame) -> Result<()> {
		Ok(())
	}

	/// Build signature (nonrepudiation) if signer is provided.
	#[cfg(feature = "signature")]
	fn build_signature(tbs: Frame, signer: Option<SignerFn>) -> Result<Frame> {
		let tbs = tbs;
		if let Some(signer) = signer {
			crate::notarize! {
				tbs: tbs,
				position: nonrepudiation,
				signer: signer
			}
		} else {
			Ok(tbs)
		}
	}

	#[cfg(not(feature = "signature"))]
	fn build_signature(tbs: Frame) -> Result<Frame> {
		Ok(tbs)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::compress::ZstdCompression;
	use crate::testing::{create_test_cipher_key, create_test_message, create_test_signing_key, TestMessage};
	use crate::{compose, test_builder};

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
			.with_aead::<Aes256GcmOid, Aes256Gcm>(cipher)
			.with_signer::<Secp256k1Signature, _>(signing_key)
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
			.with_aead::<Aes256GcmOid, Aes256Gcm>(cipher)
			.with_signer::<Secp256k1Signature, _>(signing_key)
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

			builder
				.with_message(msg)
				.with_id("test_v2_full")
				.with_order(1696521600)
				.with_message_hasher::<Sha3_256>()
				.with_witness_hasher::<Sha3_256>()
				.with_compression(ZstdCompression)
				.with_rng(Box::new(rng))
				.with_aead::<Aes256GcmOid, Aes256Gcm>(cipher)
				.with_signer::<Secp256k1Signature, _>(signing_key)
				.with_priority(crate::MessagePriority::High)
				.with_lifetime(3600)
				.with_previous_hash(previous_hash)
				// Matrix removed - V2 doesn't support it (V3+ only)
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
			assert!(tightbeam.metadata.matrix.is_none()); // Matrix is V3+ only
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

			// Verify signature before decrypting (decrypt consumes the frame)
			let signing_key = create_test_signing_key();
			let verifying_key = signing_key.verifying_key();
			assert!(tightbeam.verify::<Secp256k1Signature>(verifying_key).is_ok());

			// Decrypt (automatically decompresses) and verify
			let (_, cipher) = create_test_cipher_key();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, Some(&ZstdCompression))?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	#[test]
	#[cfg(feature = "sha3")]
	fn test_missing_message() {
		let result = FrameBuilder::<TestMessage>::from(Version::V0)
			.with_id("no-message")
			.with_order(1696521600)
			.with_message_hasher::<Sha3_256>()
			.build();
		assert!(result.is_err());
	}

	#[test]
	#[cfg(feature = "sha3")]
	fn test_error_accumulation() {
		let message = create_test_message(None);
		let result = FrameBuilder::from(Version::V0)
			.with_id("error-test")
			.with_order(1696521600)
			.with_message_hasher::<Sha3_256>()
			.with_message(message)
			.build();
		assert!(result.is_err());
		assert!(matches!(result, Err(TightBeamError::Sequence(_))));
	}

	#[test]
	#[cfg(feature = "derive")]
	fn test_compose_macro() -> Result<()> {
		let message = create_test_message(None);
		let frame = compose! {
			V0:
				id: "test-id",
				order: 1696521600,
				message: message,
				message_integrity: type Sha3_256
		}?;
		assert_eq!(frame.version, Version::V0);
		assert_eq!(frame.metadata.id, b"test-id");
		assert_eq!(frame.metadata.order, 1696521600);
		Ok(())
	}

	mod validation {
		use super::*;
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::testing::{create_test_cipher_key, create_test_signing_key};
		use crate::Version;

		// Helper macro to run shared test logic after struct definition
		macro_rules! run_tests {
			($name:expr, $confidential:expr, $nonrepudiable:expr, $message_integrity:expr, $frame_integrity:expr, $min_version:expr, $cipher:expr, $signing_key:expr) => {
				let message = TestMsg { content: format!("test {}", $name) };

				// Test 1: Verify constants match derive macro attributes
				assert_eq!(TestMsg::MUST_BE_CONFIDENTIAL, $confidential);
				assert_eq!(TestMsg::MUST_BE_NON_REPUDIABLE, $nonrepudiable);
				assert_eq!(TestMsg::MUST_HAVE_MESSAGE_INTEGRITY, $message_integrity);
				assert_eq!(TestMsg::MUST_HAVE_FRAME_INTEGRITY, $frame_integrity);
				assert_eq!(TestMsg::MIN_VERSION, $min_version);

				// Test 2: Verify frame composition
				let result = compose_frame(
					$name,
					message.clone(),
					$cipher.clone(),
					$signing_key.clone(),
					$confidential,
					$nonrepudiable,
					$message_integrity,
					$frame_integrity,
				);
				assert!(result.is_ok());

				let frame = result.unwrap();

				// Test 3: Verify README semantics - MUST fields → Frame fields MUST be present
				// README line 363: MUST_BE_NON_REPUDIABLE=true → Frame MUST include nonrepudiation field
				assert_eq!(frame.nonrepudiation.is_some(), $nonrepudiable);
				// README line 364: MUST_BE_CONFIDENTIAL=true → Frame MUST include confidentiality field
				assert_eq!(frame.metadata.confidentiality.is_some(), $confidential);
				// MUST_HAVE_MESSAGE_INTEGRITY=true → Frame metadata MUST include integrity field
				assert_eq!(frame.metadata.integrity.is_some(), $message_integrity);
				// MUST_HAVE_FRAME_INTEGRITY=true → Frame MUST include integrity field
				assert_eq!(frame.integrity.is_some(), $frame_integrity);

				// Test 4: Verify version enforcement
				if $min_version > Version::V0 {
					let result_v0 = compose! {
						V0: id: $name, order: 1u64, message: message.clone()
					};
					assert!(result_v0.is_err());
				}
			};
		}

		// Helper macro to generate test message struct with correct attributes
		// Only matches the 4 test cases actually used in the test
		macro_rules! test_msg_struct {
			// BasicMessage: (false, false, false, false, V0)
			(false, false, false, false, V0) => {
				#[cfg(feature = "derive")]
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(min_version = "V0")]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				#[derive(Clone, Debug, PartialEq, der::Sequence)]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				impl $crate::Message for TestMsg {
					const MUST_BE_CONFIDENTIAL: bool = false;
					const MUST_BE_NON_REPUDIABLE: bool = false;
					const MUST_BE_COMPRESSED: bool = false;
					const MUST_BE_PRIORITIZED: bool = false;
					const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
					const MUST_HAVE_FRAME_INTEGRITY: bool = false;
					const MIN_VERSION: Version = Version::V0;
					type Profile = $crate::crypto::profiles::TightbeamProfile;
				}
			};
			// ConfidentialMessage: (true, false, false, false, V1)
			(true, false, false, false, V1) => {
				#[cfg(feature = "derive")]
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(confidential, min_version = "V1")]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				#[derive(Clone, Debug, PartialEq, der::Sequence)]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				impl $crate::Message for TestMsg {
					const MUST_BE_CONFIDENTIAL: bool = true;
					const MUST_BE_NON_REPUDIABLE: bool = false;
					const MUST_BE_COMPRESSED: bool = false;
					const MUST_BE_PRIORITIZED: bool = false;
					const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
					const MUST_HAVE_FRAME_INTEGRITY: bool = false;
					const MIN_VERSION: Version = Version::V1;
					type Profile = $crate::crypto::profiles::TightbeamProfile;
				}
			};
			// NonrepudiableMessage: (false, true, false, false, V1)
			(false, true, false, false, V1) => {
				#[cfg(feature = "derive")]
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(nonrepudiable, min_version = "V1")]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				#[derive(Clone, Debug, PartialEq, der::Sequence)]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				impl $crate::Message for TestMsg {
					const MUST_BE_CONFIDENTIAL: bool = false;
					const MUST_BE_NON_REPUDIABLE: bool = true;
					const MUST_BE_COMPRESSED: bool = false;
					const MUST_BE_PRIORITIZED: bool = false;
					const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
					const MUST_HAVE_FRAME_INTEGRITY: bool = false;
					const MIN_VERSION: Version = Version::V1;
					type Profile = $crate::crypto::profiles::TightbeamProfile;
				}
			};
			// FullSecurityMessage: (true, true, true, true, V2)
			(true, true, true, true, V2) => {
				#[cfg(feature = "derive")]
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(
					confidential,
					nonrepudiable,
					message_integrity,
					frame_integrity,
					min_version = "V2"
				)]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				#[derive(Clone, Debug, PartialEq, der::Sequence)]
				struct TestMsg {
					content: String,
				}
				#[cfg(not(feature = "derive"))]
				impl $crate::Message for TestMsg {
					const MUST_BE_CONFIDENTIAL: bool = true;
					const MUST_BE_NON_REPUDIABLE: bool = true;
					const MUST_BE_COMPRESSED: bool = false;
					const MUST_BE_PRIORITIZED: bool = false;
					const MUST_HAVE_MESSAGE_INTEGRITY: bool = true;
					const MUST_HAVE_FRAME_INTEGRITY: bool = true;
					const MIN_VERSION: Version = Version::V2;
					type Profile = $crate::crypto::profiles::TightbeamProfile;
				}
			};
		}

		#[test]
		fn test_message_traits() {
			let (_, cipher) = create_test_cipher_key();
			let signing_key = create_test_signing_key();

			// Helper to compose frames based on requirements
			#[allow(clippy::too_many_arguments)]
			fn compose_frame<T>(
				test_name: &str,
				message: T,
				cipher: Aes256Gcm,
				signing_key: Secp256k1SigningKey,
				confidential: bool,
				nonrepudiable: bool,
				message_integrity: bool,
				frame_integrity: bool,
			) -> crate::error::Result<crate::Frame>
			where
				T: crate::Message
					+ crate::builder::CheckAeadOid<Aes256GcmOid>
					+ crate::builder::CheckSignatureOid<Secp256k1Signature>
					+ crate::builder::CheckDigestOid<Sha3_256>
					+ Clone,
			{
				match (confidential, nonrepudiable, message_integrity, frame_integrity) {
					(true, true, true, true) => compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256,
						frame_integrity: type Sha3_256
					},
					(true, false, true, _) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						message_integrity: type Sha3_256
					},
					(true, false, false, _) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher
					},
					(false, true, true, _) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256
					},
					(false, true, false, _) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						nonrepudiation<Secp256k1Signature, _>: signing_key
					},
					(false, false, true, true) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						message_integrity: type Sha3_256,
						frame_integrity: type Sha3_256
					},
					(false, false, true, false) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						message_integrity: type Sha3_256
					},
					(false, false, false, true) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						frame_integrity: type Sha3_256
					},
					(false, false, false, false) => compose! {
						V0: id: test_name, order: 1u64, message: message.clone()
					},
					(true, true, true, false) => compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						message_integrity: type Sha3_256
					},
					(true, true, false, true) => compose! {
						V2: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key,
						frame_integrity: type Sha3_256
					},
					(true, true, false, false) => compose! {
						V1: id: test_name, order: 1u64, message: message.clone(),
						confidentiality<Aes256GcmOid, _>: cipher,
						nonrepudiation<Secp256k1Signature, _>: signing_key
					},
				}
			}

			// Test cases: (name, attrs, confidential, nonrepudiable, message_integrity, frame_integrity, min_version)
			let test_cases = [
				("BasicMessage", "", false, false, false, false, Version::V0),
				(
					"ConfidentialMessage",
					"confidential, min_version = \"V1\"",
					true,
					false,
					false,
					false,
					Version::V1,
				),
				(
					"NonrepudiableMessage",
					"nonrepudiable, min_version = \"V1\"",
					false,
					true,
					false,
					false,
					Version::V1,
				),
				(
					"FullSecurityMessage",
					"confidential, nonrepudiable, message_integrity, frame_integrity, min_version = \"V2\"",
					true,
					true,
					true,
					true,
					Version::V2,
				),
			];

			for (name, _attrs, confidential, nonrepudiable, message_integrity, frame_integrity, min_version) in
				test_cases
			{
				// Generate the appropriate test message struct based on the test case
				match (confidential, nonrepudiable, message_integrity, frame_integrity, min_version) {
					(false, false, false, false, Version::V0) => {
						test_msg_struct!(false, false, false, false, V0);
						run_tests!(
							name,
							confidential,
							nonrepudiable,
							message_integrity,
							frame_integrity,
							min_version,
							&cipher,
							&signing_key
						);
					}
					(true, false, false, false, Version::V1) => {
						test_msg_struct!(true, false, false, false, V1);
						run_tests!(
							name,
							confidential,
							nonrepudiable,
							message_integrity,
							frame_integrity,
							min_version,
							&cipher,
							&signing_key
						);
					}
					(false, true, false, false, Version::V1) => {
						test_msg_struct!(false, true, false, false, V1);
						run_tests!(
							name,
							confidential,
							nonrepudiable,
							message_integrity,
							frame_integrity,
							min_version,
							&cipher,
							&signing_key
						);
					}
					(true, true, true, true, Version::V2) => {
						test_msg_struct!(true, true, true, true, V2);
						run_tests!(
							name,
							confidential,
							nonrepudiable,
							message_integrity,
							frame_integrity,
							min_version,
							&cipher,
							&signing_key
						);
					}
					_ => panic!(
						"Unhandled test case combination: ({confidential}, {nonrepudiable}, {message_integrity}, {frame_integrity}, {min_version:?})"
					),
				}
			}
		}
	}
}

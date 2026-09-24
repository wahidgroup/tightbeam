#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(
	not(feature = "std"),
	any(feature = "aead", feature = "signature", feature = "compress")
))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::builder::{MetadataBuilder, TypeBuilder};
use crate::der::oid::ObjectIdentifier;
use crate::error::Result;
use crate::error::{ReceivedExpectedError, TightBeamError};
use crate::matrix::{IntoMatrixDyn, MatrixDyn};
use crate::{DigestInfo, Frame, Message, Metadata, Version};

#[cfg(feature = "compress")]
use crate::compress::Compressor;
#[cfg(feature = "aead")]
use crate::crypto::aead::{AeadAlgorithm, Encryptor};
#[cfg(feature = "digest")]
use crate::crypto::commitment::{commit_digest, CommitmentSalt};
#[cfg(feature = "digest")]
use crate::crypto::hash::Digest;
#[cfg(any(feature = "aead", feature = "digest", feature = "signature"))]
use crate::crypto::profiles::SecurityProfile;
#[cfg(feature = "signature")]
use crate::crypto::sign::SignatureEncoding;
#[cfg(feature = "signature")]
use crate::crypto::sign::{Signatory, SignatureAlgorithmIdentifier};
#[cfg(any(feature = "digest", feature = "aead", feature = "ecdh"))]
use crate::der::oid::AssociatedOid;
#[cfg(feature = "digest")]
use crate::helpers::Digestor;

#[cfg(feature = "aead")]
type EncryptorFn = Box<dyn FnOnce(&[u8]) -> Result<crate::EncryptedContentInfo>>;

#[cfg(feature = "signature")]
type SignerFn = Box<dyn FnOnce(&[u8]) -> Result<crate::SignerInfo>>;

/// A message type that admits digest `D`.
///
/// `#[derive(Beamable)]` implements it as follows:
///
/// - A message that names no profile admits every digest.
/// - A message that names `profile(Type)` admits only the digest of that
///   profile, so a mismatched digest fails to compile for a derived message.
///
/// Any type can implement this trait, so [`FrameBuilder`] also compares the
/// OID with the message profile at run time. That comparison is the
/// enforcement.
#[cfg(feature = "digest")]
pub trait CheckDigestOid<D: AssociatedOid> {}

/// A message type that admits the AEAD algorithm `C`.
///
/// The derive implements it the same way as [`CheckDigestOid`], and
/// [`FrameBuilder`] enforces the profile at run time.
#[cfg(feature = "aead")]
pub trait CheckAeadOid<C: AssociatedOid> {}

/// A message type that admits the signature algorithm `S`.
///
/// The derive implements it the same way as [`CheckDigestOid`], and
/// [`FrameBuilder`] enforces the profile at run time.
#[cfg(feature = "signature")]
pub trait CheckSignatureOid<S: SignatureAlgorithmIdentifier> {}

/// Zero-allocation error accumulator for [`FrameBuilder`].
///
/// The accumulator stores up to 5 errors inline, which covers the common case
/// of one deferred error per builder method. Beyond 5 errors it spills to a
/// `Vec`.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
enum ErrorAccumulator {
	/// The accumulator holds no errors and allocates nothing.
	#[default]
	None,
	/// One error, stored inline without allocation.
	One(TightBeamError),
	/// Two to five errors, stored inline without allocation.
	Many([Option<TightBeamError>; 5], u8),
	/// Six or more errors, stored on the heap.
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

	/// Collapse into the terminal build error.
	///
	/// A single deferred error surfaces bare so callers can match on it
	/// directly. Only multiple errors are wrapped in `Sequence`.
	fn into_error(self) -> Option<TightBeamError> {
		match self {
			Self::None => None,
			Self::One(error) => Some(error),
			other => Some(TightBeamError::Sequence(Vec::from(other).into())),
		}
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

/// Fluent builder that creates a tightbeam [`Frame`] and generates its
/// metadata.
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
	#[cfg(feature = "aead")]
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
			#[cfg(feature = "aead")]
			rng: None,
			#[cfg(feature = "digest")]
			witness: None,
			#[cfg(feature = "signature")]
			signer: None,
		}
	}
}

impl<T: Message> FrameBuilder<T> {
	/// Set the message ID.
	pub fn with_id(mut self, id: impl AsRef<[u8]>) -> Self {
		self.metadata_builder = self.metadata_builder.with_id(id);
		self
	}

	pub fn with_content_oid(mut self, oid: ObjectIdentifier) -> Self {
		self.message_oid = Some(oid);
		self
	}

	/// Set the order.
	///
	/// The value is protocol-opaque: any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. When omitted, the
	/// build defaults it to the current Unix time in seconds.
	pub fn with_order(mut self, order: u64) -> Self {
		self.metadata_builder = self.metadata_builder.with_order(order);
		self
	}

	/// Set the message body.
	pub fn with_message(mut self, message: T) -> Self {
		self.message = Some(message);
		self
	}

	/// Set the message priority, which requires V2 or later.
	pub fn with_priority(mut self, priority: crate::MessagePriority) -> Self {
		self.metadata_builder = self.metadata_builder.with_priority(priority);
		self
	}

	/// Set the TTL in seconds, which requires V2 or later.
	pub fn with_lifetime(mut self, seconds: u64) -> Self {
		self.metadata_builder = self.metadata_builder.with_lifetime(seconds);
		self
	}

	/// Set the parent message hash, which requires V2 or later.
	///
	/// The hash links this message to its parent, so the messages form a
	/// cryptographic chain in which each message references the hash of its
	/// parent's content.
	pub fn with_previous_hash(mut self, parent_hash: crate::DigestInfo) -> Self {
		self.metadata_builder = self.metadata_builder.previous_frame(parent_hash);
		self
	}

	/// Set the routing matrix, which requires V3 or later.
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

	/// Set the routing matrix from a [`MatrixDyn`], which requires V3 or later.
	pub fn with_matrix_dyn(mut self, matrix: MatrixDyn) -> Self {
		self.metadata_builder = self.metadata_builder.with_matrix(matrix);
		self
	}

	fn validate(&self) -> Result<()> {
		if self.version < T::MIN_VERSION {
			return Err(TightBeamError::UnsupportedVersion(ReceivedExpectedError::from((
				self.version,
				T::MIN_VERSION,
			))));
		}

		// Each marker names the builder call that satisfies it, so a refusal
		// tells the caller what to add.
		#[cfg(feature = "aead")]
		if T::MUST_BE_CONFIDENTIAL && self.encryptor.is_none() {
			return Err(TightBeamError::MissingProtection { marker: "MUST_BE_CONFIDENTIAL", call: "with_aead" });
		}

		#[cfg(feature = "signature")]
		if T::MUST_BE_NON_REPUDIABLE && self.signer.is_none() {
			return Err(TightBeamError::MissingProtection { marker: "MUST_BE_NON_REPUDIABLE", call: "with_signer" });
		}

		#[cfg(feature = "compress")]
		if T::MUST_BE_COMPRESSED && self.compressor.is_none() {
			return Err(TightBeamError::MissingProtection { marker: "MUST_BE_COMPRESSED", call: "with_compression" });
		}

		#[cfg(feature = "digest")]
		if T::MUST_HAVE_MESSAGE_INTEGRITY && !self.metadata_builder.has_integrity() {
			return Err(TightBeamError::MissingProtection {
				marker: "MUST_HAVE_MESSAGE_INTEGRITY",
				call: "with_message_hasher",
			});
		}

		#[cfg(feature = "digest")]
		if T::MUST_HAVE_FRAME_INTEGRITY && self.witness.is_none() {
			return Err(TightBeamError::MissingProtection {
				marker: "MUST_HAVE_FRAME_INTEGRITY",
				call: "with_witness_hasher",
			});
		}

		if T::MUST_BE_PRIORITIZED && !self.metadata_builder.has_priority() {
			return Err(TightBeamError::MissingProtection { marker: "MUST_BE_PRIORITIZED", call: "with_priority" });
		}

		Ok(())
	}
}

#[cfg(feature = "compress")]
impl<T: Message> FrameBuilder<T> {
	/// Set the compression algorithm. Every version supports compression.
	pub fn with_compression(mut self, compressor: impl Compressor + 'static) -> Self {
		self.compressor = Some(Box::new(compressor));
		self
	}
}

#[cfg(feature = "aead")]
impl<T: Message> FrameBuilder<T> {
	pub fn with_rng(mut self, rng: impl rand_core::CryptoRngCore + 'static) -> Self {
		self.rng = Some(Box::new(rng));
		self
	}

	/// Set the AEAD cipher for symmetric encryption.
	///
	/// The cipher type names the algorithm identifier stamped on the frame.
	pub fn with_aead<Cipher>(mut self, cipher: Cipher) -> Self
	where
		Cipher: AeadAlgorithm + 'static,
		T: CheckAeadOid<Cipher::Oid>,
	{
		// A checker impl can admit any algorithm, so this comparison
		// enforces the profile.
		let received = <Cipher::Oid as AssociatedOid>::OID;
		let expected = <T::Profile as SecurityProfile>::AeadOid::OID;
		if T::HAS_PROFILE && received != expected {
			let mismatch = ReceivedExpectedError::from((received, expected));
			self.errors.push(TightBeamError::UnexpectedAlgorithm(mismatch));
			return self;
		}

		// The closure generates the nonce, so each nonce binds to one
		// encryption call. A builder that becomes reusable MUST NOT reuse a
		// captured nonce.
		let rng = self.rng.take();
		let message_oid = self.message_oid;
		self.encryptor = Some(Box::new(move |plaintext: &[u8]| {
			let mut rng = rng;
			let rng: &mut dyn rand_core::CryptoRngCore = match rng.as_mut() {
				Some(boxed_rng) => &mut **boxed_rng,
				None => &mut rand_core::OsRng,
			};

			let nonce = Cipher::generate_nonce(rng);
			let encrypted_content =
				<Cipher as Encryptor<Cipher::Oid>>::encrypt_content(&cipher, plaintext, &nonce, message_oid)?;
			Ok(encrypted_content)
		}));

		self
	}

	/// Use a custom encryptor for asymmetric encryption, such as ECIES.
	pub fn with_encryptor<C, E>(mut self, encryptor: E) -> Self
	where
		C: AssociatedOid,
		E: Encryptor<C> + 'static,
	{
		// The profile admits an encryptor that names its AEAD or its curve.
		if T::HAS_PROFILE {
			let aead_match = C::OID == <T::Profile as SecurityProfile>::AeadOid::OID;
			#[cfg(feature = "ecdh")]
			let curve_match = C::OID == <T::Profile as SecurityProfile>::Curve::OID;
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
			// The encryptor generates its own nonce, as ECIES does.
			encryptor.encrypt_content(plaintext, [], message_oid)
		}));

		self
	}
}

#[cfg(feature = "digest")]
impl<T: Message> FrameBuilder<T> {
	/// Commit to the message body using the digest algorithm `D`.
	///
	/// The commitment goes in the metadata integrity field. A salt of at least
	/// [`MIN_SALT_SIZE`] bytes hides the body, and an empty salt commits in
	/// plain-digest mode. [`crate::crypto::commitment`] owns the preimage.
	///
	/// A rejected salt or algorithm is recorded and surfaces from
	/// [`FrameBuilder::build`]:
	///
	/// - [`TightBeamError::InvalidSaltLength`] when a non-empty salt is too short to hide the body.
	/// - [`TightBeamError::UnexpectedAlgorithm`] when `D` is not the digest the
	///   message profile names.
	/// - [`TightBeamError::InvalidBody`] when no message is set.
	///
	/// [`MIN_SALT_SIZE`]: crate::constants::MIN_SALT_SIZE
	pub fn with_message_hasher<D>(mut self, salt: impl AsRef<[u8]>) -> Self
	where
		D: Digest + AssociatedOid,
		T: CheckDigestOid<D>,
	{
		// A checker impl can admit any algorithm, so this comparison
		// enforces the profile.
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::Digest::OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
					D::OID,
					<T::Profile as SecurityProfile>::Digest::OID,
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

		let salt = match CommitmentSalt::parse(salt) {
			Ok(salt) => salt,
			Err(e) => {
				self.errors.push(e);
				return self;
			}
		};

		match commit_digest::<D>(&salt, &encoded) {
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
		// A checker impl can admit any algorithm, so this comparison
		// enforces the profile.
		if T::HAS_PROFILE && D::OID != <T::Profile as SecurityProfile>::Digest::OID {
			self.errors
				.push(TightBeamError::UnexpectedAlgorithm(ReceivedExpectedError::from((
					D::OID,
					<T::Profile as SecurityProfile>::Digest::OID,
				))));
			return self;
		}

		self.witness = Some(Box::new(|tbs_der: &[u8]| crate::utils::digest::<D>(tbs_der)));
		self
	}
}

#[cfg(feature = "signature")]
impl<T: Message> FrameBuilder<T> {
	/// Set the signer that signs the frame.
	///
	/// This method captures the signer and its signing algorithm.
	/// [`FrameBuilder::build`] computes the signature over the complete message
	/// structure.
	pub fn with_signer<S, X>(mut self, signer: X) -> Self
	where
		S: SignatureEncoding + SignatureAlgorithmIdentifier,
		X: Signatory<S> + 'static,
		T: CheckSignatureOid<S>,
	{
		// A checker impl can admit any algorithm, so this comparison
		// enforces the profile.
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

	/// Build the final TightBeam message.
	///
	/// When [`FrameBuilder::with_signer`] set a signer, the build signs the
	/// entire message structure (version, metadata, and body) after
	/// construction. The signature covers the DER-encoded TightBeam structure
	/// without the signature field.
	///
	/// # Errors
	///
	/// The build returns an error when:
	///
	/// - a builder method recorded a validation error,
	/// - a required field is missing,
	/// - metadata validation fails, or
	/// - signing fails for the configured signer.
	fn build(mut self) -> Result<Frame> {
		if let Some(error) = core::mem::take(&mut self.errors).into_error() {
			return Err(error);
		}

		// 0. Validate the message restrictions.
		self.validate()?;

		let version = self.version;
		let message = self.message.ok_or(TightBeamError::InvalidBody)?;
		let metadata_builder = self.metadata_builder;

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
	/// Run the build stages in order after [`FrameBuilder::build`] validates
	/// the message.
	fn build_impl(
		version: Version,
		message: T,
		mut metadata_builder: MetadataBuilder,
		#[cfg(feature = "compress")] compressor: Option<Box<dyn Compressor>>,
		#[cfg(feature = "aead")] encryptor: Option<EncryptorFn>,
		#[cfg(feature = "digest")] witness: Option<Digestor>,
		#[cfg(feature = "signature")] signer: Option<SignerFn>,
	) -> Result<Frame> {
		metadata_builder = Self::ensure_order_set(metadata_builder)?;

		// 1-3. Encode, compress, and encrypt the message bytes.
		let (message_bytes, metadata_builder) = Self::build_message_bytes(
			message,
			metadata_builder,
			#[cfg(feature = "compress")]
			compressor,
			#[cfg(feature = "aead")]
			encryptor,
		)?;

		// 4. Build the optional witness. FI covers only the version and the
		// metadata, so the message stays outside it.
		let metadata = metadata_builder.build()?;
		let integrity = Self::build_frame_integrity(
			version,
			&metadata,
			#[cfg(feature = "digest")]
			witness,
		)?;

		let tbs = Frame::assemble(version, metadata, message_bytes, integrity)?;

		// 5. Sign the frame when a signer is set.
		Self::build_signature(
			tbs,
			#[cfg(feature = "signature")]
			signer,
		)
	}

	/// Set the order to the current Unix time in seconds when the caller
	/// omitted it.
	#[cfg(feature = "std")]
	fn ensure_order_set(mut metadata_builder: MetadataBuilder) -> Result<MetadataBuilder> {
		if !metadata_builder.has_order() {
			match SystemTime::now().duration_since(UNIX_EPOCH) {
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

	/// Encode the message, then compress and encrypt it when configured.
	fn build_message_bytes(
		message: T,
		metadata_builder: MetadataBuilder,
		#[cfg(feature = "compress")] compressor: Option<Box<dyn Compressor>>,
		#[cfg(feature = "aead")] encryptor: Option<EncryptorFn>,
	) -> Result<(Vec<u8>, MetadataBuilder)> {
		// Reassigned only by the compression/encryption stages below.
		#[cfg(any(feature = "compress", feature = "aead"))]
		let mut metadata_builder = metadata_builder;

		// 1. Encode the message in ASN.1.
		let bytes = crate::encode(&message)?;

		// 2. Compress the bytes when a compressor is set.
		#[cfg(feature = "compress")]
		let bytes = if let Some(compressor) = compressor {
			let (compressed, compression_info) = compressor.compress(&bytes, None)?;
			metadata_builder = metadata_builder.with_compactness_info(compression_info);
			compressed
		} else {
			bytes
		};

		// 3. Encrypt the bytes when an encryptor is set.
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

	/// Build frame integrity (FI) over the envelope when a witness is set.
	#[cfg(feature = "digest")]
	fn build_frame_integrity(
		version: Version,
		metadata: &Metadata,
		witness: Option<Digestor>,
	) -> Result<Option<DigestInfo>> {
		let Some(witness_fn) = witness else {
			return Ok(None);
		};

		let scaffold = crate::frame::FrameIntegrityScaffold { version: &version, metadata };
		let scaffold_der = crate::encode(&scaffold)?;
		let witness_info = witness_fn(&scaffold_der)?;

		Ok(Some(witness_info))
	}

	#[cfg(not(feature = "digest"))]
	fn build_frame_integrity(_version: Version, _metadata: &Metadata) -> Result<Option<DigestInfo>> {
		Ok(None)
	}

	/// Build the signature (nonrepudiation) when a signer is set.
	#[cfg(feature = "signature")]
	fn build_signature(mut tbs: Frame, signer: Option<SignerFn>) -> Result<Frame> {
		let Some(signer) = signer else {
			return Ok(tbs);
		};

		let tbs_der = tbs.to_tbs()?;
		let signer_info = signer(&tbs_der)?;

		tbs.attach_signer_info(signer_info)?;

		Ok(tbs)
	}

	#[cfg(not(feature = "signature"))]
	fn build_signature(tbs: Frame) -> Result<Frame> {
		Ok(tbs)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::test_builder;
	use crate::testing::{TestKey, TestMessage};

	#[cfg(feature = "compress")]
	use crate::compress::ZstdCompression;
	#[cfg(all(feature = "aes-gcm", feature = "sha3"))]
	use crate::crypto::hash::Sha3_256;

	#[cfg(feature = "sha3")]
	test_builder! {
		name: test_v0_basic,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V0,
		message: TestMessage::sample(None),
		setup: |builder, msg| {
			builder
				.with_message(msg)
				.with_id("test_v0_basic")
				.with_order(1696521600)
				.build()
		},
		assertions: |_msg, result| {
			let tightbeam  = result?;
			assert_eq!(tightbeam.version(), Version::V0);
			assert_eq!(str::from_utf8(tightbeam.metadata().id()), Ok("test_v0_basic"));
			Ok(())
		}
	}

	#[cfg(all(feature = "aes-gcm", feature = "sha3", feature = "secp256k1"))]
	test_builder! {
		name: test_v1_with_encryption,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V1,
		message: TestMessage::sample(None),
		setup: |builder, msg| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

		builder
			.with_message(msg)
			.with_id("test_v1_with_encryption")
			.with_order(1696521600)
			.with_aead(cipher)
			.with_signer::<Secp256k1Signature, _>(signing_key)
			.build()
		},
		assertions: |message, result| {
			let tightbeam  = result?;
			assert_eq!(tightbeam.version(), Version::V1);
			assert!(tightbeam.metadata().confidentiality().is_some());
			assert!(tightbeam.nonrepudiation().is_some());

			// Body should be encrypted (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err(), "Body should be encrypted");

			// Decrypt and verify
			let (_, cipher) = TestKey::cipher();
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
		message: TestMessage::sample(None),
		setup: |builder, msg| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::compress::ZstdCompression;

			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

		builder
			.with_message(msg)
			.with_id("test_v1_with_compression")
			.with_order(1696521600)
			.with_compression(ZstdCompression::default())
			.with_aead(cipher)
			.with_signer::<Secp256k1Signature, _>(signing_key)
			.build()
		},
		assertions: |message, result| {
			let tightbeam = result?;
			assert_eq!(tightbeam.version(), Version::V1);
			assert!(tightbeam.metadata().compactness().is_some());
			assert!(tightbeam.metadata().confidentiality().is_some());

			// Body should be encrypted+compressed (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err(), "Body should be encrypted/compressed");

			// Decrypt (automatically decompresses) and verify
			let (_, cipher) = TestKey::cipher();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, Some(&ZstdCompression::default()))?;
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
			TestMessage::sample(None)
		},
		setup: |builder, msg| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let (_, cipher) = TestKey::cipher();
			let signing_key = TestKey::signing();

			let previous_hash = crate::utils::digest::<Sha3_256>(b"previous-message-data")?;
			let rng = rand_core::OsRng;

			builder
				.with_message(msg)
				.with_id("test_v2_full")
				.with_order(1696521600)
				.with_message_hasher::<Sha3_256>([])
				.with_witness_hasher::<Sha3_256>()
				.with_compression(ZstdCompression::default())
				.with_rng(rng)
				.with_aead(cipher)
				.with_signer::<Secp256k1Signature, _>(signing_key)
				.with_priority(crate::MessagePriority::LowLatency)
				.with_lifetime(3600)
				.with_previous_hash(previous_hash)
				// The matrix requires V3 or later, so this V2 frame omits it.
				.build()
		},
		assertions: |message, result| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let tightbeam = result?;
			assert_eq!(tightbeam.version(), Version::V2);
			assert_eq!(tightbeam.metadata().id(), b"test_v2_full");
			assert_eq!(tightbeam.metadata().priority(), Some(crate::MessagePriority::LowLatency));
			assert_eq!(tightbeam.metadata().lifetime(), Some(3600));
			assert!(tightbeam.metadata().confidentiality().is_some());
			assert!(tightbeam.metadata().compactness().is_some());
			assert!(tightbeam.metadata().previous_frame().is_some());
			assert!(tightbeam.metadata().matrix().is_none()); // Matrix is V3+ only
			assert!(tightbeam.integrity().is_some());
			assert!(tightbeam.nonrepudiation().is_some());
			// Verify Message Integrity (MI): re-prove the commitment over the
			// original message and compare.
			assert!(tightbeam.verify_commitment_of::<Sha3_256, _>(&message, [])?);

			// Verify Frame Integrity (FI): hash the envelope (version and
			// metadata) and compare.
			let scaffold = crate::frame::FrameIntegrityScaffold {
				version: &tightbeam.version(),
				metadata: tightbeam.metadata(),
			};
			let scaffold_der = crate::encode(&scaffold)?;
			let expected_fi = crate::utils::digest::<Sha3_256>(&scaffold_der)?;
			let actual_fi = tightbeam.integrity().ok_or(TightBeamError::MissingDigestInfo)?;
			assert_eq!(actual_fi.digest.as_bytes(), expected_fi.digest.as_bytes());

			// Body should be encrypted+compressed (not directly decodable)
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err());

			// Verify the signature first, because decryption consumes the
			// frame.
			let signing_key = TestKey::signing();
			let verifying_key = signing_key.verifying_key();
			assert!(tightbeam.verify::<Secp256k1Signature, Sha3_256>(verifying_key).is_ok());

			// Decrypt (automatically decompresses) and verify
			let (_, cipher) = TestKey::cipher();
			let decrypted = tightbeam.decrypt::<TestMessage>(&cipher, Some(&ZstdCompression::default()))?;
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
			.with_message_hasher::<Sha3_256>([])
			.build();
		assert!(result.is_err());
	}

	// Hashing before the message is set defers an `InvalidBody` error. A single
	// deferred error surfaces bare, outside a one-element `Sequence`.
	#[test]
	#[cfg(feature = "sha3")]
	fn test_single_deferred_error_surfaces_bare() {
		let message = TestMessage::sample(None);
		let result = FrameBuilder::from(Version::V0)
			.with_id("error-test")
			.with_order(1696521600)
			.with_message_hasher::<Sha3_256>([])
			.with_message(message)
			.build();
		assert!(matches!(result, Err(TightBeamError::InvalidBody)));
	}

	#[test]
	#[cfg(feature = "sha3")]
	fn test_multiple_deferred_errors_surface_as_sequence() {
		let message = TestMessage::sample(None);
		let result = FrameBuilder::from(Version::V0)
			.with_id("error-test")
			.with_order(1696521600)
			.with_message_hasher::<Sha3_256>([])
			.with_message_hasher::<Sha3_256>([])
			.with_message(message)
			.build();
		assert!(matches!(result, Err(TightBeamError::Sequence(ref errors)) if errors.len() == 2));
	}

	// V1 is the first version whose metadata carries integrity info.
	// `MetadataBuilder::build` rejects V0 with `message_integrity`.
	#[test]
	fn test_compose_macro() -> Result<()> {
		let message = TestMessage::sample(None);
		let frame = compose! {
			V1:
				id: "test-id",
				order: 1696521600,
				message: message,
				message_integrity<Sha3_256>: [] // no salt
		}?;
		assert_eq!(frame.version(), Version::V1);
		assert_eq!(frame.metadata().id(), b"test-id");
		assert_eq!(frame.metadata().order(), 1696521600);
		assert!(frame.metadata().integrity().is_some());
		Ok(())
	}

	/// The refusal a message type draws when built with nothing its markers
	/// require.
	#[cfg(all(feature = "aead", feature = "digest", feature = "signature"))]
	fn unprotected_refusal<T: Message>(message: T) -> TightBeamError {
		let built = FrameBuilder::from(Version::V2)
			.with_id("unprotected")
			.with_order(1)
			.with_message(message)
			.build();

		built.expect_err("the fixture's markers require a protection it was not given")
	}

	// A marker refusal names the marker and the builder call that satisfies
	// it, so the caller knows what to add.
	#[cfg(all(feature = "aead", feature = "digest", feature = "signature"))]
	crate::tb_cases! {
		fn a_marker_refusal_names_its_call((refusal, marker, call): (TightBeamError, &str, &str)) {
			assert!(
				matches!(&refusal, TightBeamError::MissingProtection { marker: m, call: c } if *m == marker && *c == call),
				"expected {marker} / {call}, got {refusal:?}"
			);
		}
		cases {
			confidential => (
				unprotected_refusal(crate::testing::fixtures::ConfidentialNote { content: "x".into() }),
				"MUST_BE_CONFIDENTIAL",
				"with_aead"
			),
			message_integrity => (
				unprotected_refusal(crate::testing::fixtures::IntegralNote { content: "x".into() }),
				"MUST_HAVE_MESSAGE_INTEGRITY",
				"with_message_hasher"
			),
		}
	}

	mod validation {
		use super::*;
		use crate::crypto::aead::{Aes256Gcm, Aes256GcmOid};
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::testing::TestKey;
		use crate::Version;

		// Run the shared assertions after the struct definition.
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
				let frame = result?;

				// Test 3: Verify the README semantics. Each MUST flag requires
				// the matching frame field.
				// README line 363: MUST_BE_NON_REPUDIABLE=true requires the
				// nonrepudiation field.
				assert_eq!(frame.nonrepudiation().is_some(), $nonrepudiable);
				// README line 364: MUST_BE_CONFIDENTIAL=true requires the
				// confidentiality field.
				assert_eq!(frame.metadata().confidentiality().is_some(), $confidential);
				// MUST_HAVE_MESSAGE_INTEGRITY=true requires the metadata
				// integrity field.
				assert_eq!(frame.metadata().integrity().is_some(), $message_integrity);
				// MUST_HAVE_FRAME_INTEGRITY=true requires the frame integrity
				// field.
				assert_eq!(frame.integrity().is_some(), $frame_integrity);

				// Test 4: Verify version enforcement
				if $min_version > Version::V0 {
					let result_v0 = compose! {
						V0: id: $name, order: 1u64, message: message.clone()
					};
					assert!(result_v0.is_err());
				}
			};
		}

		// Generate the test message struct with the attributes of one case. The
		// macro matches only the four cases that the test uses.
		macro_rules! test_msg_struct {
			// BasicMessage: (false, false, false, false, V0)
			(false, false, false, false, V0) => {
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(min_version = "V0")]
				struct TestMsg {
					content: String,
				}
			};
			// ConfidentialMessage: (true, false, false, false, V1)
			(true, false, false, false, V1) => {
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(confidential, min_version = "V1")]
				struct TestMsg {
					content: String,
				}
			};
			// NonrepudiableMessage: (false, true, false, false, V1)
			(false, true, false, false, V1) => {
				#[derive($crate::Beamable, Clone, Debug, PartialEq, der::Sequence)]
				#[beam(nonrepudiable, min_version = "V1")]
				struct TestMsg {
					content: String,
				}
			};
			// FullSecurityMessage: (true, true, true, true, V2)
			(true, true, true, true, V2) => {
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
			};
		}

		// Compose a frame that satisfies the given security requirements.
		// The requirement tuple selects the matching `compose!` invocation.
		#[allow(clippy::too_many_arguments)]
		fn compose_frame<T>(
			test_name: impl AsRef<str>,
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
			let test_name = test_name.as_ref();
			match (confidential, nonrepudiable, message_integrity, frame_integrity) {
				(true, true, true, true) => compose! {
					V2: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: [],
					frame_integrity: type Sha3_256
				},
				(true, false, true, _) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					message_integrity<Sha3_256>: []
				},
				(true, false, false, _) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher
				},
				(false, true, true, _) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: []
				},
				(false, true, false, _) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					nonrepudiation<Secp256k1Signature, _>: signing_key
				},
				(false, false, true, true) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					message_integrity<Sha3_256>: [],
					frame_integrity: type Sha3_256
				},
				(false, false, true, false) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					message_integrity<Sha3_256>: []
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
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					message_integrity<Sha3_256>: []
				},
				(true, true, false, true) => compose! {
					V2: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key,
					frame_integrity: type Sha3_256
				},
				(true, true, false, false) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: signing_key
				},
			}
		}

		// Each requirement combination gets one named test. The same flag tuple
		// drives the struct definition and the shared assertions, so each test
		// body stays free of dispatch logic.
		macro_rules! message_trait_test {
			($test:ident, $name:expr, $confidential:tt, $nonrepudiable:tt, $message_integrity:tt, $frame_integrity:tt, $version:ident) => {
				#[test]
				fn $test() -> Result<()> {
					let (_, cipher) = TestKey::cipher();
					let signing_key = TestKey::signing();

					test_msg_struct!($confidential, $nonrepudiable, $message_integrity, $frame_integrity, $version);
					run_tests!(
						$name,
						$confidential,
						$nonrepudiable,
						$message_integrity,
						$frame_integrity,
						Version::$version,
						&cipher,
						&signing_key
					);

					Ok(())
				}
			};
		}

		message_trait_test!(test_basic_message_traits, "BasicMessage", false, false, false, false, V0);
		message_trait_test!(
			test_confidential_message_traits,
			"ConfidentialMessage",
			true,
			false,
			false,
			false,
			V1
		);
		message_trait_test!(
			test_nonrepudiable_message_traits,
			"NonrepudiableMessage",
			false,
			true,
			false,
			false,
			V1
		);
		message_trait_test!(
			test_full_security_message_traits,
			"FullSecurityMessage",
			true,
			true,
			true,
			true,
			V2
		);
	}
}

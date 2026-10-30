#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(
	not(feature = "std"),
	any(feature = "aead", feature = "signature", feature = "compress")
))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(host_clock)]
use core::time::Duration;

use crate::builder::{MetadataBuilder, TypeBuilder};
use crate::core::Requirement;
use crate::der::oid::ObjectIdentifier;
use crate::error::Result;
use crate::error::TightBeamError;
use crate::matrix::{IntoMatrixDyn, MatrixDyn};
use crate::{DigestInfo, Frame, Message, Metadata, Version};

#[cfg(feature = "aead")]
use crate::asn1::{AuthEnvelopedData, WireDer};
#[cfg(host_clock)]
use crate::clock::UnixMillis;
#[cfg(feature = "compress")]
use crate::compress::Compressor;
#[cfg(feature = "aead")]
use crate::crypto::aead::Encryptor;
#[cfg(feature = "digest")]
use crate::crypto::commitment::CommitmentSalt;
#[cfg(feature = "digest")]
use crate::crypto::hash::Digest;
#[cfg(feature = "digest")]
use crate::crypto::profiles::Digestor;
#[cfg(any(feature = "aead", feature = "digest", feature = "signature"))]
use crate::crypto::profiles::SecurityProfile;
#[cfg(feature = "signature")]
use crate::crypto::sign::SignatureEncoding;
#[cfg(feature = "signature")]
use crate::crypto::sign::{
	CanonicalForm, CertifiedKey, CmsSigner, PrehashSigner, SignatureAlgorithmIdentifier, Signed, SignedContent,
};
#[cfg(any(feature = "digest", feature = "aead"))]
use crate::der::oid::AssociatedOid;
#[cfg(any(feature = "aead", feature = "digest", feature = "signature"))]
use crate::error::ReceivedExpectedError;

#[cfg(feature = "aead")]
type EncryptorFn = Box<dyn FnOnce(Vec<u8>) -> Result<AuthEnvelopedData>>;

/// The seal of an encryptor, which takes the content type and the random
/// source the build hands it.
#[cfg(feature = "aead")]
type SealFn = Box<
	dyn FnOnce(
		Vec<u8>,
		Option<ObjectIdentifier>,
		Option<&mut dyn rand_core::CryptoRngCore>,
	) -> Result<AuthEnvelopedData>,
>;

#[cfg(feature = "signature")]
type SignerFn = Box<dyn FnOnce(&[u8]) -> Result<Signed<crate::SignerInfo>>>;

/// A message type that admits digest `D`.
///
/// `#[derive(Beamable)]` implements it:
///
/// - A message that names no profile admits every digest.
/// - A message that names `profile(Type)` admits only that profile's digest, so a mismatch fails to compile.
///
/// Any type can implement it, so [`FrameBuilder`] also compares the OID with
/// the message profile at run time, and that comparison is the enforcement.
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

/// The inline error accumulator of [`FrameBuilder`].
///
/// It stores up to 5 errors inline, enough for the common case of one deferred
/// error per builder method, and spills to a `Vec` past 5.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default)]
enum ErrorAccumulator {
	/// The accumulator holds no errors and allocates nothing.
	#[default]
	None,
	/// The accumulator holds one error inline.
	One(TightBeamError),
	/// The accumulator holds two to five errors inline.
	Many([Option<TightBeamError>; 5], u8),
	/// The accumulator holds six or more errors on the heap.
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
				if let Some(slot) = arr.get_mut(len_usize) {
					*slot = Some(error);
					*self = Self::Many(arr, len.saturating_add(1));
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
	/// One deferred error surfaces bare, so a caller can match on it. Two or
	/// more surface as one `Sequence`.
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

/// A fluent builder that creates a tightbeam [`Frame`] and generates its
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
	encryptor: Option<SealFn>,
	#[cfg(feature = "aead")]
	rng: Option<Box<dyn rand_core::CryptoRngCore>>,
	#[cfg(feature = "digest")]
	commitment: Option<Digestor>,
	#[cfg(feature = "digest")]
	witness: Option<Digestor>,
	#[cfg(feature = "signature")]
	signer: Option<SignerFn>,
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
			commitment: None,
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

	/// Set the content type the encryptor seals the body as, or `id-data` when
	/// unset. The envelope names it in its content type and its content-type
	/// attribute.
	pub fn with_content_oid(mut self, oid: ObjectIdentifier) -> Self {
		self.message_oid = Some(oid);
		self
	}

	/// Set the order.
	///
	/// The value is protocol-opaque, so any monotonic scheme works, such as a
	/// Unix timestamp or a dense per-channel counter. A build with a host clock
	/// defaults an unset order to the current Unix time in seconds.
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
	/// The hash links this message to its parent's content, so the messages
	/// form a cryptographic chain.
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

	/// Refuse to build a Frame that is no carrier of `T`, before any work.
	///
	/// # Errors
	///
	/// - [`TightBeamError::Requirement`] -- the version is below the
	///   `MIN_VERSION` of `T`, the refusal of every typed decode.
	/// - [`TightBeamError::MissingProtection`] -- `T` sets a requirement that
	///   this builder holds no call for. The error names the marker and the
	///   builder call that meets it.
	fn validate(&self) -> Result<()> {
		self.version.admit_for::<T>()?;

		let mut requirements = Requirement::ALL.into_iter();
		let unmet = requirements.find(|requirement| requirement.is_set_by::<T>() && !self.meets(*requirement));
		if let Some(requirement) = unmet {
			let (marker, call) = (requirement.marker(), requirement.builder_call());
			return Err(TightBeamError::MissingProtection { marker, call });
		}

		Ok(())
	}

	/// Whether this builder meets `requirement` before the build: it holds the
	/// call that meets it. A build without the feature of that call leaves the
	/// requirement to step 6 of [`FrameBuilder::build`], which refuses the
	/// Frame that lacks the protection.
	fn meets(&self, requirement: Requirement) -> bool {
		match requirement {
			#[cfg(feature = "aead")]
			Requirement::Confidentiality => self.encryptor.is_some(),
			#[cfg(not(feature = "aead"))]
			Requirement::Confidentiality => true,
			#[cfg(feature = "signature")]
			Requirement::NonRepudiation => self.signer.is_some(),
			#[cfg(not(feature = "signature"))]
			Requirement::NonRepudiation => true,
			#[cfg(feature = "compress")]
			Requirement::Compression => self.compressor.is_some(),
			#[cfg(not(feature = "compress"))]
			Requirement::Compression => true,
			#[cfg(feature = "digest")]
			Requirement::MessageIntegrity => self.commitment.is_some(),
			#[cfg(feature = "digest")]
			Requirement::FrameIntegrity => self.witness.is_some(),
			#[cfg(not(feature = "digest"))]
			Requirement::MessageIntegrity | Requirement::FrameIntegrity => true,
			Requirement::Priority => self.metadata_builder.has_priority(),
		}
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
	/// Set the random source of the encryptor's content key, nonce, and
	/// recipient values, or the OS source when unset. It applies before or
	/// after [`Self::with_encryptor`].
	pub fn with_rng(mut self, rng: impl rand_core::CryptoRngCore + 'static) -> Self {
		self.rng = Some(Box::new(rng));
		self
	}

	/// Set the encryptor that seals the message body as an
	/// `AuthEnvelopedData`, such as an in-memory key-encryption key or a KEM
	/// recipient.
	///
	/// - The encryptor names the content-encryption algorithm `C` its envelopes carry.
	/// - A message with a profile admits the profile's AEAD alone, at compile time when derived.
	/// - [`Self::with_rng`] sets its random source.
	pub fn with_encryptor<C, E>(mut self, encryptor: E) -> Self
	where
		C: AssociatedOid,
		E: Encryptor<C> + 'static,
		T: CheckAeadOid<C>,
	{
		// A checker impl can admit any algorithm, so this comparison
		// enforces the profile.
		let expected = <T::Profile as SecurityProfile>::AeadOid::OID;
		if T::HAS_PROFILE && C::OID != expected {
			let mismatch = ReceivedExpectedError::from((C::OID, expected));
			self.errors.push(TightBeamError::UnexpectedAlgorithm(mismatch));
			return self;
		}

		self.encryptor = Some(Box::new(
			move |content: Vec<u8>,
			      content_type: Option<ObjectIdentifier>,
			      rng: Option<&mut dyn rand_core::CryptoRngCore>| {
				encryptor.encrypt_content(content, content_type, rng)
			},
		));

		self
	}
}

#[cfg(feature = "digest")]
impl<T: Message> FrameBuilder<T> {
	/// Commit to the body the frame carries with the digest algorithm `D`.
	///
	/// The commitment goes in the metadata integrity field. A salt of at least
	/// [`MIN_SALT_SIZE`] bytes hides the body, and an empty salt commits in
	/// plain-digest mode. [`crate::crypto::commitment`] owns the preimage.
	///
	/// The builder defers each refusal below to [`FrameBuilder::build`]:
	///
	/// - [`TightBeamError::InvalidSaltLength`] when a non-empty salt is too short to hide the body.
	/// - [`TightBeamError::UnexpectedAlgorithm`] when `D` is not the digest the message profile names.
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

		let salt = match CommitmentSalt::parse(salt) {
			Ok(salt) => salt,
			Err(e) => {
				self.errors.push(e);
				return self;
			}
		};

		self.commitment = Some(Box::new(move |body: &[u8]| salt.commit::<D>(body)));
		self
	}

	/// Set the witness: the frame integrity (FI) digest, under the digest
	/// algorithm `D`, over the version and the metadata.
	///
	/// A `D` other than the profile's digest defers
	/// [`TightBeamError::UnexpectedAlgorithm`] to [`FrameBuilder::build`].
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
	/// Set the signer that signs the frame under the algorithm `S`: a key
	/// beside the certificate that names it.
	///
	/// [`FrameBuilder::build`] signs through the CMS signer, so the
	/// `SignerInfo` carries the signed attributes and names the certificate
	/// (RFC 5652 §5.3).
	pub fn with_signer<S, X>(mut self, signer: CertifiedKey<X>) -> Self
	where
		S: CanonicalForm + SignatureEncoding + SignatureAlgorithmIdentifier,
		X: PrehashSigner<S> + 'static,
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

		self.signer = Some(Box::new(move |tbs: &[u8]| {
			let content = SignedContent::data(tbs);
			Ok(CmsSigner::sign_with::<S, X>(&signer, content)?)
		}));
		self
	}
}

impl<T: Message> TypeBuilder<Frame> for FrameBuilder<T> {
	type Error = TightBeamError;

	/// Build the final TightBeam message.
	///
	/// With a signer from [`FrameBuilder::with_signer`], the build signs the
	/// whole message structure (version, metadata, and body) last. The
	/// signature covers its DER encoding without the signature field.
	///
	/// # Errors
	///
	/// - The error a builder method recorded, or [`TightBeamError::Sequence`]
	///   when two or more methods recorded one.
	/// - [`TightBeamError::Requirement`] -- the version is below the message's
	///   `MIN_VERSION` ([`RequirementError::Version`]), as every typed decode
	///   refuses it.
	/// - [`TightBeamError::MissingProtection`] -- a message marker requires a protection the build lacks.
	/// - [`TightBeamError::InvalidBody`] -- no message is set.
	/// - [`TightBeamError::BuildError`] -- the metadata has no id or no order.
	/// - [`TightBeamError::UnsupportedField`] -- a metadata field, the FI
	///   digest, or the signature is gated above the version (§5.6).
	/// - The error of the configured signer, when the signature fails.
	/// - [`TightBeamError::Requirement`] -- the built frame fails a
	///   requirement of the message type, such as a key wrap outside its
	///   profile ([`Frame::validate_for`]).
	///
	/// [`RequirementError::Version`]: crate::core::RequirementError::Version
	fn build(mut self) -> Result<Frame> {
		if let Some(error) = core::mem::take(&mut self.errors).into_error() {
			return Err(error);
		}

		// 0. Validate the message restrictions.
		self.validate()?;

		let version = self.version;
		let message = self.message.ok_or(TightBeamError::InvalidBody)?;
		let metadata_builder = Self::ensure_order_set(self.metadata_builder)?;

		// The content type and the random source bind at the build, so each
		// applies whatever its order against the encryptor.
		#[cfg(feature = "aead")]
		let message_oid = self.message_oid;
		#[cfg(feature = "aead")]
		let mut rng = self.rng;
		#[cfg(feature = "aead")]
		let encryptor = self.encryptor.map(|seal| -> EncryptorFn {
			Box::new(move |content: Vec<u8>| {
				let rng = rng.as_deref_mut().map(|rng| rng as &mut dyn rand_core::CryptoRngCore);
				seal(content, message_oid, rng)
			})
		});

		// 1-3. Encode, commit to, compress, and encrypt the message bytes.
		let (message_bytes, metadata_builder) = Self::build_message_bytes(
			message,
			metadata_builder,
			#[cfg(feature = "digest")]
			self.commitment,
			#[cfg(feature = "compress")]
			self.compressor,
			#[cfg(feature = "aead")]
			encryptor,
		)?;

		let frame = Self::build_impl(
			version,
			message_bytes,
			metadata_builder,
			#[cfg(feature = "digest")]
			self.witness,
			#[cfg(feature = "signature")]
			self.signer,
		)?;

		// 6. Hold the frame to the requirements of the message type, as a
		// receiver holds it. The envelope alone names the key wrap of its
		// recipients, so this stage compares the wrap with the profile.
		frame.validate_for::<T>()?;

		Ok(frame)
	}
}

impl<T: Message> FrameBuilder<T> {
	/// Run the build stages that follow the message bytes, in order, after
	/// [`FrameBuilder::build`] validates the message and builds its bytes.
	fn build_impl(
		version: Version,
		message_bytes: Vec<u8>,
		metadata_builder: MetadataBuilder,
		#[cfg(feature = "digest")] witness: Option<Digestor>,
		#[cfg(feature = "signature")] signer: Option<SignerFn>,
	) -> Result<Frame> {
		// 4. Build the optional witness. FI covers only the version and the
		// metadata, so the message stays outside it.
		let metadata = Metadata::assemble(metadata_builder)?;
		let integrity = Self::build_frame_integrity(
			version,
			&metadata,
			#[cfg(feature = "digest")]
			witness,
		)?;

		// The assembly refuses a metadata field and a frame field that the
		// version forbids with one error (§5.6).
		let tbs = Frame::assemble(version, metadata, message_bytes, integrity)?;

		// 5. Sign the frame when a signer is set.
		Self::build_signature(
			tbs,
			#[cfg(feature = "signature")]
			signer,
		)
	}

	/// Default an unset order to the current Unix time in seconds.
	///
	/// The reading comes from [`UnixMillis::now`], the clock every other time
	/// decision reads. A build without a host clock leaves the order to the
	/// caller.
	#[cfg(host_clock)]
	fn ensure_order_set(mut metadata_builder: MetadataBuilder) -> Result<MetadataBuilder> {
		if !metadata_builder.has_order() {
			let now = UnixMillis::now();
			let seconds = Duration::from_millis(now.get()).as_secs();
			metadata_builder = metadata_builder.with_order(seconds);
		}

		Ok(metadata_builder)
	}

	#[cfg(not(host_clock))]
	fn ensure_order_set(metadata_builder: MetadataBuilder) -> Result<MetadataBuilder> {
		Ok(metadata_builder)
	}

	/// Encode the message, then commit to, compress, and encrypt it when
	/// configured.
	fn build_message_bytes(
		message: T,
		metadata_builder: MetadataBuilder,
		#[cfg(feature = "digest")] commitment: Option<Digestor>,
		#[cfg(feature = "compress")] compressor: Option<Box<dyn Compressor>>,
		#[cfg(feature = "aead")] encryptor: Option<EncryptorFn>,
	) -> Result<(Vec<u8>, MetadataBuilder)> {
		// Only the commitment, compression, and encryption stages reassign the
		// builder.
		#[cfg(any(feature = "digest", feature = "compress", feature = "aead"))]
		let mut metadata_builder = metadata_builder;

		// 1. Encode the message in ASN.1, and commit to that one encoding when
		// a commitment is set.
		let bytes = crate::encode(&message)?;
		#[cfg(feature = "digest")]
		if let Some(commit) = commitment {
			let integrity = commit(&bytes)?;
			metadata_builder = metadata_builder.with_integrity_info(integrity);
		}

		// 2. Compress the bytes when a compressor is set.
		#[cfg(feature = "compress")]
		let bytes = if let Some(compressor) = compressor {
			let (compressed, compression_info) = compressor.compress(&bytes, None)?;
			metadata_builder = metadata_builder.with_compactness_info(compression_info);
			compressed
		} else {
			bytes
		};

		// 3. Encrypt the bytes in place when an encryptor is set. The
		// ciphertext moves into the message, detached from the envelope that
		// stays in the metadata (RFC 5652 §6.1).
		#[cfg(feature = "aead")]
		let message_bytes = if let Some(enc) = encryptor {
			let mut envelope = enc(bytes)?;
			let encrypted_bytes = envelope
				.auth_encrypted_content_info
				.encrypted_content
				.take()
				.ok_or(TightBeamError::MissingEncryptionInfo)?;
			metadata_builder = metadata_builder.with_confidentiality_info(WireDer::new(envelope)?);
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
	use crate::core::RequirementError;
	use crate::test_builder;
	use crate::testing::{TestFrame, TestIdentity, TestKey, TestMessage};
	use crate::Beamable;

	#[cfg(feature = "zstd")]
	use crate::compress::ZstdCompression;
	#[cfg(all(feature = "aes-gcm", feature = "sha3"))]
	use crate::crypto::hash::Sha3_256;

	/// A frame built without an order takes the [`UnixMillis::now`] reading in
	/// seconds, so its order agrees with every other clock value.
	#[cfg(host_clock)]
	#[test]
	fn an_omitted_order_defaults_to_the_clocks_seconds() -> Result<()> {
		let before = Duration::from_millis(UnixMillis::now().get()).as_secs();
		let frame = FrameBuilder::<TestMessage>::from(Version::V0)
			.with_message(TestMessage::sample(None))
			.with_id("default-order")
			.build()?;

		let after = Duration::from_millis(UnixMillis::now().get()).as_secs();
		assert!((before..=after).contains(&frame.metadata().order()));
		Ok(())
	}

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

			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

		builder
			.with_message(msg)
			.with_id("test_v1_with_encryption")
			.with_order(1696521600)
			.with_encryptor(cipher)
			.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(signing_key))
			.build()
		},
		assertions: |message, result| {
			let tightbeam  = result?;
			assert_eq!(tightbeam.version(), Version::V1);
			assert!(tightbeam.metadata().confidentiality().is_some());
			assert!(tightbeam.nonrepudiation().is_some());

			// The body is encrypted, so it does not decode as the message.
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err(), "Body should be encrypted");

			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let decrypted = TestFrame::decrypted::<TestMessage>(tightbeam, &cipher, None)?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	#[cfg(all(feature = "zstd", feature = "aes-gcm", feature = "sha3", feature = "secp256k1"))]
	test_builder! {
		name: test_v1_with_compression,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V1,
		message: TestMessage::sample(None),
		setup: |builder, msg| {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::compress::ZstdCompression;

			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

		builder
			.with_message(msg)
			.with_id("test_v1_with_compression")
			.with_order(1696521600)
			.with_compression(ZstdCompression::default())
			.with_encryptor(cipher)
			.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(signing_key))
			.build()
		},
		assertions: |message, result| {
			let tightbeam = result?;
			assert_eq!(tightbeam.version(), Version::V1);
			assert!(tightbeam.metadata().compactness().is_some());
			assert!(tightbeam.metadata().confidentiality().is_some());

			// The body is compressed and encrypted, so it does not decode as
			// the message.
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err(), "Body should be encrypted/compressed");

			// The decryption also decompresses the body.
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let decrypted = TestFrame::decrypted::<TestMessage>(tightbeam, &cipher, Some(&ZstdCompression::default()))?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	#[cfg(all(
		feature = "zstd",
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

			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

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
				.with_encryptor(cipher)
				.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(signing_key))
				.with_priority(crate::MessagePriority::LowLatency)
				.with_lifetime(3600)
				.with_previous_hash(previous_hash)
				// The matrix requires V3 or later, so this V2 frame omits it.
				.build()
		},
		assertions: |message, result| {
			use crate::crypto::profiles::DefaultCryptoProvider;
			use crate::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
			use crate::testing::TestCertificate;

			let tightbeam = result?;
			assert_eq!(tightbeam.version(), Version::V2);
			assert_eq!(tightbeam.metadata().id(), b"test_v2_full");
			assert_eq!(tightbeam.metadata().priority(), Some(crate::MessagePriority::LowLatency));
			assert_eq!(tightbeam.metadata().lifetime(), Some(3600));
			assert!(tightbeam.metadata().confidentiality().is_some());
			assert!(tightbeam.metadata().compactness().is_some());
			assert!(tightbeam.metadata().previous_frame().is_some());
			assert!(tightbeam.metadata().matrix().is_none()); // The matrix needs V3 or later.
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

			// The body is compressed and encrypted, so it does not decode as
			// the message.
			let decode_result: Result<TestMessage> = crate::decode(tightbeam.message());
			assert!(decode_result.is_err());

			// Verify the signature first, because decryption consumes the
			// frame.
			let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
			let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, KeyPurposes::HOUSE.signer)?;
			assert!(tightbeam.verify(&signer).is_ok());

			// The decryption also decompresses the body.
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let decrypted = TestFrame::decrypted::<TestMessage>(tightbeam, &cipher, Some(&ZstdCompression::default()))?;
			assert_eq!(decrypted, message);

			Ok(())
		}
	}

	/// The commitment runs over the body the frame carries, so a message set
	/// after the hasher is the one it commits to.
	#[test]
	#[cfg(feature = "sha3")]
	fn a_frame_commits_to_the_body_it_carries() -> Result<()> {
		use crate::crypto::hash::Sha3_256;

		let carried = TestMessage::sample(Some("carried"));
		let frame = FrameBuilder::<TestMessage>::from(Version::V1)
			.with_id("commitment")
			.with_order(1)
			.with_message(TestMessage::sample(Some("replaced")))
			.with_message_hasher::<Sha3_256>([])
			.with_message(carried.clone())
			.build()?;
		assert!(frame.verify_commitment_of::<Sha3_256, _>(&carried, [])?);
		Ok(())
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

	/// A salt too short to hide the body, which a hash call defers as an
	/// `InvalidSaltLength` error.
	const SHORT_SALT: [u8; 1] = [0x5a];

	// A single deferred error surfaces bare, outside a one-element `Sequence`.
	#[test]
	#[cfg(feature = "sha3")]
	fn test_single_deferred_error_surfaces_bare() {
		let message = TestMessage::sample(None);
		let result = FrameBuilder::from(Version::V0)
			.with_id("error-test")
			.with_order(1696521600)
			.with_message(message)
			.with_message_hasher::<Sha3_256>(SHORT_SALT)
			.build();
		assert!(matches!(result, Err(TightBeamError::InvalidSaltLength(_))));
	}

	#[test]
	#[cfg(feature = "sha3")]
	fn test_multiple_deferred_errors_surface_as_sequence() {
		let message = TestMessage::sample(None);
		let result = FrameBuilder::from(Version::V0)
			.with_id("error-test")
			.with_order(1696521600)
			.with_message(message)
			.with_message_hasher::<Sha3_256>(SHORT_SALT)
			.with_message_hasher::<Sha3_256>(SHORT_SALT)
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
				message_integrity<Sha3_256>: [] // The salt is empty.
		}?;
		assert_eq!(frame.version(), Version::V1);
		assert_eq!(frame.metadata().id(), b"test-id");
		assert_eq!(frame.metadata().order(), 1696521600);
		assert!(frame.metadata().integrity().is_some());
		Ok(())
	}

	/// Returns the refusal that a message type draws when the build gives it
	/// none of the protections its markers require.
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
				"with_encryptor"
			),
			message_integrity => (
				unprotected_refusal(crate::testing::fixtures::IntegralNote { content: "x".into() }),
				"MUST_HAVE_MESSAGE_INTEGRITY",
				"with_message_hasher"
			),
		}
	}

	/// A note whose type requires V2 or later.
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(min_version = "V2")]
	struct RecentNote {
		content: String,
	}

	/// A build below the minimum version of its type refuses with the error
	/// that every typed decode of a frame of the type returns.
	#[test]
	fn a_build_below_the_minimum_version_refuses_as_a_typed_decode_does() -> Result<()> {
		let message = RecentNote { content: "recent".into() };
		let refused = compose! { V1: id: "recent", order: 1u64, message: message };

		let below = RequirementError::Version((Version::V1, Version::V2).into());
		assert!(matches!(refused, Err(TightBeamError::Requirement(error)) if error == below));
		Ok(())
	}

	#[cfg(all(feature = "aes-gcm", feature = "signature", feature = "kdf", feature = "ecdh"))]
	mod seals {
		use super::*;
		use crate::asn1::GcmParameters;
		use crate::crypto::aead::{Aes128GcmOid, Aes256GcmOid};
		use crate::crypto::exchange::Ecdhe;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::k256::Secp256k1;
		use crate::crypto::kdf::HkdfSha3_256;
		use crate::crypto::profiles::{Aes128Wrap, TightbeamProfile};
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::der::asn1::OctetString;
		use crate::oids::{AES_128_WRAP, AES_256_WRAP};
		use crate::random::CryptoRngCore;
		use crate::testing::{SeededStream, TestAttributes};

		/// The `id-signedData` content type, `1.2.840.113549.1.7.2` (RFC 5652
		/// §5.1), a type other than the default.
		const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

		/// The AES-128-GCM algorithm, `2.16.840.1.101.3.4.1.6` (RFC 5084).
		const AES_128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");

		/// The AES-256-GCM algorithm, `2.16.840.1.101.3.4.1.46` (RFC 5084).
		const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

		/// A V1 builder of a sample message, ready for its seal.
		fn builder() -> FrameBuilder<TestMessage> {
			FrameBuilder::<TestMessage>::from(Version::V1)
				.with_message(TestMessage::sample(None))
				.with_id("seal")
				.with_order(1)
		}

		/// The nonce the `GCMParameters` of the seal of `frame` name.
		fn sealed_nonce(frame: &Frame) -> Vec<u8> {
			let envelope = frame.metadata().confidentiality().expect("the frame is sealed");
			let parameters = envelope.auth_encrypted_content_info.content_enc_alg.parameters.as_ref();
			let parameters = parameters.expect("the seal names its nonce");
			let parameters: GcmParameters = parameters.decode_as().expect("the parameters are GCMParameters");
			parameters.aes_nonce.as_bytes().to_vec()
		}

		/// `SeededStream(0)` draws the content key `0x01` repeated 32 times,
		/// then the nonce `0x02` repeated 12 times, so the seal's nonce shows
		/// the builder's rng drew it.
		#[test]
		fn the_builders_rng_draws_the_seal() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = builder().with_rng(SeededStream(0)).with_encryptor(cipher).build()?;
			assert_eq!(sealed_nonce(&frame), [0x02; 12]);
			Ok(())
		}

		/// The rng binds at the build, so it draws the seal when it follows
		/// the encryptor.
		#[test]
		fn an_rng_set_after_the_encryptor_draws_the_seal() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = builder().with_encryptor(cipher).with_rng(SeededStream(0)).build()?;
			assert_eq!(sealed_nonce(&frame), [0x02; 12]);
			Ok(())
		}

		/// The content type the builder names is the type the frame's envelope
		/// declares, in its content type and in its content-type attribute.
		#[test]
		fn a_frame_declares_the_content_type_its_builder_names() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = builder().with_content_oid(ID_SIGNED_DATA).with_encryptor(cipher).build()?;

			let metadata = frame.metadata();
			let envelope = metadata.confidentiality().ok_or(TightBeamError::MissingEncryptionInfo)?;
			let declared = TestAttributes::declared_content_types(envelope);
			assert_eq!(declared, (ID_SIGNED_DATA, ID_SIGNED_DATA));
			Ok(())
		}

		/// A frame of the content type the builder names opens as that type
		/// under the key that sealed it.
		#[test]
		fn a_frame_of_another_content_type_opens_under_its_key() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = builder().with_content_oid(ID_SIGNED_DATA).with_encryptor(cipher).build()?;

			let (_, key) = TestKey::insecure_fixed_cipher();
			let opened = TestFrame::decrypted::<TestMessage>(frame, &key, None)?;
			assert_eq!(opened, TestMessage::sample(None));
			Ok(())
		}

		/// A message of the house profile whose manual checker admits every
		/// AEAD, so the builder's run-time comparison is its one guard.
		#[derive(Clone, Debug, PartialEq, crate::der::Sequence)]
		struct LaxMessage {
			content: OctetString,
		}

		impl Message for LaxMessage {
			const HAS_PROFILE: bool = true;
			type Profile = TightbeamProfile;
		}

		impl<C: AssociatedOid> CheckAeadOid<C> for LaxMessage {}

		/// An encryptor that names AES-128-GCM, outside the house profile.
		struct Aes128Encryptor;

		impl Encryptor<Aes128GcmOid> for Aes128Encryptor {
			fn encrypt_content(
				&self,
				_content: impl Into<Vec<u8>>,
				_content_type: Option<ObjectIdentifier>,
				_rng: Option<&mut dyn CryptoRngCore>,
			) -> Result<AuthEnvelopedData> {
				Err(TightBeamError::MissingEncryptionInfo)
			}
		}

		/// A checker that admits any algorithm leaves the profile to the
		/// builder, which refuses an encryptor outside it.
		#[test]
		fn an_encryptor_outside_the_profile_is_refused() -> Result<()> {
			let message = LaxMessage { content: OctetString::new(b"lax".as_slice())? };
			let built = FrameBuilder::<LaxMessage>::from(Version::V1)
				.with_message(message)
				.with_id("lax")
				.with_order(1)
				.with_encryptor(Aes128Encryptor)
				.build();

			let expected = ReceivedExpectedError { received: AES_128_GCM, expected: AES_256_GCM };
			assert!(matches!(built, Err(TightBeamError::UnexpectedAlgorithm(found)) if found == expected));
			Ok(())
		}

		/// The house profile under AES-128 key wrap.
		#[derive(Debug, Default, Clone, Copy)]
		struct Aes128WrapProfile;

		impl SecurityProfile for Aes128WrapProfile {
			type Digest = Sha3_256;
			type AeadOid = Aes256GcmOid;
			type SignatureAlg = Secp256k1Signature;
			type Kdf = HkdfSha3_256;
			type KeyExchange = Ecdhe<Secp256k1>;
			type KeyWrapOid = Aes128Wrap;
		}

		/// A message of the profile that names AES-128 key wrap.
		#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
		#[beam(profile(Aes128WrapProfile))]
		struct WrappedNote {
			content: OctetString,
		}

		/// The house encryptor wraps the content key under AES-256 key wrap,
		/// outside a profile that names AES-128 key wrap, so the builder
		/// refuses it.
		#[test]
		fn an_encryptor_whose_key_wrap_is_outside_the_profile_is_refused() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let message = WrappedNote { content: OctetString::new(b"wrapped".as_slice())? };
			let built = FrameBuilder::<WrappedNote>::from(Version::V1)
				.with_message(message)
				.with_id("wrapped")
				.with_order(1)
				.with_encryptor(cipher)
				.build();

			let outside = RequirementError::Algorithm((AES_256_WRAP, AES_128_WRAP).into());
			assert!(matches!(built, Err(TightBeamError::Requirement(error)) if error == outside));
			Ok(())
		}

		/// A `KEKRecipientInfo` names its wrap in `keyEncryptionAlgorithm`, so
		/// a receiver refuses a frame sealed under AES-256 key wrap as a
		/// carrier of a type whose profile names AES-128 key wrap.
		#[test]
		fn a_receiver_refuses_a_kek_recipient_whose_wrap_is_outside_the_profile() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let frame = builder().with_encryptor(cipher).build()?;

			let outside = RequirementError::Algorithm((AES_256_WRAP, AES_128_WRAP).into());
			assert_eq!(frame.validate_for::<WrappedNote>(), Err(outside));
			Ok(())
		}

		/// A `KEMRecipientInfo` names its wrap in `wrap`, so a receiver
		/// refuses a frame sealed to a KEM recipient under AES-256 key wrap as
		/// a carrier of a type whose profile names AES-128 key wrap.
		#[cfg(feature = "hpke")]
		#[test]
		fn a_receiver_refuses_a_kem_recipient_whose_wrap_is_outside_the_profile() -> Result<()> {
			use crate::crypto::cms::KemRecipient;
			use crate::crypto::hpke::HpkeEncryptor;
			use crate::crypto::key::{KeyBackend, Secp256k1KeyProvider};
			use crate::crypto::profiles::DefaultCryptoProvider;

			let backend = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
			let recipient = KemRecipient::bare(backend.to_public_key_bytes()?)?;
			let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
			let frame = builder().with_encryptor(encryptor).build()?;

			let outside = RequirementError::Algorithm((AES_256_WRAP, AES_128_WRAP).into());
			assert_eq!(frame.validate_for::<WrappedNote>(), Err(outside));
			Ok(())
		}
	}

	#[cfg(all(feature = "zstd", any(feature = "transport-cms", feature = "transport-hpke")))]
	mod interop {
		use super::*;
		use crate::crypto::cms::KemRecipient;
		use crate::crypto::hpke::HpkeEncryptor;
		use crate::crypto::key::{KeyBackend, Secp256k1KeyProvider};
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::oids::{AUTH_ENVELOPED_DATA, COMPRESSION_CONTENT};
		use crate::transport::handshake::tests::{content_info, write_interop_samples};

		/// The `ContentInfo` of the envelope of `frame`, a compressed and
		/// sealed frame, and of its `CompressedData`.
		fn samples_of(frame: &Frame) -> [(&'static str, Vec<u8>); 2] {
			let envelope = frame.metadata().confidentiality().expect("the frame is sealed");
			let compressed = frame.metadata().compactness().expect("the frame is compressed");
			[
				("frame-kem", content_info(AUTH_ENVELOPED_DATA, envelope)),
				("compressed-data", content_info(COMPRESSION_CONTENT, compressed)),
			]
		}

		/// Write the envelope of a frame sealed to a bare KEM recipient, and
		/// the `CompressedData` of its body, when the run sets
		/// `TIGHTBEAM_CMS_SAMPLES`. `scripts/cms-interop.sh` parses both with
		/// OpenSSL and checks that the `CompressedData` declares `id-data`.
		#[test]
		fn the_emitted_structures_write_their_interop_samples() -> Result<()> {
			let backend = Secp256k1KeyProvider::from(TestKey::insecure_fixed_signing());
			let recipient = KemRecipient::bare(backend.to_public_key_bytes()?)?;
			let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
			let frame = FrameBuilder::<TestMessage>::from(Version::V1)
				.with_message(TestMessage::sample(None))
				.with_id("interop")
				.with_order(1696521600)
				.with_compression(ZstdCompression::default())
				.with_encryptor(encryptor)
				.build()?;

			write_interop_samples(&samples_of(&frame), &[], &[])?;
			Ok(())
		}
	}

	mod validation {
		use super::*;
		use crate::crypto::aead::Aes256GcmOid;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::key::Aes256GcmKeyProvider;
		use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
		use crate::testing::{TestIdentity, TestKey};
		use crate::Version;

		// Run the shared assertions after the struct definition.
		macro_rules! run_tests {
			($name:expr, $confidential:expr, $nonrepudiable:expr, $message_integrity:expr, $frame_integrity:expr, $min_version:expr, $signing_key:expr) => {
				let message = TestMsg { content: format!("test {}", $name) };

				// Test 1: Verify that the constants match the derive macro
				// attributes.
				assert_eq!(TestMsg::MUST_BE_CONFIDENTIAL, $confidential);
				assert_eq!(TestMsg::MUST_BE_NON_REPUDIABLE, $nonrepudiable);
				assert_eq!(TestMsg::MUST_HAVE_MESSAGE_INTEGRITY, $message_integrity);
				assert_eq!(TestMsg::MUST_HAVE_FRAME_INTEGRITY, $frame_integrity);
				assert_eq!(TestMsg::MIN_VERSION, $min_version);

				// Test 2: Verify the frame composition.
				let result = compose_frame(
					$name,
					message.clone(),
					TestKey::insecure_fixed_cipher().1,
					$signing_key.clone(),
					$confidential,
					$nonrepudiable,
					$message_integrity,
					$frame_integrity,
				);
				let frame = result?;

				// Test 3: Verify the README "Security Requirement Semantics".
				// Each MUST flag requires the matching frame field.

				// MUST_BE_NON_REPUDIABLE=true requires the nonrepudiation
				// field.
				assert_eq!(frame.nonrepudiation().is_some(), $nonrepudiable);
				// MUST_BE_CONFIDENTIAL=true requires the confidentiality field.
				assert_eq!(frame.metadata().confidentiality().is_some(), $confidential);
				// MUST_HAVE_MESSAGE_INTEGRITY=true requires the metadata
				// integrity field.
				assert_eq!(frame.metadata().integrity().is_some(), $message_integrity);
				// MUST_HAVE_FRAME_INTEGRITY=true requires the frame integrity
				// field.
				assert_eq!(frame.integrity().is_some(), $frame_integrity);

				// Test 4: Verify the version enforcement.
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
			cipher: Aes256GcmKeyProvider,
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
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
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
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					message_integrity<Sha3_256>: []
				},
				(false, true, false, _) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key)
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
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					message_integrity<Sha3_256>: []
				},
				(true, true, false, true) => compose! {
					V2: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					frame_integrity: type Sha3_256
				},
				(true, true, false, false) => compose! {
					V1: id: test_name, order: 1u64, message: message.clone(),
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key)
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
					let signing_key = TestKey::insecure_fixed_signing();

					test_msg_struct!($confidential, $nonrepudiable, $message_integrity, $frame_integrity, $version);
					run_tests!(
						$name,
						$confidential,
						$nonrepudiable,
						$message_integrity,
						$frame_integrity,
						Version::$version,
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

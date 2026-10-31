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
	use crate::core::RequirementError;
	use crate::test_builder;
	use crate::testing::{TestFrame, TestIdentity, TestKey, TestMessage, TestResult};
	use crate::Beamable;

	#[cfg(feature = "zstd")]
	use crate::compress::ZstdCompression;
	#[cfg(feature = "sha3")]
	use crate::crypto::hash::Sha3_256;

	use super::*;

	/// Returns a builder of `version` that holds [`TestMessage::sample`] under
	/// the id `sample` at [`TestFrame::ORDER`].
	fn sample_builder(version: Version) -> FrameBuilder<TestMessage> {
		let builder = FrameBuilder::<TestMessage>::from(version).with_message(TestMessage::sample(None));
		builder.with_id("sample").with_order(TestFrame::ORDER)
	}

	/// A frame built without an order takes the [`UnixMillis::now`] reading in
	/// seconds, so its order agrees with every other clock value.
	#[cfg(host_clock)]
	#[test]
	fn an_omitted_order_defaults_to_the_clocks_seconds() -> TestResult {
		let before = Duration::from_millis(UnixMillis::now().get()).as_secs();
		let frame = FrameBuilder::<TestMessage>::from(Version::V0)
			.with_message(TestMessage::sample(None))
			.with_id("default-order")
			.build()?;

		let after = Duration::from_millis(UnixMillis::now().get()).as_secs();
		assert!((before..=after).contains(&frame.metadata().order()));
		Ok(())
	}

	// A V0 build carries the version and the id its builder names.
	#[cfg(feature = "sha3")]
	test_builder! {
		name: a_v0_build_carries_its_version_and_id,
		builder_type: FrameBuilder<TestMessage>,
		version: Version::V0,
		message: TestMessage::sample(None),
		setup: |builder, msg| {
			builder.with_message(msg).with_id("v0-build").with_order(TestFrame::ORDER).build()
		},
		assertions: |_msg, result| {
			let frame = result?;
			assert_eq!((frame.version(), frame.metadata().id()), (Version::V0, b"v0-build".as_slice()));
			Ok(())
		}
	}

	/// The commitment runs over the body the frame carries, so a message set
	/// after the hasher is the one it commits to.
	#[test]
	#[cfg(feature = "sha3")]
	fn a_frame_commits_to_the_body_it_carries() -> TestResult {
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

	/// A build with no message is refused for its missing body.
	#[test]
	#[cfg(feature = "sha3")]
	fn a_build_without_a_message_is_refused() {
		let builder = FrameBuilder::<TestMessage>::from(Version::V0).with_id("no-message");
		let builder = builder.with_order(TestFrame::ORDER).with_message_hasher::<Sha3_256>([]);

		let result = builder.build();
		assert!(matches!(result, Err(TightBeamError::InvalidBody)));
	}

	/// A salt too short to hide the body, which a hash call defers as an
	/// `InvalidSaltLength` error.
	const SHORT_SALT: [u8; 1] = [0x5a];

	/// Whether `error` refuses [`SHORT_SALT`], one octet against the least
	/// salt of 16.
	#[cfg(feature = "sha3")]
	fn refuses_the_short_salt(error: &TightBeamError) -> bool {
		let short = ReceivedExpectedError { received: 1, expected: 16 };
		matches!(error, TightBeamError::InvalidSaltLength(refusal) if *refusal == short)
	}

	/// A single deferred error surfaces bare, outside a one-element `Sequence`.
	#[test]
	#[cfg(feature = "sha3")]
	fn a_single_deferred_error_surfaces_bare() {
		let builder = sample_builder(Version::V0).with_message_hasher::<Sha3_256>(SHORT_SALT);
		let result = builder.build();
		assert!(matches!(result, Err(error) if refuses_the_short_salt(&error)));
	}

	/// Two deferred errors surface together, as one `Sequence` of both.
	#[test]
	#[cfg(feature = "sha3")]
	fn deferred_errors_surface_as_one_sequence() {
		let builder = sample_builder(Version::V0).with_message_hasher::<Sha3_256>(SHORT_SALT);
		let result = builder.with_message_hasher::<Sha3_256>(SHORT_SALT).build();

		let short = refuses_the_short_salt;
		let both_short = |errors: &[TightBeamError]| matches!(errors, [first, second] if short(first) && short(second));
		assert!(matches!(result, Err(TightBeamError::Sequence(errors)) if both_short(errors.as_slice())));
	}

	/// `compose!` builds a frame of the version, the id, the order, and the
	/// message integrity it names. V1 is the first version whose metadata
	/// carries integrity info, and `MetadataBuilder::build` rejects V0 with
	/// `message_integrity`.
	#[test]
	#[cfg(feature = "sha3")]
	fn compose_builds_the_frame_it_names() -> TestResult {
		let message = TestMessage::sample(None);
		let frame = compose! {
			V1:
				id: "test-id",
				order: TestFrame::ORDER,
				message: message,
				message_integrity<Sha3_256>: [] // The salt is empty.
		}?;

		let metadata = frame.metadata();
		let digest = metadata.integrity().map(|integrity| integrity.algorithm.oid);
		let named = (frame.version(), metadata.id(), metadata.order(), digest);
		let expected = (
			Version::V1,
			b"test-id".as_slice(),
			TestFrame::ORDER,
			Some(crate::oids::HASH_SHA3_256),
		);
		assert_eq!(named, expected);
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
			assert!(matches!(
				&refusal,
				TightBeamError::MissingProtection { marker: m, call: c } if *m == marker && *c == call
			));
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

	#[cfg(all(feature = "aes-gcm", feature = "signature", feature = "kdf", feature = "ecdh"))]
	mod seals {
		use crate::asn1::GcmParameters;
		use crate::core::Inflator;
		use crate::crypto::aead::{Aes128GcmOid, Aes256GcmOid};
		use crate::crypto::exchange::Ecdhe;
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::k256::Secp256k1;
		use crate::crypto::kdf::HkdfSha3_256;
		use crate::crypto::profiles::{Aes128Wrap, Aes256Wrap};
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::der::asn1::OctetString;
		use crate::oids::{AES_128_WRAP, AES_256_WRAP};
		use crate::testing::{SeededStream, TestAttributes};

		#[cfg(feature = "zstd")]
		use crate::asn1::admission::fixtures::{elements_of, tlv};
		#[cfg(feature = "zstd")]
		use crate::der::Tag;
		#[cfg(feature = "zstd")]
		use crate::testing::TestDigest;
		#[cfg(feature = "zstd")]
		use crate::MessagePriority;

		use super::*;

		/// The `id-signedData` content type, `1.2.840.113549.1.7.2` (RFC 5652
		/// §5.1), a type other than the default.
		const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

		/// The AES-128-GCM algorithm, `2.16.840.1.101.3.4.1.6` (RFC 5084).
		const AES_128_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.6");

		/// The AES-256-GCM algorithm, `2.16.840.1.101.3.4.1.46` (RFC 5084).
		const AES_256_GCM: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.46");

		/// The refusal of a seal under AES-256 key wrap as a carrier of a type
		/// whose profile names AES-128 key wrap.
		const WRAP_OUTSIDE_THE_PROFILE: RequirementError =
			RequirementError::Algorithm(ReceivedExpectedError { received: AES_256_WRAP, expected: AES_128_WRAP });

		/// The nonce the `GCMParameters` of the seal of `frame` name.
		fn sealed_nonce(frame: &Frame) -> Vec<u8> {
			let envelope = frame.metadata().confidentiality().expect("the frame is sealed");
			let parameters = envelope.auth_encrypted_content_info.content_enc_alg.parameters.as_ref();
			let parameters = parameters.expect("the seal names its nonce");
			let parameters: GcmParameters = parameters.decode_as().expect("the parameters are GCMParameters");
			parameters.aes_nonce.as_bytes().to_vec()
		}

		/// Returns a V1 frame of [`TestMessage::sample`] that declares the
		/// content type `id-signedData`, sealed to
		/// [`TestKey::insecure_fixed_cipher`].
		fn signed_data_frame() -> Frame {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let builder = sample_builder(Version::V1).with_content_oid(ID_SIGNED_DATA);
			let built = builder.with_encryptor(cipher).build();
			built.expect("a V1 frame seals under another content type")
		}

		/// Returns a V1 frame of [`TestMessage::sample`] that zstd compresses
		/// and the fixed keys of [`TestKey`] seal and sign.
		#[cfg(feature = "zstd")]
		fn compressed_v1_frame() -> Frame {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
			sample_builder(Version::V1)
				.with_compression(ZstdCompression::default())
				.with_rng(SeededStream(0))
				.with_encryptor(cipher)
				.with_signer::<Secp256k1Signature, _>(signer)
				.build()
				.expect("a V1 frame carries a compression, a seal, and a signature")
		}

		/// Returns a V2 frame of [`TestMessage::sample`] under the id `full-v2`
		/// that carries each field V2 admits: a commitment to its message, a
		/// frame integrity digest, a compression, a seal, a signature, a
		/// priority, a lifetime, and the [`TestDigest::info`] of a previous
		/// frame.
		#[cfg(feature = "zstd")]
		fn full_v2_frame() -> Frame {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signer = TestIdentity::certified(TestKey::insecure_fixed_signing());
			sample_builder(Version::V2)
				.with_id("full-v2")
				.with_message_hasher::<Sha3_256>([])
				.with_witness_hasher::<Sha3_256>()
				.with_compression(ZstdCompression::default())
				.with_rng(SeededStream(0))
				.with_encryptor(cipher)
				.with_signer::<Secp256k1Signature, _>(signer)
				.with_priority(MessagePriority::LowLatency)
				.with_lifetime(3600)
				.with_previous_hash(TestDigest::info())
				// The matrix requires V3 or later, so this V2 frame omits it.
				.build()
				.expect("a V2 frame carries each field it admits")
		}

		/// Returns the SEQUENCE of the version and the metadata of `frame`,
		/// which are the first two elements of its DER.
		#[cfg(feature = "zstd")]
		fn wire_envelope(frame: &Frame) -> Vec<u8> {
			let der = crate::der::Encode::to_der(frame).expect("the frame encodes");
			let envelope: Vec<u8> = elements_of(der).into_iter().take(2).flatten().collect();
			tlv(Tag::Sequence, &envelope)
		}

		// `SeededStream(0)` draws the content key `0x01` repeated 32 times,
		// then the nonce `0x02` repeated 12 times, so the nonce of the seal
		// shows that the builder's rng drew it. The rng binds at the build, so
		// it draws the seal on either side of the encryptor. Each case is a
		// builder with its rng and its encryptor in one order.
		crate::tb_cases! {
			fn the_builders_rng_draws_the_seal(builder: FrameBuilder<TestMessage>) -> TestResult {
				let frame = builder.build()?;

				assert_eq!(sealed_nonce(&frame), [0x02; 12]);
				Ok(())
			}
			cases {
				rng_before_the_encryptor => sample_builder(Version::V1)
					.with_rng(SeededStream(0))
					.with_encryptor(TestKey::insecure_fixed_cipher().1),
				rng_after_the_encryptor => sample_builder(Version::V1)
					.with_encryptor(TestKey::insecure_fixed_cipher().1)
					.with_rng(SeededStream(0)),
			}
		}

		/// The content type the builder names is the type the frame's envelope
		/// declares, in its content type and in its content-type attribute.
		#[test]
		fn a_frame_declares_the_content_type_its_builder_names() {
			let frame = signed_data_frame();

			let envelope = frame.metadata().confidentiality();
			let declared = envelope.map(TestAttributes::declared_content_types);
			assert_eq!(declared, Some((ID_SIGNED_DATA, ID_SIGNED_DATA)));
		}

		// A seal carries its ciphertext in place of the body, so the body of
		// a sealed frame decodes as no message. Each case is a sealed frame.
		crate::tb_cases! {
			fn a_sealed_frame_hides_its_message(frame: Frame) {
				let decoded: Result<TestMessage> = crate::decode(frame.message());
				assert!(matches!(decoded, Err(TightBeamError::SerializationError(_))));
			}
			cases {
				signed_v1 => TestFrame::sealed_signed(Version::V1, "signed-v1"),
				#[cfg(feature = "zstd")]
				compressed_v1 => compressed_v1_frame(),
				#[cfg(feature = "zstd")]
				full_v2 => full_v2_frame(),
			}
		}

		// Each case is a sealed frame beside the inflator of its body. The
		// frame opens to the sample message under the key that sealed it.
		crate::tb_cases! {
			fn a_sealed_frame_opens_to_its_message((frame, inflator): (Frame, Option<&(dyn Inflator + Sync)>))
				-> TestResult
			{
				let (_, cipher) = TestKey::insecure_fixed_cipher();
				let opened = TestFrame::decrypted::<TestMessage>(frame, &cipher, inflator)?;
				assert_eq!(opened, TestMessage::sample(None));
				Ok(())
			}
			cases {
				/// A frame of the content type the builder names opens as that
				/// type.
				another_content_type => (signed_data_frame(), None),
				signed_v1 => (TestFrame::sealed_signed(Version::V1, "signed-v1"), None),
				/// The open also inflates a compressed body.
				#[cfg(feature = "zstd")]
				compressed_v1 => (compressed_v1_frame(), Some(&ZstdCompression::default())),
				#[cfg(feature = "zstd")]
				full_v2 => (full_v2_frame(), Some(&ZstdCompression::default())),
			}
		}

		// Each case is a sealed frame, beside its version and whether it
		// carries a compression, a seal, a signature, and a frame integrity
		// digest, in that order.
		crate::tb_cases! {
			fn a_sealed_frame_carries_the_protections_its_builder_set(
				(frame, expected): (Frame, (Version, bool, bool, bool, bool))
			) {
				let metadata = frame.metadata();

				let (compressed, sealed) = (metadata.compactness().is_some(), metadata.confidentiality().is_some());
				let (signed, digested) = (frame.nonrepudiation().is_some(), frame.integrity().is_some());
				assert_eq!((frame.version(), compressed, sealed, signed, digested), expected);
			}
			cases {
				signed_v1 => (
					TestFrame::sealed_signed(Version::V1, "signed-v1"),
					(Version::V1, false, true, true, false),
				),
				#[cfg(feature = "zstd")]
				compressed_v1 => (compressed_v1_frame(), (Version::V1, true, true, true, false)),
				#[cfg(feature = "zstd")]
				full_v2 => (full_v2_frame(), (Version::V2, true, true, true, true)),
			}
		}

		/// A full V2 frame carries the id, the priority, the lifetime, and the
		/// previous frame its builder set, and no matrix, which V2 forbids.
		#[cfg(feature = "zstd")]
		#[test]
		fn a_full_v2_frame_carries_its_metadata() {
			let frame = full_v2_frame();

			let metadata = frame.metadata();
			let carried = (
				metadata.id(),
				metadata.priority(),
				metadata.lifetime(),
				metadata.previous_frame(),
				metadata.matrix(),
			);

			let previous = TestDigest::info();
			let expected = (
				b"full-v2".as_slice(),
				Some(MessagePriority::LowLatency),
				Some(3600),
				Some(&previous),
				None,
			);
			assert_eq!(carried, expected);
		}

		/// A full V2 frame commits to the message it seals.
		#[cfg(feature = "zstd")]
		#[test]
		fn a_full_v2_frame_commits_to_its_message() -> TestResult {
			let frame = full_v2_frame();
			let committed = frame.verify_commitment_of::<Sha3_256, _>(&TestMessage::sample(None), [])?;
			assert!(committed);
			Ok(())
		}

		/// The frame integrity digest of a full V2 frame is SHA3-256 over its
		/// version and its metadata, as its own DER carries them.
		#[cfg(feature = "zstd")]
		#[test]
		fn a_full_v2_frame_digests_its_envelope() {
			let frame = full_v2_frame();
			let digest = frame.integrity().map(|integrity| integrity.digest.as_bytes());

			// The oracle hashes the version and the metadata as a receiver
			// reads them off the wire.
			let oracle = Sha3_256::digest(wire_envelope(&frame));
			assert_eq!(digest, Some(oracle.as_slice()));
		}

		/// A full V2 frame verifies under the certificate of the key that
		/// signed it.
		#[cfg(feature = "zstd")]
		#[test]
		fn a_full_v2_frame_verifies_under_its_signer() -> TestResult {
			use crate::crypto::profiles::DefaultCryptoProvider;
			use crate::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
			use crate::testing::TestCertificate;

			let frame = full_v2_frame();
			let certificate = TestCertificate::self_signed(&TestKey::insecure_fixed_signing());
			let purpose = KeyPurposes::HOUSE.signer;
			let signer = PeerCertificate::<Signing<DefaultCryptoProvider>>::parse(certificate, purpose)?;

			frame.verify(&signer)?;
			Ok(())
		}

		/// The house profile under AES-128-GCM, so the house encryptor of
		/// AES-256-GCM seals outside it.
		#[derive(Debug, Default, Clone, Copy)]
		struct Aes128GcmProfile;

		impl SecurityProfile for Aes128GcmProfile {
			type Digest = Sha3_256;
			type AeadOid = Aes128GcmOid;
			type SignatureAlg = Secp256k1Signature;
			type Kdf = HkdfSha3_256;
			type KeyExchange = Ecdhe<Secp256k1>;
			type KeyWrapOid = Aes256Wrap;
		}

		/// A message of [`Aes128GcmProfile`] whose manual checker admits every
		/// AEAD, so the builder's run-time comparison is its one guard.
		#[derive(Clone, Debug, PartialEq, crate::der::Sequence)]
		struct LaxMessage {
			content: OctetString,
		}

		impl Message for LaxMessage {
			const HAS_PROFILE: bool = true;
			type Profile = Aes128GcmProfile;
		}

		impl<C: AssociatedOid> CheckAeadOid<C> for LaxMessage {}

		/// A checker that admits any algorithm leaves the profile to the
		/// builder, which refuses an encryptor outside it.
		#[test]
		fn an_encryptor_outside_the_profile_is_refused() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let message = LaxMessage { content: OctetString::new(b"lax".as_slice())? };
			let built = FrameBuilder::<LaxMessage>::from(Version::V1)
				.with_message(message)
				.with_id("lax")
				.with_order(1)
				.with_encryptor(cipher)
				.build();

			let expected = ReceivedExpectedError { received: AES_256_GCM, expected: AES_128_GCM };
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
		fn an_encryptor_whose_key_wrap_is_outside_the_profile_is_refused() -> TestResult {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let message = WrappedNote { content: OctetString::new(b"wrapped".as_slice())? };
			let built = FrameBuilder::<WrappedNote>::from(Version::V1)
				.with_message(message)
				.with_id("wrapped")
				.with_order(1)
				.with_encryptor(cipher)
				.build();

			assert!(matches!(built, Err(TightBeamError::Requirement(error)) if error == WRAP_OUTSIDE_THE_PROFILE));
			Ok(())
		}

		/// A `KEKRecipientInfo` names its wrap in `keyEncryptionAlgorithm`, so
		/// a receiver refuses a frame sealed under AES-256 key wrap as a
		/// carrier of a type whose profile names AES-128 key wrap.
		#[test]
		fn a_receiver_refuses_a_kek_recipient_whose_wrap_is_outside_the_profile() {
			let frame = TestFrame::sealed("sealed");
			let validated = frame.validate_for::<WrappedNote>();
			assert_eq!(validated, Err(WRAP_OUTSIDE_THE_PROFILE));
		}

		/// A `KEMRecipientInfo` names its wrap in `wrap`, so a receiver
		/// refuses a frame sealed to a KEM recipient under AES-256 key wrap as
		/// a carrier of a type whose profile names AES-128 key wrap.
		#[cfg(feature = "hpke")]
		#[test]
		fn a_receiver_refuses_a_kem_recipient_whose_wrap_is_outside_the_profile() -> TestResult {
			use crate::crypto::hpke::HpkeEncryptor;
			use crate::crypto::profiles::DefaultCryptoProvider;
			use crate::testing::fixtures::TestAgreement;

			let recipient = TestAgreement::recipient(&TestKey::insecure_fixed_signing());
			let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
			let builder = sample_builder(Version::V1).with_rng(SeededStream(0));
			let frame = builder.with_encryptor(encryptor).build()?;

			let validated = frame.validate_for::<WrappedNote>();
			assert_eq!(validated, Err(WRAP_OUTSIDE_THE_PROFILE));
			Ok(())
		}
	}

	#[cfg(all(feature = "zstd", any(feature = "transport-cms", feature = "transport-hpke")))]
	mod interop {
		use crate::crypto::hpke::HpkeEncryptor;
		use crate::crypto::profiles::DefaultCryptoProvider;
		use crate::oids::{AUTH_ENVELOPED_DATA, COMPRESSION_CONTENT};
		use crate::testing::fixtures::{write_interop_samples, TestAgreement, TestEnvelope};
		use crate::testing::SeededStream;

		use super::*;

		/// The `ContentInfo` of the envelope of `frame`, a compressed and
		/// sealed frame, and of its `CompressedData`.
		fn samples_of(frame: &Frame) -> [(&'static str, Vec<u8>); 2] {
			let envelope = frame.metadata().confidentiality().expect("the frame is sealed");
			let compressed = frame.metadata().compactness().expect("the frame is compressed");
			[
				("frame-kem", TestEnvelope::content_info(AUTH_ENVELOPED_DATA, envelope)),
				("compressed-data", TestEnvelope::content_info(COMPRESSION_CONTENT, compressed)),
			]
		}

		/// Write the envelope of a frame sealed to a bare KEM recipient, and
		/// the `CompressedData` of its body, when the run sets
		/// `TIGHTBEAM_CMS_SAMPLES`. `scripts/cms-interop.sh` parses both with
		/// OpenSSL and checks that the `CompressedData` declares `id-data`.
		#[test]
		fn the_emitted_structures_write_their_interop_samples() -> TestResult {
			let recipient = TestAgreement::recipient(&TestKey::insecure_fixed_signing());
			let encryptor = HpkeEncryptor::<DefaultCryptoProvider>::new(recipient);
			let frame = sample_builder(Version::V1)
				.with_id("interop")
				.with_compression(ZstdCompression::default())
				.with_rng(SeededStream(0))
				.with_encryptor(encryptor)
				.build()?;

			write_interop_samples(&samples_of(&frame), &[], &[]);
			Ok(())
		}
	}

	mod validation {
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::testing::fixtures::RecentNote;

		use super::*;

		/// The requirement constants of a message type: whether it requires a
		/// seal, a signature, a message integrity commitment, and a frame
		/// integrity digest, then its minimum version.
		type Requirements = (bool, bool, bool, bool, Version);

		/// Whether a frame carries a seal, a signature, a message integrity
		/// commitment, and a frame integrity digest, in that order.
		type Protections = (bool, bool, bool, bool);

		/// A note whose type requires no protection.
		#[derive(Beamable, Clone, Debug, PartialEq, crate::der::Sequence)]
		#[beam(min_version = "V0")]
		struct BasicNote {
			content: String,
		}

		/// A note whose type requires a confidential frame of V1 or later.
		#[derive(Beamable, Clone, Debug, PartialEq, crate::der::Sequence)]
		#[beam(confidential, min_version = "V1")]
		struct ConfidentialV1Note {
			content: String,
		}

		/// A note whose type requires a non-repudiable frame of V1 or later.
		#[derive(Beamable, Clone, Debug, PartialEq, crate::der::Sequence)]
		#[beam(nonrepudiable, min_version = "V1")]
		struct NonrepudiableV1Note {
			content: String,
		}

		/// A note whose type requires each protection in a frame of V2 or
		/// later.
		#[derive(Beamable, Clone, Debug, PartialEq, crate::der::Sequence)]
		#[beam(
			confidential,
			nonrepudiable,
			message_integrity,
			frame_integrity,
			min_version = "V2"
		)]
		struct FullV2Note {
			content: String,
		}

		/// Returns the requirement constants of `T`.
		fn requirements_of<T: Message>() -> Requirements {
			(
				T::MUST_BE_CONFIDENTIAL,
				T::MUST_BE_NON_REPUDIABLE,
				T::MUST_HAVE_MESSAGE_INTEGRITY,
				T::MUST_HAVE_FRAME_INTEGRITY,
				T::MIN_VERSION,
			)
		}

		/// Returns the protections that `frame` carries.
		fn protections_of(frame: &Frame) -> Protections {
			let metadata = frame.metadata();
			let sealed = metadata.confidentiality().is_some();
			let committed = metadata.integrity().is_some();
			(sealed, frame.nonrepudiation().is_some(), committed, frame.integrity().is_some())
		}

		// The derive sets each constant of a type from its `#[beam]`
		// attributes. Each case is a type beside the constants it declares.
		crate::tb_cases! {
			fn the_derive_sets_the_requirement_constants(
				(requirements, expected): (fn() -> Requirements, Requirements)
			) {
				assert_eq!(requirements(), expected);
			}
			cases {
				basic => (requirements_of::<BasicNote>, (false, false, false, false, Version::V0)),
				confidential => (requirements_of::<ConfidentialV1Note>, (true, false, false, false, Version::V1)),
				nonrepudiable => (requirements_of::<NonrepudiableV1Note>, (false, true, false, false, Version::V1)),
				full => (requirements_of::<FullV2Note>, (true, true, true, true, Version::V2)),
			}
		}

		// A frame composed with the protections its type requires carries
		// each of them, as the README section "Security Requirement Semantics"
		// states. Each case composes a frame of one type, beside the
		// protections the frame carries.
		crate::tb_cases! {
			fn a_composed_frame_carries_the_protections_its_type_requires(
				(compose, expected): (fn() -> Result<Frame>, Protections)
			) -> TestResult {
				let frame = compose()?;

				assert_eq!(protections_of(&frame), expected);
				Ok(())
			}
			cases {
				basic => (
					|| compose! { V0: id: "basic", order: 1u64, message: BasicNote { content: "basic".into() } },
					(false, false, false, false),
				),
				confidential => (
					|| compose! {
						V1: id: "confidential", order: 1u64,
						message: ConfidentialV1Note { content: "confidential".into() },
						confidentiality: TestKey::insecure_fixed_cipher().1
					},
					(true, false, false, false),
				),
				nonrepudiable => (
					|| compose! {
						V1: id: "nonrepudiable", order: 1u64,
						message: NonrepudiableV1Note { content: "nonrepudiable".into() },
						nonrepudiation<Secp256k1Signature, _>:
							TestIdentity::certified(TestKey::insecure_fixed_signing())
					},
					(false, true, false, false),
				),
				full => (
					|| compose! {
						V2: id: "full", order: 1u64,
						message: FullV2Note { content: "full".into() },
						confidentiality: TestKey::insecure_fixed_cipher().1,
						nonrepudiation<Secp256k1Signature, _>:
							TestIdentity::certified(TestKey::insecure_fixed_signing()),
						message_integrity<Sha3_256>: [],
						frame_integrity: type Sha3_256
					},
					(true, true, true, true),
				),
			}
		}

		// A build below the minimum version of its type refuses with the error
		// that every typed decode of a frame of the type returns. Each case
		// composes a frame of one type below its minimum version, beside the
		// refusal.
		crate::tb_cases! {
			fn a_build_below_the_minimum_version_of_its_type_is_refused(
				(compose, below): (fn() -> Result<Frame>, RequirementError)
			) {
				let refused = compose();
				assert!(matches!(refused, Err(TightBeamError::Requirement(error)) if error == below));
			}
			cases {
				confidential_at_v0 => (
					|| compose! {
						V0: id: "confidential", order: 1u64,
						message: ConfidentialV1Note { content: "confidential".into() }
					},
					RequirementError::Version((Version::V0, Version::V1).into()),
				),
				nonrepudiable_at_v0 => (
					|| compose! {
						V0: id: "nonrepudiable", order: 1u64,
						message: NonrepudiableV1Note { content: "nonrepudiable".into() }
					},
					RequirementError::Version((Version::V0, Version::V1).into()),
				),
				full_at_v0 => (
					|| compose! { V0: id: "full", order: 1u64, message: FullV2Note { content: "full".into() } },
					RequirementError::Version((Version::V0, Version::V2).into()),
				),
				recent_at_v1 => (
					|| compose! { V1: id: "recent", order: 1u64, message: RecentNote { content: "recent".into() } },
					RequirementError::Version((Version::V1, Version::V2).into()),
				),
			}
		}
	}
}

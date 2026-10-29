#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::asn1::admission::DerAdmission;
use crate::der::asn1::{Null, ObjectIdentifier};
use crate::der::{Any, EncodeValue, Tagged};
use crate::error::{ReceivedExpectedError, Result};
use crate::frame::BodyTransform;
use crate::{Errorizable, Frame, Metadata, TightBeamError, Version};

#[cfg(feature = "aead")]
use crate::asn1::KemRecipientInfoRef;
#[cfg(feature = "aead")]
use crate::cms::enveloped_data::RecipientInfo;
#[cfg(feature = "crypto")]
use crate::crypto::profiles::SecurityProfile;
#[cfg(feature = "signature")]
use crate::crypto::sign::SignatureAlgorithmIdentifier;
#[cfg(any(feature = "digest", feature = "aead"))]
use crate::der::oid::AssociatedOid;
#[cfg(feature = "aead")]
use crate::oids::ORI_KEM;
#[cfg(feature = "aead")]
use crate::spki::AlgorithmIdentifierRef;

/// Decompresses message bodies.
///
/// The trait is present under every feature combination, so downstream code
/// compiles alike under each.
///
/// A receiver inflates a body only when the `CompressedData` that describes
/// it names [`Self::algorithm_oid`], with parameters that
/// [`Self::admits_parameters`] admits (README §5.7.2).
///
/// # Examples
///
/// ```
/// use tightbeam::core::Inflator;
/// use tightbeam::der::asn1::{Null, ObjectIdentifier};
/// use tightbeam::der::Any;
///
/// /// An inflator of a body that travels as it is.
/// struct Identity;
///
/// impl Inflator for Identity {
///     fn algorithm_oid(&self) -> ObjectIdentifier {
///         ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1")
///     }
///
///     fn decompress(&self, data: &[u8]) -> tightbeam::error::Result<Vec<u8>> {
///         Ok(data.to_vec())
///     }
/// }
///
/// // The provided rule admits the parameters omitted or as a NULL.
/// let null = Any::encode_from(&Null)?;
/// assert!(Identity.admits_parameters(None));
/// assert!(Identity.admits_parameters(Some(&null)));
/// assert!(!Identity.admits_parameters(Some(&Any::encode_from(&3i32)?)));
/// # Ok::<(), tightbeam::der::Error>(())
/// ```
pub trait Inflator {
	/// The compression algorithm this inflator reverses, as the OID that a
	/// `CompressedData` names in its `compressionAlgorithm`.
	fn algorithm_oid(&self) -> ObjectIdentifier;

	/// Whether `parameters`, the parameters of a `compressionAlgorithm` that
	/// names [`Self::algorithm_oid`], take a form this algorithm defines, such
	/// as a level inside its valid range.
	///
	/// The provided method admits the form of an algorithm that defines no
	/// parameters: the field omitted, or a `NULL` (RFC 3274 §2).
	fn admits_parameters(&self, parameters: Option<&Any>) -> bool {
		parameters.is_none_or(|parameters| parameters.decode_as::<Null>().is_ok())
	}

	/// Decompress `data`, returning the decompressed bytes.
	///
	/// # Errors
	///
	/// Returns an error when the underlying codec rejects the input.
	fn decompress(&self, data: &[u8]) -> Result<Vec<u8>>;
}

/// A marker trait for types that can be used as the body of a TightBeam
/// message.
pub trait Message:
	EncodeValue + Tagged + for<'a> crate::der::Decode<'a> + Clone + PartialEq + core::fmt::Debug + Sized + Send + Sync
{
	/// Minimum version required to send this message type.
	const MIN_VERSION: Version = Version::V0;
	/// Whether this message type requires non-repudiation (signing).
	const MUST_BE_NON_REPUDIABLE: bool = false;
	/// Whether this message type requires confidentiality (encryption).
	const MUST_BE_CONFIDENTIAL: bool = false;
	/// Whether this message type requires compression.
	const MUST_BE_COMPRESSED: bool = false;
	/// Whether this message type requires prioritization.
	const MUST_BE_PRIORITIZED: bool = false;
	/// Whether this message type requires message integrity (hashing).
	const MUST_HAVE_MESSAGE_INTEGRITY: bool = false;
	/// Whether this message type requires frame integrity (hashing).
	const MUST_HAVE_FRAME_INTEGRITY: bool = false;

	/// Whether this message type has a custom security profile that
	/// constrains algorithms.
	const HAS_PROFILE: bool = false;

	/// The security profile that constrains the algorithms of this message
	/// type when [`Self::HAS_PROFILE`] is `true`.
	///
	/// `#[derive(Beamable)]` sets it to the type that `profile(Type)` names, or
	/// to [`TightbeamProfile`] for a type that names none. A hand-written impl
	/// names it.
	///
	/// [`TightbeamProfile`]: crate::crypto::profiles::TightbeamProfile
	#[cfg(feature = "crypto")]
	type Profile: SecurityProfile;
}

/// A requirement that a `MUST_*` constant of a [`Message`] sets: a protection
/// that every Frame of the message type carries.
///
/// The variants are in the order that the Frame builder checks them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Requirement {
	/// `MUST_BE_CONFIDENTIAL`: the Frame carries `Metadata.confidentiality`.
	Confidentiality,
	/// `MUST_BE_NON_REPUDIABLE`: the Frame carries `Frame.nonrepudiation`.
	NonRepudiation,
	/// `MUST_BE_COMPRESSED`: the Frame carries `Metadata.compactness`.
	Compression,
	/// `MUST_HAVE_MESSAGE_INTEGRITY`: the Frame carries `Metadata.integrity`.
	MessageIntegrity,
	/// `MUST_HAVE_FRAME_INTEGRITY`: the Frame carries `Frame.integrity`.
	FrameIntegrity,
	/// `MUST_BE_PRIORITIZED`: the Frame carries `Metadata.priority`.
	Priority,
}

impl Requirement {
	/// Every requirement, in the order that the Frame builder checks them.
	pub(crate) const ALL: [Self; 6] = [
		Self::Confidentiality,
		Self::NonRepudiation,
		Self::Compression,
		Self::MessageIntegrity,
		Self::FrameIntegrity,
		Self::Priority,
	];

	/// The name of the [`Message`] constant that sets this requirement.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::core::Requirement;
	///
	/// assert_eq!(Requirement::Confidentiality.marker(), "MUST_BE_CONFIDENTIAL");
	/// ```
	#[must_use]
	pub const fn marker(self) -> &'static str {
		match self {
			Self::Confidentiality => "MUST_BE_CONFIDENTIAL",
			Self::NonRepudiation => "MUST_BE_NON_REPUDIABLE",
			Self::Compression => "MUST_BE_COMPRESSED",
			Self::MessageIntegrity => "MUST_HAVE_MESSAGE_INTEGRITY",
			Self::FrameIntegrity => "MUST_HAVE_FRAME_INTEGRITY",
			Self::Priority => "MUST_BE_PRIORITIZED",
		}
	}

	/// The schema name of the Frame field that meets this requirement.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::core::Requirement;
	///
	/// assert_eq!(Requirement::FrameIntegrity.field(), "Frame.integrity");
	/// ```
	#[must_use]
	pub const fn field(self) -> &'static str {
		match self {
			Self::Confidentiality => "Metadata.confidentiality",
			Self::NonRepudiation => "Frame.nonrepudiation",
			Self::Compression => "Metadata.compactness",
			Self::MessageIntegrity => "Metadata.integrity",
			Self::FrameIntegrity => "Frame.integrity",
			Self::Priority => "Metadata.priority",
		}
	}

	/// The Frame builder call that meets this requirement, which a refused
	/// build names.
	#[cfg(feature = "builder")]
	pub(crate) const fn builder_call(self) -> &'static str {
		match self {
			Self::Confidentiality => "with_encryptor",
			Self::NonRepudiation => "with_signer",
			Self::Compression => "with_compression",
			Self::MessageIntegrity => "with_message_hasher",
			Self::FrameIntegrity => "with_witness_hasher",
			Self::Priority => "with_priority",
		}
	}

	/// Whether the message type `T` sets this requirement.
	pub(crate) const fn is_set_by<T: Message>(self) -> bool {
		match self {
			Self::Confidentiality => T::MUST_BE_CONFIDENTIAL,
			Self::NonRepudiation => T::MUST_BE_NON_REPUDIABLE,
			Self::Compression => T::MUST_BE_COMPRESSED,
			Self::MessageIntegrity => T::MUST_HAVE_MESSAGE_INTEGRITY,
			Self::FrameIntegrity => T::MUST_HAVE_FRAME_INTEGRITY,
			Self::Priority => T::MUST_BE_PRIORITIZED,
		}
	}
}

impl core::fmt::Display for Requirement {
	/// The marker, and the field that meets it.
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		write!(f, "{} requires {}", self.marker(), self.field())
	}
}

/// A requirement of a message type that a Frame fails, as
/// [`Frame::validate_for`] finds it.
///
/// # Examples
///
/// ```
/// use tightbeam::core::{Requirement, RequirementError};
///
/// // The refusal names the marker and the field that the Frame lacks.
/// let refused = RequirementError::Unprotected(Requirement::Confidentiality);
/// let reason = "MUST_BE_CONFIDENTIAL requires Metadata.confidentiality, which the Frame lacks";
/// assert_eq!(refused.to_string(), reason);
/// ```
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum RequirementError {
	/// The Frame version is below the `MIN_VERSION` of the message type.
	#[error("Frame version below the minimum of the message type: {0}")]
	Version(ReceivedExpectedError<Version, Version>),
	/// A `MUST_*` constant of the message type is `true`, and the Frame lacks
	/// the field that meets it.
	#[error("{0}, which the Frame lacks")]
	Unprotected(Requirement),
	/// The message type has a typed profile, and the Frame names an algorithm
	/// other than the one that the profile names.
	#[error("Algorithm outside the profile of the message type: {0}")]
	Algorithm(ReceivedExpectedError<ObjectIdentifier, ObjectIdentifier>),
}

impl Version {
	/// Refuse this version as the version of a Frame of the message type `T`.
	/// A Frame build and every typed decode refuse with it alike.
	///
	/// # Errors
	///
	/// - [`RequirementError::Version`] -- this version is below the `MIN_VERSION` of `T`.
	pub(crate) fn admit_for<T: Message>(self) -> core::result::Result<(), RequirementError> {
		if self < T::MIN_VERSION {
			return Err(RequirementError::Version((self, T::MIN_VERSION).into()));
		}

		Ok(())
	}
}

/// What a Frame carries that a message type can require: its version, the
/// field of each [`Requirement`], and the algorithm of each protection.
///
/// A decrypt or an inflate in place takes protections out of a Frame, so a
/// receiver takes the shape of the Frame as it arrived, before either.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FrameShape {
	/// The protocol version.
	version: Version,
	/// The content-encryption algorithm of `Metadata.confidentiality`.
	confidentiality: Option<ObjectIdentifier>,
	/// The algorithm that each recipient of `Metadata.confidentiality` wraps
	/// the content key under.
	#[cfg(feature = "aead")]
	key_wraps: Vec<ObjectIdentifier>,
	/// The signature algorithm of `Frame.nonrepudiation`.
	nonrepudiation: Option<ObjectIdentifier>,
	/// Whether `Metadata.compactness` is present.
	compressed: bool,
	/// The digest algorithm of `Metadata.integrity`.
	message_integrity: Option<ObjectIdentifier>,
	/// The digest algorithm of `Frame.integrity`.
	frame_integrity: Option<ObjectIdentifier>,
	/// Whether `Metadata.priority` is present.
	prioritized: bool,
}

impl FrameShape {
	/// Refuse a Frame of this shape as a carrier of the message type `T`.
	///
	/// # Errors
	///
	/// - [`RequirementError::Version`] -- the version is below the `MIN_VERSION` of `T`.
	/// - [`RequirementError::Unprotected`] -- `T` sets a requirement whose field the Frame lacks.
	/// - [`RequirementError::Algorithm`] -- `T` has a typed profile, and the
	///   Frame names an algorithm outside it.
	pub(crate) fn admit<T: Message>(&self) -> core::result::Result<(), RequirementError> {
		self.version.admit_for::<T>()?;

		let mut requirements = Requirement::ALL.into_iter();
		let unmet = requirements.find(|requirement| requirement.is_set_by::<T>() && !self.carries(*requirement));
		if let Some(requirement) = unmet {
			return Err(RequirementError::Unprotected(requirement));
		}

		#[cfg(feature = "crypto")]
		if T::HAS_PROFILE {
			self.admit_profile::<T::Profile>()?;
		}

		Ok(())
	}

	/// Decode `body`, the cleartext body of a Frame that arrived in this
	/// shape, as `T`, after this shape meets the requirements of `T`.
	///
	/// It is the typed decode of a received cleartext body, which
	/// `CleartextFrame::decode` of the router and [`Frame::decode_message`]
	/// run, each with its own error type `E`.
	///
	/// # Errors
	///
	/// - The errors of [`FrameShape::admit`].
	/// - A [`der::Error`](crate::der::Error) -- the body is no DER encoding
	///   of `T`, or a SET in it holds its elements out of DER order.
	pub(crate) fn decode<T, E>(&self, body: &[u8]) -> core::result::Result<T, E>
	where
		T: Message,
		E: From<RequirementError> + From<crate::der::Error>,
	{
		self.admit::<T>()?;

		Ok(DerAdmission::SetOrder.decode(body)?)
	}

	/// Whether the Frame carries the field that `requirement` names.
	fn carries(&self, requirement: Requirement) -> bool {
		match requirement {
			Requirement::Confidentiality => self.confidentiality.is_some(),
			Requirement::NonRepudiation => self.nonrepudiation.is_some(),
			Requirement::Compression => self.compressed,
			Requirement::MessageIntegrity => self.message_integrity.is_some(),
			Requirement::FrameIntegrity => self.frame_integrity.is_some(),
			Requirement::Priority => self.prioritized,
		}
	}

	/// Refuse an algorithm of this shape that the profile `P` does not name.
	///
	/// # Errors
	///
	/// - [`RequirementError::Algorithm`] -- a digest, the AEAD, a key wrap, or the signature is outside `P`.
	#[cfg(feature = "crypto")]
	fn admit_profile<P: SecurityProfile>(&self) -> core::result::Result<(), RequirementError> {
		#[cfg(feature = "digest")]
		{
			let digest = <P::Digest as AssociatedOid>::OID;
			profile_names(self.message_integrity, digest)?;
			profile_names(self.frame_integrity, digest)?;
		}

		#[cfg(feature = "aead")]
		{
			profile_names(self.confidentiality, <P::AeadOid as AssociatedOid>::OID)?;
			let wrap = <P::KeyWrapOid as AssociatedOid>::OID;
			let received = self.key_wraps.iter().copied();
			received.map(Some).try_for_each(|received| profile_names(received, wrap))?;
		}

		#[cfg(feature = "signature")]
		{
			let signature = <P::SignatureAlg as SignatureAlgorithmIdentifier>::ALGORITHM_OID;
			profile_names(self.nonrepudiation, signature)?;
		}

		Ok(())
	}
}

impl From<&Frame> for FrameShape {
	fn from(frame: &Frame) -> Self {
		let metadata = frame.metadata();
		let envelope = metadata.confidentiality();
		#[cfg(feature = "aead")]
		let recipients = envelope.into_iter().flat_map(|sealed| sealed.recipient_infos.0.iter());

		Self {
			version: frame.version(),
			confidentiality: envelope.map(|sealed| sealed.auth_encrypted_content_info.content_enc_alg.oid),
			#[cfg(feature = "aead")]
			key_wraps: recipients.map(KeyWrapOf::key_wrap).collect(),
			nonrepudiation: frame.nonrepudiation().map(|signed| signed.signature_algorithm.oid),
			compressed: metadata.compactness().is_some(),
			message_integrity: metadata.integrity().map(|digest| digest.algorithm.oid),
			frame_integrity: frame.integrity().map(|digest| digest.algorithm.oid),
			prioritized: metadata.priority().is_some(),
		}
	}
}

/// Refuse `received` when it is present and other than `expected`, the
/// algorithm that a profile names.
#[cfg(any(feature = "digest", feature = "aead", feature = "signature"))]
fn profile_names(
	received: Option<ObjectIdentifier>,
	expected: ObjectIdentifier,
) -> core::result::Result<(), RequirementError> {
	match received {
		Some(received) if received != expected => Err(RequirementError::Algorithm((received, expected).into())),
		_ => Ok(()),
	}
}

/// The algorithm that a recipient of an envelope wraps the content key under.
///
/// - A `KEKRecipientInfo` names its wrap in `keyEncryptionAlgorithm` (RFC 5652 §6.2.3).
/// - A `KeyAgreeRecipientInfo` names its wrap in the parameters of
///   `keyEncryptionAlgorithm` (RFC 5753 §3.1.1).
/// - A `KEMRecipientInfo` names its wrap in `wrap` (RFC 9629 §3).
/// - Any other recipient names no key wrap, so it gives the algorithm it names
///   in its place: the `keyEncryptionAlgorithm` of a `KeyTransRecipientInfo` or
///   a `PasswordRecipientInfo`, and the `oriType` of another `ori`.
#[cfg(feature = "aead")]
trait KeyWrapOf {
	/// The algorithm that this recipient wraps the content key under.
	fn key_wrap(&self) -> ObjectIdentifier;
}

#[cfg(feature = "aead")]
impl KeyWrapOf for RecipientInfo {
	fn key_wrap(&self) -> ObjectIdentifier {
		match self {
			RecipientInfo::Kekri(kek) => kek.key_enc_alg.oid,
			// A parameter that holds no algorithm identifier names no wrap, so
			// the recipient gives its own algorithm in its place. The read
			// borrows the parameters.
			RecipientInfo::Kari(agreement) => {
				let algorithm = &agreement.key_enc_alg;
				let parameters = algorithm.parameters.as_ref();
				let wrap = parameters.and_then(|parameters| parameters.decode_as::<AlgorithmIdentifierRef<'_>>().ok());
				wrap.map_or(algorithm.oid, |wrap| wrap.oid)
			}
			// A KEM recipient that fails to decode names no wrap, so it gives
			// its `oriType` in its place. The read borrows each field, so it
			// copies no `kemct`.
			RecipientInfo::Ori(other) if other.ori_type == ORI_KEM => {
				let kem = other.ori_value.decode_as::<KemRecipientInfoRef<'_>>();
				kem.map_or(other.ori_type, |kem| kem.wrap.oid)
			}
			RecipientInfo::Ori(other) => other.ori_type,
			RecipientInfo::Ktri(transport) => transport.key_enc_alg.oid,
			RecipientInfo::Pwri(password) => password.key_enc_alg.oid,
		}
	}
}

impl Frame {
	/// Refuse this Frame as a carrier of the message type `T`. A typed decode
	/// calls it on the Frame as it arrived.
	///
	/// - The version is at or above the `MIN_VERSION` of `T`.
	/// - The Frame carries the field of each [`Requirement`] that `T` sets.
	/// - Under a typed profile of `T`, each algorithm that the Frame names is
	///   the one that the profile names: the digest of each integrity field,
	///   the AEAD and the key wrap of each recipient of the envelope, and the
	///   signature.
	///
	/// A decrypt or an inflate in place takes protections out of the Frame,
	/// so a receiver calls this method before either. `CleartextFrame` of the
	/// `router` feature keeps the shape that a Frame arrived in across its
	/// open.
	///
	/// # Errors
	///
	/// - [`RequirementError::Version`] -- the version is below the `MIN_VERSION` of `T`.
	/// - [`RequirementError::Unprotected`] -- `T` sets a requirement whose field the Frame lacks.
	/// - [`RequirementError::Algorithm`] -- `T` has a typed profile, and the
	///   Frame names an algorithm outside it.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::core::RequirementError;
	/// use tightbeam::der::Sequence;
	/// use tightbeam::{compose, Beamable};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     sequence: u64,
	/// }
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// #[beam(min_version = "V2")]
	/// struct RecentPing {
	///     sequence: u64,
	/// }
	///
	/// let frame = compose! { V1: id: "ping", order: 1u64, message: Ping { sequence: 7 } }?;
	/// assert_eq!(frame.validate_for::<Ping>(), Ok(()));
	///
	/// // The same body is no carrier of a type whose minimum is V2.
	/// let refused = frame.validate_for::<RecentPing>();
	/// assert!(matches!(refused, Err(RequirementError::Version(_))));
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn validate_for<T: Message>(&self) -> core::result::Result<(), RequirementError> {
		FrameShape::from(self).admit::<T>()
	}

	/// Decode the body of this Frame, which arrived in cleartext, as `T`,
	/// after the Frame meets the requirements of `T`
	/// ([`Frame::validate_for`]).
	///
	/// - The decode reads the body in place, so a caller that keeps the Frame,
	///   such as to answer it, copies no body.
	/// - Every universal SET in the body MUST hold its elements in DER order
	///   (X.690 § 11.6), which the decode checks before it sorts one (CWE-407).
	///
	/// # Errors
	///
	/// - [`TightBeamError::OpaqueBody`] -- `metadata.confidentiality` or
	///   `metadata.compactness` is set, so the body needs the
	///   [`BodyTransform`] that the error names before a decode.
	/// - [`TightBeamError::Requirement`] -- the Frame fails a requirement of `T`.
	/// - [`TightBeamError::SerializationError`] -- the body is no DER encoding
	///   of `T`, or a SET in it holds its elements out of DER order.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::core::RequirementError;
	/// use tightbeam::der::Sequence;
	/// use tightbeam::{compose, Beamable, TightBeamError};
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// struct Ping {
	///     sequence: u64,
	/// }
	///
	/// #[derive(Beamable, Sequence, Clone, Debug, PartialEq)]
	/// #[beam(min_version = "V2")]
	/// struct RecentPing {
	///     sequence: u64,
	/// }
	///
	/// let frame = compose! { V1: id: "ping", order: 1u64, message: Ping { sequence: 7 } }?;
	/// assert_eq!(frame.decode_message::<Ping>()?, Ping { sequence: 7 });
	///
	/// // The same body is no carrier of a type whose minimum is V2.
	/// let refused = frame.decode_message::<RecentPing>();
	/// assert!(matches!(refused, Err(TightBeamError::Requirement(RequirementError::Version(_)))));
	/// # Ok::<(), TightBeamError>(())
	/// ```
	///
	/// # Sources
	///
	/// - ITU-T X.690 (02/2021) § 11.6, set-of components: <https://www.itu.int/rec/T-REC-X.690-202102-I/en>
	pub fn decode_message<T: Message>(&self) -> Result<T> {
		let arrived = self.cleartext_shape().map_err(TightBeamError::OpaqueBody)?;
		arrived.decode::<T, TightBeamError>(self.message())
	}

	/// Open the body of this Frame with `open`, then decode it as `T`. The
	/// Frame, as it arrived, meets the requirements of `T` first.
	///
	/// An open in place takes protections out of the Frame, so the method
	/// takes the shape of the Frame before `open` runs. It refuses a Frame
	/// that is no carrier of `T` before any work, and `open` leaves the body
	/// in cleartext for the decode.
	///
	/// # Errors
	///
	/// - [`TightBeamError::Requirement`] -- the Frame, as it arrived, fails a requirement of `T`.
	/// - The errors of `open`.
	/// - [`TightBeamError::OpaqueBody`] -- the body still needs a transform after `open`.
	/// - [`TightBeamError::SerializationError`] -- the body is no DER encoding
	///   of `T`, or a SET in it holds its elements out of DER order.
	#[cfg(feature = "aead")]
	pub(crate) async fn open_message<T: Message>(
		&mut self,
		open: impl AsyncFnOnce(&mut Self) -> Result<()>,
	) -> Result<T> {
		FrameShape::from(&*self).admit::<T>()?;

		open(self).await?;

		if let Some(transform) = self.body_transform() {
			return Err(TightBeamError::OpaqueBody(transform));
		}

		Ok(DerAdmission::SetOrder.decode(self.message())?)
	}

	/// The shape of this Frame, whose body arrived in cleartext.
	///
	/// # Errors
	///
	/// - The [`BodyTransform`] that the body still needs before a decode:
	///   `metadata.confidentiality` or `metadata.compactness` is set.
	pub(crate) fn cleartext_shape(&self) -> core::result::Result<FrameShape, BodyTransform> {
		match self.body_transform() {
			Some(transform) => Err(transform),
			None => Ok(FrameShape::from(self)),
		}
	}
}

/// A trait for types that represent a TightBeam message with associated data.
pub trait TightBeamLike:
	crate::der::Encode
	+ for<'a> crate::der::Decode<'a>
	+ Clone
	+ core::fmt::Debug
	+ PartialEq
	+ Into<Metadata>
	+ Into<Version>
{
}

impl TightBeamLike for Frame {}

/// Outcome of an integrity verification check.
#[cfg(feature = "digest")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegrityVerdict {
	/// Recomputed digest matches the stored value.
	Verified,
	/// The frame carries no integrity value to check.
	Absent,
	/// The stored digest was produced by a different algorithm than `D`.
	AlgorithmMismatch,
	/// Recomputed digest differs because the covered bytes changed after
	/// digesting.
	Mismatch,
}

#[cfg(feature = "digest")]
impl IntegrityVerdict {
	/// `true` only for [`IntegrityVerdict::Verified`].
	pub fn is_verified(self) -> bool {
		matches!(self, IntegrityVerdict::Verified)
	}
}

#[cfg(test)]
mod tests {
	#[cfg(not(feature = "std"))]
	use alloc::{
		string::{String, ToString},
		vec,
		vec::Vec,
	};

	use crate::asn1::AuthEnvelopedData;
	use crate::testing::{TestIdentity, TestKey, TestMessage};
	use crate::Beamable;
	use crate::MessagePriority;
	use crate::SignerInfo;

	use super::*;

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct SimpleMessage {
		id: u64,
		name: String,
	}

	#[derive(Clone, Debug, PartialEq, der::Sequence)]
	struct NestedMessage {
		value: u32,
		data: Vec<u8>,
		flag: bool,
	}

	/// Pin `decoded` to the type of `original`. With reduced feature sets the
	/// `serde_json` dev-dependency's `PartialEq<Value>` impls for integers make
	/// a bare `assert_eq!` on `decode`'s inferred output ambiguous.
	fn assert_round_trip<T: PartialEq + core::fmt::Debug>(original: &T, decoded: &T) {
		assert_eq!(original, decoded);
	}

	/// Macro to generate encode/decode round-trip tests.
	macro_rules! test_encode_decode {
		($($name:ident: $value:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $value;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded = crate::decode(&encoded)?;
					assert_round_trip(&original, &decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_encode_decode! {
		encode_decode_simple_message: SimpleMessage {
			id: 42,
			name: "test".to_string(),
		},
		encode_decode_simple_message_zero: SimpleMessage {
			id: 0,
			name: String::new(),
		},
		encode_decode_simple_message_large: SimpleMessage {
			id: u64::MAX,
			name: "a very long name with many characters".to_string(),
		},
		encode_decode_nested_message: NestedMessage {
			value: 12345,
			data: vec![1, 2, 3, 4, 5],
			flag: true,
		},
		encode_decode_nested_message_false: NestedMessage {
			value: 0,
			data: Vec::new(),
			flag: false,
		},
		encode_decode_u32: 42u32,
		encode_decode_u64: 9876543210u64,
		encode_decode_bool_true: true,
		encode_decode_bool_false: false,
	}

	/// Macro to generate decode failure tests.
	macro_rules! test_decode_failure {
		($($name:ident: $data:expr => $type:ty,)*) => {
			$(
				#[test]
				fn $name() {
					let result: Result<$type> = crate::decode($data);
					assert!(result.is_err());
				}
			)*
		};
	}

	test_decode_failure! {
		decode_invalid_der_should_fail: &vec![0xFF, 0xFF, 0xFF] => u32,
		decode_empty_should_fail: &vec![] => u32,
		decode_invalid_sequence: &vec![0x30, 0xFF] => SimpleMessage,
		decode_wrong_type: &vec![0x02, 0x01, 0x2A] => SimpleMessage, // INTEGER instead of SEQUENCE
	}

	#[test]
	fn decode_truncated_should_fail() -> Result<()> {
		let original = SimpleMessage { id: 100, name: "test".to_string() };
		let mut encoded = crate::encode(&original)?;
		encoded.truncate(5);

		let result: Result<SimpleMessage> = crate::decode(&encoded);
		assert!(result.is_err());

		Ok(())
	}

	/// Macro to generate TightBeam encode/decode round-trip tests.
	macro_rules! test_tightbeam_roundtrip {
		($($name:ident: $tightbeam:expr,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let original = $tightbeam;

					let encoded = crate::encode(&original)?;
					assert!(!encoded.is_empty());

					let decoded: Frame = crate::decode(&encoded)?;
					assert_eq!(original, decoded);

					// A second encode proves the decoded value is valid DER.
					let re_encoded = crate::encode(&decoded)?;
					assert_eq!(encoded, re_encoded);

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_roundtrip! {
		tightbeam_v0_minimal: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "test-001",
					order: 1696521600,
					message: message,
			}?
		},
		tightbeam_v0_large_value: {
			let message = TestMessage::sample(Some(&("A".repeat(1000))));
			compose! {
				V0:
					id: "test-002",
					order: 1696521700,
					message: message
			}?
		},
		tightbeam_v1_encrypted: {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

			compose! {
				V1: id: "test-003",
					order: 1696521800,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key)
			}?
		},
		tightbeam_v2_full: {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

			compose! {
				V2: id: "test-004",
					order: 1696521900,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::HighThroughput,
					lifetime: 3600
			}?
		},
	}

	/// Macro to test TightBeam conversions.
	macro_rules! test_tightbeam_conversions {
		($($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let _converted: $target = tightbeam.clone().into();

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_conversions! {
		tightbeam_to_metadata_v0: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "meta-001",
					order: 1000,
					message: message
			}?
		} => Metadata,
		tightbeam_to_protocol_version: {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

			compose! {
				V2:
					id: "ver-001",
					order: 2000,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::Expedited,
					lifetime: 60
			}?
		} => Version,
	}

	/// Macro to test TightBeam TryFrom conversions (owned only).
	macro_rules! test_tightbeam_try_conversions {
		(success: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_ok());

					Ok(())
				}
			)*
		};
		(failure: $($name:ident: $tightbeam:expr => $target:ty,)*) => {
			$(
				#[test]
				fn $name() -> Result<()> {
					let tightbeam = $tightbeam;
					let result: Result<$target> = tightbeam.try_into();
					assert!(result.is_err());

					Ok(())
				}
			)*
		};
	}

	test_tightbeam_try_conversions! {
		success:
		tightbeam_v1_to_signature_info: {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

			compose! {
				V1: id: "sig-001",
					order: 3000,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key)
			}?
		} => crate::crypto::sign::Signed<SignerInfo>,
		tightbeam_v2_to_encryption_info: {
			use crate::crypto::sign::ecdsa::Secp256k1Signature;
			use crate::crypto::hash::Sha3_256;

			let message = TestMessage::sample(None);
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let signing_key = TestKey::insecure_fixed_signing();

			compose! {
				V2:
					id: "enc-001",
					order: 4000,
					message: message,
					confidentiality: cipher,
					nonrepudiation<Secp256k1Signature, _>: TestIdentity::certified(signing_key),
					message_integrity<Sha3_256>: [],
					priority: MessagePriority::LowLatency,
					lifetime: 120
			}?
		} => AuthEnvelopedData,
	}

	test_tightbeam_try_conversions! {
		failure: // These conversions should fail due to missing fields.
		tightbeam_v0_to_signature_info_fails: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "fail-001",
					order: 5000,
					message: message
			}?
		} => crate::crypto::sign::Signed<SignerInfo>,
		tightbeam_v0_to_encryption_info_fails: {
			let message = TestMessage::sample(None);
			compose! {
				V0:
					id: "fail-002",
					order: 6000,
					message: message
			}?
		} => AuthEnvelopedData,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile = 1)]
	struct NumericProfileMessage {
		id: u64,
		data: String,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile(crate::crypto::profiles::TightbeamProfile))]
	struct TypeProfileMessage {
		id: u64,
		data: String,
	}

	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	struct NoProfileMessage {
		id: u64,
		data: String,
	}

	#[test]
	#[allow(clippy::assertions_on_constants)]
	fn test_profile_types() {
		// Every message type must expose a Profile type that implements
		// SecurityProfile.
		fn assert_security_profile<P: crate::crypto::profiles::SecurityProfile>() {}

		assert_security_profile::<<NumericProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<TypeProfileMessage as crate::Message>::Profile>();
		assert_security_profile::<<NoProfileMessage as crate::Message>::Profile>();

		// A type-based profile resolves to the named profile type.
		assert_eq!(
			core::any::TypeId::of::<<TypeProfileMessage as crate::Message>::Profile>(),
			core::any::TypeId::of::<crate::crypto::profiles::TightbeamProfile>()
		);

		assert!(!NumericProfileMessage::HAS_PROFILE);
		assert!(TypeProfileMessage::HAS_PROFILE);
		assert!(!NoProfileMessage::HAS_PROFILE);
	}

	/// A level-1 message that also declares a minimum version above the V1 of
	/// the level.
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile = 1, min_version = "V2")]
	struct LeveledRecentMessage {
		id: u64,
	}

	/// A numeric level and a `min_version` combine to the stricter of the two,
	/// as the level's flags combine with the declared ones.
	#[test]
	fn a_numeric_level_keeps_a_higher_declared_minimum_version() -> Result<()> {
		assert_eq!(LeveledRecentMessage::MIN_VERSION, Version::V2);
		Ok(())
	}

	/// A level-1 message that also declares a minimum version below the V1 of
	/// the level.
	#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
	#[beam(profile = 1, min_version = "V0")]
	struct LeveledEarlyMessage {
		id: u64,
	}

	/// A numeric level keeps its own minimum version above a lower declared
	/// one.
	#[test]
	fn a_numeric_level_keeps_its_minimum_above_a_lower_declared_version() -> Result<()> {
		assert_eq!(LeveledEarlyMessage::MIN_VERSION, Version::V1);
		Ok(())
	}

	/// The typed decodes outside the router, each held to the requirements of
	/// its message type.
	mod typed_decode {
		use super::*;
		use crate::core::{Requirement, RequirementError};
		use crate::frame::BodyTransform;
		use crate::TightBeamError;

		/// A note whose type requires a signature. Its DER is the DER of
		/// [`TestMessage`].
		#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
		#[beam(nonrepudiable)]
		struct SignedNote {
			content: String,
		}

		/// A note whose type requires V2 or later. Its DER is the DER of
		/// [`TestMessage`].
		#[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
		#[beam(min_version = "V2")]
		struct RecentNote {
			content: String,
		}

		/// An encrypted frame that carries no signature is no carrier of a type
		/// that requires one, so the typed decrypt refuses it before the open.
		#[tokio::test]
		async fn a_typed_decrypt_refuses_a_frame_without_the_signature_its_type_requires() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let message = TestMessage::sample(None);
			let frame = compose! { V1: id: "unsigned", order: 1u64, message: message, confidentiality: cipher }?;

			let (_, key) = TestKey::insecure_fixed_cipher();
			let refused = frame.decrypt::<SignedNote>(&key, None).await;
			let unprotected = RequirementError::Unprotected(Requirement::NonRepudiation);
			assert!(matches!(refused, Err(TightBeamError::Requirement(error)) if error == unprotected));
			Ok(())
		}

		/// The borrowed decode holds a V0 frame to the V2 minimum of its type.
		#[test]
		fn a_borrowed_decode_refuses_a_frame_below_its_minimum_version() -> Result<()> {
			let message = TestMessage::sample(None);
			let frame = compose! { V0: id: "recent", order: 1u64, message: message }?;

			let refused = frame.decode_message::<RecentNote>();
			let below = RequirementError::Version((Version::V0, Version::V2).into());
			assert!(matches!(refused, Err(TightBeamError::Requirement(error)) if error == below));
			Ok(())
		}

		/// An encrypted body is opaque, so the borrowed decode refuses it
		/// before it reads the body.
		#[test]
		fn a_borrowed_decode_refuses_an_encrypted_body() -> Result<()> {
			let (_, cipher) = TestKey::insecure_fixed_cipher();
			let message = TestMessage::sample(None);
			let frame = compose! { V1: id: "sealed", order: 1u64, message: message, confidentiality: cipher }?;

			let refused = frame.decode_message::<TestMessage>();
			assert!(matches!(refused, Err(TightBeamError::OpaqueBody(BodyTransform::Decrypt))));
			Ok(())
		}

		/// A V0 frame is below the V2 minimum of its type, so the typed
		/// delivery of a servlet refuses it before the handler runs.
		#[cfg(all(feature = "colony", feature = "instrument"))]
		#[tokio::test]
		async fn a_typed_servlet_delivery_refuses_a_frame_below_the_minimum_of_its_type() -> Result<()> {
			use std::sync::Arc;

			use crate::colony::servlet::ServletContext;
			use crate::testing::fixtures::TestTrace;

			let ctx = ServletContext::new(Arc::new(TestTrace::with_detail(false)), Arc::new(()), [], None);
			let message = TestMessage::sample(None);
			let frame = compose! { V0: id: "recent", order: 1u64, message: message }?;

			let handler = |_: RecentNote, _: Frame, _: &ServletContext| async { Ok(None) };
			let refused = frame.dispatch_typed_unary(&ctx, handler).await;
			let below = RequirementError::Version((Version::V0, Version::V2).into());
			assert!(matches!(refused, Err(TightBeamError::Requirement(error)) if error == below));
			Ok(())
		}
	}
}

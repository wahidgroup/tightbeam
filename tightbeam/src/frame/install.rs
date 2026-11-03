//! Results a caller computed outside this crate, and the steps that install
//! them.
//!
//! A caller with its own hasher, cipher, or compressor, such as a browser
//! client, builds a frame in steps. The caller hashes or transforms the body,
//! then installs the result here. A step that installs a gated field refuses
//! one the frame's version forbids, as the builder and the decoder do (§5.6).
//! [`InstallStep`] states the order of the steps.

use core::fmt;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::{Frame, Metadata};
use crate::asn1::{AuthEnvelopedData, CompressedData, DigestInfo, WireDer};
use crate::error::Result;
use crate::version::GatedField;
use crate::TightBeamError;

#[cfg(feature = "digest")]
use super::FrameIntegrityScaffold;
#[cfg(feature = "digest")]
use crate::der::{Encode, Writer};

/// The steps of a frame built by hand, in the order they run.
///
/// # Order
///
/// The steps run in the order this type lists, which is the order the
/// builder runs, and a step behind the furthest one a frame holds refuses. A
/// later step covers what the earlier steps wrote:
///
/// - The commitment covers the plain body.
/// - The witness covers the version and the metadata the earlier steps write.
/// - The signature covers the whole frame.
///
/// The guard reads which fields a frame holds, so a caller takes each preimage
/// after the last step that writes into it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum InstallStep {
	/// The body the caller encoded.
	Body,
	/// The Message Integrity commitment over the plain body.
	MessageIntegrity,
	/// The compressed body and its description.
	Compactness,
	/// The ciphertext and its envelope.
	Confidentiality,
	/// The Frame Integrity digest over the version and the metadata.
	FrameIntegrity,
	/// The signature over the whole frame.
	Signature,
}

impl fmt::Display for InstallStep {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let name = match self {
			Self::Body => "the body",
			Self::MessageIntegrity => "message integrity",
			Self::Compactness => "compactness",
			Self::Confidentiality => "confidentiality",
			Self::FrameIntegrity => "frame integrity",
			Self::Signature => "the signature",
		};

		f.write_str(name)
	}
}

impl Metadata {
	/// Refuse an envelope that carries the ciphertext inside it. A frame
	/// carries the ciphertext in `Frame.message`, detached from the envelope
	/// (RFC 5652 §6.1).
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidMetadata`] -- the envelope carries the ciphertext.
	fn ensure_detached_confidentiality(&self) -> Result<()> {
		let sealed = self.confidentiality.as_ref().map(WireDer::value);
		let inline = sealed.is_some_and(|envelope| envelope.auth_encrypted_content_info.encrypted_content.is_some());
		if inline {
			return Err(TightBeamError::InvalidMetadata);
		}

		Ok(())
	}
}

impl Frame {
	/// The furthest step this frame holds. The order of [`InstallStep`]
	/// decides which step is furthest.
	fn furthest_step(&self) -> InstallStep {
		let held = [
			(self.metadata.integrity.is_some(), InstallStep::MessageIntegrity),
			(self.metadata.compactness.is_some(), InstallStep::Compactness),
			(self.metadata.confidentiality.is_some(), InstallStep::Confidentiality),
			(self.integrity.is_some(), InstallStep::FrameIntegrity),
			(self.nonrepudiation.is_some(), InstallStep::Signature),
		];

		let steps = held.into_iter().filter_map(|(holds, step)| holds.then_some(step));
		steps.max().unwrap_or(InstallStep::Body)
	}

	/// Refuse `step` when this frame already holds a later one, which would
	/// go stale. A frame takes the same step again, so a caller replaces what
	/// it installed.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	fn ensure_open(&self, step: InstallStep) -> Result<()> {
		let furthest = self.furthest_step();
		if furthest > step {
			return Err(TightBeamError::InstallOutOfOrder { step, furthest });
		}

		Ok(())
	}

	/// Refuse `step` when this frame already holds it or a later one. A seal
	/// rewrites the body in place, so a second seal loses the first envelope.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds `step` or a later one.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub(super) fn ensure_ahead(&self, step: InstallStep) -> Result<()> {
		let furthest = self.furthest_step();
		if furthest >= step {
			return Err(TightBeamError::InstallOutOfOrder { step, furthest });
		}

		Ok(())
	}

	/// Replace the body with `body`, a DER value the caller encoded itself.
	///
	/// A body is opaque to the frame, so every version takes any body.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	pub fn with_body(mut self, body: impl Into<Vec<u8>>) -> Result<Self> {
		self.ensure_open(InstallStep::Body)?;
		self.replace_body(body.into());

		Ok(self)
	}

	/// Install the Message Integrity commitment over the plain body.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	///
	/// # Examples
	///
	/// ```
	/// # #[cfg(all(feature = "builder", feature = "sha3"))]
	/// # {
	/// use tightbeam::builder::TypeBuilder;
	/// use tightbeam::crypto::commitment::CommitmentSalt;
	/// use tightbeam::crypto::hash::{Digest, DigestInfoExt, Sha3_256};
	/// use tightbeam::{DigestInfo, Opaque, Version};
	///
	/// let composed = Version::V1.compose::<Opaque>().with_id(b"id").with_order(7);
	/// let frame = composed.with_message(Opaque::new(*b"body")?).build()?;
	///
	/// let mut hasher = Sha3_256::new();
	/// CommitmentSalt::parse([0x5A; 16])?.preimage(frame.message(), |part| hasher.update(part));
	///
	/// let commitment = DigestInfo::of_hasher(hasher)?;
	/// let frame = frame.with_message_integrity(commitment)?;
	/// assert!(frame.metadata().integrity().is_some());
	/// # }
	/// # Ok::<(), tightbeam::TightBeamError>(())
	/// ```
	pub fn with_message_integrity(mut self, commitment: DigestInfo) -> Result<Self> {
		self.ensure_allows(GatedField::MessageIntegrity)?;
		self.ensure_open(InstallStep::MessageIntegrity)?;
		self.metadata.integrity = Some(commitment);

		Ok(self)
	}

	/// Replace the body with `compressed`, and record how it was compressed.
	///
	/// Every version carries compactness. A repeat of this step replaces the
	/// compressed body, so the caller compresses the plain body again.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	/// - [`TightBeamError::InvalidMetadata`] -- `compactness` is not version 0, or carries an `eContent`.
	pub fn with_compactness(mut self, compactness: CompressedData, compressed: impl Into<Vec<u8>>) -> Result<Self> {
		self.ensure_open(InstallStep::Compactness)?;
		self.metadata.compactness = Some(compactness);
		self.metadata.ensure_carried_compactness()?;
		self.replace_body(compressed.into());

		Ok(self)
	}

	/// Replace the body with `ciphertext`, and install the `envelope` that
	/// seals it. The ciphertext travels detached from the envelope (RFC 5652
	/// §6.1).
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	/// - [`TightBeamError::InvalidMetadata`] -- `envelope` carries the ciphertext inside it.
	///
	/// # Sources
	///
	/// - RFC 5652 (09/2009) § 6.1, EnvelopedData content type:
	///   <https://datatracker.ietf.org/doc/html/rfc5652#section-6.1>
	pub fn with_confidentiality(
		mut self,
		envelope: WireDer<AuthEnvelopedData>,
		ciphertext: impl Into<Vec<u8>>,
	) -> Result<Self> {
		self.ensure_allows(GatedField::Confidentiality)?;
		self.ensure_open(InstallStep::Confidentiality)?;
		self.metadata.confidentiality = Some(envelope);
		self.metadata.ensure_detached_confidentiality()?;
		self.replace_body(ciphertext.into());

		Ok(self)
	}

	/// Feed the preimage of the Frame Integrity digest, which covers the
	/// version and the metadata, to `sink`, part by part and in order, for a
	/// caller that hashes outside this crate. The parts encode into `sink`
	/// with no buffer between the two.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the metadata does not encode.
	#[cfg(feature = "digest")]
	pub fn witness_preimage(&self, sink: impl FnMut(&[u8])) -> Result<()> {
		let scaffold = FrameIntegrityScaffold { version: &self.version, metadata: &self.metadata };
		Ok(scaffold.encode(&mut SinkWriter(sink))?)
	}

	/// Install the Frame Integrity digest, hashed over the preimage that
	/// `Frame::witness_preimage` feeds.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnsupportedField`] -- the frame's version predates the field.
	/// - [`TightBeamError::InstallOutOfOrder`] -- the frame holds a later step.
	pub fn with_frame_integrity(mut self, witness: DigestInfo) -> Result<Self> {
		self.ensure_allows(GatedField::FrameIntegrity)?;
		self.ensure_open(InstallStep::FrameIntegrity)?;
		self.integrity = Some(witness);

		Ok(self)
	}
}

/// A DER writer that feeds each encoded part to the closure it holds.
#[cfg(feature = "digest")]
struct SinkWriter<F>(F);

#[cfg(feature = "digest")]
impl<F: FnMut(&[u8])> Writer for SinkWriter<F> {
	fn write(&mut self, part: &[u8]) -> crate::der::Result<()> {
		(self.0)(part);
		Ok(())
	}
}

#[cfg(all(
	test,
	feature = "builder",
	feature = "sha3",
	feature = "aead",
	feature = "zstd",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh",
	feature = "secp256k1",
	feature = "x509"
))]
mod tests {
	use super::InstallStep;
	use crate::asn1::{AuthEnvelopedData, CompressedData, DigestInfo, GatedField, Version, WireDer};
	use crate::builder::{FrameBuilder, TypeBuilder};
	use crate::cms::content_info::CmsVersion;
	use crate::compress::{Compressor, ZstdCompression};
	use crate::crypto::commitment::CommitmentSalt;
	use crate::crypto::hash::{Digest, DigestInfoExt, Sha3_256};
	use crate::der::asn1::{Any, OctetString};
	use crate::testing::fixtures::TestIdentity;
	use crate::testing::{TestFrame, TestResult};
	use crate::{encode, tb_cases, Frame, Opaque, TightBeamError};

	/// A frame, or the refusal of the step that built it.
	type Built = Result<Frame, TightBeamError>;

	/// A fixture that holds every step up to one.
	type Held = fn() -> Built;

	/// One step, taken on a frame.
	type Step = fn(Frame) -> Built;

	/// The salt of the equivalence tests.
	const SALT: [u8; 16] = [0x5A; 16];

	/// A frame of `version` over `message`, at the id and the order every test
	/// shares.
	fn composed(version: Version, message: Opaque) -> FrameBuilder<Opaque> {
		version.compose::<Opaque>().with_id(b"id").with_order(7).with_message(message)
	}

	/// The opaque body the tests install.
	fn body() -> Result<Opaque, TightBeamError> {
		Opaque::new(*b"installed body")
	}

	/// A frame of `version` that holds the body alone.
	fn structural(version: Version) -> Built {
		composed(version, body()?).build()
	}

	/// The SHA3-256 digest of `preimage`.
	fn digest_of(preimage: impl AsRef<[u8]>) -> Result<DigestInfo, TightBeamError> {
		DigestInfo::of_hasher(Sha3_256::new_with_prefix(preimage))
	}

	/// A sealed fixture frame, and its envelope for a frame of the same id.
	fn sealed_envelope() -> Result<(Frame, WireDer<AuthEnvelopedData>), TightBeamError> {
		let sealed = TestFrame::sealed("sealed");
		let envelope = sealed.metadata().confidentiality();
		let envelope = envelope.ok_or(TightBeamError::MissingEncryptionInfo)?;
		let envelope = WireDer::new(envelope.clone())?;

		Ok((sealed, envelope))
	}

	fn take_body(frame: Frame) -> Built {
		frame.with_body([0x01])
	}

	fn take_commitment(frame: Frame) -> Built {
		frame.with_message_integrity(digest_of(b"body")?)
	}

	fn take_compactness(frame: Frame) -> Built {
		let (compressed, compactness) = ZstdCompression::default().compress(frame.message(), None)?;

		frame.with_compactness(compactness, compressed)
	}

	fn take_envelope(frame: Frame) -> Built {
		let (sealed, envelope) = sealed_envelope()?;

		frame.with_confidentiality(envelope, sealed.message())
	}

	fn take_witness(frame: Frame) -> Built {
		frame.with_frame_integrity(digest_of(b"witness")?)
	}

	fn body_held() -> Built {
		structural(Version::V1)
	}

	fn commitment_held() -> Built {
		take_commitment(body_held()?)
	}

	fn compactness_held() -> Built {
		take_compactness(commitment_held()?)
	}

	fn envelope_held() -> Built {
		take_envelope(compactness_held()?)
	}

	fn witness_held() -> Built {
		take_witness(envelope_held()?)
	}

	fn signature_held() -> Built {
		Ok(TestFrame::signed_by(witness_held()?, &TestIdentity::insecure_fixed()))
	}

	fn take_compactness_at_version_one(frame: Frame) -> Built {
		let (compressed, compactness) = ZstdCompression::default().compress(frame.message(), None)?;
		let compactness = CompressedData { version: CmsVersion::V1, ..compactness };

		frame.with_compactness(compactness, compressed)
	}

	fn take_attached_compactness(frame: Frame) -> Built {
		let (compressed, mut compactness) = ZstdCompression::default().compress(frame.message(), None)?;
		let attached = OctetString::new(compressed.clone())?;
		compactness.encap_content_info.econtent = Some(Any::encode_from(&attached)?);

		frame.with_compactness(compactness, compressed)
	}

	fn take_inline_envelope(frame: Frame) -> Built {
		let (sealed, envelope) = sealed_envelope()?;
		let mut inline = envelope.into_value();
		inline.auth_encrypted_content_info.encrypted_content = Some(OctetString::new(sealed.message())?);

		frame.with_confidentiality(WireDer::new(inline)?, sealed.message())
	}

	/// The step and the furthest step that `refused` names.
	fn out_of_order(refused: Built) -> Option<(InstallStep, InstallStep)> {
		match refused {
			Err(TightBeamError::InstallOutOfOrder { step, furthest }) => Some((step, furthest)),
			_ => None,
		}
	}

	/// The field that `taken` refused.
	fn refused_field(taken: &Built) -> Option<GatedField> {
		match taken {
			Err(TightBeamError::UnsupportedField { field, .. }) => Some(*field),
			_ => None,
		}
	}

	/// A commitment and a witness installed by hand encode as the builder
	/// encodes them.
	#[test]
	fn installed_digests_match_the_builder() -> TestResult {
		let hashed = composed(Version::V1, body()?).with_message_hasher::<Sha3_256>(SALT);
		let built = hashed.with_witness_hasher::<Sha3_256>().build()?;
		let frame = structural(Version::V1)?;
		let mut hasher = Sha3_256::new();

		CommitmentSalt::parse(SALT)?.preimage(frame.message(), |part| hasher.update(part));

		let commitment = DigestInfo::of_hasher(hasher)?;
		let frame = frame.with_message_integrity(commitment)?;
		let mut witness = Sha3_256::new();
		frame.witness_preimage(|part| witness.update(part))?;

		let witness = DigestInfo::of_hasher(witness)?;
		let frame = frame.with_frame_integrity(witness)?;
		assert_eq!(encode(&frame)?, encode(&built)?);
		Ok(())
	}

	/// Compactness installed by hand encodes as the builder encodes it.
	#[test]
	fn installed_compactness_matches_the_builder() -> TestResult {
		let compressing = composed(Version::V0, body()?).with_compression(ZstdCompression::default());
		let built = compressing.build()?;

		let frame = take_compactness(structural(Version::V0)?)?;
		assert_eq!(encode(&frame)?, encode(&built)?);
		Ok(())
	}

	/// An envelope installed by hand encodes as the frame it was sealed in.
	#[test]
	fn an_installed_envelope_matches_the_sealed_frame() -> TestResult {
		let (sealed, envelope) = sealed_envelope()?;

		let plain = TestFrame::v1(None, Some("sealed"));
		let frame = plain.with_confidentiality(envelope, sealed.message())?;
		assert_eq!(encode(&frame)?, encode(&sealed)?);
		Ok(())
	}

	/// A body installed by hand encodes as the builder encodes it.
	#[test]
	fn an_installed_body_matches_the_builder() -> TestResult {
		let message = Opaque::new(*b"other body")?;
		let body = encode(&message)?;
		let built = composed(Version::V0, message).build()?;

		let frame = structural(Version::V0)?.with_body(body)?;
		assert_eq!(encode(&frame)?, encode(&built)?);
		Ok(())
	}

	// A step refuses a description or an envelope in a form no frame carries,
	// so the refusal surfaces at the sender.
	tb_cases! {
		fn a_form_no_frame_carries_is_refused(take: Step) -> TestResult {
			let taken = take(structural(Version::V1)?);
			assert!(matches!(taken, Err(TightBeamError::InvalidMetadata)));
			Ok(())
		}
		cases {
			compactness_at_version_one => take_compactness_at_version_one,
			compactness_with_attached_content => take_attached_compactness,
			an_envelope_with_inline_content => take_inline_envelope,
		}
	}

	// A step refuses a field the version of the frame forbids, and names it.
	tb_cases! {
		fn a_version_gates_each_step((take, version, refused): (Step, Version, Option<GatedField>)) -> TestResult {
			let taken = take(structural(version)?);

			assert_eq!(refused_field(&taken), refused);
			assert_eq!(taken.is_ok(), refused.is_none());
			Ok(())
		}
		cases {
			body_v0 => (take_body, Version::V0, None),
			body_v1 => (take_body, Version::V1, None),
			body_v2 => (take_body, Version::V2, None),
			body_v3 => (take_body, Version::V3, None),
			commitment_v0 => (take_commitment, Version::V0, Some(GatedField::MessageIntegrity)),
			commitment_v1 => (take_commitment, Version::V1, None),
			commitment_v2 => (take_commitment, Version::V2, None),
			commitment_v3 => (take_commitment, Version::V3, None),
			compactness_v0 => (take_compactness, Version::V0, None),
			compactness_v1 => (take_compactness, Version::V1, None),
			compactness_v2 => (take_compactness, Version::V2, None),
			compactness_v3 => (take_compactness, Version::V3, None),
			envelope_v0 => (take_envelope, Version::V0, Some(GatedField::Confidentiality)),
			envelope_v1 => (take_envelope, Version::V1, None),
			envelope_v2 => (take_envelope, Version::V2, None),
			envelope_v3 => (take_envelope, Version::V3, None),
			witness_v0 => (take_witness, Version::V0, Some(GatedField::FrameIntegrity)),
			witness_v1 => (take_witness, Version::V1, None),
			witness_v2 => (take_witness, Version::V2, None),
			witness_v3 => (take_witness, Version::V3, None),
		}
	}

	// A step behind a later one refuses, for every pair of steps.
	tb_cases! {
		fn a_step_is_refused_behind_a_later_one(
			(held, take, step, furthest): (Held, Step, InstallStep, InstallStep)
		) -> TestResult {
			assert_eq!(out_of_order(take(held()?)), Some((step, furthest)));
			Ok(())
		}
		cases {
			body_behind_commitment => (commitment_held, take_body, InstallStep::Body, InstallStep::MessageIntegrity),
			body_behind_compactness => (compactness_held, take_body, InstallStep::Body, InstallStep::Compactness),
			body_behind_envelope => (envelope_held, take_body, InstallStep::Body, InstallStep::Confidentiality),
			body_behind_witness => (witness_held, take_body, InstallStep::Body, InstallStep::FrameIntegrity),
			body_behind_signature => (signature_held, take_body, InstallStep::Body, InstallStep::Signature),
			commitment_behind_compactness =>
				(compactness_held, take_commitment, InstallStep::MessageIntegrity, InstallStep::Compactness),
			commitment_behind_envelope =>
				(envelope_held, take_commitment, InstallStep::MessageIntegrity, InstallStep::Confidentiality),
			commitment_behind_witness =>
				(witness_held, take_commitment, InstallStep::MessageIntegrity, InstallStep::FrameIntegrity),
			commitment_behind_signature =>
				(signature_held, take_commitment, InstallStep::MessageIntegrity, InstallStep::Signature),
			compactness_behind_envelope =>
				(envelope_held, take_compactness, InstallStep::Compactness, InstallStep::Confidentiality),
			compactness_behind_witness =>
				(witness_held, take_compactness, InstallStep::Compactness, InstallStep::FrameIntegrity),
			compactness_behind_signature =>
				(signature_held, take_compactness, InstallStep::Compactness, InstallStep::Signature),
			envelope_behind_witness =>
				(witness_held, take_envelope, InstallStep::Confidentiality, InstallStep::FrameIntegrity),
			envelope_behind_signature =>
				(signature_held, take_envelope, InstallStep::Confidentiality, InstallStep::Signature),
			witness_behind_signature =>
				(signature_held, take_witness, InstallStep::FrameIntegrity, InstallStep::Signature),
		}
	}

	// A frame takes the step it holds again, so a caller replaces what it
	// installed.
	tb_cases! {
		fn a_held_step_takes_its_replacement((held, take): (Held, Step)) -> TestResult {
			assert!(take(held()?).is_ok());
			Ok(())
		}
		cases {
			body => (body_held, take_body),
			commitment => (commitment_held, take_commitment),
			compactness => (compactness_held, take_compactness),
			envelope => (envelope_held, take_envelope),
			witness => (witness_held, take_witness),
		}
	}

	// A step reads as the name a refusal shows.
	tb_cases! {
		fn a_step_names_itself((step, name): (InstallStep, &str)) {
			assert_eq!(step.to_string(), name);
		}
		cases {
			body => (InstallStep::Body, "the body"),
			message_integrity => (InstallStep::MessageIntegrity, "message integrity"),
			compactness => (InstallStep::Compactness, "compactness"),
			confidentiality => (InstallStep::Confidentiality, "confidentiality"),
			frame_integrity => (InstallStep::FrameIntegrity, "frame integrity"),
			signature => (InstallStep::Signature, "the signature"),
		}
	}

	#[test]
	fn a_refusal_names_the_step_and_the_one_it_is_behind() {
		let refusal = TightBeamError::InstallOutOfOrder { step: InstallStep::Body, furthest: InstallStep::Signature };
		assert_eq!(refusal.to_string(), "a frame that holds the signature refuses the body");
	}

	/// The replacement takes the place of what the frame held.
	#[test]
	fn a_replacement_holds_the_new_value() -> TestResult {
		let frame = structural(Version::V1)?.with_message_integrity(digest_of(b"first")?)?;
		let replacement = digest_of(b"second")?;

		let frame = frame.with_message_integrity(replacement.clone())?;
		assert_eq!(frame.metadata().integrity(), Some(&replacement));
		Ok(())
	}
}

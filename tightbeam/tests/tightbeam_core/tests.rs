//! The integration tests of TightBeam protocol workflows.
//!
//! Each protocol version builds a frame with the metadata that it permits, and
//! each test checks one property of those frames against its version.

use std::sync::Arc;

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::prelude::*;
use tightbeam::tb_cases;
use tightbeam::testing::{TestCertificate, TestDigest, TestFrame, TestIdentity, TestMessage};
use tightbeam::{utils, TightBeamError};

use crate::common::result::TestResult;

/// The development-mode flag of the custom test matrix of message metadata.
#[derive(tightbeam::Flaggable)]
#[repr(u8)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDevelopmentMode {
	#[default]
	Default = 0,
	IsMaintenanceMode = 2,
}

/// The debug-level flag of the custom test matrix of message metadata.
#[derive(tightbeam::Flaggable)]
#[repr(u8)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum FlagTestDebugLevel {
	#[default]
	Default = 0,
	Basic = 1,
}

// The flag set of both flags, whose positions the macro assigns.
tightbeam::flagset!(TestFlagSet: FlagTestDevelopmentMode, FlagTestDebugLevel);

struct TestCrypto {
	cipher: Arc<Aes256GcmKeyProvider>,
	signing_key: Secp256k1SigningKey,
	signer: PeerCertificate<Signing<DefaultCryptoProvider>>,
}

fn build_crypto(seed: u8) -> TestCrypto {
	let key_bytes = [seed; 32];
	let cipher = Aes256GcmKeyProvider::new(key_bytes.to_vec(), b"tb/test/core/kek/v1".to_vec());
	let cipher = Arc::new(cipher.expect("a key of 32 octets wraps"));
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into()).expect("a nonzero scalar signs");
	let signer = PeerCertificate::parse(TestCertificate::self_signed(&signing_key), KeyPurposes::HOUSE.signer);
	let signer = signer.expect("a self-signed house certificate parses");
	TestCrypto { cipher, signing_key, signer }
}

/// The message that every frame of these tests carries.
fn sample_message() -> TestMessage {
	TestMessage::sample(Some("Hello from workflow"))
}

/// Builds a test frame of `version` with each capability the version permits.
fn build_version_frame(version: asn1::Version, crypto: &TestCrypto) -> tightbeam::Frame {
	let message = sample_message();
	let parent_hash = utils::digest::<Sha3_256>(&message.content).expect("SHA3-256 digests a message");
	let mut builder = FrameBuilder::from(version)
		.with_id("test")
		.with_order(1_696_521_700)
		.with_message(message);

	if version >= asn1::Version::V1 {
		builder = builder
			.with_message_hasher::<Sha3_256>([])
			.with_encryptor(crypto.cipher.to_owned())
			.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(crypto.signing_key.to_owned()));
	}
	if version >= asn1::Version::V2 {
		builder = builder
			.with_priority(asn1::MessagePriority::Expedited)
			.with_lifetime(3_600)
			.with_previous_hash(parent_hash);
	}
	if version == asn1::Version::V3 {
		builder = builder.with_matrix(tightbeam::flags![
			TestFlagSet:
				FlagTestDevelopmentMode::IsMaintenanceMode,
				FlagTestDebugLevel::Basic
		]);
	}

	builder.build().expect("a frame of the fields its version permits builds")
}

/// The crypto of seed `0x44`, beside a frame of `version` under it.
fn frame_of(version: asn1::Version) -> (TestCrypto, tightbeam::Frame) {
	let crypto = build_crypto(0x44);
	let frame = build_version_frame(version, &crypto);
	(crypto, frame)
}

/// The fields of a frame that its version gates, each read as its presence or
/// its value.
#[derive(Debug, PartialEq)]
struct GatedFields {
	version: asn1::Version,
	signed: bool,
	frame_integrity: bool,
	message_integrity: bool,
	confidential: bool,
	priority: Option<asn1::MessagePriority>,
	lifetime: Option<u64>,
	chained: bool,
	matrix: bool,
}

impl GatedFields {
	/// The gated fields that `frame` carries.
	fn of(frame: &tightbeam::Frame) -> Self {
		let metadata = frame.metadata();
		Self {
			version: frame.version(),
			signed: frame.nonrepudiation().is_some(),
			frame_integrity: frame.integrity().is_some(),
			message_integrity: metadata.integrity().is_some(),
			confidential: metadata.confidentiality().is_some(),
			priority: metadata.priority(),
			lifetime: metadata.lifetime(),
			chained: metadata.previous_frame().is_some(),
			matrix: metadata.matrix().is_some(),
		}
	}
}

/// What a row of `a_frame_refuses_a_field_its_version_forbids` asks a builder
/// for.
type FieldRequest = fn(FrameBuilder<TestMessage>) -> FrameBuilder<TestMessage>;

/// The field and the version that `built` names, when the build refuses a
/// field that its version forbids.
fn forbidden_field_of(built: Result<tightbeam::Frame, TightBeamError>) -> Option<(asn1::GatedField, asn1::Version)> {
	let Err(TightBeamError::UnsupportedField { field, version }) = built else {
		return None;
	};

	Some((field, version))
}

// Each version carries the fields that it permits and that these tests ask
// for.
tb_cases! {
	fn a_frame_carries_the_fields_its_version_permits(permitted: GatedFields) {
		let (_crypto, frame) = frame_of(permitted.version);
		assert_eq!(GatedFields::of(&frame), permitted);
	}
	cases {
		v0 => GatedFields {
			version: asn1::Version::V0,
			signed: false,
			frame_integrity: false,
			message_integrity: false,
			confidential: false,
			priority: None,
			lifetime: None,
			chained: false,
			matrix: false,
		},
		v1 => GatedFields {
			version: asn1::Version::V1,
			signed: true,
			frame_integrity: false,
			message_integrity: true,
			confidential: true,
			priority: None,
			lifetime: None,
			chained: false,
			matrix: false,
		},
		v2 => GatedFields {
			version: asn1::Version::V2,
			signed: true,
			frame_integrity: false,
			message_integrity: true,
			confidential: true,
			priority: Some(asn1::MessagePriority::Expedited),
			lifetime: Some(3_600),
			chained: true,
			matrix: false,
		},
		v3 => GatedFields {
			version: asn1::Version::V3,
			signed: true,
			frame_integrity: false,
			message_integrity: true,
			confidential: true,
			priority: Some(asn1::MessagePriority::Expedited),
			lifetime: Some(3_600),
			chained: true,
			matrix: true,
		},
	}
}

// A build refuses each field below the first version that carries it, and the
// refusal names the field and the version of the frame.
tb_cases! {
	fn a_frame_refuses_a_field_its_version_forbids(
		(version, forbidden, request): (asn1::Version, asn1::GatedField, FieldRequest)
	) {
		let builder = FrameBuilder::<TestMessage>::from(version)
			.with_id("test")
			.with_order(1_696_521_700)
			.with_message(sample_message());

		let built = request(builder).build();
		assert_eq!(forbidden_field_of(built), Some((forbidden, version)));
	}
	cases {
		/// V1 is the first version with a message commitment.
		v0_message_integrity => (
			asn1::Version::V0,
			asn1::GatedField::MessageIntegrity,
			|builder| builder.with_message_hasher::<Sha3_256>([]),
		),
		/// V1 is the first version with an enveloped body.
		v0_confidentiality => (
			asn1::Version::V0,
			asn1::GatedField::Confidentiality,
			|builder| builder.with_encryptor(build_crypto(0x44).cipher),
		),
		/// V1 is the first version with a frame witness.
		v0_frame_integrity => (
			asn1::Version::V0,
			asn1::GatedField::FrameIntegrity,
			|builder| builder.with_witness_hasher::<Sha3_256>(),
		),
		/// V1 is the first version with a signature.
		v0_nonrepudiation => (
			asn1::Version::V0,
			asn1::GatedField::Nonrepudiation,
			|builder| {
				let key = build_crypto(0x44).signing_key;
				builder.with_signer::<Secp256k1Signature, _>(TestIdentity::certified(key))
			},
		),
		/// V2 is the first version with a priority.
		v1_priority => (
			asn1::Version::V1,
			asn1::GatedField::Priority,
			|builder| builder.with_priority(asn1::MessagePriority::Expedited),
		),
		/// V2 is the first version with a lifetime.
		v1_lifetime => (
			asn1::Version::V1,
			asn1::GatedField::Lifetime,
			|builder| builder.with_lifetime(3_600),
		),
		/// V2 is the first version with a link to the previous frame.
		v1_previous_frame => (
			asn1::Version::V1,
			asn1::GatedField::PreviousFrame,
			|builder| builder.with_previous_hash(TestDigest::info()),
		),
		/// V3 is the first version with a matrix.
		v2_matrix => (
			asn1::Version::V2,
			asn1::GatedField::Matrix,
			|builder| builder.with_matrix(tightbeam::flags![TestFlagSet: FlagTestDebugLevel::Basic]),
		),
	}
}

/// A V0 body is cleartext, so it decodes to the message as it stands.
#[test]
fn a_v0_body_decodes_to_the_message() -> TestResult {
	let (_crypto, frame) = frame_of(asn1::Version::V0);
	let roundtrip: TestMessage = tightbeam::decode(frame.message())?;
	assert_eq!(roundtrip, sample_message());
	Ok(())
}

// A V1 or later frame verifies under the certificate of its signer.
tb_cases! {
	fn a_signed_frame_verifies_under_its_signer(version: asn1::Version) -> TestResult {
		let (crypto, frame) = frame_of(version);
		frame.verify(&crypto.signer)?;
		Ok(())
	}
	cases {
		v1 => asn1::Version::V1,
		v2 => asn1::Version::V2,
		v3 => asn1::Version::V3,
	}
}

// The message integrity commitment of a V1 or later frame opens to the message
// it carries.
tb_cases! {
	fn the_message_commitment_opens_to_the_message(version: asn1::Version) -> TestResult {
		let (_crypto, frame) = frame_of(version);
		let opens = frame.verify_commitment_of::<Sha3_256, _>(&sample_message(), [])?;
		assert!(opens);
		Ok(())
	}
	cases {
		v1 => asn1::Version::V1,
		v2 => asn1::Version::V2,
		v3 => asn1::Version::V3,
	}
}

// The body of a V1 or later frame is enveloped, and it decrypts to the message
// under the shared cipher.
tb_cases! {
	fn an_enveloped_body_decrypts_to_the_message(version: asn1::Version) -> TestResult {
		let (crypto, frame) = frame_of(version);
		let roundtrip = TestFrame::decrypted::<TestMessage>(frame, &crypto.cipher, None)?;
		assert_eq!(roundtrip, sample_message());
		Ok(())
	}
	cases {
		v1 => asn1::Version::V1,
		v2 => asn1::Version::V2,
		v3 => asn1::Version::V3,
	}
}

// A frame of each version decodes from its DER to the same frame, and a V3
// frame keeps its matrix through the round trip.
tb_cases! {
	fn a_frame_survives_a_der_round_trip((version, matrix): (asn1::Version, bool)) -> TestResult {
		let (_crypto, frame) = frame_of(version);

		let encoded = tightbeam::encode(&frame)?;
		let decoded: tightbeam::Frame = tightbeam::decode(&encoded)?;
		assert_eq!((&decoded, decoded.version(), decoded.metadata().matrix().is_some()), (&frame, version, matrix));
		Ok(())
	}
	cases {
		/// A V0 frame carries no matrix.
		v0 => (asn1::Version::V0, false),
		/// A V1 frame carries no matrix.
		v1 => (asn1::Version::V1, false),
		/// A V2 frame carries no matrix.
		v2 => (asn1::Version::V2, false),
		/// A V3 frame with every optional field set keeps each of them, its
		/// matrix included.
		v3 => (asn1::Version::V3, true),
	}
}

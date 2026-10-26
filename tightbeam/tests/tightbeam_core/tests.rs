//! The integration tests of TightBeam protocol workflows.
//! TODO Enhance with instrumentation when available.
//!
//! Each protocol version builds a frame with the metadata that it permits, and
//! each test checks one property of those frames against its version.

#![allow(unexpected_cfgs)]

use std::sync::Arc;

use tightbeam::builder::{FrameBuilder, TypeBuilder};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::key::Aes256GcmKeyProvider;
use tightbeam::crypto::profiles::DefaultCryptoProvider;
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey};
use tightbeam::crypto::x509::{KeyPurposes, PeerCertificate, Signing};
use tightbeam::prelude::*;
use tightbeam::testing::{TestCertificate, TestFrame, TestIdentity};
use tightbeam::utils;
use tightbeam::{tb_cases, TightBeamError};

/// The test message, which carries one string of content.
#[derive(tightbeam::Beamable, Clone, Debug, PartialEq, Sequence)]
struct TestMessage {
	content: String,
}

impl AsRef<[u8]> for TestMessage {
	fn as_ref(&self) -> &[u8] {
		self.content.as_bytes()
	}
}

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

fn build_crypto(seed: u8) -> Result<TestCrypto, TightBeamError> {
	let key_bytes = [seed; 32];
	let cipher = Arc::new(Aes256GcmKeyProvider::new(key_bytes.to_vec(), b"tb/test/core/kek/v1".to_vec())?);
	let signing_key = Secp256k1SigningKey::from_bytes(&key_bytes.into())?;
	let signer = PeerCertificate::parse(TestCertificate::self_signed(&signing_key), KeyPurposes::HOUSE.signer)?;
	Ok(TestCrypto { cipher, signing_key, signer })
}

/// The message that every frame of these tests carries.
fn sample_message() -> TestMessage {
	TestMessage { content: "Hello from workflow".to_string() }
}

/// Builds a test frame of `version` with each capability the version permits.
fn build_version_frame(version: asn1::Version, crypto: &TestCrypto) -> Result<tightbeam::Frame, TightBeamError> {
	let message = sample_message();
	let parent_hash = utils::digest::<Sha3_256>(&message)?;
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

	builder.build()
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

// Each version carries the fields that it permits and that these tests ask
// for, and no field that it forbids.
tb_cases! {
	fn a_frame_carries_the_fields_its_version_permits(permitted: GatedFields) -> Result<(), TightBeamError> {
		let crypto = build_crypto(0x44)?;
		let frame = build_version_frame(permitted.version, &crypto)?;
		assert_eq!(GatedFields::of(&frame), permitted, "the frame carries other fields than its version permits");
		Ok(())
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

/// A V0 body is cleartext, so it decodes to the message as it stands.
#[test]
fn a_v0_body_decodes_to_the_message() -> Result<(), TightBeamError> {
	let crypto = build_crypto(0x44)?;
	let frame = build_version_frame(asn1::Version::V0, &crypto)?;

	let roundtrip: TestMessage = tightbeam::decode(frame.message())?;
	assert_eq!(roundtrip, sample_message(), "the V0 body decodes to another message");
	Ok(())
}

// A V1 or later frame verifies under the certificate of its signer.
tb_cases! {
	fn a_signed_frame_verifies_under_its_signer(version: asn1::Version) -> Result<(), TightBeamError> {
		let crypto = build_crypto(0x44)?;
		let frame = build_version_frame(version, &crypto)?;

		let verdict = frame.verify(&crypto.signer);
		assert!(verdict.is_ok(), "the signature does not verify under its signer: {verdict:?}");
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
	fn the_message_commitment_opens_to_the_message(version: asn1::Version) -> Result<(), TightBeamError> {
		let crypto = build_crypto(0x44)?;
		let frame = build_version_frame(version, &crypto)?;

		let opens = frame.verify_commitment_of::<Sha3_256, _>(&sample_message(), [])?;
		assert!(opens, "the message commitment does not open to the message");
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
	fn an_enveloped_body_decrypts_to_the_message(version: asn1::Version) -> Result<(), TightBeamError> {
		let crypto = build_crypto(0x44)?;
		let frame = build_version_frame(version, &crypto)?;

		let roundtrip = TestFrame::decrypted::<TestMessage>(frame, &crypto.cipher, None)?;
		assert_eq!(roundtrip, sample_message(), "the body decrypts to another message");
		Ok(())
	}
	cases {
		v1 => asn1::Version::V1,
		v2 => asn1::Version::V2,
		v3 => asn1::Version::V3,
	}
}

use tightbeam::builder::FrameBuilder;
use tightbeam::crypto::aead::{Aes128GcmOid, Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::SecurityProfile;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::der::Sequence;
use tightbeam::{Beamable, Version};

// Define a profile that expects AES-128-GCM
#[derive(Debug, Default, Clone, Copy)]
struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes128GcmOid; // Profile expects AES-128-GCM
	type SignatureAlg = Secp256k1Signature;
	#[cfg(feature = "kdf")]
	type KdfOid = tightbeam::crypto::kdf::HkdfSha3_256Oid;
	#[cfg(feature = "ecdh")]
	type CurveOid = tightbeam::crypto::curves::Secp256k1Oid;
}

// Create a message with a profile that expects AES-128-GCM
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile(Aes128Profile))]
struct Aes128Message {
	content: String,
}

fn main() {
	let message = Aes128Message { content: "test".to_string() };
	let (_, cipher) = tightbeam::testing::create_test_cipher_key();

	// Try to use AES-256-GCM cipher with a message that expects AES-128-GCM
	// This should fail to compile with compile-time enforcement
	let builder: FrameBuilder<Aes128Message> = Version::V1.into();
	builder
		.with_message(message)
		.with_id("test_algorithm_mismatch")
		.with_order(1696521600)
		// ERROR: OID mismatch! Should fail to compile
		.with_cipher::<Aes256GcmOid, Aes256Gcm>(&cipher);
}

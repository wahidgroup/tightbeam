use tightbeam::builder::FrameBuilder;
use tightbeam::crypto::aead::Aes256GcmOid;
use tightbeam::crypto::hash::{Sha3_256, Sha3_512};
use tightbeam::crypto::profiles::SecurityProfile;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::der::Sequence;
use tightbeam::{Beamable, Version};

// Define a profile that expects SHA3-256 digests
#[derive(Debug, Default, Clone, Copy)]
struct Sha3_256Profile;

impl SecurityProfile for Sha3_256Profile {
	type DigestOid = Sha3_256; // Profile expects SHA3-256
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	#[cfg(feature = "kdf")]
	type KdfOid = tightbeam::crypto::kdf::HkdfSha3_256Oid;
	#[cfg(feature = "ecdh")]
	type CurveOid = tightbeam::crypto::curves::Secp256k1Oid;
	#[cfg(feature = "kem")]
	type KemOid = tightbeam::crypto::kem::Kyber1024Oid;
}

// Create a message with a profile that expects SHA3-256
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile(Sha3_256Profile))]
struct DigestMessage {
	content: String,
}

fn main() {
	let message = DigestMessage { content: "test".to_string() };

	// Try to hash with SHA3-512 when the profile pins SHA3-256
	// This should fail to compile with compile-time enforcement
	let builder: FrameBuilder<DigestMessage> = Version::V1.into();
	builder
		.with_message(message)
		.with_id("test_digest_mismatch")
		.with_order(1696521600)
		// ERROR: digest OID mismatch! Should fail to compile
		.with_message_hasher::<Sha3_512>([]);
}

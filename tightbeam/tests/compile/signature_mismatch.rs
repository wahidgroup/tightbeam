use tightbeam::builder::FrameBuilder;
use tightbeam::crypto::aead::Aes256GcmOid;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::profiles::SecurityProfile;
use tightbeam::crypto::sign::ecdsa::Secp256k1Signature;
use tightbeam::crypto::sign::SignatureAlgorithmIdentifier;
use tightbeam::der::asn1::ObjectIdentifier;
use tightbeam::der::Sequence;
use tightbeam::{Beamable, Version};

// A signature algorithm distinct from the one the builder is asked to use
#[derive(Clone, Debug)]
struct OtherSignature;

impl SignatureAlgorithmIdentifier for OtherSignature {
	// ecdsa-with-SHA256; differs from tightbeam's SHA3-based secp256k1 OID
	const ALGORITHM_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
}

// Define a profile that expects OtherSignature
#[derive(Debug, Default, Clone, Copy)]
struct OtherSignatureProfile;

impl SecurityProfile for OtherSignatureProfile {
	type DigestOid = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = OtherSignature; // Profile expects OtherSignature
	#[cfg(feature = "kdf")]
	type KdfOid = tightbeam::crypto::kdf::HkdfSha3_256Oid;
	#[cfg(feature = "ecdh")]
	type CurveOid = tightbeam::crypto::curves::Secp256k1Oid;
	#[cfg(feature = "kem")]
	type KemOid = tightbeam::crypto::kem::Kyber1024Oid;
}

// Create a message with a profile that expects OtherSignature
#[derive(Beamable, Clone, Debug, PartialEq, Sequence)]
#[beam(profile(OtherSignatureProfile))]
struct SignatureMessage {
	content: String,
}

fn main() {
	let message = SignatureMessage { content: "test".to_string() };
	let signing_key = tightbeam::testing::create_test_signing_key();

	// Try to sign with secp256k1 when the profile pins OtherSignature
	// This should fail to compile with compile-time enforcement
	let builder: FrameBuilder<SignatureMessage> = Version::V1.into();
	builder
		.with_message(message)
		.with_id("test_signature_mismatch")
		.with_order(1696521600)
		// ERROR: signature OID mismatch! Should fail to compile
		.with_signer::<Secp256k1Signature, _>(signing_key);
}

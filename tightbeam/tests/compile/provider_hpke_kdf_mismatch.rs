use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::hpke::{DhKemKdf, DhKemSuite, HpkeKdf};
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::{HkdfSha3_256, KdfError};
use tightbeam::crypto::profiles::{
	AeadProvider, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use tightbeam::ZeroizingBytes;

// A second KDF, distinct from the KDF that the provider below runs.
struct OtherKdf;

impl HpkeKdf for OtherKdf {
	const KDF_ID: u16 = 0xFFF0;
	const EXTRACT_SIZE: usize = 32;

	fn extract(salt: &[u8], ikm: &[u8]) -> ZeroizingBytes {
		HkdfSha3_256::extract(salt, ikm)
	}

	fn expand(prk: &[u8], info: &[u8], len: usize) -> Result<ZeroizingBytes, KdfError> {
		HkdfSha3_256::expand(prk, info, len)
	}
}

impl DhKemKdf<Secp256k1> for OtherKdf {
	const KEM_ID: u16 = 0xFFF0;
}

// A profile that negotiates AES-256-GCM.
#[derive(Debug, Default, Clone, Copy)]
struct Aes256Profile;

impl SecurityProfile for Aes256Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type Curve = Secp256k1;
}

// A provider that runs that profile.
#[derive(Debug, Default, Clone, Copy)]
struct MismatchedProvider {
	profile: Aes256Profile,
}

impl DigestProvider for MismatchedProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for MismatchedProvider {
	type AeadCipher = Aes256Gcm;
}

impl SigningProvider for MismatchedProvider {
	type Signature = Secp256k1Signature;
	type SigningKey = Secp256k1SigningKey;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for MismatchedProvider {
	type Kdf = HkdfSha3_256;
}

impl CurveProvider for MismatchedProvider {
	type Curve = Secp256k1;
}

// ERROR: the KDF is HKDF-SHA3-256, and the HPKE suite derives with another KDF.
impl CryptoProvider for MismatchedProvider {
	type Profile = Aes256Profile;
	type HpkeSuite = DhKemSuite<Secp256k1, OtherKdf, Aes256Gcm>;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

fn main() {}

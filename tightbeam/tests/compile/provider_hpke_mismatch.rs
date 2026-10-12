use tightbeam::crypto::aead::{Aes128Gcm, Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::hpke::DhKemSuite;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{
	AeadProvider, CryptoProvider, CurveProvider, DigestProvider, KdfProvider, SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};

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

// ERROR: the cipher is AES-256-GCM, and the HPKE suite seals with AES-128-GCM.
impl CryptoProvider for MismatchedProvider {
	type Profile = Aes256Profile;
	type HpkeSuite = DhKemSuite<Secp256k1, HkdfSha3_256, Aes128Gcm>;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

fn main() {}

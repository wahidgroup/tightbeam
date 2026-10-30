use tightbeam::crypto::aead::{Aes128GcmOid, Aes256Gcm};
use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{
	AeadProvider, CryptoProvider, DigestProvider, KdfProvider, KeyExchangeProvider, SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};

// A profile that negotiates AES-128-GCM
#[derive(Debug, Default, Clone, Copy)]
struct Aes128Profile;

impl SecurityProfile for Aes128Profile {
	type Digest = Sha3_256;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<Secp256k1>;
	type KeyWrapOid = tightbeam::crypto::profiles::Aes256Wrap;
}

// A provider that runs AES-256-GCM under that profile
#[derive(Debug, Default, Clone, Copy)]
struct MismatchedProvider {
	profile: Aes128Profile,
}

impl DigestProvider for MismatchedProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for MismatchedProvider {
	type AeadCipher = Aes256Gcm;
}

impl SigningProvider for MismatchedProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for MismatchedProvider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for MismatchedProvider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

// ERROR: the profile negotiates AES-128-GCM, and the cipher is AES-256-GCM
impl tightbeam::crypto::profiles::KeyWrapProvider for MismatchedProvider {
	type KeyWrap = tightbeam::crypto::profiles::Aes256Wrap;
}

impl CryptoProvider for MismatchedProvider {
	type Profile = Aes128Profile;
	type Kem = tightbeam::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

fn main() {}

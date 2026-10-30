use tightbeam::crypto::aead::{Aes256Gcm, Aes256GcmOid};
use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::Sha3_256;
use tightbeam::crypto::k256::Secp256k1;
use tightbeam::crypto::kdf::HkdfSha3_256;
use tightbeam::crypto::profiles::{
	AeadProvider, Aes128Wrap, CryptoProvider, DigestProvider, KdfProvider, KeyExchangeProvider, KeyWrapProvider,
	SecurityProfile, SigningProvider,
};
use tightbeam::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};

// A profile that negotiates AES-256-GCM and AES-128 key wrap
#[derive(Debug, Default, Clone, Copy)]
struct ShortKekProfile;

impl SecurityProfile for ShortKekProfile {
	type Digest = Sha3_256;
	type AeadOid = Aes256GcmOid;
	type SignatureAlg = Secp256k1Signature;
	type Kdf = HkdfSha3_256;
	type KeyExchange = Ecdhe<Secp256k1>;
	type KeyWrapOid = Aes128Wrap;
}

// A provider that runs that profile
#[derive(Debug, Default, Clone, Copy)]
struct ShortKekProvider {
	profile: ShortKekProfile,
}

impl DigestProvider for ShortKekProvider {
	type Digest = Sha3_256;
}

impl AeadProvider for ShortKekProvider {
	type AeadCipher = Aes256Gcm;
}

// ERROR: a 16-octet KEK wraps the 32-octet key of AES-256-GCM (RFC 3565 §2.3.2)
impl KeyWrapProvider for ShortKekProvider {
	type KeyWrap = Aes128Wrap;
}

impl SigningProvider for ShortKekProvider {
	type Signature = Secp256k1Signature;
	type VerifyingKey = Secp256k1VerifyingKey;
}

impl KdfProvider for ShortKekProvider {
	type Kdf = HkdfSha3_256;
}

impl KeyExchangeProvider for ShortKekProvider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

impl CryptoProvider for ShortKekProvider {
	type Profile = ShortKekProfile;
	type Kem = tightbeam::crypto::hpke::DhKemSecp256k1;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

fn main() {}

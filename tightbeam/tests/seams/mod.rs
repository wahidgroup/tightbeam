//! Each seam an outside crate fills, built as that crate must build it,
//! through the public API of tightbeam alone.
//!
//! The outside provider writes its own parts, and takes the house AES-128 key
//! wrap through [`KeyWrapProvider`]:
//!
//! | Part | Seam |
//! | --- | --- |
//! | ECDSA over secp256k1 under `ecdsa-with-SHA3-512`, which refuses a high `s` | [`SigningProvider`] |
//! | HKDF over SHA3-512 under an identifier of its own arc | [`KdfProvider`] |
//! | The DHKEM over secp256k1 under a KEM identifier of its own | [`RecipientKem`] |
//! | A signing backend | [`SigningKeyProvider`] |
//! | A key-agreement backend that runs its own scalar product | [`DiffieHellman`] |
//! | AES-128-GCM under a cipher type of its own | [`ContentEncryption`] |
//! | A key wrap with `wrap` and `unwrap` alone, which [`OutsideWrapProvider`] names | [`KeyWrapAlgorithm`] |
//!
//! These suites run under the outside provider:
//!
//! - [`hpke`] and [`cms`] run both handshakes, under a provider that names no HPKE suite.
//! - [`kem`] brings a KEM whose private-key operation is not Diffie-Hellman.
//! - [`curves`] brings a curve decoder, which refuses its off-curve encodings at each key reader.
//! - [`colony`] runs two gateways, a hive, and its servlet, which each sign and verify under it.
//! - [`floor`] holds its strength floor at the TCP transport, and refuses a mixed pair.
//! - [`blocking`] runs a handshake and one exchange over the blocking TCP transport.
//! - [`curve`] brings providers on P-256, P-384, and P-521, which run both
//!   handshakes and a renewal, and three outside key exchanges. Its P-256 key
//!   signs a certificate that `cert!` issues under a P-256 signature type.
//!
//! These suites bring one part of the transport or the colony:
//!
//! - [`handshake`]: a client and a server orchestrator, which the TCP transport drives.
//! - [`listener`]: a blocking listener backend, which the house TCP listener serves.
//! - [`mux`]: a dispatch and a credit grantor, which the multiplexed transport runs.
//! - [`registry`]: the hive's servlet registry, which hands back each registration it replaces.
//! - [`restart`]: a restart policy and a jitter strategy, which a transport and a house backoff run.
//! - [`retry`]: the retry policy of a hive's scaling updates.
//! - [`router`]: a router policy, which decodes each frame through the requirements of its type.
//! - [`urn`]: a URN spec with components of its own, which `Urn::verify` reads a URN through.
//! - [`worker`]: a worker with no house runtime, which a servlet that drains ends through its kill.
//!
//! These suites bring one part of the trace or the test harness:
//!
//! - [`clock`]: a clock, which a trace stamps its events on and a validator reads validity periods on.
//! - [`csp`]: a process spec and a composition, which a scenario checks its run against.
//! - [`logging`]: a log backend, which a trace hands each record that its
//!   filter admits and the backend accepts.
//! - [`matcher`]: an expected value, which a scenario grades a frame against.
//! - [`scheduler`]: an exploration engine, which a run with a scheduler
//!   constraint hands the scheduled subject.

#[cfg(all(feature = "transport-hpke", feature = "tcp"))]
mod blocking;
#[cfg(feature = "instrument")]
mod clock;
#[cfg(feature = "transport-cms")]
mod cms;
mod colony;
#[cfg(feature = "testing-csp")]
mod csp;
#[cfg(all(feature = "transport-cms", feature = "transport-hpke"))]
mod curve;
mod curves;
#[cfg(all(feature = "transport-hpke", feature = "tcp", feature = "tokio"))]
mod floor;
mod frames;
#[cfg(all(feature = "transport-hpke", feature = "tcp", feature = "tokio"))]
mod handshake;
#[cfg(feature = "transport-hpke")]
mod hpke;
mod kem;
#[cfg(all(feature = "transport-hpke", feature = "tcp"))]
mod listener;
#[cfg(feature = "logging")]
mod logging;
mod matcher;
#[cfg(all(feature = "transport-multiplex", feature = "tcp", feature = "tokio"))]
mod mux;
mod registry;
#[cfg(all(feature = "tcp", feature = "tokio"))]
mod restart;
mod retry;
#[cfg(feature = "router")]
mod router;
#[cfg(feature = "testing-fault")]
mod scheduler;
mod servlet;
mod spec;
mod trust;
mod urn;
mod worker;

use std::sync::{Arc, LazyLock};

#[cfg(feature = "colony")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(all(feature = "tcp", feature = "tokio"))]
use std::net::SocketAddr;

use tightbeam::asn1::GcmParameters;
use tightbeam::builder::frame::FrameBuilder;
use tightbeam::builder::TypeBuilder;
use tightbeam::crypto::aead::aes_kw::KekAes256;
use tightbeam::crypto::aead::{
	AeadAlgorithm, AeadCore, AeadInPlace, Aes128Gcm, Aes128GcmOid, Error as AeadError, Key, KeyInit, KeySizeUser,
	Nonce, Tag,
};
use tightbeam::crypto::cms::{
	AuthEnvelopedData, ContentEncryption, Encapsulation, EnvelopeError, KemRecipient, KeyAgreementIdentity, Opener,
	Recipient, RecipientKem,
};
use tightbeam::crypto::common::typenum::U32;
use tightbeam::crypto::exchange::Ecdhe;
use tightbeam::crypto::hash::{Digest, Sha3_512};
use tightbeam::crypto::hpke::{DhKem, HkdfSha256};
use tightbeam::crypto::k256::ecdsa::{DerSignature, Signature, SigningKey, VerifyingKey};
use tightbeam::crypto::k256::elliptic_curve::point::AffineCoordinates;
use tightbeam::crypto::k256::{NonZeroScalar, PublicKey, Secp256k1};
use tightbeam::crypto::kdf::{Hkdf, KdfError, KdfFunction, KdfSalt};
use tightbeam::crypto::key::{DiffieHellman, KeyBackend, KeyError, Secp256k1KeyProvider, SigningKeyProvider};
use tightbeam::crypto::policy::ProviderPolicy;
use tightbeam::crypto::profiles::{
	AeadProvider, Aes128Wrap, Aes256Wrap, CryptoProvider, DefaultCryptoProvider, DigestProvider, KdfProvider, Kek,
	KeyExchangeProvider, KeyWrapAlgorithm, KeyWrapProvider, NoStrengthFloor, ProfileStrengthPolicy, SecurityProfile,
	SecurityProfileDesc, SigningProvider,
};
use tightbeam::crypto::secret::{SecretSlice, ToInsecure};
use tightbeam::crypto::sign::{
	CanonicalForm, CmsSigner, Error as SignatureError, PrehashSigner, PrehashVerifier, SignatureAlgorithmIdentifier,
	SignatureEncoding, SignedContent, SignerError, SigningIdentity, Verifier,
};
use tightbeam::crypto::x509::error::CertificateValidationError;
use tightbeam::crypto::x509::{KeyAgreement, KeyPurposes, PeerCertificate};
use tightbeam::der::asn1::{ObjectIdentifier, OctetString};
use tightbeam::der::oid::AssociatedOid;
use tightbeam::der::{Any, Encode};
use tightbeam::error::ReceivedExpectedError;
use tightbeam::marker::MaybeSendFuture;
use tightbeam::oids::{
	AES_128_GCM, AES_128_WRAP, CURVE_SECP256K1, DATA, SIGNER_ECDSA_WITH_SHA3_256, SIGNER_ECDSA_WITH_SHA3_512,
};
use tightbeam::random::CryptoRngCore;
use tightbeam::spki::{AlgorithmIdentifierOwned, Document, EncodePublicKey, SubjectPublicKeyInfoRef};
use tightbeam::testing::vectors::rfc3394::RFC_3394_4_3;
use tightbeam::testing::{unhex, EnvelopeRecipient, PublishedDraw, SeededStream, TestCertificate, TestMessage};
use tightbeam::trace::{ConsumedTrace, TraceCollector};
use tightbeam::urn::Urn;
use tightbeam::x509::ext::pkix::KeyUsages;
use tightbeam::x509::Certificate;
use tightbeam::zeroize::Zeroizing;
use tightbeam::{Frame, Version, ZeroizingBytes};

#[cfg(feature = "colony")]
use tightbeam::cms::signed_data::SignerIdentifier;
#[cfg(feature = "colony")]
use tightbeam::colony::hive::ServletBox;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::oids::HASH_SHA3_512;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::negotiation::RunnableProfile;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use tightbeam::transport::handshake::{
	Client, ClientFlow, Handshake, HandshakeMessage, HandshakeProvider, Server, ServerConfig, ServerFlow,
	SupportedProfiles,
};
#[cfg(feature = "transport-cms")]
use tightbeam::transport::handshake::{ClientConfig, Cms, CmsClientSettings, ProvisionedTrust};
#[cfg(all(feature = "tcp", feature = "tokio"))]
use tightbeam::transport::tcp::r#async::{TcpTransport, TokioListener, TokioStream};
#[cfg(all(feature = "tcp", feature = "tokio"))]
use tightbeam::transport::EndpointConfig;
#[cfg(all(feature = "tcp", feature = "tokio"))]
use tokio::net::TcpStream;

use crate::common::result::TestResult;
use crate::common::security::fixed_signing_key;

/// The identifier of the outside KEM, under an arc of its own.
const OUTSIDE_KEM: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.1");

/// The identifier of the outside KDF, under the same arc.
const OUTSIDE_KDF: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.3.2");

/// `id-ecPublicKey` (RFC 5480 §2.1.1), the algorithm of the key the outside
/// key-agreement backend holds.
const EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

/// The HPKE KEM identifier of the outside KEM, which its `suite_id` carries
/// in place of the registered `0x0016`.
const OUTSIDE_KEM_ID: u16 = 0xFE16;

/// The recipient key of the outside KEM's known answer.
const KNOWN_RECIPIENT_KEY: [u8; 32] = [0x2a; 32];

/// The `encryptedKey` of an outside KEM seal to [`KNOWN_RECIPIENT_KEY`] from
/// `SeededStream(0)`, computed with Python's `cryptography`: DHKEM(secp256k1,
/// HKDF-SHA256) under KEM identifier `0xFE16` (RFC 9180 §4.1), HKDF-SHA3-512
/// over the `CMSORIforKEMOtherInfo` for a 16-octet KEK, and AES-128 key wrap
/// of the content key `0x01` × 16.
const OUTSIDE_WRAPPED_KEY: &str = "c6c821278412285c30a481017736f88a21e472784d8b3180";

/// The content every envelope here seals.
const CONTENT: &[u8] = b"sealed under an outside provider";

/// The purpose label of the outside opening.
const UKM_LABEL: &[u8] = b"tb/test/outside/ukm/v1";

/// The seed of the key of a server identity, and of the one identity of a test
/// that holds one.
const SERVER_SEED: u8 = 0x31;

/// The seed of the key of a client identity, and of a second key of a test,
/// which differs from the key of [`SERVER_SEED`].
const CLIENT_SEED: u8 = 0x32;

/// The seed of the key that signs for a forged identity, which differs from
/// the key of each identity of a test.
const FORGING_SEED: u8 = 0x33;

/// The signature, the digest, and the KDF of the profile that a flow under
/// [`OutsideProvider`] agrees on.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
type AgreedAlgorithms = (Option<ObjectIdentifier>, Option<ObjectIdentifier>, Option<ObjectIdentifier>);

/// The algorithms of [`OutsideProfile`] that a flow agrees on.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
const OUTSIDE_ALGORITHMS: AgreedAlgorithms = (Some(SIGNER_ECDSA_WITH_SHA3_512), Some(HASH_SHA3_512), Some(OUTSIDE_KDF));

/// An ECDSA signature over secp256k1 under SHA3-512, in DER.
///
/// SHA3-512 stands in for SHA-256, whose type in this build names no OID, and
/// differs from the house digest.
#[derive(Clone, Debug)]
struct OutsideSignature(DerSignature);

impl TryFrom<&[u8]> for OutsideSignature {
	type Error = SignatureError;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		DerSignature::try_from(bytes).map(Self)
	}
}

impl From<OutsideSignature> for Box<[u8]> {
	fn from(signature: OutsideSignature) -> Self {
		signature.0.to_bytes()
	}
}

impl SignatureEncoding for OutsideSignature {
	type Repr = Box<[u8]>;
}

impl SignatureAlgorithmIdentifier for OutsideSignature {
	const ALGORITHM_OID: ObjectIdentifier = SIGNER_ECDSA_WITH_SHA3_512;
	type Digest = Sha3_512;
}

/// The canonical form is the DER form with a low `s`. It refuses a high `s`,
/// which the house form normalizes.
impl CanonicalForm for OutsideSignature {
	fn canonical(encoded: &[u8]) -> Result<Self, SignatureError> {
		let signature = Signature::from_der(encoded)?;
		let low = signature.normalize_s().is_none();
		low.then(|| Self(signature.to_der())).ok_or_else(SignatureError::new)
	}
}

/// The secp256k1 key that verifies an [`OutsideSignature`].
#[derive(Clone, Debug, PartialEq)]
struct OutsideVerifyingKey(VerifyingKey);

impl PrehashVerifier<OutsideSignature> for OutsideVerifyingKey {
	fn verify_prehash(&self, prehash: &[u8], signature: &OutsideSignature) -> Result<(), SignatureError> {
		self.0.verify_prehash(prehash, &signature.0)
	}
}

impl TryFrom<SubjectPublicKeyInfoRef<'_>> for OutsideVerifyingKey {
	type Error = tightbeam::spki::Error;

	fn try_from(spki: SubjectPublicKeyInfoRef<'_>) -> Result<Self, Self::Error> {
		VerifyingKey::try_from(spki).map(Self)
	}
}

/// The ECDSA check over the SHA3-512 digest of `message`, as
/// `ecdsa-with-SHA3-512` names it.
impl Verifier<OutsideSignature> for OutsideVerifyingKey {
	fn verify(&self, message: &[u8], signature: &OutsideSignature) -> Result<(), SignatureError> {
		let prehash = Sha3_512::digest(message);
		self.0.verify_prehash(&prehash, &signature.0)
	}
}

impl EncodePublicKey for OutsideVerifyingKey {
	fn to_public_key_der(&self) -> tightbeam::spki::Result<Document> {
		self.0.to_public_key_der()
	}
}

/// HKDF over SHA3-512 under an identifier of the outside arc, which differs
/// from the house HKDF-SHA3-256.
struct OutsideKdf;

impl AssociatedOid for OutsideKdf {
	const OID: ObjectIdentifier = OUTSIDE_KDF;
}

impl KdfFunction for OutsideKdf {
	fn derive_dynamic_key(
		ikm: &[u8],
		info: &[u8],
		salt: Option<KdfSalt<'_>>,
		key_size: usize,
	) -> Result<ZeroizingBytes, KdfError> {
		let mut key = Zeroizing::new(vec![0u8; key_size]);
		let salt = salt.map(|salt| salt.as_bytes());
		let expanded = Hkdf::<Sha3_512>::new(salt, ikm).expand(info, key.as_mut_slice());
		expanded.map_err(KdfError::DerivationFailed)?;
		Ok(key)
	}
}

/// The DHKEM over secp256k1 under HKDF-SHA256 and [`OUTSIDE_KEM_ID`], so its
/// shared secret differs from that of the house KEM.
type OutsideDhKem = DhKem<Secp256k1, HkdfSha256, OUTSIDE_KEM_ID>;

/// The outside KEM: [`OutsideDhKem`], named by an identifier of its own arc.
struct OutsideKem;

impl RecipientKem for OutsideKem {
	const OID: ObjectIdentifier = OUTSIDE_KEM;
	const USAGE: KeyUsages = KeyUsages::KeyAgreement;
	type PublicKey = PublicKey;
	type PrivateKey = dyn DiffieHellman<Secp256k1>;

	fn public_key(spki: SubjectPublicKeyInfoRef<'_>) -> Result<PublicKey, CertificateValidationError> {
		Ok(PublicKey::try_from(spki)?)
	}

	fn encapsulate(recipient: &PublicKey, rng: &mut dyn CryptoRngCore) -> Result<Encapsulation, EnvelopeError> {
		OutsideDhKem::encap_to(recipient, rng)
	}

	fn decapsulate<'a>(
		key: &'a dyn DiffieHellman<Secp256k1>,
		recipient: &'a PublicKey,
		kemct: &'a [u8],
	) -> MaybeSendFuture<'a, Result<ZeroizingBytes, EnvelopeError>> {
		OutsideDhKem::decap_through(key, recipient, kemct)
	}
}

/// The profile of [`OutsideProvider`].
#[derive(Debug, Default, Clone, Copy)]
struct OutsideProfile;

impl SecurityProfile for OutsideProfile {
	type Digest = Sha3_512;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = OutsideSignature;
	type Kdf = OutsideKdf;
	type KeyExchange = Ecdhe<Secp256k1>;
	type KeyWrapOid = Aes128Wrap;
}

/// AES-128-GCM as an outside crate brings it: a cipher type of its own over
/// the house cipher, with its own [`ContentEncryption`] under
/// `GCMParameters`. It seals and opens in place through the house cipher, so
/// a refused buffer keeps its contents.
struct OutsideGcm(Aes128Gcm);

impl KeySizeUser for OutsideGcm {
	type KeySize = <Aes128Gcm as KeySizeUser>::KeySize;
}

impl KeyInit for OutsideGcm {
	fn new(key: &Key<Self>) -> Self {
		Self(Aes128Gcm::new(key))
	}
}

impl AeadCore for OutsideGcm {
	type NonceSize = <Aes128Gcm as AeadCore>::NonceSize;
	type TagSize = <Aes128Gcm as AeadCore>::TagSize;
	type CiphertextOverhead = <Aes128Gcm as AeadCore>::CiphertextOverhead;
}

impl AeadInPlace for OutsideGcm {
	fn encrypt_in_place_detached(
		&self,
		nonce: &Nonce<Self>,
		associated_data: &[u8],
		buffer: &mut [u8],
	) -> Result<Tag<Self>, AeadError> {
		self.0.encrypt_in_place_detached(nonce, associated_data, buffer)
	}

	fn decrypt_in_place_detached(
		&self,
		nonce: &Nonce<Self>,
		associated_data: &[u8],
		buffer: &mut [u8],
		tag: &Tag<Self>,
	) -> Result<(), AeadError> {
		self.0.decrypt_in_place_detached(nonce, associated_data, buffer, tag)
	}
}

impl AeadAlgorithm for OutsideGcm {
	type Oid = Aes128GcmOid;
}

/// The `GCMParameters` of RFC 5084 §3.2, with the 16-octet tag of the cipher.
impl ContentEncryption for OutsideGcm {
	fn parameters(nonce: &Nonce<Self>) -> Result<Any, EnvelopeError> {
		let parameters = GcmParameters { aes_nonce: OctetString::new(nonce.as_slice())?, aes_icv_len: 16 };
		Ok(Any::encode_from(&parameters)?)
	}

	fn nonce(parameters: Option<&Any>) -> Result<Nonce<Self>, EnvelopeError> {
		let parameters = parameters.ok_or(EnvelopeError::ContentEncryptionAlgorithm)?;
		let parameters = parameters.decode_as::<GcmParameters>();
		let parameters = parameters.map_err(|_| EnvelopeError::ContentEncryptionAlgorithm)?;
		if parameters.aes_icv_len != 16 {
			return Err(EnvelopeError::TagLength((usize::from(parameters.aes_icv_len), 16).into()));
		}

		let nonce = parameters.aes_nonce.as_bytes().iter().copied();
		Nonce::<Self>::from_exact_iter(nonce).ok_or(EnvelopeError::ContentEncryptionAlgorithm)
	}
}

/// A key wrap an outside crate brings with `wrap` and `unwrap` alone, which
/// runs AES-256 key wrap (RFC 3394) on the typed key it receives, so the
/// provided `unwrap_into` serves it.
struct OutsideWrap;

impl KeyWrapAlgorithm for OutsideWrap {
	type Oid = Aes256Wrap;
	type KekSize = U32;

	fn wrap(kek: &Kek<'_, Self>, key: &[u8]) -> Result<Vec<u8>, KeyError> {
		let wrapped = KekAes256::new(kek.as_array()).wrap_vec(key);
		wrapped.map_err(KeyError::WrapFailed)
	}

	fn unwrap(kek: &Kek<'_, Self>, wrapped: &[u8]) -> Result<ZeroizingBytes, KeyError> {
		let unwrapped = KekAes256::new(kek.as_array()).unwrap_vec(wrapped);
		unwrapped.map(Zeroizing::new).map_err(KeyError::WrapFailed)
	}
}

/// The RFC 3394 §4.3 key-encryption key as the KEK of [`OutsideWrap`].
fn rfc_3394_kek() -> Kek<'static, OutsideWrap> {
	static KEK: LazyLock<Vec<u8>> = LazyLock::new(|| unhex(RFC_3394_4_3.kek));
	let kek = Kek::try_from(KEK.as_slice());
	kek.expect("the RFC 3394 §4.3 key-encryption key is 32 octets")
}

/// An outside wrap reads the typed key it receives, and wraps as RFC 3394
/// §4.3 does.
#[test]
fn an_outside_wrap_wraps_as_rfc_3394_4_3() -> TestResult {
	let kek = rfc_3394_kek();
	let wrapped = OutsideWrap::wrap(&kek, &unhex(RFC_3394_4_3.key_data))?;
	assert_eq!(wrapped, unhex(RFC_3394_4_3.ciphertext));
	Ok(())
}

/// The provided `unwrap_into` of an outside wrap copies the key its
/// `unwrap` returns into the caller's buffer.
#[test]
fn an_outside_wrap_unwraps_into_a_buffer_of_its_key_size() -> TestResult {
	let kek = rfc_3394_kek();
	let mut key = [0u8; 16];
	OutsideWrap::unwrap_into(&kek, &unhex(RFC_3394_4_3.ciphertext), &mut key)?;
	assert_eq!(key.as_slice(), unhex(RFC_3394_4_3.key_data).as_slice());
	Ok(())
}

/// The provided `unwrap_into` refuses a buffer whose size differs from the key.
#[test]
fn an_outside_wrap_refuses_a_buffer_of_another_size() {
	let kek = rfc_3394_kek();
	let mut key = [0u8; 32];
	let refused = OutsideWrap::unwrap_into(&kek, &unhex(RFC_3394_4_3.ciphertext), &mut key);
	let expected = ReceivedExpectedError { received: 32, expected: 16 };
	assert!(matches!(refused, Err(KeyError::WrapLength(found)) if found == expected));
}

/// A provider an outside crate defines: its own signature, KDF, KEM, and
/// AEAD cipher, beside the house AES-128 key wrap. Its AEAD key is 128 bits,
/// below the default floor, so it names [`NoStrengthFloor`] as its floor.
#[derive(Debug, Default, Clone, Copy)]
struct OutsideProvider {
	profile: OutsideProfile,
}

impl DigestProvider for OutsideProvider {
	type Digest = Sha3_512;
}

impl AeadProvider for OutsideProvider {
	type AeadCipher = OutsideGcm;
}

impl KeyWrapProvider for OutsideProvider {
	type KeyWrap = Aes128Wrap;
}

impl SigningProvider for OutsideProvider {
	type Signature = OutsideSignature;
	type VerifyingKey = OutsideVerifyingKey;
}

impl KdfProvider for OutsideProvider {
	type Kdf = OutsideKdf;
}

impl KeyExchangeProvider for OutsideProvider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

impl CryptoProvider for OutsideProvider {
	type Profile = OutsideProfile;
	type Kem = OutsideKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}

	fn strength_floor() -> &'static (dyn ProfileStrengthPolicy + Send + Sync) {
		&NoStrengthFloor
	}
}

/// The profile of [`OutsideWrapProvider`], which names the identifier of
/// [`OutsideWrap`] in place of AES-128 key wrap.
#[derive(Debug, Default, Clone, Copy)]
struct OutsideWrapProfile;

impl SecurityProfile for OutsideWrapProfile {
	type Digest = Sha3_512;
	type AeadOid = Aes128GcmOid;
	type SignatureAlg = OutsideSignature;
	type Kdf = OutsideKdf;
	type KeyExchange = Ecdhe<Secp256k1>;
	type KeyWrapOid = Aes256Wrap;
}

/// [`OutsideProvider`] with [`OutsideWrap`] as its key wrap, so each key wrap
/// of an envelope under it runs the wrap an outside crate writes.
#[derive(Debug, Default, Clone, Copy)]
struct OutsideWrapProvider {
	profile: OutsideWrapProfile,
}

impl DigestProvider for OutsideWrapProvider {
	type Digest = Sha3_512;
}

impl AeadProvider for OutsideWrapProvider {
	type AeadCipher = OutsideGcm;
}

impl KeyWrapProvider for OutsideWrapProvider {
	type KeyWrap = OutsideWrap;
}

impl SigningProvider for OutsideWrapProvider {
	type Signature = OutsideSignature;
	type VerifyingKey = OutsideVerifyingKey;
}

impl KdfProvider for OutsideWrapProvider {
	type Kdf = OutsideKdf;
}

impl KeyExchangeProvider for OutsideWrapProvider {
	type KeyExchange = Ecdhe<Secp256k1>;
}

impl CryptoProvider for OutsideWrapProvider {
	type Profile = OutsideWrapProfile;
	type Kem = OutsideKem;

	fn profile(&self) -> &Self::Profile {
		&self.profile
	}
}

/// The signing backend of an outside identity: it signs under
/// `ecdsa-with-SHA3-512`.
#[derive(Debug)]
struct OutsideKeyProvider {
	key: SigningKey,
}

impl KeyBackend for OutsideKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		AlgorithmIdentifierOwned { oid: SIGNER_ECDSA_WITH_SHA3_512, parameters: None }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.key.verifying_key().to_public_key_der()?.into_vec())
	}
}

impl SigningKeyProvider for OutsideKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<DerSignature, SignatureError> = self.key.sign_prehash(prehash);
		let signed = signed.map(|signature| signature.to_vec()).map_err(KeyError::from);
		Box::pin(async move { signed })
	}
}

impl OutsideKeyProvider {
	/// The outside key provider of `key`.
	fn of(key: SigningKey) -> Self {
		Self { key }
	}
}

/// The key-agreement backend of an outside identity: it holds a secp256k1
/// scalar and runs the Diffie-Hellman product itself, so the scalar stays
/// inside the backend.
struct OutsideAgreementBackend {
	scalar: NonZeroScalar,
}

/// The public key names the backend, and the scalar stays out of the output.
impl core::fmt::Debug for OutsideAgreementBackend {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_struct("OutsideAgreementBackend")
			.field("public_key", &self.public_key())
			.finish_non_exhaustive()
	}
}

impl OutsideAgreementBackend {
	/// The outside key-agreement backend of the scalar of `key`.
	fn of(key: &SigningKey) -> Self {
		Self { scalar: *key.as_nonzero_scalar() }
	}

	/// The public half of the scalar.
	fn public_key(&self) -> PublicKey {
		PublicKey::from_secret_scalar(&self.scalar)
	}
}

impl KeyBackend for OutsideAgreementBackend {
	/// `id-ecPublicKey` on secp256k1, the algorithm of the key the backend
	/// holds.
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		let parameters = Any::encode_from(&CURVE_SECP256K1).ok();
		AlgorithmIdentifierOwned { oid: EC_PUBLIC_KEY, parameters }
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		Ok(self.public_key().to_public_key_der()?.into_vec())
	}
}

/// The x-coordinate of the product of the backend's scalar and the peer
/// point (SEC 1 v2.0 §3.3.1).
impl DiffieHellman<Secp256k1> for OutsideAgreementBackend {
	fn agree<'a>(&'a self, peer: &'a PublicKey) -> MaybeSendFuture<'a, Result<SecretSlice<u8>, KeyError>> {
		let product = (peer.to_projective() * *self.scalar).to_affine();
		let agreed = SecretSlice::from(product.x().to_vec());
		Box::pin(async move { Ok(agreed) })
	}
}

/// An outside key provider whose signatures carry the high `s`, `n - s`, of
/// the low-`s` signature its key computes.
#[derive(Debug)]
struct HighSKeyProvider(OutsideKeyProvider);

impl KeyBackend for HighSKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.0.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.0.to_public_key_bytes()
	}
}

impl SigningKeyProvider for HighSKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		let signed: Result<Signature, SignatureError> = self.0.key.sign_prehash(prehash);
		let high = signed.and_then(|low| Signature::from_scalars(low.r(), -*low.s()));
		let high = high.map(|signature| signature.to_der().to_vec()).map_err(KeyError::from);
		Box::pin(async move { high })
	}
}

/// An outside key provider that declares the key of its certificate and signs
/// with another key, so each of its signatures fails against that certificate.
#[derive(Debug)]
struct ForgingKeyProvider {
	/// The backend of the key that the certificate names.
	declared: OutsideKeyProvider,
	/// The backend of the key that signs.
	signing: OutsideKeyProvider,
}

impl KeyBackend for ForgingKeyProvider {
	fn algorithm(&self) -> AlgorithmIdentifierOwned {
		self.declared.algorithm()
	}

	fn to_public_key_bytes(&self) -> Result<Vec<u8>, KeyError> {
		self.declared.to_public_key_bytes()
	}
}

impl SigningKeyProvider for ForgingKeyProvider {
	fn sign_prehash(&self, prehash: &[u8]) -> MaybeSendFuture<'_, Result<Vec<u8>, KeyError>> {
		self.signing.sign_prehash(prehash)
	}
}

/// The identity under [`OutsideProvider`] of `certificate` and its `key`.
pub(crate) fn outside_identity_of(certificate: Certificate, key: SigningKey) -> SigningIdentity {
	let provider = Arc::new(OutsideKeyProvider::of(key));
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider);
	identity.expect("the outside key matches its certificate and its algorithm")
}

/// The identity under [`OutsideProvider`] of `certificate` and its `key`,
/// whose signatures the key of [`FORGING_SEED`] makes.
pub(crate) fn forged_identity_of(certificate: Certificate, key: SigningKey) -> SigningIdentity {
	let signing = OutsideKeyProvider::of(fixed_signing_key(FORGING_SEED));
	let provider = Arc::new(ForgingKeyProvider { declared: OutsideKeyProvider::of(key), signing });
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider);
	identity.expect("the declared key matches its certificate and its algorithm")
}

/// An identity under [`OutsideProvider`], of the key whose scalar is
/// thirty-two `seed` octets.
fn outside_identity(seed: u8) -> SigningIdentity {
	let key = fixed_signing_key(seed);
	let certificate = TestCertificate::self_signed(&key);
	outside_identity_of(certificate, key)
}

/// An identity under [`OutsideProvider`] whose certificate names the key whose
/// scalar is thirty-two `seed` octets, and whose signatures another key makes.
fn forged_identity(seed: u8) -> SigningIdentity {
	let key = fixed_signing_key(seed);
	let certificate = TestCertificate::self_signed(&key);
	forged_identity_of(certificate, key)
}

/// The key-agreement identity under [`OutsideKem`] of `certificate` and its
/// key `key`, behind an [`OutsideAgreementBackend`].
fn outside_agreement_identity_of(certificate: Certificate, key: &SigningKey) -> KeyAgreementIdentity<OutsideKem> {
	let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(OutsideAgreementBackend::of(key));
	let identity = KeyAgreementIdentity::new(certificate, backend);
	identity.expect("the outside backend holds the key of its certificate")
}

/// A key-agreement identity under [`OutsideKem`], of the key whose scalar is
/// thirty-two `seed` octets, whose certificate asserts `keyAgreement`.
fn outside_agreement_identity(seed: u8) -> KeyAgreementIdentity<OutsideKem> {
	let key = fixed_signing_key(seed);
	let certificate = TestCertificate::self_signed(&key);
	outside_agreement_identity_of(certificate, &key)
}

/// The recipient under [`OutsideKem`] of `certificate`, admitted for key
/// agreement.
fn outside_recipient(certificate: Certificate) -> KemRecipient<OutsideKem> {
	let admitted = PeerCertificate::<KeyAgreement<OutsideKem>>::parse(certificate, KeyPurposes::HOUSE.server);
	let admitted = admitted.expect("the certificate asserts keyAgreement on a secp256k1 key");
	KemRecipient::from_certificate(admitted).expect("the certificate names its recipient")
}

/// Runs the three legs of `client` and `server` of flow `F` under the outside
/// provider `P`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn run_legs<P, F>(client: &mut Handshake<Client, F, P>, server: &mut Handshake<Server, F, P>)
where
	P: HandshakeProvider,
	F: ClientFlow<P> + ServerFlow<P>,
{
	let reply = replied(client, server).await;
	let closing = client.respond(reply).await.expect("the outside client closes");
	server.finish(closing).await.expect("the outside server admits the closing");
}

/// The reply of `server` to the opening of `client`.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn replied<P, F>(client: &mut Handshake<Client, F, P>, server: &mut Handshake<Server, F, P>) -> HandshakeMessage
where
	P: HandshakeProvider,
	F: ClientFlow<P> + ServerFlow<P>,
{
	let opening = client.start().expect("the client opens");
	let reply = server.reply(opening).await;
	reply.expect("the server replies to the opening")
}

/// The descriptor of the native profile of the provider `P`, the one profile
/// that a server of a seam test runs.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn native_profile<P: CryptoProvider>() -> SecurityProfileDesc {
	RunnableProfile::<P>::native().descriptor()
}

/// The configuration of a server of the flow `F` under the provider `P` that
/// holds `identity` and runs the native profile of `P` under the house key
/// purposes.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn native_server<F, P>(settings: F::Settings, identity: F::Identity) -> ServerConfig<F, P>
where
	F: ServerFlow<P>,
	P: HandshakeProvider,
{
	let profiles = SupportedProfiles::from(native_profile::<P>());
	let config = ServerConfig::<F, P>::new(settings, identity, profiles, KeyPurposes::HOUSE);
	config.expect("a test server identity serves the server role")
}

/// The configuration of a CMS client under the provider `P` that pins its
/// server through `trust` and presents `identity`.
#[cfg(feature = "transport-cms")]
fn cms_client<P: HandshakeProvider>(trust: ProvisionedTrust, identity: SigningIdentity) -> ClientConfig<Cms, P> {
	let settings = CmsClientSettings { trust, identity };
	let config = ClientConfig::<Cms, P>::new(settings, KeyPurposes::HOUSE);
	config.expect("a test client identity serves the client role")
}

/// The signature, the digest, and the KDF of the profile that `client`
/// agreed on, or `None` before it agrees on one.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn agreed_algorithms<F, P>(client: &Handshake<Client, F, P>) -> Option<AgreedAlgorithms>
where
	F: ClientFlow<P>,
	P: HandshakeProvider,
{
	let profile = client.selected_profile()?;
	Some((profile.signature, profile.digest, profile.kdf))
}

/// The certificate that the server of `pair` admitted as its client once the
/// three legs run, beside the first record that the client seals, as the
/// server opens it under its session keys.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn admitted_and_opened<P, F>(
	pair: (Handshake<Client, F, P>, Handshake<Server, F, P>),
) -> Result<(Option<Certificate>, Vec<u8>), Box<dyn core::error::Error>>
where
	P: HandshakeProvider,
	F: ClientFlow<P> + ServerFlow<P>,
{
	let (mut client, mut server) = pair;
	run_legs(&mut client, &mut server).await;

	let admitted = server.peer_certificate().cloned();
	let client_session = client.complete()?;
	let server_session = server.complete()?;

	let mut record = client_session.keys().send().encrypt_next(CONTENT)?.to_der()?;
	let opened = server_session.into_keys().recv_mut().open(&mut record)?;
	Ok((admitted, opened.to_vec()))
}

/// The first record that the client of `pair` seals once the three legs run,
/// as the server of `pair` opens it under its session keys.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
async fn first_record_opened<P, F>(
	pair: (Handshake<Client, F, P>, Handshake<Server, F, P>),
) -> Result<Vec<u8>, Box<dyn core::error::Error>>
where
	P: HandshakeProvider,
	F: ClientFlow<P> + ServerFlow<P>,
{
	let (_admitted, opened) = admitted_and_opened(pair).await?;
	Ok(opened)
}

/// [`CONTENT`] sealed under [`OutsideProvider`] to `recipient`.
fn outside_sealed(recipient: Recipient<'_, OutsideProvider>) -> AuthEnvelopedData {
	let sealed = AuthEnvelopedData::seal::<OutsideProvider>(recipient, DATA, CONTENT, [], None);
	sealed.expect("the content seals under the outside provider")
}

/// The content of `sealed`, which the holder of `identity` opens under the
/// provider `P` from the DER of the envelope as it arrives.
async fn opened_kem_seal<P>(
	identity: &KeyAgreementIdentity<P::Kem>,
	sealed: AuthEnvelopedData,
) -> Result<Vec<u8>, EnvelopeError>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	let opener: Opener<'_, P> = Opener::Kem { identity, ukm_label: UKM_LABEL };
	let arrived = sealed.to_der()?;

	let opened = sealed.open::<P>(arrived, &opener, DATA).await?;
	Ok(opened.to_insecure().to_vec())
}

/// A frame of version `version` that `identity` signed.
async fn signed_by(identity: &SigningIdentity, version: Version) -> Frame {
	let builder = FrameBuilder::from(version).with_id(b"signed-frame").with_order(1_696_521_600);
	let built = builder.with_message(TestMessage::sample(None)).build();
	let mut frame = built.expect("the frame builds");

	let signed = frame.sign_with_provider(identity).await;
	signed.expect("the identity signs the frame");
	frame
}

/// The trace of a run that records each of `labels` once, in order.
fn consumed_trace_of(labels: impl IntoIterator<Item = Urn<'static>>) -> ConsumedTrace {
	let collector = TraceCollector::new();
	for label in labels {
		let event = collector.event(label);
		event.expect("a collector with no fault model records each event").emit();
	}

	let mut trace = ConsumedTrace::new();
	trace.populate_from_collector(&collector);
	trace
}

/// A cleartext listener under the house provider on a loopback port, beside
/// the address it binds.
#[cfg(all(feature = "tcp", feature = "tokio"))]
async fn cleartext_listener() -> (TokioListener<DefaultCryptoProvider>, SocketAddr) {
	let bound = TokioListener::<DefaultCryptoProvider>::bind_cleartext("127.0.0.1:0").await;
	let listener = bound.expect("a loopback port binds");
	let addr = listener.local_addr().expect("a bound listener has an address");
	(listener, addr)
}

/// A cleartext client transport under the house provider, connected to
/// `addr`.
#[cfg(all(feature = "tcp", feature = "tokio"))]
async fn cleartext_client(addr: SocketAddr) -> TcpTransport<TokioStream, DefaultCryptoProvider> {
	let stream = TcpStream::connect(addr).await.expect("the client reaches the listener");
	TcpTransport::new(TokioStream::from(stream), EndpointConfig::<DefaultCryptoProvider>::cleartext())
}

/// A [`ServletBox`] an outside crate writes at `127.0.0.1:7100`, which marks
/// its stop.
///
/// A hive stops a servlet through [`ServletBox::stop_boxed`] alone, and the
/// probe keeps the default drain, which stops it there too, so the mark shows
/// each stop and each drain of the probe.
#[cfg(feature = "colony")]
struct StopProbe {
	/// The flag that the stop of the probe sets.
	stopped: Arc<AtomicBool>,
}

#[cfg(feature = "colony")]
impl StopProbe {
	/// A probe beside the flag that it sets when it stops.
	fn new() -> (Self, Arc<AtomicBool>) {
		let stopped = Arc::new(AtomicBool::new(false));
		let probe = Self { stopped: Arc::clone(&stopped) };
		(probe, stopped)
	}
}

#[cfg(feature = "colony")]
impl ServletBox for StopProbe {
	fn addr_bytes(&self) -> Arc<[u8]> {
		Arc::from(b"127.0.0.1:7100".as_slice())
	}

	fn stop_boxed(self: Box<Self>) {
		self.stopped.store(true, Ordering::SeqCst);
	}

	fn signer(&self) -> Option<&SignerIdentifier> {
		None
	}
}

/// An identity under the outside provider signs content, and the policy of
/// that provider verifies the signature.
#[tokio::test]
async fn an_outside_identity_signs_under_its_own_algorithm() -> TestResult {
	let identity = outside_identity(SERVER_SEED);
	let content = SignedContent::data(CONTENT);
	let signer_info = identity.sign(SignedContent::data(CONTENT)).await?;

	let policy = ProviderPolicy::<OutsideProvider>::default();
	CmsSigner::verify_with_policy(&signer_info, identity.signing_certificate(), &policy, content)?;
	Ok(())
}

/// A key that declares another algorithm pairs with no outside identity.
#[test]
fn with_provider_refuses_a_key_of_another_algorithm() {
	let key = fixed_signing_key(SERVER_SEED);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(Secp256k1KeyProvider::from(key));

	let refused = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider);
	assert!(matches!(refused, Err(SignerError::UnsupportedAlgorithm(oid)) if oid == SIGNER_ECDSA_WITH_SHA3_256));
}

/// A frame the outside identity signs verifies under the identity's own
/// policy, the check a gateway runs on a rumor it originates.
#[tokio::test]
async fn an_outside_identity_verifies_its_own_signature() -> TestResult {
	let identity = outside_identity(SERVER_SEED);
	let frame = signed_by(&identity, Version::V2).await;
	frame.verify_under(identity.signing_certificate(), identity.policy())?;
	Ok(())
}

/// A seal to the outside key-agreement identity under a `KEMRecipientInfo`
/// opens under the outside provider, through the outside backend's own
/// Diffie-Hellman product.
#[tokio::test]
async fn an_outside_provider_opens_its_kem_seal() -> TestResult {
	let identity = outside_agreement_identity(SERVER_SEED);
	let sealed = outside_sealed(Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL });

	let opened = opened_kem_seal::<OutsideProvider>(&identity, sealed).await?;
	assert_eq!(opened, CONTENT);
	Ok(())
}

/// The pairing constructor refuses an outside backend whose key differs from
/// the key of the certificate it pairs.
#[test]
fn a_key_agreement_identity_refuses_an_outside_backend_of_another_key() {
	let certificate = TestCertificate::self_signed(&fixed_signing_key(SERVER_SEED));
	let other = fixed_signing_key(CLIENT_SEED);
	let backend: Arc<dyn DiffieHellman<Secp256k1>> = Arc::new(OutsideAgreementBackend::of(&other));

	let refused = KeyAgreementIdentity::<OutsideKem>::new(certificate, backend);
	assert!(matches!(refused, Err(EnvelopeError::KeyMismatch)));
}

/// The key-agreement use refuses a point in the compact form before the
/// outside KEM reads the key, though the parse of that KEM decodes the form
/// (RFC 5480 §2.2).
#[test]
fn the_key_agreement_use_refuses_a_compact_point_for_an_outside_kem() -> TestResult {
	let key = SigningKey::from_bytes(&KNOWN_RECIPIENT_KEY.into())?;
	let compact = TestCertificate::with_compact_key(TestCertificate::self_signed(&key));

	let refused = PeerCertificate::<KeyAgreement<OutsideKem>>::parse(compact, KeyPurposes::HOUSE.server);
	assert!(matches!(refused, Err(CertificateValidationError::SpkiError(_))));
	Ok(())
}

/// A seal under a 16-octet KEK, the key size of AES-128 key wrap, opens under
/// the outside provider.
#[tokio::test]
async fn an_outside_provider_opens_its_kek_seal() -> TestResult {
	let kek = [0x24u8; 16];
	let kek = Kek::try_from(kek.as_slice())?;
	let sealed = outside_sealed(Recipient::Kek { kek, key_identifier: b"outside" });
	let opener = Opener::Kek { kek, key_identifier: b"outside" };
	let arrived = sealed.to_der()?;

	let opened = sealed.open::<OutsideProvider>(arrived, &opener, DATA).await?;
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// A seal under a provider that names [`OutsideWrap`] wraps its content key
/// through that wrap, and the open unwraps the key through it. The seal draws
/// the key data of RFC 3394 §4.3 as its content key, so its `encryptedKey` is
/// the ciphertext of that vector.
#[tokio::test]
async fn a_seal_wraps_its_content_key_through_an_outside_wrap() -> TestResult {
	let kek = rfc_3394_kek();
	let mut draw = PublishedDraw([unhex(RFC_3394_4_3.key_data), vec![0x5a; 12]].concat());
	let recipient = Recipient::Kek { kek, key_identifier: b"outside" };
	let sealed = AuthEnvelopedData::seal::<OutsideWrapProvider>(recipient, DATA, CONTENT, [], Some(&mut draw))?;
	let wrapped = frames::kek_recipient_of(&sealed).encrypted_key;
	let opener = Opener::Kek { kek, key_identifier: b"outside" };
	let arrived = sealed.to_der()?;

	let opened = sealed.open::<OutsideWrapProvider>(arrived, &opener, DATA).await?;
	assert_eq!(wrapped.as_bytes(), unhex(RFC_3394_4_3.ciphertext).as_slice());
	assert_eq!(opened.to_insecure().as_slice(), CONTENT);
	Ok(())
}

/// The outside seal names the algorithms of the outside provider:
/// AES-128-GCM, the outside KEM and KDF, and AES-128 key wrap.
#[test]
fn an_outside_seal_names_its_algorithms() {
	let identity = outside_agreement_identity(SERVER_SEED);
	let sealed = outside_sealed(Recipient::Kem { recipient: identity.recipient(), ukm_label: UKM_LABEL });
	let kem = sealed.kem_recipient();

	let cipher = sealed.auth_encrypted_content_info.content_enc_alg.oid;
	let named = (cipher, kem.kem.oid, kem.kdf.oid, kem.wrap.oid);
	assert_eq!(named, (AES_128_GCM, OUTSIDE_KEM, OUTSIDE_KDF, AES_128_WRAP));
}

/// An outside KEM seal wraps its content key under the KEK that the outside
/// KEM and the outside KDF derive. The seal draws the ephemeral scalar
/// `0x03` × 32 and the `ukm` random `0x04` × 32.
#[test]
fn an_outside_kem_seal_wraps_under_the_outside_derivation() -> TestResult {
	let key = SigningKey::from_bytes(&KNOWN_RECIPIENT_KEY.into())?;
	let recipient = outside_recipient(TestCertificate::self_signed(&key));
	let recipient = Recipient::Kem { recipient: &recipient, ukm_label: UKM_LABEL };
	let mut rng = SeededStream(0);
	let sealed = AuthEnvelopedData::seal::<OutsideProvider>(recipient, DATA, CONTENT, [], Some(&mut rng))?;

	let kem = sealed.kem_recipient();
	assert_eq!(kem.encrypted_key.as_bytes(), unhex(OUTSIDE_WRAPPED_KEY).as_slice());
	Ok(())
}

/// An outside identity refuses the high `s` its key returns, which the house
/// form would normalize.
#[tokio::test]
async fn an_outside_identity_refuses_a_high_s() -> TestResult {
	let key = fixed_signing_key(SERVER_SEED);
	let certificate = TestCertificate::self_signed(&key);
	let provider = Arc::new(HighSKeyProvider(OutsideKeyProvider::of(key)));
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, provider)?;

	let refused = identity.sign_prehash(&[0x5a; 64]).await;
	assert!(matches!(refused, Err(SignerError::Signature(_))));
	Ok(())
}

/// An outside identity shares the outside provider it holds, so a hive or a
/// gateway that takes the shared handle signs with the outside backend.
#[test]
fn an_outside_identity_shares_its_outside_provider() -> TestResult {
	let key = fixed_signing_key(SERVER_SEED);
	let certificate = TestCertificate::self_signed(&key);
	let provider: Arc<dyn SigningKeyProvider> = Arc::new(OutsideKeyProvider::of(key));
	let identity = SigningIdentity::with_provider::<OutsideProvider>(certificate, Arc::clone(&provider))?;

	let shared = identity.provider_arc();
	assert!(Arc::ptr_eq(&shared, &provider));
	Ok(())
}

/// The house provider refuses an outside seal, whose cipher is not its own,
/// before its key runs.
#[tokio::test]
async fn the_house_provider_refuses_an_outside_seal() -> TestResult {
	let outside_kek = [0x24u8; 16];
	let outside_kek = Kek::try_from(outside_kek.as_slice())?;
	let sealed = outside_sealed(Recipient::Kek { kek: outside_kek, key_identifier: b"outside" });
	let house_kek = [0x24u8; 32];
	let house_kek = Kek::try_from(house_kek.as_slice())?;
	let opener = Opener::Kek { kek: house_kek, key_identifier: b"outside" };
	let arrived = sealed.to_der()?;

	let refused = sealed.open::<DefaultCryptoProvider>(arrived, &opener, DATA).await;
	assert!(matches!(refused, Err(EnvelopeError::ContentEncryptionAlgorithm)));
	Ok(())
}

/// The DER of the descriptor of [`OutsideProfile`].
const OUTSIDE_DESCRIPTOR: &str = "304ba00b060960864801650304020aa10b0609608648016503040106a20b060960864801650304030ca3\
	0c060a2b06010401868d1f0302a40706052b8104000aa50b0609608648016503040105";

/// The descriptor of [`OutsideProfile`] encodes as [`OUTSIDE_DESCRIPTOR`].
#[test]
fn the_outside_descriptor_encodes_as_its_known_der() -> TestResult {
	let der = SecurityProfileDesc::from(&OutsideProfile).to_der()?;
	assert_eq!(der, unhex(OUTSIDE_DESCRIPTOR));
	Ok(())
}

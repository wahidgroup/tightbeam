// Re-exports
pub use aead::*;
#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};
#[cfg(feature = "transport")]
pub use aes_kw;

use core::result::Result as CoreResult;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::asn1::ObjectIdentifier;
use crate::constants::DEFAULT_REKEY_RECORD_LIMIT;
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::secret::SecretSlice;
use crate::der::asn1::{OctetString, OctetStringRef};
use crate::der::oid::AssociatedOid;
use crate::der::Any;
use crate::error::Result as TbResult;
use crate::oids::DATA;
use crate::{AlgorithmIdentifier, EncryptedContentInfo, TightBeamError};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

// OID wrapper types for AEAD ciphers
#[cfg(feature = "aes-gcm")]
mod oid_wrappers {
	crate::define_oid_wrapper!(
		/// AES-128-GCM cipher OID wrapper
		Aes128GcmOid,
		"2.16.840.1.101.3.4.1.6"
	);

	crate::define_oid_wrapper!(
		/// AES-256-GCM cipher OID wrapper
		/// Note: The `aes-gcm` crate does not implement `AssociatedOid` directly.
		Aes256GcmOid,
		"2.16.840.1.101.3.4.1.46"
	);
}

#[cfg(feature = "aes-gcm")]
pub use oid_wrappers::*;

/// Object-safe AEAD trait for runtime polymorphism.
///
/// This trait provides a minimal object-safe interface for AEAD operations,
/// allowing different cipher types to be stored in a single type (`RuntimeAead`).
trait AeadOps: Send + Sync {
	/// Encrypt plaintext with the given nonce.
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>, aead::Error>;

	/// Decrypt ciphertext with the given nonce.
	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> CoreResult<Vec<u8>, aead::Error>;

	/// Nonce length in bytes required by this AEAD.
	fn nonce_size(&self) -> usize;
}

/// Blanket implementation for all RustCrypto `Aead` types.
impl<A> AeadOps for A
where
	A: Aead + Send + Sync,
{
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>, aead::Error> {
		self.encrypt(nonce.into(), plaintext)
	}

	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> CoreResult<Vec<u8>, aead::Error> {
		self.decrypt(nonce.into(), ciphertext)
	}

	fn nonce_size(&self) -> usize {
		<A as AeadCore>::NonceSize::USIZE
	}
}

/// Runtime-polymorphic AEAD cipher wrapper.
///
/// This allows the handshake orchestrator (which knows `P::AeadCipher` at
/// compile time) to construct the appropriate cipher, then pass it to the
/// transport layer which stores it as a type-erased `RuntimeAead`. The OID
/// is stored alongside the cipher so encryption produces correct
/// `EncryptedContentInfo` structures.
///
/// The handshake negotiates the security profile and constructs the correct
/// concrete cipher type (e.g., `Aes256Gcm`, `Aes128Gcm`), then wraps it in
/// `RuntimeAead` for storage in the transport layer.
///
/// # Example
/// ```ignore
/// // In handshake orchestrator (knows P::AeadCipher at compile time)
/// let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;
/// let runtime_aead = RuntimeAead::new(cipher, AES_256_GCM_OID);
///
/// // Directional wrappers store RuntimeAead without knowing concrete type
/// let send_cipher = SendCipher::new(runtime_aead);
/// ```
pub struct RuntimeAead {
	cipher: Box<dyn AeadOps>,
	oid: ObjectIdentifier,
}

impl RuntimeAead {
	/// Construct a new RuntimeAead from any RustCrypto AEAD cipher.
	///
	/// # Parameters
	/// - `cipher`: The concrete AEAD cipher (e.g., `Aes256Gcm`)
	/// - `oid`: The algorithm OID for this cipher
	pub fn new<A>(cipher: A, oid: ObjectIdentifier) -> Self
	where
		A: Aead + Send + Sync + 'static,
	{
		Self { cipher: Box::new(cipher), oid }
	}

	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.oid
	}

	pub fn nonce_size(&self) -> usize {
		self.cipher.nonce_size()
	}
}

// ============================================================================
// Helper Functions for EncryptedContentInfo
// ============================================================================

/// Build an EncryptedContentInfo structure from components.
///
/// This helper encapsulates the common logic for constructing
/// EncryptedContentInfo from a ciphertext, nonce, content type, and
/// algorithm OID.
#[inline]
fn build_encrypted_content_info(
	ciphertext: Vec<u8>,
	nonce: &[u8],
	content_type: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
) -> TbResult<EncryptedContentInfo> {
	let content_type = content_type.unwrap_or(DATA);

	// Store the nonce in the algorithm parameters as an OctetString
	let nonce_octet_string = OctetString::new(nonce)?;
	let parameters = Some(Any::encode_from(&nonce_octet_string)?);

	let content_enc_alg = AlgorithmIdentifier { oid: algorithm_oid, parameters };
	let encrypted_content = Some(OctetString::new(ciphertext)?);

	Ok(EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
}

/// Extract nonce and ciphertext from EncryptedContentInfo.
///
/// Both slices borrow directly from `info`. The nonce length is validated
/// against `expected_nonce_len`: NIST SP 800-38D §8.2 fixes the GCM nonce at
/// the cipher's nonce size (96 bits for AES-GCM here).
#[inline]
fn extract_nonce_and_ciphertext(info: &EncryptedContentInfo, expected_nonce_len: usize) -> TbResult<(&[u8], &[u8])> {
	// Extract ciphertext
	let ciphertext = info
		.encrypted_content
		.as_ref()
		.ok_or(TightBeamError::MissingEncryptionInfo)?
		.as_bytes();

	// Extract nonce from algorithm parameters
	let nonce_any = info
		.content_enc_alg
		.parameters
		.as_ref()
		.ok_or(TightBeamError::MissingEncryptionInfo)?;

	// Borrow the nonce bytes out of the Any without an owned OctetString copy
	let nonce_octet_string: OctetStringRef<'_> = nonce_any.decode_as()?;
	let nonce = nonce_octet_string.as_bytes();
	if nonce.len() != expected_nonce_len {
		return Err(TightBeamError::InvalidNonceLength((nonce.len(), expected_nonce_len).into()));
	}

	Ok((nonce, ciphertext))
}

// ============================================================================
// Encryptor/Decryptor Traits
// ============================================================================

/// Trait for encrypting data and producing EncryptedContentInfo
///
/// An impl binds a cipher type to the algorithm OID stamped on the wire:
/// implement it only for canonically matched `(cipher, OID)` pairs (see the
/// AES-GCM impls). The trait stays unsealed so custom encryptors such as
/// ECIES remain possible.
pub trait Encryptor<C>
where
	C: AssociatedOid,
{
	/// Encrypt data and return the encrypted content info
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo>;
}

/// Trait for decrypting EncryptedContentInfo
pub trait Decryptor {
	/// Decrypt encrypted content info and return the plaintext bytes.
	/// The nonce is extracted from the algorithm parameters in the
	/// EncryptedContentInfo and validated against the cipher's nonce size.
	///
	/// Algorithm binding: [`RuntimeAead`] rejects a `content_enc_alg.oid`
	/// that differs from its negotiated OID. Bare RustCrypto `Aead` decrypt
	/// impls have no stored OID to compare against; encrypt-side binding is
	/// enforced by concrete [`Encryptor`] impls (cipher type -> canonical OID).
	///
	/// The plaintext is returned as a [`SecretSlice`] so it zeroizes on drop.
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>>;
}

/// Encrypt with a concrete AEAD and stamp the given algorithm OID.
fn encrypt_aead_content<A: Aead>(
	cipher: &A,
	data: impl AsRef<[u8]>,
	nonce: impl AsRef<[u8]>,
	content_type: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
) -> TbResult<EncryptedContentInfo> {
	let nonce_bytes = nonce.as_ref();
	let ciphertext = cipher.encrypt(nonce_bytes.into(), data.as_ref())?;
	build_encrypted_content_info(ciphertext, nonce_bytes, content_type, algorithm_oid)
}

// Concrete Encryptor impls bind each cipher to its canonical OID. A blanket
// `impl<C, A> Encryptor<C> for A` would let callers stamp an arbitrary OID on
// ciphertext from an unrelated cipher (CWE-345).
#[cfg(feature = "aes-gcm")]
impl Encryptor<Aes256GcmOid> for Aes256Gcm {
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		encrypt_aead_content(self, data, nonce, content_type, Aes256GcmOid::OID)
	}
}

#[cfg(feature = "aes-gcm")]
impl Encryptor<Aes128GcmOid> for Aes128Gcm {
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		encrypt_aead_content(self, data, nonce, content_type, Aes128GcmOid::OID)
	}
}

// Implement Decryptor for any AEAD cipher
impl<A> Decryptor for A
where
	A: Aead,
{
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>> {
		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(info, <A as AeadCore>::NonceSize::USIZE)?;
		let plaintext = self.decrypt(nonce_bytes.into(), ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

// Implement Encryptor for RuntimeAead (uses stored OID instead of generic C)
impl RuntimeAead {
	/// Encrypt data and return the encrypted content info.
	///
	/// This method is equivalent to `Encryptor::encrypt_content` but uses the
	/// runtime OID stored in this `RuntimeAead` instead of a compile-time generic.
	///
	/// # Nonce
	/// The caller supplies `nonce` and is responsible for its uniqueness. For
	/// GCM ciphers a `(key, nonce)` pair MUST never repeat.
	pub fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		let nonce_bytes = nonce.as_ref();
		let ciphertext = self.cipher.encrypt_bytes(nonce_bytes, data.as_ref())?;
		build_encrypted_content_info(ciphertext, nonce_bytes, content_type, self.oid)
	}
}

// Implement Decryptor for RuntimeAead (see trait docs for algorithm binding)
impl Decryptor for RuntimeAead {
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>> {
		// Bind the wire-declared algorithm to the negotiated cipher: a
		// mismatched OID must never reach key material (CWE-345).
		if info.content_enc_alg.oid != self.oid {
			return Err(TightBeamError::UnexpectedAlgorithm((info.content_enc_alg.oid, self.oid).into()));
		}

		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(info, self.cipher.nonce_size())?;
		let plaintext = self.cipher.decrypt_bytes(nonce_bytes, ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

// ============================================================================
// Directional Session Ciphers
// ============================================================================

/// Byte length of the invocation counter embedded in a counter nonce.
const COUNTER_LEN: usize = 8;

/// Extract the invocation counter from a counter nonce.
///
/// The deterministic construction of NIST SP 800-38D § 8.2.1 is used
/// with an all-zero fixed field and a big-endian 64-bit invocation counter
/// in the trailing bytes. The fixed field needs no validation here: the
/// nonce feeds the AEAD, so any tampering fails authentication.
fn parse_counter_nonce(nonce: &[u8]) -> TbResult<u64> {
	let nonce_len = nonce.len();
	let split_at = nonce_len
		.checked_sub(COUNTER_LEN)
		.ok_or(TightBeamError::InvalidNonceLength((nonce_len, COUNTER_LEN).into()))?;
	let (_, counter_bytes) = nonce.split_at(split_at);

	let mut counter = [0u8; COUNTER_LEN];
	counter.copy_from_slice(counter_bytes);
	let value = u64::from_be_bytes(counter);
	Ok(value)
}

/// Encode a counter value as a nonce of the given length.
fn build_counter_nonce(value: u64, nonce_len: usize) -> TbResult<Vec<u8>> {
	if nonce_len < COUNTER_LEN {
		return Err(TightBeamError::InvalidNonceLength((nonce_len, COUNTER_LEN).into()));
	}

	let mut nonce = vec![0u8; nonce_len];
	nonce[nonce_len - COUNTER_LEN..].copy_from_slice(&value.to_be_bytes());
	Ok(nonce)
}

/// Send-direction AEAD cipher with an owned monotonic counter nonce.
///
/// Each encryption consumes the next counter value as its nonce, so a
/// `(key, nonce)` pair can never repeat for the lifetime of the key. The
/// deterministic construction is exempt from the 2^32 invocation cap that
/// NIST SP 800-38D § 8.3 places on random IVs.
///
/// The operative bound is the record limit (RFC 9846 § 5.5: AES-GCM keeps its
/// authenticated-encryption safety margin for about 2^24.5 full-size records
/// per key. RFC 9846 makes acting before the limit a MUST). Encryption fails
/// closed with [`TightBeamError::RekeyRequired`] at
/// [`DEFAULT_REKEY_RECORD_LIMIT`](crate::constants::DEFAULT_REKEY_RECORD_LIMIT):
/// receipt-bearing multiplexed sessions renew keys in band before the limit,
/// while every other session must be reestablished for fresh directional keys.
pub struct SendCipher {
	aead: RuntimeAead,
	counter: AtomicU64,
	rekey_limit: u64,
}

impl SendCipher {
	/// Nonce counter starts at zero.
	pub fn new(aead: RuntimeAead) -> Self {
		Self { aead, counter: AtomicU64::new(0), rekey_limit: DEFAULT_REKEY_RECORD_LIMIT }
	}

	/// Override the record limit at which encryption demands a rekey.
	///
	/// Clamped to
	/// [`DEFAULT_REKEY_RECORD_LIMIT`](crate::constants::DEFAULT_REKEY_RECORD_LIMIT):
	/// the AES-GCM bound (RFC 9846 § 5.5) is MUST that no configuration may raise.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit.min(DEFAULT_REKEY_RECORD_LIMIT);
		self
	}

	/// Record limit this cipher halts at.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// Records still encryptable before the rekey limit halts this cipher.
	pub fn remaining_records(&self) -> u64 {
		let used = self.counter.load(Ordering::Relaxed);
		self.rekey_limit.saturating_sub(used)
	}

	/// Encrypt data under the next counter nonce.
	///
	/// # Errors
	/// - `RekeyRequired`: Limit reached. Reestablish the session for fresh keys
	/// - `NonceExhausted`: the 64-bit counter space is spent
	/// - `InvalidNonceLength`: the cipher nonce is too small to carry the counter
	pub fn encrypt_next(
		&self,
		data: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		// The failed update leaves the counter parked at the limit, so
		// every subsequent call fails instead of wrapping into nonce reuse.
		let reserve = |value: u64| {
			if value >= self.rekey_limit {
				return None;
			}

			value.checked_add(1)
		};
		let reserved = self
			.counter
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, reserve)
			.map_err(|spent| {
				if spent == u64::MAX {
					return TightBeamError::NonceExhausted;
				}

				TightBeamError::RekeyRequired
			})?;

		let nonce = build_counter_nonce(reserved, self.aead.nonce_size())?;
		let encrypted_info = self.aead.encrypt_content(data, &nonce, content_type)?;
		Ok(encrypted_info)
	}

	#[cfg(test)]
	fn with_counter(aead: RuntimeAead, counter: u64) -> Self {
		Self { aead, counter: AtomicU64::new(counter), rekey_limit: DEFAULT_REKEY_RECORD_LIMIT }
	}
}

/// Receive-direction AEAD cipher enforcing exactly sequential counter nonces.
///
/// The peer's [`SendCipher`] emits counter nonces in order over an ordered
/// transport, so the next message must carry exactly the next counter. Any
/// other value is a replay, reorder, or deletion and is rejected. Matching
/// the receiver-side sequence discipline of RFC 9846 § 5.3: an active
/// attacker excising an envelope from the stream desynchronizes the counter
/// and is detected on the very next message (CWE-345).
///
/// The receive direction enforces the AES-GCM per-key volume bound: an
/// honest peer halts or renews its [`SendCipher`] at
/// [`DEFAULT_REKEY_RECORD_LIMIT`](crate::constants::DEFAULT_REKEY_RECORD_LIMIT),
/// so a counter at or past that bound means the peer ignored the record
/// limit (RFC 9846 § 5.5) and decryption fails closed with
/// [`TightBeamError::RekeyRequired`]. The configurable rekey limit is a
/// renewal-trigger threshold only and never refuses records under the bound.
pub struct RecvCipher {
	aead: RuntimeAead,
	/// Exact counter value the next message must carry.
	expected_counter: AtomicU64,
	rekey_limit: u64,
}

impl RecvCipher {
	/// Expected counter starts at zero.
	pub fn new(aead: RuntimeAead) -> Self {
		Self {
			aead,
			expected_counter: AtomicU64::new(0),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Override the record threshold `remaining_records` counts down
	/// from, driving receive-direction renewal and drain triggers.
	///
	/// Trigger policy: decryption refuses records at the AES-GCM volume bound
	/// ([`DEFAULT_REKEY_RECORD_LIMIT`](crate::constants::DEFAULT_REKEY_RECORD_LIMIT))
	/// regardless of this value, so a threshold below the peer's send
	/// limit can never refuse legitimate records.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit;
		self
	}

	/// Renewal-trigger threshold `remaining_records` counts down from.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// Records still readable under the renewal-trigger threshold.
	///
	/// Tracks the peer's send counter on the ordered channel, so a rekey
	/// initiator can watch the receive direction without any wire addition.
	pub fn remaining_records(&self) -> u64 {
		let expected = self.expected_counter.load(Ordering::Relaxed);
		self.rekey_limit.saturating_sub(expected)
	}
}

impl Decryptor for RecvCipher {
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>> {
		let (nonce_bytes, _) = extract_nonce_and_ciphertext(info, self.aead.nonce_size())?;
		let counter = parse_counter_nonce(nonce_bytes)?;

		// Fail closed once the counter passes the AES-GCM per-key volume
		// bound (RFC 9846 § 5.5): an honest sender halts or renews its
		// cipher before this counter exists. The configurable rekey
		// limit is a renewal-trigger threshold, not a refusal bound.
		if counter >= DEFAULT_REKEY_RECORD_LIMIT {
			return Err(TightBeamError::RekeyRequired);
		}

		// Cheap pre-check so forged counters never reach the AEAD. The
		// authoritative check is the compare-exchange after authentication.
		let expected = self.expected_counter.load(Ordering::Relaxed);
		if counter != expected {
			return Err(TightBeamError::NonceReplayed((counter, expected).into()));
		}

		let plaintext = self.aead.decrypt_content(info)?;

		// Advance only after successful authentication, otherwise a forged
		// counter could block all future legitimate messages.
		let next = counter.checked_add(1).ok_or(TightBeamError::NonceExhausted)?;
		self.expected_counter
			.compare_exchange(counter, next, Ordering::Relaxed, Ordering::Relaxed)
			.map_err(|current| TightBeamError::NonceReplayed((counter, current).into()))?;

		Ok(plaintext)
	}
}

/// Role-mapped directional session keys produced by handshake completion.
///
/// The handshake derives one client-to-server and one server-to-client key
/// (RFC 9846 § 7.3 precedent). Each endpoint sends on its own direction and
/// receives on the peer's, so counter nonces never collide across directions.
pub struct SessionKeys {
	send: SendCipher,
	recv: RecvCipher,
}

impl SessionKeys {
	/// Map directional ciphers for the client role (send = client-to-server).
	pub fn for_client<A>(client_to_server: A, server_to_client: A, oid: ObjectIdentifier) -> Self
	where
		A: Aead + Send + Sync + 'static,
	{
		Self {
			send: SendCipher::new(RuntimeAead::new(client_to_server, oid)),
			recv: RecvCipher::new(RuntimeAead::new(server_to_client, oid)),
		}
	}

	/// Map directional ciphers for the server role (send = server-to-client).
	pub fn for_server<A>(client_to_server: A, server_to_client: A, oid: ObjectIdentifier) -> Self
	where
		A: Aead + Send + Sync + 'static,
	{
		Self {
			send: SendCipher::new(RuntimeAead::new(server_to_client, oid)),
			recv: RecvCipher::new(RuntimeAead::new(client_to_server, oid)),
		}
	}

	pub fn send(&self) -> &SendCipher {
		&self.send
	}

	pub fn recv(&self) -> &RecvCipher {
		&self.recv
	}

	/// Split into exclusive send and receive halves for transport ownership.
	pub fn into_parts(self) -> (SendCipher, RecvCipher) {
		(self.send, self.recv)
	}
}

#[cfg(all(test, feature = "aes-gcm"))]
mod tests {
	use super::*;
	use crate::der::asn1::OctetString;
	use crate::der::Any;
	use crate::error::ReceivedExpectedError;
	use crate::oids::{AES_128_GCM, AES_256_GCM};

	const NONCE: [u8; 12] = [0x24; 12];
	const PLAINTEXT: &[u8] = b"aead round trip";

	fn test_cipher() -> Aes256Gcm {
		Aes256Gcm::new(&[0x42u8; 32].into())
	}

	fn encrypted_info() -> EncryptedContentInfo {
		Encryptor::<Aes256GcmOid>::encrypt_content(&test_cipher(), PLAINTEXT, NONCE, None)
			.expect("fixture encryption with a fixed key and nonce")
	}

	fn stamped_oid<C, A>(cipher: &A) -> ObjectIdentifier
	where
		C: AssociatedOid,
		A: Encryptor<C>,
	{
		let info = Encryptor::<C>::encrypt_content(cipher, PLAINTEXT, NONCE, None)
			.expect("fixture encryption with a fixed key and nonce");
		info.content_enc_alg.oid
	}

	#[test]
	fn encryptor_stamps_canonical_aes256_oid() {
		assert_eq!(stamped_oid::<Aes256GcmOid, _>(&test_cipher()), Aes256GcmOid::OID);
	}

	#[test]
	fn encryptor_stamps_canonical_aes128_oid() {
		let cipher = Aes128Gcm::new(&[0x42u8; 16].into());
		assert_eq!(stamped_oid::<Aes128GcmOid, _>(&cipher), Aes128GcmOid::OID);
	}

	/// Re-encode the algorithm parameters with a nonce of the given length.
	fn with_nonce_len(mut info: EncryptedContentInfo, len: usize) -> EncryptedContentInfo {
		let nonce = OctetString::new(vec![0x24; len]).expect("fixture nonce fits an OCTET STRING");
		info.content_enc_alg.parameters = Some(Any::encode_from(&nonce).expect("fixture nonce re-encodes as DER"));
		info
	}

	#[test]
	fn decrypt_content_round_trips() -> TbResult<()> {
		let plaintext = test_cipher().decrypt_content(&encrypted_info())?;
		assert!(plaintext.with(|p| p == PLAINTEXT)?);
		Ok(())
	}

	#[test]
	fn decrypt_content_rejects_short_nonce() {
		let info = with_nonce_len(encrypted_info(), 8);
		let result = test_cipher().decrypt_content(&info);
		assert!(matches!(
			result,
			Err(TightBeamError::InvalidNonceLength(ReceivedExpectedError {
				received: 8,
				expected: 12
			}))
		));
	}

	#[test]
	fn decrypt_content_rejects_long_nonce() {
		let info = with_nonce_len(encrypted_info(), 16);
		let result = test_cipher().decrypt_content(&info);
		assert!(matches!(
			result,
			Err(TightBeamError::InvalidNonceLength(ReceivedExpectedError {
				received: 16,
				expected: 12
			}))
		));
	}

	#[test]
	fn runtime_aead_round_trips() -> TbResult<()> {
		let runtime = RuntimeAead::new(test_cipher(), AES_256_GCM);
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;

		let plaintext = runtime.decrypt_content(&info)?;
		assert!(plaintext.with(|p| p == PLAINTEXT)?);
		Ok(())
	}

	#[test]
	fn runtime_aead_rejects_algorithm_oid_mismatch() -> TbResult<()> {
		let runtime = RuntimeAead::new(test_cipher(), AES_256_GCM);
		let mut info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;
		info.content_enc_alg.oid = AES_128_GCM;

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::UnexpectedAlgorithm(_))));
		Ok(())
	}

	#[test]
	fn runtime_aead_rejects_wire_nonce_length() -> TbResult<()> {
		let runtime = RuntimeAead::new(test_cipher(), AES_256_GCM);
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;
		let info = with_nonce_len(info, 8);

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::InvalidNonceLength(_))));
		Ok(())
	}

	fn test_runtime() -> RuntimeAead {
		RuntimeAead::new(test_cipher(), AES_256_GCM)
	}

	#[test]
	fn send_cipher_counter_nonces_increment() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let second = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime());
		let first_plain = receiver.decrypt_content(&first)?;
		let second_plain = receiver.decrypt_content(&second)?;
		assert!(first_plain.with(|p| p == PLAINTEXT)?);
		assert!(second_plain.with(|p| p == PLAINTEXT)?);
		Ok(())
	}

	#[test]
	fn recv_cipher_rejects_replayed_nonce() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let info = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime());
		receiver.decrypt_content(&info)?;

		let replay = receiver.decrypt_content(&info);
		assert!(matches!(
			replay,
			Err(TightBeamError::NonceReplayed(ReceivedExpectedError {
				received: 0,
				expected: 1
			}))
		));
		Ok(())
	}

	#[test]
	fn recv_cipher_rejects_reordered_nonce() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let second = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime());
		let early = receiver.decrypt_content(&second);
		assert!(matches!(
			early,
			Err(TightBeamError::NonceReplayed(ReceivedExpectedError {
				received: 1,
				expected: 0
			}))
		));

		// Rejection advances nothing: the legitimate sequence still decrypts.
		receiver.decrypt_content(&first)?;
		receiver.decrypt_content(&second)?;
		Ok(())
	}

	#[test]
	fn recv_cipher_detects_deleted_message() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let _deleted = sender.encrypt_next(PLAINTEXT, None)?;
		let third = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime());
		receiver.decrypt_content(&first)?;

		// An attacker excising the middle envelope desynchronizes the
		// counter. The very next message exposes the deletion.
		let gapped = receiver.decrypt_content(&third);
		assert!(matches!(
			gapped,
			Err(TightBeamError::NonceReplayed(ReceivedExpectedError {
				received: 2,
				expected: 1
			}))
		));
		Ok(())
	}

	#[test]
	fn send_cipher_fails_closed_on_counter_exhaustion() {
		let sender = SendCipher::with_counter(test_runtime(), u64::MAX);
		let exhausted = sender.encrypt_next(PLAINTEXT, None);
		assert!(matches!(exhausted, Err(TightBeamError::NonceExhausted)));

		let still_exhausted = sender.encrypt_next(PLAINTEXT, None);
		assert!(matches!(still_exhausted, Err(TightBeamError::NonceExhausted)));
	}

	#[test]
	fn send_cipher_fails_closed_at_rekey_limit() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime()).with_rekey_limit(2);
		sender.encrypt_next(PLAINTEXT, None)?;
		sender.encrypt_next(PLAINTEXT, None)?;

		let limited = sender.encrypt_next(PLAINTEXT, None);
		assert!(matches!(limited, Err(TightBeamError::RekeyRequired)));

		let still_limited = sender.encrypt_next(PLAINTEXT, None);
		assert!(matches!(still_limited, Err(TightBeamError::RekeyRequired)));
		Ok(())
	}

	#[test]
	fn send_cipher_clamps_rekey_limit_to_volume_bound() {
		let sender = SendCipher::new(test_runtime()).with_rekey_limit(u64::MAX);
		assert_eq!(sender.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
	}

	#[test]
	fn recv_cipher_threshold_never_refuses_records() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let second = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime()).with_rekey_limit(1);
		receiver.decrypt_content(&first)?;
		assert_eq!(receiver.remaining_records(), 0);

		receiver.decrypt_content(&second)?;
		Ok(())
	}

	#[test]
	fn recv_cipher_fails_closed_at_volume_bound() -> TbResult<()> {
		let runtime = test_runtime();
		let nonce = build_counter_nonce(DEFAULT_REKEY_RECORD_LIMIT, runtime.nonce_size())?;
		let over_bound = runtime.encrypt_content(PLAINTEXT, &nonce, None)?;

		let receiver = RecvCipher::new(test_runtime());
		let refused = receiver.decrypt_content(&over_bound);
		assert!(matches!(refused, Err(TightBeamError::RekeyRequired)));
		Ok(())
	}

	#[test]
	fn send_cipher_reports_remaining_records() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime()).with_rekey_limit(2);
		assert_eq!(sender.remaining_records(), 2);

		sender.encrypt_next(PLAINTEXT, None)?;
		assert_eq!(sender.remaining_records(), 1);
		Ok(())
	}

	fn directional_pair() -> (SessionKeys, SessionKeys) {
		let oid = AES_256_GCM;
		let c2s_key = [0x11u8; 32];
		let s2c_key = [0x22u8; 32];
		let client = SessionKeys::for_client(Aes256Gcm::new(&c2s_key.into()), Aes256Gcm::new(&s2c_key.into()), oid);
		let server = SessionKeys::for_server(Aes256Gcm::new(&c2s_key.into()), Aes256Gcm::new(&s2c_key.into()), oid);
		(client, server)
	}

	#[test]
	fn session_keys_role_map_is_complementary() -> TbResult<()> {
		let (client, server) = directional_pair();

		let request = client.send().encrypt_next(PLAINTEXT, None)?;
		let request_plain = server.recv().decrypt_content(&request)?;
		assert!(request_plain.with(|p| p == PLAINTEXT)?);

		let response = server.send().encrypt_next(PLAINTEXT, None)?;
		let response_plain = client.recv().decrypt_content(&response)?;
		assert!(response_plain.with(|p| p == PLAINTEXT)?);
		Ok(())
	}

	#[test]
	fn session_keys_directions_use_distinct_keys() -> TbResult<()> {
		let (client, server) = directional_pair();

		// A request must not decrypt under the response direction even though
		// both start at counter zero.
		let request = client.send().encrypt_next(PLAINTEXT, None)?;
		let crossed = client.recv().decrypt_content(&request);
		assert!(crossed.is_err());

		let response = server.send().encrypt_next(PLAINTEXT, None)?;
		let crossed = server.recv().decrypt_content(&response);
		assert!(crossed.is_err());
		Ok(())
	}
}

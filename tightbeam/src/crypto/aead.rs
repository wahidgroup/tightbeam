//! AEAD ciphers, their algorithm identifiers, and the session ciphers that
//! own the counter nonces.
//!
//! - [`AeadAlgorithm`] binds a cipher type to its OID and its key size.
//! - [`RuntimeAead`] erases the cipher type so the transport can store it.
//! - [`Encryptor`], [`Decryptor`], and [`DecryptContent`] move bytes in and out
//!   of CMS [`EncryptedContentInfo`].
//! - [`SendCipher`] and [`RecvCipher`] own one direction's counter nonces and its record limit.
//! - [`SessionKeys`] maps [`DirectionalCiphers`] onto the client or server role.

pub use aead::{Aead, AeadCore, Error, Key, KeyInit, Nonce, Payload};
#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};
#[cfg(feature = "transport")]
pub use aes_kw;

use core::result::Result as CoreResult;

use aead::KeySizeUser;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::asn1::ObjectIdentifier;
use crate::constants::{rekey_record_limit, AES_GCM_VOLUME_BYTES_PER_KEY, DEFAULT_REKEY_RECORD_LIMIT};
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

#[cfg(feature = "aes-gcm")]
mod oid_wrappers {
	crate::define_oid_wrapper!(
		/// The AES-128-GCM algorithm OID.
		///
		/// The `aes-gcm` crate leaves `AssociatedOid` to this wrapper.
		Aes128GcmOid,
		"2.16.840.1.101.3.4.1.6"
	);

	crate::define_oid_wrapper!(
		/// The AES-256-GCM algorithm OID.
		///
		/// The `aes-gcm` crate leaves `AssociatedOid` to this wrapper.
		Aes256GcmOid,
		"2.16.840.1.101.3.4.1.46"
	);
}

#[cfg(feature = "aes-gcm")]
pub use oid_wrappers::*;

/// An AEAD cipher and the algorithm identifier it runs under.
///
/// The cipher type is the one home for both facts a peer needs about it: the
/// OID stamped on each ciphertext and, through [`KeySizeUser`], the key length.
/// Every other view of an AEAD algorithm reads them from here.
pub trait AeadAlgorithm: Aead + KeySizeUser {
	/// The algorithm identifier this cipher encrypts under.
	type Oid: AssociatedOid;
}

#[cfg(feature = "aes-gcm")]
impl AeadAlgorithm for Aes128Gcm {
	type Oid = Aes128GcmOid;
}

#[cfg(feature = "aes-gcm")]
impl AeadAlgorithm for Aes256Gcm {
	type Oid = Aes256GcmOid;
}

/// The object-safe AEAD surface behind [`RuntimeAead`].
///
/// A trait object of it lets one type hold any cipher type.
trait AeadOps: Send + Sync {
	/// Encrypt plaintext with the given nonce.
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>, aead::Error>;

	/// Decrypt ciphertext with the given nonce.
	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> CoreResult<Vec<u8>, aead::Error>;

	/// The nonce length in bytes that this AEAD requires.
	fn nonce_size(&self) -> usize;
}

/// Borrows `nonce` at the cipher's nonce length.
///
/// The object-safe surface carries a plain slice, so a wrong length is
/// representable at the call. Converting here returns the AEAD's own
/// error for it, which the cipher methods already propagate.
trait SizedNonce: AeadCore {
	fn sized_nonce<'a>(&self, nonce: &'a [u8]) -> CoreResult<&'a aead::Nonce<Self>, aead::Error> {
		if nonce.len() != <Self as AeadCore>::NonceSize::USIZE {
			return Err(aead::Error);
		}

		Ok(aead::Nonce::<Self>::from_slice(nonce))
	}
}

impl<A: AeadCore> SizedNonce for A {}

impl<A> AeadOps for A
where
	A: Aead + Send + Sync,
{
	fn encrypt_bytes(&self, nonce: &[u8], plaintext: &[u8]) -> CoreResult<Vec<u8>, aead::Error> {
		let nonce = self.sized_nonce(nonce)?;
		self.encrypt(nonce, plaintext)
	}

	fn decrypt_bytes(&self, nonce: &[u8], ciphertext: &[u8]) -> CoreResult<Vec<u8>, aead::Error> {
		let nonce = self.sized_nonce(nonce)?;
		self.decrypt(nonce, ciphertext)
	}

	fn nonce_size(&self) -> usize {
		<A as AeadCore>::NonceSize::USIZE
	}
}

/// A runtime-polymorphic AEAD cipher and its algorithm OID.
///
/// The handshake negotiates the security profile and builds the concrete
/// cipher type from `P::AeadCipher`, such as `Aes256Gcm` or `Aes128Gcm`. It
/// wraps that cipher here, and the transport layer stores the result
/// type-erased. The stored OID lets encryption produce a correct
/// [`EncryptedContentInfo`].
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::aead::{Aes256Gcm, KeyInit, RuntimeAead, SendCipher};
/// use tightbeam::oids::AES_256_GCM;
///
/// let cipher = Aes256Gcm::new(&[0x42; 32].into());
/// let runtime_aead = RuntimeAead::new(cipher);
/// assert_eq!(runtime_aead.algorithm_oid(), AES_256_GCM);
///
/// let send_cipher = SendCipher::new(runtime_aead);
/// assert_eq!(send_cipher.algorithm_oid(), AES_256_GCM);
/// ```
pub struct RuntimeAead {
	cipher: Box<dyn AeadOps>,
	oid: ObjectIdentifier,
}

impl RuntimeAead {
	/// Wrap `cipher`, taking its algorithm identifier from its type.
	pub fn new<A>(cipher: A) -> Self
	where
		A: AeadAlgorithm + Send + Sync + 'static,
	{
		let oid = <A::Oid as AssociatedOid>::OID;
		Self { cipher: Box::new(cipher), oid }
	}

	/// The algorithm OID this cipher encrypts under.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.oid
	}

	/// The nonce length in bytes of the wrapped cipher.
	pub fn nonce_size(&self) -> usize {
		self.cipher.nonce_size()
	}
}

/// Build an [`EncryptedContentInfo`] that carries `nonce` as an OCTET STRING
/// in the algorithm parameters.
///
/// A `None` content type defaults to [`DATA`].
#[inline]
fn build_encrypted_content_info(
	ciphertext: impl Into<Vec<u8>>,
	nonce: &[u8],
	content_type: Option<ObjectIdentifier>,
	algorithm_oid: ObjectIdentifier,
) -> TbResult<EncryptedContentInfo> {
	let ciphertext: Vec<u8> = ciphertext.into();
	let content_type = content_type.unwrap_or(DATA);

	let nonce_octet_string = OctetString::new(nonce)?;
	let parameters = Some(Any::encode_from(&nonce_octet_string)?);

	let content_enc_alg = AlgorithmIdentifier { oid: algorithm_oid, parameters };
	let encrypted_content = Some(OctetString::new(ciphertext)?);
	Ok(EncryptedContentInfo { content_type, content_enc_alg, encrypted_content })
}

/// Extract the nonce and the ciphertext from an [`EncryptedContentInfo`].
///
/// Both slices borrow directly from `info`. The nonce length MUST equal
/// `expected_nonce_len`, because NIST SP 800-38D §8.2 fixes the GCM nonce at
/// the cipher's nonce size (96 bits for AES-GCM here).
#[inline]
fn extract_nonce_and_ciphertext(info: &EncryptedContentInfo, expected_nonce_len: usize) -> TbResult<(&[u8], &[u8])> {
	let ciphertext = info
		.encrypted_content
		.as_ref()
		.ok_or(TightBeamError::MissingEncryptionInfo)?
		.as_bytes();

	let nonce_any = info
		.content_enc_alg
		.parameters
		.as_ref()
		.ok_or(TightBeamError::MissingEncryptionInfo)?;

	// `OctetStringRef` borrows the nonce bytes out of the `Any`, so no owned
	// copy exists.
	let nonce_octet_string: OctetStringRef<'_> = nonce_any.decode_as()?;
	let nonce = nonce_octet_string.as_bytes();
	if nonce.len() != expected_nonce_len {
		return Err(TightBeamError::InvalidNonceLength((nonce.len(), expected_nonce_len).into()));
	}

	Ok((nonce, ciphertext))
}

/// An encryptor that produces [`EncryptedContentInfo`] under the algorithm
/// OID `C`.
///
/// An impl binds an encryptor type to the algorithm OID stamped on its
/// ciphertext. Every [`AeadAlgorithm`] cipher implements it for its own OID and
/// no other. The trait stays unsealed so custom encryptors such as ECIES remain
/// possible.
pub trait Encryptor<C>
where
	C: AssociatedOid,
{
	/// Encrypt `data` under `nonce` and wrap the ciphertext in an
	/// [`EncryptedContentInfo`].
	///
	/// # Errors
	///
	/// An [`AeadAlgorithm`] cipher returns these errors:
	///
	/// - [`TightBeamError::EncryptionError`] when `nonce` has the wrong length or encryption fails.
	/// - [`TightBeamError::SerializationError`] when the nonce or the ciphertext fails to encode.
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo>;
}

/// Encrypted content whose algorithm matches the decryptor that opens it.
///
/// Only this crate creates one, and only after it checks the algorithm, so a
/// [`Decryptor::open`] call always follows that check (CWE-345).
pub struct CheckedContent<'a> {
	info: &'a EncryptedContentInfo,
}

impl<'a> CheckedContent<'a> {
	/// Admit `info` when it names the `expected` algorithm.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] when `info` names another algorithm.
	pub(crate) fn check(info: &'a EncryptedContentInfo, expected: ObjectIdentifier) -> TbResult<Self> {
		let received = info.content_enc_alg.oid;
		if received != expected {
			return Err(TightBeamError::UnexpectedAlgorithm((received, expected).into()));
		}

		Ok(Self { info })
	}

	/// The encrypted content.
	pub fn info(&self) -> &'a EncryptedContentInfo {
		self.info
	}
}

/// A decryptor for [`EncryptedContentInfo`] under one algorithm.
///
/// Callers decrypt through [`DecryptContent::decrypt_content`], which checks
/// the algorithm before it calls [`Decryptor::open`].
pub trait Decryptor {
	/// The algorithm identifier this decryptor opens.
	fn algorithm_oid(&self) -> ObjectIdentifier;

	/// Decrypt content that names this decryptor's algorithm.
	///
	/// The nonce is read from the algorithm parameters and validated against
	/// the cipher's nonce size.
	///
	/// # Errors
	///
	/// - [`TightBeamError::MissingEncryptionInfo`] when the ciphertext or the nonce parameter is absent.
	/// - [`TightBeamError::SerializationError`] when the nonce parameter fails to decode.
	/// - [`TightBeamError::InvalidNonceLength`] when the nonce length differs from the cipher's.
	/// - [`TightBeamError::EncryptionError`] when authentication fails.
	/// - [`TightBeamError::NonceReplayed`] from [`RecvCipher`] when the counter is out of sequence.
	/// - [`TightBeamError::RekeyRequired`] from [`RecvCipher`] at either AES-GCM volume bound.
	fn open(&self, content: CheckedContent<'_>) -> TbResult<SecretSlice<u8>>;
}

/// Decryption of [`EncryptedContentInfo`] through any [`Decryptor`].
///
/// The blanket implementation is the only one, so every decryptor refuses a
/// payload that names another algorithm.
pub trait DecryptContent {
	/// Decrypt `info` and return the plaintext bytes.
	///
	/// A payload that names an algorithm other than
	/// [`Decryptor::algorithm_oid`] is refused before any decryption. The
	/// plaintext is returned as a [`SecretSlice`] so it zeroizes on drop.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] when `info` names another algorithm.
	/// - Nonce and decryption errors from [`Decryptor::open`].
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>>;
}

impl<D: Decryptor + ?Sized> DecryptContent for D {
	fn decrypt_content(&self, info: &EncryptedContentInfo) -> TbResult<SecretSlice<u8>> {
		let content = CheckedContent::check(info, self.algorithm_oid())?;
		self.open(content)
	}
}

// The OID parameter is the cipher's own identifier, so a cipher cannot stamp
// an arbitrary OID on its ciphertext (CWE-345).
impl<A> Encryptor<A::Oid> for A
where
	A: AeadAlgorithm,
{
	fn encrypt_content(
		&self,
		data: impl AsRef<[u8]>,
		nonce: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		let nonce_bytes = nonce.as_ref();
		let ciphertext = self.encrypt(self.sized_nonce(nonce_bytes)?, data.as_ref())?;
		build_encrypted_content_info(ciphertext, nonce_bytes, content_type, <A::Oid as AssociatedOid>::OID)
	}
}

impl<A> Decryptor for A
where
	A: AeadAlgorithm,
{
	fn algorithm_oid(&self) -> ObjectIdentifier {
		<A::Oid as AssociatedOid>::OID
	}

	fn open(&self, content: CheckedContent<'_>) -> TbResult<SecretSlice<u8>> {
		let content = content.info();
		let nonce_size = <A as AeadCore>::NonceSize::USIZE;
		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(content, nonce_size)?;
		let plaintext = self.decrypt(self.sized_nonce(nonce_bytes)?, ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

impl RuntimeAead {
	/// Encrypt `data` under the OID stored in this `RuntimeAead`.
	///
	/// This is [`Encryptor::encrypt_content`] with the runtime OID in place of
	/// a compile-time generic.
	///
	/// # Nonce
	///
	/// The caller supplies `nonce` and is responsible for its uniqueness. For
	/// GCM ciphers a `(key, nonce)` pair MUST be unique.
	///
	/// # Errors
	///
	/// - [`TightBeamError::EncryptionError`] when `nonce` has the wrong length or encryption fails.
	/// - [`TightBeamError::SerializationError`] when the nonce or the ciphertext fails to encode.
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

impl Decryptor for RuntimeAead {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		self.oid
	}

	fn open(&self, content: CheckedContent<'_>) -> TbResult<SecretSlice<u8>> {
		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(content.info(), self.cipher.nonce_size())?;
		let plaintext = self.cipher.decrypt_bytes(nonce_bytes, ciphertext)?;
		Ok(SecretSlice::from(plaintext))
	}
}

/// Byte length of the invocation counter embedded in a counter nonce.
const COUNTER_LEN: usize = 8;

/// Extract the invocation counter from a counter nonce.
///
/// The nonce follows the deterministic construction of NIST SP 800-38D
/// § 8.2.1, with an all-zero fixed field and a big-endian 64-bit invocation
/// counter in the trailing bytes. The fixed field needs no validation here,
/// because the nonce feeds the AEAD and any tampering fails authentication.
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

/// A send-direction AEAD cipher with an owned monotonic counter nonce.
///
/// Each encryption consumes the next counter value as its nonce, so a
/// `(key, nonce)` pair stays unique for the lifetime of the key. The
/// deterministic construction is exempt from the 2^32 invocation cap that
/// NIST SP 800-38D § 8.3 places on random IVs.
///
/// # Record limit
///
/// The operative bound is the record limit. AES-GCM keeps its
/// authenticated-encryption safety margin for 2^24 full-size TLS records per
/// key, and RFC 9846 § 5.5 makes acting before that volume a MUST.
///
/// - The record limit is that volume divided by the encrypted-envelope ceiling.
/// - It is [`DEFAULT_REKEY_RECORD_LIMIT`] at the default ceiling, and lower at a raised one
///   ([`Self::with_envelope_ceiling`]).
/// - Encryption fails closed with [`TightBeamError::RekeyRequired`] at the limit.
/// - A receipt-bearing multiplexed session renews its keys in band before the limit.
/// - Every other session must be reestablished for fresh directional keys.
pub struct SendCipher {
	aead: RuntimeAead,
	counter: AtomicU64,
	rekey_limit: u64,
	/// The record volume the AES-GCM bound admits at this cipher's envelope
	/// ceiling. A configured limit clamps to it.
	volume_bound: u64,
}

impl SendCipher {
	/// Wrap `aead` with a nonce counter that starts at zero.
	pub fn new(aead: RuntimeAead) -> Self {
		Self {
			aead,
			counter: AtomicU64::new(0),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
			volume_bound: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Override the record limit at which encryption demands a rekey.
	///
	/// The limit clamps to the AES-GCM volume bound at this cipher's envelope
	/// ceiling, [`DEFAULT_REKEY_RECORD_LIMIT`] by default, because the bound
	/// of RFC 9846 § 5.5 is a MUST that no configuration may raise.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit.min(self.volume_bound);
		self
	}

	/// Lower the volume bound, and the record limit with it, to the records
	/// the AES-GCM analysis admits at an encrypted-envelope ceiling of
	/// `encrypted_envelope` bytes.
	///
	/// A ceiling at or below the default leaves both where they are.
	pub fn with_envelope_ceiling(mut self, encrypted_envelope: usize) -> Self {
		self.volume_bound = self.volume_bound.min(rekey_record_limit(encrypted_envelope));
		self.rekey_limit = self.rekey_limit.min(self.volume_bound);
		self
	}

	/// The record limit at which this cipher halts.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	/// The algorithm OID this cipher encrypts under.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// The number of records this cipher can still encrypt before the rekey
	/// limit halts it.
	pub fn remaining_records(&self) -> u64 {
		let used = self.counter.load(Ordering::Relaxed);
		self.rekey_limit.saturating_sub(used)
	}

	/// Encrypt `data` under the next counter nonce.
	///
	/// # Errors
	///
	/// - [`TightBeamError::RekeyRequired`] when the record limit is reached.
	///   Reestablish the session for fresh keys.
	/// - [`TightBeamError::NonceExhausted`] when the 64-bit counter space is spent.
	/// - [`TightBeamError::InvalidNonceLength`] when the cipher nonce is too small to carry the counter.
	pub fn encrypt_next(
		&self,
		data: impl AsRef<[u8]>,
		content_type: Option<ObjectIdentifier>,
	) -> TbResult<EncryptedContentInfo> {
		// The failed update leaves the counter parked at the limit, so
		// every subsequent call fails, which holds the nonce unique.
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
		Self {
			aead,
			counter: AtomicU64::new(counter),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
			volume_bound: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}
}

/// A receive-direction AEAD cipher that enforces exactly sequential counter
/// nonces.
///
/// # Sequence
///
/// The peer's [`SendCipher`] emits counter nonces in order over an ordered
/// transport, so the next message must carry exactly the next counter. Any
/// other value is a replay, reorder, or deletion, and the cipher rejects it.
///
/// This matches the receiver-side sequence discipline of RFC 9846 § 5.3. An
/// active attacker who excises an envelope from the stream desynchronizes the
/// counter, and the very next message exposes the attack (CWE-345).
///
/// # AES-GCM per-key volume bound
///
/// Decryption fails closed with [`TightBeamError::RekeyRequired`] at either
/// bound (RFC 9846 § 5.5):
///
/// - A counter at or past [`DEFAULT_REKEY_RECORD_LIMIT`], which an honest [`SendCipher`] stays below.
/// - A record that takes the bytes opened under this key past the AES-GCM volume (CWE-326).
///
/// The configurable rekey limit is a renewal-trigger threshold. Both refusals
/// stay fixed whatever it is.
///
/// # Envelope ceiling
///
/// The encrypted-envelope ceiling is not negotiated, so the byte bound counts
/// what the key opened instead of assuming the peer's record size:
///
/// - An honest sender's record limit times its own ceiling is at most the volume, so it is never refused.
/// - A peer that ignores its send clamp is refused once its records carry the volume.
pub struct RecvCipher {
	aead: RuntimeAead,
	/// The packed [`Progress`] of this key. One word holds both facts, so
	/// one compare-exchange advances them together.
	progress: AtomicU64,
	rekey_limit: u64,
}

/// How far one receive key has read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Progress {
	/// The exact counter value that the next message must carry.
	counter: u64,
	/// Ciphertext bytes the key has opened, which the volume bound caps.
	opened_bytes: u64,
}

impl Progress {
	/// Bits of the packed word that hold the counter. The opened bytes take
	/// the rest.
	const COUNTER_BITS: u32 = 24;

	/// Both facts in one word: the opened bytes above the counter.
	const fn pack(self) -> u64 {
		(self.opened_bytes << Self::COUNTER_BITS) | self.counter
	}

	/// The facts a packed word holds.
	const fn unpack(word: u64) -> Self {
		let counter = word & ((1 << Self::COUNTER_BITS) - 1);
		let opened_bytes = word >> Self::COUNTER_BITS;
		Self { counter, opened_bytes }
	}
}

// The largest counter and the largest volume each fit their share of the word.
const _: () = assert!(DEFAULT_REKEY_RECORD_LIMIT < 1 << Progress::COUNTER_BITS);
const _: () = assert!(AES_GCM_VOLUME_BYTES_PER_KEY < 1 << (u64::BITS - Progress::COUNTER_BITS));

impl RecvCipher {
	/// Wrap `aead` with an expected counter that starts at zero.
	pub fn new(aead: RuntimeAead) -> Self {
		Self { aead, progress: AtomicU64::new(0), rekey_limit: DEFAULT_REKEY_RECORD_LIMIT }
	}

	/// Override the threshold that [`Self::remaining_records`] counts down
	/// from.
	///
	/// The threshold drives the receive-direction renewal and drain triggers.
	/// Decryption refuses records at the AES-GCM volume bounds whatever this
	/// value is, so a threshold below the peer's send limit still admits every
	/// legitimate record.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit;
		self
	}

	/// The renewal-trigger threshold that [`Self::remaining_records`] counts
	/// down from.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	/// The algorithm OID this cipher decrypts under.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// The number of records still readable under the renewal-trigger
	/// threshold.
	///
	/// The count tracks the peer's send counter on the ordered channel, so a
	/// rekey initiator watches the receive direction with no new protocol
	/// field.
	pub fn remaining_records(&self) -> u64 {
		let progress = Progress::unpack(self.progress.load(Ordering::Relaxed));
		self.rekey_limit.saturating_sub(progress.counter)
	}

	#[cfg(test)]
	fn with_expected_counter(aead: RuntimeAead, counter: u64) -> Self {
		Self::with_progress(aead, counter, 0)
	}

	/// A cipher that has already read `counter` records carrying
	/// `opened_bytes` bytes.
	#[cfg(test)]
	fn with_progress(aead: RuntimeAead, counter: u64, opened_bytes: u64) -> Self {
		let progress = Progress { counter, opened_bytes };
		Self {
			aead,
			progress: AtomicU64::new(progress.pack()),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}
}

impl Decryptor for RecvCipher {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	fn open(&self, content: CheckedContent<'_>) -> TbResult<SecretSlice<u8>> {
		let (nonce_bytes, ciphertext) = extract_nonce_and_ciphertext(content.info(), self.aead.nonce_size())?;
		let counter = parse_counter_nonce(nonce_bytes)?;

		// Refuse at the AES-GCM per-key volume bound (RFC 9846 § 5.5), by
		// record count and by the bytes this key has opened.
		if counter >= DEFAULT_REKEY_RECORD_LIMIT {
			return Err(TightBeamError::RekeyRequired);
		}

		// This pre-check lets only plausible counters reach the AEAD. The
		// compare-exchange after authentication is the authoritative check.
		let word = self.progress.load(Ordering::Relaxed);
		let progress = Progress::unpack(word);
		if counter != progress.counter {
			return Err(TightBeamError::NonceReplayed((counter, progress.counter).into()));
		}

		let record_bytes = u64::try_from(ciphertext.len()).unwrap_or(u64::MAX);
		let opened_bytes = progress.opened_bytes.saturating_add(record_bytes);
		if opened_bytes > AES_GCM_VOLUME_BYTES_PER_KEY {
			return Err(TightBeamError::RekeyRequired);
		}

		let plaintext = self.aead.open(content)?;

		// Advance only after successful authentication, otherwise a forged
		// counter could block all future legitimate messages. The counter is
		// below the record limit, so the next one fits its share of the word.
		let next = Progress { counter: counter + 1, opened_bytes };
		self.progress
			.compare_exchange(word, next.pack(), Ordering::Relaxed, Ordering::Relaxed)
			.map_err(|current| TightBeamError::NonceReplayed((counter, Progress::unpack(current).counter).into()))?;

		Ok(plaintext)
	}
}

/// Directional session ciphers derived at handshake completion.
///
/// Field names use the canonical client-to-server and server-to-client
/// directions. Role mapping into send and receive sides happens in
/// [`SessionKeys`].
pub struct DirectionalCiphers<C> {
	/// Cipher for the client-to-server direction.
	pub client_to_server: C,
	/// Cipher for the server-to-client direction.
	pub server_to_client: C,
}

/// Role-mapped directional session keys produced by handshake completion.
///
/// The handshake derives one client-to-server and one server-to-client key
/// (RFC 9846 § 7.3 precedent). Each endpoint sends on its own direction and
/// receives on the peer's, so counter nonces stay distinct per direction.
pub struct SessionKeys {
	send: SendCipher,
	recv: RecvCipher,
}

impl SessionKeys {
	/// Map directional ciphers for the client role, which sends
	/// client-to-server.
	pub fn for_client<A>(ciphers: DirectionalCiphers<A>) -> Self
	where
		A: AeadAlgorithm + Send + Sync + 'static,
	{
		Self {
			send: SendCipher::new(RuntimeAead::new(ciphers.client_to_server)),
			recv: RecvCipher::new(RuntimeAead::new(ciphers.server_to_client)),
		}
	}

	/// Map directional ciphers for the server role, which sends
	/// server-to-client.
	pub fn for_server<A>(ciphers: DirectionalCiphers<A>) -> Self
	where
		A: AeadAlgorithm + Send + Sync + 'static,
	{
		Self {
			send: SendCipher::new(RuntimeAead::new(ciphers.server_to_client)),
			recv: RecvCipher::new(RuntimeAead::new(ciphers.client_to_server)),
		}
	}

	/// Bound the send cipher by the encrypted-envelope ceiling the session
	/// runs under ([`SendCipher::with_envelope_ceiling`]).
	///
	/// The receive cipher needs no ceiling. It counts the bytes it opens, so
	/// its bound holds for whatever envelopes the peer sends ([`RecvCipher`]).
	pub fn with_envelope_ceiling(mut self, encrypted_envelope: usize) -> Self {
		self.send = self.send.with_envelope_ceiling(encrypted_envelope);
		self
	}

	/// The send-direction cipher.
	pub fn send(&self) -> &SendCipher {
		&self.send
	}

	/// The receive-direction cipher.
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
	use crate::constants::DEFAULT_MAX_ENCRYPTED_ENVELOPE;
	use crate::der::asn1::OctetString;
	use crate::der::Any;
	use crate::error::ReceivedExpectedError;
	use crate::oids::AES_128_GCM;

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
		assert!(plaintext.with(|p| p == PLAINTEXT));
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
		let runtime = RuntimeAead::new(test_cipher());
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;

		let plaintext = runtime.decrypt_content(&info)?;
		assert!(plaintext.with(|p| p == PLAINTEXT));
		Ok(())
	}

	#[test]
	fn runtime_aead_rejects_algorithm_oid_mismatch() -> TbResult<()> {
		let runtime = RuntimeAead::new(test_cipher());
		let mut info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;
		info.content_enc_alg.oid = AES_128_GCM;

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::UnexpectedAlgorithm(_))));
		Ok(())
	}

	#[test]
	fn runtime_aead_rejects_wire_nonce_length() -> TbResult<()> {
		let runtime = RuntimeAead::new(test_cipher());
		let info = runtime.encrypt_content(PLAINTEXT, NONCE, None)?;
		let info = with_nonce_len(info, 8);

		let result = runtime.decrypt_content(&info);
		assert!(matches!(result, Err(TightBeamError::InvalidNonceLength(_))));
		Ok(())
	}

	fn test_runtime() -> RuntimeAead {
		RuntimeAead::new(test_cipher())
	}

	#[test]
	fn send_cipher_counter_nonces_increment() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let second = sender.encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::new(test_runtime());
		let first_plain = receiver.decrypt_content(&first)?;
		let second_plain = receiver.decrypt_content(&second)?;
		assert!(first_plain.with(|p| p == PLAINTEXT));
		assert!(second_plain.with(|p| p == PLAINTEXT));
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

		// A rejection leaves the counter parked, so the legitimate sequence
		// still decrypts.
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

	/// A raised envelope ceiling admits fewer records per key, and a limit
	/// configured afterwards still clamps to that lower bound.
	#[test]
	fn send_cipher_lowers_its_limit_for_a_raised_envelope_ceiling() {
		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let bounded = SendCipher::new(test_runtime()).with_envelope_ceiling(doubled);
		assert_eq!(bounded.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);

		let raised = bounded.with_rekey_limit(u64::MAX);
		assert_eq!(raised.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);
	}

	/// A ceiling below the default leaves the default limit in place, and a
	/// zero ceiling counts as one byte instead of dividing by zero.
	#[test]
	fn send_cipher_keeps_its_limit_for_a_lowered_or_empty_ceiling() {
		let halved = SendCipher::new(test_runtime()).with_envelope_ceiling(DEFAULT_MAX_ENCRYPTED_ENVELOPE / 2);
		assert_eq!(halved.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);

		let empty = SendCipher::new(test_runtime()).with_envelope_ceiling(0);
		assert_eq!(empty.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
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

	/// The packed word holds the largest counter and the largest volume
	/// together, and reads both back.
	#[test]
	fn progress_packs_the_largest_counter_and_volume() {
		let largest = Progress { counter: DEFAULT_REKEY_RECORD_LIMIT, opened_bytes: AES_GCM_VOLUME_BYTES_PER_KEY };
		assert_eq!(Progress::unpack(largest.pack()), largest);
	}

	/// A key that has opened the whole AES-GCM volume refuses the next record,
	/// whatever its counter is (CWE-326).
	#[test]
	fn recv_cipher_fails_closed_at_the_byte_volume() -> TbResult<()> {
		let record = SendCipher::new(test_runtime()).encrypt_next(PLAINTEXT, None)?;

		let receiver = RecvCipher::with_progress(test_runtime(), 0, AES_GCM_VOLUME_BYTES_PER_KEY);
		let refused = receiver.decrypt_content(&record);
		assert!(matches!(refused, Err(TightBeamError::RekeyRequired)));
		Ok(())
	}

	/// The ciphertext bytes of `record`, as the volume bound counts them.
	fn ciphertext_len(record: &EncryptedContentInfo) -> u64 {
		let nonce_size = test_runtime().nonce_size();
		let (_, ciphertext) = extract_nonce_and_ciphertext(record, nonce_size).expect("a sealed record carries both");
		u64::try_from(ciphertext.len()).expect("a record length fits in u64")
	}

	/// The record that brings the opened bytes exactly to the volume is the
	/// last one the key opens.
	#[test]
	fn recv_cipher_opens_the_record_that_reaches_the_byte_volume() -> TbResult<()> {
		let record = SendCipher::new(test_runtime()).encrypt_next(PLAINTEXT, None)?;
		let already_opened = AES_GCM_VOLUME_BYTES_PER_KEY - ciphertext_len(&record);

		let receiver = RecvCipher::with_progress(test_runtime(), 0, already_opened);
		let opened = receiver.decrypt_content(&record)?;
		assert!(opened.with(|plaintext| plaintext == PLAINTEXT));
		Ok(())
	}

	/// Every opened record counts toward the volume, so the second of two
	/// records is refused when only the first fits.
	#[test]
	fn recv_cipher_counts_every_record_it_opens() -> TbResult<()> {
		let sender = SendCipher::new(test_runtime());
		let first = sender.encrypt_next(PLAINTEXT, None)?;
		let second = sender.encrypt_next(PLAINTEXT, None)?;
		let room_for_one = AES_GCM_VOLUME_BYTES_PER_KEY - ciphertext_len(&first);

		let receiver = RecvCipher::with_progress(test_runtime(), 0, room_for_one);
		receiver.decrypt_content(&first)?;
		let refused = receiver.decrypt_content(&second);
		assert!(matches!(refused, Err(TightBeamError::RekeyRequired)));
		Ok(())
	}

	/// The sender's envelopes set the per-key volume, and the ceiling is not
	/// negotiated. An honest sender at a lowered ceiling keeps the constant
	/// record limit, and a receiver at the default ceiling and a receiver at a
	/// raised one both accept the last record under that limit.
	#[test]
	fn a_receiver_at_any_ceiling_accepts_an_honest_sender_up_to_the_constant() -> TbResult<()> {
		let last_counter = DEFAULT_REKEY_RECORD_LIMIT - 1;
		let halved = DEFAULT_MAX_ENCRYPTED_ENVELOPE / 2;
		let sender = SendCipher::with_counter(test_runtime(), last_counter).with_envelope_ceiling(halved);
		assert_eq!(sender.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);

		let last = sender.encrypt_next(PLAINTEXT, None)?;

		let default_receiver = RecvCipher::with_expected_counter(test_runtime(), last_counter);
		default_receiver.decrypt_content(&last)?;

		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let raised = SessionKeys {
			send: SendCipher::new(test_runtime()),
			recv: RecvCipher::with_expected_counter(test_runtime(), last_counter),
		}
		.with_envelope_ceiling(doubled);
		assert_eq!(raised.recv().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
		raised.recv().decrypt_content(&last)?;
		Ok(())
	}

	/// The session's envelope ceiling lowers the send cipher's record limit
	/// and leaves the receive cipher at the constant, because the peer's
	/// envelopes set the receive-direction volume.
	#[test]
	fn session_keys_bound_the_send_cipher_by_the_envelope_ceiling() {
		let ciphers = DirectionalCiphers {
			client_to_server: Aes256Gcm::new(&[0x11u8; 32].into()),
			server_to_client: Aes256Gcm::new(&[0x22u8; 32].into()),
		};

		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let keys = SessionKeys::for_client(ciphers).with_envelope_ceiling(doubled);
		assert_eq!(keys.send().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);
		assert_eq!(keys.recv().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
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
		let c2s_key = [0x11u8; 32];
		let s2c_key = [0x22u8; 32];
		let ciphers = || DirectionalCiphers {
			client_to_server: Aes256Gcm::new(&c2s_key.into()),
			server_to_client: Aes256Gcm::new(&s2c_key.into()),
		};

		let client = SessionKeys::for_client(ciphers());
		let server = SessionKeys::for_server(ciphers());
		(client, server)
	}

	#[test]
	fn session_keys_role_map_is_complementary() -> TbResult<()> {
		let (client, server) = directional_pair();

		let request = client.send().encrypt_next(PLAINTEXT, None)?;
		let request_plain = server.recv().decrypt_content(&request)?;
		assert!(request_plain.with(|p| p == PLAINTEXT));

		let response = server.send().encrypt_next(PLAINTEXT, None)?;
		let response_plain = client.recv().decrypt_content(&response)?;
		assert!(response_plain.with(|p| p == PLAINTEXT));
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

	/// A wrong-length nonce reaches the AEAD's own error ahead of the
	/// fixed-size conversion's assert.
	#[test]
	fn wrong_length_nonce_is_refused() {
		let cipher = <Aes256Gcm as KeyInit>::new_from_slice(&[0u8; 32]).expect("32 octets is the AES-256 key size");

		assert!(cipher.encrypt_bytes(&[0u8; 8], b"plaintext").is_err());
		assert!(cipher.decrypt_bytes(&[0u8; 8], b"ciphertext").is_err());
	}
}

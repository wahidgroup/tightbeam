//! AEAD ciphers, their algorithm identifiers, and the session ciphers that
//! seal each record as an `AuthEnvelopedData`.
//!
//! - [`AeadAlgorithm`] binds a cipher type to its OID and its key size.
//! - [`Encryptor`], [`Decryptor`], and [`DecryptContent`] seal and open a frame body as CMS.
//! - [`RuntimeAead`] erases the provider of one direction's record key for the transport.
//! - [`SendCipher`] and [`RecvCipher`] own one direction's epoch, record sequence, and record limit.
//! - [`SessionKeys`] maps [`DirectionalCiphers`] onto the client or server role.

pub use aead::{Aead, AeadCore, AeadInPlace, Error, Key, KeyInit, KeySizeUser, Nonce, Payload, Tag};

#[cfg(feature = "aes-gcm")]
pub use aes_gcm::{Aes128Gcm, Aes256Gcm, Key as Aes256GcmKey, Nonce as Aes256GcmNonce};
#[cfg(feature = "aead")]
pub use aes_kw;

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use core::marker::PhantomData;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, sync::Arc, vec::Vec};
#[cfg(feature = "std")]
use std::sync::Arc;

use crate::asn1::{AuthEnvelopedData, ObjectIdentifier, WireDer};
use crate::der::oid::AssociatedOid;
use crate::error::Result as TbResult;
use crate::random::CryptoRngCore;
use crate::utils::marker::MaybeSendFuture;
use crate::TightBeamError;

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::constants::{
	rekey_record_limit, DEFAULT_REKEY_RECORD_LIMIT, RENEWAL_VOLUME_BYTES, TIGHTBEAM_RECORD_KEY_ID_DOMAIN,
};
#[cfg(all(feature = "hpke", feature = "signature"))]
use crate::crypto::cms::Opener;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::cms::{ArrivedEnvelope, AttributesExt, ContentEncryption, Detached, EnvelopeError, OwnedKek};
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::crypto::profiles::{CryptoProvider, Kek};
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::der::asn1::SetOfVec;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::der::{Any, Sequence};
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::oids::{DATA, RECORD_SEQUENCE};
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::x509::attr::Attribute;
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
use crate::ZeroizingBytes;

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

/// The content type of every record, the encoded `TransportEnvelope` it
/// carries.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
const RECORD_CONTENT_TYPE: ObjectIdentifier = DATA;

/// The object-safe record seal behind [`RuntimeAead`].
///
/// A trait object of it lets one type hold the record key of any provider.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
trait RecordOps: Send + Sync {
	/// Seal `content` as a record whose content key is wrapped under this
	/// key, named by `key_identifier`, with `sequence` among its
	/// authenticated attributes.
	fn seal(
		&self,
		content: Vec<u8>,
		key_identifier: &[u8],
		sequence: Attribute,
	) -> Result<AuthEnvelopedData, EnvelopeError>;

	/// Open `record`, a record decoded in the buffer it arrived in, in place
	/// under this key, named by `key_identifier`.
	fn open<'a>(&self, record: Detached<'a>, key_identifier: &[u8]) -> Result<&'a [u8], EnvelopeError>;
}

/// The directional key-encryption key of one session direction, under the
/// algorithms of the provider `P`.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
struct RecordKey<P: CryptoProvider> {
	kek: OwnedKek<P::KeyWrap>,
	provider: PhantomData<fn() -> P>,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl<P> RecordOps for RecordKey<P>
where
	P: CryptoProvider<AeadCipher: ContentEncryption>,
{
	fn seal(
		&self,
		content: Vec<u8>,
		key_identifier: &[u8],
		sequence: Attribute,
	) -> Result<AuthEnvelopedData, EnvelopeError> {
		let kek = self.kek.kek();
		AuthEnvelopedData::seal_kek::<P>(&kek, key_identifier, RECORD_CONTENT_TYPE, content, [sequence], None)
	}

	fn open<'a>(&self, record: Detached<'a>, key_identifier: &[u8]) -> Result<&'a [u8], EnvelopeError> {
		let kek = self.kek.kek();
		record.open_kek::<P>(&kek, key_identifier)
	}
}

/// The direction a record key serves. Its octet leads the epoch in the
/// `kekid` of every record, so a record reflected into the other direction
/// names another key, and the receiver refuses it before any key runs.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordDirection {
	/// The client sends, and the server receives. Its octet is `0x00`.
	ClientToServer,
	/// The server sends, and the client receives. Its octet is `0x01`.
	ServerToClient,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl RecordDirection {
	/// Returns the octet of this direction in a record's `kekid`.
	const fn octet(self) -> u8 {
		match self {
			Self::ClientToServer => 0x00,
			Self::ServerToClient => 0x01,
		}
	}

	/// Returns the `kekid.keyIdentifier` of every record of this direction's
	/// key of `epoch`: the record domain, this direction's octet, and the
	/// epoch in big-endian order.
	fn key_identifier(self, epoch: u32) -> Vec<u8> {
		[TIGHTBEAM_RECORD_KEY_ID_DOMAIN, &[self.octet()], &epoch.to_be_bytes()].concat()
	}
}

/// The record key of one session direction: a key-encryption key, and the
/// algorithms of the provider `P` that seals and opens records under it.
///
/// - The handshake derives the key at the key-wrap size of `P`, and this type erases `P` for the transport.
/// - Each record wraps a fresh content key under this key in a `KEKRecipientInfo` (RFC 5652 §6.2.3).
/// - The content seals under the AEAD of `P` with `GCMParameters` (RFC 5084 §3.2).
///
/// # Examples
///
/// ```
/// use tightbeam::crypto::aead::{RecordDirection, RuntimeAead, SendCipher};
/// use tightbeam::crypto::profiles::DefaultCryptoProvider;
/// use tightbeam::oids::AES_256_GCM;
///
/// let runtime_aead = RuntimeAead::new::<DefaultCryptoProvider>(vec![0x42; 32])?;
/// assert_eq!(runtime_aead.algorithm_oid(), AES_256_GCM);
///
/// let send_cipher = SendCipher::new(runtime_aead, 0, RecordDirection::ClientToServer);
/// assert_eq!(send_cipher.algorithm_oid(), AES_256_GCM);
/// # Ok::<(), tightbeam::TightBeamError>(())
/// ```
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub struct RuntimeAead {
	key: Box<dyn RecordOps>,
	oid: ObjectIdentifier,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl RuntimeAead {
	/// Hold `kek`, the key-encryption key of one session direction, under the
	/// algorithms of `P`. The content-encryption algorithm is the AEAD of `P`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::KeyError`] -- `kek` is not the key size of the wrap of `P`.
	pub fn new<P>(kek: impl Into<ZeroizingBytes>) -> TbResult<Self>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption> + 'static,
	{
		let bytes = kek.into();
		let kek = OwnedKek::<P::KeyWrap>::try_from(bytes.as_slice())?;
		let oid = <<P::AeadCipher as AeadAlgorithm>::Oid as AssociatedOid>::OID;
		let key = Box::new(RecordKey::<P> { kek, provider: PhantomData });
		Ok(Self { key, oid })
	}

	/// Returns the content-encryption algorithm OID that this key seals
	/// records under.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.oid
	}

	/// Seal `content` as a record under this key, named by `key_identifier`,
	/// with `sequence` among its authenticated attributes.
	fn seal(&self, content: Vec<u8>, key_identifier: &[u8], sequence: Attribute) -> TbResult<AuthEnvelopedData> {
		Ok(self.key.seal(content, key_identifier, sequence)?)
	}

	/// Open `record` in place under this key, named by `key_identifier`.
	fn open<'a>(&self, record: Detached<'a>, key_identifier: &[u8]) -> TbResult<&'a [u8]> {
		Ok(self.key.open(record, key_identifier)?)
	}
}

/// A frame encryptor that seals content as an [`AuthEnvelopedData`] under the
/// content-encryption algorithm `C`.
///
/// An impl binds an encryptor type to the algorithm OID its envelopes name,
/// so a frame builder reads the OID it checks against the profile from the
/// type. The trait stays unsealed, so an outside encryptor implements it.
pub trait Encryptor<C>
where
	C: AssociatedOid,
{
	/// Seal `content`, of type `content_type` or `id-data` without one, as an
	/// [`AuthEnvelopedData`] whose encrypted content is `content` encrypted in
	/// place.
	///
	/// `rng` draws the content key, the nonce, and every value the recipient
	/// draws. `None` draws them from the OS source.
	///
	/// # Errors
	///
	/// - [`TightBeamError::EnvelopeError`] -- the envelope refused to seal.
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> TbResult<AuthEnvelopedData>;
}

/// A shared encryptor is an encryptor, so one key serves every frame builder
/// that holds it.
impl<C, E> Encryptor<C> for Arc<E>
where
	C: AssociatedOid,
	E: Encryptor<C> + ?Sized,
{
	fn encrypt_content(
		&self,
		content: impl Into<Vec<u8>>,
		content_type: Option<ObjectIdentifier>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> TbResult<AuthEnvelopedData> {
		E::encrypt_content(self, content, content_type, rng)
	}
}

/// An envelope whose content-encryption algorithm matches the decryptor that
/// opens it, beside the encoding it arrived as and the buffer of its
/// encrypted content, which the open decrypts in place. The envelope and its
/// encoding come from one [`WireDer`].
///
/// Only this crate creates one, and only after two checks, so every
/// [`Decryptor::open`] call follows both (CWE-345):
///
/// - The envelope names the algorithm of the decryptor.
/// - With `aead`, `signature`, `kdf`, and `ecdh`, the encoding it arrived as
///   carries no `originatorInfo` or `unauthAttrs` (RFC 5083 §2.1).
pub struct CheckedContent<'a> {
	sealed: &'a WireDer<AuthEnvelopedData>,
	/// The view of the encoding of `sealed` that the read of [`Self::check`]
	/// parsed. The house opens read the authenticated attributes from it.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	arrived: ArrivedEnvelope<'a>,
	content: &'a mut [u8],
}

impl<'a> CheckedContent<'a> {
	/// Admit `sealed`, whose encrypted content is in `content`, when it names
	/// the `expected` algorithm. With `aead`, `signature`, `kdf`, and `ecdh`,
	/// the encoding of `sealed` must also pass the read of an arrived
	/// envelope.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- `sealed` names another algorithm.
	/// - [`TightBeamError::EnvelopeError`] -- with `aead`, `signature`, `kdf`,
	///   and `ecdh`, the errors of [`ArrivedEnvelope::read`].
	pub(crate) fn check(
		sealed: &'a WireDer<AuthEnvelopedData>,
		content: &'a mut [u8],
		expected: ObjectIdentifier,
	) -> TbResult<Self> {
		let received = sealed.value().auth_encrypted_content_info.content_enc_alg.oid;
		if received != expected {
			return Err(TightBeamError::UnexpectedAlgorithm((received, expected).into()));
		}

		#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
		let arrived = ArrivedEnvelope::read(sealed.der())?;

		Ok(Self {
			sealed,
			#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
			arrived,
			content,
		})
	}

	/// Returns the envelope, the encoding it arrived as, and the buffer of the
	/// encrypted content. An open holds the authenticated attributes to that
	/// encoding.
	pub fn into_parts(self) -> (&'a AuthEnvelopedData, &'a [u8], &'a mut [u8]) {
		(self.sealed.value(), self.sealed.der(), self.content)
	}

	/// Open the content in its buffer with `opener` under the algorithms of
	/// `P`, as the type the envelope's attributes authenticate. A refused open
	/// leaves the buffer unchanged.
	///
	/// # Errors
	///
	/// - The errors of [`AuthEnvelopedData::open`], for the content outside the envelope.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::aead::{CheckedContent, Decryptor};
	/// use tightbeam::crypto::cms::Opener;
	/// use tightbeam::crypto::profiles::{DefaultCryptoProvider, Kek};
	/// use tightbeam::der::asn1::ObjectIdentifier;
	/// use tightbeam::oids::AES_256_GCM;
	/// use tightbeam::utils::marker::MaybeSendFuture;
	/// use tightbeam::TightBeamError;
	///
	/// /// A frame decryptor that opens each frame under a KEK it holds.
	/// struct KekDecryptor {
	///     kek: [u8; 32],
	/// }
	///
	/// impl Decryptor for KekDecryptor {
	///     fn algorithm_oid(&self) -> ObjectIdentifier {
	///         AES_256_GCM
	///     }
	///
	///     fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, Result<(), TightBeamError>> {
	///         Box::pin(async move {
	///             let kek = Kek::try_from(self.kek.as_slice())?;
	///             let opener = Opener::Kek { kek, key_identifier: b"example-kek" };
	///             content.open::<DefaultCryptoProvider>(&opener).await
	///         })
	///     }
	/// }
	/// ```
	#[cfg(all(feature = "hpke", feature = "signature"))]
	pub async fn open<P>(self, opener: &Opener<'_, P>) -> TbResult<()>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let Self { sealed, arrived, content } = self;
		let envelope = sealed.value();
		let content_type = envelope.auth_encrypted_content_info.content_type;
		Ok(envelope.open_detached::<P>(&arrived, content, opener, content_type).await?)
	}

	/// Open the content in its buffer under the AEAD of `P` and `kek`, which
	/// `key_identifier` names, as the type the envelope's attributes
	/// authenticate. A refused open leaves the buffer unchanged.
	///
	/// # Errors
	///
	/// - The errors of [`AuthEnvelopedData::open`], with `kek` as the opener.
	#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
	pub(crate) fn open_kek<P>(self, kek: &Kek<'_, P::KeyWrap>, key_identifier: &[u8]) -> TbResult<()>
	where
		P: CryptoProvider<AeadCipher: ContentEncryption>,
	{
		let Self { sealed, arrived, content } = self;
		let envelope = sealed.value();
		let content_type = envelope.auth_encrypted_content_info.content_type;
		Ok(envelope.open_detached_kek::<P>(&arrived, content, kek, key_identifier, content_type)?)
	}
}

/// A frame decryptor for [`AuthEnvelopedData`] under one content-encryption
/// algorithm.
///
/// Callers decrypt through [`DecryptContent::decrypt_content`], which checks
/// the algorithm before it calls [`Decryptor::open`] ([`CheckedContent`]).
/// With `aead`, `signature`, `kdf`, and `ecdh`, it also reads the envelope as
/// it arrived before the open.
pub trait Decryptor {
	/// The content-encryption algorithm this decryptor opens.
	fn algorithm_oid(&self) -> ObjectIdentifier;

	/// Open content that names this decryptor's algorithm in its buffer, so
	/// the buffer holds the plaintext once the open returns. The open is
	/// async, because a KEM recipient decapsulates through a key backend.
	///
	/// A refused open MUST leave the buffer unchanged, so a frame that lends
	/// its body keeps it. The house decryptors keep this, because every check
	/// runs before the cipher, and the cipher keeps it ([`ContentEncryption`]).
	///
	/// # Errors
	///
	/// - [`TightBeamError::EnvelopeError`] -- the recipient, the tag, or a field of the envelope differs.
	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, TbResult<()>>;
}

/// A shared decryptor is a decryptor, as for [`Encryptor`].
impl<D: Decryptor + ?Sized> Decryptor for Arc<D> {
	fn algorithm_oid(&self) -> ObjectIdentifier {
		D::algorithm_oid(self)
	}

	fn open<'a>(&'a self, content: CheckedContent<'a>) -> MaybeSendFuture<'a, TbResult<()>> {
		D::open(self, content)
	}
}

/// The decryption of [`AuthEnvelopedData`] through any [`Decryptor`].
///
/// The blanket implementation is the only one, so every decryptor refuses an
/// envelope that names another algorithm. With `aead`, `signature`, `kdf`,
/// and `ecdh`, every decryptor also refuses an envelope that carries a field
/// outside the tag ([`CheckedContent`]).
pub trait DecryptContent {
	/// Decrypt `content`, the encrypted content of the envelope in `sealed`, in
	/// place, so `content` holds the plaintext once the decryption returns.
	///
	/// The check against [`Decryptor::algorithm_oid`] runs before any
	/// decryption, and with `aead`, `signature`, `kdf`, and `ecdh`, so does
	/// the read of the encoding of `sealed`. A refused decryption leaves
	/// `content` unchanged.
	///
	/// # Errors
	///
	/// - [`TightBeamError::UnexpectedAlgorithm`] -- `sealed` names another algorithm.
	/// - [`TightBeamError::EnvelopeError`] -- with `aead`, `signature`, `kdf`,
	///   and `ecdh`, the encoding of `sealed` is no DER `AuthEnvelopedData`, or
	///   it carries `originatorInfo` or `unauthAttrs`.
	/// - The errors of [`Decryptor::open`].
	fn decrypt_content<'a>(
		&'a self,
		sealed: &'a WireDer<AuthEnvelopedData>,
		content: &'a mut [u8],
	) -> MaybeSendFuture<'a, TbResult<()>>;
}

impl<D: Decryptor + ?Sized> DecryptContent for D {
	fn decrypt_content<'a>(
		&'a self,
		sealed: &'a WireDer<AuthEnvelopedData>,
		content: &'a mut [u8],
	) -> MaybeSendFuture<'a, TbResult<()>> {
		match CheckedContent::check(sealed, content, self.algorithm_oid()) {
			Ok(content) => self.open(content),
			Err(error) => Box::pin(core::future::ready(Err(error))),
		}
	}
}

/// The position of one record in its session, as an authenticated attribute
/// of its `AuthEnvelopedData`: the epoch of the key that seals it, and its
/// sequence number within that epoch.
///
/// ```text
/// RecordSequence ::= SEQUENCE {
///   epoch     INTEGER (0..4294967295),
///   sequence  INTEGER (0..18446744073709551615) }
/// ```
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Sequence)]
pub(crate) struct RecordSequence {
	/// The epoch of the directional key, 0 at the handshake and one more at
	/// each renewal.
	epoch: u32,
	/// The record's sequence number within its epoch, from 0.
	sequence: u64,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl RecordSequence {
	/// Returns this position as the authenticated attribute
	/// [`RECORD_SEQUENCE`].
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the attribute fails to encode.
	fn attribute(&self) -> TbResult<Attribute> {
		let values = SetOfVec::try_from([Any::encode_from(self)?])?;
		Ok(Attribute { oid: RECORD_SEQUENCE, values })
	}

	/// Returns the one position that the authenticated attributes of
	/// `envelope` carry.
	///
	/// # Errors
	///
	/// - [`EnvelopeError::AuthenticatedAttribute`] -- the attributes carry no
	///   position, carry it twice, or carry another number of values in it.
	/// - [`TightBeamError::SerializationError`] -- its value is no `RecordSequence`.
	fn carried_by(envelope: &AuthEnvelopedData) -> TbResult<Self> {
		let attributes = envelope.auth_attrs.as_ref().ok_or(EnvelopeError::AuthenticatedAttribute)?;
		let carried = attributes.single(RECORD_SEQUENCE, EnvelopeError::AuthenticatedAttribute)?;
		let attribute = carried.ok_or(EnvelopeError::AuthenticatedAttribute)?;

		let [value] = attribute.values.as_slice() else {
			return Err(EnvelopeError::AuthenticatedAttribute.into());
		};

		Ok(value.decode_as::<Self>()?)
	}
}

/// A send-direction record cipher: each record is an `AuthEnvelopedData`
/// that wraps a fresh content key under this direction's key, and whose
/// authenticated attributes carry its epoch and its sequence number.
///
/// Each encryption consumes the next sequence number, so a receiver refuses a
/// replayed, reordered, or deleted record by the sequence the tag covers.
///
/// # Record limit
///
/// Each record draws its own content key and nonce (RFC 5084 §3.2), so the
/// AES-GCM bound of one key binds one record. The sequence space of the
/// counter and the key-wrap invocations under one key are the bounds that
/// remain, and the record limit of RFC 9846 §5.5 is the renewal trigger.
///
/// - The record limit is the volume of 2^24 full-size TLS records divided by the encrypted-envelope ceiling.
/// - It is [`DEFAULT_REKEY_RECORD_LIMIT`] at the default ceiling, and lower at a raised one
///   ([`Self::with_envelope_ceiling`]).
/// - Encryption fails closed with [`TightBeamError::RekeyRequired`] at the limit.
/// - A receipt-bearing multiplexed session renews its keys in band before the limit.
/// - The caller must reestablish every other session for fresh directional keys.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub struct SendCipher {
	aead: RuntimeAead,
	epoch: u32,
	/// The `kekid` of every record of this key, built once.
	key_identifier: Vec<u8>,
	counter: AtomicU64,
	rekey_limit: u64,
	/// The record volume the renewal trigger admits at this cipher's envelope
	/// ceiling. A configured limit clamps to it.
	volume_bound: u64,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl SendCipher {
	/// Wrap `aead`, the record key of `direction` at `epoch`, with a sequence
	/// that starts at zero.
	pub fn new(aead: RuntimeAead, epoch: u32, direction: RecordDirection) -> Self {
		let key_identifier = direction.key_identifier(epoch);
		Self {
			aead,
			epoch,
			key_identifier,
			counter: AtomicU64::new(0),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
			volume_bound: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Override the record limit at which encryption demands a rekey.
	///
	/// The limit clamps to the renewal volume at this cipher's envelope
	/// ceiling, [`DEFAULT_REKEY_RECORD_LIMIT`] by default, because the record
	/// limit of RFC 9846 §5.5 is a MUST that no configuration may raise.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit.min(self.volume_bound);
		self
	}

	/// Lower the volume bound, and the record limit with it, to the records
	/// the renewal volume admits at an encrypted-envelope ceiling of
	/// `encrypted_envelope` bytes.
	///
	/// A ceiling at or below the default leaves both where they are.
	pub fn with_envelope_ceiling(mut self, encrypted_envelope: usize) -> Self {
		self.volume_bound = self.volume_bound.min(rekey_record_limit(encrypted_envelope));
		self.rekey_limit = self.rekey_limit.min(self.volume_bound);
		self
	}

	/// Returns the record limit at which this cipher halts.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	/// Returns the content-encryption algorithm OID that this cipher seals
	/// under.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// Returns the number of records left to encrypt before the rekey limit
	/// halts this cipher.
	pub fn remaining_records(&self) -> u64 {
		let used = self.counter.load(Ordering::Relaxed);
		self.rekey_limit.saturating_sub(used)
	}

	/// Whether this cipher has no record left to seal, so every seal fails
	/// with [`TightBeamError::RekeyRequired`].
	pub fn is_spent(&self) -> bool {
		self.remaining_records() == 0
	}

	/// Seal `payload`, the encoded envelope of one record, as the next record.
	///
	/// The payload moves in, and the envelope encrypts it in place, so its
	/// buffer becomes the `encryptedContent`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::RekeyRequired`] -- the cipher is at the record limit.
	///   Reestablish the session for fresh keys.
	/// - [`TightBeamError::NonceExhausted`] -- the 64-bit sequence space is spent.
	/// - [`TightBeamError::SerializationError`] -- the position attribute fails to encode.
	/// - [`TightBeamError::EnvelopeError`] -- the envelope refuses to seal.
	pub fn encrypt_next(&self, payload: impl Into<Vec<u8>>) -> TbResult<AuthEnvelopedData> {
		// A failed update leaves the counter at the limit, so every later call
		// fails and the sequence stays unique.
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

		let sequence = RecordSequence { epoch: self.epoch, sequence: reserved };
		let attribute = sequence.attribute()?;
		self.aead.seal(payload.into(), &self.key_identifier, attribute)
	}

	/// Builds a client-to-server cipher of epoch 0 that has spent `counter`
	/// sequence numbers.
	#[cfg(test)]
	fn with_counter(aead: RuntimeAead, counter: u64) -> Self {
		let key_identifier = RecordDirection::ClientToServer.key_identifier(0);
		Self {
			aead,
			epoch: 0,
			key_identifier,
			counter: AtomicU64::new(counter),
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
			volume_bound: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Returns the `kekid` that every record of this cipher names.
	#[cfg(test)]
	fn key_identifier(&self) -> &[u8] {
		&self.key_identifier
	}

	/// Seals `payload` as a record of this cipher's epoch at `sequence`, in
	/// place of the next number, as an on-path party shapes a record that a
	/// receiver refuses before its tag check.
	///
	/// # Errors
	///
	/// - The errors of [`Self::encrypt_next`] other than the record limit.
	#[cfg(all(
		test,
		feature = "instrument",
		any(feature = "tokio", feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn seal_at(&self, payload: impl Into<Vec<u8>>, sequence: u64) -> TbResult<AuthEnvelopedData> {
		let attribute = RecordSequence { epoch: self.epoch, sequence }.attribute()?;
		self.aead.seal(payload.into(), &self.key_identifier, attribute)
	}

	/// Seals `payload` as a record whose position attribute holds `position`
	/// in place of a `RecordSequence`.
	///
	/// # Errors
	///
	/// - [`TightBeamError::SerializationError`] -- the attribute fails to encode.
	/// - [`TightBeamError::EnvelopeError`] -- the envelope refuses to seal.
	#[cfg(all(
		test,
		feature = "instrument",
		any(feature = "tokio", feature = "transport-cms", feature = "transport-hpke")
	))]
	pub(crate) fn seal_with_position(&self, payload: impl Into<Vec<u8>>, position: Any) -> TbResult<AuthEnvelopedData> {
		let values = SetOfVec::try_from([position])?;
		let attribute = Attribute { oid: RECORD_SEQUENCE, values };
		self.aead.seal(payload.into(), &self.key_identifier, attribute)
	}
}

/// A receive-direction record cipher that admits exactly the next record of
/// its epoch.
///
/// # Sequence
///
/// The peer's [`SendCipher`] numbers its records in order over an ordered
/// transport, and the tag covers each record's epoch and sequence number:
///
/// - A record of the next sequence number and this cipher's epoch opens.
/// - Any other value is a replay, a reorder, or a deletion, and the cipher refuses it.
/// - An attacker who excises a record desynchronizes the sequence, so the next record exposes it (CWE-345).
///
/// This matches the receiver-side sequence discipline of RFC 9846 §5.3.
///
/// # Renewal bound
///
/// Decryption fails closed with [`TightBeamError::RenewalBoundExceeded`] at
/// either bound of the crate's own renewal policy, which holds a peer that
/// ignores its send limit to the bounds an honest sender keeps:
///
/// - A sequence number at or past [`DEFAULT_REKEY_RECORD_LIMIT`], which an honest [`SendCipher`] stays below.
/// - A record that takes the bytes opened under this key past the renewal volume.
///
/// RFC 9846 §5.5 sets its limit on the sender, which [`SendCipher`] holds.
/// The configurable rekey limit is a renewal trigger alone, and both refusals
/// stay fixed whatever it is.
///
/// # Envelope ceiling
///
/// Each peer sets its own encrypted-envelope ceiling, so the byte bound counts
/// what the key opened instead of an assumed record size of the peer:
///
/// - An honest sender's record limit times its own ceiling is at most the volume, so the bound admits it.
/// - The cipher refuses the record of a peer that ignores its send clamp once the bytes pass the volume.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub struct RecvCipher {
	aead: RuntimeAead,
	epoch: u32,
	/// The `kekid` every record of this key names, built once.
	key_identifier: Vec<u8>,
	/// How far this key has read. An open takes the key exclusively, so the
	/// two facts advance together in one assignment.
	progress: Progress,
	rekey_limit: u64,
}

/// How far one receive key has read.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Progress {
	/// The sequence number that the next record must carry.
	counter: u64,
	/// The ciphertext bytes the key has opened, which the volume bound caps.
	opened_bytes: u64,
}

// AES wipes its round keys on drop under the `zeroize` feature of the `aes`
// crate alone (CWE-226), so a feature graph that leaves it off fails here.
#[cfg(feature = "aes-gcm")]
const _: () = {
	const fn wipes_on_drop<T: crate::zeroize::ZeroizeOnDrop>() {}

	wipes_on_drop::<::aes::Aes128>();
	wipes_on_drop::<::aes::Aes256>();
};

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl RecvCipher {
	/// Wrap `aead`, the record key of `direction` at `epoch`, with an expected
	/// sequence that starts at zero.
	pub fn new(aead: RuntimeAead, epoch: u32, direction: RecordDirection) -> Self {
		let key_identifier = direction.key_identifier(epoch);
		Self {
			aead,
			epoch,
			key_identifier,
			progress: Progress { counter: 0, opened_bytes: 0 },
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Override the threshold that [`Self::remaining_records`] counts down
	/// from.
	///
	/// The threshold drives the receive-direction renewal and drain triggers.
	/// Decryption refuses records at the renewal bounds whatever this value
	/// is, so every legitimate record opens under a threshold below the
	/// peer's send limit too.
	pub fn with_rekey_limit(mut self, limit: u64) -> Self {
		self.rekey_limit = limit;
		self
	}

	/// Returns the renewal-trigger threshold that [`Self::remaining_records`]
	/// counts down from.
	pub fn rekey_limit(&self) -> u64 {
		self.rekey_limit
	}

	/// Returns the content-encryption algorithm OID that this cipher opens.
	pub fn algorithm_oid(&self) -> ObjectIdentifier {
		self.aead.algorithm_oid()
	}

	/// Returns the number of records left to read under the renewal-trigger
	/// threshold.
	///
	/// The count tracks the peer's send sequence on the ordered channel, so a
	/// rekey initiator watches the receive direction through the record
	/// sequence alone.
	pub fn remaining_records(&self) -> u64 {
		self.rekey_limit.saturating_sub(self.progress.counter)
	}

	/// Open `record`, the DER of one record's `AuthEnvelopedData`, in the
	/// buffer it arrived in, and return the content it decrypted in place.
	///
	/// It checks the record's epoch and sequence number before the content key
	/// unwraps, and advances the sequence once the tag passes. A refused record
	/// leaves the sequence unchanged. The open takes the key exclusively, so
	/// two opens on one key run one after the other.
	///
	/// # Errors
	///
	/// - [`TightBeamError::EnvelopeError`] -- the record is no envelope this key
	///   opens, carries no single position, or its tag fails.
	/// - [`TightBeamError::SerializationError`] -- the position the record carries is no `RecordSequence`.
	/// - [`TightBeamError::RecordEpoch`] -- the record carries another epoch.
	/// - [`TightBeamError::NonceReplayed`] -- the record carries another sequence number than the next.
	/// - [`TightBeamError::RenewalBoundExceeded`] -- the record meets either renewal bound.
	pub fn open<'a>(&mut self, record: &'a mut [u8]) -> TbResult<&'a [u8]> {
		// 1. Decode the record with its content left where it arrived, and read the position it claims.
		let record = AuthEnvelopedData::detach(record, RECORD_CONTENT_TYPE)?;
		let carried = RecordSequence::carried_by(record.envelope())?;
		if carried.epoch != self.epoch {
			return Err(TightBeamError::RecordEpoch((carried.epoch, self.epoch).into()));
		}

		// 2. Refuse at the crate's renewal bounds, by record count and by the bytes this key has opened.
		let counter = carried.sequence;
		if counter >= DEFAULT_REKEY_RECORD_LIMIT {
			return Err(TightBeamError::RenewalBoundExceeded);
		}

		// This check lets only plausible records reach the key.
		let progress = self.progress;
		if counter != progress.counter {
			return Err(TightBeamError::NonceReplayed((counter, progress.counter).into()));
		}

		let record_bytes = u64::try_from(record.content_len()).unwrap_or(u64::MAX);
		let opened_bytes = progress.opened_bytes.saturating_add(record_bytes);
		if opened_bytes > RENEWAL_VOLUME_BYTES {
			return Err(TightBeamError::RenewalBoundExceeded);
		}

		// 3. Open the content in place. The tag covers the position, so a
		//    record that opens carries the position checked above, and the
		//    `kekid` names this key's direction and epoch.
		let opened = self.aead.open(record, &self.key_identifier)?;

		// Advance only after the tag passes, because a forged record could
		// otherwise block every later legitimate one.
		self.progress = Progress { counter: counter.saturating_add(1), opened_bytes };
		Ok(opened)
	}

	#[cfg(test)]
	fn with_expected_counter(aead: RuntimeAead, counter: u64) -> Self {
		Self::with_progress(aead, counter, 0)
	}

	/// Builds a client-to-server cipher of epoch 0 that has read `counter`
	/// records, which held `opened_bytes` bytes in all.
	#[cfg(test)]
	fn with_progress(aead: RuntimeAead, counter: u64, opened_bytes: u64) -> Self {
		let progress = Progress { counter, opened_bytes };
		let key_identifier = RecordDirection::ClientToServer.key_identifier(0);
		Self {
			aead,
			epoch: 0,
			key_identifier,
			progress,
			rekey_limit: DEFAULT_REKEY_RECORD_LIMIT,
		}
	}

	/// Returns the `kekid` that every record this cipher opens must name.
	#[cfg(test)]
	fn key_identifier(&self) -> &[u8] {
		&self.key_identifier
	}
}

/// The directional record keys that a handshake or a renewal derives.
///
/// The field names use the canonical client-to-server and server-to-client
/// directions. [`SessionKeys`] maps them into send and receive sides, and
/// names each key's records by the direction of its field.
pub struct DirectionalCiphers<C> {
	/// The cipher of the client-to-server direction.
	pub client_to_server: C,
	/// The cipher of the server-to-client direction.
	pub server_to_client: C,
	/// The epoch both keys serve: 0 at the handshake, and one more at each
	/// renewal. Each record carries it.
	pub epoch: u32,
}

/// The directional session keys of one endpoint, mapped onto its role at
/// handshake completion or at a renewal.
///
/// The handshake derives one client-to-server and one server-to-client key
/// (RFC 9846 §7.3 precedent). Each endpoint sends on its own direction and
/// receives on the peer's, so record sequences stay distinct per direction.
#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
pub struct SessionKeys {
	send: SendCipher,
	recv: RecvCipher,
}

#[cfg(all(feature = "aead", feature = "signature", feature = "kdf", feature = "ecdh"))]
impl SessionKeys {
	/// Map directional keys for the client role, which sends
	/// client-to-server. Both ciphers take the keys' epoch, and each takes
	/// the direction of its field.
	pub fn for_client(ciphers: DirectionalCiphers<RuntimeAead>) -> Self {
		let DirectionalCiphers { client_to_server, server_to_client, epoch } = ciphers;
		Self {
			send: SendCipher::new(client_to_server, epoch, RecordDirection::ClientToServer),
			recv: RecvCipher::new(server_to_client, epoch, RecordDirection::ServerToClient),
		}
	}

	/// Map directional keys for the server role, which sends
	/// server-to-client. Both ciphers take the keys' epoch, and each takes
	/// the direction of its field.
	pub fn for_server(ciphers: DirectionalCiphers<RuntimeAead>) -> Self {
		let DirectionalCiphers { client_to_server, server_to_client, epoch } = ciphers;
		Self {
			send: SendCipher::new(server_to_client, epoch, RecordDirection::ServerToClient),
			recv: RecvCipher::new(client_to_server, epoch, RecordDirection::ClientToServer),
		}
	}

	/// Bound the send cipher by the encrypted-envelope ceiling the session
	/// runs under ([`SendCipher::with_envelope_ceiling`]).
	///
	/// The receive cipher counts the bytes it opens instead, so its bound holds
	/// for whatever envelopes the peer sends ([`RecvCipher`]).
	pub fn with_envelope_ceiling(mut self, encrypted_envelope: usize) -> Self {
		self.send = self.send.with_envelope_ceiling(encrypted_envelope);
		self
	}

	/// Returns the send-direction cipher.
	pub fn send(&self) -> &SendCipher {
		&self.send
	}

	/// Returns the receive-direction cipher.
	pub fn recv(&self) -> &RecvCipher {
		&self.recv
	}

	/// Returns the receive-direction cipher exclusively, which
	/// [`RecvCipher::open`] takes.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::crypto::aead::SessionKeys;
	/// use tightbeam::der::Encode;
	/// use tightbeam::testing::TestKey;
	///
	/// let mut client = SessionKeys::for_client(TestKey::insecure_directional_keys());
	/// let server = SessionKeys::for_server(TestKey::insecure_directional_keys());
	/// let mut record = server.send().encrypt_next(b"to the client".to_vec())?.to_der()?;
	///
	/// let opened = client.recv_mut().open(&mut record)?;
	/// assert_eq!(opened, b"to the client");
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn recv_mut(&mut self) -> &mut RecvCipher {
		&mut self.recv
	}

	/// Split into exclusive send and receive halves for transport ownership.
	pub fn into_parts(self) -> (SendCipher, RecvCipher) {
		(self.send, self.recv)
	}
}

#[cfg(all(
	test,
	feature = "aes-gcm",
	feature = "signature",
	feature = "kdf",
	feature = "ecdh"
))]
mod tests {
	use super::*;
	use crate::asn1::admission::fixtures::{descending_values, tlv};
	use crate::cms::enveloped_data::RecipientInfo;
	use crate::constants::DEFAULT_MAX_ENCRYPTED_ENVELOPE;
	use crate::crypto::key::KeyError;
	use crate::crypto::profiles::DefaultCryptoProvider;
	use crate::der::asn1::ObjectIdentifier as Oid;
	use crate::der::{AnyRef, Decode, Encode, ErrorKind, Header, Reader, SliceReader, Tag as DerTag, TagNumber};
	use crate::error::ReceivedExpectedError;
	use crate::testing::{unhex, TestAttributes};

	const PLAINTEXT: &[u8] = b"aead round trip";

	/// The length of [`PLAINTEXT`] in octets.
	const PLAINTEXT_LEN: u64 = 15;

	/// The key-encryption key of every test record key.
	const TEST_KEK: [u8; 32] = [0x42; 32];

	/// The `kekid` of a client-to-server record of epoch 3: the record domain
	/// `tb/session/record/kekid/v1` in hex, the direction octet `00`, then
	/// the epoch as four octets.
	const EPOCH_3_KEY_IDENTIFIER: &str = "74622f73657373696f6e2f7265636f72642f6b656b69642f76310000000003";

	/// The `id-data` content type, `1.2.840.113549.1.7.1` (RFC 5652 §4).
	const ID_DATA: Oid = Oid::new_unwrap("1.2.840.113549.1.7.1");

	fn test_runtime() -> RuntimeAead {
		RuntimeAead::new::<DefaultCryptoProvider>(TEST_KEK.to_vec()).expect("32 octets is the AES-256 wrap key")
	}

	/// Builds a client-to-server send cipher of [`TEST_KEK`] at `epoch`.
	fn test_sender(epoch: u32) -> SendCipher {
		SendCipher::new(test_runtime(), epoch, RecordDirection::ClientToServer)
	}

	/// Builds a client-to-server receive cipher of [`TEST_KEK`] at `epoch`.
	fn test_receiver(epoch: u32) -> RecvCipher {
		RecvCipher::new(test_runtime(), epoch, RecordDirection::ClientToServer)
	}

	/// Seals [`PLAINTEXT`] as a client-to-server record of epoch 0 under
	/// [`TEST_KEK`], with `attributes` beside the content type, and returns
	/// its DER.
	fn record_with(attributes: impl IntoIterator<Item = Attribute>) -> Vec<u8> {
		let key_identifier = RecordDirection::ClientToServer.key_identifier(0);
		let kek = Kek::try_from(TEST_KEK.as_slice()).expect("the test KEK is the size of the house wrap's key");
		let record = AuthEnvelopedData::seal_kek::<DefaultCryptoProvider>(
			&kek,
			&key_identifier,
			DATA,
			PLAINTEXT,
			attributes,
			None,
		);
		record.expect("the record seals").to_der().expect("the record encodes")
	}

	/// Returns the position attribute of epoch 0 and `sequence`.
	fn position_attribute(sequence: u64) -> Attribute {
		RecordSequence { epoch: 0, sequence }.attribute().expect("the position encodes")
	}

	/// Returns `record` with the two attributes of its `authAttrs` in the
	/// reverse of their DER order, and every other octet unchanged.
	fn with_attributes_swapped(record: &[u8]) -> Vec<u8> {
		let envelope = AuthEnvelopedData::from_der(record).expect("the record decodes");
		let attributes = envelope.auth_attrs.expect("a record authenticates its attributes").into_vec();
		let first = attributes.first().expect("a record carries two attributes");
		let second = attributes.get(1).expect("a record carries two attributes");
		let first = first.to_der().expect("an attribute encodes");
		let second = second.to_der().expect("an attribute encodes");

		let in_order = [first.as_slice(), second.as_slice()].concat();
		let swapped = [second.as_slice(), first.as_slice()].concat();
		let at = record.windows(in_order.len()).position(|window| window == in_order.as_slice());
		let at = at.expect("the record carries its attributes in DER order");
		[&record[..at], swapped.as_slice(), &record[at + in_order.len()..]].concat()
	}

	/// The number of values in the descending `unauthAttrs` of a forged record:
	/// sixty thousand, a 240 KB record.
	const FORGED_VALUES_LEN: u16 = 60_000;

	/// Returns the fields of the `AuthEnvelopedData` of `record`, after its
	/// header.
	fn fields_of(record: &[u8]) -> &[u8] {
		let mut reader = SliceReader::new(record).expect("a record fits a DER length");
		Header::decode(&mut reader).expect("a record starts with a header");
		let header_len = usize::try_from(reader.position()).expect("a header length fits usize");
		record.get(header_len..).expect("the header lies inside the record")
	}

	/// Returns `record` with `element` after its last field.
	fn with_trailing(record: &[u8], element: &[u8]) -> Vec<u8> {
		tlv(DerTag::Sequence, &[fields_of(record), element].concat())
	}

	/// Returns `record` with a second recipient beside its first, which
	/// differs from it in one octet, in the DER order of the two.
	fn with_two_recipients(record: &[u8]) -> Vec<u8> {
		let (version, rest) = fields_of(record).split_at(3);
		let mut reader = SliceReader::new(rest).expect("a record fits a DER length");
		let recipients = reader.tlv_bytes().expect("a record carries its recipients after its version");
		let after = &rest[recipients.len()..];

		let first = AnyRef::from_der(recipients).expect("the recipients decode").value().to_vec();
		let mut second = first.clone();
		let last = second.last_mut().expect("a recipient ends with its wrapped key");
		*last ^= 0x01;

		let mut both = [first, second];
		both.sort();

		let recipients = tlv(DerTag::Set, &both.concat());
		tlv(DerTag::Sequence, &[version, recipients.as_slice(), after].concat())
	}

	/// Returns `record` with an empty `[0] originatorInfo` after its version,
	/// where RFC 5083 §2.1 places the field.
	fn with_originator_info(record: &[u8]) -> Vec<u8> {
		let (version, rest) = fields_of(record).split_at(3);
		tlv(DerTag::Sequence, &[version, &[0xa0, 0x00], rest].concat())
	}

	/// Returns `record` with a stray `[0] { NULL }` between its
	/// `authEncryptedContentInfo` and its `[1] authAttrs`, where RFC 5083 §2.1
	/// places no field.
	fn with_stray_before_attributes(record: &[u8]) -> Vec<u8> {
		let mut reader = SliceReader::new(fields_of(record)).expect("a record fits a DER length");
		let mut fields = Vec::new();
		while !reader.is_finished() {
			fields.push(reader.tlv_bytes().expect("a record is a run of DER elements"));
		}

		fields.insert(3, &[0xa0, 0x02, 0x05, 0x00]);
		tlv(DerTag::Sequence, &fields.concat())
	}

	/// Returns `record` with its tag changed in its last octet, the last of
	/// `mac`.
	fn with_forged_tag(record: &[u8]) -> Vec<u8> {
		let mut forged = record.to_vec();
		let last = forged.last_mut().expect("a record ends with its tag");
		*last ^= 1;
		forged
	}

	/// Builds an `[2] unauthAttrs` of one attribute whose `count` values
	/// arrive in descending order.
	fn unauth_attrs(count: u16) -> Vec<u8> {
		let oid = Oid::new_unwrap("1.2.3.4").to_der().expect("a test OID encodes");
		let values = tlv(DerTag::Set, &descending_values(count));
		let attribute = tlv(DerTag::Sequence, &[oid, values].concat());
		tlv(DerTag::ContextSpecific { constructed: true, number: TagNumber::N2 }, &attribute)
	}

	/// Returns the kind of the DER error that refused a record, or `None` for
	/// another outcome.
	fn encoding_refusal(outcome: TbResult<&[u8]>) -> Option<ErrorKind> {
		match outcome {
			Err(TightBeamError::EnvelopeError(EnvelopeError::Encoding(error))) => Some(error.kind()),
			_ => None,
		}
	}

	/// Seals [`PLAINTEXT`] as the next record of `sender` and returns its DER.
	fn record_of(sender: &SendCipher) -> Vec<u8> {
		let record = sender.encrypt_next(PLAINTEXT).expect("the sender seals a record");
		record.to_der().expect("the record encodes")
	}

	/// Forges a record of epoch 0 at `sequence`, which only a sender past the
	/// record limit would seal.
	fn record_at(sequence: u64) -> Vec<u8> {
		record_with([position_attribute(sequence)])
	}

	/// Returns the position that the authenticated attributes of `record`
	/// carry.
	fn position_of(record: &[u8]) -> RecordSequence {
		let envelope = AuthEnvelopedData::from_der(record).expect("the record decodes");
		RecordSequence::carried_by(&envelope).expect("the record carries a position")
	}

	/// Returns the `kekid` and the wrapped content key of `record`.
	fn recipient_of(record: &[u8]) -> (Vec<u8>, Vec<u8>) {
		let envelope = AuthEnvelopedData::from_der(record).expect("the record decodes");
		let recipient = envelope.recipient_infos.0.as_slice().first().cloned();
		let kek = match recipient {
			Some(RecipientInfo::Kekri(kek)) => Some(kek),
			_ => None,
		};

		let kek = kek.expect("a record carries one KEKRecipientInfo");
		let key_identifier = kek.kek_id.kek_identifier.as_bytes().to_vec();
		(key_identifier, kek.encrypted_key.as_bytes().to_vec())
	}

	/// Returns `record` with the position its authenticated attributes carry
	/// rewritten to `position`, and every other field unchanged.
	fn relabelled(record: &[u8], position: RecordSequence) -> Vec<u8> {
		let mut envelope = AuthEnvelopedData::from_der(record).expect("the record decodes");
		let attribute = position.attribute().expect("the position encodes");
		let attributes = envelope.auth_attrs.take().expect("a record authenticates its attributes");
		let attributes = attributes.into_vec();
		let rest = attributes.into_iter().filter(|attribute| attribute.oid != RECORD_SEQUENCE);
		let attributes = SetOfVec::try_from(rest.chain([attribute]).collect::<Vec<_>>());

		envelope.auth_attrs = Some(attributes.expect("distinct attributes are a SET"));
		envelope.to_der().expect("the record encodes")
	}

	#[test]
	fn records_open_in_the_order_they_were_sealed() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let mut second = record_of(&sender);

		let mut receiver = test_receiver(0);
		let first_plain = receiver.open(&mut first)?.to_vec();
		let second_plain = receiver.open(&mut second)?.to_vec();
		assert_eq!(first_plain, PLAINTEXT);
		assert_eq!(second_plain, PLAINTEXT);
		Ok(())
	}

	/// The content decrypts where the record arrived, so the plaintext is a
	/// slice of the arrived buffer.
	#[test]
	fn a_record_opens_in_the_buffer_it_arrived_in() -> TbResult<()> {
		let sender = test_sender(0);
		let mut record = record_of(&sender);
		let arrived = record.as_ptr_range();

		let opened = test_receiver(0).open(&mut record)?;
		assert!(arrived.contains(&opened.as_ptr()));
		Ok(())
	}

	#[test]
	fn a_record_carries_its_epoch_and_sequence_in_its_authenticated_attributes() {
		let sender = test_sender(3);

		// The first record takes sequence 0, so the second carries 1.
		let _first = record_of(&sender);
		let second = record_of(&sender);
		assert_eq!(position_of(&second), RecordSequence { epoch: 3, sequence: 1 });
	}

	#[test]
	fn a_record_names_the_key_of_its_direction_and_epoch() {
		let sender = test_sender(3);
		let record = record_of(&sender);

		let (key_identifier, _) = recipient_of(&record);
		assert_eq!(key_identifier, unhex(EPOCH_3_KEY_IDENTIFIER));
	}

	/// A record carries the encoded envelope as `id-data` (RFC 5652 §4), in
	/// its content type and in its content-type attribute.
	#[test]
	fn a_record_declares_id_data() -> TbResult<()> {
		let sender = test_sender(0);
		let record = sender.encrypt_next(PLAINTEXT)?;
		assert_eq!(TestAttributes::declared_content_types(&record), (ID_DATA, ID_DATA));
		Ok(())
	}

	/// A record of the client's send key, reflected back to the client, names
	/// the client-to-server key, so the server-to-client cipher refuses it at
	/// its `kekid`, before the key runs.
	#[test]
	fn a_record_reflected_into_the_other_direction_is_refused_by_its_kekid() {
		let sender = SendCipher::new(test_runtime(), 0, RecordDirection::ClientToServer);
		let mut record = record_of(&sender);

		let mut receiver = RecvCipher::new(test_runtime(), 0, RecordDirection::ServerToClient);
		let refused = receiver.open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::KeyIdentifier))
		));
	}

	#[test]
	fn a_record_whose_position_holds_two_values_is_refused() -> TbResult<()> {
		let one = Any::encode_from(&RecordSequence { epoch: 0, sequence: 0 })?;
		let other = Any::encode_from(&RecordSequence { epoch: 0, sequence: 1 })?;
		let values = SetOfVec::try_from([one, other])?;
		let mut record = record_with([Attribute { oid: RECORD_SEQUENCE, values }]);

		let refused = test_receiver(0).open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	#[test]
	fn a_record_with_two_positions_is_refused() {
		let mut record = record_with([position_attribute(0), position_attribute(1)]);

		let refused = test_receiver(0).open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::AuthenticatedAttribute))
		));
	}

	#[test]
	fn a_record_with_no_position_is_refused() -> TbResult<()> {
		let values = SetOfVec::try_from([Any::encode_from(&RecordSequence { epoch: 0, sequence: 0 })?])?;
		let other = Attribute { oid: Oid::new_unwrap("1.3.6.1.4.1.99999.1.1"), values };
		let mut record = record_with([other]);

		let refused = test_receiver(0).open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::AuthenticatedAttribute))
		));
		Ok(())
	}

	/// `der` sorts a SET OF as it decodes it, so the decoded attributes of a
	/// swapped record are the sender's, and the comparison with the arrived
	/// octets is what refuses it (RFC 5083 §2.1).
	#[test]
	fn a_record_whose_attributes_arrive_out_of_der_order_is_refused() {
		let sender = test_sender(0);
		let mut record = with_attributes_swapped(&record_of(&sender));

		let refused = test_receiver(0).open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::AuthAttributesNotDer))
		));
	}

	/// The admission refuses a 240 KB record with a forged tag and sixty
	/// thousand `unauthAttrs` values in descending order, before its tag runs.
	#[test]
	fn a_record_of_descending_values_is_refused_before_its_tag() {
		let forged = with_forged_tag(&record_of(&test_sender(0)));
		let mut record = with_trailing(&forged, &unauth_attrs(FORGED_VALUES_LEN));

		let refused = test_receiver(0).open(&mut record);
		assert_eq!(encoding_refusal(refused), Some(ErrorKind::SetOrdering));
	}

	/// A record names one recipient, so the receiver refuses a set of two
	/// before `der` sorts it, ahead of the epoch the record also gets wrong.
	#[test]
	fn a_record_of_two_recipients_is_refused_before_its_epoch() {
		let mut record = with_two_recipients(&record_of(&test_sender(1)));

		let refused = test_receiver(0).open(&mut record);
		let recipients = matches!(refused, Err(TightBeamError::EnvelopeError(EnvelopeError::RecipientKind)));
		assert!(recipients);
	}

	/// The tag of a record covers no `unauthAttrs`, so the receiver refuses a
	/// record that carries them, even under a tag that passes.
	#[test]
	fn a_record_that_carries_unauthenticated_attributes_is_refused() {
		let mut record = with_trailing(&record_of(&test_sender(0)), &unauth_attrs(1));

		let refused = test_receiver(0).open(&mut record);
		let unauth_tag = DerTag::ContextSpecific { constructed: true, number: TagNumber::N2 };
		assert_eq!(encoding_refusal(refused), Some(ErrorKind::Value { tag: unauth_tag }));
	}

	/// The tag of a record covers no `originatorInfo`, so the receiver refuses
	/// a record that carries one, even under a tag that passes.
	#[test]
	fn a_record_that_carries_an_originator_is_refused() {
		let mut record = with_originator_info(&record_of(&test_sender(0)));

		let refused = test_receiver(0).open(&mut record);
		let originator_tag = DerTag::ContextSpecific { constructed: true, number: TagNumber::N0 };
		assert_eq!(encoding_refusal(refused), Some(ErrorKind::Value { tag: originator_tag }));
	}

	/// `der` skips a context-specific element whose number is below the one
	/// it looks for, so the receiver holds the decoded record to its arrival
	/// and refuses a stray `[0]` before `authAttrs`, even under a tag that
	/// passes (X.690 § 8.9.2).
	#[test]
	fn a_record_with_a_stray_context_tag_is_refused() {
		let mut record = with_stray_before_attributes(&record_of(&test_sender(0)));

		let refused = test_receiver(0).open(&mut record);
		let noncanonical = ErrorKind::Noncanonical { tag: DerTag::Sequence };
		assert_eq!(encoding_refusal(refused), Some(noncanonical));
	}

	/// Each record draws its own content key, and AES key wrap is
	/// deterministic, so two records under one key-encryption key carry two
	/// wrapped keys only when their content keys differ.
	#[test]
	fn each_record_wraps_a_fresh_content_key() {
		let sender = test_sender(0);

		let (_, first_key) = recipient_of(&record_of(&sender));
		let (_, second_key) = recipient_of(&record_of(&sender));
		assert_ne!(first_key, second_key);
	}

	#[test]
	fn a_replayed_record_is_refused() -> TbResult<()> {
		let sender = test_sender(0);
		let record = record_of(&sender);
		let mut replay = record.clone();
		let mut original = record;

		let mut receiver = test_receiver(0);
		receiver.open(&mut original)?;

		let replayed = receiver.open(&mut replay);
		let expected = ReceivedExpectedError { received: 0, expected: 1 };
		assert!(matches!(replayed, Err(TightBeamError::NonceReplayed(found)) if found == expected));
		Ok(())
	}

	#[test]
	fn a_reordered_record_is_refused() {
		let sender = test_sender(0);
		let _first = record_of(&sender);
		let mut second = record_of(&sender);

		let refused = test_receiver(0).open(&mut second);
		let expected = ReceivedExpectedError { received: 1, expected: 0 };
		assert!(matches!(refused, Err(TightBeamError::NonceReplayed(found)) if found == expected));
	}

	/// A refusal leaves the sequence unchanged, so the legitimate order opens
	/// after it.
	#[test]
	fn a_refused_record_leaves_the_sequence() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let mut second = record_of(&sender);
		let mut early = second.clone();

		// The early record fails, as `a_reordered_record_is_refused` shows, and
		// the refusal is the step under test.
		let mut receiver = test_receiver(0);
		let _refused = receiver.open(&mut early);
		receiver.open(&mut first)?;

		let opened = receiver.open(&mut second)?;
		assert_eq!(opened, PLAINTEXT);
		Ok(())
	}

	/// A record of the next sequence whose tag fails leaves the sequence, so
	/// the genuine record of that sequence still opens after it (CWE-345).
	#[test]
	fn a_record_whose_tag_fails_leaves_the_sequence() -> TbResult<()> {
		let mut first = record_of(&test_sender(0));
		let mut forged = with_forged_tag(&first);
		let mut receiver = test_receiver(0);
		let refused = receiver.open(&mut forged).is_err();

		let opened = receiver.open(&mut first)?;
		assert_eq!((refused, opened), (true, PLAINTEXT));
		Ok(())
	}

	#[test]
	fn a_deleted_record_exposes_the_next() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let _deleted = record_of(&sender);
		let mut third = record_of(&sender);

		let mut receiver = test_receiver(0);
		receiver.open(&mut first)?;

		// An attacker who excises the middle record desynchronizes the
		// sequence, so the next record exposes the deletion.
		let gapped = receiver.open(&mut third);
		let expected = ReceivedExpectedError { received: 2, expected: 1 };
		assert!(matches!(gapped, Err(TightBeamError::NonceReplayed(found)) if found == expected));
		Ok(())
	}

	/// A replay whose position an attacker rewrote to the next sequence number
	/// passes the pre-check, and the tag over the attributes refuses it, so
	/// the authenticated sequence decides.
	#[test]
	fn a_replay_relabelled_with_the_next_sequence_fails_its_tag() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let mut replay = relabelled(&first, RecordSequence { epoch: 0, sequence: 1 });

		let mut receiver = test_receiver(0);
		receiver.open(&mut first)?;

		let refused = receiver.open(&mut replay);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::Authentication))
		));
		Ok(())
	}

	#[test]
	fn a_record_of_another_epoch_is_refused() {
		let sender = test_sender(1);
		let mut record = record_of(&sender);

		let refused = test_receiver(0).open(&mut record);
		let expected = ReceivedExpectedError { received: 1, expected: 0 };
		assert!(matches!(refused, Err(TightBeamError::RecordEpoch(found)) if found == expected));
	}

	/// A record of epoch 1 relabelled to epoch 0 passes the epoch check, and
	/// its `kekid`, which names the key of epoch 1, refuses it before the key
	/// runs.
	#[test]
	fn a_record_relabelled_to_this_epoch_is_refused_by_its_kekid() {
		let sender = test_sender(1);
		let mut record = relabelled(&record_of(&sender), RecordSequence { epoch: 0, sequence: 0 });

		let refused = test_receiver(0).open(&mut record);
		assert!(matches!(
			refused,
			Err(TightBeamError::EnvelopeError(EnvelopeError::KeyIdentifier))
		));
	}

	#[test]
	fn a_record_key_of_another_size_is_refused() {
		let refused = RuntimeAead::new::<DefaultCryptoProvider>(vec![0x42u8; 16]);
		let expected = ReceivedExpectedError { received: 16, expected: 32 };
		assert!(matches!(refused, Err(TightBeamError::KeyError(KeyError::KekLength(found))) if found == expected));
	}

	#[test]
	fn send_cipher_fails_closed_on_sequence_exhaustion() {
		let sender = SendCipher::with_counter(test_runtime(), u64::MAX);
		let exhausted = sender.encrypt_next(PLAINTEXT);
		assert!(matches!(exhausted, Err(TightBeamError::NonceExhausted)));

		let still_exhausted = sender.encrypt_next(PLAINTEXT);
		assert!(matches!(still_exhausted, Err(TightBeamError::NonceExhausted)));
	}

	#[test]
	fn send_cipher_fails_closed_at_rekey_limit() -> TbResult<()> {
		let sender = test_sender(0).with_rekey_limit(2);
		sender.encrypt_next(PLAINTEXT)?;
		sender.encrypt_next(PLAINTEXT)?;

		let limited = sender.encrypt_next(PLAINTEXT);
		assert!(matches!(limited, Err(TightBeamError::RekeyRequired)));

		let still_limited = sender.encrypt_next(PLAINTEXT);
		assert!(matches!(still_limited, Err(TightBeamError::RekeyRequired)));
		Ok(())
	}

	#[test]
	fn send_cipher_clamps_rekey_limit_to_volume_bound() {
		let sender = test_sender(0).with_rekey_limit(u64::MAX);
		assert_eq!(sender.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
	}

	/// A raised envelope ceiling admits fewer records per key, and a limit
	/// configured afterwards clamps to that lower bound as well.
	#[test]
	fn send_cipher_lowers_its_limit_for_a_raised_envelope_ceiling() {
		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let bounded = test_sender(0).with_envelope_ceiling(doubled);
		assert_eq!(bounded.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);

		let raised = bounded.with_rekey_limit(u64::MAX);
		assert_eq!(raised.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);
	}

	/// A ceiling below the default leaves the default limit in place, and a
	/// zero ceiling counts as one byte, so the limit never divides by zero.
	#[test]
	fn send_cipher_keeps_its_limit_for_a_lowered_or_empty_ceiling() {
		let halved = test_sender(0).with_envelope_ceiling(DEFAULT_MAX_ENCRYPTED_ENVELOPE / 2);
		assert_eq!(halved.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);

		let empty = test_sender(0).with_envelope_ceiling(0);
		assert_eq!(empty.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
	}

	#[test]
	fn recv_cipher_threshold_never_refuses_records() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let mut second = record_of(&sender);

		let mut receiver = test_receiver(0).with_rekey_limit(1);
		receiver.open(&mut first)?;
		assert_eq!(receiver.remaining_records(), 0);

		receiver.open(&mut second)?;
		Ok(())
	}

	#[test]
	fn recv_cipher_fails_closed_at_the_record_limit() {
		let mut over_bound = record_at(DEFAULT_REKEY_RECORD_LIMIT);

		let mut receiver = RecvCipher::with_expected_counter(test_runtime(), DEFAULT_REKEY_RECORD_LIMIT);
		let refused = receiver.open(&mut over_bound);
		assert!(matches!(refused, Err(TightBeamError::RenewalBoundExceeded)));
	}

	/// A key that has opened the whole renewal volume refuses the next
	/// record, whatever its sequence number is.
	#[test]
	fn recv_cipher_fails_closed_at_the_byte_volume() {
		let mut record = record_of(&test_sender(0));

		let mut receiver = RecvCipher::with_progress(test_runtime(), 0, RENEWAL_VOLUME_BYTES);
		let refused = receiver.open(&mut record);
		assert!(matches!(refused, Err(TightBeamError::RenewalBoundExceeded)));
	}

	/// The record that brings the opened bytes exactly to the volume is the
	/// last one the key opens. A record's content is as long as its
	/// plaintext, because the tag travels in `mac`.
	#[test]
	fn recv_cipher_opens_the_record_that_reaches_the_byte_volume() -> TbResult<()> {
		let mut record = record_of(&test_sender(0));
		let already_opened = RENEWAL_VOLUME_BYTES - PLAINTEXT_LEN;

		let mut receiver = RecvCipher::with_progress(test_runtime(), 0, already_opened);
		let opened = receiver.open(&mut record)?;
		assert_eq!(opened, PLAINTEXT);
		Ok(())
	}

	/// Every opened record counts toward the volume, so the key refuses the
	/// second of two records when only the first fits.
	#[test]
	fn recv_cipher_counts_every_record_it_opens() -> TbResult<()> {
		let sender = test_sender(0);
		let mut first = record_of(&sender);
		let mut second = record_of(&sender);
		let room_for_one = RENEWAL_VOLUME_BYTES - PLAINTEXT_LEN;

		let mut receiver = RecvCipher::with_progress(test_runtime(), 0, room_for_one);
		receiver.open(&mut first)?;

		let refused = receiver.open(&mut second);
		assert!(matches!(refused, Err(TightBeamError::RenewalBoundExceeded)));
		Ok(())
	}

	/// The sender's envelopes set the per-key volume, and each peer sets its
	/// own ceiling. An honest sender at a lowered ceiling keeps the constant
	/// record limit, and receivers at the default and at a raised ceiling both
	/// accept its last record under that limit.
	#[test]
	fn a_receiver_at_any_ceiling_accepts_an_honest_sender_up_to_the_constant() -> TbResult<()> {
		let last_counter = DEFAULT_REKEY_RECORD_LIMIT - 1;
		let halved = DEFAULT_MAX_ENCRYPTED_ENVELOPE / 2;
		let sender = SendCipher::with_counter(test_runtime(), last_counter).with_envelope_ceiling(halved);
		assert_eq!(sender.rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);

		let last = record_of(&sender);
		let mut to_default = last.clone();
		let mut to_raised = last;

		let mut default_receiver = RecvCipher::with_expected_counter(test_runtime(), last_counter);
		default_receiver.open(&mut to_default)?;

		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let mut raised = SessionKeys {
			send: test_sender(0),
			recv: RecvCipher::with_expected_counter(test_runtime(), last_counter),
		}
		.with_envelope_ceiling(doubled);
		assert_eq!(raised.recv().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
		raised.recv_mut().open(&mut to_raised)?;
		Ok(())
	}

	/// Builds the directional record keys of the default provider from two
	/// fixed KEKs, at `epoch`.
	fn directional(epoch: u32) -> DirectionalCiphers<RuntimeAead> {
		let key = |fill: u8| RuntimeAead::new::<DefaultCryptoProvider>(vec![fill; 32]).expect("a 32-octet KEK");
		DirectionalCiphers { client_to_server: key(0x11), server_to_client: key(0x22), epoch }
	}

	/// The session's envelope ceiling lowers the send cipher's record limit
	/// and leaves the receive cipher at the constant, because the peer's
	/// envelopes set the receive-direction volume.
	#[test]
	fn session_keys_bound_the_send_cipher_by_the_envelope_ceiling() {
		let doubled = DEFAULT_MAX_ENCRYPTED_ENVELOPE * 2;
		let keys = SessionKeys::for_client(directional(0)).with_envelope_ceiling(doubled);
		assert_eq!(keys.send().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT / 2);
		assert_eq!(keys.recv().rekey_limit(), DEFAULT_REKEY_RECORD_LIMIT);
	}

	#[test]
	fn send_cipher_reports_remaining_records() -> TbResult<()> {
		let sender = test_sender(0).with_rekey_limit(2);
		assert_eq!(sender.remaining_records(), 2);

		sender.encrypt_next(PLAINTEXT)?;
		assert_eq!(sender.remaining_records(), 1);
		Ok(())
	}

	#[test]
	fn session_keys_role_map_is_complementary() -> TbResult<()> {
		let mut client = SessionKeys::for_client(directional(0));
		let mut server = SessionKeys::for_server(directional(0));

		let mut request = client.send().encrypt_next(PLAINTEXT)?.to_der()?;
		let request_plain = server.recv_mut().open(&mut request)?.to_vec();
		assert_eq!(request_plain, PLAINTEXT);

		let mut response = server.send().encrypt_next(PLAINTEXT)?.to_der()?;
		let response_plain = client.recv_mut().open(&mut response)?.to_vec();
		assert_eq!(response_plain, PLAINTEXT);
		Ok(())
	}

	/// The keys carry their epoch into both ciphers, so a record of the
	/// session carries it, and opens on the peer of the same epoch alone.
	#[test]
	fn session_keys_carry_their_epoch_into_both_ciphers() -> TbResult<()> {
		let mut client = SessionKeys::for_client(directional(4));
		let mut server = SessionKeys::for_server(directional(4));

		let mut request = client.send().encrypt_next(PLAINTEXT)?.to_der()?;
		let mut response = server.send().encrypt_next(PLAINTEXT)?.to_der()?;
		assert_eq!(position_of(&request), RecordSequence { epoch: 4, sequence: 0 });
		assert_eq!(position_of(&response), RecordSequence { epoch: 4, sequence: 0 });

		let request = server.recv_mut().open(&mut request)?.to_vec();
		let response = client.recv_mut().open(&mut response)?.to_vec();
		assert_eq!((request, response), (PLAINTEXT.to_vec(), PLAINTEXT.to_vec()));
		Ok(())
	}

	/// Returns the direction octet of the `kekid` of each cipher of `keys`,
	/// the send cipher's first. The octet follows the record domain.
	fn direction_octets(keys: &SessionKeys) -> (u8, u8) {
		let octet = |key_identifier: &[u8]| {
			let rest = key_identifier.strip_prefix(TIGHTBEAM_RECORD_KEY_ID_DOMAIN);
			let octet = rest.and_then(|rest| rest.first().copied());
			octet.expect("a kekid carries its direction after the record domain")
		};
		(octet(keys.send().key_identifier()), octet(keys.recv().key_identifier()))
	}

	/// Each role names each cipher's records by the direction of its key's
	/// field: `00` client to server, and `01` server to client.
	#[test]
	fn session_keys_name_each_cipher_by_the_direction_of_its_field() {
		assert_eq!(direction_octets(&SessionKeys::for_client(directional(0))), (0x00, 0x01));
		assert_eq!(direction_octets(&SessionKeys::for_server(directional(0))), (0x01, 0x00));
	}

	#[test]
	fn session_keys_directions_use_distinct_keys() -> TbResult<()> {
		let mut client = SessionKeys::for_client(directional(0));
		let mut server = SessionKeys::for_server(directional(0));

		// A request must not open under the response direction even though
		// both start at sequence zero.
		let mut request = client.send().encrypt_next(PLAINTEXT)?.to_der()?;
		let crossed = client.recv_mut().open(&mut request);
		assert!(crossed.is_err());

		let mut response = server.send().encrypt_next(PLAINTEXT)?.to_der()?;
		let crossed = server.recv_mut().open(&mut response);
		assert!(crossed.is_err());
		Ok(())
	}

	/// Write a record of epoch 3 under the fixed key `0x42` repeated 32 times.
	/// `scripts/cms-interop.sh` decrypts it with OpenSSL under that key, named
	/// by its `kekid`, when the run sets `TIGHTBEAM_CMS_SAMPLES`, which
	/// `make interop` does.
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	#[test]
	fn the_emitted_structures_write_their_interop_samples() -> TbResult<()> {
		use crate::oids::AUTH_ENVELOPED_DATA;
		use crate::transport::handshake::tests::{content_info, write_interop_samples, KekOpening};

		let sender = test_sender(3);
		let record = sender.encrypt_next(PLAINTEXT)?;
		let opening = KekOpening::new([0x42u8; 32], unhex(EPOCH_3_KEY_IDENTIFIER), PLAINTEXT);

		let samples = [("record", content_info(AUTH_ENVELOPED_DATA, &record))];
		write_interop_samples(&samples, &[("record", &opening)], &[])?;
		Ok(())
	}
}

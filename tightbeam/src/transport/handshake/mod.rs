#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::sync::Arc as ArcAlloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
pub use std::sync::Arc;
#[cfg(not(feature = "std"))]
pub use ArcAlloc as Arc;

mod error;
pub use error::HandshakeError;
mod attributes;
pub use attributes::*;

mod utils;
pub use utils::{aes_256_gcm_algorithm, aes_gcm_decrypt, aes_gcm_encrypt, generate_cek};

pub mod state;
pub use state::{
	ClientStateTransition, HandshakeMessageType, HandshakeState as ProtocolState, ServerStateTransition,
	StateTransition,
};

#[cfg(feature = "builder")]
pub mod builders;
#[cfg(feature = "builder")]
pub use builders::{KariBuilderError, TightBeamKariBuilder};

#[cfg(feature = "builder")]
pub mod processors;
#[cfg(all(feature = "builder", feature = "aead"))]
pub use processors::TightBeamEnvelopedDataProcessor;
#[cfg(feature = "builder")]
pub use processors::TightBeamKariRecipient;

pub mod client;
pub mod server;

use crate::asn1::OctetString;
use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use crate::crypto::aead::{Aes256Gcm, KeyInit};
use crate::crypto::ecies::encrypt;
use crate::crypto::hash::{Digest, Sha3_256};
use crate::crypto::kdf::{hkdf, HkdfSha3_256};
use crate::crypto::secret::ToInsecure;
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1VerifyingKey};
use crate::crypto::sign::elliptic_curve::subtle::ConstantTimeEq;
use crate::crypto::sign::Verifier;
use crate::der::{Decode, Encode, Enumerated, Sequence};
use crate::random::generate_nonce;
use crate::transport::error::TransportError;
use crate::transport::TransportEnvelope;
use crate::x509::Certificate;
use crate::Beamable;

#[cfg(feature = "std")]
use std::time::Instant;

// ============================================================================
// Certificate Validation
// ============================================================================

/// Validate certificate expiration using time feature (preferred)
#[cfg(feature = "time")]
fn validate_certificate(cert: &Certificate) -> Result<(), HandshakeError> {
	use time::OffsetDateTime;

	// Check certificate validity period using time crate
	let now = OffsetDateTime::now_utc();
	let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
	let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();

	let now_duration = time::Duration::seconds(now.unix_timestamp());

	if now_duration < not_before {
		return Err(HandshakeError::CertificateNotYetValid);
	}

	if now_duration > not_after {
		return Err(HandshakeError::CertificateExpired);
	}

	Ok(())
}

/// Validate certificate expiration using std::time (fallback)
#[cfg(all(feature = "std", not(feature = "time")))]
fn validate_certificate(cert: &Certificate) -> Result<(), HandshakeError> {
	// Check certificate validity period using std::time
	let now = std::time::SystemTime::now();
	let not_before = cert.tbs_certificate.validity.not_before.to_system_time();
	let not_after = cert.tbs_certificate.validity.not_after.to_system_time();

	if now < not_before {
		return Err(HandshakeError::CertificateNotYetValid);
	}

	if now > not_after {
		return Err(HandshakeError::CertificateExpired);
	}

	Ok(())
}

/// Validate certificate with provided timestamp (no_std without time feature)
#[cfg(all(not(feature = "std"), not(feature = "time")))]
fn validate_certificate_with_timestamp(cert: &Certificate, current_timestamp: u64) -> Result<(), HandshakeError> {
	use der::DateTime;

	let not_before = cert.tbs_certificate.validity.not_before.to_unix_duration();
	let not_after = cert.tbs_certificate.validity.not_after.to_unix_duration();

	let now_duration =
		der::asn1::GeneralizedTime::from_unix_duration(core::time::Duration::from_secs(current_timestamp))
			.map_err(|_| HandshakeError::InvalidTimestamp)?
			.to_unix_duration();

	if now_duration < not_before {
		return Err(HandshakeError::CertificateNotYetValid);
	}

	if now_duration > not_after {
		return Err(HandshakeError::CertificateExpired);
	}

	Ok(())
}

/// Validate certificate without timestamp checking (no_std without time feature)
#[cfg(all(not(feature = "std"), not(feature = "time")))]
fn validate_certificate(cert: &Certificate) -> Result<(), HandshakeError> {
	let _ = cert;
	Ok(())
}

// ============================================================================
// Server key abstraction for handshake (sign + decrypt)
// ============================================================================

/// Server-side key operations for handshake protocols.
///
/// This trait provides curve-agnostic abstractions for cryptographic operations
/// needed during server-side handshakes. Implementations handle the curve-specific
/// details internally while exposing a uniform interface.
///
/// The trait is designed to keep private key material encapsulated - all operations
/// that require the private key are performed within the trait methods, and the
/// key itself is never exposed.
#[cfg(feature = "x509")]
pub trait ServerHandshakeKey: Send + Sync {
	/// Sign a 32-byte server challenge for ECIES handshake.
	///
	/// Used during the server handshake to sign the transcript hash (derived from
	/// client random, server random, and server public key).
	///
	/// # Parameters
	/// - `msg`: 32-byte message to sign (typically a transcript hash)
	///
	/// # Returns
	/// Signature bytes in the curve's native format
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Decrypt an ECIES-encrypted message for ECIES handshake.
	///
	/// The message format is curve-specific (e.g., for secp256k1, it's a
	/// Secp256k1EciesMessage containing ephemeral public key, encrypted data,
	/// and authentication tag).
	///
	/// # Parameters
	/// - `encrypted_bytes`: The complete ECIES message in serialized form
	/// - `aad`: Optional additional authenticated data
	///
	/// # Returns
	/// Decrypted plaintext wrapped in a Secret for memory safety
	fn decrypt_ecies(
		&self,
		encrypted_bytes: &[u8],
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<Vec<u8>>, HandshakeError>;

	/// Decrypt a CMS EnvelopedData using KARI (Key Agreement Recipient Info).
	///
	/// This performs ECDH with the originator's ephemeral key, derives a KEK,
	/// and unwraps the encrypted content-encryption key. The curve type is
	/// determined by the implementation.
	///
	/// # Parameters
	/// - `enveloped_data_der`: DER-encoded CMS EnvelopedData structure
	/// - `kdf_info`: KDF info string (e.g., b"tb-kari-v1")
	/// - `recipient_index`: Index of the recipient in recipient_enc_keys (usually 0)
	///
	/// # Returns
	/// The unwrapped content-encryption key (CEK)
	#[cfg(all(feature = "builder", feature = "aead"))]
	fn decrypt_kari(
		&self,
		enveloped_data_der: &[u8],
		kdf_info: &[u8],
		recipient_index: usize,
	) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Build a CMS SignedData structure by signing content.
	///
	/// This creates a complete CMS SignedData with the server's signature,
	/// including proper digest and signature algorithm identifiers. The signature
	/// algorithm is determined by the key type.
	///
	/// # Parameters
	/// - `content`: The data to sign (typically a transcript hash)
	/// - `digest_alg`: Algorithm identifier for the digest algorithm
	/// - `signature_alg`: Algorithm identifier for the signature algorithm
	///
	/// # Returns
	/// DER-encoded CMS SignedData structure
	#[cfg(all(feature = "builder", feature = "signature"))]
	fn build_cms_signed_data(
		&self,
		content: &[u8],
		digest_alg: &crate::spki::AlgorithmIdentifierOwned,
		signature_alg: &crate::spki::AlgorithmIdentifierOwned,
	) -> core::result::Result<Vec<u8>, HandshakeError>;

	/// Get the digest algorithm identifier used by this key.
	///
	/// Returns the OID and parameters for the digest algorithm (e.g., SHA3-256).
	#[cfg(all(feature = "builder", feature = "signature"))]
	fn digest_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned;

	/// Get the signature algorithm identifier used by this key.
	///
	/// Returns the OID and parameters for the signature algorithm (e.g., ecdsa-with-SHA3-256).
	#[cfg(all(feature = "builder", feature = "signature"))]
	fn signature_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned;
}

#[cfg(all(feature = "x509", feature = "secp256k1"))]
impl ServerHandshakeKey for crate::crypto::sign::ecdsa::Secp256k1SigningKey {
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::crypto::sign::Signer;
		let sig: Secp256k1Signature = self.try_sign(msg)?;
		Ok(sig.to_bytes().to_vec())
	}

	fn decrypt_ecies(
		&self,
		encrypted_bytes: &[u8],
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<Vec<u8>>, HandshakeError> {
		use crate::crypto::ecies::decrypt;
		use crate::crypto::secret::ToInsecure;

		// Parse the ECIES message from bytes
		let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)
			.map_err(|e| HandshakeError::InvalidEciesMessage(format!("{e:?}")))?;

		// Convert to SecretKey for ECIES decryption
		let scalar = self.as_nonzero_scalar();
		let sk = k256::SecretKey::from(scalar);

		// Decrypt
		let decrypted = decrypt(&sk, &encrypted_message, aad)
			.map_err(|e| HandshakeError::EciesDecryptionFailed(format!("{e:?}")))?;

		// Convert Secret<[u8]> to Secret<Vec<u8>>
		let vec = decrypted.to_insecure().to_vec();
		Ok(crate::crypto::secret::Secret::new(Box::new(vec)))
	}

	#[cfg(all(feature = "builder", feature = "aead"))]
	fn decrypt_kari(
		&self,
		enveloped_data_der: &[u8],
		kdf_info: &[u8],
		recipient_index: usize,
	) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
		use crate::crypto::sign::elliptic_curve::PublicKey;
		use crate::transport::handshake::builders::kari::{aes_key_unwrap, hkdf_sha3_256};

		use crate::crypto::sign::elliptic_curve::SecretKey;
		use crate::der::Decode;

		// Convert to SecretKey (stays encapsulated within this method)
		let secret = SecretKey::from(self.clone());

		// Decode EnvelopedData
		let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(enveloped_data_der)?;

		// Get the recipient info
		let recipient_info = enveloped_data
			.recip_infos
			.0
			.get(recipient_index)
			.ok_or(HandshakeError::InvalidRecipientIndex)?;

		// Extract KARI
		let kari = match recipient_info {
			cms::enveloped_data::RecipientInfo::Kari(k) => k,
			_ => return Err(HandshakeError::UnsupportedOriginatorIdentifier),
		};

		// Manually perform KARI processing without requiring 'static lifetime
		// This duplicates some logic from TightBeamKariRecipient but keeps keys encapsulated
		// Extract originator's public key
		let originator_pub = match &kari.originator {
			cms::enveloped_data::OriginatorIdentifierOrKey::OriginatorKey(orig_key) => {
				let pub_key_bytes = orig_key.public_key.raw_bytes();
				PublicKey::<k256::Secp256k1>::from_sec1_bytes(pub_key_bytes)
					.map_err(|_| HandshakeError::InvalidOriginatorPublicKey)?
			}
			_ => return Err(HandshakeError::UnsupportedOriginatorIdentifier),
		};

		// Perform ECDH
		let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), originator_pub.as_affine());

		// Derive KEK using UKM as salt
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let salt = ukm.as_bytes();
		let mut kek = hkdf_sha3_256(shared_secret.raw_secret_bytes().as_ref(), salt, kdf_info, 32)?;

		// Validate recipient index for encrypted keys
		if recipient_index >= kari.recipient_enc_keys.len() {
			return Err(HandshakeError::InvalidRecipientIndex);
		}

		// Extract wrapped key
		let wrapped_key = kari.recipient_enc_keys[0].enc_key.as_bytes();
		// Unwrap to get CEK
		let cek = aes_key_unwrap(wrapped_key, &kek)?;

		// Zeroize KEK
		#[cfg(feature = "zeroize")]
		{
			use zeroize::Zeroize;
			kek.zeroize();
		}

		Ok(cek)
	}

	#[cfg(all(feature = "builder", feature = "signature"))]
	fn build_cms_signed_data(
		&self,
		content: &[u8],
		digest_alg: &crate::spki::AlgorithmIdentifierOwned,
		signature_alg: &crate::spki::AlgorithmIdentifierOwned,
	) -> core::result::Result<Vec<u8>, HandshakeError> {
		use crate::crypto::hash::Sha3_256;
		use crate::crypto::sign::ecdsa::Secp256k1Signature;
		use crate::transport::handshake::builders::TightBeamSignedDataBuilder;

		// Create builder with concrete signature and digest types
		let mut builder = TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(
			self.clone(),
			digest_alg.clone(),
			signature_alg.clone(),
		)?;

		// Build and return DER-encoded SignedData
		builder.build_der(content)
	}

	#[cfg(all(feature = "builder", feature = "signature"))]
	fn digest_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned {
		crate::spki::AlgorithmIdentifierOwned { oid: crate::HASH_SHA3_256_OID, parameters: None }
	}

	#[cfg(all(feature = "builder", feature = "signature"))]
	fn signature_algorithm(&self) -> crate::spki::AlgorithmIdentifierOwned {
		crate::spki::AlgorithmIdentifierOwned { oid: crate::SIGNER_ECDSA_WITH_SHA3_256_OID, parameters: None }
	}
}

// ============================================================================
// Handshake State Machine
// ============================================================================
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeState {
	#[default]
	None,
	#[cfg(feature = "std")]
	AwaitingServerResponse {
		initiated_at: Instant,
	},
	#[cfg(not(feature = "std"))]
	AwaitingServerResponse {
		initiated_at: u64,
	},
	#[cfg(feature = "std")]
	AwaitingClientFinish {
		initiated_at: Instant,
	},
	#[cfg(not(feature = "std"))]
	AwaitingClientFinish {
		initiated_at: u64,
	},
	Complete,
}

// ============================================================================
// Alert codes for CMS-based handshake abort signaling
// ============================================================================
#[derive(Enumerated, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeAlert {
	/// Client authentication required but missing certificate/signature
	AuthRequired = 1,
	/// Protocol version mismatch between client and server
	VersionMismatch = 2,
	/// Algorithm (profile OID) mismatch
	AlgorithmMismatch = 3,
	/// Decryption failure (ECIES / AEAD)
	DecryptFail = 4,
	/// Finished (transcript hash) MAC/signature verification failure
	FinishedIntegrityFail = 5,
}

// ============================================================================
// Handshake Protocol Abstraction
// ============================================================================

/// Client-side handshake protocol trait.
///
/// Supports multi-round handshakes where the client may need to send multiple
/// messages before completing the handshake.
pub trait ClientHandshakeProtocol: Send {
	type SessionKey: Send;
	type Error: Into<TransportError> + Send;

	/// Start the handshake, returns the first message to send to the server.
	fn start<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>, Self::Error>> + Send + 'a>>;

	/// Handle a response from the server.
	///
	/// Returns `Some(Vec<u8>)` if the client needs to send another message,
	/// or `None` if the client has no more messages to send.
	fn handle_response<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a;

	/// Complete the handshake and extract the session key.
	///
	/// Should be called after the handshake is complete (when `is_complete()` returns true).
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;
}

/// Server-side handshake protocol trait.
///
/// Supports multi-round handshakes where the server may need to handle multiple
/// requests from the client before completing the handshake.
pub trait ServerHandshakeProtocol: Send {
	type SessionKey: Send;
	type Error: Into<TransportError> + Send;

	/// Handle a request from the client.
	///
	/// Can be called multiple times for multi-round handshakes.
	/// Returns `Some(Vec<u8>)` if the server needs to send a response,
	/// or `None` if the server has no response to send.
	fn handle_request<'a, 'b>(
		&'a mut self,
		msg: &'b [u8],
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Option<Vec<u8>>, Self::Error>> + Send + 'a>>
	where
		'b: 'a;

	/// Complete the handshake and extract the session key.
	///
	/// Should be called after the handshake is complete (when `is_complete()` returns true).
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;
}

/// Legacy trait for backward compatibility.
///
/// **Deprecated**: Use `ClientHandshakeProtocol` or `ServerHandshakeProtocol` instead.
#[deprecated(
	since = "0.1.3",
	note = "Use ClientHandshakeProtocol or ServerHandshakeProtocol instead"
)]
pub trait HandshakeProtocol: Send {
	type SessionKey;
	type Error: Into<TransportError>;
	#[allow(async_fn_in_trait)]
	async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error>;
	#[allow(async_fn_in_trait)]
	async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error>;
	#[allow(async_fn_in_trait)]
	async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error>;
	#[allow(async_fn_in_trait)]
	async fn complete_server_handshake(&mut self) -> Result<Self::SessionKey, Self::Error>;
}

// ============================================================================
// Protocol Selection Enums
// ============================================================================

/// Specifies which handshake protocol to use (ECIES or CMS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeProtocolKind {
	/// Use ECIES-based handshake (default, lighter weight)
	Ecies,
	/// Use CMS-based handshake (full X.509 PKI support)
	Cms,
}

impl Default for HandshakeProtocolKind {
	fn default() -> Self {
		Self::Ecies
	}
}

// ============================================================================
// TLS-like ECIES + Server Randomness Protocol Structures
// ============================================================================

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientHello {
	pub client_random: OctetString,
}

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ServerHandshake {
	#[cfg(feature = "x509")]
	pub certificate: Certificate,
	pub server_random: OctetString,
	pub signature: OctetString,
}

#[derive(Beamable, Sequence, Debug, Clone, PartialEq)]
pub struct ClientKeyExchange {
	pub encrypted_data: OctetString,
}

// ============================================================================
// TightBeam Default Handshake Implementation
// ============================================================================

fn encode_envelope(envelope: TransportEnvelope) -> Result<Vec<u8>, TransportError> {
	Ok(envelope.to_der()?)
}

fn decode_envelope(bytes: &[u8]) -> Result<TransportEnvelope, TransportError> {
	Ok(TransportEnvelope::from_der(bytes)?)
}

fn generate_random_nonce() -> Result<[u8; 32], HandshakeError> {
	Ok(generate_nonce::<32>(None)?)
}

fn octet_string_to_array<const N: usize>(octet_string: &OctetString) -> Result<[u8; N], HandshakeError> {
	let bytes = octet_string.as_bytes();
	if bytes.len() != N {
		return Err(HandshakeError::OctetStringLengthError((bytes.len(), N).into()));
	}
	let mut out = [0u8; N];
	out.copy_from_slice(bytes);
	Ok(out)
}

fn ensure_client_role(role: HandshakeRole) -> Result<(), HandshakeError> {
	if role != HandshakeRole::Client {
		return Err(HandshakeError::InvalidState);
	}
	Ok(())
}

fn ensure_server_role(role: HandshakeRole) -> Result<(), HandshakeError> {
	if role != HandshakeRole::Server {
		return Err(HandshakeError::InvalidState);
	}
	Ok(())
}

// ============================================================================
// Idiomatic TryFrom conversions for ECIES <-> CMS types
// ============================================================================

/// Convert ClientHello to SignedData (opaque wrapper)
impl TryFrom<&ClientHello> for crate::cms::signed_data::SignedData {
	type Error = HandshakeError;

	fn try_from(hello: &ClientHello) -> Result<Self, Self::Error> {
		let message_der = hello.to_der()?;
		let octet_string = OctetString::new(message_der)?;
		let econtent = crate::der::Any::from_der(&octet_string.to_der()?)?;

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: Default::default(),
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: crate::asn1::DATA_OID,
				econtent: Some(econtent),
			},
			certificates: None,
			crls: None,
			signer_infos: SignerInfos::try_from(Vec::new())?,
		})
	}
}

/// Extract ClientHello from SignedData
impl TryFrom<&crate::cms::signed_data::SignedData> for ClientHello {
	type Error = HandshakeError;

	fn try_from(signed_data: &crate::cms::signed_data::SignedData) -> Result<Self, Self::Error> {
		let econtent_any = signed_data
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::InvalidServerKeyExchange)?;

		// econtent_any is the full DER encoding of an OCTET STRING
		let octet_string = OctetString::from_der(econtent_any.to_der()?.as_ref())?;
		Ok(ClientHello::from_der(octet_string.as_bytes())?)
	}
}

/// Convert ServerHandshake to SignedData (opaque wrapper)
impl TryFrom<&ServerHandshake> for crate::cms::signed_data::SignedData {
	type Error = HandshakeError;

	fn try_from(handshake: &ServerHandshake) -> Result<Self, Self::Error> {
		let message_der = handshake.to_der()?;
		let octet_string = OctetString::new(message_der)?;
		let econtent = crate::der::Any::from_der(&octet_string.to_der()?)?;

		Ok(SignedData {
			version: CmsVersion::V1,
			digest_algorithms: Default::default(),
			encap_content_info: EncapsulatedContentInfo {
				econtent_type: crate::asn1::DATA_OID,
				econtent: Some(econtent),
			},
			certificates: None,
			crls: None,
			signer_infos: SignerInfos::try_from(Vec::new())?,
		})
	}
}

/// Extract ServerHandshake from SignedData
impl TryFrom<&crate::cms::signed_data::SignedData> for ServerHandshake {
	type Error = HandshakeError;

	fn try_from(signed_data: &crate::cms::signed_data::SignedData) -> Result<Self, Self::Error> {
		let econtent_any = signed_data
			.encap_content_info
			.econtent
			.as_ref()
			.ok_or(HandshakeError::InvalidServerKeyExchange)?;

		// econtent_any is the full DER encoding of an OCTET STRING
		let octet_string = OctetString::from_der(econtent_any.to_der()?.as_ref())?;
		Ok(ServerHandshake::from_der(octet_string.as_bytes())?)
	}
}

/// Convert ClientKeyExchange to EnvelopedData (opaque wrapper for ECIES ciphertext)
impl TryFrom<&ClientKeyExchange> for crate::cms::enveloped_data::EnvelopedData {
	type Error = HandshakeError;

	fn try_from(kex: &ClientKeyExchange) -> Result<Self, Self::Error> {
		use crate::cms::content_info::CmsVersion;
		use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfos};
		use crate::der::asn1::OctetString;

		Ok(EnvelopedData {
			version: CmsVersion::V0,
			originator_info: None,
			recip_infos: RecipientInfos::try_from(Vec::new())?,
			encrypted_content: EncryptedContentInfo {
				content_type: crate::asn1::DATA_OID,
				content_enc_alg: crate::transport::handshake::utils::aes_256_gcm_algorithm(),
				encrypted_content: Some(OctetString::new(kex.encrypted_data.as_bytes())?),
			},
			unprotected_attrs: None,
		})
	}
}

/// Extract ClientKeyExchange from EnvelopedData
impl TryFrom<&crate::cms::enveloped_data::EnvelopedData> for ClientKeyExchange {
	type Error = HandshakeError;

	fn try_from(enveloped_data: &crate::cms::enveloped_data::EnvelopedData) -> Result<Self, Self::Error> {
		let encrypted_bytes = enveloped_data
			.encrypted_content
			.encrypted_content
			.as_ref()
			.ok_or(HandshakeError::InvalidClientKeyExchange)?
			.as_bytes();

		Ok(ClientKeyExchange { encrypted_data: OctetString::new(encrypted_bytes)? })
	}
}

fn compute_transcript_hash(client_random: &[u8; 32], server_random: &[u8; 32], spki_bytes: &[u8]) -> [u8; 32] {
	let mut data = Vec::with_capacity(32 + 32 + spki_bytes.len());
	data.extend_from_slice(client_random);
	data.extend_from_slice(server_random);
	data.extend_from_slice(spki_bytes);
	let digest_arr = Sha3_256::digest(&data);
	let mut digest = [0u8; 32];
	digest.copy_from_slice(&digest_arr);
	digest
}

fn verify_server_signature(
	verifying_key: &Secp256k1VerifyingKey,
	digest: &[u8; 32],
	signature_bytes: &[u8],
) -> Result<(), HandshakeError> {
	let signature = Secp256k1Signature::try_from(signature_bytes)?;
	verifying_key.verify(digest, &signature)?;
	Ok(())
}

fn perform_ecies_encryption(
	base_key: &[u8; 32],
	client_random: &[u8; 32],
	server_certificate: &Certificate,
	aad_domain_tag: Option<&[u8]>,
) -> Result<Vec<u8>, HandshakeError> {
	let mut plaintext = [0u8; 64];
	plaintext[..32].copy_from_slice(base_key);
	plaintext[32..].copy_from_slice(client_random);
	let server_pubkey = k256::PublicKey::from_sec1_bytes(
		server_certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes(),
	)?;
	let encrypted_message = encrypt::<_, _, _, crate::crypto::ecies::Secp256k1EciesMessage>(
		&server_pubkey,
		&plaintext,
		aad_domain_tag,
		Some(&mut rand_core::OsRng),
	)
	.map_err(|e| HandshakeError::EciesEncryptionFailed(format!("{e:?}")))?;
	Ok(encrypted_message.to_bytes())
}

/// Legacy monolithic handshake implementation.
///
/// **Deprecated**: Use `EciesHandshakeClient`/`EciesHandshakeServer` or
/// `CmsHandshakeClient`/`CmsHandshakeServer` instead for cleaner architecture.
///
/// This implementation combines both client and server logic with runtime role
/// checking, which is less type-safe than the separate orchestrator approach.
#[deprecated(
	since = "0.1.3",
	note = "Use EciesHandshakeClient/EciesHandshakeServer or CmsHandshakeClient/CmsHandshakeServer instead"
)]
pub struct TightBeamHandshake {
	role: HandshakeRole,
	client_random: Option<[u8; 32]>,
	base_session_key: Option<[u8; 32]>,
	server_random: Option<[u8; 32]>,
	server_cert: Option<Certificate>,
	server_key: Option<Arc<dyn ServerHandshakeKey>>,
	aad_domain_tag: Option<Vec<u8>>,
	server_verifying_key: Option<Secp256k1VerifyingKey>,
	pending_client_kex: Option<Vec<u8>>,
	transcript_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeRole {
	Client,
	Server,
}

#[allow(deprecated)]
impl TightBeamHandshake {
	pub fn new_client() -> Self {
		Self {
			role: HandshakeRole::Client,
			client_random: None,
			base_session_key: None,
			server_random: None,
			server_cert: None,
			server_key: None,
			aad_domain_tag: Some(b"tb-v1".to_vec()),
			server_verifying_key: None,
			pending_client_kex: None,
			transcript_hash: None,
		}
	}

	pub fn new_server(
		certificate: Certificate,
		server_key: Arc<dyn ServerHandshakeKey>,
		aad_domain_tag: Option<Vec<u8>>,
	) -> Self {
		Self {
			role: HandshakeRole::Server,
			client_random: None,
			base_session_key: None,
			server_random: None,
			server_cert: Some(certificate),
			server_key: Some(server_key),
			aad_domain_tag,
			server_verifying_key: None,
			pending_client_kex: None,
			transcript_hash: None,
		}
	}

	#[cfg(all(not(feature = "std"), not(feature = "time")))]
	pub fn validate_cert_with_timestamp(cert: &Certificate, current_timestamp: u64) -> Result<(), HandshakeError> {
		validate_certificate_with_timestamp(cert, current_timestamp)
	}

	fn derive_final_session_key(
		&self,
		base_key: &[u8; 32],
		client_random: &[u8; 32],
		server_random: &[u8; 32],
	) -> Result<Aes256Gcm, HandshakeError> {
		let mut salt = [0u8; 64];
		salt[..32].copy_from_slice(client_random);
		salt[32..].copy_from_slice(server_random);
		let final_key_bytes = hkdf::<HkdfSha3_256, 32>(base_key, b"tightbeam-session-v1", Some(&salt))?;
		Ok(Aes256Gcm::new_from_slice(&final_key_bytes[..])?)
	}
	fn extract_verifying_key(cert: &Certificate) -> Result<Secp256k1VerifyingKey, HandshakeError> {
		let spki = &cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.raw_bytes();
		let public_key = k256::PublicKey::from_sec1_bytes(public_key_bytes)?;
		Ok(Secp256k1VerifyingKey::from(public_key))
	}
}

#[allow(deprecated)]
impl HandshakeProtocol for TightBeamHandshake {
	type SessionKey = Aes256Gcm;
	type Error = TransportError;

	async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error> {
		ensure_client_role(self.role)?;
		let client_random = generate_random_nonce()?;
		self.client_random = Some(client_random);
		let client_hello = ClientHello { client_random: OctetString::new(client_random)? };
		let signed_data = crate::cms::signed_data::SignedData::try_from(&client_hello)?;
		let envelope = TransportEnvelope::SignedData(signed_data);
		encode_envelope(envelope)
	}

	async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error> {
		ensure_client_role(self.role)?;
		let envelope = decode_envelope(response)?;
		let server_handshake = match envelope {
			TransportEnvelope::SignedData(ref signed_data) => ServerHandshake::try_from(signed_data)?,
			_ => return Err(HandshakeError::InvalidServerKeyExchange.into()),
		};
		validate_certificate(&server_handshake.certificate)?;
		let server_random: [u8; 32] = octet_string_to_array(&server_handshake.server_random)?;
		self.server_random = Some(server_random);
		let verifying_key = Self::extract_verifying_key(&server_handshake.certificate)?;
		self.server_verifying_key = Some(verifying_key);
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		let spki_bytes = server_handshake
			.certificate
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let digest = compute_transcript_hash(&client_random, &server_random, spki_bytes);
		self.transcript_hash = Some(digest);
		verify_server_signature(&verifying_key, &digest, server_handshake.signature.as_bytes())?;
		let base_key = generate_random_nonce()?;
		let client_random = self.client_random.ok_or(HandshakeError::InvalidState)?;
		self.base_session_key = Some(base_key);
		let encrypted_bytes = perform_ecies_encryption(
			&base_key,
			&client_random,
			&server_handshake.certificate,
			self.aad_domain_tag.as_deref(),
		)?;
		let client_kex = ClientKeyExchange { encrypted_data: OctetString::new(encrypted_bytes)? };
		let enveloped_data = crate::cms::enveloped_data::EnvelopedData::try_from(&client_kex)?;
		let envelope = TransportEnvelope::EnvelopedData(enveloped_data);
		self.pending_client_kex = Some(encode_envelope(envelope)?);
		Ok(self.derive_final_session_key(&base_key, &client_random, &server_random)?)
	}

	async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
		ensure_server_role(self.role)?;
		let envelope = decode_envelope(request)?;
		match envelope {
			TransportEnvelope::SignedData(ref signed_data) => {
				let client_hello = ClientHello::try_from(signed_data)?;
				self.handle_client_hello(client_hello)
			}
			TransportEnvelope::EnvelopedData(ref enveloped_data) => {
				let client_kex = ClientKeyExchange::try_from(enveloped_data)?;
				let encrypted_bytes = client_kex.encrypted_data.as_bytes();
				let server_key = self.server_key.as_ref().ok_or(HandshakeError::MissingServerKey)?;
				let decrypted = server_key.decrypt_ecies(encrypted_bytes, self.aad_domain_tag.as_deref())?;
				let decrypted = decrypted.to_insecure();
				if decrypted.len() != 64 {
					return Err(HandshakeError::InvalidDecryptedPayloadSize.into());
				}
				let mut base_key = [0u8; 32];
				let mut client_random = [0u8; 32];
				base_key.copy_from_slice(&decrypted[..32]);
				client_random.copy_from_slice(&decrypted[32..]);
				let expected_client_random = self.client_random.ok_or(HandshakeError::MissingClientRandom)?;
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
				let is_equal: bool = client_random.ct_eq(&expected_client_random).into();
				if !is_equal {
					return Err(HandshakeError::ClientRandomMismatchReplay.into());
				}
				core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
				self.base_session_key = Some(base_key);
				Ok(Vec::new())
			}
			_ => Err(HandshakeError::InvalidClientKeyExchange.into()),
		}
	}

	async fn complete_server_handshake(&mut self) -> Result<Self::SessionKey, Self::Error> {
		ensure_server_role(self.role)?;
		let base_key = self.base_session_key.as_ref().ok_or(HandshakeError::MissingBaseSessionKey)?;
		let client_random = self.client_random.as_ref().ok_or(HandshakeError::MissingClientRandomState)?;
		let server_random = self.server_random.as_ref().ok_or(HandshakeError::MissingServerRandom)?;
		let final_key: Aes256Gcm = self.derive_final_session_key(base_key, client_random, server_random)?;
		if let Some(mut bk) = self.base_session_key.take() {
			bk.fill(0);
		}
		if let Some(mut cr) = self.client_random.take() {
			cr.fill(0);
		}
		if let Some(mut sr) = self.server_random.take() {
			sr.fill(0);
		}
		Ok(final_key)
	}
}

#[allow(deprecated)]
impl TightBeamHandshake {
	pub fn take_client_key_exchange(&mut self) -> Option<Vec<u8>> {
		self.pending_client_kex.take()
	}
	pub fn transcript_hash(&self) -> Option<[u8; 32]> {
		self.transcript_hash
	}
	fn handle_client_hello(&mut self, client_hello: ClientHello) -> Result<Vec<u8>, TransportError> {
		let client_random: [u8; 32] = octet_string_to_array(&client_hello.client_random)?;
		self.client_random = Some(client_random);
		let server_random = generate_random_nonce()?;
		self.server_random = Some(server_random);
		let server_key = self.server_key.as_ref().ok_or(HandshakeError::MissingServerKey)?;
		let spki_bytes = self
			.server_cert
			.as_ref()
			.ok_or(HandshakeError::MissingServerCertificate)?
			.tbs_certificate
			.subject_public_key_info
			.subject_public_key
			.raw_bytes();
		let digest = compute_transcript_hash(&client_random, &server_random, spki_bytes);
		self.transcript_hash = Some(digest);
		let sig_bytes = server_key.sign_server_challenge(&digest)?;
		let signature = Secp256k1Signature::try_from(sig_bytes.as_slice())?;
		let server_handshake = ServerHandshake {
			certificate: self.server_cert.clone().ok_or(HandshakeError::MissingServerCertificate)?,
			server_random: OctetString::new(server_random)?,
			signature: OctetString::new(signature.to_bytes().as_slice())?,
		};
		let signed_data = crate::cms::signed_data::SignedData::try_from(&server_handshake)?;
		let envelope = TransportEnvelope::SignedData(signed_data);
		encode_envelope(envelope)
	}
}

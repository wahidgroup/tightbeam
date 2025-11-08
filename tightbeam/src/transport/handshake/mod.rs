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

mod attributes;
mod error;
mod utils;

pub mod client;
pub mod server;
pub mod state;

pub use attributes::*;
pub use error::HandshakeError;
pub use state::{
	ClientStateTransition, HandshakeMessageType, HandshakeState as ProtocolState, ServerStateTransition,
	StateTransition,
};
pub use utils::{aes_256_gcm_algorithm, aes_gcm_decrypt, aes_gcm_encrypt, generate_cek};

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

#[cfg(test)]
mod tests;

use crate::asn1::OctetString;
use crate::cms::content_info::CmsVersion;
use crate::cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerInfos};
use crate::der::{Decode, Encode, Enumerated, Sequence};
use crate::transport::error::TransportError;
use crate::x509::Certificate;
use crate::Beamable;

#[cfg(feature = "std")]
use std::time::Instant;

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
	/// - `kdf_info`: KDF info string (e.g., `TIGHTBEAM_KARI_KDF_INFO`)
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
		let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)?;

		// Convert to SecretKey for ECIES decryption
		let scalar = self.as_nonzero_scalar();
		let sk = k256::SecretKey::from(scalar);

		// Decrypt
		let decrypted = decrypt(&sk, &encrypted_message, aad)?;

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
		// 1. Decode the enveloped data
		let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(enveloped_data_der)
			.map_err(|e| HandshakeError::DerError(e))?;

		// 2. Extract the KARI recipient info
		let recipient_info = enveloped_data
			.recip_infos
			.0
			.get(recipient_index)
			.ok_or(HandshakeError::InvalidRecipientIndex)?;

		let kari = match recipient_info {
			cms::enveloped_data::RecipientInfo::Kari(k) => k,
			_ => return Err(HandshakeError::UnsupportedOriginatorIdentifier),
		};

		// 3. Extract originator's public key
		use cms::enveloped_data::OriginatorIdentifierOrKey;
		let originator_pub = match &kari.originator {
			OriginatorIdentifierOrKey::OriginatorKey(orig_key) => {
				let pub_key_bytes = orig_key.public_key.raw_bytes();
				crate::crypto::sign::elliptic_curve::PublicKey::<k256::Secp256k1>::from_sec1_bytes(pub_key_bytes)
					.map_err(|_| HandshakeError::InvalidOriginatorPublicKey)?
			}
			_ => return Err(HandshakeError::UnsupportedOriginatorIdentifier),
		};

		// 4. Perform ECDH to get shared secret
		use crate::crypto::sign::elliptic_curve::ecdh::diffie_hellman;
		use crate::crypto::sign::elliptic_curve::SecretKey;
		let secret = SecretKey::from(self.clone());
		let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), originator_pub.as_affine());

		// 5. Derive KEK using HKDF
		use crate::transport::handshake::builders::kari::hkdf_sha3_256;
		let ukm = kari.ukm.as_ref().ok_or(HandshakeError::MissingUkm)?;
		let salt = ukm.as_bytes();
		let kek = hkdf_sha3_256(shared_secret.raw_secret_bytes().as_ref(), salt, kdf_info, 32)
			.map_err(|_| HandshakeError::KdfError)?;

		// 6. Unwrap the CEK
		use crate::transport::handshake::builders::kari::aes_key_unwrap;
		if recipient_index >= kari.recipient_enc_keys.len() {
			return Err(HandshakeError::InvalidRecipientIndex);
		}
		let wrapped_key = kari.recipient_enc_keys[recipient_index].enc_key.as_bytes();
		let cek = aes_key_unwrap(wrapped_key, &kek)
			.map_err(|_| HandshakeError::InvalidKeySize { expected: 32, received: 0 })?;

		// 7. Zeroize KEK for security
		#[cfg(feature = "zeroize")]
		{
			use zeroize::Zeroize;
			let mut kek_vec = kek.to_vec();
			kek_vec.zeroize();
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
// TCP Handshake State Machine
// ============================================================================
/// State tracking for TCP connection handshake process with optional timeout tracking.
/// This is distinct from the protocol-level HandshakeState in state.rs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TcpHandshakeState {
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
	/// Returns the session key wrapped in Secret for memory safety.
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
	/// Returns the session key wrapped in Secret for memory safety.
	fn complete<'a>(
		&'a mut self,
	) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Self::SessionKey, Self::Error>> + Send + 'a>>;

	/// Check if the handshake is complete.
	fn is_complete(&self) -> bool;
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
// TryFrom conversions for ECIES <-> CMS types
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

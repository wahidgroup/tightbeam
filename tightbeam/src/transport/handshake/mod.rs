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

#[cfg(all(feature = "x509", feature = "secp256k1"))]
pub trait ServerHandshakeKey: Send + Sync {
	fn sign_server_challenge(&self, msg: &[u8; 32]) -> core::result::Result<Vec<u8>, HandshakeError>;
	fn decrypt_ecies(
		&self,
		msg: &crate::crypto::ecies::Secp256k1EciesMessage,
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<[u8]>, crate::crypto::ecies::EciesError>;
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
		msg: &crate::crypto::ecies::Secp256k1EciesMessage,
		aad: Option<&[u8]>,
	) -> core::result::Result<crate::crypto::secret::Secret<[u8]>, crate::crypto::ecies::EciesError> {
		use crate::crypto::ecies::decrypt;
		let scalar = self.as_nonzero_scalar();
		let sk = k256::SecretKey::from(scalar);
		decrypt(&sk, msg, aad)
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

impl HandshakeProtocol for TightBeamHandshake {
	type SessionKey = Aes256Gcm;
	type Error = TransportError;

	async fn initiate_client(&mut self) -> Result<Vec<u8>, Self::Error> {
		ensure_client_role(self.role)?;
		let client_random = generate_random_nonce()?;
		self.client_random = Some(client_random);
		let client_hello = ClientHello { client_random: OctetString::new(client_random)? };
		let envelope = TransportEnvelope::ClientHello(client_hello);
		encode_envelope(envelope)
	}

	async fn process_server_response(&mut self, response: &[u8]) -> Result<Self::SessionKey, Self::Error> {
		ensure_client_role(self.role)?;
		let envelope = decode_envelope(response)?;
		let server_handshake = match envelope {
			TransportEnvelope::ServerHandshake(handshake) => handshake,
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
		let envelope = TransportEnvelope::ClientKeyExchange(client_kex);
		self.pending_client_kex = Some(encode_envelope(envelope)?);
		Ok(self.derive_final_session_key(&base_key, &client_random, &server_random)?)
	}

	async fn handle_client_request(&mut self, request: &[u8]) -> Result<Vec<u8>, Self::Error> {
		ensure_server_role(self.role)?;
		let envelope = decode_envelope(request)?;
		match envelope {
			TransportEnvelope::ClientHello(client_hello) => self.handle_client_hello(client_hello),
			TransportEnvelope::ClientKeyExchange(client_kex) => {
				let encrypted_bytes = client_kex.encrypted_data.as_bytes();
				let encrypted_message = crate::crypto::ecies::Secp256k1EciesMessage::from_bytes(encrypted_bytes)
					.map_err(|e| HandshakeError::InvalidEciesMessage(format!("{e:?}")))?;
				let server_key = self.server_key.as_ref().ok_or(HandshakeError::MissingServerKey)?;
				let decrypted = server_key
					.decrypt_ecies(&encrypted_message, self.aad_domain_tag.as_deref())
					.map_err(|e| HandshakeError::EciesDecryptionFailed(format!("{e:?}")))?;
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
		let envelope = TransportEnvelope::ServerHandshake(server_handshake);
		encode_envelope(envelope)
	}
}

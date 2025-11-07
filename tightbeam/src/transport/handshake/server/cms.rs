//! CMS-based server handshake orchestrator.
//!
//! Implements the server side of the TightBeam handshake protocol using
//! CMS builders and processors.

#![cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "signature",
	feature = "secp256k1"
))]

use crate::crypto::aead::{Aes256Gcm, KeyInit};
use crate::crypto::hash::Sha3_256;
use crate::crypto::sign::ecdsa::{Secp256k1Signature, Secp256k1SigningKey, Secp256k1VerifyingKey};
use crate::crypto::sign::elliptic_curve::SecretKey;
use crate::crypto::sign::EcdsaSignatureVerifier;
use crate::der::asn1::ObjectIdentifier;
use crate::spki::AlgorithmIdentifierOwned;
use crate::transport::handshake::builders::TightBeamSignedDataBuilder;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::processors::{
	AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor, TightBeamKariRecipient, TightBeamSignedDataProcessor,
};
use crate::transport::handshake::state::{HandshakeState, ServerStateTransition, StateTransition};
use crate::transport::handshake::ServerHandshakeProtocol;
use crate::x509::Certificate;

/// Server-side CMS handshake orchestrator.
///
/// Manages the complete server handshake flow:
/// 1. Receives and decrypts KeyExchange (EnvelopedData with KARI)
/// 2. Sends server Finished (SignedData)
/// 3. Receives and verifies client Finished (SignedData)
pub struct CmsHandshakeServer {
	state: ServerStateTransition,
	server_key: Secp256k1SigningKey,
	client_cert: Option<Certificate>,
	transcript_hash: Vec<u8>,
	session_key: Option<Vec<u8>>,
}

impl CmsHandshakeServer {
	/// Create a new CMS handshake server.
	///
	/// # Parameters
	/// - `server_key`: The server's signing key for authentication
	/// - `transcript_hash`: The handshake transcript hash (from previous handshake messages)
	pub fn new(server_key: Secp256k1SigningKey, transcript_hash: Vec<u8>) -> Self {
		Self {
			state: ServerStateTransition::new(),
			server_key,
			client_cert: None,
			transcript_hash,
			session_key: None,
		}
	}

	/// Set the client certificate (optional, for mutual authentication).
	pub fn set_client_certificate(&mut self, cert: Certificate) -> Result<(), HandshakeError> {
		self.client_cert = Some(cert);
		Ok(())
	}

	/// Process KeyExchange message (EnvelopedData with KARI containing session key).
	///
	/// # Parameters
	/// - `enveloped_data_der`: DER-encoded EnvelopedData from client
	///
	/// # Returns
	/// The extracted session key
	pub fn process_key_exchange(&mut self, enveloped_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::Init {
			return Err(HandshakeError::InvalidState);
		}

		// Transition to received state
		self.state.transition(HandshakeState::KeyExchangeReceived)?;

		// Create KARI processor
		let server_secret = SecretKey::from(self.server_key.clone());
		let kari_processor = TightBeamKariRecipient::new(server_secret, b"tb-kari-v1");

		// Create EnvelopedData processor
		let content_decryptor = AesGcmContentDecryptor;
		let processor = TightBeamEnvelopedDataProcessor::new(kari_processor, content_decryptor);

		// Decode and process
		use der::Decode;
		let enveloped_data = cms::enveloped_data::EnvelopedData::from_der(enveloped_data_der)?;
		let session_key = processor.process(&enveloped_data)?;

		// Store session key
		self.session_key = Some(session_key.clone());

		Ok(session_key)
	}

	/// Build server Finished message (SignedData over transcript hash).
	///
	/// # Returns
	/// DER-encoded SignedData
	pub fn build_server_finished(&mut self) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::KeyExchangeReceived {
			return Err(HandshakeError::InvalidState);
		}

		// Algorithm identifiers
		let digest_alg = AlgorithmIdentifierOwned {
			oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"), // SHA3-256
			parameters: None,
		};
		let signature_alg = AlgorithmIdentifierOwned {
			oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), // ecdsa-with-SHA256
			parameters: None,
		};

		// Build SignedData
		let mut builder = TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(
			self.server_key.clone(),
			digest_alg,
			signature_alg,
		)?;
		let signed_data_der = builder.build_der(&self.transcript_hash)?;

		// Transition state
		self.state.transition(HandshakeState::ServerFinishedSent)?;

		Ok(signed_data_der)
	}

	/// Process client Finished message (SignedData over transcript hash).
	///
	/// # Parameters
	/// - `signed_data_der`: DER-encoded SignedData from client
	///
	/// # Returns
	/// Verified transcript hash
	pub fn process_client_finished(&mut self, signed_data_der: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::ServerFinishedSent {
			return Err(HandshakeError::InvalidState);
		}

		let client_cert = self.client_cert.as_ref().ok_or(HandshakeError::MissingClientCertificate)?;

		// Extract client verifying key
		let client_verifying_key = crate::crypto::sign::elliptic_curve::PublicKey::<k256::Secp256k1>::from_sec1_bytes(
			client_cert
				.tbs_certificate
				.subject_public_key_info
				.subject_public_key
				.raw_bytes(),
		)?;
		let client_verifying_key = Secp256k1VerifyingKey::from(client_verifying_key);

		// Create verifier with proper SID checking
		let expected_sid = crate::crypto::sign::secp256k1_signer_identifier(&client_verifying_key)?;
		let verifier =
			EcdsaSignatureVerifier::<Secp256k1VerifyingKey, Secp256k1Signature, Sha3_256>::from_verifying_key_with_sid(
				client_verifying_key,
				expected_sid,
			);
		let processor = TightBeamSignedDataProcessor::new(verifier);

		// Verify signature
		let digest_oid = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"); // SHA3-256
		let verified_content = processor.process_der(signed_data_der, &digest_oid)?;

		// Verify content matches our transcript hash
		if verified_content != self.transcript_hash {
			return Err(HandshakeError::SignatureVerificationFailed);
		}

		// Transition state
		self.state.transition(HandshakeState::ClientFinishedReceived)?;

		Ok(verified_content)
	}

	/// Complete the handshake.
	pub fn complete(&mut self) -> Result<(), HandshakeError> {
		// Validate state
		if self.state.state() != HandshakeState::ClientFinishedReceived {
			return Err(HandshakeError::InvalidState);
		}

		// Transition to complete
		self.state.transition(HandshakeState::Complete)?;

		Ok(())
	}

	/// Get the current handshake state.
	pub fn state(&self) -> HandshakeState {
		self.state.state()
	}

	/// Check if handshake is complete.
	pub fn is_complete(&self) -> bool {
		self.state.state().is_complete()
	}

	/// Get the session key (if available).
	pub fn session_key(&self) -> Option<&[u8]> {
		self.session_key.as_deref()
	}
}

// ============================================================================
// ServerHandshakeProtocol Implementation
// ============================================================================

impl ServerHandshakeProtocol for CmsHandshakeServer {
	type SessionKey = Vec<u8>;
	type Error = HandshakeError;

	async fn handle_request(&mut self, msg: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
		// Determine which message type this is based on state
		match self.state() {
			HandshakeState::Init => {
				// This is KeyExchange (EnvelopedData) - process and send ServerFinished
				self.process_key_exchange(msg)?;
				let server_finished = self.build_server_finished()?;
				Ok(Some(server_finished))
			}
			HandshakeState::ServerFinishedSent => {
				// This is ClientFinished (SignedData) - no response needed
				self.process_client_finished(msg)?;
				Ok(None)
			}
			_ => Err(HandshakeError::InvalidState),
		}
	}

	async fn complete(&mut self) -> Result<Self::SessionKey, Self::Error> {
		self.complete()?;
		Ok(self.session_key().ok_or(HandshakeError::InvalidState)?.to_vec())
	}

	fn is_complete(&self) -> bool {
		self.is_complete()
	}
}

#[cfg(test)]
mod tests {
	mod server {
		use super::super::*;
		use crate::der::Decode;
		use crate::random::OsRng;
		use crate::spki::EncodePublicKey;
		use crate::transport::handshake::builders::TightBeamEnvelopedDataBuilder;
		use crate::transport::handshake::TightBeamKariBuilder;
		use crate::x509::time::Validity;
		use crate::x509::{name::RdnSequence, TbsCertificate};

		fn create_test_certificate(signing_key: &Secp256k1SigningKey) -> Certificate {
			let verifying_key = *signing_key.verifying_key();
			let public_key_der = verifying_key.to_public_key_der().unwrap();

			let tbs_cert = TbsCertificate {
				version: crate::x509::Version::V3,
				serial_number: crate::x509::serial_number::SerialNumber::new(&[1]).unwrap(),
				signature: AlgorithmIdentifierOwned {
					oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
					parameters: None,
				},
				issuer: RdnSequence::default(),
				validity: Validity {
					not_before: crate::x509::time::Time::UtcTime(
						crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(0)).unwrap(),
					),
					not_after: crate::x509::time::Time::UtcTime(
						crate::der::asn1::UtcTime::from_unix_duration(core::time::Duration::from_secs(2_000_000_000))
							.unwrap(),
					),
				},
				subject: RdnSequence::default(),
				subject_public_key_info: crate::spki::SubjectPublicKeyInfoOwned::from_der(public_key_der.as_bytes())
					.unwrap(),
				issuer_unique_id: None,
				subject_unique_id: None,
				extensions: None,
			};

			Certificate {
				tbs_certificate: tbs_cert,
				signature_algorithm: AlgorithmIdentifierOwned {
					oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
					parameters: None,
				},
				signature: crate::der::asn1::BitString::new(0, vec![0; 64]).unwrap(),
			}
		}

		#[test]
		fn test_server_state_flow() -> Result<(), Box<dyn std::error::Error>> {
			// Setup
			let server_key = Secp256k1SigningKey::random(&mut OsRng);
			let client_key = Secp256k1SigningKey::random(&mut OsRng);
			let client_cert = create_test_certificate(&client_key);
			let transcript_hash = vec![1u8; 32];

			// Create server
			let mut server = CmsHandshakeServer::new(server_key.clone(), transcript_hash.clone());
			assert_eq!(server.state(), HandshakeState::Init);

			// Set client certificate
			server.set_client_certificate(client_cert)?;

			// Build client KeyExchange
			let session_key = vec![2u8; 32];
			let server_public_key =
				crate::crypto::sign::elliptic_curve::PublicKey::<k256::Secp256k1>::from(*server_key.verifying_key());

			// Generate ephemeral sender key for KARI
			use crate::spki::EncodePublicKey;
			use cms::enveloped_data::{KeyAgreeRecipientIdentifier, UserKeyingMaterial};

			let sender_ephemeral = SecretKey::<k256::Secp256k1>::random(&mut OsRng);
			let sender_public = sender_ephemeral.public_key();
			let sender_pub_spki = sender_public.to_public_key_der().unwrap();
			let sender_pub_spki = crate::spki::SubjectPublicKeyInfoOwned::from_der(sender_pub_spki.as_bytes()).unwrap();

			// Create UKM
			let ukm = UserKeyingMaterial::new(vec![0u8; 64]).unwrap();

			// Create recipient identifier
			let rid = KeyAgreeRecipientIdentifier::IssuerAndSerialNumber(cms::cert::IssuerAndSerialNumber {
				issuer: x509_cert::name::Name::default(),
				serial_number: x509_cert::serial_number::SerialNumber::new(&[0x01]).unwrap(),
			});

			// Key encryption algorithm
			let key_enc_alg = AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.1.45"),
				parameters: None,
			};

			let kari_builder = TightBeamKariBuilder::default()
				.with_sender_priv(sender_ephemeral)
				.with_sender_pub_spki(sender_pub_spki)
				.with_recipient_pub(server_public_key)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg);
			let enveloped_builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let key_exchange = enveloped_builder.build_der(&session_key, None)?;

			// Process KeyExchange
			let extracted_key = server.process_key_exchange(&key_exchange)?;
			assert_eq!(extracted_key, session_key);
			assert_eq!(server.state(), HandshakeState::KeyExchangeReceived);
			assert_eq!(server.session_key(), Some(session_key.as_slice()));

			// Build server Finished
			let _server_finished = server.build_server_finished()?;
			assert_eq!(server.state(), HandshakeState::ServerFinishedSent);

			// Build client Finished
			let digest_alg = AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.8"),
				parameters: None,
			};
			let signature_alg =
				AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"), parameters: None };
			let mut client_finished_builder =
				TightBeamSignedDataBuilder::<Secp256k1Signature, Sha3_256>::new(client_key, digest_alg, signature_alg)?;
			let client_finished = client_finished_builder.build_der(&transcript_hash)?;

			// Process client Finished
			let verified = server.process_client_finished(&client_finished)?;
			assert_eq!(verified, transcript_hash);
			assert_eq!(server.state(), HandshakeState::ClientFinishedReceived);

			// Complete
			server.complete()?;
			assert!(server.is_complete());
			assert_eq!(server.state(), HandshakeState::Complete);

			Ok(())
		}

		#[test]
		fn test_invalid_state_transitions() -> Result<(), Box<dyn std::error::Error>> {
			let server_key = Secp256k1SigningKey::random(&mut OsRng);
			let transcript_hash = vec![1u8; 32];
			let mut server = CmsHandshakeServer::new(server_key, transcript_hash);

			// Can't build server finished before processing key exchange
			let result = server.build_server_finished();
			assert!(result.is_err());

			// Can't process client finished before sending server finished
			let result = server.process_client_finished(&[]);
			assert!(result.is_err());

			Ok(())
		}
	}
}

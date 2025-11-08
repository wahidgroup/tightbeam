//! EnvelopedData builder for TightBeam CMS handshake.
//!
//! Constructs complete CMS EnvelopedData messages with encrypted content using
//! KeyAgreeRecipientInfo for key transport.

use super::kari::TightBeamKariBuilder;
use crate::asn1::{DATA_OID, ENVELOPED_DATA_OID};
use crate::cms::builder::RecipientInfoBuilder;
use crate::cms::content_info::{CmsVersion, ContentInfo};
use crate::cms::enveloped_data::EnvelopedData;
use crate::der::asn1::{OctetString, SetOfVec};
use crate::der::Encode;
use crate::spki::AlgorithmIdentifierOwned;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::utils::{aes_256_gcm_algorithm, aes_gcm_encrypt, generate_cek};

/// Builder for constructing CMS EnvelopedData messages.
///
/// This combines:
/// - KeyAgreeRecipientInfo (built via TightBeamKariBuilder)
/// - Encrypted content (using AES-GCM with the CEK)
/// - Authenticated attributes
///
/// # Example Flow
/// 1. Generate or derive a CEK (content-encryption key)
/// 2. Build KARI using TightBeamKariBuilder to wrap the CEK
/// 3. Encrypt plaintext content with CEK using AES-GCM
/// 4. Wrap everything into EnvelopedData structure
#[cfg(all(feature = "builder", feature = "aead"))]
pub struct TightBeamEnvelopedDataBuilder<C>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
{
	kari_builder: Option<TightBeamKariBuilder<C>>,
	content_encryption_alg: Option<AlgorithmIdentifierOwned>,
	unprotected_attrs: Vec<HandshakeAttribute>,
	encryptor: Box<dyn Fn(&[u8], &[u8], Option<&[u8]>) -> Result<Vec<u8>, HandshakeError>>,
}

#[cfg(all(feature = "builder", feature = "aead"))]
impl<C> TightBeamEnvelopedDataBuilder<C>
where
	C: elliptic_curve::Curve + elliptic_curve::CurveArithmetic,
	elliptic_curve::AffinePoint<C>: elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
	elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
	/// Create a new EnvelopedData builder with the given KARI builder.
	///
	/// The KARI builder should be fully configured before passing it here,
	/// including any custom KDF info via `with_kdf_info()` for interoperability.
	///
	/// # Example
	/// ```ignore
	/// let kari = TightBeamKariBuilder::new()
	///     .with_kdf_info(b"custom-info")  // Configure KDF before passing
	///     .with_sender_priv(sender_key)
	///     .with_recipient_pub(recipient_pub);
	///
	/// let builder = TightBeamEnvelopedDataBuilder::new(kari);
	/// ```
	pub fn new(kari_builder: TightBeamKariBuilder<C>) -> Self {
		Self {
			kari_builder: Some(kari_builder),
			content_encryption_alg: None,
			unprotected_attrs: Vec::new(),
			encryptor: Box::new(aes_gcm_encrypt),
		}
	}

	/// Set the content encryption algorithm.
	///
	/// This should match the algorithm used with the encryptor function.
	pub fn with_content_encryption_alg(mut self, alg: AlgorithmIdentifierOwned) -> Self {
		self.content_encryption_alg = Some(alg);
		self
	}

	/// Add an unprotected attribute to the EnvelopedData.
	///
	/// These attributes are not encrypted or authenticated.
	pub fn with_unprotected_attr(mut self, attr: HandshakeAttribute) -> Self {
		self.unprotected_attrs.push(attr);
		self
	}

	/// Add multiple unprotected attributes.
	pub fn with_unprotected_attrs(mut self, attrs: Vec<HandshakeAttribute>) -> Self {
		self.unprotected_attrs.extend(attrs);
		self
	}

	// Helper methods

	fn validate_builder_state(&self) -> Result<(), HandshakeError> {
		if self.kari_builder.is_none() {
			return Err(HandshakeError::KariBuilderConsumed);
		}
		if self.content_encryption_alg.is_none() {
			return Err(HandshakeError::MissingContentEncryptionAlgorithm);
		}
		Ok(())
	}

	fn build_kari_with_cek(&mut self, cek: &[u8]) -> Result<cms::enveloped_data::RecipientInfo, HandshakeError> {
		let mut kari_builder = self.kari_builder.take().ok_or(HandshakeError::KariBuilderConsumed)?;
		kari_builder.build(cek).map_err(HandshakeError::CmsBuilderError)
	}

	fn encrypt_plaintext(&self, cek: &[u8], plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, HandshakeError> {
		(self.encryptor)(cek, plaintext, aad)
	}

	fn build_encrypted_content_info(
		&self,
		ciphertext: Vec<u8>,
	) -> Result<cms::enveloped_data::EncryptedContentInfo, HandshakeError> {
		let content_enc_alg = self
			.content_encryption_alg
			.as_ref()
			.ok_or(HandshakeError::MissingContentEncryptionAlgorithm)?;

		Ok(cms::enveloped_data::EncryptedContentInfo {
			content_type: DATA_OID,
			content_enc_alg: content_enc_alg.clone(),
			encrypted_content: Some(OctetString::new(ciphertext)?),
		})
	}

	fn build_unprotected_attributes(&self) -> Result<Option<x509_cert::attr::Attributes>, HandshakeError> {
		if self.unprotected_attrs.is_empty() {
			return Ok(None);
		}

		// Sort attributes for canonical DER encoding
		let mut attrs = self.unprotected_attrs.clone();
		attrs.sort();

		// Convert to x509_cert::attr::Attribute
		let x509_attrs: Result<Vec<_>, der::Error> = attrs
			.into_iter()
			.map(|attr| {
				Ok(x509_cert::attr::Attribute { oid: attr.attr_type, values: SetOfVec::try_from(attr.attr_values)? })
			})
			.collect();

		Ok(Some(SetOfVec::try_from(x509_attrs?)?))
	}

	fn build_recipient_infos(
		&self,
		recipient_info: cms::enveloped_data::RecipientInfo,
	) -> Result<cms::enveloped_data::RecipientInfos, HandshakeError> {
		cms::enveloped_data::RecipientInfos::try_from(vec![recipient_info]).map_err(HandshakeError::DerError)
	}

	/// Build the complete EnvelopedData structure.
	///
	/// # Parameters
	/// - `plaintext`: The content to encrypt
	/// - `aad`: Optional additional authenticated data for AEAD cipher
	///
	/// # Returns
	/// A complete CMS EnvelopedData structure with:
	/// - Wrapped CEK in RecipientInfo
	/// - Encrypted content
	/// - Content encryption algorithm identifier
	/// - Optional unprotected attributes
	pub fn build(mut self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<EnvelopedData, HandshakeError> {
		// 1. Validate builder state
		self.validate_builder_state()?;

		// 2. Generate CEK (content-encryption key)
		let cek = generate_cek()?;

		// 3. Build KARI with wrapped CEK
		let recipient_info = self.build_kari_with_cek(&cek)?;

		// 4. Encrypt plaintext with CEK
		let ciphertext = self.encrypt_plaintext(&cek, plaintext, aad)?;

		// 5. Build EncryptedContentInfo
		let encrypted_content_info = self.build_encrypted_content_info(ciphertext)?;

		// 6. Build unprotected attributes if present
		let unprotected_attrs = self.build_unprotected_attributes()?;

		// 7. Build RecipientInfos
		let recip_infos = self.build_recipient_infos(recipient_info)?;

		// 8. Build final EnvelopedData
		Ok(EnvelopedData {
			version: CmsVersion::V3, // V3 for KeyAgreeRecipientInfo
			originator_info: None,
			recip_infos,
			encrypted_content: encrypted_content_info,
			unprotected_attrs,
		})
	}

	/// Build and encode the EnvelopedData as DER bytes.
	pub fn build_der(self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>, HandshakeError> {
		let enveloped_data = self.build(plaintext, aad)?;
		Ok(enveloped_data.to_der()?)
	}

	/// Build and wrap in ContentInfo structure.
	pub fn build_content_info(self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<ContentInfo, HandshakeError> {
		let enveloped_data = self.build(plaintext, aad)?;

		Ok(ContentInfo {
			content_type: ENVELOPED_DATA_OID,
			content: der::Any::encode_from(&enveloped_data)?,
		})
	}
}
/// Default implementation for secp256k1 + AES-256-GCM.
#[cfg(all(
	feature = "builder",
	feature = "aead",
	feature = "secp256k1",
	feature = "kdf",
	feature = "sha3"
))]
impl TightBeamEnvelopedDataBuilder<k256::Secp256k1> {
	/// Create a builder with default TightBeam settings.
	///
	/// Uses:
	/// - secp256k1 for ECDH
	/// - HKDF-SHA3-256 for KDF
	/// - AES-256 key wrap for KEK
	/// - AES-256-GCM for content encryption
	pub fn with_defaults(kari_builder: TightBeamKariBuilder<k256::Secp256k1>) -> Self {
		Self::new(kari_builder).with_content_encryption_alg(aes_256_gcm_algorithm())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[cfg(all(
		feature = "builder",
		feature = "aead",
		feature = "secp256k1",
		feature = "kdf",
		feature = "sha3"
	))]
	mod enveloped_data {
		use super::*;
		use crate::der::Decode;
		use crate::transport::handshake::attributes::{encode_client_nonce, encode_server_nonce};
		use crate::transport::handshake::tests::{
			create_test_key_enc_alg, create_test_keypair, create_test_recipient_id, create_test_ukm,
		};

		// Test helper functions

		fn create_test_kari_builder() -> TightBeamKariBuilder<k256::Secp256k1> {
			// 1. Create sender keypair
			let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create UKM
			let ukm = create_test_ukm();

			// 3. Create recipient identifier
			let rid = create_test_recipient_id();

			// 4. Create key encryption algorithm
			let key_enc_alg = create_test_key_enc_alg();

			// 5. Build and return KARI builder
			TightBeamKariBuilder::<k256::Secp256k1>::default()
				.with_sender_priv(sender_key)
				.with_sender_pub_spki(sender_spki)
				.with_recipient_pub(recipient_pubkey)
				.with_recipient_rid(rid)
				.with_ukm(ukm)
				.with_key_enc_alg(key_enc_alg)
		}

		#[test]
		fn test_basic_enveloped_data() {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Build EnvelopedData
			let plaintext = b"Hello, TightBeam!";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let enveloped_data = builder.build(plaintext, None).unwrap();

			// 3. Verify structure
			assert_eq!(enveloped_data.version, CmsVersion::V3);
			assert_eq!(enveloped_data.recip_infos.0.len(), 1);
			assert!(enveloped_data.encrypted_content.encrypted_content.is_some());
			assert_eq!(enveloped_data.encrypted_content.content_type, DATA_OID);
		}

		#[test]
		fn test_with_unprotected_attributes() {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Create test attributes
			let client_nonce = [0x11u8; 32];
			let server_nonce = [0x22u8; 32];
			let attr1 = encode_client_nonce(&client_nonce).unwrap();
			let attr2 = encode_server_nonce(&server_nonce).unwrap();

			// 3. Build EnvelopedData with attributes
			let plaintext = b"Authenticated message";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder)
				.with_unprotected_attr(attr1)
				.with_unprotected_attr(attr2);

			let enveloped_data = builder.build(plaintext, None).unwrap();

			// 4. Verify attributes are present
			assert!(enveloped_data.unprotected_attrs.is_some());
			let attrs = enveloped_data.unprotected_attrs.unwrap();
			assert_eq!(attrs.len(), 2);
		}

		#[test]
		fn test_der_encoding() {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Build and encode
			let plaintext = b"DER encoding test";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let der_bytes = builder.build_der(plaintext, None).unwrap();

			// 3. Verify we can decode it back
			let decoded = EnvelopedData::from_der(&der_bytes).unwrap();
			assert_eq!(decoded.version, CmsVersion::V3);
		}

		#[test]
		fn test_content_info_wrapper() {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Build ContentInfo
			let plaintext = b"ContentInfo wrapper test";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let content_info = builder.build_content_info(plaintext, None).unwrap();

			// 3. Verify ContentInfo structure
			assert_eq!(content_info.content_type, ENVELOPED_DATA_OID);

			// 4. Decode inner EnvelopedData
			let enveloped_data: EnvelopedData = content_info.content.decode_as().unwrap();
			assert_eq!(enveloped_data.version, CmsVersion::V3);
		}
	}
}

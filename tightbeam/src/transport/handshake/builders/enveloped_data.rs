//! EnvelopedData builder for TightBeam CMS handshake.
//!
//! Constructs complete CMS EnvelopedData messages with encrypted content using
//! KeyAgreeRecipientInfo for key transport.

use super::kari::TightBeamKariBuilder;
use crate::asn1::{DATA_OID, ENVELOPED_DATA_OID};
use crate::cms::builder::RecipientInfoBuilder;
use crate::cms::content_info::{CmsVersion, ContentInfo};
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfo, RecipientInfos};
use crate::crypto::aead::{AeadCore, Encryptor, KeyInit};
use crate::crypto::common::typenum::Unsigned;
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, FieldBytesSize};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::der::asn1::{Any, SetOfVec};
use crate::der::Encode;
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::error::HandshakeError;
use crate::transport::handshake::utils::generate_cek;

/// Builder for constructing CMS EnvelopedData messages.
///
/// This combines:
/// - KeyAgreeRecipientInfo (built via TightBeamKariBuilder)
/// - Encrypted content (using AEAD cipher from provider)
/// - Authenticated attributes
///
/// # Example Flow
/// 1. Generate or derive a CEK (content-encryption key)
/// 2. Build KARI using TightBeamKariBuilder to wrap the CEK
/// 3. Encrypt plaintext content with CEK using provider's AEAD
/// 4. Wrap everything into EnvelopedData structure
pub struct TightBeamEnvelopedDataBuilder<P>
where
	P: CryptoProvider,
{
	kari_builder: Option<TightBeamKariBuilder<P>>,
	unprotected_attrs: Vec<HandshakeAttribute>,
}

impl<P> TightBeamEnvelopedDataBuilder<P>
where
	P: CryptoProvider,
	P::AeadCipher: KeyInit,
	AffinePoint<P::Curve>: FromEncodedPoint<P::Curve> + ToEncodedPoint<P::Curve>,
	FieldBytesSize<P::Curve>: ModulusSize,
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
	pub fn new(kari_builder: TightBeamKariBuilder<P>) -> Self {
		Self { kari_builder: Some(kari_builder), unprotected_attrs: Vec::new() }
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
			Err(HandshakeError::KariBuilderConsumed)
		} else {
			Ok(())
		}
	}

	fn build_kari_with_cek(&mut self, cek: &[u8]) -> Result<cms::enveloped_data::RecipientInfo, HandshakeError> {
		let mut kari_builder = self.kari_builder.take().ok_or(HandshakeError::KariBuilderConsumed)?;
		kari_builder.build(cek).map_err(HandshakeError::CmsBuilderError)
	}

	fn build_unprotected_attributes(&mut self) -> Result<Option<Attributes>, HandshakeError> {
		if self.unprotected_attrs.is_empty() {
			return Ok(None);
		}

		// Sort attributes for canonical DER encoding
		self.unprotected_attrs.sort();

		// Take ownership and convert to
		let attrs = core::mem::take(&mut self.unprotected_attrs);
		let x509_attrs: Result<Vec<_>, der::Error> = attrs
			.into_iter()
			.map(|attr| Ok(Attribute { oid: attr.attr_type, values: SetOfVec::try_from(attr.attr_values)? }))
			.collect();

		Ok(Some(SetOfVec::try_from(x509_attrs?)?))
	}

	fn build_recipient_infos(&self, recipient_info: RecipientInfo) -> Result<RecipientInfos, HandshakeError> {
		Ok(RecipientInfos::try_from(vec![recipient_info])?)
	}

	fn generate_nonce() -> Vec<u8> {
		use rand_core::RngCore;

		let mut nonce_bytes = vec![0u8; <P::AeadCipher as AeadCore>::NonceSize::USIZE];
		rand_core::OsRng.fill_bytes(&mut nonce_bytes);
		nonce_bytes
	}

	fn create_cipher_from_cek(cek_bytes: &[u8]) -> Result<P::AeadCipher, HandshakeError> {
		P::AeadCipher::new_from_slice(cek_bytes)
			.map_err(|_| HandshakeError::InvalidKeySize { expected: 32, received: cek_bytes.len() })
	}

	fn encrypt_content_with_cipher(
		cipher: &P::AeadCipher,
		plaintext: &[u8],
		nonce: &[u8],
	) -> Result<EncryptedContentInfo, HandshakeError>
	where
		P::AeadCipher: Encryptor<P::AeadOid>,
	{
		Ok(cipher.encrypt_content(plaintext, nonce, Some(DATA_OID))?)
	}

	/// Build the complete EnvelopedData structure.
	///
	/// # Parameters
	/// - `plaintext`: The content to encrypt
	/// - `aad`: Optional additional authenticated data for AEAD cipher (currently unused)
	///
	/// # Returns
	/// A complete CMS EnvelopedData structure with:
	/// - Wrapped CEK in RecipientInfo
	/// - Encrypted content
	/// - Content encryption algorithm identifier
	/// - Optional unprotected attributes
	pub fn build(mut self, plaintext: &[u8], _aad: Option<&[u8]>) -> Result<EnvelopedData, HandshakeError> {
		// 1. Validate builder state
		self.validate_builder_state()?;

		// 2. Generate CEK (content-encryption key) wrapped in Secret
		let cek = generate_cek()?;

		// 3. Build KARI with wrapped CEK
		let recipient_info = cek.with(|cek_bytes| self.build_kari_with_cek(cek_bytes))?;

		// 4. Encrypt plaintext with CEK
		let encrypted_content = cek.with(|cek_bytes| {
			let cipher = Self::create_cipher_from_cek(cek_bytes)?;
			let nonce = Self::generate_nonce();
			Self::encrypt_content_with_cipher(&cipher, plaintext, &nonce)
		})?;

		// 5. Build unprotected attributes
		let unprotected_attrs = self.build_unprotected_attributes()?;

		// 6. Build RecipientInfos
		let recip_infos = self.build_recipient_infos(recipient_info)?;

		// 7. Assemble final EnvelopedData
		Ok(EnvelopedData {
			version: CmsVersion::V3,
			originator_info: None,
			recip_infos,
			encrypted_content,
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
		let content = Any::encode_from(&enveloped_data)?;
		Ok(ContentInfo { content_type: ENVELOPED_DATA_OID, content })
	}
}

/// Default implementation for secp256k1 + AES-256-GCM.
impl TightBeamEnvelopedDataBuilder<DefaultCryptoProvider> {
	/// Create a builder with default TightBeam settings.
	///
	/// Uses:
	/// - secp256k1 for ECDH
	/// - HKDF-SHA3-256 for KDF
	/// - AES-256 key wrap for KEK
	/// - AES-256-GCM for content encryption
	pub fn with_defaults(kari_builder: TightBeamKariBuilder<DefaultCryptoProvider>) -> Self {
		Self::new(kari_builder)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	mod enveloped_data {
		use super::*;
		use crate::der::Decode;
		use crate::transport::handshake::attributes::{encode_client_nonce, encode_server_nonce};
		use crate::transport::handshake::tests::{
			create_test_key_enc_alg, create_test_keypair, create_test_recipient_id, create_test_ukm,
		};

		fn create_test_kari_builder() -> TightBeamKariBuilder<DefaultCryptoProvider> {
			// 1. Create sender keypair
			let (sender_key, sender_spki, _recipient_key, recipient_pubkey) = create_test_keypair();

			// 2. Create UKM
			let ukm = create_test_ukm();

			// 3. Create recipient identifier
			let rid = create_test_recipient_id();

			// 4. Create key encryption algorithm
			let key_enc_alg = create_test_key_enc_alg();

			// 5. Build and return KARI builder
			TightBeamKariBuilder::default()
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

			// 3. Verify structure
			let enveloped_data = builder.build(plaintext, None).unwrap();
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

			// 4. Verify attributes are present
			let enveloped_data = builder.build(plaintext, None).unwrap();
			assert!(enveloped_data.unprotected_attrs.is_some());

			// 5. Verify correct number of attributes
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

			// 3. Verify ContentInfo structure
			let content_info = builder.build_content_info(plaintext, None).unwrap();
			assert_eq!(content_info.content_type, ENVELOPED_DATA_OID);

			// 4. Decode inner EnvelopedData
			let enveloped_data: EnvelopedData = content_info.content.decode_as().unwrap();
			assert_eq!(enveloped_data.version, CmsVersion::V3);
		}
	}
}

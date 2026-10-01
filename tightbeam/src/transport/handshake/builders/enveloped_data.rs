//! EnvelopedData builder for the TightBeam CMS handshake.
//!
//! The builder constructs complete CMS EnvelopedData messages with encrypted
//! content, and uses KeyAgreeRecipientInfo for key transport.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use super::kari::TightBeamKariBuilder;
use crate::cms::builder::RecipientInfoBuilder;
use crate::cms::content_info::{CmsVersion, ContentInfo};
use crate::cms::enveloped_data::{EncryptedContentInfo, EnvelopedData, RecipientInfo, RecipientInfos};
use crate::crypto::aead::{AeadCore, Encryptor, KeyInit};
use crate::crypto::common::{typenum::Unsigned, KeySizeUser};
use crate::crypto::profiles::{CryptoProvider, DefaultCryptoProvider};
use crate::crypto::secret::SecretSlice;
use crate::crypto::sign::elliptic_curve::sec1::{FromEncodedPoint, ModulusSize, ToEncodedPoint};
use crate::crypto::sign::elliptic_curve::{AffinePoint, FieldBytesSize};
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::der::asn1::{Any, SetOfVec};
use crate::oids::{DATA, ENVELOPED_DATA};
use crate::random::{generate_random_bytes, CryptoRngCore, OsRng};
use crate::transport::handshake::attributes::HandshakeAttribute;
use crate::transport::handshake::error::HandshakeError;

/// Builder for constructing CMS EnvelopedData messages.
///
/// The builder combines:
///
/// - a KeyAgreeRecipientInfo, built through [`TightBeamKariBuilder`],
/// - content encrypted with the AEAD cipher of the provider, and
/// - unprotected attributes.
///
/// # Example flow
///
/// 1. Generate or derive a CEK (content-encryption key).
/// 2. Build the KARI with [`TightBeamKariBuilder`] to wrap the CEK.
/// 3. Encrypt the plaintext content with the CEK through the AEAD of the provider.
/// 4. Wrap everything into an EnvelopedData structure.
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
	/// Creates an EnvelopedData builder around `kari_builder`.
	///
	/// Configure the KARI builder fully before passing it here, including any
	/// custom KDF info through [`TightBeamKariBuilder::with_kdf_info`] for
	/// interoperability.
	pub fn new(kari_builder: TightBeamKariBuilder<P>) -> Self {
		Self { kari_builder: Some(kari_builder), unprotected_attrs: Vec::new() }
	}

	/// Adds an unprotected attribute to the EnvelopedData.
	///
	/// The EnvelopedData carries these attributes without encryption or
	/// authentication.
	pub fn with_unprotected_attr(mut self, attr: HandshakeAttribute) -> Self {
		self.unprotected_attrs.push(attr);
		self
	}

	/// Adds each attribute in `attrs` as an unprotected attribute.
	pub fn with_unprotected_attrs(mut self, attrs: impl IntoIterator<Item = HandshakeAttribute>) -> Self {
		let attrs: Vec<HandshakeAttribute> = attrs.into_iter().collect();
		self.unprotected_attrs.extend(attrs);
		self
	}

	fn validate_builder_state(&self) -> Result<(), HandshakeError> {
		if self.kari_builder.is_none() {
			Err(HandshakeError::KariBuilderConsumed)
		} else {
			Ok(())
		}
	}

	fn build_kari_with_cek(&mut self, cek: &[u8]) -> Result<cms::enveloped_data::RecipientInfo, HandshakeError> {
		let mut kari_builder = self.kari_builder.take().ok_or(HandshakeError::KariBuilderConsumed)?;
		let recipient_info = kari_builder.build(cek).map_err(HandshakeError::CmsBuilderError)?;
		Ok(recipient_info)
	}

	fn build_unprotected_attributes(&mut self) -> Result<Option<Attributes>, HandshakeError> {
		if self.unprotected_attrs.is_empty() {
			return Ok(None);
		}

		// A canonical DER SET OF encoding needs its members in sorted order.
		self.unprotected_attrs.sort();

		let attrs = core::mem::take(&mut self.unprotected_attrs);
		let x509_attrs: Result<Vec<Attribute>, HandshakeError> = attrs.into_iter().map(Attribute::try_from).collect();

		Ok(Some(SetOfVec::try_from(x509_attrs?)?))
	}

	fn build_recipient_infos(&self, recipient_info: RecipientInfo) -> Result<RecipientInfos, HandshakeError> {
		Ok(RecipientInfos::try_from(vec![recipient_info])?)
	}

	/// Returns a content nonce sized to the negotiated AEAD cipher.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	fn generate_nonce(rng: &mut dyn CryptoRngCore) -> Result<Vec<u8>, HandshakeError> {
		let mut nonce_bytes = vec![0u8; <P::AeadCipher as AeadCore>::NonceSize::USIZE];
		generate_random_bytes(&mut nonce_bytes, Some(rng))?;
		Ok(nonce_bytes)
	}

	/// Returns a random CEK sized to the negotiated AEAD cipher key length.
	///
	/// # Errors
	///
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	fn generate_cek(rng: &mut dyn CryptoRngCore) -> Result<SecretSlice<u8>, HandshakeError> {
		let mut cek = vec![0u8; <P::AeadCipher as KeySizeUser>::KeySize::USIZE];
		generate_random_bytes(&mut cek, Some(rng))?;
		Ok(cek.into())
	}

	fn create_cipher_from_cek(cek_bytes: &[u8]) -> Result<P::AeadCipher, HandshakeError> {
		P::AeadCipher::new_from_slice(cek_bytes).map_err(|_| HandshakeError::InvalidKeySize {
			expected: <P::AeadCipher as KeySizeUser>::KeySize::USIZE,
			received: cek_bytes.len(),
		})
	}

	fn encrypt_content_with_cipher(
		cipher: &P::AeadCipher,
		plaintext: impl AsRef<[u8]>,
		nonce: &[u8],
	) -> Result<EncryptedContentInfo, HandshakeError> {
		let plaintext = plaintext.as_ref();
		Ok(cipher.encrypt_content(plaintext, nonce, Some(DATA))?)
	}

	/// Builds the complete EnvelopedData structure.
	///
	/// # Parameters
	///
	/// - `plaintext`: the content to encrypt.
	/// - `rng`: the random source for the CEK and the nonce. `None` uses [`OsRng`].
	///
	/// # Returns
	///
	/// A complete CMS EnvelopedData structure with:
	///
	/// - the wrapped CEK in a RecipientInfo,
	/// - the encrypted content,
	/// - the content encryption algorithm identifier, and
	/// - optional unprotected attributes.
	///
	/// # Errors
	///
	/// - [`HandshakeError::KariBuilderConsumed`] -- the KARI builder is gone.
	/// - [`HandshakeError::RandomGenerationFailed`] -- the random source failed.
	/// - [`HandshakeError::CmsBuilderError`] -- the KARI builder failed to wrap the CEK.
	/// - [`HandshakeError::InvalidKeySize`] -- the CEK does not fit the cipher.
	/// - [`HandshakeError::DerError`] -- an attribute set or the recipient set fails to encode.
	pub fn build(
		mut self,
		plaintext: impl AsRef<[u8]>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<EnvelopedData, HandshakeError> {
		let plaintext = plaintext.as_ref();
		// 1. Validate builder state
		self.validate_builder_state()?;

		// 2. Resolve the RNG once (defaulting to OsRng) then generate the CEK
		//    sized to the negotiated AEAD cipher key length and a content
		//    nonce.
		let mut os = OsRng;
		let rng: &mut dyn CryptoRngCore = rng.unwrap_or(&mut os);
		let cek = Self::generate_cek(rng)?;
		let nonce = Self::generate_nonce(rng)?;

		// 3. Build KARI with wrapped CEK
		let recipient_info = cek.with(|cek_bytes| self.build_kari_with_cek(cek_bytes))?;

		// 4. Encrypt plaintext with CEK
		let encrypted_content = cek.with(|cek_bytes| {
			let cipher = Self::create_cipher_from_cek(cek_bytes)?;
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

	/// Builds the EnvelopedData and wraps it in a ContentInfo structure.
	///
	/// # Errors
	///
	/// - Any error of [`Self::build`].
	/// - [`HandshakeError::DerError`] -- the EnvelopedData fails to encode.
	pub fn build_content_info(
		self,
		plaintext: impl AsRef<[u8]>,
		rng: Option<&mut dyn CryptoRngCore>,
	) -> Result<ContentInfo, HandshakeError> {
		let plaintext = plaintext.as_ref();
		let enveloped_data = self.build(plaintext, rng)?;
		let content = Any::encode_from(&enveloped_data)?;
		Ok(ContentInfo { content_type: ENVELOPED_DATA, content })
	}
}

/// Default implementation for secp256k1 and AES-256-GCM.
impl TightBeamEnvelopedDataBuilder<DefaultCryptoProvider> {
	/// Creates a builder with the default TightBeam settings.
	///
	/// The defaults are:
	///
	/// - secp256k1 for ECDH,
	/// - HKDF-SHA3-256 for the KDF,
	/// - AES-256 key wrap for the KEK, and
	/// - AES-256-GCM for content encryption.
	pub fn with_defaults(kari_builder: TightBeamKariBuilder<DefaultCryptoProvider>) -> Self {
		Self::new(kari_builder)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	mod enveloped_data {
		use rand_core::{CryptoRng, Error as RandomError, RngCore};

		use super::*;
		use crate::der::asn1::OctetString;
		use crate::der::{Decode, Encode};
		use crate::oids::{HANDSHAKE_CLIENT_NONCE, HANDSHAKE_SERVER_NONCE};
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

		/// A random source that refuses every draw. No real source can be made
		/// to refuse on demand, so the refusal path needs this double.
		struct DrainedRng;

		impl RngCore for DrainedRng {
			fn next_u32(&mut self) -> u32 {
				0
			}

			fn next_u64(&mut self) -> u64 {
				0
			}

			fn fill_bytes(&mut self, _dest: &mut [u8]) {}

			fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), RandomError> {
				Err(RandomError::new("the source is drained"))
			}
		}

		impl CryptoRng for DrainedRng {}

		/// A draw the random source refuses fails the build, rather than
		/// leaving a zero key.
		#[test]
		fn a_refused_random_draw_fails_the_build() {
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(create_test_kari_builder());
			let refused = builder.build(b"payload", Some(&mut DrainedRng));
			assert!(matches!(refused, Err(HandshakeError::RandomGenerationFailed)));
		}

		#[test]
		fn test_basic_enveloped_data() -> Result<(), Box<dyn core::error::Error>> {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();
			// 2. Create the EnvelopedData builder
			let plaintext = b"Hello, TightBeam!";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);

			// 3. Build the EnvelopedData and verify its structure
			let enveloped_data = builder.build(plaintext, None)?;
			assert_eq!(enveloped_data.version, CmsVersion::V3);
			assert_eq!(enveloped_data.recip_infos.0.len(), 1);
			assert!(enveloped_data.encrypted_content.encrypted_content.is_some());
			assert_eq!(enveloped_data.encrypted_content.content_type, DATA);

			Ok(())
		}

		#[test]
		fn test_with_unprotected_attributes() -> Result<(), Box<dyn core::error::Error>> {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Create test attributes
			let client_nonce = Any::encode_from(&OctetString::new([0x11u8; 32])?)?;
			let server_nonce = Any::encode_from(&OctetString::new([0x22u8; 32])?)?;
			let attr1 = HandshakeAttribute::new_single(HANDSHAKE_CLIENT_NONCE, client_nonce)?;
			let attr2 = HandshakeAttribute::new_single(HANDSHAKE_SERVER_NONCE, server_nonce)?;

			// 3. Build EnvelopedData with attributes
			let plaintext = b"Authenticated message";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder)
				.with_unprotected_attr(attr1)
				.with_unprotected_attr(attr2);

			// 4. Build the EnvelopedData
			let enveloped_data = builder.build(plaintext, None)?;

			// 5. Verify correct number of attributes
			let Some(attrs) = enveloped_data.unprotected_attrs.as_ref() else {
				return Err(crate::testing::error::TestingError::InvariantViolated.into());
			};

			assert_eq!(attrs.len(), 2);
			Ok(())
		}

		#[test]
		fn test_der_encoding() -> Result<(), Box<dyn core::error::Error>> {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Build and encode
			let plaintext = b"DER encoding test";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);
			let built = builder.build(plaintext, None)?;
			let der_bytes = built.to_der()?;

			// 3. Verify we can decode it back
			let decoded = EnvelopedData::from_der(&der_bytes)?;
			assert_eq!(decoded.version, CmsVersion::V3);

			Ok(())
		}

		#[test]
		fn test_content_info_wrapper() -> Result<(), Box<dyn core::error::Error>> {
			// 1. Create test KARI builder
			let kari_builder = create_test_kari_builder();

			// 2. Create the EnvelopedData builder
			let plaintext = b"ContentInfo wrapper test";
			let builder = TightBeamEnvelopedDataBuilder::with_defaults(kari_builder);

			// 3. Build the ContentInfo and verify its content type
			let content_info = builder.build_content_info(plaintext, None)?;
			assert_eq!(content_info.content_type, ENVELOPED_DATA);

			// 4. Decode inner EnvelopedData
			let enveloped_data: EnvelopedData = content_info.content.decode_as()?;
			assert_eq!(enveloped_data.version, CmsVersion::V3);

			Ok(())
		}
	}
}

//! ASN.1 structures for prekey-based handshake protocols.
//!
//! PREVIEW: behind the `preview-pqc` feature, so the API may change until a
//! PQXDH protocol consumes these structures.
//!
//! Provides standard structures for asynchronous key agreement protocols
//! like PQXDH where one party publishes prekey bundles offline.

use crate::asn1::OctetString;
use crate::cms::enveloped_data::EnvelopedData;
use crate::der::Sequence;
use crate::spki::SubjectPublicKeyInfoOwned;
use crate::Beamable;

/// Prekey bundle for PQXDH-style protocols.
///
/// PREVIEW: a PQXDH prekey structure behind `preview-pqc`.
///
/// Contains the public key material that a party publishes for asynchronous
/// key agreement. Other parties retrieve this bundle and use it to establish
/// a shared secret without real-time interaction.
///
/// # Fields
/// - `identity_key`: Long-term identity public key (EC)
/// - `signed_prekey`: Medium-term signed prekey (EC)
/// - `signed_prekey_signature`: Signature over signed_prekey by identity_key
/// - `prekey_ids`: Identifiers for retrieving/referencing keys
/// - `onetime_prekey`: Optional single-use prekey (EC)
/// - `pq_prekey`: Optional post-quantum KEM public key
#[derive(Sequence, Clone, Debug, PartialEq, Beamable)]
pub struct PrekeyBundle {
	/// Identity public key (long-term)
	pub identity_key: SubjectPublicKeyInfoOwned,

	/// Signed prekey (medium-term)
	pub signed_prekey: SubjectPublicKeyInfoOwned,

	/// Signature over signed prekey
	pub signed_prekey_signature: OctetString,

	/// Prekey identifiers for retrieval
	pub prekey_ids: PrekeyIdentifiers,

	/// One-time prekey (single-use, optional)
	#[asn1(optional = "true")]
	pub onetime_prekey: Option<SubjectPublicKeyInfoOwned>,

	/// Post-quantum KEM public key
	#[asn1(optional = "true")]
	pub pq_prekey: Option<OctetString>,
}

/// Identifiers for prekeys in a bundle.
///
/// PREVIEW: a PQXDH prekey structure behind `preview-pqc`.
///
/// Used to reference specific prekeys when constructing initial messages,
/// and for tracking/rotating prekeys on the server. Each optional identifier
/// carries its own context tag, so a post-quantum identifier decodes into its
/// own field when the one-time identifier is absent.
#[derive(Sequence, Clone, Debug, PartialEq, Eq, Beamable)]
pub struct PrekeyIdentifiers {
	/// Signed prekey ID
	pub signed_prekey_id: u32,

	/// One-time prekey ID (if used)
	#[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
	pub onetime_prekey_id: Option<u32>,

	/// Post-quantum prekey ID (if used)
	#[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
	pub pq_prekey_id: Option<u32>,
}

/// Initial message in a PQXDH-style handshake.
///
/// PREVIEW: a PQXDH prekey structure behind `preview-pqc`.
///
/// Sent by the initiating party to establish a shared secret with a party
/// whose prekey bundle was retrieved. Contains the initiator's identity,
/// ephemeral key, and reference to which prekeys were used.
///
/// # Fields
/// - `sender_identity`: Initiator's identity public key
/// - `sender_ephemeral`: Initiator's ephemeral public key for this session
/// - `used_prekeys`: Identifiers of which prekeys from bundle were used
/// - `encrypted_payload`: Initial message encrypted under derived session key
/// - `kem_ciphertext`: KEM encapsulation output (if using PQ prekey)
#[derive(Sequence, Clone, Debug, PartialEq, Beamable)]
pub struct PrekeyInitialMessage {
	/// Sender's identity key
	pub sender_identity: SubjectPublicKeyInfoOwned,

	/// Sender's ephemeral key
	pub sender_ephemeral: SubjectPublicKeyInfoOwned,

	/// Which prekeys this message uses
	pub used_prekeys: PrekeyIdentifiers,

	/// Encrypted initial payload
	pub encrypted_payload: EnvelopedData,

	/// KEM ciphertext (if using PQ prekey)
	#[asn1(optional = "true")]
	pub kem_ciphertext: Option<OctetString>,
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::asn1::{BitString, ObjectIdentifier};
	use crate::der::{Decode, Encode};
	use crate::spki::AlgorithmIdentifierOwned;

	fn create_test_spki() -> SubjectPublicKeyInfoOwned {
		// Create a minimal valid SPKI for testing
		SubjectPublicKeyInfoOwned {
			algorithm: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
				parameters: None,
			},
			subject_public_key: BitString::from_bytes(&[0x04, 0x01, 0x02])
				.expect("fixed point bytes form a valid BitString"),
		}
	}

	#[test]
	fn test_prekey_identifiers_encode_decode() -> Result<(), Box<dyn std::error::Error>> {
		let ids = PrekeyIdentifiers { signed_prekey_id: 42, onetime_prekey_id: Some(123), pq_prekey_id: Some(999) };

		let encoded = ids.to_der()?;
		let decoded = PrekeyIdentifiers::from_der(&encoded)?;
		assert_eq!(ids.signed_prekey_id, decoded.signed_prekey_id);
		assert_eq!(ids.onetime_prekey_id, decoded.onetime_prekey_id);
		assert_eq!(ids.pq_prekey_id, decoded.pq_prekey_id);
		Ok(())
	}

	/// Each optional identifier decodes into its own field when the other is
	/// absent.
	#[test]
	fn a_lone_optional_identifier_decodes_into_its_own_field() -> Result<(), Box<dyn std::error::Error>> {
		let pq_alone = PrekeyIdentifiers { signed_prekey_id: 42, onetime_prekey_id: None, pq_prekey_id: Some(999) };
		let onetime_alone = PrekeyIdentifiers { pq_prekey_id: None, onetime_prekey_id: Some(999), ..pq_alone };
		let pq_encoded = pq_alone.to_der()?;
		let onetime_encoded = onetime_alone.to_der()?;

		let pq_decoded = PrekeyIdentifiers::from_der(&pq_encoded)?;
		let onetime_decoded = PrekeyIdentifiers::from_der(&onetime_encoded)?;
		assert_eq!((pq_decoded, onetime_decoded), (pq_alone, onetime_alone));
		Ok(())
	}

	#[test]
	fn test_prekey_bundle_minimal() -> Result<(), Box<dyn std::error::Error>> {
		let bundle = PrekeyBundle {
			identity_key: create_test_spki(),
			signed_prekey: create_test_spki(),
			signed_prekey_signature: OctetString::new([0x01, 0x02, 0x03])?,
			onetime_prekey: None,
			pq_prekey: None,
			prekey_ids: PrekeyIdentifiers { signed_prekey_id: 1, onetime_prekey_id: None, pq_prekey_id: None },
		};

		let encoded = bundle.to_der()?;
		let decoded = PrekeyBundle::from_der(&encoded)?;
		assert_eq!(decoded, bundle);
		Ok(())
	}
}

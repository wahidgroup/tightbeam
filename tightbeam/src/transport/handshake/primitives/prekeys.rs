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
	use crate::spki::AlgorithmIdentifierOwned;
	use crate::testing::fixtures::der_round_trip;
	use crate::testing::TestResult;

	/// A minimal SPKI: the EC public key algorithm over a three-octet point.
	fn create_test_spki() -> SubjectPublicKeyInfoOwned {
		let point = BitString::from_bytes(&[0x04, 0x01, 0x02]);
		let point = point.expect("fixed point bytes form a valid BitString");

		SubjectPublicKeyInfoOwned {
			algorithm: AlgorithmIdentifierOwned {
				oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
				parameters: None,
			},
			subject_public_key: point,
		}
	}

	// Prekey identifiers decode from their DER into the fields they were
	// encoded from.
	crate::tb_cases! {
		fn prekey_identifiers_round_trip_through_der((onetime, pq): (Option<u32>, Option<u32>)) {
			let ids = PrekeyIdentifiers { signed_prekey_id: 42, onetime_prekey_id: onetime, pq_prekey_id: pq };
			let decoded = der_round_trip(&ids);
			assert_eq!(decoded, ids);
		}
		cases {
			with_all_three => (Some(123), Some(999)),
			/// The post-quantum identifier decodes into its own field when
			/// the one-time identifier is absent.
			with_pq_alone => (None, Some(999)),
			/// The one-time identifier decodes into its own field when the
			/// post-quantum identifier is absent.
			with_onetime_alone => (Some(999), None),
		}
	}

	/// A prekey bundle of its mandatory fields alone decodes from its DER into
	/// the bundle it was encoded from.
	#[test]
	fn a_minimal_prekey_bundle_round_trips_through_der() -> TestResult {
		let bundle = PrekeyBundle {
			identity_key: create_test_spki(),
			signed_prekey: create_test_spki(),
			signed_prekey_signature: OctetString::new([0x01, 0x02, 0x03])?,
			onetime_prekey: None,
			pq_prekey: None,
			prekey_ids: PrekeyIdentifiers { signed_prekey_id: 1, onetime_prekey_id: None, pq_prekey_id: None },
		};

		let decoded = der_round_trip(&bundle);
		assert_eq!(decoded, bundle);
		Ok(())
	}
}

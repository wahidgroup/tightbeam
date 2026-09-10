#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(all(
	not(feature = "std"),
	any(feature = "transport-cms", feature = "transport-ecies")
))]
use alloc::vec::Vec;

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use core::cmp::{Ord, Ordering, PartialOrd};

use crate::crypto::x509::attr::Attribute;
use crate::der::asn1::{Any, ObjectIdentifier, UintRef};

#[cfg(feature = "transport-cms")]
use crate::cms::signed_data::SignedData;
#[cfg(feature = "transport-cms")]
use crate::der::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::der::{Sequence, Tagged};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};

use super::{HandshakeAlert, HandshakeError};
#[cfg(feature = "transport-cms")]
use crate::oids::{
	HANDSHAKE_SECURITY_ACCEPT, HANDSHAKE_SECURITY_OFFER, HANDSHAKE_TRANSPORT_ACCEPT, HANDSHAKE_TRANSPORT_OFFER,
	RECEIPT_ACK, SESSION_RECEIPT,
};

/// CMS Attribute simplified (profile enforces single value only)
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAttribute {
	/// OID naming the attribute (RFC 5652 § 5.3 `attrType`).
	pub attr_type: ObjectIdentifier,
	/// Attribute values; the profile requires exactly one element.
	pub attr_values: Vec<Any>,
}

// Provide ordering for canonical DER SET OF encoding. Order by attr_type OID bytes,
// then lexicographically by each value's encoding (tag octet, then content octets).
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl PartialOrd for HandshakeAttribute {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl Ord for HandshakeAttribute {
	fn cmp(&self, other: &Self) -> Ordering {
		let oid_ord = self.attr_type.as_bytes().cmp(other.attr_type.as_bytes());
		if oid_ord != Ordering::Equal {
			return oid_ord;
		}

		let lhs = self.attr_values.iter().map(any_encoding_key);
		let rhs = other.attr_values.iter().map(any_encoding_key);
		lhs.cmp(rhs)
	}
}

/// Deterministic comparison key for an `Any`: tag octet followed by content octets.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
fn any_encoding_key(any: &Any) -> (u8, &[u8]) {
	(u8::from(any.tag()), any.value())
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeAttribute {
	pub fn new_single(attr_type: ObjectIdentifier, value: Any) -> Result<Self, HandshakeError> {
		Ok(Self { attr_type, attr_values: vec![value] })
	}

	pub fn value(&self) -> Result<&Any, HandshakeError> {
		if self.attr_values.len() != 1 {
			return Err(HandshakeError::InvalidAttributeArity);
		}
		Ok(&self.attr_values[0])
	}
}

/// Convert X.509 Attribute to HandshakeAttribute.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl From<&Attribute> for HandshakeAttribute {
	fn from(attr: &Attribute) -> Self {
		HandshakeAttribute { attr_type: attr.oid, attr_values: attr.values.clone().into() }
	}
}

/// A payload carried as a handshake attribute under its own OID.
///
/// Each implementation is the one home for its type's attribute OID, so
/// the encode and decode sides agree on which OID names which type.
#[cfg(feature = "transport-cms")]
pub trait AttributePayload {
	/// OID this payload is carried under.
	const OID: ObjectIdentifier;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for SecurityOffer {
	const OID: ObjectIdentifier = HANDSHAKE_SECURITY_OFFER;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for SecurityAccept {
	const OID: ObjectIdentifier = HANDSHAKE_SECURITY_ACCEPT;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for TransportOffer {
	const OID: ObjectIdentifier = HANDSHAKE_TRANSPORT_OFFER;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for TransportAccept {
	const OID: ObjectIdentifier = HANDSHAKE_TRANSPORT_ACCEPT;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for SignedData {
	const OID: ObjectIdentifier = SESSION_RECEIPT;
}

#[cfg(feature = "transport-cms")]
impl AttributePayload for OctetString {
	const OID: ObjectIdentifier = RECEIPT_ACK;
}

#[cfg(feature = "transport-cms")]
impl HandshakeAttribute {
	/// Encodes `payload` under its own OID for wire transmission.
	pub fn encode<T>(payload: &T) -> Result<Self, HandshakeError>
	where
		T: AttributePayload + Tagged + crate::der::EncodeValue,
	{
		Self::new_single(T::OID, Any::encode_from(payload)?)
	}

	/// Decodes this attribute, requiring the OID `T` is carried under.
	///
	/// An attribute of another type yields [`HandshakeError::MissingAttribute`],
	/// so a peer cannot substitute one negotiated value for another.
	pub fn decode<'a, T>(&'a self) -> Result<T, HandshakeError>
	where
		T: AttributePayload + crate::der::Choice<'a> + crate::der::DecodeValue<'a>,
	{
		if self.attr_type != T::OID {
			return Err(HandshakeError::MissingAttribute);
		}

		Ok(self.value()?.decode_as()?)
	}

	/// The bytes this attribute's value arrived as.
	///
	/// A receiver binds what the peer actually sent. Re-encoding the decoded
	/// value instead would erase any difference the decoder normalised away:
	/// `der` sorts a `SET OF` before validating it, so a reordered set would
	/// hash the same as the well-ordered one and pass unseen (CWE-345).
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the attribute carries no
	///   value.
	pub fn received_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
		use crate::der::Encode;

		Ok(self.value()?.to_der()?)
	}

	/// Canonical DER bytes of `payload` for transcript binding.
	///
	/// The sender's half of the pairing with [`Self::received_bytes`]: these
	/// are the bytes about to go on the wire, so both sides hash the same
	/// encoding and a tampered attribute diverges the two transcript hashes
	/// (CWE-345).
	pub fn transcript_bytes<T>(payload: &T) -> Result<Vec<u8>, HandshakeError>
	where
		T: AttributePayload + Tagged + crate::der::EncodeValue,
	{
		use crate::der::Encode;

		Ok(Any::encode_from(payload)?.to_der()?)
	}
}

// -------------------------- Decoders --------------------------

/// Decode a one- or two-byte unsigned INTEGER from an `Any`.
fn u16_from_any(any: &Any) -> Result<u16, HandshakeError> {
	let uint_ref: UintRef = any.decode_as().map_err(|_| HandshakeError::InvalidIntegerEncoding)?;
	let b = uint_ref.as_bytes();
	if b.is_empty() || b.len() > 2 {
		return Err(HandshakeError::IntegerOutOfRange);
	}
	if b.len() == 1 {
		return Ok(b[0] as u16);
	}

	Ok(((b[0] as u16) << 8) | b[1] as u16)
}

/// Decode an alert code from a single INTEGER-bearing `Any`.
///
/// Alert codes occupy the u8 domain. Wider values are rejected outright so a
/// two-byte code can never alias a valid alert through truncation.
fn alert_from_any(any: &Any) -> Result<HandshakeAlert, HandshakeError> {
	let code = u16_from_any(any)?;
	if code > u8::MAX as u16 {
		return Err(HandshakeError::IntegerOutOfRange);
	}

	match code as u8 {
		1 => Ok(HandshakeAlert::AuthRequired),
		2 => Ok(HandshakeAlert::VersionMismatch),
		3 => Ok(HandshakeAlert::AlgorithmMismatch),
		4 => Ok(HandshakeAlert::DecryptFail),
		5 => Ok(HandshakeAlert::FinishedIntegrityFail),
		code => Err(HandshakeError::UnknownAlertCode(code)),
	}
}

// -------------------------- Attribute search --------------------------

#[cfg(feature = "transport-cms")]
pub fn find<'a>(
	attrs: &'a [HandshakeAttribute],
	oid: &ObjectIdentifier,
) -> Result<&'a HandshakeAttribute, HandshakeError> {
	let mut found: Option<&HandshakeAttribute> = None;
	for a in attrs.iter() {
		if &a.attr_type == oid {
			if found.is_some() {
				return Err(HandshakeError::DuplicateAttribute);
			}

			found = Some(a);
		}
	}

	found.ok_or(HandshakeError::MissingAttribute)
}

/// Find an X.509 attribute by OID without cloning
pub fn find_x509<'a>(attrs: &'a [&Attribute], oid: &ObjectIdentifier) -> Result<&'a Attribute, HandshakeError> {
	let mut found: Option<&Attribute> = None;
	for a in attrs.iter() {
		if &a.oid == oid {
			if found.is_some() {
				return Err(HandshakeError::DuplicateAttribute);
			}
			found = Some(a);
		}
	}

	found.ok_or(HandshakeError::MissingAttribute)
}

// -------------------------- Tests --------------------------
/// Handshake attribute lookups on a CMS `SignedData`.
#[cfg(feature = "transport-cms")]
pub trait HandshakeAttributes {
	/// Find at most one unsigned attribute with `oid` across the
	/// SignerInfos of a parsed Finished message, rejecting duplicates.
	///
	/// [RFC 5652 §11.4](https://datatracker.ietf.org/doc/html/rfc5652#section-11.4)
	/// permits repeated unsigned attributes, but every TightBeam handshake
	/// attribute is single-use: a duplicate is either a builder bug or an
	/// injection attempt, and fails closed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] when the oid repeats
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError>;
}

#[cfg(feature = "transport-cms")]
impl HandshakeAttributes for SignedData {
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		let mut found = None;
		let matches = self
			.signer_infos
			.0
			.iter()
			.filter_map(|signer_info| signer_info.unsigned_attrs.as_ref())
			.flat_map(|attrs| attrs.iter())
			.filter(|attr| attr.oid == oid);

		for attr in matches {
			if found.is_some() {
				return Err(HandshakeError::DuplicateAttribute);
			}

			found = Some(HandshakeAttribute::from(attr));
		}

		Ok(found)
	}
}

/// Handshake alert decoding on the x509-cert `Attribute`.
pub trait HandshakeAlertAttribute {
	/// Alert code carried by this attribute.
	///
	/// The profile admits one value, so any other arity is refused.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidAttributeArity`] on any arity but one
	/// - [`HandshakeError::IntegerOutOfRange`] on a code above `u8::MAX`
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError>;
}

impl HandshakeAlertAttribute for Attribute {
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError> {
		if self.values.len() != 1 {
			return Err(HandshakeError::InvalidAttributeArity);
		}

		let value = self.values.get(0).ok_or(HandshakeError::InvalidAttributeArity)?;

		alert_from_any(value)
	}
}

#[cfg(all(test, feature = "transport-cms"))]
mod tests {
	use super::*;
	use crate::der::asn1::Any;
	use crate::der::asn1::{OctetString as DerOctetString, SetOfVec, UintRef};
	use crate::oids::{HANDSHAKE_ABORT_ALERT, HANDSHAKE_SECURITY_ACCEPT};

	fn mk_integer(bytes: &[u8]) -> Result<Any, der::Error> {
		let u = UintRef::new(bytes)?;
		Any::encode_from(&u)
	}

	fn mk_octet(bytes: &[u8]) -> Result<Any, der::Error> {
		let os = DerOctetString::new(bytes)?;
		Any::encode_from(&os)
	}

	fn mk_alert_attr(bytes: &[u8]) -> Result<Attribute, der::Error> {
		Ok(Attribute {
			oid: HANDSHAKE_ABORT_ALERT,
			values: SetOfVec::try_from(vec![mk_integer(bytes)?])?,
		})
	}

	/// A receiver binds what arrived. `der` sorts a `SET OF` before it
	/// validates one, so a value that re-encodes to different bytes than it
	/// arrived as would let that normalisation erase tamper evidence
	/// (CWE-345, U-107).
	#[test]
	fn the_transcript_binds_the_bytes_an_attribute_arrived_as() -> Result<(), HandshakeError> {
		use crate::der::{Decode, Encode};

		// A SET OF whose members are out of DER order. Decoding sorts them,
		// so the decoded value no longer describes what was sent.
		let unsorted = Any::from_der(&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01])?;
		let attribute = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_ACCEPT, unsorted.to_owned())?;
		assert_eq!(attribute.received_bytes()?, unsorted.to_der()?);
		Ok(())
	}

	#[test]
	fn duplicate_detected() -> Result<(), HandshakeError> {
		let a1 = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, mk_octet(&[0x11u8; 32])?)?;
		let a2 = a1.to_owned();
		let attrs = vec![a1, a2];
		assert!(matches!(
			find(&attrs, &HANDSHAKE_SECURITY_OFFER),
			Err(HandshakeError::DuplicateAttribute)
		));
		Ok(())
	}

	#[test]
	fn missing_attribute_detected() -> Result<(), HandshakeError> {
		let only = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, mk_octet(&[0x22u8; 32])?)?;
		let attrs = vec![only];
		assert!(matches!(
			find(&attrs, &HANDSHAKE_SECURITY_ACCEPT),
			Err(HandshakeError::MissingAttribute)
		));
		Ok(())
	}

	#[test]
	fn invalid_attribute_arity() -> Result<(), der::Error> {
		let any = mk_octet(&[0x33u8; 32])?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![any.to_owned(), any] };
		assert!(matches!(attr.value(), Err(HandshakeError::InvalidAttributeArity)));
		Ok(())
	}

	#[test]
	fn alert_code_mapping() -> Result<(), HandshakeError> {
		let alerts = [
			(HandshakeAlert::AuthRequired, 1u8),
			(HandshakeAlert::VersionMismatch, 2u8),
			(HandshakeAlert::AlgorithmMismatch, 3u8),
			(HandshakeAlert::DecryptFail, 4u8),
			(HandshakeAlert::FinishedIntegrityFail, 5u8),
		];
		for (alert, code) in alerts.iter() {
			let attr = mk_alert_attr(&[*code])?;
			assert_eq!(attr.handshake_alert()?, *alert);
		}

		let unknown = mk_alert_attr(&[0x07])?;
		assert!(matches!(unknown.handshake_alert(), Err(HandshakeError::UnknownAlertCode(7))));
		Ok(())
	}

	#[test]
	fn alert_integer_out_of_range_rejected() -> Result<(), der::Error> {
		// Three-byte INTEGER exceeds the u16 decode domain outright.
		let wide = mk_alert_attr(&[0x01, 0x02, 0x03])?;
		assert!(matches!(wide.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));

		// 0x0101 = 257. Truncating to u8 would alias alert code 1 (AuthRequired).
		let above = mk_alert_attr(&[0x01, 0x01])?;
		assert!(matches!(above.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));
		Ok(())
	}

	#[test]
	fn attribute_ord_tiebreaks_on_value() -> Result<(), der::Error> {
		let low = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![mk_integer(&[0x01])?] };
		let high = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![mk_integer(&[0x02])?] };
		assert_eq!(low.cmp(&high), Ordering::Less);
		assert_eq!(high.cmp(&low), Ordering::Greater);
		assert_eq!(low.cmp(&low.to_owned()), Ordering::Equal);
		Ok(())
	}
}

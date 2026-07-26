#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
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
	pub attr_type: ObjectIdentifier,
	pub attr_values: Vec<Any>, // MUST contain exactly one value under profile
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

// -------------------------- Builders --------------------------

/// Encode SecurityOffer for wire transmission.
///
/// Client uses this to advertise supported security profiles to server.
#[cfg(feature = "transport-cms")]
pub fn encode_security_offer(offer: &SecurityOffer) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(offer)?;
	HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, any)
}

/// Encode SecurityAccept for wire transmission.
///
/// Server uses this to inform client which profile was selected.
#[cfg(feature = "transport-cms")]
pub fn encode_security_accept(accept: &SecurityAccept) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(accept)?;
	HandshakeAttribute::new_single(HANDSHAKE_SECURITY_ACCEPT, any)
}

/// Canonical DER bytes of a `SecurityAccept` for transcript binding.
///
/// Both handshake sides append these bytes to the transcript before the
/// Finished hash is computed, binding the negotiated profile to the
/// signature (CWE-345): a tampered accept attribute changes the client's
/// transcript hash and fails signature verification.
#[cfg(feature = "transport-cms")]
pub fn security_accept_transcript_bytes(accept: &SecurityAccept) -> Result<Vec<u8>, HandshakeError> {
	use crate::der::Encode;

	Ok(Any::encode_from(accept)?.to_der()?)
}

/// Encode TransportOffer for wire transmission.
///
/// Client uses this to advertise transport capabilities (multiplexing).
#[cfg(feature = "transport-cms")]
pub fn encode_transport_offer(offer: &TransportOffer) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(offer)?;
	HandshakeAttribute::new_single(HANDSHAKE_TRANSPORT_OFFER, any)
}

/// Encode TransportAccept for wire transmission.
///
/// Server uses this to activate multiplexing offered by the client.
#[cfg(feature = "transport-cms")]
pub fn encode_transport_accept(accept: &TransportAccept) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(accept)?;
	HandshakeAttribute::new_single(HANDSHAKE_TRANSPORT_ACCEPT, any)
}

/// Canonical DER bytes of a `TransportAccept` for transcript binding.
///
/// Same contract as [`security_accept_transcript_bytes`]: a tampered
/// transport accept attribute changes the transcript hash and fails
/// signature verification (CWE-345).
#[cfg(feature = "transport-cms")]
pub fn transport_accept_transcript_bytes(accept: &TransportAccept) -> Result<Vec<u8>, HandshakeError> {
	use crate::der::Encode;

	Ok(Any::encode_from(accept)?.to_der()?)
}

/// Encode a session receipt artifact attribute (CMS carriage): the
/// server-signed receipt `SignedData`.
#[cfg(feature = "transport-cms")]
pub fn encode_session_receipt(artifact: &SignedData) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(artifact)?;
	HandshakeAttribute::new_single(SESSION_RECEIPT, any)
}

/// Encode a receipt acknowledgement attribute. The octets are a
/// DER-encoded EnvelopedData encrypted to the server whose plaintext is
/// the client's receipt `SignerInfo`. Neither the countersignature nor
/// the settlement answer bound inside it travels the cleartext wire.
#[cfg(feature = "transport-cms")]
pub fn encode_receipt_ack(envelope: &OctetString) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(envelope)?;
	HandshakeAttribute::new_single(RECEIPT_ACK, any)
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

/// Extract SecurityOffer from unprotected attributes.
///
/// # Parameters
/// - `attr`: HandshakeAttribute with HANDSHAKE_SECURITY_OFFER_OID type
///
/// # Returns
/// The decoded SecurityOffer
#[cfg(feature = "transport-cms")]
pub fn extract_security_offer(attr: &HandshakeAttribute) -> Result<SecurityOffer, HandshakeError> {
	if attr.attr_type != HANDSHAKE_SECURITY_OFFER {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract SecurityAccept from unprotected attributes.
///
/// # Parameters
/// - `attr`: HandshakeAttribute with HANDSHAKE_SECURITY_ACCEPT_OID type
///
/// # Returns
/// The decoded SecurityAccept
#[cfg(feature = "transport-cms")]
pub fn extract_security_accept(attr: &HandshakeAttribute) -> Result<SecurityAccept, HandshakeError> {
	if attr.attr_type != HANDSHAKE_SECURITY_ACCEPT {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract TransportOffer from unprotected attributes.
#[cfg(feature = "transport-cms")]
pub fn extract_transport_offer(attr: &HandshakeAttribute) -> Result<TransportOffer, HandshakeError> {
	if attr.attr_type != HANDSHAKE_TRANSPORT_OFFER {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract TransportAccept from unprotected attributes.
#[cfg(feature = "transport-cms")]
pub fn extract_transport_accept(attr: &HandshakeAttribute) -> Result<TransportAccept, HandshakeError> {
	if attr.attr_type != HANDSHAKE_TRANSPORT_ACCEPT {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract the server-signed receipt `SignedData` artifact from
/// unprotected attributes.
#[cfg(feature = "transport-cms")]
pub fn extract_session_receipt(attr: &HandshakeAttribute) -> Result<SignedData, HandshakeError> {
	if attr.attr_type != SESSION_RECEIPT {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract the enveloped receipt-acknowledgement bytes from unprotected
/// attributes.
#[cfg(feature = "transport-cms")]
pub fn extract_receipt_ack(attr: &HandshakeAttribute) -> Result<OctetString, HandshakeError> {
	if attr.attr_type != RECEIPT_ACK {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Find at most one unsigned attribute with `oid` across the SignerInfos
/// of a parsed Finished message, rejecting duplicates.
///
/// [RFC 5652 §11.4](https://datatracker.ietf.org/doc/html/rfc5652#section-11.4)
/// permits repeated unsigned attributes, but every TightBeam handshake
/// attribute is single-use: a duplicate is either a builder bug or an
/// injection attempt, and fails closed.
#[cfg(feature = "transport-cms")]
pub fn find_unsigned_attr(
	signed_data: &SignedData,
	oid: ObjectIdentifier,
) -> Result<Option<HandshakeAttribute>, HandshakeError> {
	let mut found = None;
	let matches = signed_data
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

/// Extract alert from X.509 attribute without cloning
pub fn extract_alert_x509(attr: &Attribute) -> Result<HandshakeAlert, HandshakeError> {
	// Convert values to Vec<Any> (unavoidable due to SetOfVec API)
	let values: Vec<Any> = attr.values.clone().into();
	if values.len() != 1 {
		return Err(HandshakeError::InvalidAttributeArity);
	}

	alert_from_any(&values[0])
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

	#[test]
	fn duplicate_detected() -> Result<(), HandshakeError> {
		let a1 = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, mk_octet(&[0x11u8; 32])?)?;
		let a2 = a1.to_owned();
		let attrs = vec![a1, a2];
		assert!(matches!(
			find(&attrs, &HANDSHAKE_SECURITY_OFFER).unwrap_err(),
			HandshakeError::DuplicateAttribute
		));
		Ok(())
	}

	#[test]
	fn missing_attribute_detected() -> Result<(), HandshakeError> {
		let only = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, mk_octet(&[0x22u8; 32])?)?;
		let attrs = vec![only];
		assert!(matches!(
			find(&attrs, &HANDSHAKE_SECURITY_ACCEPT).unwrap_err(),
			HandshakeError::MissingAttribute
		));
		Ok(())
	}

	#[test]
	fn invalid_attribute_arity() -> Result<(), der::Error> {
		let any = mk_octet(&[0x33u8; 32])?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![any.to_owned(), any] };
		assert!(matches!(attr.value().unwrap_err(), HandshakeError::InvalidAttributeArity));
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
			assert_eq!(extract_alert_x509(&attr)?, *alert);
		}

		let unknown = mk_alert_attr(&[0x07])?;
		assert!(matches!(
			extract_alert_x509(&unknown).unwrap_err(),
			HandshakeError::UnknownAlertCode(7)
		));
		Ok(())
	}

	#[test]
	fn alert_integer_out_of_range_rejected() -> Result<(), der::Error> {
		// Three-byte INTEGER exceeds the u16 decode domain outright.
		let wide = mk_alert_attr(&[0x01, 0x02, 0x03])?;
		assert!(matches!(
			extract_alert_x509(&wide).unwrap_err(),
			HandshakeError::IntegerOutOfRange
		));

		// 0x0101 = 257. Truncating to u8 would alias alert code 1 (AuthRequired).
		let above = mk_alert_attr(&[0x01, 0x01])?;
		assert!(matches!(
			extract_alert_x509(&above).unwrap_err(),
			HandshakeError::IntegerOutOfRange
		));
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

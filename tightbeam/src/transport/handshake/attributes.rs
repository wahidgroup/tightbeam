#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::cmp::{Ord, Ordering, PartialOrd};

use super::HandshakeError;
use crate::crypto::x509::attr::{Attribute, Attributes};
use crate::der::asn1::{Any, ObjectIdentifier, SetOfVec};
use crate::der::{Sequence, Tagged};

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use super::HandshakeAlert;
#[cfg(feature = "transport-cms")]
use crate::cms::enveloped_data::OriginatorPublicKey;
#[cfg(feature = "transport-cms")]
use crate::cms::signed_data::SignedData;
#[cfg(feature = "transport-cms")]
use crate::der::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::der::asn1::UintRef;
#[cfg(feature = "x509")]
use crate::oids::CLIENT_CERTIFICATE;
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
use crate::oids::HANDSHAKE_ABORT_ALERT;
#[cfg(feature = "transport-cms")]
use crate::oids::{
	HANDSHAKE_SECURITY_ACCEPT, HANDSHAKE_SECURITY_OFFER, HANDSHAKE_SERVER_EPHEMERAL, HANDSHAKE_TRANSPORT_ACCEPT,
	HANDSHAKE_TRANSPORT_OFFER, RECEIPT_ACK, SESSION_RECEIPT,
};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
#[cfg(feature = "x509")]
use crate::x509::Certificate;

/// A CMS attribute that carries one value, as the handshake profile requires.
///
/// The shape follows the RFC 5652 § 5.3 `Attribute`. The profile narrows
/// `attrValues` to exactly one element, and [`Self::value`] enforces it.
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAttribute {
	/// OID naming the attribute (RFC 5652 § 5.3 `attrType`).
	pub attr_type: ObjectIdentifier,
	/// Values of the attribute. The profile requires exactly one element.
	pub attr_values: Vec<Any>,
}

// A canonical DER SET OF encoding needs a total order. Attributes order by the
// `attr_type` OID bytes, then lexicographically by the encoding of each value:
// the tag octet, then the content octets.
impl PartialOrd for HandshakeAttribute {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

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

/// Deterministic comparison key for an `Any`: the tag octet, then the content
/// octets.
fn any_encoding_key(any: &Any) -> (u8, &[u8]) {
	(u8::from(any.tag()), any.value())
}

impl HandshakeAttribute {
	/// Creates an attribute that carries `value` as its one value.
	///
	/// The result is always `Ok`.
	pub fn new_single(attr_type: ObjectIdentifier, value: Any) -> Result<Self, HandshakeError> {
		Ok(Self { attr_type, attr_values: vec![value] })
	}

	/// Returns the one value this attribute carries.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidAttributeArity`] -- the attribute carries zero values or more than one.
	pub fn value(&self) -> Result<&Any, HandshakeError> {
		if self.attr_values.len() != 1 {
			return Err(HandshakeError::InvalidAttributeArity);
		}
		Ok(&self.attr_values[0])
	}
}

/// Copies the OID and every value of an X.509 attribute.
///
/// The copy keeps any arity, so [`HandshakeAttribute::value`] checks it later.
impl From<&Attribute> for HandshakeAttribute {
	fn from(attr: &Attribute) -> Self {
		HandshakeAttribute { attr_type: attr.oid, attr_values: attr.values.clone().into() }
	}
}

/// Converts a [`HandshakeAttribute`] into the X.509 attribute an
/// `EnvelopedData` carries.
impl TryFrom<HandshakeAttribute> for Attribute {
	type Error = HandshakeError;

	fn try_from(attr: HandshakeAttribute) -> Result<Self, Self::Error> {
		let values = SetOfVec::try_from(attr.attr_values)?;
		Ok(Self { oid: attr.attr_type, values })
	}
}

/// A payload carried as a handshake attribute under its own OID.
///
/// Each implementation is the one home for its type's attribute OID, so
/// the encode and decode sides agree on which OID names which type.
#[cfg(feature = "x509")]
pub trait AttributePayload {
	/// OID this payload is carried under.
	const OID: ObjectIdentifier;
}

/// The client certificate a key exchange carries under mutual
/// authentication, on the CMS and the ECIES path alike.
#[cfg(feature = "x509")]
impl AttributePayload for Certificate {
	const OID: ObjectIdentifier = CLIENT_CERTIFICATE;
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

/// The sealed receipt acknowledgement a client Finished carries.
#[cfg(feature = "transport-cms")]
impl AttributePayload for OctetString {
	const OID: ObjectIdentifier = RECEIPT_ACK;
}

/// The server's per-handshake ephemeral public key on its Finished, carried
/// as the same type the client's KARI originator uses.
#[cfg(feature = "transport-cms")]
impl AttributePayload for OriginatorPublicKey {
	const OID: ObjectIdentifier = HANDSHAKE_SERVER_EPHEMERAL;
}

#[cfg(feature = "x509")]
impl HandshakeAttribute {
	/// Encodes `payload` under its own OID for transmission.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- `payload` fails to encode.
	pub fn encode<T>(payload: &T) -> Result<Self, HandshakeError>
	where
		T: AttributePayload + Tagged + crate::der::EncodeValue,
	{
		Self::new_single(T::OID, Any::encode_from(payload)?)
	}

	/// Decodes this attribute, requiring the OID `T` is carried under.
	///
	/// An attribute of another type yields
	/// [`HandshakeError::MissingAttribute`], so a peer cannot substitute one
	/// negotiated value for another.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the OID differs from `T::OID`.
	/// - [`HandshakeError::InvalidAttributeArity`] -- the attribute carries zero values or more than one.
	/// - [`HandshakeError::DerError`] -- the value fails to decode as `T`.
	pub fn decode<'a, T>(&'a self) -> Result<T, HandshakeError>
	where
		T: AttributePayload + crate::der::Choice<'a> + crate::der::DecodeValue<'a>,
	{
		if self.attr_type != T::OID {
			return Err(HandshakeError::MissingAttribute);
		}

		Ok(self.value()?.decode_as()?)
	}

	/// Returns the bytes that the value of this attribute arrived as.
	///
	/// A receiver binds what the peer sent. Re-encoding the decoded value
	/// instead would erase any difference the decoder normalised away: `der`
	/// sorts a `SET OF` before validating it, so a reordered set would hash
	/// the same as the well-ordered one and pass unseen (CWE-345).
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidAttributeArity`] -- the attribute carries zero values or more than one.
	/// - [`HandshakeError::DerError`] -- the value fails to encode.
	pub fn received_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
		use crate::der::Encode;

		Ok(self.value()?.to_der()?)
	}

	/// Returns the canonical DER bytes of `payload` for transcript binding.
	///
	/// The sender calls this and the receiver calls [`Self::received_bytes`].
	/// These are the bytes about to go on the wire, so both sides hash the
	/// same encoding and a tampered attribute diverges the two transcript
	/// hashes (CWE-345).
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- `payload` fails to encode.
	pub fn transcript_bytes<T>(payload: &T) -> Result<Vec<u8>, HandshakeError>
	where
		T: AttributePayload + Tagged + crate::der::EncodeValue,
	{
		use crate::der::Encode;

		Ok(Any::encode_from(payload)?.to_der()?)
	}
}

/// Decode a one- or two-byte unsigned INTEGER from an `Any`.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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
/// Alert codes occupy the u8 domain. A wider value is refused, so a two-byte
/// code can never alias a valid alert through truncation.
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
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

/// Handshake attribute lookups on a CMS `SignedData` or an attribute set.
pub trait HandshakeAttributes {
	/// Finds at most one unsigned attribute with `oid`, rejecting duplicates.
	///
	/// On a `SignedData` the search spans the SignerInfos of a parsed
	/// Finished message.
	///
	/// # Duplicates
	///
	/// RFC 5652 § 11.4 permits repeated unsigned attributes, but every
	/// TightBeam handshake attribute is single-use: a duplicate is either a
	/// builder bug or an injection attempt, and fails closed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] -- the OID appears more than once.
	///
	/// # Sources
	///
	/// - RFC 5652 § 11.4, countersignature attributes:
	///   <https://datatracker.ietf.org/doc/html/rfc5652#section-11.4>
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError>;

	/// Refuses a message that carries an abort alert from the peer.
	///
	/// An abort alert travels as an unsigned attribute, so it is advisory and
	/// unauthenticated.
	///
	/// # Errors
	///
	/// - [`HandshakeError::AbortReceived`] -- an alert with a known code is present.
	/// - [`HandshakeError::DuplicateAttribute`] -- the alert attribute repeats.
	/// - [`HandshakeError::InvalidAttributeArity`] -- the alert carries zero values or more than one.
	/// - [`HandshakeError::InvalidIntegerEncoding`] -- the alert code is not an INTEGER.
	/// - [`HandshakeError::IntegerOutOfRange`] -- the alert code is above `u8::MAX`.
	/// - [`HandshakeError::UnknownAlertCode`] -- the code names no alert.
	#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
	fn refuse_alert(&self) -> Result<(), HandshakeError> {
		let Some(alert) = self.find_unsigned_attr(HANDSHAKE_ABORT_ALERT)? else {
			return Ok(());
		};

		Err(HandshakeError::AbortReceived(alert.handshake_alert()?))
	}
}

impl HandshakeAttributes for Attributes {
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		let mut found = None;
		let matches = self.iter().filter(|attr| attr.oid == oid);
		for attr in matches {
			if found.is_some() {
				return Err(HandshakeError::DuplicateAttribute);
			}

			found = Some(HandshakeAttribute::from(attr));
		}

		Ok(found)
	}
}

#[cfg(feature = "transport-cms")]
impl HandshakeAttributes for SignedData {
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		let mut found = None;
		let signer_attrs = self
			.signer_infos
			.0
			.iter()
			.filter_map(|signer_info| signer_info.unsigned_attrs.as_ref());

		for attrs in signer_attrs {
			let Some(attr) = attrs.find_unsigned_attr(oid)? else {
				continue;
			};
			if found.is_some() {
				return Err(HandshakeError::DuplicateAttribute);
			}

			found = Some(attr);
		}

		Ok(found)
	}
}

/// Handshake alert decoding on a [`HandshakeAttribute`].
#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
pub trait HandshakeAlertAttribute {
	/// Returns the alert code this attribute carries.
	///
	/// The profile admits one value, so any other arity is refused.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidAttributeArity`] -- the arity is other than one.
	/// - [`HandshakeError::InvalidIntegerEncoding`] -- the value is not an INTEGER.
	/// - [`HandshakeError::IntegerOutOfRange`] -- the code is empty or above `u8::MAX`.
	/// - [`HandshakeError::UnknownAlertCode`] -- the code names no alert.
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-ecies"))]
impl HandshakeAlertAttribute for HandshakeAttribute {
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError> {
		alert_from_any(self.value()?)
	}
}

#[cfg(all(test, feature = "transport-cms"))]
mod tests {
	use super::*;
	use crate::cms::signed_data::{SignerInfo, SignerInfos};
	use crate::der::asn1::Any;
	use crate::der::asn1::{OctetString as DerOctetString, SetOfVec, UintRef};
	use crate::oids::HANDSHAKE_SECURITY_ACCEPT;
	use crate::transport::handshake::tests::create_test_signed_data;

	fn mk_integer(bytes: impl AsRef<[u8]>) -> Result<Any, der::Error> {
		let bytes = bytes.as_ref();
		let u = UintRef::new(bytes)?;
		Any::encode_from(&u)
	}

	fn mk_octet(bytes: impl AsRef<[u8]>) -> Result<Any, der::Error> {
		let bytes = bytes.as_ref();
		let os = DerOctetString::new(bytes)?;
		Any::encode_from(&os)
	}

	fn mk_alert_attr(bytes: impl AsRef<[u8]>) -> Result<HandshakeAttribute, der::Error> {
		let bytes = bytes.as_ref();
		let attribute = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer(bytes)?)?;
		Ok(HandshakeAttribute::from(&attribute))
	}

	fn mk_attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute, der::Error> {
		Ok(Attribute { oid, values: SetOfVec::try_from(vec![value])? })
	}

	/// The one `SignerInfo` of a fresh test `SignedData`, carrying the same
	/// security offer as an unsigned attribute on every call.
	fn signer_with_offer() -> SignerInfo {
		let signed_data = create_test_signed_data([0x07u8; 32]);
		let value = mk_octet([0x11u8; 32]).expect("a 32-byte OCTET STRING encodes");
		let offer = mk_attr(HANDSHAKE_SECURITY_OFFER, value).expect("one value forms a SET OF");
		let attrs = Attributes::try_from(vec![offer]).expect("one attribute forms a SET OF");

		let signer = signed_data.signer_infos.0.iter().next().cloned();
		let mut signer = signer.expect("the test SignedData has one signer");
		signer.unsigned_attrs = Some(attrs);
		signer
	}

	/// A receiver binds what arrived. `der` sorts a `SET OF` before it
	/// validates one, so a value that re-encodes to different bytes than it
	/// arrived as would let that normalisation erase tamper evidence
	/// (CWE-345).
	#[test]
	fn the_transcript_binds_the_bytes_an_attribute_arrived_as() -> Result<(), HandshakeError> {
		use crate::der::{Decode, Encode};

		// The members of this SET OF are out of DER order. Decoding sorts
		// them, so the decoded value differs from what was sent.
		let unsorted = Any::from_der(&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01])?;
		let attribute = HandshakeAttribute::new_single(HANDSHAKE_SECURITY_ACCEPT, unsorted.to_owned())?;
		assert_eq!(attribute.received_bytes()?, unsorted.to_der()?);
		Ok(())
	}

	#[test]
	fn an_abort_alert_attribute_is_refused() -> Result<(), HandshakeError> {
		let alert = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x03])?)?;
		let attrs = Attributes::try_from(vec![alert])?;

		let refused = attrs.refuse_alert();
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(refused, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A repeated abort alert fails closed as a duplicate attribute rather
	/// than reading as no alert and letting processing continue into the
	/// message body.
	#[test]
	fn a_duplicate_abort_alert_fails_closed() -> Result<(), HandshakeError> {
		let first = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x03])?)?;
		let second = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x04])?)?;
		let attrs = Attributes::try_from(vec![first, second])?;

		let refused = attrs.refuse_alert();
		assert!(matches!(refused, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A message without an abort alert passes the alert check.
	#[test]
	fn a_message_without_an_alert_passes() -> Result<(), HandshakeError> {
		let offer = mk_attr(HANDSHAKE_SECURITY_OFFER, mk_octet([0x11u8; 32])?)?;
		let attrs = Attributes::try_from(vec![offer])?;
		attrs.refuse_alert()
	}

	#[test]
	fn duplicate_detected() -> Result<(), HandshakeError> {
		let a1 = mk_attr(HANDSHAKE_SECURITY_OFFER, mk_octet([0x11u8; 32])?)?;
		let a2 = mk_attr(HANDSHAKE_SECURITY_OFFER, mk_octet([0x12u8; 32])?)?;
		let attrs = Attributes::try_from(vec![a1, a2])?;
		assert!(matches!(
			attrs.find_unsigned_attr(HANDSHAKE_SECURITY_OFFER),
			Err(HandshakeError::DuplicateAttribute)
		));
		Ok(())
	}

	#[test]
	fn duplicate_across_signers_detected() -> Result<(), HandshakeError> {
		let mut signed_data = create_test_signed_data([0x07u8; 32]);
		let signers = vec![signer_with_offer(), signer_with_offer()];
		signed_data.signer_infos = SignerInfos::try_from(signers)?;

		let found = signed_data.find_unsigned_attr(HANDSHAKE_SECURITY_OFFER);
		assert!(matches!(found, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	#[test]
	fn missing_attribute_detected() -> Result<(), HandshakeError> {
		let only = mk_attr(HANDSHAKE_SECURITY_OFFER, mk_octet([0x22u8; 32])?)?;
		let attrs = Attributes::try_from(vec![only])?;
		assert!(matches!(attrs.find_unsigned_attr(HANDSHAKE_SECURITY_ACCEPT), Ok(None)));
		Ok(())
	}

	#[test]
	fn invalid_attribute_arity() -> Result<(), der::Error> {
		let any = mk_octet([0x33u8; 32])?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![any.to_owned(), any] };
		assert!(matches!(attr.value(), Err(HandshakeError::InvalidAttributeArity)));
		Ok(())
	}

	#[test]
	fn multi_valued_alert_rejected() -> Result<(), der::Error> {
		let attr_values = vec![mk_integer([0x01])?, mk_integer([0x02])?];
		let alert = HandshakeAttribute { attr_type: HANDSHAKE_ABORT_ALERT, attr_values };
		assert!(matches!(alert.handshake_alert(), Err(HandshakeError::InvalidAttributeArity)));
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
			let attr = mk_alert_attr([*code])?;
			assert_eq!(attr.handshake_alert()?, *alert);
		}

		let unknown = mk_alert_attr([0x07])?;
		assert!(matches!(unknown.handshake_alert(), Err(HandshakeError::UnknownAlertCode(7))));
		Ok(())
	}

	#[test]
	fn alert_integer_out_of_range_rejected() -> Result<(), der::Error> {
		// A three-byte INTEGER exceeds the u16 decode domain.
		let wide = mk_alert_attr([0x01, 0x02, 0x03])?;
		assert!(matches!(wide.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));

		// 0x0101 = 257. Truncating to u8 would alias alert code 1
		// (AuthRequired).
		let above = mk_alert_attr([0x01, 0x01])?;
		assert!(matches!(above.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));
		Ok(())
	}

	#[test]
	fn attribute_ord_tiebreaks_on_value() -> Result<(), der::Error> {
		let low = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![mk_integer([0x01])?] };
		let high = HandshakeAttribute { attr_type: HANDSHAKE_SECURITY_OFFER, attr_values: vec![mk_integer([0x02])?] };
		assert_eq!(low.cmp(&high), Ordering::Less);
		assert_eq!(high.cmp(&low), Ordering::Greater);
		assert_eq!(low.cmp(&low.to_owned()), Ordering::Equal);
		Ok(())
	}
}

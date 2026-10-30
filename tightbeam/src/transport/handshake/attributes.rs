#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::cmp::{Ord, Ordering, PartialOrd};

use super::HandshakeError;
use crate::crypto::x509::attr::Attribute;
use crate::der::asn1::{Any, AnyRef, ObjectIdentifier, SetOf, SetOfVec};
use crate::der::{DecodeValue, EncodeValue, Header, Length, Reader, Sequence, Tag, Tagged, Writer};

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use super::HandshakeAlert;
#[cfg(feature = "transport-cms")]
use crate::cms::enveloped_data::OriginatorPublicKey;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::cms::signed_data::SignedData;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::cms::AttributesExt;
#[cfg(feature = "transport-cms")]
use crate::crypto::exchange::KemCiphertext;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::sign::Signed;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::crypto::x509::attr::Attributes;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::OctetString;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::der::asn1::UintRef;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::oids::HANDSHAKE_ABORT_ALERT;
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::oids::{HANDSHAKE_KEY_CONFIRMATION, RECEIPT_ACK, SESSION_RECEIPT};
#[cfg(feature = "transport-cms")]
use crate::oids::{
	HANDSHAKE_SECURITY_ACCEPT, HANDSHAKE_SECURITY_OFFER, HANDSHAKE_SERVER_EPHEMERAL, HANDSHAKE_SERVER_KEM_CIPHERTEXT,
	HANDSHAKE_TRANSPORT_ACCEPT, HANDSHAKE_TRANSPORT_OFFER,
};
#[cfg(feature = "transport-cms")]
use crate::transport::handshake::negotiation::{SecurityAccept, SecurityOffer, TransportAccept, TransportOffer};
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
use crate::transport::handshake::schedule::KeyConfirmation;

/// A CMS attribute that carries one value, as the handshake profile requires.
///
/// Its DER is the RFC 5652 § 5.3 `Attribute`, with `attrValues` narrowed to
/// one element. A received attribute and the DER decode both enter through
/// [`TryFrom<&Attribute>`], which refuses any other arity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAttribute {
	/// OID that names the attribute (RFC 5652 § 5.3 `attrType`).
	attr_type: ObjectIdentifier,
	/// The one value of the attribute (RFC 5652 § 5.3 `attrValues`).
	value: Any,
}

// A canonical DER SET OF encoding needs a total order. Attributes order by the
// `attr_type` OID bytes, then by the `any_encoding_key` of each value.
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

		any_encoding_key(&self.value).cmp(&any_encoding_key(&other.value))
	}
}

/// Deterministic comparison key for an `Any`: the tag octet, then the content
/// octets.
fn any_encoding_key(any: &Any) -> (u8, &[u8]) {
	(u8::from(any.tag()), any.value())
}

impl HandshakeAttribute {
	/// Creates an attribute of type `attr_type` that carries `value` as its
	/// one value.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::der::asn1::{Any, ObjectIdentifier};
	/// use tightbeam::transport::handshake::HandshakeAttribute;
	///
	/// let attr_type = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.99");
	/// let attribute = HandshakeAttribute::new(attr_type, Any::encode_from(&7u8)?);
	/// assert_eq!(attribute.attr_type(), attr_type);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn new(attr_type: ObjectIdentifier, value: Any) -> Self {
		Self { attr_type, value }
	}

	/// Returns the OID that names this attribute (RFC 5652 § 5.3 `attrType`).
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::der::asn1::{Any, ObjectIdentifier};
	/// use tightbeam::transport::handshake::HandshakeAttribute;
	///
	/// let attr_type = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.99");
	/// let attribute = HandshakeAttribute::new(attr_type, Any::encode_from(&7u8)?);
	/// assert_eq!(attribute.attr_type(), attr_type);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn attr_type(&self) -> ObjectIdentifier {
		self.attr_type
	}

	/// Returns the one value this attribute carries.
	///
	/// # Examples
	///
	/// ```
	/// use tightbeam::der::asn1::{Any, ObjectIdentifier};
	/// use tightbeam::transport::handshake::HandshakeAttribute;
	///
	/// let value = Any::encode_from(&7u8)?;
	/// let attribute = HandshakeAttribute::new(ObjectIdentifier::new_unwrap("1.3.6.1.4.1.64586.1.99"), value.clone());
	/// assert_eq!(attribute.value(), &value);
	/// # Ok::<(), Box<dyn core::error::Error>>(())
	/// ```
	pub fn value(&self) -> &Any {
		&self.value
	}

	/// The `attrValues` of this attribute: a SET OF that borrows its one value.
	fn attr_values(&self) -> crate::der::Result<SetOf<AnyRef<'_>, 1>> {
		SetOf::try_from([AnyRef::from(&self.value)])
	}
}

/// Admits an X.509 attribute that carries exactly one value, as the handshake
/// profile requires. It is the one arity check, where an attribute arrives.
impl TryFrom<&Attribute> for HandshakeAttribute {
	type Error = HandshakeError;

	/// # Errors
	///
	/// - [`HandshakeError::InvalidAttributeArity`] -- the attribute carries zero values or more than one.
	fn try_from(attr: &Attribute) -> Result<Self, Self::Error> {
		let mut values = attr.values.iter();
		let (Some(value), None) = (values.next(), values.next()) else {
			return Err(HandshakeError::InvalidAttributeArity);
		};

		Ok(Self { attr_type: attr.oid, value: value.clone() })
	}
}

/// Converts a [`HandshakeAttribute`] into the X.509 attribute an
/// `AuthEnvelopedData` carries.
impl TryFrom<HandshakeAttribute> for Attribute {
	type Error = HandshakeError;

	fn try_from(attr: HandshakeAttribute) -> Result<Self, Self::Error> {
		let values = SetOfVec::try_from(vec![attr.value])?;
		Ok(Self { oid: attr.attr_type, values })
	}
}

// The DER traits are written by hand, so a decode reads an RFC 5652 § 5.3
// `Attribute` and passes the one arity check of `TryFrom<&Attribute>`. The
// `Sequence` marker gives the SEQUENCE tag.
impl<'a> Sequence<'a> for HandshakeAttribute {}

impl EncodeValue for HandshakeAttribute {
	fn value_len(&self) -> crate::der::Result<Length> {
		use crate::der::Encode;

		self.attr_type.encoded_len()? + self.attr_values()?.encoded_len()?
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		use crate::der::Encode;

		self.attr_type.encode(writer)?;
		self.attr_values()?.encode(writer)
	}
}

impl<'a> DecodeValue<'a> for HandshakeAttribute {
	// An attribute of any arity but one is a value error of its SET OF, which
	// names the DER that failed. The refusal of the arity check names the same
	// cause.
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> crate::der::Result<Self> {
		let attribute = Attribute::decode_value(reader, header)?;
		Self::try_from(&attribute).map_err(|_arity| Tag::Set.value_error())
	}
}

/// A payload carried as a handshake attribute under its own OID.
///
/// Each implementation is the one home for its type's attribute OID, so
/// the encode and decode sides agree on which OID names which type.
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

/// The session receipt a reply carries, as a server-signed artifact that a
/// third party can verify.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl AttributePayload for Signed<SignedData> {
	const OID: ObjectIdentifier = SESSION_RECEIPT;
}

/// The sealed receipt acknowledgement a closing carries.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl AttributePayload for OctetString {
	const OID: ObjectIdentifier = RECEIPT_ACK;
}

/// The server's per-handshake ephemeral public key on its Finished, carried
/// as the same type the client's agreement key uses in the opening.
#[cfg(feature = "transport-cms")]
impl AttributePayload for OriginatorPublicKey {
	const OID: ObjectIdentifier = HANDSHAKE_SERVER_EPHEMERAL;
}

/// The server's share of a KEM exchange on its Finished, the ciphertext the
/// server encapsulated for the client.
#[cfg(feature = "transport-cms")]
impl AttributePayload for KemCiphertext {
	const OID: ObjectIdentifier = HANDSHAKE_SERVER_KEM_CIPHERTEXT;
}

/// The key-confirmation tag a closing carries, and the server Finished the
/// HPKE reply carries.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl AttributePayload for KeyConfirmation {
	const OID: ObjectIdentifier = HANDSHAKE_KEY_CONFIRMATION;
}

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
		let value = Any::encode_from(payload)?;
		Ok(Self::new(T::OID, value))
	}

	/// Decodes this attribute as `T`, when it carries the OID of `T`.
	///
	/// An attribute of another type is refused, so a peer cannot substitute one
	/// negotiated value for another.
	///
	/// # Errors
	///
	/// - [`HandshakeError::MissingAttribute`] -- the OID differs from `T::OID`.
	/// - [`HandshakeError::DerError`] -- the value fails to decode as `T`.
	pub fn decode<'a, T>(&'a self) -> Result<T, HandshakeError>
	where
		T: AttributePayload + crate::der::Choice<'a> + crate::der::DecodeValue<'a>,
	{
		if self.attr_type != T::OID {
			return Err(HandshakeError::MissingAttribute);
		}

		Ok(self.value.decode_as()?)
	}

	/// Returns the bytes that the value of this attribute arrived as.
	///
	/// A receiver binds what the peer sent. `der` sorts a `SET OF` before it
	/// validates the set, so a re-encoding would hash a reordered set the same
	/// as the well-ordered one and let it pass unseen (CWE-345).
	///
	/// # Errors
	///
	/// - [`HandshakeError::DerError`] -- the value fails to encode.
	pub fn received_bytes(&self) -> Result<Vec<u8>, HandshakeError> {
		use crate::der::Encode;

		Ok(self.value.to_der()?)
	}

	/// Returns the canonical DER bytes of `payload` for transcript binding.
	///
	/// The sender calls this, and the receiver calls [`Self::received_bytes`].
	/// Both hash the transmitted bytes, so a tampered attribute makes the two
	/// transcript hashes differ (CWE-345).
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
fn u16_from_any(any: &Any) -> Result<u16, HandshakeError> {
	let uint_ref: UintRef = any.decode_as().map_err(|_| HandshakeError::InvalidIntegerEncoding)?;
	match uint_ref.as_bytes() {
		[low] => Ok(u16::from(*low)),
		[high, low] => Ok(u16::from_be_bytes([*high, *low])),
		_ => Err(HandshakeError::IntegerOutOfRange),
	}
}

/// Decode an alert code from a single INTEGER-bearing `Any`.
///
/// A code above `u8::MAX` is refused, so a two-byte code never aliases a
/// valid alert through truncation.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait HandshakeAttributes {
	/// Finds at most one unsigned attribute with `oid`, and rejects duplicates.
	///
	/// On a `SignedData` the search spans the SignerInfos of a parsed
	/// Finished message or of an HPKE reply.
	///
	/// # Duplicates
	///
	/// RFC 5652 § 11.4 permits repeated unsigned attributes. Every TightBeam
	/// handshake attribute is single-use, so a duplicate, from a builder bug or
	/// an injection attempt, fails closed.
	///
	/// # Errors
	///
	/// - [`HandshakeError::DuplicateAttribute`] -- the OID appears more than once.
	/// - [`HandshakeError::InvalidAttributeArity`] -- the attribute carries zero values or more than one.
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
	#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
	fn refuse_alert(&self) -> Result<(), HandshakeError> {
		let Some(alert) = self.find_unsigned_attr(HANDSHAKE_ABORT_ALERT)? else {
			return Ok(());
		};

		Err(HandshakeError::AbortReceived(alert.handshake_alert()?))
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeAttributes for Attributes {
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		let found = self.single(oid, HandshakeError::DuplicateAttribute)?;
		found.map(HandshakeAttribute::try_from).transpose()
	}
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
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

/// An attribute set that may be absent, as the unprotected attributes of a CMS
/// container are.
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeAttributes for Option<Attributes> {
	fn find_unsigned_attr(&self, oid: ObjectIdentifier) -> Result<Option<HandshakeAttribute>, HandshakeError> {
		let found = self.as_ref().map(|attrs| attrs.find_unsigned_attr(oid));
		Ok(found.transpose()?.flatten())
	}
}

/// Handshake alert decoding on a [`HandshakeAttribute`].
#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
pub trait HandshakeAlertAttribute {
	/// Returns the alert code this attribute carries.
	///
	/// # Errors
	///
	/// - [`HandshakeError::InvalidIntegerEncoding`] -- the value is not an INTEGER.
	/// - [`HandshakeError::IntegerOutOfRange`] -- the code is empty or above `u8::MAX`.
	/// - [`HandshakeError::UnknownAlertCode`] -- the code names no alert.
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError>;
}

#[cfg(any(feature = "transport-cms", feature = "transport-hpke"))]
impl HandshakeAlertAttribute for HandshakeAttribute {
	fn handshake_alert(&self) -> Result<HandshakeAlert, HandshakeError> {
		alert_from_any(self.value())
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
		Ok(HandshakeAttribute::new(HANDSHAKE_ABORT_ALERT, mk_integer(bytes)?))
	}

	fn mk_attr(oid: ObjectIdentifier, value: Any) -> Result<Attribute, der::Error> {
		Ok(Attribute { oid, values: SetOfVec::try_from(vec![value])? })
	}

	/// The one `SignerInfo` of a fresh test `SignedData`, which carries the
	/// same security offer as an unsigned attribute on every call.
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

	/// A receiver binds the bytes that arrived. `der` sorts a `SET OF` at
	/// decode, so a re-encoding would erase tamper evidence (CWE-345).
	#[test]
	fn the_transcript_binds_the_bytes_an_attribute_arrived_as() -> Result<(), HandshakeError> {
		use crate::der::{Decode, Encode};

		// The members of this SET OF are out of DER order. Decoding sorts
		// them, so the decoded value differs from what was sent.
		let unsorted = Any::from_der(&[0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01])?;
		let attribute = HandshakeAttribute::new(HANDSHAKE_SECURITY_ACCEPT, unsorted.to_owned());
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

	/// A repeated abort alert fails closed as a duplicate attribute. Read as
	/// no alert, it would let processing continue into the message body.
	#[test]
	fn a_duplicate_abort_alert_fails_closed() -> Result<(), HandshakeError> {
		let first = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x03])?)?;
		let second = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x04])?)?;
		let attrs = Attributes::try_from(vec![first, second])?;

		let refused = attrs.refuse_alert();
		assert!(matches!(refused, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// The unprotected attributes of a CMS container are an optional set, and
	/// a present set that repeats the abort alert fails closed as the set does.
	#[test]
	fn a_duplicate_abort_alert_in_an_optional_set_fails_closed() -> Result<(), HandshakeError> {
		let first = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x03])?)?;
		let second = mk_attr(HANDSHAKE_ABORT_ALERT, mk_integer([0x04])?)?;
		let attrs = Some(Attributes::try_from(vec![first, second])?);

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

	/// A received attribute carries one value, so the boundary refuses an
	/// attribute of two values before any reader sees it (RFC 5652 § 5.3).
	#[test]
	fn an_attribute_with_two_values_is_refused_at_the_boundary() -> Result<(), der::Error> {
		let values = vec![mk_octet([0x33u8; 32])?, mk_octet([0x34u8; 32])?];
		let attribute = Attribute { oid: HANDSHAKE_SECURITY_OFFER, values: SetOfVec::try_from(values)? };

		let refused = HandshakeAttribute::try_from(&attribute);
		assert!(matches!(refused, Err(HandshakeError::InvalidAttributeArity)));
		Ok(())
	}

	/// The DER decode of a handshake attribute reads an RFC 5652 § 5.3
	/// `Attribute` and passes its arity check, so an attribute of two values
	/// is a value error of its SET OF.
	#[test]
	fn an_attribute_with_two_values_does_not_decode() -> Result<(), der::Error> {
		use crate::der::{Decode, Encode, ErrorKind, Tag};

		let values = vec![mk_octet([0x33u8; 32])?, mk_octet([0x34u8; 32])?];
		let attribute = Attribute { oid: HANDSHAKE_SECURITY_OFFER, values: SetOfVec::try_from(values)? };

		let refused = HandshakeAttribute::from_der(&attribute.to_der()?).map_err(|error| error.kind());
		assert!(matches!(refused, Err(ErrorKind::Value { tag: Tag::Set })));
		Ok(())
	}

	/// A handshake attribute encodes as the RFC 5652 § 5.3 `Attribute` of its
	/// one value.
	#[test]
	fn a_handshake_attribute_encodes_as_an_rfc_attribute() -> Result<(), der::Error> {
		use crate::der::{Decode, Encode};

		let value = mk_octet([0x35u8; 32])?;
		let attribute = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, value.clone());

		let decoded = Attribute::from_der(&attribute.to_der()?)?;
		assert_eq!(decoded, mk_attr(HANDSHAKE_SECURITY_OFFER, value)?);
		Ok(())
	}

	/// An alert of two values is refused at the boundary of its set, as any
	/// attribute of the handshake profile is.
	#[test]
	fn a_multi_valued_alert_is_refused_at_the_boundary() -> Result<(), der::Error> {
		let values = vec![mk_integer([0x01])?, mk_integer([0x02])?];
		let alert = Attribute { oid: HANDSHAKE_ABORT_ALERT, values: SetOfVec::try_from(values)? };
		let attrs = Attributes::try_from(vec![alert])?;

		assert!(matches!(attrs.refuse_alert(), Err(HandshakeError::InvalidAttributeArity)));
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

		// 0x0101 is 257, which a truncation to u8 would alias to alert code 1
		// (AuthRequired).
		let above = mk_alert_attr([0x01, 0x01])?;
		assert!(matches!(above.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));
		Ok(())
	}

	/// A two-octet alert code reads big-endian: `0x0100` is 256, past the
	/// alert domain, and never alert 1.
	#[test]
	fn a_two_octet_alert_code_reads_big_endian() -> Result<(), der::Error> {
		let wide = mk_alert_attr([0x01, 0x00])?;

		assert!(matches!(wide.handshake_alert(), Err(HandshakeError::IntegerOutOfRange)));
		Ok(())
	}

	#[test]
	fn attribute_ord_tiebreaks_on_value() -> Result<(), der::Error> {
		let low = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, mk_integer([0x01])?);
		let high = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, mk_integer([0x02])?);
		assert_eq!(low.cmp(&high), Ordering::Less);
		assert_eq!(high.cmp(&low), Ordering::Greater);
		assert_eq!(low.cmp(&low.to_owned()), Ordering::Equal);
		Ok(())
	}
}

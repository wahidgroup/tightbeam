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
	use crate::crypto::sign::SignedDataSigners;
	use crate::der::asn1::Any;
	use crate::der::asn1::{OctetString as DerOctetString, SetOfVec, UintRef};
	use crate::oids::HANDSHAKE_SECURITY_ACCEPT;
	use crate::testing::TestResult;
	use crate::transport::handshake::tests::create_test_signed_data;

	/// The INTEGER whose unsigned big-endian octets are `bytes`.
	fn integer_of(bytes: impl AsRef<[u8]>) -> Any {
		let integer = UintRef::new(bytes.as_ref()).expect("the octets are an unsigned INTEGER");
		Any::encode_from(&integer).expect("an INTEGER encodes")
	}

	/// The OCTET STRING of `bytes`.
	fn octets_of(bytes: impl AsRef<[u8]>) -> Any {
		let octets = DerOctetString::new(bytes.as_ref()).expect("the octets are an OCTET STRING");
		Any::encode_from(&octets).expect("an OCTET STRING encodes")
	}

	/// The abort alert whose code is the INTEGER of `bytes`.
	fn alert_of(bytes: impl AsRef<[u8]>) -> HandshakeAttribute {
		HandshakeAttribute::new(HANDSHAKE_ABORT_ALERT, integer_of(bytes))
	}

	/// The attribute of type `oid` that carries `values`.
	fn attribute_of(oid: ObjectIdentifier, values: impl IntoIterator<Item = Any>) -> Attribute {
		let values = SetOfVec::try_from(values.into_iter().collect::<Vec<Any>>());
		Attribute { oid, values: values.expect("distinct values form a SET OF") }
	}

	/// The security offer whose value is 32 octets of `fill`.
	fn offer_attr(fill: u8) -> Attribute {
		attribute_of(HANDSHAKE_SECURITY_OFFER, [octets_of([fill; 32])])
	}

	/// A set that carries the abort alert twice, of codes 3 and 4.
	fn duplicate_alerts() -> Attributes {
		let first = attribute_of(HANDSHAKE_ABORT_ALERT, [integer_of([0x03])]);
		let second = attribute_of(HANDSHAKE_ABORT_ALERT, [integer_of([0x04])]);
		Attributes::try_from(vec![first, second]).expect("two distinct attributes form a SET OF")
	}

	/// A security offer of two values.
	fn two_valued_offer() -> Attribute {
		attribute_of(HANDSHAKE_SECURITY_OFFER, [octets_of([0x33u8; 32]), octets_of([0x34u8; 32])])
	}

	/// The one `SignerInfo` of a fresh test `SignedData`, which carries the
	/// same security offer as an unsigned attribute on every call.
	fn signer_with_offer() -> SignerInfo {
		let signed_data = create_test_signed_data([0x07u8; 32]);
		let attrs = Attributes::try_from(vec![offer_attr(0x11)]).expect("one attribute forms a SET OF");

		let signer = signed_data.sole_signer().expect("the test SignedData has one signer");
		let mut signer = signer.to_owned();
		signer.unsigned_attrs = Some(attrs);
		signer
	}

	/// A receiver binds the bytes that arrived. `der` sorts a `SET OF` at
	/// decode, so a re-encoding would erase tamper evidence (CWE-345).
	#[test]
	fn the_transcript_binds_the_bytes_an_attribute_arrived_as() -> TestResult {
		use crate::der::Decode;

		// The members of this SET OF are out of DER order, so a decode into a
		// SET OF would sort them into a value that differs from what was sent.
		const ARRIVED: [u8; 8] = [0x31, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
		let attribute = HandshakeAttribute::new(HANDSHAKE_SECURITY_ACCEPT, Any::from_der(&ARRIVED)?);

		let bound = attribute.received_bytes()?;
		assert_eq!(bound, ARRIVED);
		Ok(())
	}

	/// An abort alert in a message refuses the message with the alert it
	/// carries.
	#[test]
	fn an_abort_alert_attribute_is_refused() -> TestResult {
		let alert = attribute_of(HANDSHAKE_ABORT_ALERT, [integer_of([0x03])]);
		let attrs = Attributes::try_from(vec![alert])?;

		let refused = attrs.refuse_alert();
		let expected = HandshakeAlert::AlgorithmMismatch;
		assert!(matches!(refused, Err(HandshakeError::AbortReceived(alert)) if alert == expected));
		Ok(())
	}

	/// A repeated abort alert fails closed as a duplicate attribute. Read as
	/// no alert, it would let processing continue into the message body.
	#[test]
	fn a_duplicate_abort_alert_fails_closed() {
		let refused = duplicate_alerts().refuse_alert();
		assert!(matches!(refused, Err(HandshakeError::DuplicateAttribute)));
	}

	/// The unprotected attributes of a CMS container are an optional set, and
	/// a present set that repeats the abort alert fails closed as the set does.
	#[test]
	fn a_duplicate_abort_alert_in_an_optional_set_fails_closed() {
		let refused = Some(duplicate_alerts()).refuse_alert();
		assert!(matches!(refused, Err(HandshakeError::DuplicateAttribute)));
	}

	/// A message without an abort alert passes the alert check.
	#[test]
	fn a_message_without_an_alert_passes() -> TestResult {
		let attrs = Attributes::try_from(vec![offer_attr(0x11)])?;
		attrs.refuse_alert()?;
		Ok(())
	}

	/// A lookup of an attribute that a set carries twice fails closed as a
	/// duplicate attribute.
	#[test]
	fn a_lookup_of_a_repeated_attribute_is_refused() -> TestResult {
		let attrs = Attributes::try_from(vec![offer_attr(0x11), offer_attr(0x12)])?;
		let found = attrs.find_unsigned_attr(HANDSHAKE_SECURITY_OFFER);
		assert!(matches!(found, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A lookup of an attribute that two signers each carry fails closed as a
	/// duplicate attribute.
	#[test]
	fn a_lookup_of_an_attribute_across_signers_is_refused() -> TestResult {
		let mut signed_data = create_test_signed_data([0x07u8; 32]);
		let signers = vec![signer_with_offer(), signer_with_offer()];
		signed_data.signer_infos = SignerInfos::try_from(signers)?;

		let found = signed_data.find_unsigned_attr(HANDSHAKE_SECURITY_OFFER);
		assert!(matches!(found, Err(HandshakeError::DuplicateAttribute)));
		Ok(())
	}

	/// A lookup of an attribute absent from a set finds none.
	#[test]
	fn a_lookup_of_an_absent_attribute_finds_none() -> TestResult {
		let attrs = Attributes::try_from(vec![offer_attr(0x22)])?;
		let found = attrs.find_unsigned_attr(HANDSHAKE_SECURITY_ACCEPT);
		assert!(matches!(found, Ok(None)));
		Ok(())
	}

	/// A received attribute carries one value, so the boundary refuses an
	/// attribute of two values before any reader sees it (RFC 5652 § 5.3).
	#[test]
	fn an_attribute_with_two_values_is_refused_at_the_boundary() {
		let refused = HandshakeAttribute::try_from(&two_valued_offer());
		assert!(matches!(refused, Err(HandshakeError::InvalidAttributeArity)));
	}

	/// The DER decode of a handshake attribute reads an RFC 5652 § 5.3
	/// `Attribute` and passes its arity check, so an attribute of two values
	/// is a value error of its SET OF.
	#[test]
	fn an_attribute_with_two_values_does_not_decode() -> TestResult {
		use crate::der::{Decode, Encode, ErrorKind, Tag};

		let encoded = two_valued_offer().to_der()?;
		let refused = HandshakeAttribute::from_der(&encoded).map_err(|error| error.kind());
		assert!(matches!(refused, Err(ErrorKind::Value { tag: Tag::Set })));
		Ok(())
	}

	/// A handshake attribute encodes as the RFC 5652 § 5.3 `Attribute` of its
	/// one value.
	#[test]
	fn a_handshake_attribute_encodes_as_an_rfc_attribute() -> TestResult {
		use crate::der::{Decode, Encode};

		let value = octets_of([0x35u8; 32]);
		let attribute = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, value.clone());

		let decoded = Attribute::from_der(&attribute.to_der()?)?;
		assert_eq!(decoded, attribute_of(HANDSHAKE_SECURITY_OFFER, [value]));
		Ok(())
	}

	/// An alert of two values is refused at the boundary of its set, as any
	/// attribute of the handshake profile is.
	#[test]
	fn a_multi_valued_alert_is_refused_at_the_boundary() -> TestResult {
		let alert = attribute_of(HANDSHAKE_ABORT_ALERT, [integer_of([0x01]), integer_of([0x02])]);
		let attrs = Attributes::try_from(vec![alert])?;
		assert!(matches!(attrs.refuse_alert(), Err(HandshakeError::InvalidAttributeArity)));
		Ok(())
	}

	// Each alert code of the alert domain reads as its alert.
	crate::tb_cases! {
		fn an_alert_code_maps_to_its_alert((code, alert): (u8, HandshakeAlert)) -> TestResult {
			let read = alert_of([code]).handshake_alert()?;
			assert_eq!(read, alert);
			Ok(())
		}
		cases {
			auth_required => (1, HandshakeAlert::AuthRequired),
			version_mismatch => (2, HandshakeAlert::VersionMismatch),
			algorithm_mismatch => (3, HandshakeAlert::AlgorithmMismatch),
			decrypt_fail => (4, HandshakeAlert::DecryptFail),
			finished_integrity_fail => (5, HandshakeAlert::FinishedIntegrityFail),
		}
	}

	/// A code inside the decode domain that names no alert is refused with
	/// the code it carries.
	#[test]
	fn an_unknown_alert_code_is_refused() {
		let refused = alert_of([0x07]).handshake_alert();
		assert!(matches!(refused, Err(HandshakeError::UnknownAlertCode(7))));
	}

	// An alert code past the `u16` decode domain or past the alert domain is
	// refused as out of range.
	crate::tb_cases! {
		fn an_alert_code_past_its_domain_is_refused(bytes: &[u8]) {
			let refused = alert_of(bytes).handshake_alert();
			assert!(matches!(refused, Err(HandshakeError::IntegerOutOfRange)));
		}
		cases {
			/// A three-octet INTEGER exceeds the `u16` decode domain.
			three_octets => &[0x01, 0x02, 0x03],
			/// `0x0101` is 257, which a truncation to `u8` would alias to
			/// alert code 1 (`AuthRequired`).
			value_257 => &[0x01, 0x01],
			/// A two-octet alert code reads big-endian: `0x0100` is 256, past
			/// the alert domain, and never alert 1.
			value_256 => &[0x01, 0x00],
		}
	}

	// Two attributes of one type order by their values.
	crate::tb_cases! {
		fn attributes_of_one_type_order_by_value((first, second, ordering): (u8, u8, Ordering)) {
			let first = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, integer_of([first]));
			let second = HandshakeAttribute::new(HANDSHAKE_SECURITY_OFFER, integer_of([second]));
			assert_eq!(first.cmp(&second), ordering);
		}
		cases {
			less => (0x01, 0x02, Ordering::Less),
			greater => (0x02, 0x01, Ordering::Greater),
			equal => (0x01, 0x01, Ordering::Equal),
		}
	}
}

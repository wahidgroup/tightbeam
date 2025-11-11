#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::crypto::negotiation::{SecurityAccept, SecurityOffer};
use crate::crypto::x509::attr::Attribute;
use crate::der::asn1::{ObjectIdentifier, OctetString, UintRef};
use crate::der::{asn1::Any, Sequence};

use super::{HandshakeAlert, HandshakeError};
use crate::oids::{
	HANDSHAKE_ABORT_ALERT, HANDSHAKE_ALGORITHM_PROFILE, HANDSHAKE_CLIENT_NONCE, HANDSHAKE_PROTOCOL_VERSION,
	HANDSHAKE_SECURITY_ACCEPT, HANDSHAKE_SECURITY_OFFER, HANDSHAKE_SELECTED_CURVE, HANDSHAKE_SELECT_ALGORITHM,
	HANDSHAKE_SELECT_VERSION, HANDSHAKE_SERVER_NONCE, HANDSHAKE_SUPPORTED_CURVES, HANDSHAKE_TRANSCRIPT_HASH,
};

/// CMS Attribute simplified (profile enforces single value only)
#[derive(Sequence, Debug, Clone, PartialEq, Eq)]
pub struct HandshakeAttribute {
	pub attr_type: ObjectIdentifier,
	pub attr_values: Vec<Any>, // MUST contain exactly one value under profile
}

// Provide ordering for canonical DER SET OF encoding. Order by attr_type OID bytes then encoded first value.
impl core::cmp::PartialOrd for HandshakeAttribute {
	fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl core::cmp::Ord for HandshakeAttribute {
	fn cmp(&self, other: &Self) -> core::cmp::Ordering {
		let oid_ord = self.attr_type.as_bytes().cmp(other.attr_type.as_bytes());
		if oid_ord != core::cmp::Ordering::Equal {
			return oid_ord;
		}

		core::cmp::Ordering::Equal
	}
}

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
impl From<&Attribute> for HandshakeAttribute {
	fn from(attr: &Attribute) -> Self {
		HandshakeAttribute { attr_type: attr.oid.clone(), attr_values: attr.values.clone().into() }
	}
}

// -------------------------- Builders --------------------------

fn encode_uint_u16(v: u16) -> Result<Any, HandshakeError> {
	let be = v.to_be_bytes();
	let slice = if v < 256 {
		&be[1..]
	} else {
		&be[..]
	};
	let uint = UintRef::new(slice).map_err(|_| HandshakeError::InvalidIntegerEncoding)?;
	Any::encode_from(&uint).map_err(|_| HandshakeError::InvalidIntegerEncoding)
}

pub fn encode_protocol_version(version: u16) -> Result<HandshakeAttribute, HandshakeError> {
	let any = encode_uint_u16(version)?;
	HandshakeAttribute::new_single(HANDSHAKE_PROTOCOL_VERSION, any)
}

pub fn encode_algorithm_profile() -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(&HANDSHAKE_ALGORITHM_PROFILE)?;
	HandshakeAttribute::new_single(HANDSHAKE_ALGORITHM_PROFILE, any)
}

pub fn encode_client_nonce(nonce: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(nonce).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_CLIENT_NONCE, any)
}

pub fn encode_server_nonce(nonce: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(nonce).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_SERVER_NONCE, any)
}

pub fn encode_selected_version(version: u16) -> Result<HandshakeAttribute, HandshakeError> {
	let any = encode_uint_u16(version)?;
	HandshakeAttribute::new_single(HANDSHAKE_SELECT_VERSION, any)
}

pub fn encode_selected_algorithm_profile() -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(&HANDSHAKE_ALGORITHM_PROFILE)
		.map_err(|_| HandshakeError::DerError(der::Error::from(der::ErrorKind::Failed)))?;
	HandshakeAttribute::new_single(HANDSHAKE_SELECT_ALGORITHM, any)
}

pub fn encode_abort_alert(alert: HandshakeAlert) -> Result<HandshakeAttribute, HandshakeError> {
	let any = encode_uint_u16(alert as u16)?;
	HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT, any)
}

pub fn encode_transcript_hash(hash: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(hash).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_TRANSCRIPT_HASH, any)
}

/// Encode list of supported curves for algorithm negotiation.
///
/// This allows clients/servers to advertise which elliptic curves they support.
/// The list should be in preference order (most preferred first).
///
/// # Parameters
/// - `curves`: Slice of curve OIDs in preference order
///
/// # Returns
/// HandshakeAttribute with multiple values (exception to single-value rule for capabilities)
pub fn encode_supported_curves(curves: &[ObjectIdentifier]) -> Result<HandshakeAttribute, HandshakeError> {
	if curves.is_empty() {
		return Err(HandshakeError::MissingAttribute);
	}

	let mut values = Vec::with_capacity(curves.len());
	for curve in curves {
		values.push(Any::encode_from(curve)?);
	}

	Ok(HandshakeAttribute { attr_type: HANDSHAKE_SUPPORTED_CURVES, attr_values: values })
}

/// Encode selected curve for algorithm negotiation.
///
/// Server uses this to inform client which curve was selected from the
/// client's supported curves list.
///
/// # Parameters
/// - `curve`: The selected curve OID
pub fn encode_selected_curve(curve: ObjectIdentifier) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(&curve)?;
	HandshakeAttribute::new_single(HANDSHAKE_SELECTED_CURVE, any)
}

/// Encode SecurityOffer for wire transmission.
///
/// Client uses this to advertise supported security profiles to server.
pub fn encode_security_offer(offer: &SecurityOffer) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(offer)?;
	HandshakeAttribute::new_single(HANDSHAKE_SECURITY_OFFER, any)
}

/// Encode SecurityAccept for wire transmission.
///
/// Server uses this to inform client which profile was selected.
pub fn encode_security_accept(accept: &SecurityAccept) -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(accept)?;
	HandshakeAttribute::new_single(HANDSHAKE_SECURITY_ACCEPT, any)
}

// -------------------------- Decoders --------------------------

pub fn extract_nonce(attr: &HandshakeAttribute) -> Result<[u8; 32], HandshakeError> {
	let any = attr.value()?;
	let os: OctetString = any.decode_as().map_err(|_| HandshakeError::InvalidNonceEncoding)?;

	let bytes = os.as_bytes();
	if bytes.len() != 32 {
		return Err(HandshakeError::NonceLengthError((bytes.len(), 32).into()));
	}

	let mut out = [0u8; 32];
	out.copy_from_slice(bytes);
	Ok(out)
}

pub fn extract_u16(attr: &HandshakeAttribute) -> Result<u16, HandshakeError> {
	let any = attr.value()?;
	let uint_ref: UintRef = any.decode_as().map_err(|_| HandshakeError::InvalidIntegerEncoding)?;

	let b = uint_ref.as_bytes();
	if b.is_empty() || b.len() > 2 {
		return Err(HandshakeError::IntegerOutOfRange);
	}

	let v = if b.len() == 1 {
		b[0] as u16
	} else {
		((b[0] as u16) << 8) | b[1] as u16
	};

	Ok(v)
}

pub fn extract_transcript_hash(attr: &HandshakeAttribute) -> Result<[u8; 32], HandshakeError> {
	extract_nonce(attr) // same structure (OCTET STRING SIZE(32))
}

/// Extract list of supported curves from a capabilities attribute.
///
/// # Parameters
/// - `attr`: HandshakeAttribute with HANDSHAKE_SUPPORTED_CURVES_OID type
///
/// # Returns
/// Vector of curve OIDs in preference order
pub fn extract_supported_curves(attr: &HandshakeAttribute) -> Result<Vec<ObjectIdentifier>, HandshakeError> {
	if attr.attr_type != HANDSHAKE_SUPPORTED_CURVES {
		return Err(HandshakeError::MissingAttribute);
	}

	if attr.attr_values.is_empty() {
		return Err(HandshakeError::MissingAttribute);
	}

	let mut curves = Vec::with_capacity(attr.attr_values.len());
	for any in &attr.attr_values {
		curves.push(any.decode_as()?);
	}

	Ok(curves)
}

/// Extract selected curve from server's response.
///
/// # Parameters
/// - `attr`: HandshakeAttribute with HANDSHAKE_SELECTED_CURVE_OID type
///
/// # Returns
/// The selected curve OID
pub fn extract_selected_curve(attr: &HandshakeAttribute) -> Result<ObjectIdentifier, HandshakeError> {
	if attr.attr_type != HANDSHAKE_SELECTED_CURVE {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

/// Extract SecurityOffer from unprotected attributes.
///
/// # Parameters
/// - `attr`: HandshakeAttribute with HANDSHAKE_SECURITY_OFFER_OID type
///
/// # Returns
/// The decoded SecurityOffer
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
pub fn extract_security_accept(attr: &HandshakeAttribute) -> Result<SecurityAccept, HandshakeError> {
	if attr.attr_type != HANDSHAKE_SECURITY_ACCEPT {
		return Err(HandshakeError::MissingAttribute);
	}

	let any = attr.value()?;
	Ok(any.decode_as()?)
}

pub fn extract_alert(attr: &HandshakeAttribute) -> Result<HandshakeAlert, HandshakeError> {
	let code = extract_u16(attr)? as u8;
	match code {
		1 => Ok(HandshakeAlert::AuthRequired),
		2 => Ok(HandshakeAlert::VersionMismatch),
		3 => Ok(HandshakeAlert::AlgorithmMismatch),
		4 => Ok(HandshakeAlert::DecryptFail),
		5 => Ok(HandshakeAlert::FinishedIntegrityFail),
		_ => Err(HandshakeError::UnknownAlertCode(code)),
	}
}

/// Extract alert from X.509 attribute without cloning
pub fn extract_alert_x509(attr: &Attribute) -> Result<HandshakeAlert, HandshakeError> {
	// Convert values to Vec<Any> (unavoidable due to SetOfVec API)
	let values: Vec<Any> = attr.values.clone().into();
	if values.len() != 1 {
		return Err(HandshakeError::InvalidAttributeArity);
	}

	let any = &values[0];
	let uint_ref: UintRef = any.decode_as().map_err(|_| HandshakeError::InvalidIntegerEncoding)?;

	let b = uint_ref.as_bytes();
	if b.is_empty() || b.len() > 2 {
		return Err(HandshakeError::IntegerOutOfRange);
	}

	let code = if b.len() == 1 {
		b[0] as u16
	} else {
		((b[0] as u16) << 8) | b[1] as u16
	} as u8;

	match code {
		1 => Ok(HandshakeAlert::AuthRequired),
		2 => Ok(HandshakeAlert::VersionMismatch),
		3 => Ok(HandshakeAlert::AlgorithmMismatch),
		4 => Ok(HandshakeAlert::DecryptFail),
		5 => Ok(HandshakeAlert::FinishedIntegrityFail),
		_ => Err(HandshakeError::UnknownAlertCode(code)),
	}
}

// -------------------------- Attribute search --------------------------

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

pub fn validate_required(attrs: &[HandshakeAttribute], oids: &[ObjectIdentifier]) -> Result<(), HandshakeError> {
	for oid in oids {
		let _ = find(attrs, oid)?;
	}

	Ok(())
}

// -------------------------- Tests --------------------------
#[cfg(test)]
mod tests {
	use super::*;
	use crate::der::asn1::Any;
	use crate::der::asn1::{OctetString as DerOctetString, UintRef};
	use crate::oids::{CURVE_NIST_P256, CURVE_NIST_P384, CURVE_SECP256K1};
	use crate::oids::{
		HANDSHAKE_ABORT_ALERT, HANDSHAKE_ALGORITHM_PROFILE, HANDSHAKE_CLIENT_NONCE, HANDSHAKE_PROTOCOL_VERSION,
		HANDSHAKE_SELECT_ALGORITHM, HANDSHAKE_SELECT_VERSION, HANDSHAKE_SERVER_NONCE,
	};

	fn mk_integer(bytes: &[u8]) -> Result<Any, der::Error> {
		let u = UintRef::new(bytes)?;
		Any::encode_from(&u)
	}

	fn mk_octet(bytes: &[u8]) -> Result<Any, der::Error> {
		let os = DerOctetString::new(bytes)?;
		Any::encode_from(&os)
	}

	#[test]
	fn round_trip_nonce() -> Result<(), HandshakeError> {
		let n = [0xAAu8; 32];
		let attr = encode_client_nonce(&n)?;
		let out = extract_nonce(&attr)?;
		assert_eq!(n, out);
		Ok(())
	}

	#[test]
	fn duplicate_detected() -> Result<(), HandshakeError> {
		let n = [0x11u8; 32];
		let a1 = encode_client_nonce(&n)?;
		let a2 = encode_client_nonce(&n)?;
		let attrs = vec![a1, a2];
		let err = find(&attrs, &HANDSHAKE_CLIENT_NONCE).unwrap_err();
		assert!(matches!(err, HandshakeError::DuplicateAttribute));
		Ok(())
	}

	#[test]
	fn missing_attribute_detected() -> Result<(), HandshakeError> {
		let n = [0x22u8; 32];
		let only = encode_client_nonce(&n)?;
		let attrs = vec![only];
		let err = find(&attrs, &HANDSHAKE_SERVER_NONCE).unwrap_err();
		assert!(matches!(err, HandshakeError::MissingAttribute));
		Ok(())
	}

	#[test]
	fn invalid_attribute_arity() -> Result<(), der::Error> {
		let n = [0x33u8; 32];
		let any = mk_octet(&n)?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_CLIENT_NONCE, attr_values: vec![any.clone(), any] };
		assert!(matches!(attr.value().unwrap_err(), HandshakeError::InvalidAttributeArity));
		Ok(())
	}

	#[test]
	fn nonce_length_error() -> Result<(), der::Error> {
		let short = [0x44u8; 16];
		let any = mk_octet(&short)?;

		let attr = HandshakeAttribute { attr_type: HANDSHAKE_CLIENT_NONCE, attr_values: vec![any] };
		if let HandshakeError::NonceLengthError(e) = extract_nonce(&attr).unwrap_err() {
			assert_eq!(e.received, 16);
			assert_eq!(e.expected, 32);
		} else {
			panic!("expected NonceLengthError");
		}
		Ok(())
	}

	#[test]
	fn protocol_version_round_trip() -> Result<(), HandshakeError> {
		for v in [0u16, 1, 255, 256, 65535] {
			let attr = encode_protocol_version(v)?;
			assert_eq!(attr.attr_type, HANDSHAKE_PROTOCOL_VERSION);
			let extracted = extract_u16(&attr)?;
			assert_eq!(extracted, v);
		}
		Ok(())
	}

	#[test]
	fn selected_version_round_trip() -> Result<(), HandshakeError> {
		for v in [0u16, 5, 1024, 65535] {
			let attr = encode_selected_version(v)?;
			assert_eq!(attr.attr_type, HANDSHAKE_SELECT_VERSION);
			let extracted = extract_u16(&attr)?;
			assert_eq!(extracted, v);
		}
		Ok(())
	}

	#[test]
	fn algorithm_profile_attributes() -> Result<(), HandshakeError> {
		let base = encode_algorithm_profile()?;
		assert_eq!(base.attr_type, HANDSHAKE_ALGORITHM_PROFILE);
		let sel = encode_selected_algorithm_profile()?;
		assert_eq!(sel.attr_type, HANDSHAKE_SELECT_ALGORITHM);
		Ok(())
	}

	#[test]
	fn transcript_hash_round_trip() -> Result<(), HandshakeError> {
		let h = [0x55u8; 32];
		let attr = encode_transcript_hash(&h)?;
		let out = extract_transcript_hash(&attr)?;
		assert_eq!(h, out);
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
			let attr = encode_abort_alert(*alert)?;
			assert_eq!(extract_alert(&attr)?, *alert);
			// Verify raw integer encoding
			let raw = extract_u16(&attr)?;
			assert_eq!(raw as u8, *code);
		}

		// Unknown alert code
		let unknown_any = mk_integer(&[0x06])?;
		let unknown_attr = HandshakeAttribute { attr_type: HANDSHAKE_ABORT_ALERT, attr_values: vec![unknown_any] };
		if let HandshakeError::UnknownAlertCode(c) = extract_alert(&unknown_attr).unwrap_err() {
			assert_eq!(c, 6u8);
		} else {
			panic!("expected UnknownAlertCode");
		}
		Ok(())
	}

	#[test]
	fn integer_out_of_range_error() -> Result<(), der::Error> {
		// 3-byte integer should be rejected
		let any = mk_integer(&[0x01, 0x02, 0x03])?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_PROTOCOL_VERSION, attr_values: vec![any] };
		assert!(matches!(extract_u16(&attr).unwrap_err(), HandshakeError::IntegerOutOfRange));
		Ok(())
	}

	#[test]
	fn supported_curves_encoding() -> Result<(), HandshakeError> {
		// Encode multiple curves in preference order
		let curves = vec![CURVE_SECP256K1, CURVE_NIST_P256, CURVE_NIST_P384];
		let attr = encode_supported_curves(&curves)?;

		assert_eq!(attr.attr_type, HANDSHAKE_SUPPORTED_CURVES);
		assert_eq!(attr.attr_values.len(), 3);

		// Extract and verify
		let extracted = extract_supported_curves(&attr)?;
		assert_eq!(extracted, curves);

		Ok(())
	}

	#[test]
	fn selected_curve_round_trip() -> Result<(), HandshakeError> {
		let attr = encode_selected_curve(CURVE_NIST_P256)?;
		assert_eq!(attr.attr_type, HANDSHAKE_SELECTED_CURVE);

		let extracted = extract_selected_curve(&attr)?;
		assert_eq!(extracted, CURVE_NIST_P256);

		Ok(())
	}

	#[test]
	fn empty_supported_curves_fails() {
		let result = encode_supported_curves(&[]);
		assert!(matches!(result.unwrap_err(), HandshakeError::MissingAttribute));
	}

	#[test]
	fn wrong_oid_type_for_curves() -> Result<(), HandshakeError> {
		// Create attribute with wrong OID type
		let any = Any::encode_from(&CURVE_SECP256K1)?;
		let wrong_attr = HandshakeAttribute { attr_type: HANDSHAKE_CLIENT_NONCE, attr_values: vec![any] };

		// Should fail because OID doesn't match
		let result = extract_supported_curves(&wrong_attr);
		assert!(matches!(result.unwrap_err(), HandshakeError::MissingAttribute));

		Ok(())
	}
}

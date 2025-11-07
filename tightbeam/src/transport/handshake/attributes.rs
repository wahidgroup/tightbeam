#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::der::asn1::{ObjectIdentifier, OctetString, UintRef};
use crate::der::{asn1::Any, Sequence};

use super::{HandshakeAlert, HandshakeError};
use crate::asn1::transport::{
	HANDSHAKE_ABORT_ALERT_OID, HANDSHAKE_ALGORITHM_PROFILE_OID, HANDSHAKE_CLIENT_NONCE_OID,
	HANDSHAKE_PROTOCOL_VERSION_OID, HANDSHAKE_SELECT_ALGORITHM_OID, HANDSHAKE_SELECT_VERSION_OID,
	HANDSHAKE_SERVER_NONCE_OID, HANDSHAKE_TRANSCRIPT_HASH_OID,
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
	HandshakeAttribute::new_single(HANDSHAKE_PROTOCOL_VERSION_OID, any)
}

pub fn encode_algorithm_profile() -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(&HANDSHAKE_ALGORITHM_PROFILE_OID)?;
	HandshakeAttribute::new_single(HANDSHAKE_ALGORITHM_PROFILE_OID, any)
}

pub fn encode_client_nonce(nonce: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(nonce).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_CLIENT_NONCE_OID, any)
}

pub fn encode_server_nonce(nonce: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(nonce).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_SERVER_NONCE_OID, any)
}

pub fn encode_selected_version(version: u16) -> Result<HandshakeAttribute, HandshakeError> {
	let any = encode_uint_u16(version)?;
	HandshakeAttribute::new_single(HANDSHAKE_SELECT_VERSION_OID, any)
}

pub fn encode_selected_algorithm_profile() -> Result<HandshakeAttribute, HandshakeError> {
	let any = Any::encode_from(&HANDSHAKE_ALGORITHM_PROFILE_OID)
		.map_err(|_| HandshakeError::DerError(der::Error::from(der::ErrorKind::Failed)))?;
	HandshakeAttribute::new_single(HANDSHAKE_SELECT_ALGORITHM_OID, any)
}

pub fn encode_abort_alert(alert: HandshakeAlert) -> Result<HandshakeAttribute, HandshakeError> {
	let any = encode_uint_u16(alert as u16)?;
	HandshakeAttribute::new_single(HANDSHAKE_ABORT_ALERT_OID, any)
}

pub fn encode_transcript_hash(hash: &[u8; 32]) -> Result<HandshakeAttribute, HandshakeError> {
	let os = OctetString::new(hash).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	let any = Any::encode_from(&os).map_err(|_| HandshakeError::InvalidNonceEncoding)?;
	HandshakeAttribute::new_single(HANDSHAKE_TRANSCRIPT_HASH_OID, any)
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
	use crate::asn1::transport::{
		HANDSHAKE_ABORT_ALERT_OID, HANDSHAKE_ALGORITHM_PROFILE_OID, HANDSHAKE_CLIENT_NONCE_OID,
		HANDSHAKE_PROTOCOL_VERSION_OID, HANDSHAKE_SELECT_ALGORITHM_OID, HANDSHAKE_SELECT_VERSION_OID,
		HANDSHAKE_SERVER_NONCE_OID,
	};
	use crate::der::asn1::Any;
	use crate::der::asn1::{OctetString as DerOctetString, UintRef};

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
		let err = find(&attrs, &HANDSHAKE_CLIENT_NONCE_OID).unwrap_err();
		assert!(matches!(err, HandshakeError::DuplicateAttribute));
		Ok(())
	}

	#[test]
	fn missing_attribute_detected() -> Result<(), HandshakeError> {
		let n = [0x22u8; 32];
		let only = encode_client_nonce(&n)?;
		let attrs = vec![only];
		let err = find(&attrs, &HANDSHAKE_SERVER_NONCE_OID).unwrap_err();
		assert!(matches!(err, HandshakeError::MissingAttribute));
		Ok(())
	}

	#[test]
	fn invalid_attribute_arity() -> Result<(), der::Error> {
		let n = [0x33u8; 32];
		let any = mk_octet(&n)?;
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_CLIENT_NONCE_OID, attr_values: vec![any.clone(), any] };
		assert!(matches!(attr.value().unwrap_err(), HandshakeError::InvalidAttributeArity));
		Ok(())
	}

	#[test]
	fn nonce_length_error() -> Result<(), der::Error> {
		let short = [0x44u8; 16];
		let any = mk_octet(&short)?;

		let attr = HandshakeAttribute { attr_type: HANDSHAKE_CLIENT_NONCE_OID, attr_values: vec![any] };
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
			assert_eq!(attr.attr_type, HANDSHAKE_PROTOCOL_VERSION_OID);
			let extracted = extract_u16(&attr)?;
			assert_eq!(extracted, v);
		}
		Ok(())
	}

	#[test]
	fn selected_version_round_trip() -> Result<(), HandshakeError> {
		for v in [0u16, 5, 1024, 65535] {
			let attr = encode_selected_version(v)?;
			assert_eq!(attr.attr_type, HANDSHAKE_SELECT_VERSION_OID);
			let extracted = extract_u16(&attr)?;
			assert_eq!(extracted, v);
		}
		Ok(())
	}

	#[test]
	fn algorithm_profile_attributes() -> Result<(), HandshakeError> {
		let base = encode_algorithm_profile()?;
		assert_eq!(base.attr_type, HANDSHAKE_ALGORITHM_PROFILE_OID);
		let sel = encode_selected_algorithm_profile()?;
		assert_eq!(sel.attr_type, HANDSHAKE_SELECT_ALGORITHM_OID);
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
		let unknown_attr = HandshakeAttribute { attr_type: HANDSHAKE_ABORT_ALERT_OID, attr_values: vec![unknown_any] };
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
		let attr = HandshakeAttribute { attr_type: HANDSHAKE_PROTOCOL_VERSION_OID, attr_values: vec![any] };
		assert!(matches!(extract_u16(&attr).unwrap_err(), HandshakeError::IntegerOutOfRange));
		Ok(())
	}
}

//! The payment message types of the tests, after ISO 20022.
//!
//! The types follow the structure of ISO 20022 pacs.008 (FI-to-FI Credit
//! Transfer). They serve business-level correlation and audit, and idempotency
//! keys on the frame's (`metadata.id`, `metadata.order`) instead.

use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::asn1::OctetString;
use tightbeam::der::{Enumerated, Sequence};
use tightbeam::Beamable;

use super::currency::MonetaryAmount;

// Payment identification

/// The business-level transaction reference of a payment.
///
/// The type follows ISO 20022 PaymentIdentification. It serves business
/// correlation and audit, and idempotency keys on the frame's
/// (`metadata.id`, `metadata.order`) instead.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct PaymentIdentification {
	/// The instruction identification, the local reference of this leg.
	pub instruction_id: OctetString,
	/// The end-to-end identification, which spans authorization to capture.
	pub end_to_end_id: OctetString,
	/// The transaction identification, unique per business transaction.
	pub transaction_id: OctetString,
}

impl PaymentIdentification {
	/// Creates a payment identification.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- an identifier is longer than an OCTET STRING holds.
	pub fn new(
		instruction_id: impl Into<Vec<u8>>,
		end_to_end_id: impl Into<Vec<u8>>,
		transaction_id: impl Into<Vec<u8>>,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			instruction_id: OctetString::new(instruction_id)?,
			end_to_end_id: OctetString::new(end_to_end_id)?,
			transaction_id: OctetString::new(transaction_id)?,
		})
	}
}

// Credit transfer transaction, the authorization request

/// The credit transfer transaction, which is the authorization request.
///
/// The type follows ISO 20022 CreditTransferTransaction.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(
	profile(TightbeamProfile),
	confidential,
	nonrepudiable,
	message_integrity,
	min_version = "V1"
)]
pub struct CreditTransferTransaction {
	/// The identification of the payment.
	pub payment_id: PaymentIdentification,
	/// The instructed amount, in quanta.
	pub instructed_amount: MonetaryAmount,
	/// The tokenized reference of the creditor account.
	pub creditor_account: OctetString,
	/// The tokenized reference of the debtor account.
	pub debtor_account: OctetString,
	/// The remittance information, an optional reference.
	#[asn1(optional = "true")]
	pub remittance_info: Option<OctetString>,
	/// The creation time, in milliseconds since the Unix epoch.
	pub creation_datetime: u64,
}

impl CreditTransferTransaction {
	/// Creates a credit transfer transaction.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- an account reference or the remittance information is longer than an
	///   OCTET STRING holds.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		payment_id: PaymentIdentification,
		instructed_amount: MonetaryAmount,
		creditor_account: impl Into<Vec<u8>>,
		debtor_account: impl Into<Vec<u8>>,
		remittance_info: Option<Vec<u8>>,
		creation_datetime: u64,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			payment_id,
			instructed_amount,
			creditor_account: OctetString::new(creditor_account)?,
			debtor_account: OctetString::new(debtor_account)?,
			remittance_info: remittance_info.map(OctetString::new).transpose()?,
			creation_datetime,
		})
	}
}

// Capture transaction

/// The capture request, which references the original authorization.
///
/// The type follows the payment chain concept of ISO 20022. It links to the
/// original authorization through `original_end_to_end_id`.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(
	profile(TightbeamProfile),
	confidential,
	nonrepudiable,
	message_integrity,
	min_version = "V1"
)]
pub struct CaptureTransaction {
	/// The end-to-end ID of the original authorization.
	pub original_end_to_end_id: OctetString,
	/// The capture amount, which can differ from the authorized amount on a
	/// partial capture.
	pub capture_amount: MonetaryAmount,
	/// The capture time, in milliseconds since the Unix epoch.
	pub capture_datetime: u64,
}

impl CaptureTransaction {
	/// Creates a capture transaction.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- the end-to-end ID is longer than an OCTET STRING holds.
	pub fn new(
		original_end_to_end_id: impl Into<Vec<u8>>,
		capture_amount: MonetaryAmount,
		capture_datetime: u64,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			original_end_to_end_id: OctetString::new(original_end_to_end_id)?,
			capture_amount,
			capture_datetime,
		})
	}
}

// Payment status code

/// The payment status codes.
///
/// The codes follow ISO 20022 ExternalPaymentTransactionStatus1Code.
#[repr(u8)]
#[derive(Enumerated, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStatusCode {
	/// ACCP, Accepted Customer Profile, for an approved authorization.
	AcceptedCustomerProfile = 0,
	/// ACSP, Accepted Settlement Completed, for a completed capture.
	AcceptedSettlementCompleted = 1,
	/// RJCT, for a rejected payment.
	Rejected = 2,
	/// PDNG, for a pending payment.
	Pending = 3,
	/// ACWC, Accepted With Change, for a partial capture.
	AcceptedWithChange = 4,
}

impl PaymentStatusCode {
	/// Returns whether the status indicates success.
	pub const fn is_success(&self) -> bool {
		matches!(
			self,
			Self::AcceptedCustomerProfile | Self::AcceptedSettlementCompleted | Self::AcceptedWithChange
		)
	}

	/// Returns whether the status is a final state.
	pub const fn is_final(&self) -> bool {
		matches!(self, Self::AcceptedSettlementCompleted | Self::Rejected)
	}
}

// Transaction status, the response

/// The transaction status, which is the response.
///
/// The type follows ISO 20022 pacs.002 TransactionStatus.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(profile(TightbeamProfile), min_version = "V1")]
pub struct TransactionStatus {
	/// The identification of the original payment.
	pub original_payment_id: PaymentIdentification,
	/// The status code of the payment.
	pub status: PaymentStatusCode,
	/// The authorization code of an approved or captured payment.
	#[asn1(optional = "true")]
	pub authorization_code: Option<OctetString>,
	/// The reason code of a rejected payment.
	#[asn1(optional = "true")]
	pub reason_code: Option<OctetString>,
}

impl TransactionStatus {
	/// Creates an approved status.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- the code is longer than an OCTET STRING holds.
	pub fn approved(
		original_payment_id: PaymentIdentification,
		authorization_code: impl Into<Vec<u8>>,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			original_payment_id,
			status: PaymentStatusCode::AcceptedCustomerProfile,
			authorization_code: Some(OctetString::new(authorization_code)?),
			reason_code: None,
		})
	}

	/// Creates a captured status.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- the code is longer than an OCTET STRING holds.
	pub fn captured(
		original_payment_id: PaymentIdentification,
		authorization_code: impl Into<Vec<u8>>,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			original_payment_id,
			status: PaymentStatusCode::AcceptedSettlementCompleted,
			authorization_code: Some(OctetString::new(authorization_code)?),
			reason_code: None,
		})
	}

	/// Creates a rejected status.
	///
	/// # Errors
	///
	/// - [`tightbeam::der::Error`] -- the code is longer than an OCTET STRING holds.
	pub fn rejected(
		original_payment_id: PaymentIdentification,
		reason_code: impl Into<Vec<u8>>,
	) -> tightbeam::der::Result<Self> {
		Ok(Self {
			original_payment_id,
			status: PaymentStatusCode::Rejected,
			authorization_code: None,
			reason_code: Some(OctetString::new(reason_code)?),
		})
	}

	/// Creates a pending status.
	#[allow(dead_code)]
	pub fn pending(original_payment_id: PaymentIdentification) -> Self {
		Self {
			original_payment_id,
			status: PaymentStatusCode::Pending,
			authorization_code: None,
			reason_code: None,
		}
	}
}

// KeyManager messages, for intra-hive HPKE key management

/// A request for the public encryption key of the KeyManager.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct GetPublicKeyRequest {
	/// A placeholder field, because the derives fail on an empty struct.
	#[asn1(optional = "true")]
	pub _placeholder: Option<u8>,
}

/// The response that carries the public key of the KeyManager.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct GetPublicKeyResponse {
	/// The HPKE public key in SEC 1 compressed form, 33 bytes for secp256k1.
	pub public_key: OctetString,
}

/// A request to decrypt a ciphertext with the private key of the KeyManager.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct DecryptRequest {
	/// The HPKE ciphertext to decrypt.
	pub ciphertext: OctetString,
}

/// The response that carries the decrypted plaintext.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct DecryptResponse {
	/// The bytes of the decrypted plaintext.
	pub plaintext: OctetString,
}

// Unit tests

#[cfg(test)]
mod tests {
	use super::*;
	use tightbeam::der::{asn1::Any, Decode, Encode, Tag, Tagged};
	use tightbeam::{tb_cases, TightBeamError};

	/// The tags of the fields of the SEQUENCE that `message` encodes to.
	fn tags_of(message: &impl Encode) -> Vec<Tag> {
		let encoding = message.to_der().expect("a payment message encodes");
		let fields = Vec::<Any>::from_der(&encoding).expect("a payment message is a SEQUENCE");
		fields.iter().map(Any::tag).collect()
	}

	/// `bytes` as an OCTET STRING.
	fn octets(bytes: &[u8]) -> OctetString {
		OctetString::new(bytes).expect("a short value fits an OCTET STRING")
	}

	/// The identification of a sample payment.
	fn sample_payment_id() -> PaymentIdentification {
		PaymentIdentification::new(b"INST001", b"E2E001", b"TXN001").expect("short identifiers fit")
	}

	/// A sample credit transfer with every optional field set.
	fn sample_transfer() -> CreditTransferTransaction {
		let amount = MonetaryAmount::new(1099, *b"USD");
		let transfer =
			CreditTransferTransaction::new(sample_payment_id(), amount, b"CRED", b"DEB", Some(b"INFO".to_vec()), 1);
		transfer.expect("short references fit")
	}

	/// A sample capture of the sample payment.
	fn sample_capture() -> CaptureTransaction {
		CaptureTransaction::new(b"E2E001", MonetaryAmount::new(1099, *b"USD"), 1).expect("a short ID fits")
	}

	/// The approved status of the sample payment.
	fn sample_approval() -> TransactionStatus {
		TransactionStatus::approved(sample_payment_id(), b"AUTH123").expect("a short code fits")
	}

	/// The rejected status of the sample payment.
	fn sample_rejection() -> TransactionStatus {
		TransactionStatus::rejected(sample_payment_id(), b"INSUFFICIENT_FUNDS").expect("a short code fits")
	}

	// Each byte field of a payment message encodes as an OCTET STRING, so the
	// tags of a message's fields are its schema.
	tb_cases! {
		fn a_message_encodes_its_bytes_as_octet_strings((tags, schema): (Vec<Tag>, Vec<Tag>)) {
			assert_eq!(tags, schema);
		}
		cases {
			payment_identification => (tags_of(&sample_payment_id()), vec![Tag::OctetString; 3]),
			monetary_amount => (tags_of(&MonetaryAmount::new(1099, *b"USD")), vec![Tag::Integer, Tag::OctetString]),
			credit_transfer => (
				tags_of(&sample_transfer()),
				vec![Tag::Sequence, Tag::Sequence, Tag::OctetString, Tag::OctetString, Tag::OctetString, Tag::Integer],
			),
			capture => (tags_of(&sample_capture()), vec![Tag::OctetString, Tag::Sequence, Tag::Integer]),
			approved_status => (tags_of(&sample_approval()), vec![Tag::Sequence, Tag::Enumerated, Tag::OctetString]),
			rejected_status => (tags_of(&sample_rejection()), vec![Tag::Sequence, Tag::Enumerated, Tag::OctetString]),
			public_key_response => (tags_of(&GetPublicKeyResponse { public_key: octets(&[2; 33]) }), vec![Tag::OctetString]),
			decrypt_request => (tags_of(&DecryptRequest { ciphertext: octets(&[1; 16]) }), vec![Tag::OctetString]),
			decrypt_response => (tags_of(&DecryptResponse { plaintext: octets(&[1; 16]) }), vec![Tag::OctetString]),
		}
	}

	#[test]
	fn payment_id_creation() -> Result<(), TightBeamError> {
		let pid = PaymentIdentification::new(b"INST001", b"E2E001", b"TXN001")?;
		assert_eq!(pid.instruction_id.as_bytes(), b"INST001");
		assert_eq!(pid.end_to_end_id.as_bytes(), b"E2E001");
		assert_eq!(pid.transaction_id.as_bytes(), b"TXN001");
		Ok(())
	}

	#[test]
	fn status_code_is_success() {
		assert!(PaymentStatusCode::AcceptedCustomerProfile.is_success());
		assert!(PaymentStatusCode::AcceptedSettlementCompleted.is_success());
		assert!(PaymentStatusCode::AcceptedWithChange.is_success());
		assert!(!PaymentStatusCode::Rejected.is_success());
		assert!(!PaymentStatusCode::Pending.is_success());
	}

	#[test]
	fn status_code_is_final() {
		assert!(PaymentStatusCode::AcceptedSettlementCompleted.is_final());
		assert!(PaymentStatusCode::Rejected.is_final());
		assert!(!PaymentStatusCode::AcceptedCustomerProfile.is_final());
		assert!(!PaymentStatusCode::Pending.is_final());
	}

	#[test]
	fn transaction_status_approved() -> Result<(), TightBeamError> {
		let pid = PaymentIdentification::new(b"I", b"E", b"T")?;
		let status = TransactionStatus::approved(pid.to_owned(), b"AUTH123".to_vec())?;
		assert_eq!(status.status, PaymentStatusCode::AcceptedCustomerProfile);
		assert_eq!(status.authorization_code, Some(OctetString::new(b"AUTH123")?));
		assert!(status.reason_code.is_none());
		Ok(())
	}

	#[test]
	fn get_public_key_request_roundtrip() -> Result<(), TightBeamError> {
		use tightbeam::{decode, encode};
		let req = super::GetPublicKeyRequest { _placeholder: None };
		let encoded = encode(&req)?;
		let decoded: super::GetPublicKeyRequest = decode(&encoded)?;
		assert_eq!(decoded, req);
		Ok(())
	}

	#[test]
	fn decrypt_request_roundtrip() -> Result<(), TightBeamError> {
		use tightbeam::{decode, encode};
		let req = super::DecryptRequest { ciphertext: OctetString::new(b"encrypted_data")? };
		let encoded = encode(&req)?;
		let decoded: super::DecryptRequest = decode(&encoded)?;
		assert_eq!(decoded.ciphertext, req.ciphertext);
		Ok(())
	}

	#[test]
	fn transaction_status_rejected() -> Result<(), TightBeamError> {
		let pid = PaymentIdentification::new(b"I", b"E", b"T")?;
		let status = TransactionStatus::rejected(pid.to_owned(), b"INSUFFICIENT_FUNDS".to_vec())?;
		assert_eq!(status.status, PaymentStatusCode::Rejected);
		assert!(status.authorization_code.is_none());
		assert_eq!(status.reason_code, Some(OctetString::new(b"INSUFFICIENT_FUNDS")?));
		Ok(())
	}
}

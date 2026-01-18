//! ISO 20022-Inspired Payment Message Types
//!
//! Based on ISO 20022 pacs.008 (FI-to-FI Credit Transfer) structure.
//! These types are for business-level correlation/audit, NOT idempotency.
//! Idempotency uses Frame's (metadata.id, metadata.order).

use tightbeam::crypto::profiles::TightbeamProfile;
use tightbeam::der::{Enumerated, Sequence};
use tightbeam::Beamable;

use super::currency::MonetaryAmount;

// ============================================================================
// Payment Identification
// ============================================================================

/// Payment identification - business-level transaction reference
///
/// Based on ISO 20022 PaymentIdentification.
/// NOTE: This is for business correlation/audit, NOT idempotency.
///       Idempotency uses Frame's (metadata.id, metadata.order).
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct PaymentIdentification {
	/// Instruction identification (local reference for this leg)
	pub instruction_id: Vec<u8>,
	/// End-to-end identification (survives entire auth->capture chain)
	pub end_to_end_id: Vec<u8>,
	/// Transaction identification (unique per business transaction)
	pub transaction_id: Vec<u8>,
}

impl PaymentIdentification {
	/// Create a new payment identification
	pub fn new(
		instruction_id: impl Into<Vec<u8>>,
		end_to_end_id: impl Into<Vec<u8>>,
		transaction_id: impl Into<Vec<u8>>,
	) -> Self {
		Self {
			instruction_id: instruction_id.into(),
			end_to_end_id: end_to_end_id.into(),
			transaction_id: transaction_id.into(),
		}
	}
}

// ============================================================================
// Credit Transfer Transaction (Authorization Request)
// ============================================================================

/// Credit transfer transaction - the authorization request
///
/// Based on ISO 20022 CreditTransferTransaction.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(
	profile(TightbeamProfile),
	confidential,
	nonrepudiable,
	message_integrity,
	min_version = "V1"
)]
pub struct CreditTransferTransaction {
	/// Payment identification
	pub payment_id: PaymentIdentification,
	/// Instructed amount in quanta
	pub instructed_amount: MonetaryAmount,
	/// Creditor account reference (tokenized)
	pub creditor_account: Vec<u8>,
	/// Debtor account reference (tokenized)
	pub debtor_account: Vec<u8>,
	/// Remittance information (optional reference)
	#[asn1(optional = "true")]
	pub remittance_info: Option<Vec<u8>>,
	/// Creation timestamp (epoch ms)
	pub creation_datetime: u64,
}

impl CreditTransferTransaction {
	/// Create a new credit transfer transaction
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		payment_id: PaymentIdentification,
		instructed_amount: MonetaryAmount,
		creditor_account: impl Into<Vec<u8>>,
		debtor_account: impl Into<Vec<u8>>,
		remittance_info: Option<Vec<u8>>,
		creation_datetime: u64,
	) -> Self {
		Self {
			payment_id,
			instructed_amount,
			creditor_account: creditor_account.into(),
			debtor_account: debtor_account.into(),
			remittance_info,
			creation_datetime,
		}
	}
}

// ============================================================================
// Capture Transaction
// ============================================================================

/// Capture request - references the original authorization
///
/// Based on ISO 20022 payment chain concept.
/// Links to original auth via original_end_to_end_id.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(
	profile(TightbeamProfile),
	confidential,
	nonrepudiable,
	message_integrity,
	min_version = "V1"
)]
pub struct CaptureTransaction {
	/// Original authorization's end-to-end ID
	pub original_end_to_end_id: Vec<u8>,
	/// Capture amount (may differ from auth for partial capture)
	pub capture_amount: MonetaryAmount,
	/// Capture timestamp (epoch ms)
	pub capture_datetime: u64,
}

impl CaptureTransaction {
	/// Create a new capture transaction
	#[allow(dead_code)]
	pub fn new(
		original_end_to_end_id: impl Into<Vec<u8>>,
		capture_amount: MonetaryAmount,
		capture_datetime: u64,
	) -> Self {
		Self {
			original_end_to_end_id: original_end_to_end_id.into(),
			capture_amount,
			capture_datetime,
		}
	}
}

// ============================================================================
// Payment Status Code
// ============================================================================

/// Payment status codes
///
/// Based on ISO 20022 ExternalPaymentTransactionStatus1Code.
#[repr(u8)]
#[derive(Enumerated, Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentStatusCode {
	/// ACCP - Accepted Customer Profile (authorization approved)
	AcceptedCustomerProfile = 0,
	/// ACSP - Accepted Settlement Completed (capture completed)
	AcceptedSettlementCompleted = 1,
	/// RJCT - Rejected
	Rejected = 2,
	/// PDNG - Pending
	Pending = 3,
	/// ACWC - Accepted With Change (partial capture)
	AcceptedWithChange = 4,
}

impl PaymentStatusCode {
	/// Check if the status indicates success
	pub const fn is_success(&self) -> bool {
		matches!(
			self,
			Self::AcceptedCustomerProfile | Self::AcceptedSettlementCompleted | Self::AcceptedWithChange
		)
	}

	/// Check if the status indicates a final state
	pub const fn is_final(&self) -> bool {
		matches!(self, Self::AcceptedSettlementCompleted | Self::Rejected)
	}
}

// ============================================================================
// Transaction Status (Response)
// ============================================================================

/// Transaction status - the response
///
/// Based on ISO 20022 pacs.002 TransactionStatus.
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
#[beam(
	profile(TightbeamProfile),
	confidential,
	nonrepudiable,
	message_integrity,
	min_version = "V1"
)]
pub struct TransactionStatus {
	/// Original payment identification
	pub original_payment_id: PaymentIdentification,
	/// Status code
	pub status: PaymentStatusCode,
	/// Authorization code (if approved)
	#[asn1(optional = "true")]
	pub authorization_code: Option<Vec<u8>>,
	/// Reason code (if rejected)
	#[asn1(optional = "true")]
	pub reason_code: Option<Vec<u8>>,
}

impl TransactionStatus {
	/// Create an approved status
	pub fn approved(original_payment_id: PaymentIdentification, authorization_code: Vec<u8>) -> Self {
		Self {
			original_payment_id,
			status: PaymentStatusCode::AcceptedCustomerProfile,
			authorization_code: Some(authorization_code),
			reason_code: None,
		}
	}

	/// Create a captured status
	pub fn captured(original_payment_id: PaymentIdentification, authorization_code: Vec<u8>) -> Self {
		Self {
			original_payment_id,
			status: PaymentStatusCode::AcceptedSettlementCompleted,
			authorization_code: Some(authorization_code),
			reason_code: None,
		}
	}

	/// Create a rejected status
	pub fn rejected(original_payment_id: PaymentIdentification, reason_code: Vec<u8>) -> Self {
		Self {
			original_payment_id,
			status: PaymentStatusCode::Rejected,
			authorization_code: None,
			reason_code: Some(reason_code),
		}
	}

	/// Create a pending status
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

// ============================================================================
// KeyManager Messages (for intra-hive ECIES key management)
// ============================================================================

/// Request to get the KeyManager's public key for encryption
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct GetPublicKeyRequest {
	/// Placeholder (empty struct causes derive issues)
	#[asn1(optional = "true")]
	pub _placeholder: Option<u8>,
}

/// Response containing the KeyManager's public key
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct GetPublicKeyResponse {
	/// The ECIES public key in SEC1 compressed format (33 bytes for secp256k1)
	pub public_key: Vec<u8>,
}

/// Request to decrypt ciphertext using the KeyManager's private key
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct DecryptRequest {
	/// ECIES ciphertext to decrypt
	pub ciphertext: Vec<u8>,
}

/// Response containing the decrypted plaintext
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct DecryptResponse {
	/// Decrypted plaintext bytes
	pub plaintext: Vec<u8>,
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn payment_id_creation() {
		let pid = PaymentIdentification::new(b"INST001", b"E2E001", b"TXN001");
		assert_eq!(pid.instruction_id, b"INST001");
		assert_eq!(pid.end_to_end_id, b"E2E001");
		assert_eq!(pid.transaction_id, b"TXN001");
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
	fn transaction_status_approved() {
		let pid = PaymentIdentification::new(b"I", b"E", b"T");
		let status = TransactionStatus::approved(pid.clone(), b"AUTH123".to_vec());
		assert_eq!(status.status, PaymentStatusCode::AcceptedCustomerProfile);
		assert_eq!(status.authorization_code, Some(b"AUTH123".to_vec()));
		assert!(status.reason_code.is_none());
	}

	#[test]
	fn get_public_key_request_roundtrip() {
		use tightbeam::{decode, encode};
		let req = super::GetPublicKeyRequest { _placeholder: None };
		let encoded = encode(&req).unwrap();
		let decoded: super::GetPublicKeyRequest = decode(&encoded).unwrap();
		assert_eq!(decoded, req);
	}

	#[test]
	fn decrypt_request_roundtrip() {
		use tightbeam::{decode, encode};
		let req = super::DecryptRequest { ciphertext: b"encrypted_data".to_vec() };
		let encoded = encode(&req).unwrap();
		let decoded: super::DecryptRequest = decode(&encoded).unwrap();
		assert_eq!(decoded.ciphertext, req.ciphertext);
	}

	#[test]
	fn transaction_status_rejected() {
		let pid = PaymentIdentification::new(b"I", b"E", b"T");
		let status = TransactionStatus::rejected(pid.clone(), b"INSUFFICIENT_FUNDS".to_vec());
		assert_eq!(status.status, PaymentStatusCode::Rejected);
		assert!(status.authorization_code.is_none());
		assert_eq!(status.reason_code, Some(b"INSUFFICIENT_FUNDS".to_vec()));
	}
}

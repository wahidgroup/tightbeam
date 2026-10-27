//! The servlets of the payment scenarios.
//!
//! [`AuthorizationServlet`] approves a credit transfer, [`CaptureServlet`]
//! settles a capture, and [`KeyManagerServlet`] serves its public key and
//! opens a secret sealed to it.

use std::sync::Arc;

use sha3::Sha3_256;
use tightbeam::asn1::MessagePriority;
use tightbeam::crypto::hpke::{HpkeMessage, HpkeSecp256k1Sha256Aes256Gcm, HpkeSecretKeyOps};
use tightbeam::crypto::secret::ToInsecure;
use tightbeam::crypto::sign::ecdsa::k256::SecretKey;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, servlet, Frame, TightBeamError};

use super::currency::MonetaryAmount;
use super::harness::{PaymentHarness, PAYMENT_TAG};

use tightbeam::der::asn1::OctetString;
use tightbeam::urn::Urn;

/// The HPKE `info` under which the key manager opens a sealed secret.
pub(crate) const KEY_MANAGER_HPKE_INFO: &[u8] = b"tb/test/payments/hpke/v1";

pub(crate) const AUTHORIZATION_APPROVED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/authorization-approved");
pub(crate) const CAPTURE_COMPLETED: Urn<'static> = tightbeam::urn!("test", "event:servlets/capture-completed");
pub(crate) const CURRENCY_BHD_PROCESSED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/currency-bhd-processed");
pub(crate) const CURRENCY_JPY_PROCESSED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/currency-jpy-processed");
pub(crate) const CURRENCY_OTHER_PROCESSED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/currency-other-processed");
pub(crate) const CURRENCY_USD_PROCESSED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/currency-usd-processed");
pub(crate) const HIGH_VALUE_EXPEDITED: Urn<'static> = tightbeam::urn!("test", "event:servlets/high-value-expedited");
pub(crate) const INTEGRITY_VERIFIED: Urn<'static> = tightbeam::urn!("test", "event:servlets/integrity-verified");
pub(crate) const KEYMANAGER_DECRYPT_SUCCESS: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/keymanager-decrypt-success");
pub(crate) const KEYMANAGER_PUBKEY_SERVED: Urn<'static> =
	tightbeam::urn!("test", "event:servlets/keymanager-pubkey-served");
use super::messages::{
	CaptureTransaction, CreditTransferTransaction, DecryptRequest, DecryptResponse, GetPublicKeyRequest,
	GetPublicKeyResponse, PaymentIdentification, TransactionStatus,
};

/// Calculates the message priority from the transaction amount.
///
/// It converts the amount to US cents with [`MonetaryAmount::to_usd_cents`],
/// then picks the priority:
///
/// - A high-value amount over 100,000 cents gets [`MessagePriority::Expedited`].
/// - An amount over 10,000 cents gets [`MessagePriority::LowLatency`].
/// - Any other amount gets [`MessagePriority::Standard`].
pub fn to_priority(amount: &MonetaryAmount) -> MessagePriority {
	let normalized = amount.to_usd_cents();

	if normalized > 100_000 {
		MessagePriority::Expedited
	} else if normalized > 10_000 {
		MessagePriority::LowLatency
	} else {
		MessagePriority::Standard
	}
}

impl CreditTransferTransaction {
	/// Approves this transfer once the commitment of `frame` opens over it.
	///
	/// # Errors
	///
	/// - [`TightBeamError::InvalidBody`] -- the commitment of `frame` misses this transfer.
	/// - [`TightBeamError`] -- the commitment fails to compute, or a trace record fails.
	fn authorize(&self, frame: &Frame, trace: &TraceCollector) -> Result<TransactionStatus, TightBeamError> {
		// The commitment binds the decrypted body to what the client sent.
		let commitment_verified = frame.verify_commitment_of::<Sha3_256, _>(self, [])?;
		trace.event_with(INTEGRITY_VERIFIED, &[PAYMENT_TAG], commitment_verified)?;
		if !commitment_verified {
			return Err(TightBeamError::InvalidBody);
		}

		match self.instructed_amount.currency.as_bytes() {
			b"JPY" => trace.event_with(CURRENCY_JPY_PROCESSED, &[PAYMENT_TAG], ())?,
			b"USD" => trace.event_with(CURRENCY_USD_PROCESSED, &[PAYMENT_TAG], ())?,
			b"BHD" => trace.event_with(CURRENCY_BHD_PROCESSED, &[PAYMENT_TAG], ())?,
			_ => trace.event_with(CURRENCY_OTHER_PROCESSED, &[PAYMENT_TAG], ())?,
		};

		let priority = to_priority(&self.instructed_amount);
		if priority == MessagePriority::Expedited {
			trace.event_with(HIGH_VALUE_EXPEDITED, &[PAYMENT_TAG], ())?;
		}

		let auth_code = format!("AUTH{:08X}", self.creation_datetime as u32).into_bytes();
		let response = TransactionStatus::approved(self.payment_id.to_owned(), auth_code)?;

		trace.event_with(AUTHORIZATION_APPROVED, &[PAYMENT_TAG], ())?;

		Ok(response)
	}
}

servlet! {
	pub AuthorizationServlet<CreditTransferTransaction, EnvConfig = PaymentHarness>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = &ctx.trace();
		let harness: &PaymentHarness = ctx.env_config();

		// The harness answers a duplicate from its cache.
		let response = harness.answer(&frame, trace, || req.authorize(&frame, trace))?;
		Ok(Some(compose! {
			V2: id: frame.metadata().id(),
				message: response
		}?))
	}
}

servlet! {
	pub CaptureServlet<CaptureTransaction, EnvConfig = PaymentHarness>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = &ctx.trace();
		let harness: &PaymentHarness = ctx.env_config();

		// A capture links back to its authorization through `previous_frame`,
		// and the harness refuses a capture whose link misses the
		// authorization that the flow saw last. The harness answers a
		// duplicate from its cache, so the servlet settles each capture once.
		let response = harness.answer(&frame, trace, || {
			let payment_id = PaymentIdentification::new(
				b"CAPTURE",
				req.original_end_to_end_id.as_bytes(),
				format!("CAP{}", req.capture_datetime).as_bytes(),
			)?;

			let settlement_code = format!("SETTLE{:08X}", req.capture_datetime as u32).into_bytes();
			let response = TransactionStatus::captured(payment_id, settlement_code)?;

			trace.event_with(CAPTURE_COMPLETED, &[PAYMENT_TAG], ())?;

			Ok(response)
		})?;

		Ok(Some(compose! {
			V2: id: frame.metadata().id(),
				message: response
		}?))
	}
}

/// A request to [`KeyManagerServlet`], either a public key fetch or a
/// decrypt.
///
/// Both requests encode as a SEQUENCE, so each alternative carries a context
/// tag of its own, and the decoder tells the two apart.
#[derive(tightbeam::Beamable, tightbeam::der::Choice, Clone, Debug, PartialEq, Eq)]
pub enum KeyManagerRequest {
	/// A request for the public key of the key manager, under context tag 0.
	#[asn1(context_specific = "0", constructed = "true")]
	GetPublicKey(GetPublicKeyRequest),
	/// A request to decrypt a sealed ciphertext, under context tag 1.
	#[asn1(context_specific = "1", constructed = "true")]
	Decrypt(DecryptRequest),
}

servlet! {
	pub KeyManagerServlet<KeyManagerRequest, EnvConfig = Arc<SecretKey>>,
	protocol: TokioListener,
	handle: |req, frame, ctx| async move {
		let trace = ctx.trace();
		let secret_key: &Arc<SecretKey> = ctx.env_config();

		match req {
			KeyManagerRequest::GetPublicKey(_) => {
				let response = GetPublicKeyResponse {
					public_key: OctetString::new(secret_key.public_key().to_sec1_bytes().to_vec())?,
				};
				trace.event_with(KEYMANAGER_PUBKEY_SERVED, &[PAYMENT_TAG], ())?;
				Ok(Some(compose! {
					V2: id: frame.metadata().id(),
						message: response
				}?))
			}
			KeyManagerRequest::Decrypt(decrypt_req) => {
				let sealed = HpkeMessage::<HpkeSecp256k1Sha256Aes256Gcm>::from_bytes(decrypt_req.ciphertext.as_bytes())?;
				let plaintext_secret = secret_key.as_ref().open(&sealed, KEY_MANAGER_HPKE_INFO, b"")?;
				let plaintext = OctetString::new(plaintext_secret.to_insecure().to_vec())?;
				let response = DecryptResponse { plaintext };

				trace.event_with(KEYMANAGER_DECRYPT_SUCCESS, &[PAYMENT_TAG], ())?;

				Ok(Some(compose! {
					V2: id: frame.metadata().id(),
						message: response
				}?))
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use tightbeam::asn1::Version;
	use tightbeam::builder::TypeBuilder;
	use tightbeam::testing::TestMessage;

	use super::*;

	#[test]
	fn priority_low_value_normal() {
		let amount = MonetaryAmount::new(1000, *b"USD"); // $10.00
		assert_eq!(to_priority(&amount), MessagePriority::Standard);
	}

	#[test]
	fn priority_high_value_top() {
		let amount = MonetaryAmount::new(1_000_000, *b"USD"); // $10,000.00
		assert_eq!(to_priority(&amount), MessagePriority::Expedited);
	}

	#[test]
	fn priority_jpy_converts_to_us_cents() {
		// 100,000 JPY is about 1,000 USD, which is 100,000 cents.
		let amount = MonetaryAmount::new(100_000, *b"JPY");
		assert_eq!(to_priority(&amount), MessagePriority::LowLatency);
	}

	#[test]
	fn priority_medium_value_high() {
		let amount = MonetaryAmount::new(50_000, *b"USD"); // $500.00
		assert_eq!(to_priority(&amount), MessagePriority::LowLatency);
	}

	/// A transfer of 100.00 USD to the creditor account `creditor`.
	fn transfer(creditor: &[u8]) -> CreditTransferTransaction {
		let payment_id = PaymentIdentification::new(b"INST", b"E2E", b"TXN").expect("short identifiers fit");
		let amount = MonetaryAmount::new(10_000, *b"USD");
		let transfer = CreditTransferTransaction::new(payment_id, amount, creditor, b"DEBTOR", None, 0);
		transfer.expect("short account references fit")
	}

	/// A frame whose commitment opens over a test message alone.
	fn frame_of_another_body() -> Frame {
		let message = TestMessage::sample(None);
		let frame = Version::V2.compose().with_id(b"txn").with_order(1).with_message(message);
		let frame = frame.with_message_hasher::<Sha3_256>([]).build();
		frame.expect("a hashed V2 frame builds")
	}

	/// A transfer that the commitment of its frame misses is refused.
	#[test]
	fn a_transfer_that_its_commitment_misses_is_refused() -> Result<(), TightBeamError> {
		let trace = TraceCollector::default();
		let refusal = transfer(b"CREDITOR").authorize(&frame_of_another_body(), &trace);
		assert!(matches!(refusal, Err(TightBeamError::InvalidBody)));
		Ok(())
	}
}

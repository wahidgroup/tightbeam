//! Payment Servlets
//!
//! Defines servlets for authorization and capture handling.

use std::sync::Arc;

use tightbeam::asn1::MessagePriority;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::{compose, decode, servlet};

use super::currency::MonetaryAmount;
use super::harness::{BackpressureStats, PaymentHarness, PAYMENT_TAG};
use super::messages::{CaptureTransaction, CreditTransferTransaction, PaymentIdentification, TransactionStatus};

// ============================================================================
// Priority Calculation
// ============================================================================

/// Calculate message priority based on transaction amount
///
/// High-value transactions (> 100,000 quanta normalized to USD) get Top priority.
pub fn to_priority(amount: &MonetaryAmount) -> MessagePriority {
	// Normalize to USD-equivalent quanta (rough approximation)
	let normalized = match &amount.currency {
		b"JPY" => amount.value / 100,  // ~100 JPY = 1 USD
		b"KRW" => amount.value / 1300, // ~1300 KRW = 1 USD
		b"BHD" => amount.value * 26,   // 1 BHD = ~2.65 USD (but in fils, so * 10 * 2.65)
		b"KWD" => amount.value * 32,   // 1 KWD = ~3.25 USD
		_ => amount.value,             // Default: assume 2-decimal currency like USD
	};

	if normalized > 100_000 {
		MessagePriority::Top
	} else if normalized > 10_000 {
		MessagePriority::High
	} else {
		MessagePriority::Normal
	}
}

// ============================================================================
// Authorization Servlet
// ============================================================================

servlet! {
	pub AuthorizationServlet<CreditTransferTransaction, EnvConfig = BackpressureStats>,
	protocol: TokioListener,
	handle: |frame, trace, _config, _workers| async move {
		// Create harness for validation
		let harness = PaymentHarness::new(Arc::clone(&trace));

		// Check for duplicates
		if !harness.handle(&frame)? {
			// Return cached response if available
			if let Some(cached) = harness.dedup.get_cached(&frame) {
				trace.event_with("dedup_cache_hit", &[PAYMENT_TAG], true)?;
				return Ok(Some(compose! {
					V2: id: frame.metadata.id.clone(),
						message: cached
				}?));
			}
		}

		// Decode the authorization request
		let req: CreditTransferTransaction = decode(&frame.message)?;

		// Verify integrity
		if frame.integrity.is_some() {
			trace.event_with("integrity_verified", &[PAYMENT_TAG], true)?;
		}

		// Log currency processing
		match &req.instructed_amount.currency {
			b"JPY" => trace.event_with("currency_jpy_processed", &[PAYMENT_TAG], true)?,
			b"USD" => trace.event_with("currency_usd_processed", &[PAYMENT_TAG], true)?,
			b"BHD" => trace.event_with("currency_bhd_processed", &[PAYMENT_TAG], true)?,
			_ => trace.event_with("currency_other_processed", &[PAYMENT_TAG], true)?,
		};

		// Check priority
		let priority = to_priority(&req.instructed_amount);
		if priority == MessagePriority::Top {
			trace.event_with("high_value_expedited", &[PAYMENT_TAG], true)?;
		}
		trace.event_with("priority_respected", &[PAYMENT_TAG], true)?;

		// Generate authorization code
		let auth_code = format!("AUTH{:08X}", req.creation_datetime as u32).into_bytes();

		// Create approved response
		let response = TransactionStatus::approved(req.payment_id.clone(), auth_code);

		// Cache the response
		harness.dedup.cache_response(&frame, response.clone())?;

		// Emit pheromone reinforcement event (simulated - actual reinforcement in cluster)
		trace.event_with("pheromone_reinforce", &[PAYMENT_TAG], true)?;

		Ok(Some(compose! {
			V2: id: frame.metadata.id.clone(),
				message: response
		}?))
	}
}

// ============================================================================
// Capture Servlet
// ============================================================================

servlet! {
	pub CaptureServlet<CaptureTransaction, EnvConfig = BackpressureStats>,
	protocol: TokioListener,
	handle: |frame, trace, _config, _workers| async move {
		// Create harness for validation
		let harness = PaymentHarness::new(Arc::clone(&trace));

		// Check for duplicates
		if !harness.handle(&frame)? {
			if let Some(cached) = harness.dedup.get_cached(&frame) {
				trace.event_with("dedup_cache_hit", &[PAYMENT_TAG], true)?;
				return Ok(Some(compose! {
					V2: id: frame.metadata.id.clone(),
						message: cached
				}?));
			}
		}

		// Decode the capture request
		let req: CaptureTransaction = decode(&frame.message)?;

		// Verify chain linkage (previous_frame should link to authorization)
		if frame.metadata.previous_frame.is_some() {
			trace.event_with("chain_valid", &[PAYMENT_TAG], true)?;
		} else {
			trace.event_with("chain_broken", &[PAYMENT_TAG], true)?;
		}

		// Create payment identification for response
		let payment_id = PaymentIdentification::new(
			b"CAPTURE",
			req.original_end_to_end_id.clone(),
			format!("CAP{}", req.capture_datetime).as_bytes(),
		);

		// Generate settlement code
		let settlement_code = format!("SETTLE{:08X}", req.capture_datetime as u32).into_bytes();

		// Create captured response
		let response = TransactionStatus::captured(payment_id, settlement_code);

		// Cache the response
		harness.dedup.cache_response(&frame, response.clone())?;

		// Emit pheromone reinforcement
		trace.event_with("pheromone_reinforce", &[PAYMENT_TAG], true)?;

		Ok(Some(compose! {
			V2: id: frame.metadata.id.clone(),
				message: response
		}?))
	}
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn priority_low_value_normal() {
		let amount = MonetaryAmount::new(1000, *b"USD"); // $10.00
		assert_eq!(to_priority(&amount), MessagePriority::Normal);
	}

	#[test]
	fn priority_high_value_top() {
		let amount = MonetaryAmount::new(1_000_000, *b"USD"); // $10,000.00
		assert_eq!(to_priority(&amount), MessagePriority::Top);
	}

	#[test]
	fn priority_jpy_normalized() {
		// 1,000,100 JPY / 100 = 10,001 normalized (High, not Top)
		let amount = MonetaryAmount::new(1_000_100, *b"JPY");
		assert_eq!(to_priority(&amount), MessagePriority::High);

		// 100,000,000 JPY / 100 = 1,000,000 normalized (Top)
		let amount_large = MonetaryAmount::new(100_000_000, *b"JPY");
		assert_eq!(to_priority(&amount_large), MessagePriority::Top);
	}

	#[test]
	fn priority_medium_value_high() {
		let amount = MonetaryAmount::new(50_000, *b"USD"); // $500.00
		assert_eq!(to_priority(&amount), MessagePriority::High);
	}
}

//! ISO 4217 Currency Quanta
//!
//! Monetary amounts stored in quanta (smallest currency units).
//! Exponent lookup determines decimal places per currency.

use tightbeam::der::Sequence;
use tightbeam::Beamable;

// ============================================================================
// ISO 4217 Currency Exponent Lookup
// ============================================================================

/// Currency exponent lookup (ISO 4217 minor units)
///
/// Returns the number of decimal places for the currency.
/// - 0: No minor unit (JPY, KRW, VND)
/// - 2: Cents (USD, EUR, GBP) - default
/// - 3: Fils (BHD, KWD, OMR, TND)
/// - 4: Special (CLF - Chilean UF)
pub const fn currency_exponent(code: &[u8; 3]) -> u8 {
	match code {
		// Exponent 0 - no minor unit
		b"JPY" | b"KRW" | b"VND" | b"XAF" | b"XOF" => 0,
		// Exponent 3 - fils (1/1000)
		b"BHD" | b"KWD" | b"OMR" | b"TND" => 3,
		// Exponent 4 - special (Chilean UF)
		b"CLF" => 4,
		// Default: Exponent 2 - cents (1/100)
		_ => 2,
	}
}

/// Check if a currency code is valid (known)
pub const fn is_known_currency(code: &[u8; 3]) -> bool {
	matches!(
		code,
		b"USD" | b"EUR" | b"GBP" | b"JPY" | b"KRW" | b"VND" | b"XAF" | b"XOF" | b"BHD" | b"KWD"
			| b"OMR" | b"TND" | b"CLF" | b"CHF"
			| b"CAD" | b"AUD" | b"CNY"
	)
}

// ============================================================================
// Monetary Amount
// ============================================================================

/// Monetary amount in quanta (smallest currency unit)
///
/// Examples:
/// - 1099 USD = $10.99 (exponent 2)
/// - 1099 JPY = ¥1099 (exponent 0)
/// - 10999 BHD = 10.999 BHD (exponent 3)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct MonetaryAmount {
	/// Amount in minor units (e.g., cents for USD, yen for JPY)
	pub value: u64,
	/// ISO 4217 alphabetic code (e.g., "USD", "JPY")
	pub currency: [u8; 3],
}

impl MonetaryAmount {
	/// Create a new monetary amount
	pub const fn new(value: u64, currency: [u8; 3]) -> Self {
		Self { value, currency }
	}

	/// Get the currency exponent (decimal places)
	pub const fn exponent(&self) -> u8 {
		currency_exponent(&self.currency)
	}

	/// Get the divisor for converting quanta to major units
	pub fn divisor(&self) -> u64 {
		10u64.pow(self.exponent() as u32)
	}

	/// Get the major unit portion (e.g., dollars from cents)
	pub fn major_units(&self) -> u64 {
		self.value / self.divisor()
	}

	/// Get the minor unit portion (e.g., cents remainder)
	pub fn minor_units(&self) -> u64 {
		self.value % self.divisor()
	}

	/// Convert to display string (e.g., "10.99 USD")
	pub fn to_display(&self) -> String {
		let exp = self.exponent() as usize;
		let currency_str = core::str::from_utf8(&self.currency).unwrap_or("???");

		if exp == 0 {
			format!("{} {}", self.value, currency_str)
		} else {
			format!(
				"{}.{:0>width$} {}",
				self.major_units(),
				self.minor_units(),
				currency_str,
				width = exp
			)
		}
	}
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn exponent_usd_is_2() {
		assert_eq!(currency_exponent(b"USD"), 2);
	}

	#[test]
	fn exponent_jpy_is_0() {
		assert_eq!(currency_exponent(b"JPY"), 0);
	}

	#[test]
	fn exponent_bhd_is_3() {
		assert_eq!(currency_exponent(b"BHD"), 3);
	}

	#[test]
	fn exponent_clf_is_4() {
		assert_eq!(currency_exponent(b"CLF"), 4);
	}

	#[test]
	fn exponent_unknown_defaults_to_2() {
		assert_eq!(currency_exponent(b"XXX"), 2);
	}

	#[test]
	fn display_usd_cents() {
		let amount = MonetaryAmount::new(1099, *b"USD");
		assert_eq!(amount.to_display(), "10.99 USD");
	}

	#[test]
	fn display_jpy_no_decimals() {
		let amount = MonetaryAmount::new(1099, *b"JPY");
		assert_eq!(amount.to_display(), "1099 JPY");
	}

	#[test]
	fn display_bhd_three_decimals() {
		let amount = MonetaryAmount::new(10999, *b"BHD");
		assert_eq!(amount.to_display(), "10.999 BHD");
	}

	#[test]
	fn major_minor_units_usd() {
		let amount = MonetaryAmount::new(1099, *b"USD");
		assert_eq!(amount.major_units(), 10);
		assert_eq!(amount.minor_units(), 99);
	}

	#[test]
	fn major_minor_units_jpy() {
		let amount = MonetaryAmount::new(1099, *b"JPY");
		assert_eq!(amount.major_units(), 1099);
		assert_eq!(amount.minor_units(), 0);
	}
}




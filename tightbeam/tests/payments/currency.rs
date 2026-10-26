//! The ISO 4217 currency quanta of the payment tests.
//!
//! A monetary amount holds quanta, the smallest units of its currency, and
//! the exponent lookup gives the decimal places of each currency.

use tightbeam::der::asn1::OctetStringRef;
use tightbeam::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Sequence, Tag, Writer};
use tightbeam::Beamable;

// ISO 4217 currency exponent lookup

/// Returns the ISO 4217 minor-unit exponent of a currency.
///
/// The exponent is the number of decimal places of the currency:
/// - 0: no minor unit (JPY, KRW, VND, XAF, XOF)
/// - 2: cents (USD, EUR, GBP), the default
/// - 3: fils (BHD, KWD, OMR, TND)
/// - 4: special (CLF, the Chilean UF)
pub const fn currency_exponent(code: &[u8; 3]) -> u8 {
	match code {
		b"JPY" | b"KRW" | b"VND" | b"XAF" | b"XOF" => 0,
		b"BHD" | b"KWD" | b"OMR" | b"TND" => 3,
		b"CLF" => 4,
		_ => 2,
	}
}

/// Returns whether the table knows the currency code.
#[allow(dead_code)]
pub const fn is_known_currency(code: &[u8; 3]) -> bool {
	matches!(
		code,
		b"USD"
			| b"EUR" | b"GBP"
			| b"JPY" | b"KRW"
			| b"VND" | b"XAF"
			| b"XOF" | b"BHD"
			| b"KWD" | b"OMR"
			| b"TND" | b"CLF"
			| b"CHF" | b"CAD"
			| b"AUD" | b"CNY"
	)
}

// Currency code

/// An ISO 4217 alphabetic currency code, which encodes as an OCTET STRING of
/// three octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrencyCode([u8; 3]);

impl CurrencyCode {
	/// The currency whose alphabetic code is `code`.
	pub const fn new(code: [u8; 3]) -> Self {
		Self(code)
	}

	/// The three letters of the code.
	pub const fn as_bytes(&self) -> &[u8; 3] {
		&self.0
	}

	/// The rough value of one major unit in US dollars, as a numerator and a
	/// denominator. A currency outside the table counts at par with the
	/// dollar.
	const fn usd_rate(&self) -> (u64, u64) {
		match &self.0 {
			b"JPY" => (1, 100),
			b"KRW" => (1, 1300),
			b"BHD" => (265, 100),
			b"KWD" => (325, 100),
			_ => (1, 1),
		}
	}
}

impl FixedTag for CurrencyCode {
	const TAG: Tag = Tag::OctetString;
}

impl EncodeValue for CurrencyCode {
	fn value_len(&self) -> tightbeam::der::Result<Length> {
		Length::try_from(self.0.len())
	}

	fn encode_value(&self, writer: &mut impl Writer) -> tightbeam::der::Result<()> {
		writer.write(&self.0)
	}
}

impl<'a> DecodeValue<'a> for CurrencyCode {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> tightbeam::der::Result<Self> {
		let octets = OctetStringRef::decode_value(reader, header)?;
		let code = <[u8; 3]>::try_from(octets.as_bytes()).map_err(|_| Self::TAG.length_error())?;

		Ok(Self(code))
	}
}

// Monetary amount

/// A monetary amount in quanta, the smallest unit of its currency.
///
/// Examples:
/// - 1099 USD = $10.99 (exponent 2)
/// - 1099 JPY = ¥1099 (exponent 0)
/// - 10999 BHD = 10.999 BHD (exponent 3)
#[derive(Beamable, Sequence, Clone, Debug, PartialEq, Eq)]
pub struct MonetaryAmount {
	/// The amount in minor units, such as cents for USD and yen for JPY.
	pub value: u64,
	/// The ISO 4217 alphabetic code, such as "USD" or "JPY".
	pub currency: CurrencyCode,
}

impl MonetaryAmount {
	/// Creates a monetary amount.
	pub const fn new(value: u64, currency: [u8; 3]) -> Self {
		Self { value, currency: CurrencyCode::new(currency) }
	}

	/// Returns the currency exponent, the count of decimal places.
	pub const fn exponent(&self) -> u8 {
		currency_exponent(self.currency.as_bytes())
	}

	/// The value of the amount in US cents, at the rough rate of its currency
	/// and in the minor unit of its currency. A value past `u64::MAX` cents
	/// saturates.
	pub fn to_usd_cents(&self) -> u64 {
		let (numerator, denominator) = self.currency.usd_rate();
		let cents = u128::from(self.value) * 100 * u128::from(numerator);
		let minor_units = u128::from(denominator) * u128::from(self.divisor());

		u64::try_from(cents / minor_units).unwrap_or(u64::MAX)
	}

	/// Returns the divisor that converts quanta to major units.
	pub fn divisor(&self) -> u64 {
		10u64.pow(self.exponent() as u32)
	}

	/// Returns the major-unit part, such as the dollars of an amount in cents.
	pub fn major_units(&self) -> u64 {
		self.value / self.divisor()
	}

	/// Returns the minor-unit part, such as the cents that remain.
	pub fn minor_units(&self) -> u64 {
		self.value % self.divisor()
	}

	/// Returns the display string, such as "10.99 USD".
	pub fn to_display(&self) -> String {
		let exp = self.exponent() as usize;
		let currency_str = core::str::from_utf8(self.currency.as_bytes()).unwrap_or("???");

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

// Unit tests

#[cfg(test)]
mod tests {
	use tightbeam::der::Decode;
	use tightbeam::tb_cases;

	use super::*;

	// An amount converts to US cents at the rate of its currency, counted in
	// the minor unit of its currency.
	tb_cases! {
		fn an_amount_converts_to_us_cents((amount, cents): (MonetaryAmount, u64)) {
			assert_eq!(amount.to_usd_cents(), cents);
		}
		cases {
			dollars => (MonetaryAmount::new(1099, *b"USD"), 1099),
			euros_at_par => (MonetaryAmount::new(1099, *b"EUR"), 1099),
			yen => (MonetaryAmount::new(100_000, *b"JPY"), 100_000),
			won => (MonetaryAmount::new(13_000, *b"KRW"), 1_000),
			bahraini_fils => (MonetaryAmount::new(1_000, *b"BHD"), 265),
			kuwaiti_fils => (MonetaryAmount::new(1_000, *b"KWD"), 325),
		}
	}

	/// A currency code holds three octets, so a code of four fails to decode.
	#[test]
	fn a_currency_code_of_four_octets_is_refused() {
		let four_octets = [0x30, 0x09, 0x02, 0x01, 0x01, 0x04, 0x04, b'U', b'S', b'D', b'X'];

		let decoded = MonetaryAmount::from_der(&four_octets);

		assert!(decoded.is_err());
	}

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

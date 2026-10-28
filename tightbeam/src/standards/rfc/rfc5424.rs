#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::string::{String, ToString};

use crate::der::{DecodeValue, EncodeValue, FixedTag, Header, Length, Reader, Tag, Writer};
use crate::Errorizable;

/// The syslog severity, from 0 (Emergency) to 7 (Debug).
///
/// # Sources
///
/// - RFC 5424 § 6.2.1, the severity values: <https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1>
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(u8)]
pub enum SyslogSeverity {
	/// The system is unusable.
	Emergency = 0,
	/// An action must be taken immediately.
	Alert = 1,
	/// A critical condition.
	Critical = 2,
	/// An error condition.
	Error = 3,
	/// A warning condition.
	Warning = 4,
	/// A normal but significant condition.
	Notice = 5,
	/// An informational message.
	Informational = 6,
	/// A debug-level message.
	Debug = 7,
}

impl From<SyslogSeverity> for u8 {
	fn from(s: SyslogSeverity) -> Self {
		s as u8
	}
}

/// The severity whose number is `value`.
///
/// # Errors
///
/// - [`RFC5424Error::InvalidSeverityValue`] -- `value` is past 7, the number of `Debug`.
///
/// # Examples
///
/// ```
/// use tightbeam::standards::rfc5424::{RFC5424Error, SyslogSeverity};
///
/// assert_eq!(SyslogSeverity::try_from(6), Ok(SyslogSeverity::Informational));
/// assert_eq!(SyslogSeverity::try_from(8), Err(RFC5424Error::InvalidSeverityValue(8)));
/// ```
impl TryFrom<u8> for SyslogSeverity {
	type Error = RFC5424Error;

	fn try_from(value: u8) -> Result<Self, RFC5424Error> {
		match value {
			0 => Ok(Self::Emergency),
			1 => Ok(Self::Alert),
			2 => Ok(Self::Critical),
			3 => Ok(Self::Error),
			4 => Ok(Self::Warning),
			5 => Ok(Self::Notice),
			6 => Ok(Self::Informational),
			7 => Ok(Self::Debug),
			_ => Err(RFC5424Error::InvalidSeverityValue(value)),
		}
	}
}

// A severity encodes as an ENUMERATED of its number (X.690 § 8.4). The DER
// traits sit here by hand, so the numeric parse above is the one parse and
// returns the error of this module.
impl FixedTag for SyslogSeverity {
	const TAG: Tag = Tag::Enumerated;
}

impl EncodeValue for SyslogSeverity {
	fn value_len(&self) -> crate::der::Result<Length> {
		u8::from(*self).value_len()
	}

	fn encode_value(&self, encoder: &mut impl Writer) -> crate::der::Result<()> {
		u8::from(*self).encode_value(encoder)
	}
}

impl<'a> DecodeValue<'a> for SyslogSeverity {
	// A number past 7 is a value error of the ENUMERATED tag, which names the
	// DER that failed. The refusal of the parse carries the same number.
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> crate::der::Result<Self> {
		let value = u8::decode_value(reader, header)?;
		Self::try_from(value).map_err(|_refused| Tag::Enumerated.value_error())
	}
}

impl core::fmt::Display for SyslogSeverity {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		let s = match self {
			SyslogSeverity::Emergency => "EMERGENCY",
			SyslogSeverity::Alert => "ALERT",
			SyslogSeverity::Critical => "CRITICAL",
			SyslogSeverity::Error => "ERROR",
			SyslogSeverity::Warning => "WARNING",
			SyslogSeverity::Notice => "NOTICE",
			SyslogSeverity::Informational => "INFORMATIONAL",
			SyslogSeverity::Debug => "DEBUG",
		};
		f.write_str(s)
	}
}

/// The severity that `s` names. A name is in upper, title, or lower case, or
/// a short form such as `warn`. A number maps through [`TryFrom<u8>`], the one
/// table of the numbers.
///
/// # Errors
///
/// - [`RFC5424Error::InvalidSeverityValue`] -- `s` is a number from 8 to 255.
/// - [`RFC5424Error::InvalidSeverityName`] -- `s` is neither a name nor a number that `u8` parses.
///
/// # Examples
///
/// ```
/// use tightbeam::standards::rfc5424::{RFC5424Error, SyslogSeverity};
///
/// assert_eq!("warn".parse(), Ok(SyslogSeverity::Warning));
/// assert_eq!("6".parse(), Ok(SyslogSeverity::Informational));
/// assert_eq!("8".parse::<SyslogSeverity>(), Err(RFC5424Error::InvalidSeverityValue(8)));
/// ```
impl core::str::FromStr for SyslogSeverity {
	type Err = RFC5424Error;
	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			// Common names
			"EMERGENCY" | "Emergency" | "emergency" | "EMERG" | "emerg" => Ok(SyslogSeverity::Emergency),
			"ALERT" | "Alert" | "alert" => Ok(SyslogSeverity::Alert),
			"CRITICAL" | "Critical" | "critical" | "CRIT" | "crit" => Ok(SyslogSeverity::Critical),
			"ERROR" | "Error" | "error" | "ERR" | "err" => Ok(SyslogSeverity::Error),
			"WARNING" | "Warning" | "warning" | "WARN" | "warn" => Ok(SyslogSeverity::Warning),
			"NOTICE" | "Notice" | "notice" => Ok(SyslogSeverity::Notice),
			"INFORMATIONAL" | "Informational" | "informational" | "INFO" | "info" => Ok(SyslogSeverity::Informational),
			"DEBUG" | "Debug" | "debug" => Ok(SyslogSeverity::Debug),
			// A number maps through the numeric table of `TryFrom<u8>`.
			_ => {
				let number = s.parse::<u8>();
				let number = number.map_err(|_not_a_number| RFC5424Error::InvalidSeverityName(s.to_string()))?;
				Self::try_from(number)
			}
		}
	}
}

#[derive(Errorizable, Debug, Clone, PartialEq, Eq, Hash)]
pub enum RFC5424Error {
	#[error("invalid RFC5424 severity value: {0}")]
	InvalidSeverityValue(u8),
	#[error("invalid RFC5424 severity name: {0}")]
	InvalidSeverityName(String),
}

#[cfg(test)]
mod tests {
	use super::{RFC5424Error, SyslogSeverity};
	use crate::der::{Decode, Encode};

	#[test]
	fn a_severity_value_past_seven_is_refused() {
		assert_eq!(SyslogSeverity::try_from(8), Err(RFC5424Error::InvalidSeverityValue(8)));
	}

	/// A severity encodes as an ENUMERATED of its number, and decodes back.
	#[test]
	fn a_severity_survives_a_der_round_trip() -> Result<(), crate::der::Error> {
		let encoded = SyslogSeverity::Notice.to_der()?;

		let decoded = SyslogSeverity::from_der(&encoded)?;

		assert_eq!((encoded, decoded), (vec![0x0A, 0x01, 0x05], SyslogSeverity::Notice));
		Ok(())
	}

	/// A number names the severity of that number.
	#[test]
	fn a_number_parses_as_the_severity_of_that_number() {
		assert_eq!("6".parse::<SyslogSeverity>(), Ok(SyslogSeverity::Informational));
	}

	/// The parse of a number goes through the numeric table, so a number past
	/// 7 is refused as a value, as `TryFrom<u8>` refuses it.
	#[test]
	fn a_number_past_seven_is_refused_as_a_severity_value() {
		assert_eq!("8".parse::<SyslogSeverity>(), Err(RFC5424Error::InvalidSeverityValue(8)));
	}
}

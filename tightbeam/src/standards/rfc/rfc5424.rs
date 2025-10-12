use crate::der::Enumerated;

#[cfg(feature = "derive")]
use crate::Errorizable;

/// Syslog Severity (RFC 5424, Section 6.2.1)
/// See `<https://datatracker.ietf.org/doc/html/rfc5424#section-6.2.1>`
/// Values: 0 (Emergency) .. 7 (Debug)
#[derive(Enumerated, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(u8)]
pub enum SyslogSeverity {
	Emergency = 0,     // system is unusable
	Alert = 1,         // action must be taken immediately
	Critical = 2,      // critical conditions
	Error = 3,         // error conditions
	Warning = 4,       // warning conditions
	Notice = 5,        // normal but significant condition
	Informational = 6, // informational messages
	Debug = 7,         // debug-level messages
}

impl From<SyslogSeverity> for u8 {
	fn from(s: SyslogSeverity) -> Self {
		s as u8
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
			// Numeric strings
			"0" => Ok(SyslogSeverity::Emergency),
			"1" => Ok(SyslogSeverity::Alert),
			"2" => Ok(SyslogSeverity::Critical),
			"3" => Ok(SyslogSeverity::Error),
			"4" => Ok(SyslogSeverity::Warning),
			"5" => Ok(SyslogSeverity::Notice),
			"6" => Ok(SyslogSeverity::Informational),
			"7" => Ok(SyslogSeverity::Debug),
			_ => Err(RFC5424Error::InvalidSeverityName(s.to_string())),
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "derive", derive(Errorizable))]
pub enum RFC5424Error {
	#[cfg_attr(feature = "derive", error("invalid RFC5424 severity value: {0}"))]
	InvalidSeverityValue(u8),
	#[cfg_attr(feature = "derive", error("invalid RFC5424 severity name: {0}"))]
	InvalidSeverityName(String),
}

#[cfg(not(feature = "derive"))]
impl core::fmt::Display for RFC5424Error {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		match self {
			RFC5424Error::InvalidSeverityValue(v) => write!(f, "invalid RFC5424 severity value: {v}"),
			RFC5424Error::InvalidSeverityName(s) => write!(f, "invalid RFC5424 severity name: {s}"),
		}
	}
}

#[cfg(not(feature = "derive"))]
impl core::error::Error for RFC5424Error {}

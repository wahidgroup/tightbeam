#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "standards-rfc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RFCError {
	#[cfg(feature = "standards-rfc")]
	RFC5424Error(crate::standards::rfc::rfc5424::RFC5424Error),
}

#[cfg(feature = "standards-iso")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ISOError {
	Message(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
	RFC(RFCError),
	ISO(ISOError),
}

#[cfg(feature = "standards-rfc")]
crate::impl_from!(crate::standards::rfc::rfc5424::RFC5424Error => RFCError::RFC5424Error);
crate::impl_from!(RFCError => StandardError::RFC);
crate::impl_from!(ISOError => StandardError::ISO);

#[cfg(feature = "standards-rfc")]
crate::impl_error_display!(unconditional display RFCError {
	RFC5424Error(e) => "{e}",
});

#[cfg(feature = "standards-iso")]
crate::impl_error_display!(unconditional ISOError {
	Message(s) => "ISO error: {s}",
});

crate::impl_error_display!(unconditional display StandardError {
	RFC(e) => "{e}",
	ISO(e) => "{e}",
});

// `source()` delegates to the wrapped standard error, so a caller walking
// the chain reaches the RFC or ISO cause. The wrapped types implement
// `Error` only under `std`, matching the `Errorizable` derive this
// replaced.
#[cfg(all(feature = "std", feature = "standards-rfc"))]
impl core::error::Error for RFCError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			RFCError::RFC5424Error(err) => Some(err),
		}
	}
}

#[cfg(all(not(feature = "std"), feature = "standards-rfc"))]
impl core::error::Error for RFCError {}

#[cfg(feature = "std")]
impl core::error::Error for StandardError {
	fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
		match self {
			StandardError::RFC(err) => Some(err),
			StandardError::ISO(err) => Some(err),
		}
	}
}

#[cfg(not(feature = "std"))]
impl core::error::Error for StandardError {}

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "derive")]
use crate::Errorizable;

#[cfg(feature = "standards-rfc")]
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RFCError {
	#[cfg(feature = "standards-rfc")]
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	RFC5424Error(crate::standards::rfc::rfc5424::RFC5424Error),
}

#[cfg(feature = "standards-iso")]
#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ISOError {
	#[cfg_attr(feature = "derive", error("ISO error: {0}"))]
	Message(String),
}

#[cfg_attr(feature = "derive", derive(Errorizable))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	RFC(RFCError),
	#[cfg_attr(feature = "derive", error("{0}"))]
	#[cfg_attr(feature = "derive", from)]
	ISO(ISOError),
}

#[cfg(not(feature = "derive"))]
impl From<RFCError> for StandardError {
	fn from(e: RFCError) -> Self {
		StandardError::RFC(e)
	}
}

#[cfg(not(feature = "derive"))]
impl From<ISOError> for StandardError {
	fn from(e: ISOError) -> Self {
		StandardError::ISO(e)
	}
}

#[cfg(feature = "standards-rfc")]
crate::impl_error_display!(RFCError {
	RFC5424Error(e) => "{e}",
});

#[cfg(feature = "standards-iso")]
crate::impl_error_display!(ISOError {
	Message(s) => "ISO error: {s}",
});

crate::impl_error_display!(StandardError {
	RFC(e) => "{e}",
	ISO(e) => "{e}",
});

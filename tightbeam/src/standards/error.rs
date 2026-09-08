#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::Errorizable;

#[cfg(not(feature = "std"))]
use alloc::string::String;

#[cfg(feature = "standards-rfc")]
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum RFCError {
	#[cfg(feature = "standards-rfc")]
	#[error("{0}")]
	#[source]
	RFC5424Error(crate::standards::rfc::rfc5424::RFC5424Error),
}

#[cfg(feature = "standards-iso")]
#[derive(Errorizable, Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ISOError {
	#[error("ISO error: {0}")]
	Message(String),
}

#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
	#[error("{0}")]
	#[source]
	RFC(RFCError),
	#[error("{0}")]
	#[source]
	ISO(ISOError),
}

crate::impl_from!(RFCError => StandardError::RFC);
crate::impl_from!(ISOError => StandardError::ISO);

#[cfg(feature = "standards-rfc")]
crate::impl_from!(crate::standards::rfc::rfc5424::RFC5424Error => RFCError::RFC5424Error);

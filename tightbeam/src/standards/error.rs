#[cfg(not(feature = "std"))]
extern crate alloc;

use crate::Errorizable;

#[cfg(all(not(feature = "std"), feature = "standards-iso"))]
use alloc::string::String;

#[cfg(feature = "standards-rfc")]
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum RFCError {
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

/// A variant whose payload type is feature-gated carries the same gate, so the
/// enum has exactly the arms its build can construct.
#[derive(Errorizable, Debug, Clone, PartialEq, Eq)]
pub enum StandardError {
	#[cfg(feature = "standards-rfc")]
	#[error("{0}")]
	#[source]
	RFC(RFCError),

	#[cfg(feature = "standards-iso")]
	#[error("{0}")]
	#[source]
	ISO(ISOError),
}

#[cfg(feature = "standards-rfc")]
crate::impl_from!(RFCError => StandardError::RFC);
#[cfg(feature = "standards-iso")]
crate::impl_from!(ISOError => StandardError::ISO);

#[cfg(feature = "standards-rfc")]
crate::impl_from!(crate::standards::rfc::rfc5424::RFC5424Error => RFCError::RFC5424Error);

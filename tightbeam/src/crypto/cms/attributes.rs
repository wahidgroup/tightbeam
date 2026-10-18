//! The one lookup of an attribute in a CMS attribute set.

use crate::der::asn1::ObjectIdentifier;
use crate::x509::attr::{Attribute, Attributes};

/// Lookups in a set of CMS attributes (RFC 5652 §5.3, RFC 5083 §2.1).
pub trait AttributesExt {
	/// The one attribute of `oid` in this set, or `None` when the set carries
	/// none. Each reader names the error a repeated OID returns.
	///
	/// # Errors
	///
	/// - `duplicate` -- the set carries `oid` more than once.
	fn single<E>(&self, oid: ObjectIdentifier, duplicate: E) -> Result<Option<&Attribute>, E>;
}

impl AttributesExt for Attributes {
	fn single<E>(&self, oid: ObjectIdentifier, duplicate: E) -> Result<Option<&Attribute>, E> {
		let mut named = self.iter().filter(|attribute| attribute.oid == oid);
		let first = named.next();
		if named.next().is_some() {
			return Err(duplicate);
		}

		Ok(first)
	}
}

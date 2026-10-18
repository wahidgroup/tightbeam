//! The signed CMS structures the crate holds at its wire slots.

use core::ops::Deref;

use crate::der::{DecodeValue, EncodeValue, Header, Length, Reader, Sequence, Writer};

/// A CMS `SignerInfo` or `SignedData` (RFC 5652 §5) at a wire slot of the
/// crate.
///
/// The signer of `crypto::sign` builds every value the crate emits, and the
/// DER decoder yields every value it reads. The value reads as `T` and
/// encodes as `T`, and it is immutable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed<T>(T);

impl<T> Signed<T> {
	/// Wrap a structure the signer built. The seal is the signer's alone.
	#[cfg(feature = "signature")]
	pub(crate) fn new(inner: T, _seal: crate::crypto::sign::SignerSeal) -> Self {
		Self(inner)
	}

	/// Take the structure out of the wrapper.
	pub fn into_inner(self) -> T {
		self.0
	}
}

impl<T> Deref for Signed<T> {
	type Target = T;

	fn deref(&self) -> &T {
		&self.0
	}
}

impl<T> AsRef<T> for Signed<T> {
	fn as_ref(&self) -> &T {
		&self.0
	}
}

impl<T: EncodeValue> EncodeValue for Signed<T> {
	fn value_len(&self) -> crate::der::Result<Length> {
		self.0.value_len()
	}

	fn encode_value(&self, writer: &mut impl Writer) -> crate::der::Result<()> {
		self.0.encode_value(writer)
	}
}

impl<'a, T: DecodeValue<'a>> DecodeValue<'a> for Signed<T> {
	fn decode_value<R: Reader<'a>>(reader: &mut R, header: Header) -> crate::der::Result<Self> {
		T::decode_value(reader, header).map(Self)
	}
}

/// A `SignerInfo` and a `SignedData` are each a SEQUENCE, so the wrapper is
/// one, with that tag.
impl<'a, T: Sequence<'a>> Sequence<'a> for Signed<T> {}

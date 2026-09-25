pub mod error;
pub mod frame;
pub mod metadata;

pub use frame::FrameBuilder;
pub use metadata::MetadataBuilder;

#[cfg(feature = "aead")]
pub use frame::CheckAeadOid;
#[cfg(feature = "digest")]
pub use frame::CheckDigestOid;
#[cfg(feature = "signature")]
pub use frame::CheckSignatureOid;

/// A trait for building types with a builder pattern.
pub trait TypeBuilder<T> {
	type Error;

	fn build(self) -> Result<T, Self::Error>;
}

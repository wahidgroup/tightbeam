pub mod error;
pub mod frame;
pub mod metadata;

#[cfg(feature = "digest")]
pub use frame::CheckDigestOid;
#[cfg(feature = "aead")]
pub use frame::CheckAeadOid;
#[cfg(feature = "signature")]
pub use frame::CheckSignatureOid;
pub use frame::FrameBuilder;
pub use metadata::MetadataBuilder;

// Re-export private module for derive macro access
pub use frame::private;

/// A trait for building types with a builder pattern.
pub trait TypeBuilder<T> {
	type Error;

	fn build(self) -> Result<T, Self::Error>;
}

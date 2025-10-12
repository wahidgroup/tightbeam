pub mod error;
pub mod metadata;
pub mod frame;

pub use metadata::MetadataBuilder;
pub use frame::FrameBuilder;

/// A trait for building types with a builder pattern.
pub trait TypeBuilder<T> {
	type Error;

	fn build(self) -> Result<T, Self::Error>;
}

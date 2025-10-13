pub mod error;
pub mod frame;
pub mod metadata;

pub use frame::FrameBuilder;
pub use metadata::MetadataBuilder;

/// A trait for building types with a builder pattern.
pub trait TypeBuilder<T> {
	type Error;

	fn build(self) -> Result<T, Self::Error>;
}

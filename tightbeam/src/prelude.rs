//! Convenience imports for the everyday TightBeam surface.
//!
//! The module carries the frame types, the builder entry points, the
//! matrix types, and the crate error, so an application reaches the
//! common API through one `use`. The [`collect`] submodule carries the
//! receive side, and [`TightBeamSocketAddr`] rides along for the callers
//! that name an address.
//!
//! # Examples
//!
//! ```
//! use tightbeam::prelude::*;
//! ```

// Multi-threading support
#[cfg(feature = "std")]
pub use crate::mpsc;
// ASN.1/DER support
pub use der::{Decode, Encode, Sequence};

// Core types
pub use crate::asn1;
pub use crate::error;
pub use crate::flags;
pub use crate::flags::FlagSet;
pub use crate::matrix::{IntoMatrixDyn, Matrix, MatrixDyn, MatrixError, MatrixLike, MatrixResult};
pub use crate::utils;
pub use crate::TightBeamError;
pub use crate::{Frame, Message, Version};

#[cfg(feature = "builder")]
pub use crate::builder::{FrameBuilder, TypeBuilder};
#[cfg(feature = "builder")]
pub use crate::compose;
#[cfg(feature = "derive")]
pub use crate::Beamable;

#[cfg(feature = "tcp")]
pub use crate::transport::tcp::TightBeamSocketAddr;

/// Message collection and processing
pub mod collect {
	#[cfg(feature = "transport")]
	pub use crate::transport::MessageCollector;

	#[cfg(feature = "transport-policy")]
	pub use crate::transport::policy::{
		self, CollectorGateConfig, EmitterGateConfig, PolicyConfig, RestartConfig, TimeoutConfig,
	};

	#[cfg(feature = "tcp")]
	pub use crate::transport::tcp;

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	pub use crate::transport::tcp::r#async::TokioListener;

	#[cfg(feature = "tcp")]
	pub use crate::transport::tcp::sync::TcpListener;
}

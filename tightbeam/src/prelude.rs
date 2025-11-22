//! Prelude module for convenient imports
//!
//! This module re-exports commonly used types, traits, and macros from the
//! tightbeam crate, organized into two main categories:
//!
//! - `emit`: For creating and sending TightBeam messages
//! - `collect`: For receiving and processing TightBeam messages
//!
//! # Examples
//!
//! ```
//! use tightbeam::prelude::*;
//! ```

// Multi-threading support
#[cfg(any(feature = "std", feature = "tokio"))]
pub use crate::mpsc;
// ASN.1/DER support
pub use der::{Decode, Encode, Sequence};

// Core types
pub use crate::asn1;
pub use crate::error;
pub use crate::flags;
pub use crate::matrix::*;
pub use crate::tightbeam::flags::FlagSet;
pub use crate::utils;
pub use crate::TightBeamError;
pub use crate::{Frame, Message, Version};

// Derive macro
#[cfg(feature = "derive")]
pub use crate::Beamable;

// Builder support
#[cfg(feature = "builder")]
pub use crate::builder::FrameBuilder;

#[cfg(feature = "policy")]
pub mod policy {
	pub use crate::policy::*;

	#[cfg(feature = "transport-policy")]
	pub use crate::transport::policy::*;
}

#[cfg(feature = "tcp")]
pub use crate::transport::tcp::TightBeamSocketAddr;

// Macros
#[cfg(feature = "derive")]
pub mod tb {
	pub use crate::flagset;

	#[cfg(feature = "transport")]
	pub use crate::{client, server};
	#[cfg(feature = "compress")]
	pub use crate::{compress, decompress};
	#[cfg(feature = "std")]
	pub use crate::{mutex, rwlock};
	#[cfg(feature = "signature")]
	pub use crate::{notarize, sign};

	pub use crate::asn1::MessagePriority;
	pub use crate::asn1::Version;
}

/// Message emission and creation
pub mod emit {
	#[cfg(feature = "builder")]
	pub use crate::builder::FrameBuilder;
}

/// Message collection and processing
pub mod collect {
	#[cfg(feature = "transport")]
	pub use crate::transport::{MessageCollector, ResponseHandler};

	#[cfg(feature = "transport-policy")]
	pub use crate::transport::policy::{self, PolicyConf};

	#[cfg(feature = "tcp")]
	pub use crate::transport::tcp;

	#[cfg(all(feature = "tcp", feature = "tokio"))]
	pub use crate::transport::tcp::r#async::TokioListener;

	#[cfg(feature = "tcp")]
	pub use crate::transport::tcp::sync::TcpListener;
}

// Crypto module re-exports
#[cfg(feature = "crypto")]
pub mod crypto {
	#[cfg(feature = "aead")]
	pub use crate::crypto::aead;

	#[cfg(feature = "digest")]
	pub use crate::crypto::hash;

	#[cfg(feature = "signature")]
	pub use crate::crypto::sign;

	#[cfg(all(feature = "signature", feature = "secp256k1"))]
	pub use crate::crypto::sign::ecdsa::schnorr;

	#[cfg(feature = "aead")]
	pub use crate::crypto::common;
}

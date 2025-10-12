//! # TightBeam Protocol
//!
//! A lightweight, versioned messaging protocol with cryptographic primitives
//! built on ASN.1 DER encoding.
//!
//! ## Security Model
//!
//! ### Cryptographic Operations Order (Sign-Then-Encrypt)
//!
//! 1. **Hash** - Computed on plaintext message for integrity verification
//! 2. **Sign** - Computed on entire payload and appended
//! 3. **Encrypt** - Applied to plaintext message, producing ciphertext
//!
//! ## Compression
//!
//! Optional compression can be applied to the plaintext message before hashing
//! and signing.
//!
//! This follows the **sign-then-encrypt** pattern which provides:
//! - Non-repudiation: Signature proves who created the original message
//! - Authentication: Verifiable without requiring decryption keys
//! - Confidentiality: Only encrypted content is transmitted
//!
//! ## Protocol Versions
//!
//! - **V0**: Basic metadata (id, order, hash, optional compression)
//! - **V1**: Secure messaging (adds encryption + signature requirements)
//! - **V2**: Extended features (adds priority, TTL, headers, message chaining)
//!
//! ## Quick Start
//!
//! ```rust
//! use tightbeam::{Message, Beamable};
//! use tightbeam::compose;
//!
//! #[derive(Beamable, Clone, Debug, PartialEq, der::Sequence)]
//! struct MyMessage { value: u64 }
//!
//! let message = MyMessage { value: 42 };
//!
//! // Build basic V0 message
//! let tightbeam = compose! {
//!     V0:
//!         id: "demo-001",
//!         order: 1696521600,
//!         message: message
//! }?;
//!
//! // Decode the message
//! let decoded: MyMessage = tightbeam::decode(&tightbeam.message)?;
//! assert_eq!(decoded.value, 42);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// TODO Find a way
#![allow(macro_expanded_macro_exports_accessed_by_absolute_paths)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

pub mod asn1;
pub mod core;
pub mod error;
pub mod flags;
pub mod helpers;
pub mod prelude;
pub mod utils;

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "constants")]
pub mod constants;
#[cfg(feature = "crypto")]
pub mod crypto;
#[cfg(feature = "builder")]
pub mod macros;
#[cfg(feature = "random")]
pub mod random;
#[cfg(feature = "standards")]
pub mod standards;
#[cfg(feature = "transport")]
pub mod transport;
#[cfg(feature = "router")]
pub mod router;
#[cfg(feature = "policy")]
pub mod policy;
#[cfg(feature = "doc")]
pub mod doc;
#[cfg(feature = "servlets")]
pub mod servlets;


// Re-export
pub use asn1::*;
pub use der;
pub use spki;

#[cfg(feature = "hex")]
pub use hex_literal::hex;
#[cfg(feature = "time")]
pub use time;
#[cfg(feature = "tokio")]
pub use tokio::sync::mpsc;
#[cfg(all(feature = "std", not(feature = "tokio")))]
pub use std::sync::mpsc;

pub use utils::{decode, encode};

#[cfg(feature = "derive")]
pub use tightbeam_derive::{Beamable, Flaggable, Errorizable};

extern crate self as tightbeam;

pub use crate::core::*;
pub use crate::error::TightBeamError;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(feature = "builder")]
tightbeam_derive::generate_builders!();

// TODO relay! { TightBeam, Router }

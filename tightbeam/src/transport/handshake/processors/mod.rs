//! Message processors for received CMS structures.
//!
//! This module provides processors for extracting keys and data from
//! received CMS messages in the TightBeam handshake protocol.

pub mod kari;
pub use kari::TightBeamKariRecipient;

#[cfg(all(feature = "builder", feature = "aead"))]
pub mod enveloped_data;
#[cfg(all(feature = "builder", feature = "aead"))]
pub use enveloped_data::{AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor};

#[cfg(feature = "signature")]
pub mod signed_data;
#[cfg(feature = "signature")]
pub use signed_data::TightBeamSignedDataProcessor;

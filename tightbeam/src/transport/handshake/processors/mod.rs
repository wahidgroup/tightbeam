//! Message processors for received CMS structures.
//!
//! This module provides processors for extracting keys and data from
//! received CMS messages in the TightBeam handshake protocol.

pub mod kari;
pub use kari::TightBeamKariRecipient;

pub mod enveloped_data;
pub use enveloped_data::{AesGcmContentDecryptor, TightBeamEnvelopedDataProcessor};

pub mod signed_data;
pub use signed_data::TightBeamSignedDataProcessor;

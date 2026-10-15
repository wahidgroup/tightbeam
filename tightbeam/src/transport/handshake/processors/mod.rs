//! Message processors for received CMS structures.
//!
//! This module provides processors for extracting keys and data from
//! received CMS messages in the TightBeam handshake protocol.

mod kari;
pub use kari::TightBeamKariRecipient;

mod enveloped_data;
pub use enveloped_data::{RecipientProcessor, TightBeamEnvelopedDataProcessor};

mod signed_data;
pub use signed_data::TightBeamSignedDataProcessor;

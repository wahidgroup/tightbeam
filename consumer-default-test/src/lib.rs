//! Compile probe for the `tightbeam` default feature set.

use tightbeam::builder::MetadataBuilder;
use tightbeam::{Frame, TightBeamError};

/// Names one ungated root item and one the `builder` feature carries, so a
/// default build is shown to expose them rather than merely to compile.
pub type DefaultDecode = Result<Frame, TightBeamError>;

/// Names the builder a default build reaches.
pub type DefaultMetadataBuilder = MetadataBuilder;

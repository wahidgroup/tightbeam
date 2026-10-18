#![allow(unused_imports)]

// ERROR: each item of a nested transport module has one public path, at the
// parent of its module, so a path through the module itself is private.
use tightbeam::transport::builders::envelope::EnvelopeBuilder;
use tightbeam::transport::client::builder::ClientBuilder;
use tightbeam::transport::client::pool::ConnectionPool;
use tightbeam::transport::handshake::primitives::kdf::KdfSalt;
use tightbeam::transport::handshake::primitives::transcript::transcript_hash;

// The parent paths resolve, including the four items the parents re-export.
use tightbeam::transport::client::{ConnectionPoolBuilder, DynGate, DynRestart};
use tightbeam::transport::handshake::primitives::TranscriptHash;

fn main() {}

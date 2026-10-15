#![allow(unused_imports)]

// ERROR: each item of a nested transport module has one public path, at the
// parent of its module, so a path through the module itself is private.
use tightbeam::transport::builders::envelope::EnvelopeBuilder;
use tightbeam::transport::client::builder::ClientBuilder;
use tightbeam::transport::client::pool::ConnectionPool;
use tightbeam::transport::handshake::builders::enveloped_data::TightBeamEnvelopedDataBuilder;
use tightbeam::transport::handshake::builders::error::KariBuilderError;
use tightbeam::transport::handshake::builders::kari::TightBeamKariBuilder;
use tightbeam::transport::handshake::builders::signed_data::TightBeamSignedDataBuilder;
use tightbeam::transport::handshake::primitives::kdf::KdfSalt;
use tightbeam::transport::handshake::primitives::transcript::transcript_hash;
use tightbeam::transport::handshake::processors::enveloped_data::TightBeamEnvelopedDataProcessor;
use tightbeam::transport::handshake::processors::kari::TightBeamKariRecipient;
use tightbeam::transport::handshake::processors::signed_data::TightBeamSignedDataProcessor;

// The parent paths resolve, including the five items the parents re-export.
use tightbeam::transport::client::{ConnectionPoolBuilder, DynGate, DynRestart};
use tightbeam::transport::handshake::primitives::TRANSCRIPT_HASH_LEN;
use tightbeam::transport::handshake::processors::RecipientProcessor;

fn main() {}

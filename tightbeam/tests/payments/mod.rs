//! Payment Processing Gateway Integration Tests
//!
//! Real-world scenarios that run these TightBeam features in a payment flow:
//! - Integrity verification (Sha3_256 hashing)
//! - Non-repudiation (SignerInfo signatures that a collector gate verifies)
//! - DAG transaction chains (previous_frame linking)
//! - TLS mutual authentication on the control plane of a hive
//!
//! Idempotence sits in the dedup book of the harness, over the ID and the
//! order of a frame.
//!
//! Message types follow ISO 20022 pacs.008 structure.
//! Monetary amounts use ISO 4217 currency quanta.

#![cfg(feature = "testing")]

pub mod cluster;
pub mod currency;
pub mod harness;
pub mod hives;
pub mod messages;
mod scenarios;
pub mod servlets;

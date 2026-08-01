//! Integration tests for Cluster environment
//!
//! Tests the Cluster lifecycle with hive registration and work routing.

#![cfg(all(
	feature = "std",
	feature = "tokio",
	feature = "testing",
	feature = "testing-csp",
	feature = "x509",
	feature = "secp256k1",
	feature = "signature"
))]

mod common;
mod events;
mod federation;
mod gossip;
mod organizations;
mod peering;
mod registration;
mod routing;
mod streaming;
mod topology;

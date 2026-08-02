//! Integration tests for the colony cluster environment.
//!
//! These scenarios exercise hive registration, work routing, peering,
//! federation, gossip, streaming, and the servlet export boundary. Each
//! submodule owns one concern and shares fixtures through [common].
//!
//! # Modules
//!
//! - [`exports`]: servlet export boundary (discoverability and enforcement)
//! - [`federation`], [`peering`], [`gossip`]: peer federation and soft state
//! - [`registration`], [`routing`], [`topology`]: hive lifecycle and trails
//! - [`streaming`]: routed stream and duplex opens
//! - [`organizations`]: multi-org trust layouts

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
mod exports;
mod federation;
mod gossip;
mod organizations;
mod peering;
mod registration;
mod routing;
mod streaming;
mod topology;

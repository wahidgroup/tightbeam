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
//! - [`flood`]: the gossip flood across colonies, and the subnets partial trust makes
//! - [`registration`], [`routing`], [`topology`]: hive lifecycle and trails
//! - [`streaming`]: routed stream and duplex opens
//! - [`organizations`]: multi-org trust layouts

#![cfg(feature = "testing-csp")]

mod common;
mod events;
mod exports;
mod federation;
mod flood;
mod gossip;
mod organizations;
mod peering;
mod registration;
mod routing;
mod streaming;
mod topology;

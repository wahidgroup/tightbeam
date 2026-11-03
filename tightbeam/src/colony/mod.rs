//! The colony framework runs servlets across a distributed system.
//!
//! The framework has four parts:
//!
//! - **Workers**: The base processing units, which receive messages and produce responses
//! - **Servlets**: Self-contained, policy-driven message processing applications
//! - **Hives**: Orchestrators that manage one or more servlet instances
//! - **Clusters**: Gateways that route work requests to registered hives
//!
//! # Module Organization
//!
//! Every module but [`work`] needs the `colony` feature:
//!
//! - `protocol`: Protocol messages of the colony control and work planes
//! - [`work`]: Wire messages of the work plane, which compile on every target with `std`
//! - `urn`: Colony resource URNs and the namespace that creates and validates them
//! - `worker`: Worker trait and runtime abstractions
//! - `servlet`: Servlet trait and configuration builders
//! - `hive`: Hive trait, configuration, and security gates
//! - `cluster`: Cluster trait, registry, and configuration
//! - `client`: Client-side work submission against a cluster gateway

#[cfg(feature = "colony")]
pub(crate) mod bound_dial;
#[cfg(feature = "colony")]
pub mod client;
#[cfg(feature = "colony")]
pub mod cluster;
#[cfg(feature = "colony")]
pub mod hive;
#[cfg(feature = "colony")]
pub mod protocol;
#[cfg(feature = "colony")]
pub mod servlet;
#[cfg(feature = "colony")]
pub mod urn;
pub mod work;
#[cfg(feature = "colony")]
pub mod worker;

#[cfg(feature = "colony")]
pub use client::SubmitWork;

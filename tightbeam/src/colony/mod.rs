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
//! - [`protocol`]: Protocol messages of the colony control and work planes
//! - [`urn`]: Colony resource URNs and the namespace that creates and validates them
//! - [`worker`]: Worker trait and runtime abstractions
//! - [`servlet`]: Servlet trait and configuration builders
//! - [`hive`]: Hive trait, configuration, and security gates
//! - [`cluster`]: Cluster trait, registry, and configuration
//! - [`client`]: Client-side work submission against a cluster gateway

pub(crate) mod bound_dial;
pub mod client;
pub mod cluster;
pub mod hive;
pub mod protocol;
pub mod servlet;
mod task_group;
pub mod urn;
pub mod worker;

pub use client::SubmitWork;
pub(crate) use task_group::TaskGroup;

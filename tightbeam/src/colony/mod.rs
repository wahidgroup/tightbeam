//! Colony framework for distributed servlet orchestration.
//!
//! A distributed message processing system has four parts:
//!
//! - **Workers**: The base processing units, which receive messages and produce responses
//! - **Servlets**: Self-contained, policy-driven message processing applications
//! - **Hives**: Orchestrators that manage one or more servlet instances
//! - **Clusters**: Gateways that route work requests to registered hives
//!
//! # Module Organization
//!
//! - [`common`]: Shared types such as load balancers, message routers, and protocol messages
//! - [`worker`]: Worker trait and runtime abstractions
//! - [`servlet`]: Servlet trait and configuration builders
//! - [`hive`]: Hive trait, configuration, and security gates
//! - [`cluster`]: Cluster trait, registry, and configuration
//! - [`client`]: Client-side work submission against a cluster gateway

pub(crate) mod bound_dial;
pub mod client;
pub mod cluster;
pub mod common;
pub mod hive;
pub mod servlet;
pub mod worker;

pub use client::SubmitWork;

//! Colony framework for distributed servlet orchestration
//!
//! This module provides the building blocks for creating distributed message
//! processing systems:
//!
//! - **Workers**: Fundamental processing units that receive messages and produce responses
//! - **Servlets**: Self-contained, policy-driven message processing applications
//! - **Hives**: Orchestrators that manage servlet instances (single or multiple)
//! - **Clusters**: Gateways that route work requests to registered hives
//!
//! # Module Organization
//!
//! - [`common`]: Shared types like load balancers, message routers, and protocol messages
//! - [`worker`]: Worker trait and runtime abstractions
//! - [`servlet`]: Servlet trait and configuration builders
//! - [`hive`]: Hive trait, configuration, and security gates
//! - [`cluster`]: Cluster trait, registry, and configuration

pub mod cluster;
pub mod common;
pub mod hive;
pub mod servlet;
pub mod worker;

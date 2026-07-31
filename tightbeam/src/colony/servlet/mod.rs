//! Servlet framework: policy-gated accept loops that dispatch unary,
//! streaming, and duplex handlers with shared workers and env config.
//!
//! # Macro-free path
//!
//! 1. Build handlers with [`ServletHandlers`] (or implement [`ServletService`]).
//! 2. Call [`ServletRuntime::start`] with a [`ServletConfig`].
//! 3. For call sites that need [`Servlet`], pass [`RuntimeServletConf`]
//!    (config + handlers) into [`Servlet::start`] on [`ServletRuntime`].
//!
//! Typed unary delivery without `servlet!`:
//! [`ServletHandlers::on_typed_unary`] or [`dispatch_typed_unary`].

mod config;
mod context;
mod serve;
mod service;

pub mod macros;
pub mod runtime;
pub mod tracking;

pub use config::{ServletConfig, ServletConfigBuilder};
pub use context::{dispatch_typed_unary, prepare_typed_frame, ServletContext, WorkerBox, WorkerBoxStartFuture};
pub use runtime::ServletRuntime;
pub use serve::serve_servlet;
pub use service::{RuntimeServletConf, Servlet, ServletFuture, ServletHandlers, ServletService};
pub use tracking::{LatencyTracker, ServletMetrics, UtilizationReporter};

/// Runtime task primitives used by servlet accept loops.
pub mod servlet_runtime {
	pub use crate::runtime::rt;
}

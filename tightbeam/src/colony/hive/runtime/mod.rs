//! Hive runtime: context, control, scaling, and cluster client helpers.
//!
//! - [`HiveContextImpl`] owns intra-hive routing and the servlet pool.
//! - [`HiveRuntime`] implements [`crate::colony::hive::Hive`].
//! - `hive!` names a type alias of [`HiveRuntime`].

mod cluster_client;
mod context;
mod control;
mod instances;
mod lifecycle;
mod scaling;

pub(crate) use cluster_client::ClusterLink;
pub use context::HiveContextImpl;
pub(crate) use control::HiveControlCtx;
pub(crate) use instances::HiveInstances;
pub use lifecycle::HiveRuntime;
pub(crate) use scaling::ScalingLoop;

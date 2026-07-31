//! Hive runtime: context, control, scaling, and cluster client helpers.
//!
//! - [`HiveContextImpl`] owns intra-hive routing and the servlet pool.
//! - [`HiveRuntime`] implements [`crate::colony::hive::Hive`].
//! - `hive!` names a type alias of [`HiveRuntime`].

mod cluster_client;
mod context;
mod control;
mod instances;
mod runtime;
mod scaling;

pub use cluster_client::{build_control_frame, notify_cluster, register_once, spawn_reregister_task};
pub use context::HiveContextImpl;
pub use control::{handle_command, handle_manage, spawn_control_server, HiveControlCtx};
pub use instances::{insert_instance, instance_urn, remove_instance, servlet_slate};
pub use runtime::HiveRuntime;
pub use scaling::spawn_scaling_task;

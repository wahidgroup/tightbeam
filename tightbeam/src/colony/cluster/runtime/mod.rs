//! Cluster gateway runtime: accept loop, dispatch, heartbeat, and gossip tasks.
//!
//! - [`ClusterGateway`] owns lifecycle and trait impls.
//! - Request handling splits across registration, work, and gossip modules.
//! - `cluster!` names a type alias of [`ClusterGateway`].

mod bounds;
mod dispatch;
mod gateway;
mod gossip_handler;
mod gossip_tasks;
mod heartbeat;
mod refuse;
mod registration;
mod streaming;
mod verify;
mod work;

pub use gateway::ClusterGateway;
pub use gossip_tasks::{build_advertise_task, peer_dial_pool};
pub use heartbeat::{parse_hive_addr, process_heartbeat_result, send_heartbeat_async};

pub mod client;

#[cfg(feature = "builder")]
pub mod builder;
#[cfg(feature = "derive")]
pub mod macros;
#[cfg(feature = "std")]
pub mod pool;

pub use client::GenericClient;

#[cfg(feature = "builder")]
pub use builder::{ClientBuilder, ClientPolicies};
#[cfg(feature = "std")]
pub use pool::{ConnectionBuilder, ConnectionPool, PoolConfig, PooledClient};

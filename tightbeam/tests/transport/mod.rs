//! The integration tests of the transport layer.

mod cms_socket;
mod cms_toolkit;
mod connection_pool;
mod connection_reuse;
mod key_purposes;
mod loopback;
mod multiplex;
mod mutual_auth;
mod negotiation;
mod paywall;
mod pool_mux;
mod receipt;
mod split;

#[cfg(all(
	feature = "transport-hpke",
	feature = "tcp",
	feature = "tokio",
	feature = "testing"
))]
mod fixtures;
#[cfg(feature = "hex")]
mod static_pair;

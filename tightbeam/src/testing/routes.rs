//! Routed stream opens for fuzz harnesses.
//!
//! This module compiles when the `testing-fuzz` and `colony` features
//! are both enabled, and the default `full` feature enables both. The
//! surface is therefore present in default builds, but it is not a
//! supported API: fuzz harnesses are the only intended consumer. Every
//! entry point delegates to a `pub(crate)` inherent item under its
//! exact inherent name, so call sites grep identically across harness
//! and production.

use core::future::Future;
use core::hash::Hash;

use crate::crypto::profiles::CryptoProvider;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxConnector, RequestSink, StreamBody, StreamRoute};
use crate::transport::policy::PolicyConfig;
use crate::transport::{PersistentConnection, PooledClient, Protocol, TransportResult, X509ClientConfig};
use crate::utils::marker::MaybeSend;
use crate::utils::urn::Urn;
use crate::Frame;

/// Build a relayed [`StreamRoute`] for harness opens that must spend hop
/// budget before the first gateway.
///
/// The origin sentinel is excluded by construction: hop budget is clamped
/// below the origin open budget.
pub fn relayed_to(target: Urn<'static>, hops_remaining: u8) -> StreamRoute {
	StreamRoute::relayed_to(target, hops_remaining)
}

/// Harness-facing stream opens on [`PooledClient`] that carry a fully
/// formed [`StreamRoute`].
///
/// The harness depends on these two entry points and nothing else of
/// [`PooledClient`] for routed streaming.
pub trait RoutedOpens {
	/// Open a streamed request carrying a fully-formed [`StreamRoute`].
	///
	/// Delegates to the inherent `PooledClient::open_stream_with_route`.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`](crate::transport::TransportError::InvalidState):
	///   the lease is exclusive, so streaming needs a multiplexed connection.
	fn open_stream_with_route(
		&self,
		route: StreamRoute,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)>;

	/// Open a duplex stream carrying a fully-formed [`StreamRoute`].
	///
	/// Delegates to the inherent `PooledClient::open_duplex_with_route`.
	///
	/// # Errors
	///
	/// - [`TransportError::InvalidState`](crate::transport::TransportError::InvalidState):
	///   the lease is exclusive, so streaming needs a multiplexed connection.
	fn open_duplex_with_route(&self, route: StreamRoute) -> TransportResult<(RequestSink, StreamBody)>;
}

impl<P, C> RoutedOpens for PooledClient<P, C>
where
	P: Protocol + PersistentConnection + Send + Sync,
	C: CryptoProvider + Send + Sync + 'static,
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter
		+ MessageCollector
		+ PolicyConfig
		+ X509ClientConfig<CryptoProvider = C>
		+ MuxConnector
		+ Send
		+ Sync,
{
	fn open_stream_with_route(
		&self,
		route: StreamRoute,
	) -> TransportResult<(RequestSink, impl Future<Output = TransportResult<Option<Frame>>> + MaybeSend)> {
		PooledClient::open_stream_with_route(self, route)
	}

	fn open_duplex_with_route(&self, route: StreamRoute) -> TransportResult<(RequestSink, StreamBody)> {
		PooledClient::open_duplex_with_route(self, route)
	}
}

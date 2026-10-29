//! Routed stream opens for fuzz harnesses.
//!
//! The module exists under the `testing-fuzz` and `colony` features. Fuzz
//! harnesses are its one consumer, and it is no supported API. Each entry
//! point delegates to the `pub(crate)` inherent item of the same name, so a
//! search for the name finds the harness call and the production call.

use core::future::Future;
use core::hash::Hash;

use crate::marker::MaybeSend;
use crate::transport::messaging::{MessageCollector, MessageEmitter};
use crate::transport::multiplex::{MuxConnector, RequestSink, StreamBody, StreamRoute};
use crate::transport::policy::PolicyConfig;
use crate::transport::{PersistentConnection, PooledClient, Protocol, TransportResult};
use crate::Frame;

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

impl<P> RoutedOpens for PooledClient<P>
where
	P: Protocol + PersistentConnection + Send + Sync,
	P::Address: Hash + Eq + Clone + Send + Sync,
	P::Transport: MessageEmitter + MessageCollector + PolicyConfig + MuxConnector + Send + Sync,
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

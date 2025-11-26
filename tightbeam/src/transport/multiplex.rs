//! TODO Multiplexing support for concurrent requests on a single connection
//!
//! This module provides stub interfaces for HTTP/2-style multiplexing.

#![cfg(feature = "transport-multiplex")]

use core::future::Future;

use crate::transport::error::TransportError;
use crate::transport::protocols::Protocol;
use crate::transport::TransportResult;
use crate::Frame;

/// Stream identifier for multiplexed protocols
///
/// Uniquely identifies a logical stream within a single physical connection.
/// Similar to HTTP/2 stream IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StreamId(pub u32);

impl StreamId {
	/// Create a new stream ID
	pub const fn new(id: u32) -> Self {
		Self(id)
	}

	/// Get the underlying ID value
	pub const fn value(&self) -> u32 {
		self.0
	}

	/// Check if this is a client-initiated stream (odd ID)
	pub const fn is_client_initiated(&self) -> bool {
		self.0 % 2 == 1
	}

	/// Check if this is a server-initiated stream (even ID)
	pub const fn is_server_initiated(&self) -> bool {
		self.0 % 2 == 0
	}
}

/// Multiplexed frame with stream correlation
///
/// Wraps a TightBeam frame with stream metadata for concurrent
/// request/response handling on a single connection.
#[derive(Debug, Clone)]
pub struct MultiplexedFrame {
	/// Stream ID for correlation
	pub stream_id: StreamId,
	/// The actual TightBeam frame
	pub frame: Frame,
}

/// Protocol multiplexing (multiple concurrent requests on one connection)
///
/// Implementations provide HTTP/2-style stream multiplexing over a single
/// physical connection, enabling concurrent request/response pairs without
/// head-of-line blocking.
pub trait MultiplexedProtocol: Protocol {
	/// Maximum number of concurrent streams allowed
	///
	/// Similar to HTTP/2 SETTINGS_MAX_CONCURRENT_STREAMS.
	/// Returns 0 for unlimited (not recommended).
	fn max_concurrent_streams() -> u32;

	/// Send frame on a specific stream
	///
	/// If the stream does not exist, it is implicitly created.
	/// Returns the response frame (if any) for this stream.
	#[allow(async_fn_in_trait)]
	fn emit_on_stream(
		&mut self,
		stream_id: StreamId,
		frame: Frame,
	) -> impl Future<Output = TransportResult<Option<Frame>>> + Send;

	/// Allocate a new stream ID
	///
	/// Returns None if max concurrent streams reached.
	/// Client implementations should return odd IDs, server implementations even IDs.
	fn allocate_stream_id(&mut self) -> Option<StreamId>;

	/// Close a specific stream
	///
	/// Best-effort close, should not panic.
	fn close_stream(&mut self, stream_id: StreamId);
}

/// Stream state for multiplexed transports
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
	/// Stream is idle (not yet used)
	Idle,
	/// Stream is open and active
	Open,
	/// Stream is half-closed (local side closed)
	HalfClosedLocal,
	/// Stream is half-closed (remote side closed)
	HalfClosedRemote,
	/// Stream is fully closed
	Closed,
}

/// TODO Implement multiplexed transport

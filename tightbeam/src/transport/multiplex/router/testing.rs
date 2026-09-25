//! Shared test fixtures for the router submodules.

use core::future::Future;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures::channel::mpsc;

use super::body::{DrainNote, ForwardedStream, StreamBody};
use super::shared::{MuxShared, OpenSlot};
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::TransportResult;

pub fn noop_cx() -> Context<'static> {
	Context::from_waker(futures::task::noop_waker_ref())
}

pub fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
	let mut cx = noop_cx();
	let mut future = Box::pin(future);
	future.as_mut().poll(&mut cx)
}

pub fn client_shared() -> Arc<MuxShared> {
	Arc::new(MuxShared::new(MuxRole::Client, &MuxSettings::symmetric(4)))
}

/// Body/forwarder pair with its drain-note receiver.
pub fn body_fixture(stream_id: u32, window: u64) -> (StreamBody, ForwardedStream, mpsc::UnboundedReceiver<DrainNote>) {
	let (feedback, notes) = mpsc::unbounded();
	let (body, forwarder) = StreamBody::pair(OpenSlot::assigned(stream_id), window, feedback);
	(body, forwarder, notes)
}

impl StreamBody {
	pub fn poll_chunk_now(&mut self) -> Poll<TransportResult<Option<Vec<u8>>>> {
		poll_now(self.chunk())
	}
}

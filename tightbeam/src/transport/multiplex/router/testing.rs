//! Shared test fixtures for the router submodules.

use core::future::Future;
use core::task::{Context, Poll};
use std::sync::Arc;

use futures::channel::mpsc;

use super::body::{stream_body, DrainNote, ForwardedStream, StreamBody};
use super::shared::MuxShared;
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::TransportResult;

pub(super) fn noop_cx() -> Context<'static> {
	Context::from_waker(futures::task::noop_waker_ref())
}

pub(super) fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
	let mut cx = noop_cx();
	let mut future = Box::pin(future);
	future.as_mut().poll(&mut cx)
}

pub(super) fn client_shared() -> Arc<MuxShared> {
	Arc::new(MuxShared::new(MuxRole::Client, &MuxSettings::symmetric(4)))
}

/// Body/forwarder pair with its drain-note receiver.
pub(super) fn body_fixture(
	stream_id: u32,
	window: u64,
) -> (StreamBody, ForwardedStream, mpsc::UnboundedReceiver<DrainNote>) {
	let (feedback, notes) = mpsc::unbounded();
	let (body, forwarder) = stream_body(stream_id, window, feedback);

	(body, forwarder, notes)
}

pub(super) fn poll_chunk(body: &mut StreamBody) -> Poll<TransportResult<Option<Vec<u8>>>> {
	poll_now(body.chunk())
}

//! Shared test fixtures for the router submodules.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use std::sync::Arc;

use futures::channel::mpsc;
use futures::task::ArcWake;

use super::body::{DrainNote, ForwardedStream, StreamBody};
use super::link::MuxLink;
use super::shared::{MuxShared, OpenSlot};
use crate::transport::handshake::negotiation::MuxSettings;
use crate::transport::multiplex::MuxRole;
use crate::transport::TransportResult;

/// Poll context over a waker that does nothing when woken.
pub fn noop_cx() -> Context<'static> {
	Context::from_waker(futures::task::noop_waker_ref())
}

/// Poll `future` once with a waker that does nothing, and return the outcome.
pub fn poll_now<F: Future>(future: F) -> Poll<F::Output> {
	let mut cx = noop_cx();
	let mut future = Box::pin(future);
	future.as_mut().poll(&mut cx)
}

/// Poll `future` a fixed number of times with a waker that does nothing, for
/// drivers that make progress per poll and never resolve on their own.
pub fn poll_times<F>(future: &mut Pin<Box<F>>, times: usize)
where
	F: Future,
{
	let mut cx = noop_cx();
	for _ in 0..times {
		// The driver under test runs until the connection ends, so the
		// poll outcome carries no assertion of its own.
		let _ = future.as_mut().poll(&mut cx);
	}
}

/// The stream cap both sides of a router fixture advertise.
pub const FIXTURE_PEER_CAP: u32 = 4;

/// Client-role connection state that advertises [`FIXTURE_PEER_CAP`] on both
/// sides.
pub fn client_shared() -> Arc<MuxShared> {
	Arc::new(MuxShared::new(MuxRole::Client, &MuxSettings::symmetric(FIXTURE_PEER_CAP)))
}

/// Body/forwarder pair with its drain-note receiver, on the drain channel a
/// production link opens.
pub fn body_fixture(stream_id: u32, window: u64) -> (StreamBody, ForwardedStream, mpsc::Receiver<DrainNote>) {
	let (outbound, _wire) = mpsc::channel(0);
	let (link, notes) = MuxLink::new(client_shared(), outbound);
	let (body, forwarder) = StreamBody::pair(OpenSlot::assigned(stream_id), window, link.drain_feedback());

	(body, forwarder, notes)
}

impl StreamBody {
	/// Poll [`chunk`](Self::chunk) once with a waker that does nothing.
	pub fn poll_chunk_now(&mut self) -> Poll<TransportResult<Option<Vec<u8>>>> {
		poll_now(self.chunk())
	}
}

/// Waker that records delivery, for wake assertions on parked pollers.
#[derive(Default)]
pub struct FlagWake {
	woken: AtomicBool,
}

impl FlagWake {
	/// Create a flag and a waker that sets it when woken.
	pub fn pair() -> (Arc<Self>, Waker) {
		let flag = Arc::new(Self::default());
		let waker = futures::task::waker(Arc::clone(&flag));
		(flag, waker)
	}

	/// Whether the paired waker has been woken.
	pub fn woken(&self) -> bool {
		self.woken.load(Ordering::SeqCst)
	}
}

impl ArcWake for FlagWake {
	fn wake_by_ref(arc_self: &Arc<Self>) {
		arc_self.woken.store(true, Ordering::SeqCst);
	}
}

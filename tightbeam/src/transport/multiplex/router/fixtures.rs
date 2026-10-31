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
use super::outbound::Outbound;
use super::reassembly::ReassemblyBudget;
use super::shared::{MuxShared, OpenSlot};
use crate::transport::envelopes::MuxEnvelope;
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

/// The mux envelope of the next command on `wire`, or `None` when the queue
/// is empty or its next command writes no mux envelope.
pub fn next_mux(wire: &mut mpsc::Receiver<Outbound>) -> Option<MuxEnvelope> {
	wire.try_recv().ok().and_then(Outbound::into_mux)
}

/// Every command that waits on `wire`, in queue order.
pub fn drained(wire: &mut mpsc::Receiver<Outbound>) -> Vec<Outbound> {
	core::iter::from_fn(|| wire.try_recv().ok()).collect()
}

impl StreamBody {
	/// Body/forwarder pair of `stream_id` under `window`, with its drain-note
	/// receiver, on the drain channel a production link opens.
	pub(crate) fn fixture(stream_id: u32, window: u64) -> (StreamBody, ForwardedStream, mpsc::Receiver<DrainNote>) {
		StreamBody::budgeted_fixture(stream_id, window, Arc::new(ReassemblyBudget::default()))
	}

	/// The pair of [`Self::fixture`], whose collect charges `budget`.
	pub(crate) fn budgeted_fixture(
		stream_id: u32,
		window: u64,
		budget: Arc<ReassemblyBudget>,
	) -> (StreamBody, ForwardedStream, mpsc::Receiver<DrainNote>) {
		let shared = MuxShared::fixture(MuxRole::Client, &MuxSettings::symmetric(FIXTURE_PEER_CAP));
		let (outbound, _wire) = mpsc::channel(0);
		let (link, notes) = MuxLink::new(shared, outbound);
		let (body, forwarder) = StreamBody::pair(OpenSlot::assigned(stream_id), window, link.drain_feedback(), budget);

		(body, forwarder, notes)
	}

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

	/// Create a flag and its waker as one poller that parks on a poll and
	/// reads the flag after a wake.
	pub fn parked() -> Parked {
		let (flag, waker) = Self::pair();
		Parked { flag, waker }
	}
}

/// A poller that holds a [`FlagWake`] flag and its waker, so one value polls
/// and reports the wake.
pub struct Parked {
	flag: Arc<FlagWake>,
	waker: Waker,
}

impl Parked {
	/// A poll context over the waker of this poller.
	pub fn cx(&self) -> Context<'_> {
		Context::from_waker(&self.waker)
	}

	/// Whether the waker of this poller has been woken.
	pub fn woken(&self) -> bool {
		self.flag.woken()
	}
}

impl ArcWake for FlagWake {
	fn wake_by_ref(arc_self: &Arc<Self>) {
		arc_self.woken.store(true, Ordering::SeqCst);
	}
}

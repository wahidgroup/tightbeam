//! An outside crate writes a [`Worker`] here with no house runtime under it,
//! and a servlet that drains ends that worker through its kill.
//!
//! An outside crate also hands a [`ServletContext`] a worker, or a
//! [`WorkerBox`] of its own with no [`Worker`] under it, and the context finds
//! each by its type.

#![cfg(all(feature = "std", feature = "tokio", feature = "colony"))]

use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tightbeam::colony::servlet::{
	ServletConfig, ServletContext, ServletRuntime, ServletService, WorkerBox, WorkerBoxStartFuture,
};
use tightbeam::colony::worker::{Worker, WorkerKillFuture, WorkerRelayFuture, WorkerStartFuture};
use tightbeam::testing::TestMessage;
use tightbeam::trace::TraceCollector;
use tightbeam::transport::tcp::r#async::TokioListener;
use tightbeam::TightBeamError;

/// A worker an outside crate writes with no house runtime: it answers the
/// length of the content of each message, and it marks its kill.
struct OutsideWorker {
	killed: Arc<AtomicBool>,
}

impl Worker for OutsideWorker {
	type Input = TestMessage;
	type Output = usize;
	type Config = Arc<AtomicBool>;

	fn new(killed: Arc<AtomicBool>) -> Self {
		Self { killed }
	}

	fn start(self, _trace: Arc<TraceCollector>) -> WorkerStartFuture<Self> {
		Box::pin(async move { Ok(self) })
	}

	fn kill(&self) -> WorkerKillFuture {
		let killed = Arc::clone(&self.killed);
		Box::pin(async move {
			killed.store(true, Ordering::SeqCst);
			Ok(())
		})
	}

	fn relay(&self, message: Arc<TestMessage>) -> WorkerRelayFuture<usize> {
		let length = message.content.len();
		Box::pin(async move { Ok(length) })
	}

	fn queue_capacity(&self) -> usize {
		0
	}
}

/// A [`WorkerBox`] an outside crate writes itself, with no [`Worker`] under
/// it: it starts as it is, and its kill ends at once.
struct OutsideBox;

impl WorkerBox for OutsideBox {
	fn start_boxed(self: Box<Self>, _trace: Arc<TraceCollector>) -> WorkerBoxStartFuture {
		Box::pin(async move { Ok(self as Box<dyn WorkerBox>) })
	}

	fn kill_shared(&self) -> WorkerKillFuture {
		Box::pin(async { Ok(()) })
	}
}

/// A service that serves no kind of request, so each request it meets
/// refuses with `Unimplemented`.
struct Idle;

impl ServletService for Idle {
	type Env = ();
}

/// A servlet that drains ends its outside worker through the worker's kill.
#[tokio::test]
async fn a_servlet_drain_kills_an_outside_worker() -> Result<(), TightBeamError> {
	let killed = Arc::new(AtomicBool::new(false));
	let worker = OutsideWorker::new(Arc::clone(&killed));
	let builder = ServletConfig::<TokioListener, TestMessage>::builder().with_worker(worker);
	let trace = Arc::new(TraceCollector::new());
	let runtime = ServletRuntime::<TokioListener>::start(trace, builder.allow_cleartext().build(), Idle).await?;

	runtime.drain().await?;

	assert!(killed.load(Ordering::SeqCst));
	Ok(())
}

/// A worker that an outside crate hands to a context finds itself by its
/// type.
#[test]
fn a_worker_handed_to_a_context_resolves_by_its_type() -> Result<(), TightBeamError> {
	let workers: [Box<dyn WorkerBox>; 1] = [Box::new(OutsideWorker::new(Arc::default()))];

	let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), workers, None);

	assert!(ctx.worker::<OutsideWorker>().is_some());
	Ok(())
}

/// An outside box that an outside crate hands to a context finds itself by its
/// type, so the context keys a box with no [`Worker`] under it.
#[test]
fn an_outside_worker_box_handed_to_a_context_resolves_by_its_type() -> Result<(), TightBeamError> {
	let workers: [Box<dyn WorkerBox>; 1] = [Box::new(OutsideBox)];

	let ctx: ServletContext = ServletContext::new(Arc::new(TraceCollector::new()), Arc::new(()), workers, None);

	assert!(ctx.worker::<OutsideBox>().is_some());
	Ok(())
}

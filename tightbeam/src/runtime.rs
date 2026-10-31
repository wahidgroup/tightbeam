//! The runtime layer under the async and the blocking builds.
//!
//! [`rt`] holds one set of primitives to spawn and join tasks and to pass
//! messages between them. A feature picks the implementation behind it.
//!
//! # Features
//!
//! - `tokio`: the primitives of the tokio runtime, recommended for async workloads.
//! - `std` with no `tokio`: std threads, bounded sync channels, and a parking `block_on` executor.
//!
//! [`ParkingExecutor`] drives a future on a thread outside any runtime, in
//! every build.

use core::fmt;
use core::future::Future;
use core::marker::PhantomData;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;
use std::task::Wake;
use std::thread::{self, Thread};

#[cfg(feature = "colony")]
mod task_group;

#[cfg(feature = "colony")]
pub(crate) use task_group::TaskGroup;

/// The error of a channel whose other half is gone: a [`rt::send`] whose
/// receiver dropped, or a [`rt::wait_response`] whose sender dropped before it
/// sent.
///
/// # Examples
///
/// ```
/// use tightbeam::runtime::{rt, ChannelClosed};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let runtime = tokio::runtime::Builder::new_current_thread().build()?;
/// # runtime.block_on(async {
/// let (sender, receiver) = rt::oneshot::<u8>();
/// drop(sender);
///
/// assert_eq!(rt::wait_response(receiver).await, Err(ChannelClosed));
/// # });
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelClosed;

impl fmt::Display for ChannelClosed {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "the other half of the channel is gone")
	}
}

impl core::error::Error for ChannelClosed {}

/// The executor of one thread, which parks the thread while its future waits.
///
/// A future that waits on a tokio timer or reactor needs another thread to
/// drive its runtime. [`rt::block_on`] picks it outside a multi-thread runtime.
///
/// # Examples
///
/// ```
/// use tightbeam::runtime::ParkingExecutor;
///
/// let executor = ParkingExecutor::on_current_thread();
/// assert_eq!(executor.block_on(async { 7 }), 7);
/// ```
pub struct ParkingExecutor {
	waker: Waker,
	/// A raw pointer is neither `Send` nor `Sync`, so the executor stays on
	/// the thread that its waker unparks.
	thread_bound: PhantomData<*const ()>,
}

impl ParkingExecutor {
	/// The executor of the calling thread.
	#[must_use]
	pub fn on_current_thread() -> Self {
		let waker = Waker::from(Arc::new(ThreadWaker(thread::current())));
		Self { waker, thread_bound: PhantomData }
	}

	/// Drives `future` to its end, and returns its output.
	///
	/// The thread parks between polls and the waker unparks it, so a
	/// `Pending` future consumes no CPU while it waits. A spurious unpark
	/// costs one extra poll.
	pub fn block_on<F: Future>(&self, future: F) -> F::Output {
		let mut cx = Context::from_waker(&self.waker);
		let mut future = pin!(future);

		loop {
			match future.as_mut().poll(&mut cx) {
				Poll::Ready(result) => return result,
				Poll::Pending => thread::park(),
			}
		}
	}
}

/// The waker that unparks the thread of a [`ParkingExecutor`] when the future
/// can make progress.
struct ThreadWaker(Thread);

impl Wake for ThreadWaker {
	fn wake(self: Arc<Self>) {
		self.0.unpark();
	}

	fn wake_by_ref(self: &Arc<Self>) {
		self.0.unpark();
	}
}

/// The runtime primitives.
///
/// The aliases and functions abstract over tokio or std threads, so a caller
/// writes one call for either.
#[cfg(feature = "tokio")]
pub mod rt {
	use core::future::Future;

	use tokio::runtime::{Handle, RuntimeFlavor};

	use super::{ChannelClosed, ParkingExecutor};

	// Types

	/// The handle of a spawned task.
	pub type JoinHandle = tokio::task::JoinHandle<()>;

	/// The error that a failed join of a task returns.
	pub type JoinError = tokio::task::JoinError;

	/// The sender of a multi-producer, single-consumer channel.
	pub type Sender<T> = tokio::sync::mpsc::Sender<T>;

	/// The receiver of a multi-producer, single-consumer channel.
	pub type Receiver<T> = tokio::sync::mpsc::Receiver<T>;

	/// The sender of a one-shot channel, which carries one value to one
	/// consumer.
	pub type OneshotSender<T> = tokio::sync::oneshot::Sender<T>;

	/// The receiver of a one-shot channel, which carries one value to one
	/// consumer.
	pub type OneshotReceiver<T> = tokio::sync::oneshot::Receiver<T>;

	// Task management

	/// Spawn `fut` as an async task.
	pub fn spawn<F>(fut: F) -> JoinHandle
	where
		F: Future<Output = ()> + Send + 'static,
	{
		tokio::spawn(fut)
	}

	/// Abort the task of `handle`.
	pub fn abort(handle: &JoinHandle) {
		handle.abort();
	}

	/// Take an optional join handle and abort it when present.
	///
	/// The servlet and cluster `stop` and `Drop` paths share it, so the take
	/// and the abort stay one step and a stopped runtime keeps no live handle.
	pub fn take_and_abort(handle: &mut Option<JoinHandle>) {
		if let Some(handle) = handle.take() {
			abort(&handle);
		}
	}

	/// Wait for the task of `handle` to complete.
	pub async fn join(handle: JoinHandle) -> Result<(), JoinError> {
		handle.await
	}

	// Channels

	/// Create a bounded multi-producer, single-consumer channel of `capacity`
	/// messages.
	pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
		tokio::sync::mpsc::channel(capacity)
	}

	/// Create a one-shot channel, which carries one value.
	pub fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
		tokio::sync::oneshot::channel()
	}

	/// Send `value` through the channel of `sender`.
	///
	/// # Errors
	///
	/// - [`ChannelClosed`] -- the receiver is gone, and the value drops unsent.
	pub async fn send<T>(sender: &Sender<T>, value: T) -> Result<(), ChannelClosed> {
		sender.send(value).await.map_err(|_unsent| ChannelClosed)
	}

	/// Receive the next value from the channel of `receiver`.
	pub async fn recv<T>(receiver: &mut Receiver<T>) -> Option<T> {
		receiver.recv().await
	}

	/// Wait for the response on the one-shot channel of `receiver`.
	///
	/// # Errors
	///
	/// - [`ChannelClosed`] -- the sender dropped before it sent.
	pub async fn wait_response<T>(receiver: OneshotReceiver<T>) -> Result<T, ChannelClosed> {
		receiver.await.map_err(|_closed| ChannelClosed)
	}

	// Blocking on a future

	/// Block on `future` with the executor that fits the calling thread.
	///
	/// On a multi-thread runtime it blocks in place, and elsewhere it parks on
	/// a [`ParkingExecutor`]. A tokio timer or socket needs that runtime.
	pub fn block_on<F>(future: F) -> F::Output
	where
		F: Future,
	{
		match Handle::try_current() {
			Ok(handle) if handle.runtime_flavor() == RuntimeFlavor::MultiThread => {
				tokio::task::block_in_place(|| handle.block_on(future))
			}
			_ => ParkingExecutor::on_current_thread().block_on(future),
		}
	}
}

#[cfg(all(not(feature = "tokio"), feature = "std"))]
pub mod rt {
	use core::future::Future;
	use std::{io::Error, sync::mpsc, thread};

	use super::{ChannelClosed, ParkingExecutor};

	// Types

	/// The handle of a spawned thread.
	pub type JoinHandle = thread::JoinHandle<()>;

	/// The error that a failed join of a thread returns.
	pub type JoinError = Error;

	/// The sender of a bounded multi-producer, single-consumer std channel.
	pub type Sender<T> = mpsc::SyncSender<T>;

	/// The receiver of a bounded multi-producer, single-consumer std channel.
	pub type Receiver<T> = mpsc::Receiver<T>;

	/// The sender of a one-shot channel: a bounded mpsc channel of capacity 1.
	pub type OneshotSender<T> = mpsc::SyncSender<T>;

	/// The receiver of a one-shot channel: a bounded mpsc channel of
	/// capacity 1.
	pub type OneshotReceiver<T> = mpsc::Receiver<T>;

	// Task management

	/// Spawn `task` on a thread of its own.
	///
	/// # Errors
	///
	/// - The I/O error of a system that refuses to start the thread, such as one at its thread limit.
	pub fn spawn<F>(task: F) -> Result<JoinHandle, Error>
	where
		F: FnOnce() + Send + 'static,
	{
		thread::Builder::new().spawn(task)
	}

	/// Abort a thread. For a std thread the call does nothing, and a drop of
	/// its handle detaches the thread.
	pub fn abort(_handle: &JoinHandle) {
		// A std thread has no cooperative cancellation.
	}

	/// Take an optional join handle and drop it when present.
	///
	/// The drop detaches the std thread, which runs to its own end.
	pub fn take_and_abort(handle: &mut Option<JoinHandle>) {
		if let Some(handle) = handle.take() {
			abort(&handle);
		}
	}

	/// Wait for the thread of `handle` to complete.
	pub fn join(handle: JoinHandle) -> Result<(), JoinError> {
		handle.join().map_err(|_| Error::other("thread panicked"))
	}

	// Channels

	/// Create a bounded multi-producer, single-consumer channel of `capacity`
	/// messages.
	///
	/// [`send`] blocks once `capacity` messages are queued, so the backpressure
	/// matches the tokio implementation.
	pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
		mpsc::sync_channel(capacity)
	}

	/// Create a one-shot channel, as a bounded mpsc channel of capacity 1.
	pub fn oneshot<T>() -> (OneshotSender<T>, OneshotReceiver<T>) {
		mpsc::sync_channel(1)
	}

	/// Send `value` through the channel of `sender`, and block while the
	/// channel is full.
	///
	/// # Errors
	///
	/// - [`ChannelClosed`] -- the receiver is gone, and the value drops unsent.
	pub fn send<T>(sender: &Sender<T>, value: T) -> Result<(), ChannelClosed> {
		sender.send(value).map_err(|_unsent| ChannelClosed)
	}

	/// Receive a value from the channel of `receiver`, and block while it
	/// waits.
	pub fn recv<T>(receiver: &Receiver<T>) -> Option<T> {
		receiver.recv().ok()
	}

	/// Wait for the response on the one-shot channel of `receiver`, and block
	/// while it waits.
	///
	/// # Errors
	///
	/// - [`ChannelClosed`] -- the sender dropped before it sent.
	pub fn wait_response<T>(receiver: OneshotReceiver<T>) -> Result<T, ChannelClosed> {
		receiver.recv().map_err(|_closed| ChannelClosed)
	}

	// Blocking on a future

	/// Block on `future` with the [`ParkingExecutor`] of the current thread.
	pub fn block_on<F: Future>(future: F) -> F::Output {
		ParkingExecutor::on_current_thread().block_on(future)
	}
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
	use core::time::Duration;
	use std::sync::mpsc;

	use crate::testing::TestResult;

	use super::{rt, ChannelClosed};

	/// A thread outside any runtime blocks on a future to its output.
	#[test]
	fn a_thread_outside_a_runtime_blocks_on_a_future() {
		let output = rt::block_on(async { 7 });
		assert_eq!(output, 7);
	}

	/// The thread of a current-thread runtime blocks on a future to its output.
	#[tokio::test]
	async fn the_thread_of_a_current_thread_runtime_blocks_on_a_future() {
		let output = rt::block_on(async { 7 });
		assert_eq!(output, 7);
	}

	/// A lone worker of a multi-thread runtime blocks on a tokio timer.
	#[test]
	fn a_worker_of_a_multi_thread_runtime_blocks_on_a_tokio_timer() -> TestResult {
		let mut builder = tokio::runtime::Builder::new_multi_thread();
		let runtime = builder.worker_threads(1).enable_time().build()?;
		let (sender, receiver) = mpsc::channel();
		let _task = runtime.spawn(async move {
			let timer = async {
				tokio::time::sleep(Duration::from_millis(1)).await;
				7
			};
			let output = rt::block_on(timer);
			sender.send(output)
		});

		let output = receiver.recv_timeout(Duration::from_secs(5));
		runtime.shutdown_background();
		assert_eq!(output?, 7);
		Ok(())
	}

	/// A send to a channel whose receiver is gone fails as closed.
	#[tokio::test]
	async fn a_send_to_a_dropped_receiver_fails_as_closed() {
		let (sender, receiver) = rt::channel::<u8>(1);
		drop(receiver);
		assert_eq!(rt::send(&sender, 7).await, Err(ChannelClosed));
	}

	/// A wait on a oneshot whose sender dropped unsent fails as closed.
	#[tokio::test]
	async fn a_wait_on_a_dropped_sender_fails_as_closed() {
		let (sender, receiver) = rt::oneshot::<u8>();
		drop(sender);
		assert_eq!(rt::wait_response(receiver).await, Err(ChannelClosed));
	}
}
